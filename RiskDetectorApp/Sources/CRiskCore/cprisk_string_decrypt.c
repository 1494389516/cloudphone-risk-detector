/*
 * CRiskCore - Runtime string decryptor for cprisk-armor ABI v1.
 * Consumes the packed string table section using the shared layout defined in
 * include/cprisk_armor_abi.h. Side-effect: each decryption updates an
 * integrity accumulator used downstream.
 */

#include "include/CRiskCore.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

_Static_assert(CPRISK_SHA256_DIGEST_LENGTH == CPRISK_ARMOR_HASH_SIZE,
               "inline SHA256 digest size must match armor ABI");

/* ── state ─────────────────────────────────────────────────────────── */

static uint8_t  s_dec_key[CPRISK_ARMOR_KEY_SIZE];
static int      s_dec_ready;
static uint64_t s_str_acc;

/* ── internal ──────────────────────────────────────────────────────── */

static inline uint64_t cprisk_rotl64(uint64_t x, int k) {
    k &= 63;  /* avoid UB: shift amount must be in [0, 63] */
    return k == 0 ? x : ((x << k) | (x >> (64 - k)));
}

static const struct mach_header_64 *cprisk_own_hdr(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr);
}

static void cprisk_keystream(const uint8_t *key, uint32_t sid,
                             uint8_t *out, size_t len) {
    uint8_t seed[36];
    memcpy(seed, key, CPRISK_ARMOR_KEY_SIZE);
    seed[32] = (uint8_t)(sid);
    seed[33] = (uint8_t)(sid >> 8);
    seed[34] = (uint8_t)(sid >> 16);
    seed[35] = (uint8_t)(sid >> 24);

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, sizeof(seed), blk);
    cprisk_secure_zero(seed, sizeof(seed));

    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH)
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        memcpy(out + off, blk, chunk);
        off += chunk;
        if (off < len) {
            uint8_t prev[CPRISK_SHA256_DIGEST_LENGTH];
            memcpy(prev, blk, CPRISK_SHA256_DIGEST_LENGTH);
            cprisk_sha256(prev, CPRISK_SHA256_DIGEST_LENGTH, blk);
            cprisk_secure_zero(prev, sizeof(prev));
        }
    }
    cprisk_secure_zero(blk, sizeof(blk));
}

/* ── public API ────────────────────────────────────────────────────── */

int cprisk_init_string_decryptor(const uint8_t *key, size_t key_len) {
    if (!key || key_len != CPRISK_ARMOR_KEY_SIZE)
        return -1;
    memcpy(s_dec_key, key, CPRISK_ARMOR_KEY_SIZE);
    s_dec_ready = 1;
    s_str_acc = 0;
    return 0;
}

int cprisk_decrypt_string(uint32_t string_id, char *buffer, size_t buffer_size) {
    if (!s_dec_ready || !buffer || buffer_size == 0)
        return -1;

    const struct mach_header_64 *hdr = cprisk_own_hdr();
    if (!hdr)
        return -1;

    unsigned long sec_sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_STRTAB, &sec_sz);
    if (!sec || sec_sz < sizeof(struct cprisk_armor_strtab_header))
        return -1;

    const struct cprisk_armor_strtab_header *th =
        (const struct cprisk_armor_strtab_header *)sec;
    if (th->magic != CPRISK_ARMOR_STRTAB_MAGIC ||
        th->version != CPRISK_ARMOR_ABI_VERSION)
        return -1;

    uint32_t count = th->count;
    size_t idx_base  = sizeof(struct cprisk_armor_strtab_header);
    if (count > (UINT32_MAX /
                 (uint32_t)sizeof(struct cprisk_armor_strtab_index_entry)))
        return -1;
    size_t data_base =
        idx_base + (size_t)count * sizeof(struct cprisk_armor_strtab_index_entry);
    if (data_base > sec_sz)
        return -1;

    const struct cprisk_armor_strtab_index_entry *idx =
        (const struct cprisk_armor_strtab_index_entry *)(sec + idx_base);

    const struct cprisk_armor_strtab_index_entry *ent = NULL;
    for (uint32_t i = 0; i < count; i++) {
        if (idx[i].string_id == string_id) {
            ent = &idx[i];
            break;
        }
    }
    if (!ent)
        return -1;

    uint32_t dlen = ent->data_length;
    if (dlen == 0 || dlen + 1 > buffer_size)
        return -1;
    size_t data_end = (size_t)ent->data_offset + (size_t)dlen;
    if (data_end < (size_t)dlen || data_end < (size_t)ent->data_offset)
        return -1;  /* overflow */
    if ((size_t)ent->data_offset > sec_sz ||
        (size_t)dlen > sec_sz ||
        data_base + data_end > sec_sz)
        return -1;

    const uint8_t *enc = sec + data_base + ent->data_offset;

    uint8_t *ks = (uint8_t *)malloc(dlen);
    if (!ks)
        return -1;
    cprisk_keystream(s_dec_key, string_id, ks, dlen);

    for (uint32_t i = 0; i < dlen; i++)
        buffer[i] = (char)(enc[i] ^ ks[i]);
    buffer[dlen] = '\0';

    uint8_t dh[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256((const uint8_t *)buffer, dlen, dh);
    uint64_t hv;
    memcpy(&hv, dh, sizeof(hv));
    s_str_acc ^= cprisk_rotl64(hv, string_id % 64);

    cprisk_secure_zero(ks, dlen);
    free(ks);
    cprisk_secure_zero(dh, sizeof(dh));

    return (int)dlen;
}

uint64_t cprisk_get_string_integrity_accumulator(void) {
    return s_str_acc;
}

void cprisk_cleanup_string_decryptor(void) {
    cprisk_secure_zero(s_dec_key, sizeof(s_dec_key));
    s_dec_ready = 0;
    s_str_acc = 0;
}
