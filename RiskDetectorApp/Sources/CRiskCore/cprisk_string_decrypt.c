/*
 * CRiskCore - Runtime string decryptor for cprisk-armor ABI v2.
 * Consumes the packed string table section using the shared layout defined in
 * include/cprisk_armor_abi.h. Verifies HMAC-SHA256 authentication tag before
 * decryption. Side-effect: each decryption updates an integrity accumulator.
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
    k &= 63;
    return k == 0 ? x : ((x << k) | (x >> (64 - k)));
}

static const struct mach_header_64 *cprisk_own_hdr(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr);
}

static void cprisk_keystream(const uint8_t *key, uint32_t sid,
                             const uint8_t *nonce, size_t nonce_len,
                             uint8_t *out, size_t len) {
    if (nonce_len > CPRISK_ARMOR_NONCE_SIZE)
        return;
    /* seed = key[32] || sid_le[4] || nonce[nonce_len] */
    size_t seed_len = CPRISK_ARMOR_KEY_SIZE + 4 + nonce_len;
    uint8_t seed_buf[CPRISK_ARMOR_KEY_SIZE + 4 + CPRISK_ARMOR_NONCE_SIZE];
    uint8_t *seed = seed_buf;
    uint8_t *seed_alloc = NULL;

    if (seed_len > sizeof(seed_buf)) {
        seed_alloc = (uint8_t *)malloc(seed_len);
        if (!seed_alloc) return;
        seed = seed_alloc;
    }

    memcpy(seed, key, CPRISK_ARMOR_KEY_SIZE);
    seed[32] = (uint8_t)(sid);
    seed[33] = (uint8_t)(sid >> 8);
    seed[34] = (uint8_t)(sid >> 16);
    seed[35] = (uint8_t)(sid >> 24);
    if (nonce_len > 0)
        memcpy(seed + 36, nonce, nonce_len);

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, seed_len, blk);
    cprisk_secure_zero(seed, seed_len);
    if (seed_alloc) free(seed_alloc);

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
        return -1;
    if ((size_t)ent->data_offset > sec_sz ||
        (size_t)dlen > sec_sz ||
        data_end > sec_sz - data_base)
        return -1;

    const uint8_t *enc = sec + data_base + ent->data_offset;

    /* Verify HMAC-SHA256(key, nonce || ciphertext) before decrypting */
    {
        size_t hmac_msg_len = CPRISK_ARMOR_NONCE_SIZE + dlen;
        uint8_t *hmac_msg = (uint8_t *)malloc(hmac_msg_len);
        if (!hmac_msg)
            return -1;
        memcpy(hmac_msg, ent->nonce, CPRISK_ARMOR_NONCE_SIZE);
        memcpy(hmac_msg + CPRISK_ARMOR_NONCE_SIZE, enc, dlen);

        uint8_t computed_hmac[CPRISK_ARMOR_HASH_SIZE];
        cprisk_hmac_sha256(s_dec_key, CPRISK_ARMOR_KEY_SIZE,
                           hmac_msg, hmac_msg_len, computed_hmac);
        cprisk_secure_zero(hmac_msg, hmac_msg_len);
        free(hmac_msg);

        if (cprisk_hmac_verify(ent->hmac_tag, computed_hmac,
                               CPRISK_ARMOR_HASH_SIZE) != 0) {
            cprisk_secure_zero(computed_hmac, sizeof(computed_hmac));
            return -1;
        }
        cprisk_secure_zero(computed_hmac, sizeof(computed_hmac));
    }

    uint8_t *ks = (uint8_t *)malloc(dlen);
    if (!ks)
        return -1;
    cprisk_keystream(s_dec_key, string_id,
                     ent->nonce, CPRISK_ARMOR_NONCE_SIZE, ks, dlen);

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
