/*
 * CRiskCore - Runtime string decryptor for cprisk-armor ABI v2.
 * Consumes the packed string table section using the shared layout defined in
 * include/cprisk_armor_abi.h. Verifies HMAC-SHA256 authentication tag before
 * decryption. Side-effect: each decryption updates an integrity accumulator.
 */

#include "include/CRiskCore.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

_Static_assert(CPRISK_SHA256_DIGEST_LENGTH == CPRISK_ARMOR_HASH_SIZE,
               "inline SHA256 digest size must match armor ABI");

/* ── state ─────────────────────────────────────────────────────────── */

static uint8_t  s_dec_key[CPRISK_ARMOR_KEY_SIZE];
static _Atomic int s_dec_ready;
static uint64_t s_str_acc;
static uint64_t s_dispatch_seed;
static uint8_t  s_per_string_key[CPRISK_ARMOR_KEY_SIZE];
static uint32_t s_lazy_id;
static char     s_lazy_buf[512];
static int      s_lazy_len;
static int      s_lazy_valid;

/* ── internal ──────────────────────────────────────────────────────── */

static inline uint64_t cprisk_rotl64(uint64_t x, int k) {
    k &= 63;
    return k == 0 ? x : ((x << k) | (x >> (64 - k)));
}

static inline uint64_t cprisk_fnv_mix_byte(uint64_t hash, uint8_t byte) {
    hash ^= (uint64_t)byte;
    hash *= 0x00000100000001B3ULL;
    return hash;
}

static uint64_t cprisk_avalanche64(uint64_t value) {
    uint64_t v = value;
    v ^= v >> 33;
    v *= 0xFF51AFD7ED558CCDULL;
    v ^= v >> 33;
    v *= 0xC4CEB9FE1A85EC53ULL;
    v ^= v >> 33;
    return v == 0 ? 1 : v;
}

static uint64_t cprisk_derive_dispatch_seed(const uint8_t *key, size_t key_len) {
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < key_len; i++) {
        hash = cprisk_fnv_mix_byte(hash, key[i]);
    }
    return cprisk_avalanche64(hash);
}

static uint32_t cprisk_select_keystream_variant(uint32_t sid,
                                                const uint8_t *nonce,
                                                size_t nonce_len,
                                                uint64_t dispatch_seed) {
    uint64_t hash = dispatch_seed == 0 ? 0xCBF29CE484222325ULL : dispatch_seed;
    hash = cprisk_fnv_mix_byte(hash, (uint8_t)(sid));
    hash = cprisk_fnv_mix_byte(hash, (uint8_t)(sid >> 8));
    hash = cprisk_fnv_mix_byte(hash, (uint8_t)(sid >> 16));
    hash = cprisk_fnv_mix_byte(hash, (uint8_t)(sid >> 24));

    for (size_t i = 0; i < nonce_len; i++) {
        hash = cprisk_fnv_mix_byte(hash, nonce[i]);
    }

    return (uint32_t)(cprisk_avalanche64(hash) & 0x3u);
}

static const struct mach_header_64 *cprisk_own_hdr(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr);
}

static void cprisk_keystream_path_a(const uint8_t *key, uint32_t sid,
                                    const uint8_t *nonce, size_t nonce_len,
                                    uint8_t *out, size_t len) {
    uint8_t seed[CPRISK_ARMOR_KEY_SIZE + 4 + CPRISK_ARMOR_NONCE_SIZE];
    size_t seed_len = CPRISK_ARMOR_KEY_SIZE + 4 + nonce_len;
    memcpy(seed, key, CPRISK_ARMOR_KEY_SIZE);
    seed[32] = (uint8_t)(sid);
    seed[33] = (uint8_t)(sid >> 8);
    seed[34] = (uint8_t)(sid >> 16);
    seed[35] = (uint8_t)(sid >> 24);
    if (nonce_len > 0) {
        memcpy(seed + 36, nonce, nonce_len);
    }

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, seed_len, blk);

    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH) {
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        }
        memcpy(out + off, blk, chunk);
        off += chunk;
        if (off < len) {
            uint8_t prev[CPRISK_SHA256_DIGEST_LENGTH];
            memcpy(prev, blk, sizeof(prev));
            cprisk_sha256(prev, sizeof(prev), blk);
            cprisk_secure_zero(prev, sizeof(prev));
        }
    }

    cprisk_secure_zero(seed, sizeof(seed));
    cprisk_secure_zero(blk, sizeof(blk));
}

static void cprisk_keystream_path_b(const uint8_t *key, uint32_t sid,
                                    const uint8_t *nonce, size_t nonce_len,
                                    uint8_t *out, size_t len) {
    uint8_t seed[CPRISK_ARMOR_NONCE_SIZE + 4 + CPRISK_ARMOR_KEY_SIZE];
    size_t seed_len = nonce_len + 4 + CPRISK_ARMOR_KEY_SIZE;
    if (nonce_len > 0) {
        memcpy(seed, nonce, nonce_len);
    }
    seed[nonce_len + 0] = (uint8_t)(sid >> 24);
    seed[nonce_len + 1] = (uint8_t)(sid >> 16);
    seed[nonce_len + 2] = (uint8_t)(sid >> 8);
    seed[nonce_len + 3] = (uint8_t)(sid);
    memcpy(seed + nonce_len + 4, key, CPRISK_ARMOR_KEY_SIZE);

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, seed_len, blk);

    uint32_t counter = 0;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH) {
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        }
        memcpy(out + off, blk, chunk);
        off += chunk;
        if (off < len) {
            uint8_t round[CPRISK_SHA256_DIGEST_LENGTH + 4 + CPRISK_ARMOR_NONCE_SIZE];
            memcpy(round, blk, CPRISK_SHA256_DIGEST_LENGTH);
            round[32] = (uint8_t)(counter);
            round[33] = (uint8_t)(counter >> 8);
            round[34] = (uint8_t)(counter >> 16);
            round[35] = (uint8_t)(counter >> 24);
            if (nonce_len > 0) {
                memcpy(round + 36, nonce, nonce_len);
            }
            cprisk_sha256(round, 36 + nonce_len, blk);
            cprisk_secure_zero(round, sizeof(round));
            counter++;
        }
    }

    cprisk_secure_zero(seed, sizeof(seed));
    cprisk_secure_zero(blk, sizeof(blk));
}

static void cprisk_keystream_path_c(const uint8_t *key, uint32_t sid,
                                    const uint8_t *nonce, size_t nonce_len,
                                    uint8_t *out, size_t len) {
    uint8_t seed_msg[4 + CPRISK_ARMOR_NONCE_SIZE + 4];
    size_t msg_len = 4 + nonce_len + 4;
    seed_msg[0] = (uint8_t)(sid);
    seed_msg[1] = (uint8_t)(sid >> 8);
    seed_msg[2] = (uint8_t)(sid >> 16);
    seed_msg[3] = (uint8_t)(sid >> 24);
    if (nonce_len > 0) {
        memcpy(seed_msg + 4, nonce, nonce_len);
    }
    seed_msg[4 + nonce_len + 0] = 0x43;
    seed_msg[4 + nonce_len + 1] = 0x50;
    seed_msg[4 + nonce_len + 2] = 0x52;
    seed_msg[4 + nonce_len + 3] = 0x49;

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_hmac_sha256(key, CPRISK_ARMOR_KEY_SIZE, seed_msg, msg_len, blk);

    uint32_t counter = 1;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH) {
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        }
        memcpy(out + off, blk, chunk);
        off += chunk;
        if (off < len) {
            uint8_t round[4 + CPRISK_SHA256_DIGEST_LENGTH + 4];
            round[0] = (uint8_t)(counter >> 24);
            round[1] = (uint8_t)(counter >> 16);
            round[2] = (uint8_t)(counter >> 8);
            round[3] = (uint8_t)(counter);
            memcpy(round + 4, blk, CPRISK_SHA256_DIGEST_LENGTH);
            round[36] = (uint8_t)(sid);
            round[37] = (uint8_t)(sid >> 8);
            round[38] = (uint8_t)(sid >> 16);
            round[39] = (uint8_t)(sid >> 24);
            cprisk_sha256(round, sizeof(round), blk);
            cprisk_secure_zero(round, sizeof(round));
            counter++;
        }
    }

    cprisk_secure_zero(seed_msg, sizeof(seed_msg));
    cprisk_secure_zero(blk, sizeof(blk));
}

static void cprisk_keystream_path_d(const uint8_t *key, uint32_t sid,
                                    const uint8_t *nonce, size_t nonce_len,
                                    uint8_t *out, size_t len) {
    /*
     * Seed buffer is sized for at most CPRISK_ARMOR_NONCE_SIZE nonce bytes.
     * If a caller passes nonce_len > CPRISK_ARMOR_NONCE_SIZE the loop below
     * would write past the buffer. Audit pass flagged this as a stack
     * overflow vector if string-table parsing is ever fed adversarial data.
     * Hard-clamp at the contract boundary.
     */
    if (nonce_len > CPRISK_ARMOR_NONCE_SIZE) {
        nonce_len = CPRISK_ARMOR_NONCE_SIZE;
    }
    uint8_t seed[CPRISK_ARMOR_KEY_SIZE + 4 + CPRISK_ARMOR_NONCE_SIZE];
    for (size_t i = 0; i < CPRISK_ARMOR_KEY_SIZE; i++) {
        seed[i] = key[i] ^ 0x5A;
    }
    seed[32] = (uint8_t)(sid);
    seed[33] = (uint8_t)(sid >> 8);
    seed[34] = (uint8_t)(sid >> 16);
    seed[35] = (uint8_t)(sid >> 24);
    for (size_t i = 0; i < nonce_len; i++) {
        seed[36 + i] = nonce[nonce_len - 1 - i];
    }

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, CPRISK_ARMOR_KEY_SIZE + 4 + nonce_len, blk);

    uint32_t counter = 0;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH) {
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        }
        memcpy(out + off, blk, chunk);
        off += chunk;
        if (off < len) {
            uint8_t lane = key[counter % CPRISK_ARMOR_KEY_SIZE];
            uint8_t round[CPRISK_SHA256_DIGEST_LENGTH + 4];
            for (size_t i = 0; i < CPRISK_SHA256_DIGEST_LENGTH; i++) {
                round[i] = (uint8_t)(blk[i] ^ lane);
            }
            round[32] = (uint8_t)(counter);
            round[33] = (uint8_t)(counter >> 8);
            round[34] = (uint8_t)(counter >> 16);
            round[35] = (uint8_t)(counter >> 24);
            cprisk_sha256(round, sizeof(round), blk);
            cprisk_secure_zero(round, sizeof(round));
            counter++;
        }
    }

    cprisk_secure_zero(seed, sizeof(seed));
    cprisk_secure_zero(blk, sizeof(blk));
}

static void cprisk_keystream_dispatch_level2(uint32_t variant,
                                             const uint8_t *key, uint32_t sid,
                                             const uint8_t *nonce, size_t nonce_len,
                                             uint8_t *out, size_t len) {
    switch (variant) {
    case 0:
        cprisk_keystream_path_a(key, sid, nonce, nonce_len, out, len);
        break;
    case 1:
        cprisk_keystream_path_b(key, sid, nonce, nonce_len, out, len);
        break;
    case 2:
        cprisk_keystream_path_c(key, sid, nonce, nonce_len, out, len);
        break;
    default:
        cprisk_keystream_path_d(key, sid, nonce, nonce_len, out, len);
        break;
    }
}

static void cprisk_keystream_dispatch_level1(const uint8_t *key, uint32_t sid,
                                             const uint8_t *nonce, size_t nonce_len,
                                             uint8_t *out, size_t len,
                                             uint64_t dispatch_seed) {
    uint32_t variant = cprisk_select_keystream_variant(sid, nonce, nonce_len, dispatch_seed);
    if ((variant & 1u) == 0u) {
        cprisk_keystream_dispatch_level2(variant, key, sid, nonce, nonce_len, out, len);
    } else {
        cprisk_keystream_dispatch_level2(variant ^ 0u, key, sid, nonce, nonce_len, out, len);
    }
}

static void cprisk_keystream_distributed(const uint8_t *key, uint32_t sid,
                                         const uint8_t *nonce, size_t nonce_len,
                                         uint8_t *out, size_t len,
                                         uint64_t dispatch_seed) {
    if (!key || !out || nonce_len > CPRISK_ARMOR_NONCE_SIZE || len == 0) {
        return;
    }
    cprisk_keystream_dispatch_level1(key, sid, nonce, nonce_len, out, len, dispatch_seed);
}

/* ── per-string key derivation ─────────────────────────────────────── */

static void cprisk_derive_per_string_key(
    uint32_t string_id,
    const uint8_t *nonce
) {
    uint8_t material[4 + CPRISK_ARMOR_NONCE_SIZE];
    material[0] = (uint8_t)(string_id);
    material[1] = (uint8_t)(string_id >> 8);
    material[2] = (uint8_t)(string_id >> 16);
    material[3] = (uint8_t)(string_id >> 24);
    memcpy(material + 4, nonce, CPRISK_ARMOR_NONCE_SIZE);

    cprisk_hmac_sha256(s_dec_key, CPRISK_ARMOR_KEY_SIZE,
                       material, sizeof(material), s_per_string_key);
    cprisk_secure_zero(material, sizeof(material));
}

/* ── public API ────────────────────────────────────────────────────── */

int cprisk_init_string_decryptor(const uint8_t *key, size_t key_len) {
    if (!key || key_len != CPRISK_ARMOR_KEY_SIZE)
        return -1;
    memcpy(s_dec_key, key, CPRISK_ARMOR_KEY_SIZE);
    s_dispatch_seed = cprisk_derive_dispatch_seed(key, key_len);
    atomic_store(&s_dec_ready, 1);
    s_str_acc = 0;
    return 0;
}

int cprisk_decrypt_string(uint32_t string_id, char *buffer, size_t buffer_size) {
    if (!atomic_load(&s_dec_ready) || !buffer || buffer_size == 0)
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
    if (dlen == 0 || dlen >= buffer_size)
        return -1;
    size_t data_block_sz = sec_sz - data_base;
    size_t data_end = (size_t)ent->data_offset + (size_t)dlen;
    if (data_end < (size_t)dlen || data_end < (size_t)ent->data_offset)
        return -1;
    if ((size_t)ent->data_offset >= data_block_sz ||
        (size_t)dlen > data_block_sz ||
        data_end > data_block_sz)
        return -1;

    const uint8_t *enc = sec + data_base + ent->data_offset;

    /* Verify HMAC-SHA256(key, nonce || ciphertext) before decrypting */
    {
        if ((size_t)dlen > SIZE_MAX - CPRISK_ARMOR_NONCE_SIZE)
            return -1;
        size_t hmac_msg_len = CPRISK_ARMOR_NONCE_SIZE + dlen;
        uint8_t *hmac_msg = NULL;
        hmac_msg = (uint8_t *)malloc(hmac_msg_len);
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

    uint8_t *ks = NULL;
    ks = (uint8_t *)malloc(dlen);
    if (!ks)
        return -1;
    memset(ks, 0, dlen);
    cprisk_derive_per_string_key(string_id, ent->nonce);
    cprisk_keystream_distributed(s_per_string_key, string_id,
                                 ent->nonce, CPRISK_ARMOR_NONCE_SIZE, ks, dlen,
                                 s_dispatch_seed);

    for (uint32_t i = 0; i < dlen; i++)
        buffer[i] = (char)(enc[i] ^ ks[i]);
    buffer[dlen] = '\0';

    uint8_t dh[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256((const uint8_t *)buffer, dlen, dh);
    uint64_t hv;
    memcpy(&hv, dh, sizeof(hv));
    s_str_acc ^= cprisk_rotl64(hv, string_id % 64);

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Subtle byte-level corruption under debugger; fixed accumulator poison
       ensures downstream key derivation also silently fails. */
    if (cprisk_is_being_traced_redundant()) {
        for (uint32_t pi = 0; pi < dlen; pi++)
            buffer[pi] ^= 0x01;
        s_str_acc = 0xDEADBEEFCAFEBABEULL;
    }
#endif

    cprisk_secure_zero(ks, dlen);
    free(ks);
    cprisk_secure_zero(dh, sizeof(dh));

    if (dlen > (uint32_t)INT_MAX)
        return -1;
    return (int)dlen;
}

uint64_t cprisk_get_string_integrity_accumulator(void) {
    return s_str_acc;
}

int cprisk_decrypt_string_lazy(uint32_t string_id, char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0)
        return -1;
    if (s_lazy_valid != 0 && s_lazy_id == string_id && s_lazy_len > 0 && (size_t)s_lazy_len < buffer_size) {
        memcpy(buffer, s_lazy_buf, (size_t)s_lazy_len + 1u);
        return s_lazy_len;
    }
    int r = cprisk_decrypt_string(string_id, buffer, buffer_size);
    if (r > 0 && r < (int)sizeof(s_lazy_buf)) {
        memcpy(s_lazy_buf, buffer, (size_t)r + 1u);
        s_lazy_id = string_id;
        s_lazy_len = r;
        s_lazy_valid = 1;
    }
    return r;
}

void cprisk_string_lazy_scrub_all(void) {
    cprisk_secure_zero(s_lazy_buf, sizeof(s_lazy_buf));
    s_lazy_valid = 0;
    s_lazy_len = 0;
    s_lazy_id = 0u;
}

void cprisk_cleanup_string_decryptor(void) {
    cprisk_string_lazy_scrub_all();
    cprisk_secure_zero(s_dec_key, sizeof(s_dec_key));
    cprisk_secure_zero(s_per_string_key, sizeof(s_per_string_key));
    atomic_store(&s_dec_ready, 0);
    /* Use cprisk_secure_zero (volatile + memset) for the integrity
     * accumulator and dispatch seed too — even though both are static
     * uint64s where a plain assignment is observable, the explicit
     * secure_zero matches the pattern used by the rest of the file and
     * documents that "this is sensitive material, scrub it" rather than
     * just "this is a value reset". */
    cprisk_secure_zero(&s_str_acc, sizeof(s_str_acc));
    cprisk_secure_zero(&s_dispatch_seed, sizeof(s_dispatch_seed));
}

uint32_t cprisk_test_select_string_decrypt_path(
    uint32_t string_id,
    const uint8_t nonce[CPRISK_ARMOR_NONCE_SIZE],
    uint64_t seed
) {
    if (!nonce) {
        return 0;
    }
    return cprisk_select_keystream_variant(
        string_id,
        nonce,
        CPRISK_ARMOR_NONCE_SIZE,
        seed
    );
}
