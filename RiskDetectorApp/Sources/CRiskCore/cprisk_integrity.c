/*
 * CRiskCore - Multi-path integrity verification for cprisk-armor ABI v2.
 * Three independent paths compute the __TEXT.__text hash; path C reconstructs
 * the digest from the four split anchor sections. The HMAC anchor tag is
 * verified against the reconstructed hash using the root key.
 * The combined result feeds key derivation, so tampering silently corrupts
 * the derived key.
 */

#include "include/CRiskCore.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

_Static_assert(CPRISK_SHA256_DIGEST_LENGTH == CPRISK_ARMOR_HASH_SIZE,
               "inline SHA256 digest size must match armor ABI");

/* ── internal ──────────────────────────────────────────────────────── */

static uint8_t s_runtime_material[CPRISK_ARMOR_HASH_SIZE];
static int s_runtime_material_ready;

static uint8_t s_poison_material[CPRISK_ARMOR_HASH_SIZE];
static int s_poison_material_ready;

static uint8_t s_root_material[CPRISK_ARMOR_KEY_SIZE];
static uint8_t s_salt_xor_key;

static void cprisk_szero_i(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

static uint8_t s_saved_integrity_hash[CPRISK_ARMOR_HASH_SIZE];
static int s_integrity_hash_saved;
static int s_integrity_poisoned;

static uint64_t s_init_elapsed_ns;

static const struct mach_header_64 *cprisk_own_hdr_i(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr_i);
}

static void cprisk_fill_root_material_i(const uint8_t *root_key,
                                        size_t root_key_len,
                                        uint8_t out[CPRISK_ARMOR_KEY_SIZE]) {
    memset(out, 0, CPRISK_ARMOR_KEY_SIZE);
    if (!root_key || root_key_len == 0)
        return;

    size_t copy_len = root_key_len;
    if (copy_len > CPRISK_ARMOR_KEY_SIZE)
        copy_len = CPRISK_ARMOR_KEY_SIZE;
    memcpy(out, root_key, copy_len);
}

static void cprisk_u64_to_le_i(uint64_t value, uint8_t out[8]) {
    out[0] = (uint8_t)(value);
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
    out[4] = (uint8_t)(value >> 32);
    out[5] = (uint8_t)(value >> 40);
    out[6] = (uint8_t)(value >> 48);
    out[7] = (uint8_t)(value >> 56);
}

static void cprisk_derive_string_key_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]
) {
    static const uint8_t label_enc_default[] = {
        'c'^CPRISK_SALT_XOR_KEY_DEFAULT, 'p'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'r'^CPRISK_SALT_XOR_KEY_DEFAULT, 'i'^CPRISK_SALT_XOR_KEY_DEFAULT,
        's'^CPRISK_SALT_XOR_KEY_DEFAULT, 'k'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'p'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'a'^CPRISK_SALT_XOR_KEY_DEFAULT, 's'^CPRISK_SALT_XOR_KEY_DEFAULT,
        's'^CPRISK_SALT_XOR_KEY_DEFAULT, '1'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'k'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'e'^CPRISK_SALT_XOR_KEY_DEFAULT, 'y'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'v'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '1'^CPRISK_SALT_XOR_KEY_DEFAULT
    };
    char label[sizeof(label_enc_default) + 1];
    cprisk_decode_salt(label_enc_default, sizeof(label_enc_default),
                       CPRISK_SALT_XOR_KEY_DEFAULT, label);

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, (const uint8_t *)label, sizeof(label_enc_default));
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_final(&ctx, out_key);

    cprisk_secure_zero(label, sizeof(label));
}

static void cprisk_derive_loader_key_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity_hash[CPRISK_ARMOR_HASH_SIZE],
    uint64_t string_acc,
    uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]
) {
    static const uint8_t label_enc_default[] = {
        'c'^CPRISK_SALT_XOR_KEY_DEFAULT, 'p'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'r'^CPRISK_SALT_XOR_KEY_DEFAULT, 'i'^CPRISK_SALT_XOR_KEY_DEFAULT,
        's'^CPRISK_SALT_XOR_KEY_DEFAULT, 'k'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'p'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'a'^CPRISK_SALT_XOR_KEY_DEFAULT, 's'^CPRISK_SALT_XOR_KEY_DEFAULT,
        's'^CPRISK_SALT_XOR_KEY_DEFAULT, '3'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'k'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'e'^CPRISK_SALT_XOR_KEY_DEFAULT, 'y'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'v'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '1'^CPRISK_SALT_XOR_KEY_DEFAULT
    };
    char label[sizeof(label_enc_default) + 1];
    cprisk_decode_salt(label_enc_default, sizeof(label_enc_default),
                       CPRISK_SALT_XOR_KEY_DEFAULT, label);

    uint8_t acc_le[8];
    cprisk_u64_to_le_i(string_acc, acc_le);

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, (const uint8_t *)label, sizeof(label_enc_default));
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, acc_le, sizeof(acc_le));
    cprisk_sha256_final(&ctx, out_key);

    cprisk_secure_zero(label, sizeof(label));
    cprisk_secure_zero(acc_le, sizeof(acc_le));
}

static void cprisk_derive_runtime_material_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity_hash[CPRISK_ARMOR_HASH_SIZE],
    uint64_t string_acc,
    uint64_t data_acc,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    static const uint8_t label_enc_default[] = {
        'c'^CPRISK_SALT_XOR_KEY_DEFAULT, 'p'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'r'^CPRISK_SALT_XOR_KEY_DEFAULT, 'i'^CPRISK_SALT_XOR_KEY_DEFAULT,
        's'^CPRISK_SALT_XOR_KEY_DEFAULT, 'k'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'r'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'u'^CPRISK_SALT_XOR_KEY_DEFAULT, 'n'^CPRISK_SALT_XOR_KEY_DEFAULT,
        't'^CPRISK_SALT_XOR_KEY_DEFAULT, 'i'^CPRISK_SALT_XOR_KEY_DEFAULT,
        'm'^CPRISK_SALT_XOR_KEY_DEFAULT, 'e'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 's'^CPRISK_SALT_XOR_KEY_DEFAULT,
        't'^CPRISK_SALT_XOR_KEY_DEFAULT, 'a'^CPRISK_SALT_XOR_KEY_DEFAULT,
        't'^CPRISK_SALT_XOR_KEY_DEFAULT, 'e'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '.'^CPRISK_SALT_XOR_KEY_DEFAULT, 'v'^CPRISK_SALT_XOR_KEY_DEFAULT,
        '1'^CPRISK_SALT_XOR_KEY_DEFAULT
    };
    char label[sizeof(label_enc_default) + 1];
    cprisk_decode_salt(label_enc_default, sizeof(label_enc_default),
                       CPRISK_SALT_XOR_KEY_DEFAULT, label);

    uint8_t str_le[8];
    uint8_t data_le[8];
    cprisk_u64_to_le_i(string_acc, str_le);
    cprisk_u64_to_le_i(data_acc, data_le);

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, (const uint8_t *)label, sizeof(label_enc_default));
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, str_le, sizeof(str_le));
    cprisk_sha256_update(&ctx, data_le, sizeof(data_le));
    cprisk_sha256_final(&ctx, out_hash);

    cprisk_secure_zero(label, sizeof(label));
    cprisk_secure_zero(str_le, sizeof(str_le));
    cprisk_secure_zero(data_le, sizeof(data_le));
}

/* ── Path A: Mach VM read ──────────────────────────────────────────── */

static int path_a(const struct mach_header_64 *hdr, uint8_t *out) {
    unsigned long sz = 0;
    const uint8_t *text = cprisk_find_section(hdr, "__TEXT", "__text", &sz);
    if (!text || sz == 0)
        return -1;

    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf)
        return -1;

    vm_size_t out_sz = (vm_size_t)sz;
    kern_return_t kr = vm_read_overwrite(
        mach_task_self(),
        (vm_address_t)text,
        (vm_size_t)sz,
        (vm_address_t)buf,
        &out_sz);
    if (kr != KERN_SUCCESS) {
        free(buf);
        return -1;
    }

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    size_t rem = (size_t)out_sz;
    const uint8_t *p = buf;
    while (rem > 0) {
        size_t chunk = (rem > 0x40000000UL) ? 0x40000000UL : rem;
        cprisk_sha256_update(&ctx, p, chunk);
        p   += chunk;
        rem -= chunk;
    }
    cprisk_sha256_final(&ctx, out);

    cprisk_secure_zero(buf, (size_t)out_sz);
    free(buf);
    return 0;
}

/* ── Path B: direct pointer read ───────────────────────────────────── */

static int path_b(const struct mach_header_64 *hdr, uint8_t *out) {
    unsigned long sz = 0;
    const uint8_t *text = cprisk_find_section(hdr, "__TEXT", "__text", &sz);
    if (!text || sz == 0)
        return -1;

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    size_t rem = sz;
    const uint8_t *p = text;
    while (rem > 0) {
        size_t chunk = (rem > 0x40000000UL) ? 0x40000000UL : rem;
        cprisk_sha256_update(&ctx, p, chunk);
        p   += chunk;
        rem -= chunk;
    }
    cprisk_sha256_final(&ctx, out);

    return 0;
}

/* ── Path C: reassemble from split anchor sections ─────────────────── */

static int path_c(const struct mach_header_64 *hdr, uint8_t *out) {
    static const char *names[CPRISK_ARMOR_ANCHOR_LANE_COUNT] = {
        CPRISK_ARMOR_SECTION_ANCHOR_A,
        CPRISK_ARMOR_SECTION_ANCHOR_B,
        CPRISK_ARMOR_SECTION_ANCHOR_C,
        CPRISK_ARMOR_SECTION_ANCHOR_D
    };
    for (uint32_t i = 0; i < CPRISK_ARMOR_ANCHOR_LANE_COUNT; i++) {
        unsigned long sz = 0;
        const uint8_t *p = cprisk_find_section(
            hdr, CPRISK_ARMOR_SEGMENT_DATA, names[i], &sz);
        if (!p || sz < CPRISK_ARMOR_ANCHOR_LANE_SIZE)
            return -1;
        memcpy(out + i * CPRISK_ARMOR_ANCHOR_LANE_SIZE,
               p,
               CPRISK_ARMOR_ANCHOR_LANE_SIZE);
    }
    return 0;
}

/* ── public API ────────────────────────────────────────────────────── */

int cprisk_compute_integrity_hash(uint8_t *out_hash) {
    if (!out_hash)
        return -1;

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    uint8_t ha[CPRISK_SHA256_DIGEST_LENGTH];
    uint8_t hb[CPRISK_SHA256_DIGEST_LENGTH];
    uint8_t hc[CPRISK_SHA256_DIGEST_LENGTH];

    int ra = path_a(hdr, ha);
    int rb = path_b(hdr, hb);
    int rc = path_c(hdr, hc);

    uint8_t cat[CPRISK_SHA256_DIGEST_LENGTH * 3];
    if (ra == 0)
        memcpy(cat, ha, CPRISK_SHA256_DIGEST_LENGTH);
    else
        memset(cat, 0xFF, CPRISK_SHA256_DIGEST_LENGTH);

    if (rb == 0)
        memcpy(cat + CPRISK_SHA256_DIGEST_LENGTH, hb, CPRISK_SHA256_DIGEST_LENGTH);
    else
        memset(cat + CPRISK_SHA256_DIGEST_LENGTH, 0xFF, CPRISK_SHA256_DIGEST_LENGTH);

    if (rc == 0)
        memcpy(cat + 2 * CPRISK_SHA256_DIGEST_LENGTH, hc, CPRISK_SHA256_DIGEST_LENGTH);
    else
        memset(cat + 2 * CPRISK_SHA256_DIGEST_LENGTH, 0xFF, CPRISK_SHA256_DIGEST_LENGTH);

    cprisk_sha256(cat, sizeof(cat), out_hash);

    cprisk_secure_zero(ha, sizeof(ha));
    cprisk_secure_zero(hb, sizeof(hb));
    cprisk_secure_zero(hc, sizeof(hc));
    cprisk_secure_zero(cat, sizeof(cat));

    return 0;
}

int cprisk_read_full_anchor_hash(uint8_t *out_hash) {
    if (!out_hash)
        return -1;

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    /* ABI v2: reconstruct fullHash from split anchor lanes */
    return path_c(hdr, out_hash);
}

int cprisk_verify_anchor_hmac(const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
                              const uint8_t full_hash[CPRISK_ARMOR_HASH_SIZE]) {
    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    unsigned long sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_FULL_HASH, &sz);
    if (!sec || sz < CPRISK_ARMOR_HMAC_FULL_HASH_SECTION_SIZE)
        return -1;

    uint8_t computed_hmac[CPRISK_ARMOR_HASH_SIZE];
    cprisk_hmac_sha256(root_material, CPRISK_ARMOR_KEY_SIZE,
                       full_hash, CPRISK_ARMOR_HASH_SIZE,
                       computed_hmac);

    int result = cprisk_hmac_verify(sec, computed_hmac, CPRISK_ARMOR_HASH_SIZE);
    cprisk_secure_zero(computed_hmac, sizeof(computed_hmac));
    return result;
}

static uint64_t cprisk_monotonic_ns(void) {
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0)
        mach_timebase_info(&tb);
    if (tb.denom == 0)
        return 0;
    return mach_absolute_time() * tb.numer / tb.denom;
}

int cprisk_init_protection(const uint8_t *root_key, size_t root_key_len) {
    uint64_t t_start = cprisk_monotonic_ns();

    uint8_t root_material[CPRISK_ARMOR_KEY_SIZE];
    uint8_t string_key[CPRISK_ARMOR_KEY_SIZE];
    uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE];
    uint8_t integrity[CPRISK_ARMOR_HASH_SIZE];
    uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE];
    char bootstrap[128];
    int rc = -1;

    s_integrity_poisoned = 0;
    s_integrity_hash_saved = 0;

    cprisk_fill_root_material_i(root_key, root_key_len, root_material);

    /* Reject NULL or all-zero root keys */
    {
        int all_zero = 1;
        for (int zi = 0; zi < CPRISK_ARMOR_KEY_SIZE; zi++) {
            if (root_material[zi] != 0) { all_zero = 0; break; }
        }
        if (all_zero) {
            rc = -1;
            goto cleanup;
        }
    }

    /* Derive and store salt XOR key from root material */
    s_salt_xor_key = cprisk_derive_salt_xor_key(root_material);
    memcpy(s_root_material, root_material, CPRISK_ARMOR_KEY_SIZE);

    cprisk_derive_string_key_i(root_material, string_key);
    if (cprisk_init_string_decryptor(string_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -2;
        goto cleanup;
    }

    int bootstrap_len = cprisk_decrypt_string(
        CPRISK_ARMOR_BOOTSTRAP_STRING_ID, bootstrap, sizeof(bootstrap));
    if (bootstrap_len < 0) {
        rc = -3;
        goto cleanup;
    }
    cprisk_secure_zero(bootstrap, sizeof(bootstrap));

    if (cprisk_compute_integrity_hash(integrity) != 0) {
        rc = -4;
        goto cleanup;
    }

    memcpy(s_saved_integrity_hash, integrity, CPRISK_ARMOR_HASH_SIZE);
    s_integrity_hash_saved = 1;

    if (cprisk_read_full_anchor_hash(full_anchor_hash) != 0) {
        rc = -5;
        goto cleanup;
    }

    /* Verify HMAC anchor tag against reconstructed full hash */
    if (cprisk_verify_anchor_hmac(root_material, full_anchor_hash) != 0) {
        rc = -5;
        goto cleanup;
    }

    cprisk_derive_loader_key_i(
        root_material,
        full_anchor_hash,
        integrity,
        cprisk_get_string_integrity_accumulator(),
        loader_key);

    if (cprisk_init_data_loader(loader_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -6;
        goto cleanup;
    }

    int loaded = cprisk_load_protected_data();
    if (loaded < 0) {
        cprisk_unload_protected_data();
        rc = -7;
        goto cleanup;
    }

    cprisk_derive_runtime_material_i(
        root_material,
        full_anchor_hash,
        integrity,
        cprisk_get_string_integrity_accumulator(),
        cprisk_get_data_integrity_accumulator(),
        s_runtime_material);
    s_runtime_material_ready = 1;
    rc = 0;

cleanup:
    if (rc != 0) {
        cprisk_cleanup_string_decryptor();
        cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
        s_runtime_material_ready = 0;
    }

    cprisk_secure_zero(root_material, sizeof(root_material));
    cprisk_secure_zero(string_key, sizeof(string_key));
    cprisk_secure_zero(loader_key, sizeof(loader_key));
    cprisk_secure_zero(integrity, sizeof(integrity));
    cprisk_secure_zero(full_anchor_hash, sizeof(full_anchor_hash));
    cprisk_secure_zero(bootstrap, sizeof(bootstrap));

    s_init_elapsed_ns = cprisk_monotonic_ns() - t_start;
    return rc;
}

void cprisk_cleanup_protection(void) {
    cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
    cprisk_secure_zero(s_saved_integrity_hash, sizeof(s_saved_integrity_hash));
    cprisk_secure_zero(s_root_material, sizeof(s_root_material));
    s_runtime_material_ready = 0;
    cprisk_szero_i(s_poison_material, sizeof(s_poison_material));
    s_poison_material_ready = 0;
    s_integrity_hash_saved = 0;
    s_integrity_poisoned = 0;
    s_init_elapsed_ns = 0;
    cprisk_cleanup_string_decryptor();
    cprisk_unload_protected_data();
}

int cprisk_get_runtime_material(uint8_t out_material[32]) {
    if (!out_material)
        return -1;

    if (s_integrity_poisoned || !s_runtime_material_ready) {
        if (!s_poison_material_ready) {
            arc4random_buf(s_poison_material, CPRISK_ARMOR_HASH_SIZE);
            s_poison_material_ready = 1;
        }
        memcpy(out_material, s_poison_material, CPRISK_ARMOR_HASH_SIZE);
        return 0;
    }

    memcpy(out_material, s_runtime_material, CPRISK_ARMOR_HASH_SIZE);
    return 0;
}

int cprisk_recheck_integrity(void) {
    if (!s_integrity_hash_saved)
        return -1;

    uint8_t current[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_compute_integrity_hash(current) != 0) {
        s_integrity_poisoned = 1;
        cprisk_secure_zero(current, sizeof(current));
        return -2;
    }

    uint8_t diff = 0;
    for (int i = 0; i < CPRISK_ARMOR_HASH_SIZE; i++)
        diff |= current[i] ^ s_saved_integrity_hash[i];

    cprisk_secure_zero(current, sizeof(current));

    if (diff != 0) {
        s_integrity_poisoned = 1;
        return 1;
    }
    return 0;
}

int cprisk_is_integrity_poisoned(void) {
    return s_integrity_poisoned;
}

uint64_t cprisk_get_init_elapsed_ns(void) {
    return s_init_elapsed_ns;
}

void cprisk_test_secure_zero(void *buf, size_t len) {
    cprisk_secure_zero(buf, len);
}
