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
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

_Static_assert(CPRISK_SHA256_DIGEST_LENGTH == CPRISK_ARMOR_HASH_SIZE,
               "inline SHA256 digest size must match armor ABI");

/* ── internal ──────────────────────────────────────────────────────── */

/* Single-thread assumption: cprisk_init_protection / cprisk_prepare_deception_material_i
 * are called from Swift start() before any concurrent evaluate(). s_runtime_material_ready,
 * s_deception_material_ready are not atomic; use _Atomic or pthread_once if multi-threaded. */
static uint8_t s_runtime_material[CPRISK_ARMOR_HASH_SIZE];
static int s_runtime_material_ready;

static int s_integrity_deception_active;
static uint8_t s_deception_material[CPRISK_ARMOR_HASH_SIZE];
static int s_deception_material_ready;

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

static uint64_t cprisk_u64_from_le_i(const uint8_t in[8]) {
    return ((uint64_t)in[0]) |
           ((uint64_t)in[1] << 8) |
           ((uint64_t)in[2] << 16) |
           ((uint64_t)in[3] << 24) |
           ((uint64_t)in[4] << 32) |
           ((uint64_t)in[5] << 40) |
           ((uint64_t)in[6] << 48) |
           ((uint64_t)in[7] << 56);
}

static uint64_t cprisk_rotl64_i(uint64_t value, unsigned int shift) {
    shift &= 63U;
    if (shift == 0U)
        return value;
    return (value << shift) | (value >> (64U - shift));
}

enum {
    CPRISK_WHITEBOX_DOMAIN_ANCHOR_TAG_I = 1u,
    CPRISK_WHITEBOX_DOMAIN_PASS1_STRING_KEY_I = 2u,
    CPRISK_WHITEBOX_DOMAIN_ANCHOR_ACCUMULATOR_SEED_I = 3u,
    CPRISK_WHITEBOX_DOMAIN_LOADER_KEY_I = 4u,
    CPRISK_WHITEBOX_DOMAIN_RUNTIME_MATERIAL_I = 5u
};

int cprisk_whitebox_evaluate_domain(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
);

static int cprisk_derive_pass1_string_key_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]
) {
    static const uint8_t label[] = "cprisk.pass1.key.v1";
    uint8_t digest[CPRISK_SHA256_DIGEST_LENGTH];

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, label, sizeof(label) - 1U);
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_final(&ctx, digest);

    memcpy(out_key, digest, CPRISK_ARMOR_KEY_SIZE);
    cprisk_secure_zero(digest, sizeof(digest));
    return 0;
}

static uint64_t cprisk_anchor_bound_accumulator_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    static const uint8_t label[] = "cprisk.pass1.acc.v2";
    uint8_t digest[CPRISK_SHA256_DIGEST_LENGTH];

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, label, sizeof(label) - 1U);
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_final(&ctx, digest);

    uint64_t acc = cprisk_u64_from_le_i(digest);
    cprisk_secure_zero(digest, sizeof(digest));
    return cprisk_rotl64_i(acc, 7U);
}

static void cprisk_mix_stable_deception_context_i(cprisk_sha256_ctx *ctx) {
    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    uint8_t hdr_le[8];
    uint8_t self_le[8];
    uint8_t pid_le[8];
    uint8_t elapsed_le[8];

    cprisk_u64_to_le_i((uint64_t)(uintptr_t)hdr, hdr_le);
    cprisk_u64_to_le_i((uint64_t)(uintptr_t)cprisk_get_runtime_material, self_le);
    cprisk_u64_to_le_i((uint64_t)cprisk_getpid_direct(), pid_le);
    cprisk_u64_to_le_i(s_init_elapsed_ns, elapsed_le);

    cprisk_sha256_update(ctx, hdr_le, sizeof(hdr_le));
    cprisk_sha256_update(ctx, self_le, sizeof(self_le));
    cprisk_sha256_update(ctx, pid_le, sizeof(pid_le));
    cprisk_sha256_update(ctx, elapsed_le, sizeof(elapsed_le));

    cprisk_secure_zero(hdr_le, sizeof(hdr_le));
    cprisk_secure_zero(self_le, sizeof(self_le));
    cprisk_secure_zero(pid_le, sizeof(pid_le));
    cprisk_secure_zero(elapsed_le, sizeof(elapsed_le));
}

static void cprisk_derive_decoy_material_i(
    const uint8_t *root_material,
    const uint8_t *full_anchor_hash,
    const uint8_t *integrity_hash,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    static const uint8_t label[] = "cprisk.runtime.decoy.v1";
    static const uint8_t missing_root[] = "missing-root";
    static const uint8_t missing_anchor[] = "missing-anchor";
    static const uint8_t missing_integrity[] = "missing-integrity";

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, label, sizeof(label) - 1U);

    if (root_material)
        cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    else
        cprisk_sha256_update(&ctx, missing_root, sizeof(missing_root) - 1U);

    if (full_anchor_hash)
        cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    else
        cprisk_sha256_update(&ctx, missing_anchor, sizeof(missing_anchor) - 1U);

    if (integrity_hash)
        cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    else
        cprisk_sha256_update(&ctx, missing_integrity, sizeof(missing_integrity) - 1U);

    cprisk_mix_stable_deception_context_i(&ctx);
    cprisk_sha256_final(&ctx, out_hash);
}

static void cprisk_prepare_deception_material_i(
    const uint8_t *root_material,
    const uint8_t *full_anchor_hash,
    const uint8_t *integrity_hash
) {
    if (s_deception_material_ready)
        return;
    cprisk_derive_decoy_material_i(
        root_material, full_anchor_hash, integrity_hash, s_deception_material);
    s_deception_material_ready = 1;
}

static int cprisk_should_activate_deception_i(void) {
    if (cprisk_is_being_traced())
        return 1;
    if (cprisk_is_mprotect_tampered())
        return 1;
    if (cprisk_check_init_timing())
        return 1;
    return 0;
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

static void cprisk_sha256_concat2_i(
    const uint8_t *a,
    size_t a_len,
    const uint8_t *b,
    size_t b_len,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, a, a_len);
    cprisk_sha256_update(&ctx, b, b_len);
    cprisk_sha256_final(&ctx, out_hash);
}

static void cprisk_sha256_concat3_i(
    const uint8_t *a,
    size_t a_len,
    const uint8_t *b,
    size_t b_len,
    const uint8_t *c,
    size_t c_len,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, a, a_len);
    cprisk_sha256_update(&ctx, b, b_len);
    cprisk_sha256_update(&ctx, c, c_len);
    cprisk_sha256_final(&ctx, out_hash);
}

static void cprisk_sha256_concat4_i(
    const uint8_t *a,
    size_t a_len,
    const uint8_t *b,
    size_t b_len,
    const uint8_t *c,
    size_t c_len,
    const uint8_t *d,
    size_t d_len,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, a, a_len);
    cprisk_sha256_update(&ctx, b, b_len);
    cprisk_sha256_update(&ctx, c, c_len);
    cprisk_sha256_update(&ctx, d, d_len);
    cprisk_sha256_final(&ctx, out_hash);
}

static int cprisk_verify_anchor_whitebox_i(
    const uint8_t full_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    unsigned long sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_FULL_HASH, &sz);
    if (!sec || sz != CPRISK_ARMOR_HASH_SIZE)
        return -1;

    uint8_t computed_tag[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_ANCHOR_TAG_I,
            full_hash,
            computed_tag) != 0) {
        return -1;
    }

    const int rc = cprisk_hmac_verify(sec, computed_tag, CPRISK_ARMOR_HASH_SIZE);
    cprisk_secure_zero(computed_tag, sizeof(computed_tag));
    return rc;
}

static int cprisk_init_protection_legacy_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity[CPRISK_ARMOR_HASH_SIZE]
) {
    uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE];
    uint64_t string_acc = 0;
    int rc = -1;
    memset(loader_key, 0, sizeof(loader_key));

    if (cprisk_verify_anchor_hmac(root_material, full_anchor_hash) != 0) {
        rc = -4;
        goto cleanup;
    }

    string_acc = cprisk_anchor_bound_accumulator_i(
        root_material, full_anchor_hash, integrity);

    {
        uint8_t pass1_string_key[CPRISK_ARMOR_KEY_SIZE];
        cprisk_derive_pass1_string_key_i(root_material, pass1_string_key);
        if (cprisk_init_string_decryptor(pass1_string_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
            cprisk_secure_zero(pass1_string_key, sizeof(pass1_string_key));
            rc = -5;
            goto cleanup;
        }
        cprisk_secure_zero(pass1_string_key, sizeof(pass1_string_key));
    }

    cprisk_prepare_deception_material_i(
        root_material, full_anchor_hash, integrity);

    cprisk_derive_loader_key_i(
        root_material,
        full_anchor_hash,
        integrity,
        string_acc,
        loader_key);

    if (cprisk_init_data_loader(loader_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -6;
        goto cleanup;
    }

    if (cprisk_load_protected_data() < 0) {
        cprisk_unload_protected_data();
        rc = -7;
        goto cleanup;
    }

    cprisk_derive_runtime_material_i(
        root_material,
        full_anchor_hash,
        integrity,
        string_acc,
        cprisk_get_data_integrity_accumulator(),
        s_runtime_material);
    s_runtime_material_ready = 1;
    rc = 0;

cleanup:
    cprisk_secure_zero(loader_key, sizeof(loader_key));
    return rc;
}

static int cprisk_init_protection_whitebox_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity[CPRISK_ARMOR_HASH_SIZE]
) {
    uint8_t pass1_key[CPRISK_ARMOR_KEY_SIZE];
    uint8_t acc_digest[CPRISK_ARMOR_HASH_SIZE];
    uint8_t acc_seed[CPRISK_ARMOR_HASH_SIZE];
    uint8_t loader_digest[CPRISK_ARMOR_HASH_SIZE];
    uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE];
    uint8_t runtime_digest[CPRISK_ARMOR_HASH_SIZE];
    uint8_t anchor_acc_le[8];
    uint8_t string_acc_le[8];
    uint8_t data_acc_le[8];
    uint64_t anchor_accumulator = 0;
    int rc = -1;

    memset(pass1_key, 0, sizeof(pass1_key));
    memset(acc_digest, 0, sizeof(acc_digest));
    memset(acc_seed, 0, sizeof(acc_seed));
    memset(loader_digest, 0, sizeof(loader_digest));
    memset(loader_key, 0, sizeof(loader_key));
    memset(runtime_digest, 0, sizeof(runtime_digest));
    memset(anchor_acc_le, 0, sizeof(anchor_acc_le));
    memset(string_acc_le, 0, sizeof(string_acc_le));
    memset(data_acc_le, 0, sizeof(data_acc_le));

    if (cprisk_verify_anchor_whitebox_i(full_anchor_hash) != 0) {
        cprisk_force_integrity_poison();
        rc = -4;
        goto cleanup;
    }

    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_PASS1_STRING_KEY_I,
            NULL,
            pass1_key) != 0) {
        cprisk_force_integrity_poison();
        rc = -5;
        goto cleanup;
    }
    if (cprisk_init_string_decryptor(pass1_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -5;
        goto cleanup;
    }

    cprisk_prepare_deception_material_i(
        root_material, full_anchor_hash, integrity);

    cprisk_sha256_concat2_i(full_anchor_hash,
                            CPRISK_ARMOR_HASH_SIZE,
                            integrity,
                            CPRISK_ARMOR_HASH_SIZE,
                            acc_digest);
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_ANCHOR_ACCUMULATOR_SEED_I,
            acc_digest,
            acc_seed) != 0) {
        cprisk_force_integrity_poison();
        rc = -6;
        goto cleanup;
    }
    anchor_accumulator = cprisk_rotl64_i(cprisk_u64_from_le_i(acc_seed), 7U);
    cprisk_u64_to_le_i(anchor_accumulator, anchor_acc_le);

    cprisk_sha256_concat3_i(full_anchor_hash,
                            CPRISK_ARMOR_HASH_SIZE,
                            integrity,
                            CPRISK_ARMOR_HASH_SIZE,
                            anchor_acc_le,
                            sizeof(anchor_acc_le),
                            loader_digest);
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_LOADER_KEY_I,
            loader_digest,
            loader_key) != 0) {
        cprisk_force_integrity_poison();
        rc = -6;
        goto cleanup;
    }

    if (cprisk_init_data_loader(loader_key, CPRISK_ARMOR_KEY_SIZE) != 0) {
        rc = -6;
        goto cleanup;
    }

    if (cprisk_load_protected_data() < 0) {
        cprisk_unload_protected_data();
        rc = -7;
        goto cleanup;
    }

    cprisk_u64_to_le_i(cprisk_get_string_integrity_accumulator(), string_acc_le);
    cprisk_u64_to_le_i(cprisk_get_data_integrity_accumulator(), data_acc_le);
    cprisk_sha256_concat4_i(full_anchor_hash,
                            CPRISK_ARMOR_HASH_SIZE,
                            integrity,
                            CPRISK_ARMOR_HASH_SIZE,
                            string_acc_le,
                            sizeof(string_acc_le),
                            data_acc_le,
                            sizeof(data_acc_le),
                            runtime_digest);
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_WHITEBOX_DOMAIN_RUNTIME_MATERIAL_I,
            runtime_digest,
            s_runtime_material) != 0) {
        cprisk_force_integrity_poison();
        cprisk_unload_protected_data();
        rc = -7;
        goto cleanup;
    }

    s_runtime_material_ready = 1;
    rc = 0;

cleanup:
    cprisk_secure_zero(pass1_key, sizeof(pass1_key));
    cprisk_secure_zero(acc_digest, sizeof(acc_digest));
    cprisk_secure_zero(acc_seed, sizeof(acc_seed));
    cprisk_secure_zero(loader_digest, sizeof(loader_digest));
    cprisk_secure_zero(loader_key, sizeof(loader_key));
    cprisk_secure_zero(runtime_digest, sizeof(runtime_digest));
    cprisk_secure_zero(anchor_acc_le, sizeof(anchor_acc_le));
    cprisk_secure_zero(string_acc_le, sizeof(string_acc_le));
    cprisk_secure_zero(data_acc_le, sizeof(data_acc_le));
    return rc;
}

/* ── Path A: Mach VM read ──────────────────────────────────────────── */

/* vm_size_t is 32-bit on Darwin; avoid truncation when sz > UINT32_MAX */
#define CPRISK_VM_READ_CHUNK_MAX ((size_t)0xFFFFFFFFUL)

static int path_a(const struct mach_header_64 *hdr, uint8_t *out) {
    unsigned long sz = 0;
    const uint8_t *text = cprisk_find_section(hdr, "__TEXT", "__text", &sz);
    if (!text || sz == 0)
        return -1;

    uint8_t *buf = NULL;
    buf = (uint8_t *)malloc(sz);
    if (!buf)
        return -1;

    size_t total_read = 0;
    size_t offset = 0;
    while (offset < sz) {
        size_t to_read = sz - offset;
        if (to_read > CPRISK_VM_READ_CHUNK_MAX)
            to_read = CPRISK_VM_READ_CHUNK_MAX;

        vm_size_t vmsz = (vm_size_t)to_read;
        vm_size_t out_sz = vmsz;
        kern_return_t kr = vm_read_overwrite(
            mach_task_self(),
            (vm_address_t)(text + offset),
            vmsz,
            (vm_address_t)(buf + offset),
            &out_sz);
        if (kr != KERN_SUCCESS) {
            cprisk_secure_zero(buf, total_read);
            free(buf);
            return -1;
        }
        total_read += (size_t)out_sz;
        offset += (size_t)out_sz;
        if (out_sz < vmsz)
            break;
    }

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    size_t rem = total_read;
    const uint8_t *p = buf;
    while (rem > 0) {
        size_t chunk = (rem > 0x40000000UL) ? 0x40000000UL : rem;
        cprisk_sha256_update(&ctx, p, chunk);
        p   += chunk;
        rem -= chunk;
    }
    cprisk_sha256_final(&ctx, out);

    cprisk_secure_zero(buf, total_read);
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
    uint64_t abs_time = mach_absolute_time();
    /* Avoid overflow: split multiply to prevent abs_time * numer from wrapping. */
    return abs_time / tb.denom * tb.numer + (abs_time % tb.denom) * tb.numer / tb.denom;
}

int cprisk_init_protection(const uint8_t *root_key, size_t root_key_len) {
    uint64_t t_start = cprisk_monotonic_ns();

    uint8_t root_material[CPRISK_ARMOR_KEY_SIZE];
    uint8_t integrity[CPRISK_ARMOR_HASH_SIZE];
    uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE];
    int rc = -1;

    s_integrity_poisoned = 0;
    s_integrity_hash_saved = 0;
    s_integrity_deception_active = 0;
    s_runtime_material_ready = 0;
    s_deception_material_ready = 0;
    cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
    cprisk_secure_zero(s_saved_integrity_hash, sizeof(s_saved_integrity_hash));
    cprisk_secure_zero(s_deception_material, sizeof(s_deception_material));

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

    if (cprisk_compute_integrity_hash(integrity) != 0) {
        rc = -2;
        goto cleanup;
    }

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Inline single-step timing probe: ~100 arithmetic ops complete in
       microseconds normally; >50ms indicates instruction-level tracing. */
    {
        uint64_t t_probe_0 = cprisk_monotonic_ns();
        volatile uint32_t step_acc = 0x5A5A5A5Au;
        for (int step_j = 0; step_j < 100; step_j++)
            step_acc = step_acc * 0x01010101u + (uint32_t)step_j;
        (void)step_acc;
        uint64_t t_probe_1 = cprisk_monotonic_ns();
        if (t_probe_1 - t_probe_0 > 50000000ULL)
            s_integrity_deception_active = 1;
    }
#endif

    memcpy(s_saved_integrity_hash, integrity, CPRISK_ARMOR_HASH_SIZE);
    s_integrity_hash_saved = 1;

    if (cprisk_read_full_anchor_hash(full_anchor_hash) != 0) {
        rc = -3;
        goto cleanup;
    }

    if (cprisk_whitebox_available() != 0) {
        rc = cprisk_init_protection_whitebox_i(
            root_material,
            full_anchor_hash,
            integrity);
    } else {
        rc = cprisk_init_protection_legacy_i(
            root_material,
            full_anchor_hash,
            integrity);
    }

cleanup:
    if (rc != 0) {
        cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
        s_runtime_material_ready = 0;
    }

    cprisk_secure_zero(root_material, sizeof(root_material));
    cprisk_secure_zero(integrity, sizeof(integrity));
    cprisk_secure_zero(full_anchor_hash, sizeof(full_anchor_hash));

    s_init_elapsed_ns = cprisk_monotonic_ns() - t_start;
    return rc;
}

void cprisk_cleanup_protection(void) {
    cprisk_secure_zero(s_runtime_material, sizeof(s_runtime_material));
    cprisk_secure_zero(s_saved_integrity_hash, sizeof(s_saved_integrity_hash));
    s_runtime_material_ready = 0;
    cprisk_secure_zero(s_deception_material, sizeof(s_deception_material));
    s_deception_material_ready = 0;
    s_integrity_hash_saved = 0;
    s_integrity_poisoned = 0;
    s_integrity_deception_active = 0;
    s_init_elapsed_ns = 0;
    cprisk_cleanup_string_decryptor();
    cprisk_unload_protected_data();
}

int cprisk_get_runtime_material(uint8_t out_material[32]) {
    if (!out_material)
        return -1;

    if (s_integrity_poisoned || s_integrity_deception_active || !s_runtime_material_ready) {
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        memcpy(out_material, s_deception_material, CPRISK_ARMOR_HASH_SIZE);
        return 0;
    }

    memcpy(out_material, s_runtime_material, CPRISK_ARMOR_HASH_SIZE);
    return 0;
}

int cprisk_runtime_material_ready(void) {
    return s_runtime_material_ready ? 1 : 0;
}

int cprisk_recheck_integrity(void) {
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Under debugger: report "all clear" but silently activate deception */
    if (cprisk_is_being_traced()) {
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        s_integrity_deception_active = 1;
        return 0;
    }
#endif

    if (!s_integrity_hash_saved)
        return -1;

    uint8_t current[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_compute_integrity_hash(current) != 0) {
        s_integrity_poisoned = 1;
        if (cprisk_should_activate_deception_i()) {
            cprisk_prepare_deception_material_i(NULL, NULL, NULL);
            s_integrity_deception_active = 1;
        }
        cprisk_secure_zero(current, sizeof(current));
        return -2;
    }

    uint8_t diff = 0;
    for (int i = 0; i < CPRISK_ARMOR_HASH_SIZE; i++)
        diff |= current[i] ^ s_saved_integrity_hash[i];

    cprisk_secure_zero(current, sizeof(current));

    if (diff != 0) {
        s_integrity_poisoned = 1;
        if (cprisk_should_activate_deception_i()) {
            cprisk_prepare_deception_material_i(NULL, NULL, NULL);
            s_integrity_deception_active = 1;
        }
        return 1;
    }
    return 0;
}

int cprisk_is_integrity_poisoned(void) {
    if (s_integrity_deception_active)
        return 0;
    return s_integrity_poisoned;
}

void cprisk_force_integrity_poison(void) {
    s_integrity_poisoned = 1;
    if (cprisk_should_activate_deception_i()) {
        cprisk_prepare_deception_material_i(NULL, NULL, NULL);
        s_integrity_deception_active = 1;
    }
}

uint64_t cprisk_get_init_elapsed_ns(void) {
    return s_init_elapsed_ns;
}

int cprisk_check_init_timing(void) {
    /* 5 seconds in nanoseconds — if init took longer, likely DBI-traced */
    return s_init_elapsed_ns > 5000000000ULL ? 1 : 0;
}

void cprisk_test_secure_zero(void *buf, size_t len) {
    cprisk_secure_zero(buf, len);
}
