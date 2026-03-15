/*
 * CRiskCore - Multi-path integrity verification for cprisk-armor ABI v1.
 * Three independent paths compute the __TEXT.__text hash; path C reconstructs
 * the digest from the four split anchor sections. The combined result feeds
 * key derivation, so tampering silently corrupts the derived key.
 */

#include "include/CRiskCore.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"

_Static_assert(CPRISK_SHA256_DIGEST_LENGTH == CPRISK_ARMOR_HASH_SIZE,
               "inline SHA256 digest size must match armor ABI");

/* ── internal ──────────────────────────────────────────────────────── */

static uint8_t s_runtime_material[CPRISK_ARMOR_HASH_SIZE];
static int s_runtime_material_ready;

static void cprisk_szero_i(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

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
    static const uint8_t label_enc[] = {
        'c'^0xA7, 'p'^0xA7, 'r'^0xA7, 'i'^0xA7, 's'^0xA7, 'k'^0xA7,
        '.'^0xA7, 'p'^0xA7, 'a'^0xA7, 's'^0xA7, 's'^0xA7, '1'^0xA7,
        '.'^0xA7, 'k'^0xA7, 'e'^0xA7, 'y'^0xA7, '.'^0xA7, 'v'^0xA7, '1'^0xA7
    };
    char label[sizeof(label_enc) + 1];
    cprisk_decode_salt(label_enc, sizeof(label_enc), label);

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, (const uint8_t *)label, sizeof(label_enc));
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_final(&ctx, out_key);

    cprisk_szero_i(label, sizeof(label));
}

static void cprisk_derive_loader_key_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity_hash[CPRISK_ARMOR_HASH_SIZE],
    uint64_t string_acc,
    uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]
) {
    static const uint8_t label_enc[] = {
        'c'^0xA7, 'p'^0xA7, 'r'^0xA7, 'i'^0xA7, 's'^0xA7, 'k'^0xA7,
        '.'^0xA7, 'p'^0xA7, 'a'^0xA7, 's'^0xA7, 's'^0xA7, '3'^0xA7,
        '.'^0xA7, 'k'^0xA7, 'e'^0xA7, 'y'^0xA7, '.'^0xA7, 'v'^0xA7, '1'^0xA7
    };
    char label[sizeof(label_enc) + 1];
    cprisk_decode_salt(label_enc, sizeof(label_enc), label);

    uint8_t acc_le[8];
    cprisk_u64_to_le_i(string_acc, acc_le);

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, (const uint8_t *)label, sizeof(label_enc));
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, acc_le, sizeof(acc_le));
    cprisk_sha256_final(&ctx, out_key);

    cprisk_szero_i(label, sizeof(label));
    cprisk_szero_i(acc_le, sizeof(acc_le));
}

static void cprisk_derive_runtime_material_i(
    const uint8_t root_material[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE],
    const uint8_t integrity_hash[CPRISK_ARMOR_HASH_SIZE],
    uint64_t string_acc,
    uint64_t data_acc,
    uint8_t out_hash[CPRISK_ARMOR_HASH_SIZE]
) {
    static const uint8_t label_enc[] = {
        'c'^0xA7, 'p'^0xA7, 'r'^0xA7, 'i'^0xA7, 's'^0xA7, 'k'^0xA7,
        '.'^0xA7, 'r'^0xA7, 'u'^0xA7, 'n'^0xA7, 't'^0xA7, 'i'^0xA7,
        'm'^0xA7, 'e'^0xA7, '.'^0xA7, 's'^0xA7, 't'^0xA7, 'a'^0xA7,
        't'^0xA7, 'e'^0xA7, '.'^0xA7, 'v'^0xA7, '1'^0xA7
    };
    char label[sizeof(label_enc) + 1];
    cprisk_decode_salt(label_enc, sizeof(label_enc), label);

    uint8_t str_le[8];
    uint8_t data_le[8];
    cprisk_u64_to_le_i(string_acc, str_le);
    cprisk_u64_to_le_i(data_acc, data_le);

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, (const uint8_t *)label, sizeof(label_enc));
    cprisk_sha256_update(&ctx, root_material, CPRISK_ARMOR_KEY_SIZE);
    cprisk_sha256_update(&ctx, full_anchor_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, integrity_hash, CPRISK_ARMOR_HASH_SIZE);
    cprisk_sha256_update(&ctx, str_le, sizeof(str_le));
    cprisk_sha256_update(&ctx, data_le, sizeof(data_le));
    cprisk_sha256_final(&ctx, out_hash);

    cprisk_szero_i(label, sizeof(label));
    cprisk_szero_i(str_le, sizeof(str_le));
    cprisk_szero_i(data_le, sizeof(data_le));
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

    cprisk_szero_i(buf, (size_t)out_sz);
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

    /*
     * SHA256(ha || hb || hc) — deterministic iff all three agree.
     * On failure, fill with 0xFF so result diverges predictably.
     */
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

    cprisk_szero_i(ha, sizeof(ha));
    cprisk_szero_i(hb, sizeof(hb));
    cprisk_szero_i(hc, sizeof(hc));
    cprisk_szero_i(cat, sizeof(cat));

    return 0;
}

int cprisk_read_full_anchor_hash(uint8_t *out_hash) {
    if (!out_hash)
        return -1;

    const struct mach_header_64 *hdr = cprisk_own_hdr_i();
    if (!hdr)
        return -1;

    unsigned long sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_FULL_HASH, &sz);
    if (!sec || sz < CPRISK_ARMOR_FULL_HASH_SECTION_SIZE)
        return -1;

    for (uint32_t i = 0; i < CPRISK_ARMOR_HASH_SIZE; i++)
        out_hash[i] = sec[CPRISK_ARMOR_HASH_SIZE + i] ^ sec[i];

    return 0;
}

int cprisk_init_protection(const uint8_t *root_key, size_t root_key_len) {
    uint8_t root_material[CPRISK_ARMOR_KEY_SIZE];
    uint8_t string_key[CPRISK_ARMOR_KEY_SIZE];
    uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE];
    uint8_t integrity[CPRISK_ARMOR_HASH_SIZE];
    uint8_t full_anchor_hash[CPRISK_ARMOR_HASH_SIZE];
    char bootstrap[128];
    int rc = -1;

    cprisk_fill_root_material_i(root_key, root_key_len, root_material);
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
    cprisk_szero_i(bootstrap, sizeof(bootstrap));

    if (cprisk_compute_integrity_hash(integrity) != 0) {
        rc = -4;
        goto cleanup;
    }
    if (cprisk_read_full_anchor_hash(full_anchor_hash) != 0) {
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
        cprisk_szero_i(s_runtime_material, sizeof(s_runtime_material));
        s_runtime_material_ready = 0;
    }

    cprisk_szero_i(root_material, sizeof(root_material));
    cprisk_szero_i(string_key, sizeof(string_key));
    cprisk_szero_i(loader_key, sizeof(loader_key));
    cprisk_szero_i(integrity, sizeof(integrity));
    cprisk_szero_i(full_anchor_hash, sizeof(full_anchor_hash));
    cprisk_szero_i(bootstrap, sizeof(bootstrap));
    return rc;
}

void cprisk_cleanup_protection(void) {
    cprisk_szero_i(s_runtime_material, sizeof(s_runtime_material));
    s_runtime_material_ready = 0;
    cprisk_cleanup_string_decryptor();
    cprisk_unload_protected_data();
}

int cprisk_get_runtime_material(uint8_t out_material[32]) {
    if (!out_material)
        return -1;

    if (s_runtime_material_ready) {
        memcpy(out_material, s_runtime_material, CPRISK_ARMOR_HASH_SIZE);
        return 0;
    }

    /*
     * Poison path: deterministic but WRONG 32-byte value.
     * Any signature derived from this will fail server-side verification.
     */
    static const uint8_t poison_seed[32] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x13, 0x37, 0x42, 0x42, 0xFE, 0xED, 0xFA, 0xCE,
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        0x98, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA
    };
    memcpy(out_material, poison_seed, CPRISK_ARMOR_HASH_SIZE);
    return -1;
}
