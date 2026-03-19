#ifndef CPRISK_ARMOR_ABI_H
#define CPRISK_ARMOR_ABI_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "cprisk_sha256.h"
#include "cprisk_secure_zero.h"

#define CPRISK_ARMOR_ABI_VERSION 2u

#define CPRISK_ARMOR_KEY_SIZE 32u
#define CPRISK_ARMOR_HASH_SIZE 32u
#define CPRISK_ARMOR_NONCE_SIZE 8u

#define CPRISK_ARMOR_SEGMENT_DATA "__DATA"

#define CPRISK_ARMOR_SECTION_STRTAB "__swift5_types2"
#define CPRISK_ARMOR_SECTION_LOADER "__swift5_proto2"
#define CPRISK_ARMOR_SECTION_PROTECTED_DATA "__swift5_mpenum"
#define CPRISK_ARMOR_SECTION_ANCHOR_A "__swift5_aa"
#define CPRISK_ARMOR_SECTION_ANCHOR_B "__swift5_ab"
#define CPRISK_ARMOR_SECTION_ANCHOR_C "__swift5_ac"
#define CPRISK_ARMOR_SECTION_ANCHOR_D "__swift5_ad"
#define CPRISK_ARMOR_SECTION_FULL_HASH "__swift5_acfun"
#define CPRISK_ARMOR_SECTION_WHITEBOX_META "__swift5_awbm"
#define CPRISK_ARMOR_SECTION_WHITEBOX_CODE "__swift5_awbc"
#define CPRISK_ARMOR_SECTION_WHITEBOX_DATA "__swift5_awbd"
#define CPRISK_ARMOR_SECTION_WHITEBOX_TAG "__swift5_awbt"
#define CPRISK_ARMOR_SECTION_ANTI_DEBUG_PLAN "__objc_data2"

#define CPRISK_ARMOR_ADBG_ABI_VERSION 1u
#define CPRISK_ARMOR_ADBG_MAGIC 0x43504137u /* "CPA7" */
#define CPRISK_ARMOR_ADBG_HEADER_SIZE 48u
#define CPRISK_ARMOR_ADBG_ENTRY_SIZE 64u
#define CPRISK_ARMOR_ADBG_TARGET_NAME_SIZE 32u

#define CPRISK_ARMOR_ADBG_FLAG_HAS_SYMBOL_TARGETS 0x00000001u
#define CPRISK_ARMOR_ADBG_FLAG_HAS_SYNTHETIC_TARGETS 0x00000002u
#define CPRISK_ARMOR_ADBG_FLAG_SEED_FROM_CONFIG 0x00000004u
#define CPRISK_ARMOR_ADBG_FLAG_SEED_FROM_BINARY 0x00000008u

#define CPRISK_ARMOR_ADBG_ENTRY_FLAG_SYNTHETIC_TARGET 0x00000001u
#define CPRISK_ARMOR_ADBG_ENTRY_FLAG_INLINE_PATCH_RESERVED 0x00000002u
#define CPRISK_ARMOR_ADBG_ENTRY_FLAG_RUNTIME_GATE_RESERVED 0x00000004u

#define CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE 0x00000001u
#define CPRISK_ARMOR_ADBG_POLICY_CRASH_ON_DEBUGGER 0x00000002u
#define CPRISK_ARMOR_ADBG_POLICY_TRAP_ON_TAMPER 0x00000004u
#define CPRISK_ARMOR_ADBG_POLICY_DELAY_RESPONSE 0x00000008u
#define CPRISK_ARMOR_ADBG_POLICY_ESCALATE_INTEGRITY 0x00000010u

#define CPRISK_ARMOR_WHITEBOX_ABI_VERSION 1u
#define CPRISK_ARMOR_WHITEBOX_MAGIC 0x43505742u /* "CPWB" */
#define CPRISK_ARMOR_WHITEBOX_FLAG_ENGINE_READY 0x00000001u
#define CPRISK_ARMOR_WHITEBOX_FLAG_SIGNING_PIPELINE 0x00000002u

#define CPRISK_ARMOR_CAP_RUNTIME_DERIVE_KEY     0x00000001u
#define CPRISK_ARMOR_CAP_RUNTIME_SIGN_HELPER    0x00000002u
#define CPRISK_ARMOR_CAP_RUNTIME_VERIFY_HELPER  0x00000004u
#define CPRISK_ARMOR_CAP_WHITEBOX_FRAMEWORK     0x00000010u
#define CPRISK_ARMOR_CAP_WHITEBOX_SECTION_LAYOUT 0x00000020u

#define CPRISK_WHITEBOX_PROBE_FLAG_COMPILED         0x00000001u
#define CPRISK_WHITEBOX_PROBE_FLAG_METADATA_PRESENT 0x00000002u
#define CPRISK_WHITEBOX_PROBE_FLAG_METADATA_VALID   0x00000004u
#define CPRISK_WHITEBOX_PROBE_FLAG_ENGINE_READY     0x00000008u

#define CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE (CPRISK_ARMOR_HASH_SIZE * 2u)

#define CPRISK_ARMOR_BOOTSTRAP_STRING_ID 1u

#define CPRISK_ARMOR_STRTAB_MAGIC 0x43505354u  /* table guard sentinel */
#define CPRISK_ARMOR_LOADER_MAGIC 0x4350524Bu  /* descriptor guard sentinel */

#define CPRISK_ARMOR_ANCHOR_LANE_COUNT 4u
#define CPRISK_ARMOR_ANCHOR_LANE_SIZE 8u
#define CPRISK_ARMOR_HMAC_FULL_HASH_SECTION_SIZE CPRISK_ARMOR_HASH_SIZE
#define CPRISK_MAX_SECTION_SIZE (256UL * 1024UL * 1024UL)
#define CPRISK_MAX_ENTRY_COUNT 64u

#pragma pack(push, 1)

struct cprisk_armor_strtab_header {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
};

struct cprisk_armor_strtab_index_entry {
    uint32_t string_id;
    uint32_t data_offset;
    uint32_t data_length;
    uint8_t  nonce[CPRISK_ARMOR_NONCE_SIZE];
    uint8_t  hmac_tag[CPRISK_ARMOR_HASH_SIZE];
};

struct cprisk_armor_loader_header {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
};

struct cprisk_armor_loader_entry {
    char     segment_name[16];
    char     section_name[16];
    uint32_t key_id;
    uint32_t flags;
    uint64_t vm_addr;
    uint64_t size;
    uint8_t  content_hash[CPRISK_ARMOR_HASH_SIZE];
    uint8_t  nonce[CPRISK_ARMOR_NONCE_SIZE];
    uint8_t  hmac_tag[CPRISK_ARMOR_HASH_SIZE];
};

struct cprisk_armor_antidebug_header {
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
    uint32_t header_size;
    uint64_t seed;
    uint64_t text_base_address;
    uint32_t probe_immediate;
    uint32_t entry_count;
    uint32_t entry_size;
    uint32_t reserved;
};

struct cprisk_armor_antidebug_entry {
    uint64_t identifier_hash;
    uint64_t patch_site_vm_offset;
    uint32_t patch_site_file_offset;
    uint32_t policy_bits;
    uint32_t scatter_slot;
    uint32_t entry_flags;
    char target_name[CPRISK_ARMOR_ADBG_TARGET_NAME_SIZE];
};

struct cprisk_armor_whitebox_header {
    uint32_t magic;
    uint32_t version;
    uint32_t flags;
    uint32_t payload_size;
    uint8_t  config_digest[CPRISK_ARMOR_HASH_SIZE];
};

struct cprisk_whitebox_probe_result {
    uint32_t abi_version;
    uint32_t capabilities;
    uint32_t flags;
    uint32_t metadata_version;
};

#pragma pack(pop)

_Static_assert(sizeof(struct cprisk_armor_strtab_header) == 12,
               "cprisk strtab header ABI drift");
_Static_assert(sizeof(struct cprisk_armor_strtab_index_entry) == 52,
               "cprisk strtab index ABI drift");
_Static_assert(sizeof(struct cprisk_armor_loader_header) == 12,
               "cprisk loader header ABI drift");
_Static_assert(sizeof(struct cprisk_armor_loader_entry) == 128,
               "cprisk loader entry ABI drift");
_Static_assert(sizeof(struct cprisk_armor_antidebug_header) == 48,
               "cprisk anti-debug header ABI drift");
_Static_assert(sizeof(struct cprisk_armor_antidebug_entry) == 64,
               "cprisk anti-debug entry ABI drift");
_Static_assert(sizeof(struct cprisk_armor_whitebox_header) == 48,
               "cprisk whitebox header ABI drift");
_Static_assert(sizeof(struct cprisk_whitebox_probe_result) == 16,
               "cprisk whitebox probe ABI drift");
_Static_assert(CPRISK_ARMOR_ANCHOR_LANE_COUNT * CPRISK_ARMOR_ANCHOR_LANE_SIZE ==
                   CPRISK_ARMOR_HASH_SIZE,
               "split anchor sections must reconstruct a 32-byte hash");

/* ── HMAC-SHA256 ───────────────────────────────────────────────────── */

#define CPRISK_HMAC_BLOCK_SIZE 64

static inline __attribute__((always_inline))
void cprisk_hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[CPRISK_ARMOR_HASH_SIZE]) {
    uint8_t k_norm[CPRISK_HMAC_BLOCK_SIZE];
    memset(k_norm, 0, CPRISK_HMAC_BLOCK_SIZE);
    if (key_len > CPRISK_HMAC_BLOCK_SIZE) {
        cprisk_sha256(key, key_len, k_norm);
    } else {
        memcpy(k_norm, key, key_len);
    }

    uint8_t ipad[CPRISK_HMAC_BLOCK_SIZE];
    uint8_t opad[CPRISK_HMAC_BLOCK_SIZE];
    for (int i = 0; i < CPRISK_HMAC_BLOCK_SIZE; i++) {
        ipad[i] = k_norm[i] ^ 0x36;
        opad[i] = k_norm[i] ^ 0x5C;
    }

    cprisk_sha256_ctx ctx;
    uint8_t inner_hash[CPRISK_SHA256_DIGEST_LENGTH];

    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, ipad, CPRISK_HMAC_BLOCK_SIZE);
    cprisk_sha256_update(&ctx, msg, msg_len);
    cprisk_sha256_final(&ctx, inner_hash);

    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, opad, CPRISK_HMAC_BLOCK_SIZE);
    cprisk_sha256_update(&ctx, inner_hash, CPRISK_SHA256_DIGEST_LENGTH);
    cprisk_sha256_final(&ctx, out);

    cprisk_secure_zero(k_norm, sizeof(k_norm));
    cprisk_secure_zero(ipad, sizeof(ipad));
    cprisk_secure_zero(opad, sizeof(opad));
    cprisk_secure_zero(inner_hash, sizeof(inner_hash));
}

/* ── compile-time salt obfuscation ──────────────────────────────────── */

/* Legacy default; runtime should derive from root key via
   cprisk_derive_salt_xor_key() and use the result instead. */
#define CPRISK_SALT_XOR_KEY_DEFAULT 0xA7

static inline __attribute__((always_inline))
uint8_t cprisk_derive_salt_xor_key(const uint8_t root_key[CPRISK_ARMOR_KEY_SIZE]) {
    uint8_t seed[CPRISK_ARMOR_KEY_SIZE + 8];
    memcpy(seed, root_key, CPRISK_ARMOR_KEY_SIZE);
    seed[CPRISK_ARMOR_KEY_SIZE + 0] = 's';
    seed[CPRISK_ARMOR_KEY_SIZE + 1] = 'a';
    seed[CPRISK_ARMOR_KEY_SIZE + 2] = 'l';
    seed[CPRISK_ARMOR_KEY_SIZE + 3] = 't';
    seed[CPRISK_ARMOR_KEY_SIZE + 4] = '-';
    seed[CPRISK_ARMOR_KEY_SIZE + 5] = 'x';
    seed[CPRISK_ARMOR_KEY_SIZE + 6] = 'o';
    seed[CPRISK_ARMOR_KEY_SIZE + 7] = 'r';
    uint8_t hash[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, sizeof(seed), hash);
    uint8_t result = hash[0];
    cprisk_secure_zero(seed, sizeof(seed));
    cprisk_secure_zero(hash, sizeof(hash));
    return result;
}

static inline __attribute__((always_inline))
void cprisk_decode_salt(const uint8_t *encoded, size_t len,
                        uint8_t xor_key, char *out) {
    for (size_t i = 0; i < len; i++)
        out[i] = (char)(encoded[i] ^ xor_key);
    out[len] = '\0';
}

/* Constant-time comparison for HMAC tags. */
static inline __attribute__((always_inline))
int cprisk_hmac_verify(const uint8_t *expected, const uint8_t *actual, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= expected[i] ^ actual[i];
    return diff == 0 ? 0 : -1;
}

#endif /* CPRISK_ARMOR_ABI_H */
