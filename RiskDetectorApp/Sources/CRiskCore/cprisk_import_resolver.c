/*
 * CRiskCore - Import Table Encryption resolver for cprisk-armor ABI.
 *
 * Reads the encrypted import table from __DATA.__swift5_dyrel,
 * verifies HMAC-SHA256 integrity, decrypts symbol names via
 * SHA256-based keystream, and resolves them via dlsym.
 *
 * Table layout:
 *   Header (16 bytes):
 *     uint32_t magic      = 0x43494D50 ("CPIM")
 *     uint32_t version    = 1
 *     uint32_t count      = number of symbols
 *     uint32_t reserved   = 0
 *   Index entries (48 bytes each):
 *     uint32_t data_offset   (relative to start of encrypted name data)
 *     uint32_t data_length   (byte length of encrypted name)
 *     uint8_t  nonce[8]      (random nonce used in HMAC and keystream)
 *     uint8_t  hmac_tag[32]  (HMAC-SHA256 over nonce || plaintext_name)
 *   Encrypted name data (variable):
 *     Concatenated encrypted name bytes, in entry order.
 */

#include "include/CRiskCore.h"
#include "include/cprisk_macho.h"
#include "include/cprisk_dlsym.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <mach-o/dyld.h>

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT ((void *)(intptr_t)-2)
#endif

/*
 * Optional: compare dlsym(RTLD_DEFAULT) with export-trie resolution (cprisk_dlsym).
 * Mismatch → return NULL for this resolve (fail closed) without global poison,
 * to reduce false positives from DYLD interposition / tooling.
 */
#ifndef CPRISK_IMPORT_DLSYM_TRIE_CROSSCHECK
#if defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_IMPORT_DLSYM_TRIE_CROSSCHECK 1
#else
#define CPRISK_IMPORT_DLSYM_TRIE_CROSSCHECK 0
#endif
#endif

/*
 * dlsym(RTLD_DEFAULT, …) is a high-value hook target: it can steer encrypted
 * imports to attacker stubs while leaving HMAC/name decryption intact.
 * cprisk_dlsym() walks the Mach-O export trie from dyld_all_image_infos (no
 * libc dlsym). When trie resolution in known system dylibs yields a unique
 * address that disagrees with dlsym, fail closed.
 */
static const char *cprisk_import_trie_sym_i(const char *name_buf) {
    if (!name_buf || name_buf[0] == '\0') {
        return NULL;
    }
    return (name_buf[0] == '_') ? (name_buf + 1) : name_buf;
}

static void *cprisk_import_crosscheck_dlsym_vs_trie_i(
    const char *name_buf,
    void *rtld_addr
) {
    if (!rtld_addr || !name_buf) {
        return rtld_addr;
    }
    const char *sym = cprisk_import_trie_sym_i(name_buf);
    if (!sym || sym[0] == '\0') {
        return rtld_addr;
    }

    static const char *const k_sys_libs[] = {
        "libsystem_kernel.dylib",
        "libsystem_c.dylib",
        "libsystem_pthread.dylib",
        "libsystem_info.dylib",
        "libsystem_malloc.dylib",
        "libsystem_platform.dylib",
        "libsystem_blocks.dylib",
        "libsystem_asl.dylib",
        "libsystem_trace.dylib",
    };

    const void *seen = NULL;
    for (size_t i = 0; i < sizeof(k_sys_libs) / sizeof(k_sys_libs[0]); i++) {
        void *t = cprisk_dlsym(k_sys_libs[i], sym);
        if (t == NULL) {
            continue;
        }
        if (seen == NULL) {
            seen = t;
        } else if (t != seen) {
            /* Same name resolves to different exports — ambiguous; do not tripwire. */
            return rtld_addr;
        }
    }

    if (seen != NULL && seen != (const void *)rtld_addr) {
        return NULL;
    }
    return rtld_addr;
}

int cprisk_verify_mprotect_dlsym_matches_export_trie(void) {
    void *a = dlsym(RTLD_DEFAULT, "mprotect");
    void *b = cprisk_dlsym("libsystem_kernel.dylib", "mprotect");
    if (!a || !b) {
        return -1;
    }
    return (a == b) ? 0 : 1;
}

/* CPRISK_IMPORT_MAGIC: "CPIM" = 0x43494D50 */
#define CPRISK_IMPORT_MAGIC     0x43494D50
#define CPRISK_IMPORT_VERSION   1
#define CPRISK_IMPORT_INDEX_SZ  48
#define CPRISK_IMPORT_HDR_SZ     16
#define CPRISK_IMPORT_CACHE_SLOTS 32u

typedef struct cprisk_import_cache_entry_i {
    uint32_t symbol_index;
    uintptr_t addr;
    uint32_t tag;
    uint8_t valid;
    uint8_t _reserved[3];
} cprisk_import_cache_entry_i;

static pthread_mutex_t s_import_cache_mutex_i = PTHREAD_MUTEX_INITIALIZER;
static cprisk_import_cache_entry_i s_import_cache_i[CPRISK_IMPORT_CACHE_SLOTS];

static uint32_t cprisk_import_os_mix_i(void) {
    char osrelease[128];
    size_t len = sizeof(osrelease);
    int err = 0;
    if (cprisk_sysctlbyname_direct("kern.osrelease", osrelease, &len, NULL, 0, &err) != 0 || len == 0) {
        return 0x7F4A7C15u;
    }
    uint32_t mix = 0x811C9DC5u;
    for (size_t i = 0; i < len && osrelease[i] != '\0'; i++) {
        mix ^= (uint32_t)(uint8_t)osrelease[i];
        mix *= 16777619u;
    }
    return mix;
}

static uint32_t cprisk_import_dyld_mix_i(void) {
    const uint32_t image_count = _dyld_image_count();
    return (image_count << 11u) ^ (image_count >> 3u) ^ 0xA24BAED5u;
}

static void cprisk_import_timing_hook_i(uint32_t stage, uint32_t symbol_index) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return;
    }
    uint32_t mix = (uint32_t)ts.tv_nsec
        ^ cprisk_import_os_mix_i()
        ^ cprisk_import_dyld_mix_i()
        ^ (stage * 0x45D9F3Bu)
        ^ (symbol_index * 0x27D4EB2Du);
    volatile uint32_t sink = mix;
    const uint32_t spin = 32u + (mix & 0x3Fu);
    for (uint32_t i = 0; i < spin; i++) {
        sink ^= (sink << 5u) + (i * 0x9E37u);
    }
    (void)sink;
}

static uint32_t cprisk_import_cache_tag_i(
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    uint32_t symbol_index,
    uintptr_t addr,
    uint32_t table_fingerprint
) {
    uint8_t msg[4 + sizeof(uintptr_t) + 4];
    memset(msg, 0, sizeof(msg));
    memcpy(msg, &symbol_index, sizeof(symbol_index));
    memcpy(msg + 4, &addr, sizeof(addr));
    memcpy(msg + 4 + sizeof(addr), &table_fingerprint, sizeof(table_fingerprint));

    uint8_t digest[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_hmac_sha256(key, CPRISK_ARMOR_KEY_SIZE, msg, sizeof(msg), digest);
    uint32_t tag = 0u;
    memcpy(&tag, digest, sizeof(tag));
    cprisk_secure_zero(digest, sizeof(digest));
    cprisk_secure_zero(msg, sizeof(msg));
    return tag;
}

static int cprisk_import_cache_lookup_i(
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    uint32_t symbol_index,
    uint32_t table_fingerprint,
    void **out_addr
) {
    if (!out_addr)
        return 0;

    pthread_mutex_lock(&s_import_cache_mutex_i);
    for (size_t i = 0; i < CPRISK_IMPORT_CACHE_SLOTS; i++) {
        const cprisk_import_cache_entry_i *entry = &s_import_cache_i[i];
        if (!entry->valid || entry->symbol_index != symbol_index)
            continue;

        const uint32_t expected_tag = cprisk_import_cache_tag_i(
            key, symbol_index, entry->addr, table_fingerprint
        );
        if (expected_tag == entry->tag) {
            *out_addr = (void *)entry->addr;
            pthread_mutex_unlock(&s_import_cache_mutex_i);
            return *out_addr != NULL ? 1 : 0;
        }
    }
    pthread_mutex_unlock(&s_import_cache_mutex_i);
    return 0;
}

static void cprisk_import_cache_store_i(
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    uint32_t symbol_index,
    uint32_t table_fingerprint,
    void *addr
) {
    const size_t slot = (size_t)(symbol_index % CPRISK_IMPORT_CACHE_SLOTS);
    const uint32_t tag = cprisk_import_cache_tag_i(
        key, symbol_index, (uintptr_t)addr, table_fingerprint
    );

    pthread_mutex_lock(&s_import_cache_mutex_i);
    s_import_cache_i[slot].symbol_index = symbol_index;
    s_import_cache_i[slot].addr = (uintptr_t)addr;
    s_import_cache_i[slot].tag = tag;
    s_import_cache_i[slot].valid = 1u;
    pthread_mutex_unlock(&s_import_cache_mutex_i);
}

static int cprisk_derive_import_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_key) return -1;

    uint8_t zero_seed[CPRISK_ARMOR_KEY_SIZE];
    memset(zero_seed, 0, sizeof(zero_seed));
    int rc = cprisk_whitebox_evaluate_domain(
        CPRISK_WHITEBOX_DOMAIN_IMPORT_ENCRYPTION,
        zero_seed,
        out_key
    );
    if (rc != 0) {
        uint8_t runtime_material[CPRISK_ARMOR_KEY_SIZE];
        static const char label[] = "cprisk.import.key.fallback.v1";
        uint8_t fallback_seed[CPRISK_ARMOR_KEY_SIZE + sizeof(label) - 1u];
        memset(runtime_material, 0, sizeof(runtime_material));
        if (cprisk_get_runtime_material(runtime_material) == 0) {
            memset(fallback_seed, 0, sizeof(fallback_seed));
            memcpy(fallback_seed, runtime_material, CPRISK_ARMOR_KEY_SIZE);
            memcpy(fallback_seed + CPRISK_ARMOR_KEY_SIZE, label, sizeof(label) - 1u);
            cprisk_sha256(fallback_seed, sizeof(fallback_seed), out_key);
            rc = 0;
            cprisk_secure_zero(fallback_seed, sizeof(fallback_seed));
        }
        cprisk_secure_zero(runtime_material, sizeof(runtime_material));
    }
    cprisk_secure_zero(zero_seed, sizeof(zero_seed));
    return rc;
}

/* ── Keystream derivation (matches Swift side) ──────────────────────── */

static void derive_keystream(
    const uint8_t *key, uint32_t index,
    const uint8_t *nonce, size_t name_len,
    uint8_t *out_keystream
) {
    /* SHA256-based keystream:
     * Material: key || index(4) || nonce(8) || counter(8)
     * SHA256(material) repeated as needed. */
    uint8_t material[32 + 4 + 8 + 8];
    size_t mat_len = 0;

    memcpy(material, key, 32);
    mat_len = 32;

    material[mat_len++] = (uint8_t)(index & 0xFF);
    material[mat_len++] = (uint8_t)((index >> 8) & 0xFF);
    material[mat_len++] = (uint8_t)((index >> 16) & 0xFF);
    material[mat_len++] = (uint8_t)((index >> 24) & 0xFF);

    memcpy(material + mat_len, nonce, 8);
    mat_len += 8;

    size_t produced = 0;
    uint64_t counter = 0;

    while (produced < name_len) {
        memcpy(material + mat_len, &counter, 8);
        uint8_t hash[CPRISK_SHA256_DIGEST_LENGTH];
        cprisk_sha256(material, mat_len + 8, hash);

        size_t take = name_len - produced;
        if (take > CPRISK_SHA256_DIGEST_LENGTH)
            take = CPRISK_SHA256_DIGEST_LENGTH;

        memcpy(out_keystream + produced, hash, take);
        produced += take;
        counter += 1;
    }
}

/* ── Own Mach-O header (self-locating) ──────────────────────────────── */

static const struct mach_header_64 *cprisk_own_hdr(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr);
}

void cprisk_swift_bridge_force_link(void);

static int cprisk_resolve_swift_bridge_alias_i(uint32_t symbol_index, void **out_addr) {
    if (!out_addr || symbol_index < CPRISK_SWIFT_BRIDGE_IMPORT_BASE) {
        return 1;
    }

    const uint32_t bridge_index = symbol_index - CPRISK_SWIFT_BRIDGE_IMPORT_BASE;
    if (bridge_index >= CPRISK_SWIFT_BRIDGE_IMPORT_COUNT) {
        return -1;
    }

    if (cprisk_verify_dlsym_prologue() == 0) {
        return -1;
    }

    cprisk_swift_bridge_force_link();

    char alias_name[16];
    const int written = snprintf(
        alias_name,
        sizeof(alias_name),
        "cpra_%04u",
        (unsigned)(bridge_index + 1u)
    );
    if (written <= 0 || (size_t)written >= sizeof(alias_name)) {
        return -1;
    }

    void *addr = dlsym(RTLD_DEFAULT, alias_name);
    *out_addr = addr;
    return (addr != NULL) ? 0 : -1;
}

/* ── Main resolver ─────────────────────────────────────────────────── */

int cprisk_resolve_import(uint32_t symbol_index, void **out_addr) {
    if (!out_addr) return -1;
    *out_addr = NULL;

    if (symbol_index >= CPRISK_SWIFT_BRIDGE_IMPORT_BASE) {
        return cprisk_resolve_swift_bridge_alias_i(symbol_index, out_addr);
    }

    /* Import table is encrypted with WhiteBox Domain-8 key on the Swift side. */
    uint8_t key[CPRISK_ARMOR_KEY_SIZE];
    if (cprisk_derive_import_key(key) != 0) return -1;

    const struct mach_header_64 *hdr = cprisk_own_hdr();
    if (!hdr) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    unsigned long sec_sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr,
        CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_IMPORT_ENCRYPTED_TABLE,
        &sec_sz
    );

    if (!sec || sec_sz < CPRISK_IMPORT_HDR_SZ) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    /* Verify header */
    uint32_t magic = 0;
    uint32_t version = 0;
    uint32_t count = 0;
    uint32_t reserved = 0;
    memcpy(&magic, sec, 4);
    memcpy(&version, sec + 4, 4);
    memcpy(&count, sec + 8, 4);
    memcpy(&reserved, sec + 12, 4);

    if (magic != CPRISK_IMPORT_MAGIC || version != CPRISK_IMPORT_VERSION || symbol_index >= count) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    if (count > (UINT32_MAX / CPRISK_IMPORT_INDEX_SZ)) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }
    const size_t index_table_size = (size_t)count * CPRISK_IMPORT_INDEX_SZ;
    const size_t index_table_end = CPRISK_IMPORT_HDR_SZ + index_table_size;
    if (index_table_end > sec_sz) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    const uint32_t table_fingerprint =
        magic ^
        (version << 7u) ^
        (count * 0x9E3779B1u) ^
        (reserved * 0x45D9F3Bu) ^
        (uint32_t)sec_sz;

    if (cprisk_import_cache_lookup_i(key, symbol_index, table_fingerprint, out_addr) != 0) {
        cprisk_secure_zero(key, sizeof(key));
        return 0;
    }

    /* Read index entry */
    const uint8_t *idx = sec + CPRISK_IMPORT_HDR_SZ
                        + (uintptr_t)symbol_index * CPRISK_IMPORT_INDEX_SZ;

    uint32_t data_off = 0;
    uint32_t data_len = 0;
    memcpy(&data_off, idx, 4);
    memcpy(&data_len, idx + 4, 4);
    const uint8_t *nonce = idx + 8;
    const uint8_t *stored_hmac = idx + 16;

    /* Encrypted name data starts after all index entries */
    const uint8_t *encrypted_names_base = sec + index_table_end;
    const size_t encrypted_names_len = sec_sz - index_table_end;
    const uint8_t *encrypted_name = encrypted_names_base + data_off;

    /* Bounds check */
    if ((size_t)data_off > encrypted_names_len ||
        (size_t)data_len > encrypted_names_len - (size_t)data_off) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    /* Decrypt symbol name */
    char name_buf[512];
    if (data_len >= sizeof(name_buf)) {
        cprisk_secure_zero(key, sizeof(key));
        return -1;
    }

    uint8_t ks[512];
    derive_keystream(key, symbol_index + 1, nonce, data_len, ks);

    for (uint32_t i = 0; i < data_len; i++) {
        name_buf[i] = (char)(encrypted_name[i] ^ ks[i]);
    }
    name_buf[data_len] = '\0';

    /* Verify HMAC-SHA256 over nonce || plaintext_name.
     * HMAC input = nonce (8 bytes) || plaintext_name. */
    uint8_t hmac_input[8 + 512];
    memcpy(hmac_input, nonce, 8);
    memcpy(hmac_input + 8, name_buf, data_len);
    uint8_t computed_hmac[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_hmac_sha256(key, CPRISK_ARMOR_KEY_SIZE,
                       hmac_input, 8 + data_len,
                       computed_hmac);

    if (cprisk_hmac_verify(stored_hmac, computed_hmac,
                            CPRISK_SHA256_DIGEST_LENGTH) != 0) {
        /* HMAC mismatch — tampered or wrong key */
        cprisk_secure_zero(name_buf, data_len);
        cprisk_secure_zero(ks, data_len < sizeof(ks) ? data_len : sizeof(ks));
        cprisk_secure_zero(key, sizeof(key));
        cprisk_secure_zero(hmac_input, sizeof(hmac_input));
        cprisk_secure_zero(computed_hmac, sizeof(computed_hmac));
        return -1;
    }

    /* dlsym resolution — prologue must match early baseline before trusting RTLD_DEFAULT. */
    if (cprisk_verify_dlsym_prologue() == 0) {
        cprisk_secure_zero(name_buf, data_len);
        cprisk_secure_zero(ks, data_len < sizeof(ks) ? data_len : sizeof(ks));
        cprisk_secure_zero(key, sizeof(key));
        cprisk_secure_zero(hmac_input, sizeof(hmac_input));
        cprisk_secure_zero(computed_hmac, sizeof(computed_hmac));
        return -1;
    }
    cprisk_import_timing_hook_i(1u, symbol_index);
    void *addr = dlsym(RTLD_DEFAULT, name_buf);
#if CPRISK_IMPORT_DLSYM_TRIE_CROSSCHECK
    addr = cprisk_import_crosscheck_dlsym_vs_trie_i(name_buf, addr);
#endif
    if (addr != NULL) {
        cprisk_import_cache_store_i(key, symbol_index, table_fingerprint, addr);
    }

    /* Clean up decrypted name before returning */
    cprisk_secure_zero(name_buf, data_len);
    cprisk_secure_zero(ks, data_len < sizeof(ks) ? data_len : sizeof(ks));
    cprisk_secure_zero(hmac_input, sizeof(hmac_input));
    cprisk_secure_zero(computed_hmac, sizeof(computed_hmac));
    cprisk_secure_zero(key, sizeof(key));

    *out_addr = addr;
    return (addr != NULL) ? 0 : -1;
}
