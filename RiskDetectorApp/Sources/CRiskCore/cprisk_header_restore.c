/*
 * cprisk_header_restore.c — Runtime header decryption for cprisk-armor.
 *
 * Consumes the `__DATA.__swift5_mhsav` section produced by Pass 11
 * (HeaderEncryptorPass).  Verifies HMAC-SHA256 before writing decrypted
 * fields back to mach_header_64.
 *
 * Layout of backup section (64 bytes):
 *   offset  0.. 7:  nonce[8]
 *   offset  8..31:  encrypted_fields[24]  (magic + filetype + ncmds + sizeofcmds + flags + reserved)
 *   offset 32..63:  hmac_tag[32]
 *
 * The producer (Swift) now writes a per-binary camouflage value into
 * mach_header_64.reserved (instead of a fixed marker). Runtime restoration
 * still accepts the legacy marker 0x43504248 ("CPBH") for backward
 * compatibility.
 */

#include "include/CRiskCore.h"

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <pthread.h>
#include <time.h>
#include <mach-o/dyld.h>

#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

/* Mirrors cprisk_hdr_mprotect from cprisk_data_loader.c.
 * Uses direct syscall first, falls back to libc mprotect. */
static inline int cprisk_hdr_mprotect(void *addr, size_t len, int prot) {
    int direct_errno = 0;
    if (cprisk_mprotect_direct(addr, len, prot, &direct_errno) == 0) {
        return 0;
    }
    return mprotect(addr, len, prot);
}

/* Legacy marker written by old HeaderEncryptor builds. */
#define CPRISK_HBHDR_LEGACY_MAGIC 0x43504248u  /* "CPBH" */

/* Camouflage mix constant (must match HeaderEncryptorPass.makeCamouflagedReserved). */
#define CPRISK_HBHDR_CAMO_XOR 0xA5C31F27u

/* Backup section size: nonce(8) + encrypted(24) + HMAC(32) = 64 bytes. */
#define CPRISK_HBHDR_SECTION_SIZE 64
#define CPRISK_HBHDR_NONCE_SIZE 8
#define CPRISK_HBHDR_ENC_FIELDS_SIZE 24
/* encrypted fields layout (all little-endian UInt32):
 *   offset  0: magic (UInt32)
 *   offset  4: filetype (UInt32)
 *   offset  8: ncmds (UInt32)
 *   offset 12: sizeofcmds (UInt32)
 *   offset 16: flags (UInt32)
 *   offset 20: reserved (UInt32)
 */

static const struct mach_header_64 *cprisk_hdr_restore_own_hdr(void) {
    return cprisk_find_own_header((const void *)cprisk_hdr_restore_own_hdr);
}

static inline uint32_t cprisk_read_le32_i(const uint8_t *ptr) {
    if (!ptr)
        return 0u;
    return ((uint32_t)ptr[0]) |
           ((uint32_t)ptr[1] << 8) |
           ((uint32_t)ptr[2] << 16) |
           ((uint32_t)ptr[3] << 24);
}

static inline uint32_t cprisk_rotl32_i(uint32_t value, uint32_t shift) {
    shift &= 31u;
    if (shift == 0u)
        return value;
    return (value << shift) | (value >> (32u - shift));
}

/* Mirrors HeaderEncryptorPass.makeCamouflagedReserved(). */
static uint32_t cprisk_hdr_camouflaged_reserved_i(
    uint32_t original_reserved,
    const uint8_t nonce[CPRISK_HBHDR_NONCE_SIZE]
) {
    if (!nonce)
        return original_reserved;
    const uint32_t n0 = cprisk_read_le32_i(nonce);
    const uint32_t n1 = cprisk_read_le32_i(nonce + 4);
    uint32_t camouflaged = original_reserved ^ n0 ^ cprisk_rotl32_i(n1, 7) ^ CPRISK_HBHDR_CAMO_XOR;
    if (camouflaged == original_reserved || camouflaged == CPRISK_HBHDR_LEGACY_MAGIC)
        camouflaged ^= 0x01010101u;
    return camouflaged;
}

static int cprisk_restore_macho_header_impl_i(void);

static pthread_once_t s_header_restore_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t s_header_restore_retry_mutex = PTHREAD_MUTEX_INITIALIZER;
static int s_header_restore_result = -2; /* -2: uninitialized, >=0 terminal success/no-op */

static void cprisk_restore_macho_header_once_i(void) {
    s_header_restore_result = cprisk_restore_macho_header_impl_i();
}

static int cprisk_header_fields_sane_i(const struct mach_header_64 *hdr) {
    if (!hdr)
        return 0;

    if (hdr->magic != MH_MAGIC_64)
        return 0;
    if (hdr->ncmds == 0u || hdr->ncmds > 8192u)
        return 0;
    if (hdr->sizeofcmds == 0u || hdr->sizeofcmds > (32u * 1024u * 1024u))
        return 0;
    return 1;
}

static uint32_t cprisk_runtime_os_mix_i(void) {
    char osrelease[128];
    size_t len = sizeof(osrelease);
    int err = 0;
    if (cprisk_sysctlbyname_direct("kern.osrelease", osrelease, &len, NULL, 0, &err) != 0 || len == 0) {
        return 0xA24BAED5u;
    }
    uint32_t mix = 0x811C9DC5u;
    for (size_t i = 0; i < len && osrelease[i] != '\0'; i++) {
        mix ^= (uint32_t)(uint8_t)osrelease[i];
        mix *= 16777619u;
    }
    return mix;
}

static uint32_t cprisk_runtime_dyld_mix_i(void) {
    const uint32_t image_count = _dyld_image_count();
    uint32_t mix = 0x9E3779B9u ^ image_count;
    mix ^= (image_count << 7u) | (image_count >> 3u);
    return mix;
}

static void cprisk_runtime_timing_hook_i(uint32_t stage) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return;
    }

    uint32_t mix = (uint32_t)now.tv_nsec;
    mix ^= cprisk_runtime_os_mix_i();
    mix ^= cprisk_runtime_dyld_mix_i();
    mix ^= stage * 0x45D9F3Bu;
    const uint32_t spin = 48u + (mix & 0x3Fu);
    volatile uint32_t sink = mix;
    for (uint32_t i = 0; i < spin; i++) {
        sink ^= (sink << 7u) + (i * 0x9E37u);
    }
    (void)sink;
}

/* Derive the header encryption key by evaluating WhiteBox Domain 9
 * with an all-zero input.  This matches the Swift producer's key
 * derivation (ArmorWhiteBox PRF with domain=9, seed=all-zeros). */
static int cprisk_derive_header_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_key)
        return -1;

    /* Use an all-zero seed for Domain 9, matching the Swift side:
     * let seed = Data(repeating: 0, count: 32)
     * return whitebox.prf(domain: .headerEncryptionKey, input: seed) */
    uint8_t zero_seed[CPRISK_ARMOR_KEY_SIZE];
    memset(zero_seed, 0, CPRISK_ARMOR_KEY_SIZE);

    int rc = cprisk_whitebox_evaluate_domain(
        CPRISK_WHITEBOX_DOMAIN_HEADER_ENCRYPTION,
        zero_seed,
        out_key);
    if (rc != 0) {
        uint8_t runtime_material[CPRISK_ARMOR_KEY_SIZE];
        static const char label[] = "cprisk.header.key.fallback.v1";
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

    /* zero out the stack copy of the seed */
    cprisk_secure_zero(zero_seed, sizeof(zero_seed));
    return rc;
}

/* Generate a keystream block: SHA256(key || keyID_le[4] || nonce).
 * Returns the first CPRISK_SHA256_DIGEST_LENGTH bytes of the keystream.
 * This mirrors the Swift makeKeystream() logic. */
static void cprisk_hdr_keystream(
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    uint32_t key_id,
    const uint8_t nonce[CPRISK_ARMOR_NONCE_SIZE],
    uint8_t *out,
    size_t len
) {
    uint8_t seed[CPRISK_ARMOR_KEY_SIZE + 4 + CPRISK_ARMOR_NONCE_SIZE];
    size_t seed_len = CPRISK_ARMOR_KEY_SIZE + 4 + CPRISK_ARMOR_NONCE_SIZE;

    memcpy(seed, key, CPRISK_ARMOR_KEY_SIZE);
    seed[32] = (uint8_t)(key_id);
    seed[33] = (uint8_t)(key_id >> 8);
    seed[34] = (uint8_t)(key_id >> 16);
    seed[35] = (uint8_t)(key_id >> 24);
    memcpy(seed + 36, nonce, CPRISK_ARMOR_NONCE_SIZE);

    /* Produce the first block */
    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, seed_len, blk);
    cprisk_secure_zero(seed, sizeof(seed));

    /* The keystream for our 24-byte payload fits in a single block */
    if (len > CPRISK_SHA256_DIGEST_LENGTH)
        len = CPRISK_SHA256_DIGEST_LENGTH;
    memcpy(out, blk, len);
    cprisk_secure_zero(blk, sizeof(blk));
}

/* Decrypt the 24-byte encrypted header fields in place using XOR keystream.
 * keyID is always 0 for the header backup section. */
static void cprisk_decrypt_header_fields(
    uint8_t *enc_fields,
    size_t enc_len,
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    uint32_t key_id,
    const uint8_t nonce[CPRISK_ARMOR_NONCE_SIZE]
) {
    if (enc_len == 0 || enc_len > 256)
        return;

    uint8_t ks[256];
    size_t to_decrypt = enc_len < sizeof(ks) ? enc_len : sizeof(ks);
    cprisk_hdr_keystream(key, key_id, nonce, ks, to_decrypt);

    for (size_t i = 0; i < to_decrypt; i++)
        enc_fields[i] ^= ks[i];

    cprisk_secure_zero(ks, sizeof(ks));
}

/* Verify HMAC over the canonical encoding written by HeaderEncryptor.swift:
 *   u32 nonce_len | nonce[nonce_len] | u32 ct_len | ciphertext[ct_len]
 * Returns 0 on match, -1 on mismatch. */
static int cprisk_verify_header_hmac(
    const uint8_t key[CPRISK_ARMOR_KEY_SIZE],
    const uint8_t nonce[CPRISK_ARMOR_NONCE_SIZE],
    const uint8_t *enc_fields,
    size_t enc_len,
    const uint8_t expected_tag[CPRISK_ARMOR_HASH_SIZE]
) {
    uint8_t hmac_msg[4u + CPRISK_ARMOR_NONCE_SIZE + 4u + CPRISK_HBHDR_ENC_FIELDS_SIZE];
    size_t mp = 0u;
    hmac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE      );
    hmac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE >>  8);
    hmac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE >> 16);
    hmac_msg[mp++] = (uint8_t)(CPRISK_ARMOR_NONCE_SIZE >> 24);
    memcpy(hmac_msg + mp, nonce, CPRISK_ARMOR_NONCE_SIZE);
    mp += CPRISK_ARMOR_NONCE_SIZE;
    hmac_msg[mp++] = (uint8_t)((uint32_t)enc_len      );
    hmac_msg[mp++] = (uint8_t)((uint32_t)enc_len >>  8);
    hmac_msg[mp++] = (uint8_t)((uint32_t)enc_len >> 16);
    hmac_msg[mp++] = (uint8_t)((uint32_t)enc_len >> 24);
    memcpy(hmac_msg + mp, enc_fields, enc_len);
    mp += enc_len;

    uint8_t computed_tag[CPRISK_ARMOR_HASH_SIZE];
    cprisk_hmac_sha256(key, CPRISK_ARMOR_KEY_SIZE,
                       hmac_msg, mp,
                       computed_tag);

    const int rc = cprisk_hmac_verify(expected_tag, computed_tag,
                                      CPRISK_ARMOR_HASH_SIZE);
    cprisk_secure_zero(computed_tag, sizeof(computed_tag));
    return rc;
}

/* Write back the six little-endian UInt32 header fields into the Mach-O header.
 * The fields are stored in the same byte order as the original header. */
static void cprisk_write_header_fields(
    struct mach_header_64 *hdr,
    const uint8_t fields[CPRISK_HBHDR_ENC_FIELDS_SIZE]
) {
    if (!hdr || !fields)
        return;

    uint32_t magic;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;

    /* Read back little-endian fields */
    memcpy(&magic,      fields +  0, 4);
    memcpy(&filetype,   fields +  4, 4);
    memcpy(&ncmds,      fields +  8, 4);
    memcpy(&sizeofcmds, fields + 12, 4);
    memcpy(&flags,      fields + 16, 4);
    memcpy(&reserved,   fields + 20, 4);

    /* Write back to the header */
    hdr->magic      = magic;
    hdr->filetype   = filetype;
    hdr->ncmds      = ncmds;
    hdr->sizeofcmds = sizeofcmds;
    hdr->flags      = flags;
    hdr->reserved   = reserved;
}

/* Restore implementation.
 *
 * Returns  0 on successful restore.
 * Returns  1 when no restore is needed.
 * Returns -1 on verification / runtime failure.
 */
static int cprisk_restore_macho_header_impl_i(void) {
    const struct mach_header_64 *hdr_const = cprisk_hdr_restore_own_hdr();
    if (!hdr_const)
        return -1;

    /* Find the backup section */
    unsigned long sec_sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr_const,
        CPRISK_ARMOR_SEGMENT_DATA,
        CPRISK_ARMOR_SECTION_HEADER_BACKUP,
        &sec_sz);
    if (!sec)
        return 1; /* Binary is not header-armored. */
    if (sec_sz < CPRISK_HBHDR_SECTION_SIZE)
        return cprisk_header_fields_sane_i(hdr_const) ? 1 : -1;

    /* Parse the backup section layout */
    const uint8_t *nonce       = sec +  0;
    const uint8_t *enc_fields = sec +  CPRISK_HBHDR_NONCE_SIZE;
    const uint8_t *hmac_tag   = sec +  CPRISK_HBHDR_NONCE_SIZE
                                    + CPRISK_HBHDR_ENC_FIELDS_SIZE;

    /* Derive the header key via WhiteBox Domain 9 */
    uint8_t header_key[CPRISK_ARMOR_KEY_SIZE];
    cprisk_runtime_timing_hook_i(1u);
    if (cprisk_derive_header_key(header_key) != 0) {
        return cprisk_header_fields_sane_i(hdr_const) ? 1 : -1;
    }

    /* Verify HMAC before writing any decrypted data */
    if (cprisk_verify_header_hmac(header_key, nonce,
                                  enc_fields, CPRISK_HBHDR_ENC_FIELDS_SIZE,
                                  hmac_tag) != 0) {
        cprisk_secure_zero(header_key, sizeof(header_key));
        return cprisk_header_fields_sane_i(hdr_const) ? 1 : -1;
    }

    /* Copy encrypted fields to a temporary buffer so we can decrypt in place */
    uint8_t fields_buf[CPRISK_HBHDR_ENC_FIELDS_SIZE];
    memcpy(fields_buf, enc_fields, CPRISK_HBHDR_ENC_FIELDS_SIZE);

    /* Decrypt via XOR keystream (keyID = 0 for header backup) */
    cprisk_decrypt_header_fields(fields_buf, CPRISK_HBHDR_ENC_FIELDS_SIZE,
                                 header_key, 0, nonce);
    cprisk_secure_zero(header_key, sizeof(header_key));

    uint32_t original_reserved = 0u;
    memcpy(&original_reserved, fields_buf + 20, sizeof(original_reserved));

    const uint32_t expected_camouflaged =
        cprisk_hdr_camouflaged_reserved_i(original_reserved, nonce);
    const uint32_t current_reserved = hdr_const->reserved;

    /* Idempotent fast-path:
     * if the original reserved is already present, restoration happened earlier.
     */
    if (current_reserved == original_reserved) {
        cprisk_secure_zero(fields_buf, sizeof(fields_buf));
        return 1;
    }

    /* Legacy compatibility:
     * old builds use a fixed marker (CPBH) instead of per-binary camouflage.
     */
    if (current_reserved != expected_camouflaged &&
        current_reserved != CPRISK_HBHDR_LEGACY_MAGIC) {
        cprisk_secure_zero(fields_buf, sizeof(fields_buf));
        return -1;
    }

    /* Make the header page writable */
    uintptr_t page_start = (uintptr_t)hdr_const & ~(uintptr_t)0xFFF;
    cprisk_runtime_timing_hook_i(2u);
    if (cprisk_hdr_mprotect((void *)page_start, 0x1000,
                              PROT_READ | PROT_WRITE) != 0) {
        cprisk_secure_zero(fields_buf, sizeof(fields_buf));
        return -1;
    }

    /* Write decrypted fields back to the header */
    struct mach_header_64 *hdr = (struct mach_header_64 *)hdr_const;
    cprisk_write_header_fields(hdr, fields_buf);
    cprisk_secure_zero(fields_buf, sizeof(fields_buf));

    /* Restore header page to read-only */
    if (cprisk_hdr_mprotect((void *)page_start, 0x1000, PROT_READ) != 0) {
        /* Non-fatal: the page might already be in a non-standard state */
    }

    return 0;
}

/* ── public API ─────────────────────────────────────────────────────────── */

/* Restore mach_header_64 fields from __DATA.__swift5_mhsav.
 *
 * Uses one eager attempt (pthread_once) for fast path + stable idempotence.
 * If the eager path fails (for example due to startup ordering), later calls
 * may retry under a mutex until a non-negative result is reached.
 *
 * Returns  0 on success.
 * Returns  1 when no restoration is needed or already restored.
 * Returns -1 on failure.
 */
int cprisk_restore_macho_header(void) {
    (void)pthread_once(&s_header_restore_once, cprisk_restore_macho_header_once_i);
    if (s_header_restore_result >= 0)
        return s_header_restore_result;

    if (pthread_mutex_lock(&s_header_restore_retry_mutex) != 0)
        return s_header_restore_result;

    /* Retry while the once path reports failure.
     * We intentionally do not overwrite s_header_restore_result here to keep
     * it immutable after pthread_once initialization. */
    const int out = (s_header_restore_result < 0)
        ? cprisk_restore_macho_header_impl_i()
        : s_header_restore_result;
    pthread_mutex_unlock(&s_header_restore_retry_mutex);
    return out;
}

/* Run as early as possible after image load to shrink plaintext header window.
 * Failures are non-fatal here; the normal runtime path can retry later.
 */
__attribute__((constructor(120)))
static void cprisk_restore_macho_header_ctor_i(void) {
    (void)cprisk_restore_macho_header();
}
