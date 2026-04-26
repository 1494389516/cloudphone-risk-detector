/*
 * cprisk_detection_attest.c — Cross-language detection attestation.
 *
 * Purpose: produce a 32-byte attestation tag that binds the sequence of
 * (detector_id, score, methods_hash) tuples observed during a single
 * JailbreakEngineV2 run.  An attacker hooking the Swift dispatcher to
 * skip detectors and return clean results bypasses the Swift-level
 * canary, but the runtime accumulator here only records what the engine
 * actually invokes.  Server-side replay of the claimed detector results
 * recomputes the tag using a key derived from the WhiteBox PRF; if the
 * client report omits the attestation tag, presents an incorrect tag,
 * or the count disagrees, the report is flagged as tampered.
 *
 * The session secret is derived once via the WhiteBox PRF
 * (Domain 5 = runtimeMaterial); the attacker therefore must compromise
 * the C/WhiteBox layer (much harder) in addition to the Swift dispatcher
 * to forge a consistent attestation.
 *
 * Threading: a single coarse mutex serializes session_begin / record /
 * finalize so the engine's randomized dispatch order is internally
 * consistent across detector threads.
 */

#include "include/CRiskCore.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#if defined(__APPLE__)
#include <Security/SecRandom.h>
#endif

#define CPRISK_ATTEST_KEY_DOMAIN_RUNTIME_MATERIAL 5u

/* Session state. Held under s_attest_mutex for all mutators. */
static pthread_mutex_t s_attest_mutex = PTHREAD_MUTEX_INITIALIZER;
static _Atomic int     s_attest_key_init;
static uint8_t         s_attest_key[CPRISK_ARMOR_KEY_SIZE];
static uint8_t         s_attest_running_hash[CPRISK_ARMOR_HASH_SIZE];
static uint8_t         s_attest_session_nonce[16];
static uint32_t        s_attest_count;
static int             s_attest_session_active;

static int cprisk_attest_random_bytes_i(uint8_t *out, size_t len) {
#if defined(__APPLE__)
    if (SecRandomCopyBytes(kSecRandomDefault, len, out) == errSecSuccess)
        return 0;
#endif
    /* Fallback: timestamp + per-call counter, mixed via SHA256 to avoid
     * leaking the raw clock pattern. Not cryptographically strong but
     * enough to make replay impractical when SecRandom is unavailable. */
    static _Atomic uint64_t ctr;
    uint64_t c = atomic_fetch_add(&ctr, 1ULL);
    uint64_t t = (uint64_t)time(NULL);
    uint8_t seed[24];
    memcpy(seed, &t, 8);
    memcpy(seed + 8, &c, 8);
    memcpy(seed + 16, "ATTESTNONCEFB!\0\0", 8);
    uint8_t digest[CPRISK_ARMOR_HASH_SIZE];
    cprisk_sha256(seed, sizeof(seed), digest);
    size_t n = len < sizeof(digest) ? len : sizeof(digest);
    memcpy(out, digest, n);
    if (len > n) memset(out + n, 0, len - n);
    cprisk_secure_zero(seed, sizeof(seed));
    cprisk_secure_zero(digest, sizeof(digest));
    return 0;
}

static void cprisk_attest_ensure_key_i(void) {
    if (atomic_load(&s_attest_key_init))
        return;

    /* Derive once: HMAC under WhiteBox Domain 5 using a stable label.
     * Subsequent sessions reuse this key. */
    uint8_t input[32];
    memset(input, 0, sizeof(input));
    static const char label[] = "cprisk.attest.key.v1";
    /* sizeof(label) - 1 == 20, fits in 32 bytes; pad zeros stay. */
    memcpy(input, label, sizeof(label) - 1u);

    uint8_t derived[32];
    if (cprisk_whitebox_evaluate_domain(
            CPRISK_ATTEST_KEY_DOMAIN_RUNTIME_MATERIAL,
            input,
            derived) == 0) {
        memcpy(s_attest_key, derived, sizeof(s_attest_key));
    } else {
        /* WhiteBox unavailable (early boot, test fixture, etc.) — fall
         * back to a build-derived constant. The attestation is still
         * useful against generic Swift hooks but loses the
         * "needs to compromise WhiteBox" property. */
        for (size_t i = 0; i < sizeof(s_attest_key); i++) {
            s_attest_key[i] = (uint8_t)(0xCC ^ (i * 0x37));
        }
    }
    cprisk_secure_zero(derived, sizeof(derived));
    cprisk_secure_zero(input, sizeof(input));
    atomic_store(&s_attest_key_init, 1);
}

int cprisk_attest_session_begin(uint8_t out_nonce[16]) {
    pthread_mutex_lock(&s_attest_mutex);

    cprisk_attest_ensure_key_i();
    cprisk_attest_random_bytes_i(s_attest_session_nonce, sizeof(s_attest_session_nonce));

    /* Initialize the running hash with a domain label and the session
     * nonce so attestation tags from different sessions are not
     * splice-able. */
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    static const uint8_t session_label[] = "cprisk.attest.session.v1";
    cprisk_sha256_update(&ctx, session_label, sizeof(session_label) - 1u);
    cprisk_sha256_update(&ctx, s_attest_session_nonce, sizeof(s_attest_session_nonce));
    cprisk_sha256_final(&ctx, s_attest_running_hash);

    s_attest_count = 0;
    s_attest_session_active = 1;

    if (out_nonce) {
        memcpy(out_nonce, s_attest_session_nonce, 16);
    }

    pthread_mutex_unlock(&s_attest_mutex);
    return 0;
}

void cprisk_attest_record(uint8_t detector_id,
                          int32_t score,
                          const uint8_t methods_hash[CPRISK_ARMOR_HASH_SIZE]) {
    pthread_mutex_lock(&s_attest_mutex);

    if (!s_attest_session_active) {
        pthread_mutex_unlock(&s_attest_mutex);
        return;
    }

    /* Hash chain: H_{n+1} = SHA256(H_n || id_le4 || score_le4 || methods_hash[32])
     * Rolling chain, not Merkle, because we want the order of records to
     * matter — server replay must follow the same dispatch order the
     * client used. */
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, s_attest_running_hash, CPRISK_ARMOR_HASH_SIZE);

    uint8_t id_le4[4] = { detector_id, 0u, 0u, 0u };
    cprisk_sha256_update(&ctx, id_le4, 4);

    uint32_t score_u = (uint32_t)score;
    uint8_t score_le4[4] = {
        (uint8_t)(score_u),
        (uint8_t)(score_u >> 8),
        (uint8_t)(score_u >> 16),
        (uint8_t)(score_u >> 24),
    };
    cprisk_sha256_update(&ctx, score_le4, 4);

    if (methods_hash) {
        cprisk_sha256_update(&ctx, methods_hash, CPRISK_ARMOR_HASH_SIZE);
    } else {
        uint8_t zero_hash[CPRISK_ARMOR_HASH_SIZE] = {0};
        cprisk_sha256_update(&ctx, zero_hash, CPRISK_ARMOR_HASH_SIZE);
    }

    cprisk_sha256_final(&ctx, s_attest_running_hash);
    s_attest_count++;

    pthread_mutex_unlock(&s_attest_mutex);
}

int cprisk_attest_session_finalize(uint8_t out_tag[CPRISK_ARMOR_HASH_SIZE],
                                   uint32_t *out_count) {
    pthread_mutex_lock(&s_attest_mutex);

    if (!s_attest_session_active || !out_tag) {
        if (out_tag) memset(out_tag, 0, CPRISK_ARMOR_HASH_SIZE);
        if (out_count) *out_count = 0u;
        pthread_mutex_unlock(&s_attest_mutex);
        return -1;
    }

    /* Final tag = HMAC(s_attest_key, "cprisk.attest.tag.v1" || nonce || running_hash || count_le4)
     * Keying the FINAL step (rather than the rolling chain) means the
     * attacker cannot pre-compute partial states without the key. */
    uint8_t msg[24 + 16 + CPRISK_ARMOR_HASH_SIZE + 4];
    static const uint8_t tag_label[] = "cprisk.attest.tag.v1";
    /* sizeof(tag_label)-1 == 20, fits in 24-byte slot; tail two bytes 0. */
    size_t mp = 0;
    memset(msg, 0, sizeof(msg));
    memcpy(msg + mp, tag_label, sizeof(tag_label) - 1u);
    mp += 24;
    memcpy(msg + mp, s_attest_session_nonce, 16);
    mp += 16;
    memcpy(msg + mp, s_attest_running_hash, CPRISK_ARMOR_HASH_SIZE);
    mp += CPRISK_ARMOR_HASH_SIZE;
    msg[mp++] = (uint8_t)(s_attest_count);
    msg[mp++] = (uint8_t)(s_attest_count >> 8);
    msg[mp++] = (uint8_t)(s_attest_count >> 16);
    msg[mp++] = (uint8_t)(s_attest_count >> 24);

    cprisk_hmac_sha256(s_attest_key, sizeof(s_attest_key),
                       msg, sizeof(msg), out_tag);

    if (out_count) *out_count = s_attest_count;

    /* End the session — subsequent record() calls without begin() are no-ops. */
    cprisk_secure_zero(s_attest_running_hash, sizeof(s_attest_running_hash));
    s_attest_session_active = 0;
    s_attest_count = 0;
    cprisk_secure_zero(msg, sizeof(msg));

    pthread_mutex_unlock(&s_attest_mutex);
    return 0;
}

void cprisk_attest_get_session_nonce(uint8_t out_nonce[16]) {
    pthread_mutex_lock(&s_attest_mutex);
    if (out_nonce) {
        memcpy(out_nonce, s_attest_session_nonce, 16);
    }
    pthread_mutex_unlock(&s_attest_mutex);
}
