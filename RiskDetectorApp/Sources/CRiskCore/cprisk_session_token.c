/*
 * cprisk_session_token.c — Layer-3 session-bound key derivation.
 *
 * Three-layer key derivation:
 *   Layer 1: rootKey        (CLI provided)
 *   Layer 2: deviceKey      = CPRisk-MAC(rootKey, deviceSalt)
 *   Layer 3: effectiveRoot  = CPRisk-MAC(deviceKey, sessionKey)
 *
 * This file implements Layer-3 (session binding).  Session keys are
 * received from the remote attestation server and used to derive a
 * third-layer key bound to the current session.
 *
 * Session tokens carry a 24-hour TTL to limit the impact of key exposure.
 * ONLY the signed token format is accepted:
 *   - signed: 32-byte token + 32-byte CPRisk-MAC(token)
 * A bare 32-byte token is REJECTED unconditionally (it carries no
 * authentication). The verification key is derived at runtime from the
 * runtime material (never a hardcoded / compiled-in key string); if
 * runtime material is unavailable, every token is rejected.
 * The TTL guards against replay even when the caller keeps using
 * stale in-memory material.
 */

#include "include/CRiskCore.h"
#include "include/cprisk_sha256.h"
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <limits.h>

#define CPRISK_SESSION_TOKEN_TTL_SECONDS (24UL * 60 * 60)   /* 24 hours */
#define CPRISK_SESSION_TOKEN_SIGNED_SIZE (CPRISK_ARMOR_KEY_SIZE + CPRISK_ARMOR_HASH_SIZE)

/* Token format (v2 only):
 * - signed: [32-byte token || 32-byte CPRisk-MAC(token)]
 *
 * There is NO hardcoded MAC key anywhere in this file: the verification
 * key is derived from the runtime material at call time (see
 * cprisk_session_mac_key_i). A token without a valid tag is rejected.
 * Local CPRisk-MAC validation is a tamper filter. Server-side attestation remains
 * the source of truth. */

/* Per-instance session state — single-thread assumption matches
 * cprisk_integrity.c (s_runtime_material etc.).  Guard with
 * pthread_once / _Atomic if multi-threaded init is required. */
static uint8_t s_session_token[CPRISK_ARMOR_KEY_SIZE];
static _Atomic int s_session_token_valid = 0;
static time_t s_session_token_expires_at;

/* CPRisk-MAC-SHA256 wrapper delegating to the static inline in cprisk_armor_abi.h */
static void cprisk_mac_sha256_i(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[CPRISK_ARMOR_HASH_SIZE]
) {
    cprisk_mac_sha256(key, key_len, msg, msg_len, out);
}

/* Derive the token-verification key from runtime material. Returns 0 on
 * success, -1 when runtime material is unavailable (caller must then
 * reject the token — there is no fallback key). */
static int cprisk_session_mac_key_i(uint8_t out_key[CPRISK_ARMOR_HASH_SIZE]) {
    uint8_t runtime_material[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_get_runtime_material(runtime_material) != 0)
        return -1;
    static const char label[] = "cprisk.session.token.mac.v1";
    cprisk_mac_sha256_i(runtime_material, CPRISK_ARMOR_HASH_SIZE,
                        (const uint8_t *)label, sizeof(label) - 1,
                        out_key);
    cprisk_secure_zero(runtime_material, sizeof(runtime_material));
    return 0;
}

static int cprisk_session_is_expired_i(time_t now) {
    if (atomic_load(&s_session_token_valid) == 0)
        return 1;
    if (s_session_token_expires_at <= 0)
        return 1;
    if (now < 0)
        return 1;
    return now > s_session_token_expires_at;
}

static int cprisk_verify_signed_token_i(const uint8_t *token, size_t token_len) {
    if (!token || token_len != CPRISK_SESSION_TOKEN_SIGNED_SIZE)
        return -1;

    const uint8_t *payload = token;
    const uint8_t *provided_tag = token + CPRISK_ARMOR_KEY_SIZE;
    uint8_t expected_tag[CPRISK_ARMOR_HASH_SIZE];
    uint8_t mac_key[CPRISK_ARMOR_HASH_SIZE];
    if (cprisk_session_mac_key_i(mac_key) != 0)
        return -1;

    cprisk_mac_sha256_i(
        mac_key,
        CPRISK_ARMOR_HASH_SIZE,
        payload,
        CPRISK_ARMOR_KEY_SIZE,
        expected_tag
    );
    cprisk_secure_zero(mac_key, sizeof(mac_key));

    const int rc = cprisk_mac_verify(provided_tag, expected_tag, CPRISK_ARMOR_HASH_SIZE);
    cprisk_secure_zero(expected_tag, sizeof(expected_tag));
    return rc == 0 ? 0 : -1;
}

int cprisk_set_session_token(const uint8_t *token, size_t token_len) {
    if (!token)
        return -1;

    time_t now = time(NULL);
    if (now < 0)
        return -1;

    /* ONLY signed tokens are accepted. A bare 32-byte token carries no
     * authentication and is rejected unconditionally; anything that is
     * not exactly the signed size is rejected too. */
    if (token_len != CPRISK_SESSION_TOKEN_SIGNED_SIZE)
        return -1;
    if (cprisk_verify_signed_token_i(token, token_len) != 0) {
        cprisk_clear_session_token();
        return -1;
    }

    if ((time_t)CPRISK_SESSION_TOKEN_TTL_SECONDS > (time_t)(LONG_MAX - now))
        return -1;

    memcpy(s_session_token, token, CPRISK_ARMOR_KEY_SIZE);
    atomic_store(&s_session_token_valid, 1);
    s_session_token_expires_at = now + (time_t)CPRISK_SESSION_TOKEN_TTL_SECONDS;

    return 0;
}

int cprisk_get_session_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]) {
    if (!out_key)
        return -1;

    time_t now = time(NULL);
    if (now < 0 || cprisk_session_is_expired_i(now)) {
        cprisk_clear_session_token();
        return -1;
    }

    /* Return session token as-is.
     * The caller composes effectiveRoot = CPRisk-MAC(deviceKey, sessionKey). */
    memcpy(out_key, s_session_token, CPRISK_ARMOR_KEY_SIZE);
    return 0;
}

int cprisk_has_session_token(void) {
    time_t now = time(NULL);
    if (now < 0 || cprisk_session_is_expired_i(now)) {
        cprisk_clear_session_token();
        return 0;
    }
    return 1;
}

void cprisk_clear_session_token(void) {
    cprisk_secure_zero(s_session_token, sizeof(s_session_token));
    atomic_store(&s_session_token_valid, 0);
    s_session_token_expires_at = 0;
}
