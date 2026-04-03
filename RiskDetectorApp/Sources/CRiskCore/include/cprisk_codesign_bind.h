#ifndef CPRISK_CODESIGN_BIND_H
#define CPRISK_CODESIGN_BIND_H

/*
 * cprisk_codesign_bind.h
 * CRiskCore
 *
 * Derives a 64-bit salt from the running app's code-signing Team Identifier.
 *
 * ## Purpose
 * Without this binding, a repackaged app (different TeamID) can call the SDK
 * and get correct risk-detection output.  By mixing the TeamID into the
 * whitebox S-box table XOR pad, the tables only decrypt to valid keys when
 * the same Team Identifier is present at runtime.  A repackaged binary uses a
 * different TeamID → wrong XOR pad → corrupted S-box → wrong PRF output →
 * risk score is silently incorrect without any crash.
 *
 * ## Derivation
 * 1. `SecTaskCopyValueForEntitlement(NULL, "com.apple.developer.team-identifier")`
 *    — reads the in-memory entitlement blob attached to the running task.
 * 2. If unavailable (simulator, no entitlement), falls back to
 *    `_NSGetExecutablePath` + SHA-256 path hash so the salt is still non-zero
 *    and deterministic within the same binary.
 * 3. Result is cached after first call (atomic).
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns a stable 64-bit salt derived from the running app's TeamID.
 * Thread-safe; first call may take up to ~1 ms (Security framework lookup).
 * Subsequent calls return a cached value in < 1 ns.
 *
 * Returns 0 only if derivation completely failed — callers should treat 0
 * as a neutral (do-nothing) salt so legitimate apps without entitlements
 * still function normally.
 */
uint64_t cprisk_codesign_team_salt(void);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_CODESIGN_BIND_H */
