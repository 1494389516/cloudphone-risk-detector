/*
 * cprisk_codesign_bind.c
 * CRiskCore
 *
 * Team Identifier → whitebox salt derivation.
 * See cprisk_codesign_bind.h for full rationale.
 */

#include "include/cprisk_codesign_bind.h"
#include "include/CRiskCore.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#if defined(__APPLE__)
#  include <TargetConditionals.h>
#  include <Security/Security.h>
#  if __has_include(<Security/SecTask.h>)
#    include <Security/SecTask.h>
#    define CPRISK_CODESIGN_HAVE_SECTASK 1
#  endif
#  include <mach-o/dyld.h>
#  include <stddef.h>
#endif

/* ── Cached result ───────────────────────────────────────────────────────── */

/* 0 == not yet computed; 1 == failed; anything else == valid salt. */
static _Atomic(uint64_t) s_salt_cache = ATOMIC_VAR_INIT(0u);

/* ── SplitMix64 avalanche ────────────────────────────────────────────────── */

static uint64_t smix64(uint64_t x) {
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    return x ^ (x >> 31);
}

/* ── FNV-1a byte-by-byte hash ────────────────────────────────────────────── */

static uint64_t fnv1a64(const uint8_t *data, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* ── TeamID extraction ───────────────────────────────────────────────────── */

#if defined(__APPLE__)

static uint64_t derive_from_team_id(void) {
#ifndef CPRISK_CODESIGN_HAVE_SECTASK
    return 0u;
#else
    /* Entitlement key: "com.apple.developer.team-identifier"
     * XOR-obfuscated with key 0x55 to avoid plain-text scanning.
     *
     * "com.apple.developer.team-identifier" XOR 0x55:
     * c=0x16 o=0x3A m=0x38 .=0x7B a=0x34 p=0x25 p=0x25 l=0x39 e=0x30
     * .=0x7B d=0x31 e=0x30 v=0x23 e=0x30 l=0x39 o=0x3A p=0x25 e=0x30
     * r=0x27 .=0x7B t=0x21 e=0x30 a=0x34 m=0x38 -=0x68 i=0x3C d=0x31
     * e=0x30 n=0x3B t=0x21 i=0x3C f=0x33 i=0x3C e=0x30 r=0x27
     */
    static const uint8_t key_enc[] = {
        0x16,0x3A,0x38,0x7B,0x34,0x25,0x25,0x39,0x30,
        0x7B,0x31,0x30,0x23,0x30,0x39,0x3A,0x25,0x30,
        0x27,0x7B,0x21,0x30,0x34,0x38,0x68,0x3C,0x31,
        0x30,0x3B,0x21,0x3C,0x33,0x3C,0x30,0x27
    };
    char key_buf[sizeof(key_enc) + 1];
    for (size_t i = 0; i < sizeof(key_enc); i++)
        key_buf[i] = (char)(key_enc[i] ^ 0x55u);
    key_buf[sizeof(key_enc)] = '\0';

    CFStringRef ent_key = CFStringCreateWithCStringNoCopy(
        kCFAllocatorDefault, key_buf, kCFStringEncodingUTF8, kCFAllocatorNull);
    if (!ent_key) return 0u;

    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) {
        CFRelease(ent_key);
        return 0u;
    }

    CFTypeRef val = SecTaskCopyValueForEntitlement(task, ent_key, NULL);
    CFRelease(task);
    CFRelease(ent_key);

    if (!val) return 0u;

    uint64_t salt = 0u;
    if (CFGetTypeID(val) == CFStringGetTypeID()) {
        char buf[64] = {0};
        if (CFStringGetCString((CFStringRef)val, buf, sizeof(buf), kCFStringEncodingUTF8)) {
            const size_t len = strnlen(buf, sizeof(buf));
            if (len > 0) {
                salt = smix64(fnv1a64((const uint8_t *)buf, len)
                              ^ 0x434F44455349474EUll /* "CODESIGN" */);
            }
        }
    }
    CFRelease(val);
    return salt;
#endif
}

static uint64_t derive_from_executable_path(void) {
    /* Fallback: hash the executable path — stable within a build/install but
     * different across repackaged binaries (different bundle path). */
    char path[1024] = {0};
    uint32_t sz = sizeof(path);
    if (_NSGetExecutablePath(path, &sz) != 0) return 0u;
    const size_t len = strnlen(path, sizeof(path));
    if (len == 0) return 0u;
    return smix64(fnv1a64((const uint8_t *)path, len) ^ UINT64_C(0x455845435041544));  /* "EXECPATH" */
}

#endif /* __APPLE__ */

/* ── Public API ──────────────────────────────────────────────────────────── */

uint64_t cprisk_codesign_team_salt(void) {
    uint64_t cached = atomic_load_explicit(&s_salt_cache, memory_order_relaxed);
    if (cached != 0u) return (cached == 1u) ? 0u : cached;

#if defined(__APPLE__) && !TARGET_OS_SIMULATOR
    uint64_t salt = derive_from_team_id();
    if (salt == 0u)
        salt = derive_from_executable_path();
#else
    uint64_t salt = 0u;
#endif

    /* Store 1 as sentinel for "computed but zero" so we don't retry. */
    const uint64_t store_val = (salt == 0u) ? 1u : salt;
    atomic_store_explicit(&s_salt_cache, store_val, memory_order_relaxed);
    return salt;
}
