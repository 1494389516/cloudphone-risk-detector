/*
 * Prologue snapshots for Security.framework trust-evaluation exports plus dlopen/dlsym,
 * to detect Frida-style Interceptor patches on the TLS pinning / trust path.
 * Mirrors the anti-debug watchdog memcpy+memcmp strategy (see anti_debug_watchdog.c).
 */

#include "include/CRiskCore.h"

#include <dlfcn.h>
#include <stdatomic.h>
#include <string.h>

#if defined(__APPLE__)

#include <Security/Security.h>

#define CPRISK_THS_PROLOGUE_BYTES 16u
#define CPRISK_THS_SEC_SLOT_COUNT 3u

static uint8_t s_ths_sec_ref[CPRISK_THS_SEC_SLOT_COUNT][CPRISK_THS_PROLOGUE_BYTES];
static uint8_t s_ths_sec_last_ok[CPRISK_THS_SEC_SLOT_COUNT][CPRISK_THS_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_ths_sec_last_ok_valid = 0u;
static atomic_uint_fast32_t s_ths_captured = 0u;

static uint8_t s_ths_dlopen_ref[CPRISK_THS_PROLOGUE_BYTES];
static uint8_t s_ths_dlopen_last_ok[CPRISK_THS_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_ths_dlopen_last_ok_valid = 0u;

static void cprisk_ths_fill_sec_addrs(const void **addrs) {
    addrs[0] = (const void *)&SecTrustEvaluateWithError;
    addrs[1] = (const void *)&SecTrustGetTrustResult;
    addrs[2] = (const void *)&SecTrustCopyKey;
}

static void cprisk_ths_capture_once_i(void) {
    if (atomic_load(&s_ths_captured) != 0u) {
        return;
    }
    const void *addrs[CPRISK_THS_SEC_SLOT_COUNT];
    cprisk_ths_fill_sec_addrs(addrs);
    for (uint32_t i = 0u; i < CPRISK_THS_SEC_SLOT_COUNT; i++) {
        memcpy(s_ths_sec_ref[i], addrs[i], CPRISK_THS_PROLOGUE_BYTES);
    }
    memcpy(s_ths_dlopen_ref, (const void *)&dlopen, CPRISK_THS_PROLOGUE_BYTES);
    atomic_store(&s_ths_captured, 1u);
}

__attribute__((constructor(10)))
static void cprisk_ths_early_ctor_i(void) {
    cprisk_ths_capture_once_i();
}

static int cprisk_ths_verify_dlopen_prologue_i(uint32_t *mask_out) {
    if (atomic_load(&s_ths_captured) == 0u) {
        cprisk_ths_capture_once_i();
    }
    uint8_t live[CPRISK_THS_PROLOGUE_BYTES];
    memcpy(live, (const void *)&dlopen, CPRISK_THS_PROLOGUE_BYTES);
    if (atomic_load_explicit(&s_ths_dlopen_last_ok_valid, memory_order_relaxed) != 0u &&
        memcmp(s_ths_dlopen_last_ok, live, CPRISK_THS_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_TRUST_HOOK_FAIL_DLOPEN;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    if (memcmp(s_ths_dlopen_ref, live, CPRISK_THS_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_TRUST_HOOK_FAIL_DLOPEN;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    memcpy(s_ths_dlopen_last_ok, live, CPRISK_THS_PROLOGUE_BYTES);
    atomic_store_explicit(&s_ths_dlopen_last_ok_valid, 1u, memory_order_release);
    return 1;
}

int cprisk_verify_trust_hook_surface_integrity(uint32_t *fail_mask_out) {
    uint32_t mask = 0u;
    if (fail_mask_out != NULL) {
        *fail_mask_out = 0u;
    }

    cprisk_ths_capture_once_i();

    const void *addrs[CPRISK_THS_SEC_SLOT_COUNT];
    cprisk_ths_fill_sec_addrs(addrs);
    const int have_last =
        atomic_load_explicit(&s_ths_sec_last_ok_valid, memory_order_relaxed) != 0u;
    for (uint32_t i = 0u; i < CPRISK_THS_SEC_SLOT_COUNT; i++) {
        uint8_t live[CPRISK_THS_PROLOGUE_BYTES];
        memcpy(live, addrs[i], CPRISK_THS_PROLOGUE_BYTES);
        if (have_last != 0 &&
            memcmp(s_ths_sec_last_ok[i], live, CPRISK_THS_PROLOGUE_BYTES) != 0) {
            mask |= (1u << i);
            cprisk_integrity_poison_watchdog_lane_now();
        }
        if (memcmp(s_ths_sec_ref[i], live, CPRISK_THS_PROLOGUE_BYTES) != 0) {
            mask |= (1u << i);
            cprisk_integrity_poison_watchdog_lane_now();
        }
        memcpy(s_ths_sec_last_ok[i], live, CPRISK_THS_PROLOGUE_BYTES);
    }
    atomic_store_explicit(&s_ths_sec_last_ok_valid, 1u, memory_order_release);

    if (cprisk_verify_dlsym_prologue() == 0) {
        mask |= CPRISK_TRUST_HOOK_FAIL_DLSYM;
    }
    if (cprisk_ths_verify_dlopen_prologue_i(&mask) == 0) {
        /* mask already updated */
    }

    if (fail_mask_out != NULL) {
        *fail_mask_out = mask;
    }
    return mask == 0u ? 1 : 0;
}

#else /* !__APPLE__ */

int cprisk_verify_trust_hook_surface_integrity(uint32_t *fail_mask_out) {
    if (fail_mask_out != NULL) {
        *fail_mask_out = 0u;
    }
    return 1;
}

#endif /* __APPLE__ */
