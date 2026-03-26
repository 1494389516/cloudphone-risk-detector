/*
 * Earliest feasible dyld-injection environment probes (constructor priority 1).
 * Poison is deferred to cprisk_init_protection via cprisk_apply_deferred_early_injection_policy()
 * so App Store safe / relaxed QA modes skip silent fail-closed poisoning.
 */

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)

#include <TargetConditionals.h>

#if (defined(__arm64__) || defined(__aarch64__)) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR) && \
    (!defined(TARGET_OS_TV) || !TARGET_OS_TV) && (!defined(TARGET_OS_WATCH) || !TARGET_OS_WATCH)

static atomic_uint_fast32_t s_early_inject_mask;

enum {
    CPRISK_EARLY_INJ_DYLD_INSERT_LIBRARIES = 1u << 0,
    CPRISK_EARLY_INJ_DYLD_INSERT_FRAMEWORKS = 1u << 1,
    CPRISK_EARLY_INJ_DYLD_LIBRARY_PATH = 1u << 2,
    CPRISK_EARLY_INJ_DYLD_FORCE_FLAT_NAMESPACE = 1u << 3,
};

__attribute__((constructor(1)))
static void cprisk_early_injection_env_ctor_i(void) {
    const char *ins = getenv("DYLD_INSERT_LIBRARIES");
    if (ins && ins[0] != '\0') {
        atomic_fetch_or(&s_early_inject_mask, CPRISK_EARLY_INJ_DYLD_INSERT_LIBRARIES);
    }
    const char *fw = getenv("DYLD_INSERT_FRAMEWORKS");
    if (fw && fw[0] != '\0') {
        atomic_fetch_or(&s_early_inject_mask, CPRISK_EARLY_INJ_DYLD_INSERT_FRAMEWORKS);
    }
    const char *lp = getenv("DYLD_LIBRARY_PATH");
    if (lp && lp[0] != '\0') {
        atomic_fetch_or(&s_early_inject_mask, CPRISK_EARLY_INJ_DYLD_LIBRARY_PATH);
    }
    const char *ff = getenv("DYLD_FORCE_FLAT_NAMESPACE");
    if (ff && ff[0] != '\0') {
        atomic_fetch_or(&s_early_inject_mask, CPRISK_EARLY_INJ_DYLD_FORCE_FLAT_NAMESPACE);
    }
}

uint32_t cprisk_get_early_injection_env_mask(void) {
    return (uint32_t)atomic_load_explicit(&s_early_inject_mask, memory_order_relaxed);
}

#else /* Simulator / non-arm64 Apple */

uint32_t cprisk_get_early_injection_env_mask(void) {
    return 0u;
}

#endif

#else /* !__APPLE__ */

uint32_t cprisk_get_early_injection_env_mask(void) {
    return 0u;
}

#endif
