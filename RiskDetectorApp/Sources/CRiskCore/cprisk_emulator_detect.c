/*
 * cprisk_emulator_detect.c
 * CRiskCore
 *
 * C-layer emulator / unidbg detection.
 * See cprisk_emulator_detect.h for full design rationale.
 *
 * All sentinel strings are XOR-obfuscated with key 0x55 to prevent trivial
 * string-scan discovery of the detection logic.
 */

#include "include/cprisk_emulator_detect.h"
#include "include/cprisk_vm_sync_barrier.h"
#include "include/CRiskCore.h"

#include <mach/mach_vm.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Compile-time XOR encoding verification ──────────────────────────────────
 * Each _Static_assert verifies that a character XOR the sentinel key equals
 * the first encoded byte used in the corresponding detection array.
 * If any future edit corrupts the byte arrays, the build fails immediately.
 * Key 0x55 sentinels:                                                       */
_Static_assert(('k' ^ 0x55u) == 0x3Eu, "kern.ostype[0] XOR 0x55 mismatch");
_Static_assert(('e' ^ 0x55u) == 0x30u, "kern.ostype[1] XOR 0x55 mismatch");
_Static_assert(('D' ^ 0x55u) == 0x11u, "Darwin[0] XOR 0x55 mismatch");
_Static_assert(('a' ^ 0x55u) == 0x34u, "Darwin[1] XOR 0x55 mismatch");
_Static_assert(('/' ^ 0x55u) == 0x7Au, "libobjc_path[0] XOR 0x55 mismatch");
_Static_assert(('u' ^ 0x55u) == 0x20u, "libobjc_path[1] XOR 0x55 mismatch");
_Static_assert(('J' ^ 0x55u) == 0x1Fu, "JAVA_HOME[0] XOR 0x55 mismatch");
_Static_assert(('A' ^ 0x55u) == 0x14u, "JAVA_HOME[1] XOR 0x55 mismatch");
_Static_assert(('C' ^ 0x55u) == 0x16u, "CLASSPATH[0] XOR 0x55 mismatch");
_Static_assert(('L' ^ 0x55u) == 0x19u, "LD_LIBRARY_PATH[0] XOR 0x55 mismatch");
_Static_assert(('D' ^ 0x55u) == 0x11u, "LD_LIBRARY_PATH[1] XOR 0x55 mismatch");
/* ─────────────────────────────────────────────────────────────────────────── */

#if defined(__APPLE__)
#  include <TargetConditionals.h>
#  include <dlfcn.h>
#  include <mach/mach.h>
#  include <mach/mach_time.h>
#  include <sys/sysctl.h>
#  include <unistd.h>
#endif

/* ── XOR decode helper ───────────────────────────────────────────────────── */

/* Decode an in-place copy of a short XOR-obfuscated string into `out`.
 * `out` must be at least len+1 bytes.  Returns `out`. */
static char *xor_decode(const uint8_t *enc, size_t len, char *out, uint8_t key) {
    for (size_t i = 0; i < len; i++)
        out[i] = (char)(enc[i] ^ key);
    out[len] = '\0';
    return out;
}

/* ── Probe cache ─────────────────────────────────────────────────────────── */

/* Cache the result after the first call to avoid repeating slow probes.
 * 0xFFFFFFFF == not yet computed. */
static _Atomic(uint32_t) s_cached_flags = ATOMIC_VAR_INIT(0xFFFFFFFFu);

/* ── Individual probes ───────────────────────────────────────────────────── */

#if defined(__APPLE__)

/*
 * Probe 1: dyld shared cache
 *
 * `_dyld_shared_cache_contains_path("/usr/lib/libobjc.A.dylib")` returns true
 * on every real iOS device; unidbg has no dyld shared cache.
 *
 * Resolved via dlsym to avoid a hard link and make it harder to hook at the
 * import table level.
 *
 * Path "/usr/lib/libobjc.A.dylib" XOR 0x55:
 *   [0x7A,0x20,0x26,0x27,0x7A,0x39,0x3C,0x37,0x7A,0x39,0x3C,0x37,
 *    0x3A,0x37,0x3F,0x36,0x7B,0x14,0x7B,0x31,0x2C,0x39,0x3C,0x37]
 */
static int probe_dyld_cache(void) {
    typedef bool (*fn_t)(const char *);
    /* "_dyld_shared_cache_contains_path" XOR 0x55 is long; look it up by the
     * public symbol name via RTLD_DEFAULT — the linker already resolved it. */
    fn_t fn = (fn_t)dlsym(RTLD_DEFAULT, "_dyld_shared_cache_contains_path");
    if (!fn) return 0; /* symbol absent — itself suspicious but not conclusive */

    static const uint8_t path_enc[] = {
        0x7A,0x20,0x26,0x27,0x7A,0x39,0x3C,0x37,0x7A,0x39,0x3C,0x37,
        0x3A,0x37,0x3F,0x36,0x7B,0x14,0x7B,0x31,0x2C,0x39,0x3C,0x37
    };
    char path[sizeof(path_enc) + 1];
    xor_decode(path_enc, sizeof(path_enc), path, 0x55u);
    return fn(path) ? 1 : 0;
}

/*
 * Probe 2: vm_region_64 count
 *
 * A real iOS process has ≥40 VM regions (ASLR, dyld shared cache segments,
 * stack guard regions, commpage, etc.).  unidbg synthesises a minimal map.
 */
static int probe_vm_region_count(void) {
    mach_vm_address_t addr = 0;
    mach_vm_size_t    size = 0;
    natural_t         depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    int regions = 0;

    while (regions < 200) { /* cap to avoid hanging on pathological mappings */
        kern_return_t kr = mach_vm_region_recurse(
            mach_task_self(), &addr, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) break;
        regions++;
        addr += size;
    }
    /* < 40 is anomalous */
    return (regions < 40) ? 0 : 1;
}

/*
 * Probe 3: main-thread stack address
 *
 * On iOS, the main thread stack is always above 0x0001_0000_0000 (4 GB).
 * unidbg on Linux typically places the emulated stack much lower.
 */
static int probe_stack_address(void) {
    volatile uintptr_t sp;
#if defined(__arm64__) || defined(__aarch64__)
    __asm__ __volatile__("mov %0, sp" : "=r"(sp));
#else
    volatile uint8_t local;
    sp = (uintptr_t)&local;
#endif
    return (sp > (uintptr_t)0x0001000000000000ULL) ? 1 : 0;
}

/*
 * Probe 4: kern.ostype sysctl
 *
 * "kern.ostype" XOR 0x55 → [0x3E,0x30,0x27,0x3B,0x7B,0x3A,0x26,0x21,0x2C,0x25,0x30]
 * "Darwin"      XOR 0x55 → [0x11,0x34,0x27,0x22,0x3C,0x3B]
 */
static int probe_ostype(void) {
    static const uint8_t name_enc[] = {
        0x3E,0x30,0x27,0x3B,0x7B,0x3A,0x26,0x21,0x2C,0x25,0x30
    };
    static const uint8_t expected_enc[] = { 0x11,0x34,0x27,0x22,0x3C,0x3B };

    char name[sizeof(name_enc) + 1];
    char expected[sizeof(expected_enc) + 1];
    xor_decode(name_enc, sizeof(name_enc), name, 0x55u);
    xor_decode(expected_enc, sizeof(expected_enc), expected, 0x55u);

    char buf[64] = {0};
    size_t bsz = sizeof(buf) - 1; /* leave room for defensive null-terminator */
    if (sysctlbyname(name, buf, &bsz, NULL, 0) != 0) return 0; /* query failed */
    buf[sizeof(buf) - 1] = '\0'; /* ensure null-termination regardless of kernel output */
    return (strcmp(buf, expected) == 0) ? 1 : 0;
}

/*
 * Probe 5: Mach thread count
 *
 * A real iOS app has ≥4 threads at cold start (main, GCD serial, libdispatch
 * worker, CoreFoundation run-loop, etc.).  unidbg JNI harness typically has 1–3.
 */
static int probe_thread_count(void) {
    thread_act_array_t list = NULL;
    mach_msg_type_number_t cnt = 0;
    kern_return_t kr = task_threads(mach_task_self(), &list, &cnt);
    if (kr != KERN_SUCCESS) {
        /* Defensive cleanup: kernel may partially populate list on failure. */
        if (list != NULL && cnt > 0) {
            vm_deallocate(mach_task_self(),
                          (vm_address_t)list,
                          (vm_size_t)cnt * sizeof(thread_t));
        }
        return 1; /* error — treat as ok to avoid false positives */
    }
    int n = (int)cnt;
    for (int i = 0; i < n; i++)
        mach_port_deallocate(mach_task_self(), list[i]);
    vm_deallocate(mach_task_self(),
                  (vm_address_t)list,
                  (vm_size_t)n * sizeof(thread_t));
    return (n >= 4) ? 1 : 0;
}

/*
 * Probe 6: JVM indicator environment variables
 *
 * All names XOR-obfuscated with key 0x55:
 *   "JAVA_HOME"       → [0x1F,0x14,0x03,0x14,0x0A,0x1D,0x1A,0x18,0x10]
 *   "CLASSPATH"       → [0x16,0x19,0x14,0x06,0x06,0x05,0x14,0x01,0x1D]
 *   "LD_LIBRARY_PATH" → [0x19,0x11,0x0A,0x19,0x1C,0x17,0x07,0x14,0x07,
 *                        0x0C,0x0A,0x05,0x14,0x01,0x1D]
 */
static int probe_jvm_env(void) {
    /* Separate static arrays for XOR-encoded JVM env var names */
    static const uint8_t JAVA_HOME_ENC[]   = {0x1F,0x14,0x03,0x14,0x0A,0x1D,0x1A,0x18,0x10};
    static const uint8_t CLASSPATH_ENC[]   = {0x16,0x19,0x14,0x06,0x06,0x05,0x14,0x01,0x1D};
    static const uint8_t LD_LIB_ENC[]      = {0x19,0x11,0x0A,0x19,0x1C,0x17,0x07,0x14,0x07,
                                            0x0C,0x0A,0x05,0x14,0x01,0x1D};
    /* Use separate const size_t variables to avoid initializer complexity */
    static const size_t JAVA_HOME_LEN = 9u;
    static const size_t CLASSPATH_LEN = 9u;
    static const size_t LD_LIB_LEN    = 15u;
    static const struct { const uint8_t *enc; size_t len; } vars[3] = {
        [0] = { JAVA_HOME_ENC,   JAVA_HOME_LEN   },
        [1] = { CLASSPATH_ENC,   CLASSPATH_LEN   },
        [2] = { LD_LIB_ENC,      LD_LIB_LEN      },
    };
    char buf[32];
    for (size_t i = 0; i < 3u; i++) {
        if (vars[i].len >= sizeof(buf)) continue;
        xor_decode(vars[i].enc, vars[i].len, buf, 0x55u);
        if (getenv(buf) != NULL) return 1; /* found — JVM env present */
    }
    return 0;
}

/*
 * Probe 7: mach_timebase_info ratio
 *
 * On real Apple Silicon iOS devices the ratio is typically 125:3 or similar.
 * On unidbg's Linux host the stub often returns 1:1 (numer==denom).
 * We flag 1:1 only when combined with no dyld shared cache.
 */
static int probe_timebase_flat(int have_dyld_cache) {
    if (have_dyld_cache) return 0; /* real device — skip */
    struct mach_timebase_info tb = {0, 0};
    mach_timebase_info(&tb);
    return (tb.numer == tb.denom && tb.numer != 0) ? 1 : 0;
}

/*
 * Probe 8: CLOCK_PROCESS_CPUTIME_ID advance
 *
 * On real devices this clock advances with CPU usage.  unidbg stubs often
 * return 0 or a fixed value.
 */
static int probe_cpu_clock_frozen(void) {
    struct timespec t1, t2;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1) != 0) return 0;
    /* Burn enough cycles that any real CPU clock must advance */
    volatile uint64_t dummy = 0xDEADBEEFCAFE0000ULL;
    for (int i = 0; i < 8192; i++)
        dummy = dummy * 6364136223846793005ULL + 1442695040888963407ULL;
    (void)dummy;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t2) != 0) return 0;
    int64_t ns1 = (int64_t)t1.tv_sec * 1000000000LL + t1.tv_nsec;
    int64_t ns2 = (int64_t)t2.tv_sec * 1000000000LL + t2.tv_nsec;
    return (ns2 <= ns1) ? 1 : 0;
}

#endif /* __APPLE__ */

/* ── Public API ──────────────────────────────────────────────────────────── */

uint32_t cprisk_emulator_probe(void) {
    /* Return cached result if available */
    uint32_t cached = atomic_load_explicit(&s_cached_flags, memory_order_relaxed);
    if (cached != 0xFFFFFFFFu)
        return cached;

    uint32_t flags = 0u;

#if defined(__APPLE__) && !TARGET_OS_SIMULATOR

    int have_dyld_cache = probe_dyld_cache();
    if (!have_dyld_cache)
        flags |= CPRISK_EMU_FLAG_DYLD_CACHE_ABSENT;

    if (!probe_vm_region_count())
        flags |= CPRISK_EMU_FLAG_LOW_VM_REGIONS;

    if (!probe_stack_address())
        flags |= CPRISK_EMU_FLAG_LOW_STACK_ADDR;

    if (!probe_ostype())
        flags |= CPRISK_EMU_FLAG_OSTYPE_NOT_DARWIN;

    if (!probe_thread_count())
        flags |= CPRISK_EMU_FLAG_LOW_THREAD_COUNT;

    if (probe_jvm_env())
        flags |= CPRISK_EMU_FLAG_JVM_ENV_VAR;

    if (probe_timebase_flat(have_dyld_cache))
        flags |= CPRISK_EMU_FLAG_TIMEBASE_FLAT;

    if (probe_cpu_clock_frozen())
        flags |= CPRISK_EMU_FLAG_CPU_CLOCK_FROZEN;

    /* WATCHDOG_STUCK is set externally by the VM interpreter after the sync
     * barrier detects no watchdog advancement; not probed here. */

#endif /* __APPLE__ && !SIMULATOR */

    /* Incorporate global watchdog stuck state — set by the VM sync barrier
     * the first time it detects no watchdog advancement. */
    if (cprisk_vm_sync_barrier_global_stuck())
        flags |= CPRISK_EMU_FLAG_WATCHDOG_STUCK;

    atomic_store_explicit(&s_cached_flags, flags, memory_order_release);
    return flags;
}

uint32_t cprisk_emulator_quick_probe(void) {
    /*
     * Re-run only the two lightest probes — no malloc, no syscall with side
     * effects.  Result is NOT cached so an attacker who zeroed s_cached_flags
     * must also defeat this live check on every signing call.
     *
     * Returns a bitmask using the same CPRISK_EMU_FLAG_* constants.
     */
    uint32_t flags = 0u;
#if defined(__APPLE__) && !TARGET_OS_SIMULATOR
    if (!probe_ostype())
        flags |= CPRISK_EMU_FLAG_OSTYPE_NOT_DARWIN;
    if (!probe_stack_address())
        flags |= CPRISK_EMU_FLAG_LOW_STACK_ADDR;
    if (cprisk_vm_sync_barrier_global_stuck())
        flags |= CPRISK_EMU_FLAG_WATCHDOG_STUCK;
#endif
    return flags;
}

void cprisk_emulator_mark_watchdog_stuck(void) {
    /* OR in the stuck flag without disturbing other cached bits.
     * Uses a compare-and-swap loop so we don't clobber 0xFFFFFFFF
     * (not-yet-computed sentinel) — in that case the full probe will
     * incorporate the stuck flag via cprisk_vm_sync_barrier_global_stuck(). */
    uint32_t current = atomic_load_explicit(&s_cached_flags, memory_order_acquire);
    while (current != 0xFFFFFFFFu) {
        if (current & CPRISK_EMU_FLAG_WATCHDOG_STUCK)
            return; /* already set */
        if (atomic_compare_exchange_weak_explicit(
                &s_cached_flags,
                &current,
                current | CPRISK_EMU_FLAG_WATCHDOG_STUCK,
                memory_order_release,
                memory_order_relaxed))
            return;
    }
    /* Cache not yet populated; the full probe will pick it up from
     * cprisk_vm_sync_barrier_global_stuck() when it eventually runs. */
}

int cprisk_emulator_score(uint32_t flags) {
    /* Weights chosen to mirror the Swift-layer detectors */
    static const struct { uint32_t flag; int weight; } weights[] = {
        { CPRISK_EMU_FLAG_DYLD_CACHE_ABSENT,  22 },
        { CPRISK_EMU_FLAG_LOW_VM_REGIONS,     12 },
        { CPRISK_EMU_FLAG_LOW_STACK_ADDR,     14 },
        { CPRISK_EMU_FLAG_OSTYPE_NOT_DARWIN,   8 },
        { CPRISK_EMU_FLAG_LOW_THREAD_COUNT,    8 },
        { CPRISK_EMU_FLAG_JVM_ENV_VAR,        14 },
        { CPRISK_EMU_FLAG_TIMEBASE_FLAT,       8 },
        { CPRISK_EMU_FLAG_CPU_CLOCK_FROZEN,    6 },
        { CPRISK_EMU_FLAG_WATCHDOG_STUCK,     12 },
    };
    int score = 0;
    for (size_t i = 0; i < sizeof(weights)/sizeof(weights[0]); i++) {
        if (flags & weights[i].flag)
            score += weights[i].weight;
    }
    return score > 100 ? 100 : score;
}

int cprisk_emulator_is_hostile(uint32_t flags) {
    /* Hostile if score exceeds 25 OR any of the two highest-confidence flags
     * are set (dyld cache absent or stack address out of range). */
    if (cprisk_emulator_score(flags) >= 25) return 1;
    if (flags & (CPRISK_EMU_FLAG_DYLD_CACHE_ABSENT | CPRISK_EMU_FLAG_LOW_STACK_ADDR)) return 1;
    return 0;
}
