/*
 * cprisk_signal_probe.c — Low-level anti-debug probes using signals,
 * hardware breakpoint detection, timing analysis, Mach thread inspection,
 * csops CS_DEBUGGED check, and Developer Disk Image detection.
 *
 * All functions return 0 (safe default) on simulator / non-arm64 platforms.
 */

#include "include/CRiskCore.h"

#include <signal.h>
#include <setjmp.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <sys/syscall.h>
#endif

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_SIGNAL_PROBE_AVAILABLE 1
#else
#define CPRISK_SIGNAL_PROBE_AVAILABLE 0
#endif

/* ===================================================================== */
#if CPRISK_SIGNAL_PROBE_AVAILABLE
/* ===================================================================== */

#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <mach/mach_time.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <crt_externs.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <time.h>
#include "include/cprisk_macho.h"

#define CPRISK_EXCEPTION_DELIVERY_TIMEOUT_NS 10000000ull
#define CPRISK_SINGLE_STEP_DEFAULT_THRESHOLD_NS 50000000ull
#define CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS 5000000ull
#define CPRISK_SINGLE_STEP_THRESHOLD_MULTIPLIER 16ull
#define CPRISK_SINGLE_STEP_CALIBRATION_SAMPLES 9u
#define CPRISK_TIMING_SAMPLE_COUNT 7u
#define CPRISK_TIMING_MEDIAN_MULTIPLIER 14ull
#define CPRISK_TIMING_SPIKE_MULTIPLIER 22ull
#define CPRISK_TIMING_JITTER_DIVISOR 4ull
#define CPRISK_SOFTWARE_BP_RANDOM_DEFAULT_WINDOWS 8u
#define CPRISK_SOFTWARE_BP_RANDOM_DEFAULT_WINDOW_BYTES 768u

/* ── (a) SIGTRAP signal probe ─────────────────────────────────────── */

static sigjmp_buf s_trap_jmpbuf;
static volatile sig_atomic_t s_sigtrap_flag = 0;
static sigjmp_buf s_exception_delivery_jmpbuf;
static volatile sig_atomic_t s_exception_delivery_sigtrap = 0;
static atomic_uint_fast32_t s_exception_delivery_probe_armed = 0;
static atomic_uint_fast32_t s_exception_delivery_probe_handled = 0;
static atomic_uint_fast64_t s_exception_delivery_probe_start_ns = 0;
static atomic_uint_fast64_t s_exception_delivery_probe_last_ns = 0;
static atomic_uint_fast64_t s_single_step_baseline_ns = 0;
static atomic_uint_fast64_t s_single_step_threshold_ns = 0;
static atomic_uint_fast32_t s_single_step_calibrated = 0;
static atomic_flag s_single_step_calibration_lock = ATOMIC_FLAG_INIT;
static atomic_uint_fast32_t s_dbi_last_marker_flags = 0;
static atomic_uint_fast32_t s_dbi_last_hit_count = 0;
static atomic_uint_fast32_t s_timing_last_anomaly_flags = 0;
static atomic_uint_fast64_t s_timing_last_median_ns = 0;
static atomic_uint_fast64_t s_timing_last_max_ns = 0;
static atomic_uint_fast64_t s_timing_last_threshold_ns = 0;

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_TIMING_CNTPCT_AVAILABLE 1
#else
#define CPRISK_TIMING_CNTPCT_AVAILABLE 0
#endif

static uint64_t cprisk_mach_abs_to_ns_i(uint64_t delta_abs) {
    mach_timebase_info_data_t tb;
    if (mach_timebase_info(&tb) != KERN_SUCCESS || tb.denom == 0u) {
        return 0u;
    }

    return delta_abs / tb.denom * tb.numer + (delta_abs % tb.denom) * tb.numer / tb.denom;
}

static uint64_t cprisk_monotonic_now_ns_i(void) {
#if CPRISK_TIMING_CNTPCT_AVAILABLE
    static _Atomic uint64_t s_cntfrq = 0u;
    uint64_t freq = atomic_load_explicit(&s_cntfrq, memory_order_relaxed);
    if (freq == 0u) {
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
        atomic_store_explicit(&s_cntfrq, freq, memory_order_relaxed);
    }
    if (freq != 0u) {
        uint64_t ticks = 0u;
        __asm__ volatile("mrs %0, cntpct_el0" : "=r"(ticks));
        return (ticks / freq) * 1000000000ull +
               ((ticks % freq) * 1000000000ull) / freq;
    }
#endif
    return cprisk_mach_abs_to_ns_i(mach_absolute_time());
}

static uint64_t cprisk_random_u64_i(void) {
    uint64_t value = 0u;
    int err = 0;
    if (cprisk_getentropy_direct(&value, sizeof(value), &err) == 0) {
        return value;
    }
    (void)err;
    value = cprisk_monotonic_now_ns_i();
    value ^= ((uint64_t)(uintptr_t)&value << 21u);
    value ^= value >> 7u;
    value ^= value << 13u;
    return value;
}

static uint64_t cprisk_prng_next_i(uint64_t *state) {
    uint64_t x = *state;
    if (x == 0u) {
        x = 0xC3A5C85C97CB3127ULL;
    }
    x ^= x << 7u;
    x ^= x >> 9u;
    x ^= x << 8u;
    *state = x;
    return x;
}

static int cprisk_ascii_tolower_i(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static int cprisk_contains_token_ascii_i(const char *haystack, const char *needle) {
    if (!haystack || !needle || needle[0] == '\0') {
        return 0;
    }

    size_t nlen = 0u;
    while (needle[nlen] != '\0') {
        nlen++;
    }
    if (nlen == 0u) {
        return 0;
    }

    for (size_t i = 0u; haystack[i] != '\0'; i++) {
        size_t j = 0u;
        while (j < nlen) {
            const int hc = cprisk_ascii_tolower_i((unsigned char)haystack[i + j]);
            const int nc = cprisk_ascii_tolower_i((unsigned char)needle[j]);
            if (haystack[i + j] == '\0' || hc != nc) {
                break;
            }
            j++;
        }
        if (j == nlen) {
            return 1;
        }
    }
    return 0;
}

static int cprisk_contains_any_token_i(
    const char *text,
    const char *const *tokens,
    size_t token_count
) {
    if (!text || !tokens || token_count == 0u) {
        return 0;
    }

    for (size_t i = 0u; i < token_count; i++) {
        if (tokens[i] && cprisk_contains_token_ascii_i(text, tokens[i])) {
            return 1;
        }
    }
    return 0;
}

static uint32_t cprisk_detect_dbi_env_markers_i(int *hit_count_out) {
    static const char *const strict_env_keys[] = {
        "PIN_VM",
        "PIN_ROOT",
        "PIN_CRT",
        "PIN_APP_DYLIB",
        "DYNAMORIO_OPTIONS",
        "DYNAMORIO_HOME",
        "DYNAMORIO_LOGDIR",
        "VALGRIND_LAUNCHER",
        "VALGRIND_LIB",
        "VALGRIND_OPTS",
        /* QBDI / QuarkslaB DBI (desktop + some embedded runners expose these). */
        "QBDI_PRELOAD",
        "QBDI_LOG",
        "QBDI_LIB",
        "QBDI_MAX_INST_COUNT",
        "QBDI_APPEND",
        "QBDI_FRIDA",
        "QBDI_STOCK_FILE_REMOVE",
    };
    static const char *const tokenized_env_keys[] = {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "LD_PRELOAD",
    };
    static const char *const dbi_tokens[] = {
        "pinvm",
        "pincrt",
        "/pin/",
        "dynamorio",
        "libdynamorio",
        "drrun",
        "valgrind",
        "vgpreload",
        "memcheck",
        "helgrind",
        "drmemory",
        /* QBDI */
        "qbdi",
        "libqbdi",
        "qbdipreload",
        "/qbdi/",
        "quarkslab",
    };

    int hit_count = 0;
    uint32_t flags = 0u;

    for (size_t i = 0u; i < sizeof(strict_env_keys) / sizeof(strict_env_keys[0]); i++) {
        const char *value = getenv(strict_env_keys[i]);
        if (value && value[0] != '\0') {
            flags |= CPRISK_DBI_MARKER_ENV;
            hit_count++;
        }
    }

    for (size_t i = 0u; i < sizeof(tokenized_env_keys) / sizeof(tokenized_env_keys[0]); i++) {
        const char *value = getenv(tokenized_env_keys[i]);
        if (!value || value[0] == '\0') {
            continue;
        }
        if (cprisk_contains_any_token_i(
                value, dbi_tokens, sizeof(dbi_tokens) / sizeof(dbi_tokens[0]))) {
            flags |= CPRISK_DBI_MARKER_ENV;
            hit_count++;
        }
    }

    if (hit_count_out) {
        *hit_count_out = hit_count;
    }
    return flags;
}

/*
 * Bounded scan of the entire environ table for DBI/QBDI substring markers.
 * Catches renamed or custom env vars that strict-key checks miss.
 */
static uint32_t cprisk_detect_dbi_environ_scan_i(int *hit_count_out) {
    static const char *const scan_tokens[] = {
        "pinvm",
        "pincrt",
        "/pin/",
        "dynamorio",
        "libdynamorio",
        "drrun",
        "valgrind",
        "vgpreload",
        "memcheck",
        "helgrind",
        "drmemory",
        "qbdi",
        "libqbdi",
        "qbdipreload",
        "/qbdi/",
        "quarkslab",
    };

    int hit_count = 0;
    uint32_t flags = 0u;

    char ***penv = _NSGetEnviron();
    if (!penv || *penv == NULL) {
        if (hit_count_out) {
            *hit_count_out = 0;
        }
        return 0u;
    }

    for (char **e = *penv; *e != NULL; e++) {
        const char *line = *e;
        if (!line || line[0] == '\0') {
            continue;
        }
        size_t walk = 0u;
        while (line[walk] != '\0' && walk < 4096u) {
            walk++;
        }
        if (walk >= 4096u) {
            continue;
        }
        if (cprisk_contains_any_token_i(
                line,
                scan_tokens,
                sizeof(scan_tokens) / sizeof(scan_tokens[0]))) {
            flags |= CPRISK_DBI_MARKER_ENVIRON_SCAN;
            hit_count++;
            break;
        }
    }

    if (hit_count_out) {
        *hit_count_out = hit_count;
    }
    return flags;
}

static uint32_t cprisk_detect_dbi_image_markers_i(int *hit_count_out) {
    static const char *const image_tokens[] = {
        "pinvm",
        "pincrt",
        "libdynamorio",
        "dynamorio",
        "drrun",
        "valgrind",
        "vgpreload",
        "memcheck",
        "helgrind",
        "drmemory",
        "qbdi",
        "libqbdi",
        "qbdipreload",
        "/qbdi/",
    };

    uint32_t flags = 0u;
    int hit_count = 0;
    const uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0u; i < image_count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || name[0] == '\0') {
            continue;
        }
        if (cprisk_contains_any_token_i(
                name, image_tokens, sizeof(image_tokens) / sizeof(image_tokens[0]))) {
            flags |= CPRISK_DBI_MARKER_IMAGE;
            hit_count++;
        }
    }

    if (hit_count_out) {
        *hit_count_out = hit_count;
    }
    return flags;
}

static uint32_t cprisk_detect_dbi_thread_markers_i(int *hit_count_out) {
    static const char *const thread_tokens[] = {
        "dynamorio",
        "drrun",
        "drhelper",
        "drmemory",
        "valgrind",
        "memcheck",
        "helgrind",
        "pinvm",
        "pin-worker",
        "pin-tool",
        "qbdi",
        "qbdipreload",
    };

    uint32_t flags = 0u;
    int hit_count = 0;
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    if (task_threads(mach_task_self(), &threads, &thread_count) != KERN_SUCCESS) {
        if (hit_count_out) {
            *hit_count_out = 0;
        }
        return 0u;
    }

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        char name[64];
        memset(name, 0, sizeof(name));
        pthread_t pthread_handle = pthread_from_mach_thread_np(threads[i]);
        if ((uintptr_t)pthread_handle == 0u) {
            continue;
        }
        if (pthread_getname_np(pthread_handle, name, sizeof(name)) != 0 || name[0] == '\0') {
            continue;
        }
        if (cprisk_contains_any_token_i(
                name, thread_tokens, sizeof(thread_tokens) / sizeof(thread_tokens[0]))) {
            flags |= CPRISK_DBI_MARKER_THREAD;
            hit_count++;
        }
    }

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(
        mach_task_self(),
        (vm_address_t)threads,
        sizeof(thread_act_t) * thread_count);

    if (hit_count_out) {
        *hit_count_out = hit_count;
    }
    return flags;
}

static uint32_t cprisk_detect_dbi_execmem_i(int *hit_count_out) {
    uint32_t flags = 0u;
    int hit_count = 0;
    mach_vm_address_t addr = MACH_VM_MIN_ADDRESS;

    while (1) {
        mach_vm_size_t region_size = 0u;
        uint32_t depth = 0u;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(
            mach_task_self(),
            &addr,
            &region_size,
            &depth,
            (vm_region_recurse_info_t)&info,
            &info_count
        );
        if (kr != KERN_SUCCESS) {
            break;
        }
        if (info.is_submap) {
            depth += 1u;
            continue;
        }
        if ((info.protection & VM_PROT_EXECUTE) != 0 &&
            (info.protection & VM_PROT_WRITE) != 0) {
            flags |= CPRISK_DBI_MARKER_EXEC_WRITE;
            hit_count++;
            if (hit_count >= 4) {
                break;
            }
        }
        if (region_size == 0u || addr > UINT64_MAX - region_size) {
            break;
        }
        addr += region_size;
    }

    if (hit_count_out) {
        *hit_count_out = hit_count;
    }
    return flags;
}

static uint64_t cprisk_mul_u64_saturating_i(uint64_t a, uint64_t b) {
    if (a == 0u || b == 0u) {
        return 0u;
    }
    if (a > UINT64_MAX / b) {
        return UINT64_MAX;
    }
    return a * b;
}

int cprisk_detect_dbi_markers(void) {
    int env_hits = 0;
    int image_hits = 0;
    int thread_hits = 0;
    int environ_scan_hits = 0;
    int execmem_hits = 0;

    uint32_t marker_flags = 0u;
    marker_flags |= cprisk_detect_dbi_env_markers_i(&env_hits);
    marker_flags |= cprisk_detect_dbi_environ_scan_i(&environ_scan_hits);
    marker_flags |= cprisk_detect_dbi_image_markers_i(&image_hits);
    marker_flags |= cprisk_detect_dbi_thread_markers_i(&thread_hits);
    marker_flags |= cprisk_detect_dbi_execmem_i(&execmem_hits);

    const int total_hits =
        env_hits + environ_scan_hits + image_hits + thread_hits + execmem_hits;
    atomic_store(&s_dbi_last_marker_flags, marker_flags);
    atomic_store(&s_dbi_last_hit_count, total_hits > 0 ? (uint32_t)total_hits : 0u);
    return total_hits;
}

uint32_t cprisk_get_last_dbi_marker_flags(void) {
    return atomic_load(&s_dbi_last_marker_flags);
}

int cprisk_get_last_dbi_marker_hit_count(void) {
    return (int)atomic_load(&s_dbi_last_hit_count);
}

uint32_t cprisk_get_last_timing_anomaly_flags(void) {
    return atomic_load(&s_timing_last_anomaly_flags);
}

uint64_t cprisk_get_last_timing_probe_median_ns(void) {
    return atomic_load(&s_timing_last_median_ns);
}

uint64_t cprisk_get_last_timing_probe_max_ns(void) {
    return atomic_load(&s_timing_last_max_ns);
}

uint64_t cprisk_get_last_timing_probe_threshold_ns(void) {
    return atomic_load(&s_timing_last_threshold_ns);
}

static void cprisk_reset_exception_delivery_probe_state_i(void) {
    atomic_store(&s_exception_delivery_probe_armed, 0u);
    atomic_store(&s_exception_delivery_probe_handled, 0u);
    atomic_store(&s_exception_delivery_probe_start_ns, 0u);
    atomic_store(&s_exception_delivery_probe_last_ns, 0u);
}

static void cprisk_sigtrap_handler_i(int sig) {
    (void)sig;
    s_sigtrap_flag = 1;
    siglongjmp(s_trap_jmpbuf, 1);
}

static void cprisk_exception_delivery_sigtrap_handler_i(int sig) {
    (void)sig;
    s_exception_delivery_sigtrap = 1;
    siglongjmp(s_exception_delivery_jmpbuf, 1);
}

int cprisk_probe_debugger_via_signal(void) {
    s_sigtrap_flag = 0;

    struct sigaction sa, prev;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cprisk_sigtrap_handler_i;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGTRAP, &sa, &prev);

    if (sigsetjmp(s_trap_jmpbuf, 1) == 0) {
        /*
         * BRK #0xC0DE triggers EXC_BREAKPOINT → SIGTRAP.
         * Debugger intercepts the Mach exception first; if present,
         * our signal handler never fires and s_sigtrap_flag stays 0.
         * The immediate 0xC0DE distinguishes this from normal BRK traps
         * so the project's Mach exception handler can let it pass through.
         */
        __asm__ volatile("brk #0xC0DE");
    }

    sigaction(SIGTRAP, &prev, NULL);

    return s_sigtrap_flag ? 0 : 1;
}

int cprisk_exception_handler_should_passthrough_brk_imm(uint16_t brk_imm) {
    return brk_imm == (uint16_t)CPRISK_BRK_IMM_SIGNAL_PROBE;
}

int cprisk_exception_handler_consume_reserved_brk_imm(uint16_t brk_imm) {
    if (brk_imm != (uint16_t)CPRISK_BRK_IMM_EXCEPTION_DELIVERY_PROBE) {
        return 0;
    }

    const int armed = atomic_load(&s_exception_delivery_probe_armed) != 0u;
    uint64_t elapsed_ns = 0u;
    const uint64_t start_ns = atomic_load(&s_exception_delivery_probe_start_ns);
    if (armed && start_ns != 0u) {
        const uint64_t now_ns = cprisk_monotonic_now_ns_i();
        if (now_ns >= start_ns) {
            elapsed_ns = now_ns - start_ns;
        }
    }

    atomic_store(&s_exception_delivery_probe_last_ns, elapsed_ns);
    atomic_store(&s_exception_delivery_probe_handled, armed ? 1u : 0u);
    atomic_store(&s_exception_delivery_probe_armed, 0u);
    return 1;
}

uint64_t cprisk_get_last_exception_delivery_probe_ns(void) {
    return atomic_load(&s_exception_delivery_probe_last_ns);
}

int cprisk_get_last_exception_delivery_probe_handled(void) {
    return atomic_load(&s_exception_delivery_probe_handled) != 0u ? 1 : 0;
}

int cprisk_probe_exception_delivery_timeout(void) {
    cprisk_reset_exception_delivery_probe_state_i();
    s_exception_delivery_sigtrap = 0;

    struct sigaction sa, prev;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cprisk_exception_delivery_sigtrap_handler_i;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGTRAP, &sa, &prev);

    if (sigsetjmp(s_exception_delivery_jmpbuf, 1) == 0) {
        atomic_store(&s_exception_delivery_probe_start_ns, cprisk_monotonic_now_ns_i());
        atomic_store(&s_exception_delivery_probe_armed, 1u);
        __asm__ volatile("brk #0xC0DF");
    } else {
        const uint64_t start_ns = atomic_load(&s_exception_delivery_probe_start_ns);
        uint64_t elapsed_ns = 0u;
        if (start_ns != 0u) {
            const uint64_t now_ns = cprisk_monotonic_now_ns_i();
            if (now_ns >= start_ns) {
                elapsed_ns = now_ns - start_ns;
            }
        }
        atomic_store(&s_exception_delivery_probe_last_ns, elapsed_ns);
        atomic_store(&s_exception_delivery_probe_armed, 0u);
        atomic_store(&s_exception_delivery_probe_handled, 0u);
    }

    sigaction(SIGTRAP, &prev, NULL);

    const uint64_t elapsed_ns = atomic_load(&s_exception_delivery_probe_last_ns);
    const int handled = atomic_load(&s_exception_delivery_probe_handled) != 0u;
    return (!handled || elapsed_ns > CPRISK_EXCEPTION_DELIVERY_TIMEOUT_NS) ? 1 : 0;
}

/* ── (b) Thread exception-port detection ──────────────────────────── */

static mach_port_t cprisk_expected_exception_port_i(void) {
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    mach_port_t expected = MACH_PORT_NULL;

    const exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS;
    kern_return_t kr = task_get_exception_ports(
        mach_task_self(),
        mask,
        masks,
        &count,
        ports,
        behaviors,
        flavors
    );
    if (kr == KERN_SUCCESS) {
        for (mach_msg_type_number_t i = 0; i < count; i++) {
            if ((masks[i] & EXC_MASK_BREAKPOINT) != 0u) {
                expected = ports[i];
            }
            if (ports[i] != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), ports[i]);
            }
        }
    }
    return expected;
}

int cprisk_detect_thread_exception_ports(void) {
    const mach_port_t expected_port = cprisk_expected_exception_port_i();
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    const exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS;

    if (task_threads(mach_task_self(), &threads, &thread_count) != KERN_SUCCESS) {
        return 0;
    }

    int mismatched = 0;
    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        exception_mask_t masks[EXC_TYPES_COUNT];
        mach_port_t ports[EXC_TYPES_COUNT];
        exception_behavior_t behaviors[EXC_TYPES_COUNT];
        thread_state_flavor_t flavors[EXC_TYPES_COUNT];
        mach_msg_type_number_t count = EXC_TYPES_COUNT;

        kern_return_t kr = thread_get_exception_ports(
            threads[i],
            mask,
            masks,
            &count,
            ports,
            behaviors,
            flavors
        );
        if (kr != KERN_SUCCESS) {
            continue;
        }

        int thread_mismatch = 0;
        for (mach_msg_type_number_t j = 0; j < count; j++) {
            if ((masks[j] & EXC_MASK_BREAKPOINT) == 0u) {
                if (ports[j] != MACH_PORT_NULL) {
                    mach_port_deallocate(mach_task_self(), ports[j]);
                }
                continue;
            }
            if (ports[j] != MACH_PORT_NULL &&
                (expected_port == MACH_PORT_NULL || ports[j] != expected_port)) {
                thread_mismatch = 1;
            }
            if (ports[j] != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), ports[j]);
            }
        }

        if (thread_mismatch) {
            mismatched++;
        }
    }

    vm_deallocate(mach_task_self(),
                  (vm_address_t)threads,
                  sizeof(thread_act_t) * thread_count);

    return mismatched;
}

/* ── (b) Hardware breakpoint detection ────────────────────────────── */

int cprisk_detect_hardware_breakpoints(void) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;

    if (task_threads(mach_task_self(), &threads, &thread_count) != KERN_SUCCESS) {
        return 0;
    }

    int detected = 0;

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        arm_debug_state64_t dbg;
        mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
        memset(&dbg, 0, sizeof(dbg));

        kern_return_t kr = thread_get_state(
            threads[i], ARM_DEBUG_STATE64, (thread_state_t)&dbg, &count);

        if (kr == KERN_SUCCESS) {
            for (int j = 0; j < 16; j++) {
                if (dbg.__bcr[j] & 1u) detected++;
                if (dbg.__wcr[j] & 1u) detected++;
            }
        }
    }

    vm_deallocate(mach_task_self(),
                  (vm_address_t)threads,
                  sizeof(thread_act_t) * thread_count);

    return detected;
}

/* ── (c) Software breakpoint scan ─────────────────────────────────── */

int cprisk_scan_software_breakpoints(const void *func_ptr, size_t size) {
    if (!func_ptr || size < 4) return 0;

    const uint32_t *start = (const uint32_t *)func_ptr;
    size_t word_count = size / 4;
    int found = 0;

    /*
     * ARM64 BRK encoding: 0xD4200000 | (imm16 << 5)
     * Exclude our reserved BRK probes to avoid self-detection.
     */
    const uint32_t signal_probe_brk =
        0xD4200000u | ((uint32_t)CPRISK_BRK_IMM_SIGNAL_PROBE << 5);
    const uint32_t exception_delivery_brk =
        0xD4200000u | ((uint32_t)CPRISK_BRK_IMM_EXCEPTION_DELIVERY_PROBE << 5);
    const uint32_t runtime_gate_brk =
        0xD4200000u | ((uint32_t)CPRISK_BRK_IMM_RUNTIME_GATE << 5);

    for (size_t i = 0; i < word_count; i++) {
        uint32_t instr = start[i];
        if ((instr & 0xFFE00000u) == 0xD4200000u &&
            instr != signal_probe_brk &&
            instr != exception_delivery_brk &&
            instr != runtime_gate_brk) {
            found++;
        }
    }

    return found;
}

struct cprisk_text_exec_section_i {
    const uint8_t *base;
    size_t size;
};

static size_t cprisk_collect_text_exec_sections_i(
    const struct mach_header_64 *hdr,
    struct cprisk_text_exec_section_i *out_sections,
    size_t out_capacity
) {
    if (!hdr || !out_sections || out_capacity == 0u) {
        return 0u;
    }

    const intptr_t slide = cprisk_compute_slide(hdr);
    const uint8_t *cursor = (const uint8_t *)(hdr + 1);
    const uint8_t *end = cursor + hdr->sizeofcmds;
    size_t count = 0u;

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > end) {
            break;
        }
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize == 0u || cursor + lc->cmdsize > end) {
            break;
        }
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cursor;
            const size_t seg_header_size = sizeof(struct segment_command_64);
            const size_t sec_table_size =
                (size_t)seg->nsects * sizeof(struct section_64);
            if (sec_table_size / sizeof(struct section_64) != (size_t)seg->nsects ||
                seg_header_size + sec_table_size > (size_t)lc->cmdsize) {
                cursor += lc->cmdsize;
                continue;
            }
            if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                const struct section_64 *sections =
                    (const struct section_64 *)(cursor + sizeof(*seg));
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    const struct section_64 *sec = &sections[s];
                    const uint32_t attrs = sec->flags & SECTION_ATTRIBUTES_USR;
                    const int executable =
                        (attrs & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)) != 0u ||
                        strncmp(sec->sectname, "__text", 16) == 0;
                    if (!executable || sec->size < 4u) {
                        continue;
                    }
                    if (count >= out_capacity) {
                        return count;
                    }
                    out_sections[count].base =
                        (const uint8_t *)((uintptr_t)sec->addr + (uintptr_t)slide);
                    out_sections[count].size = (size_t)sec->size;
                    count++;
                }
            }
        }
        cursor += lc->cmdsize;
    }

    return count;
}

int cprisk_scan_software_breakpoints_randomized_text(
    size_t sample_windows,
    size_t window_size
) {
    if (sample_windows == 0u) {
        sample_windows = CPRISK_SOFTWARE_BP_RANDOM_DEFAULT_WINDOWS;
    }
    if (window_size < 16u) {
        window_size = CPRISK_SOFTWARE_BP_RANDOM_DEFAULT_WINDOW_BYTES;
    }

    const struct mach_header_64 *hdr =
        cprisk_find_own_header((const void *)cprisk_scan_software_breakpoints_randomized_text);
    if (!hdr) {
        return 0;
    }

    struct cprisk_text_exec_section_i sections[32];
    const size_t section_count =
        cprisk_collect_text_exec_sections_i(hdr, sections, sizeof(sections) / sizeof(sections[0]));
    if (section_count == 0u) {
        return 0;
    }

    uint64_t rng = cprisk_random_u64_i() ^ (uint64_t)(uintptr_t)hdr;
    const size_t start_idx = (size_t)(cprisk_prng_next_i(&rng) % section_count);
    size_t windows = sample_windows;
    if (windows > section_count * 4u) {
        windows = section_count * 4u;
    }

    int found = 0;
    for (size_t i = 0; i < windows; i++) {
        const size_t idx = (start_idx + i) % section_count;
        const uint8_t *base = sections[idx].base;
        size_t sec_size = sections[idx].size;
        if (!base || sec_size < 4u) {
            continue;
        }

        size_t sample_size = window_size;
        if (sample_size > sec_size) {
            sample_size = sec_size;
        }

        size_t offset = 0u;
        const size_t max_offset = sec_size - sample_size;
        if (max_offset > 0u) {
            offset = (size_t)(cprisk_prng_next_i(&rng) % (max_offset + 1u));
        }

        offset &= ~(size_t)0x3u;
        if (offset >= sec_size) {
            continue;
        }
        sample_size = sec_size - offset < sample_size ? (sec_size - offset) : sample_size;
        sample_size &= ~(size_t)0x3u;
        if (sample_size < 4u) {
            continue;
        }

        found += cprisk_scan_software_breakpoints(base + offset, sample_size);
    }

    return found;
}

/* ── (d) TTY debug detection ──────────────────────────────────────── */

int cprisk_detect_tty_debug(void) {
    if (!isatty(STDOUT_FILENO)) return 0;

    char path[MAXPATHLEN];
    memset(path, 0, sizeof(path));

    if (fcntl(STDOUT_FILENO, F_GETPATH, path) == -1) return 0;

    if (path[0] == '/' && path[1] == 'd' && path[2] == 'e' &&
        path[3] == 'v' && path[4] == '/') {
        const char *name = path + 5;
        if ((name[0] == 't' && name[1] == 't' && name[2] == 'y' && name[3] == 's') ||
            (name[0] == 'p' && name[1] == 't' && name[2] == 's')) {
            return 1;
        }
    }

    return 0;
}

/* ── (e) csops CS_DEBUGGED check ──────────────────────────────────── */

#ifndef SYS_csops
#define SYS_csops 169
#endif

#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS 0
#endif

#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000u
#endif

static long cprisk_csops_syscall_i(pid_t pid, unsigned int ops,
                                   void *useraddr, size_t usersize) {
    register long x0 __asm("x0") = (long)pid;
    register long x1 __asm("x1") = (long)ops;
    register long x2 __asm("x2") = (long)(uintptr_t)useraddr;
    register long x3 __asm("x3") = (long)usersize;
    register long x16 __asm("x16") = SYS_csops;
    unsigned int did_error = 0;

    __asm__ volatile(
        "svc #0x80\n"
        "cset %w[did_error], cs\n"
        : "+r"(x0), [did_error] "=r"(did_error)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x16)
        : "cc", "memory"
    );

    if (did_error) return -1;
    return x0;
}

int cprisk_csops_debug_check(void) {
    uint32_t flags = 0;
    pid_t pid = cprisk_getpid_direct();

    long result = cprisk_csops_syscall_i(pid, CS_OPS_STATUS, &flags, sizeof(flags));
    if (result != 0) return 0;

    return (flags & CS_DEBUGGED) ? 1 : 0;
}

int cprisk_csops_status_flags(uint32_t *flags_out, int *error_out) {
    uint32_t flags = 0u;
    pid_t pid = cprisk_getpid_direct();

    if (flags_out != NULL) {
        *flags_out = 0u;
    }
    if (error_out != NULL) {
        *error_out = 0;
    }

    long result = cprisk_csops_syscall_i(pid, CS_OPS_STATUS, &flags, sizeof(flags));
    if (result != 0) {
        if (error_out != NULL) {
            *error_out = (int)result;
        }
        return -1;
    }

    if (flags_out != NULL) {
        *flags_out = flags;
    }
    return 0;
}

/* ── (f) Single-step timing detection ─────────────────────────────── */

static uint64_t cprisk_single_step_workload_i(void) {
    volatile uint64_t acc = 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < 320; i++) {
        acc ^= ((uint64_t)i * 0x100000001B3ULL) + 0x9E37u;
        acc = (acc << 5u) | (acc >> 59u);
    }
    return acc;
}

static uint64_t cprisk_single_step_measure_once_i(void) {
    const uint64_t t0 = cprisk_monotonic_now_ns_i();
    const uint64_t acc = cprisk_single_step_workload_i();
    (void)acc;
    const uint64_t t1 = cprisk_monotonic_now_ns_i();
    if (t1 < t0) {
        return 0u;
    }
    return t1 - t0;
}

static uint64_t cprisk_single_step_threshold_from_baseline_i(uint64_t baseline_ns) {
    if (baseline_ns == 0u) {
        return CPRISK_SINGLE_STEP_DEFAULT_THRESHOLD_NS;
    }
    uint64_t threshold = baseline_ns * CPRISK_SINGLE_STEP_THRESHOLD_MULTIPLIER;
    if (threshold / CPRISK_SINGLE_STEP_THRESHOLD_MULTIPLIER != baseline_ns) {
        threshold = UINT64_MAX;
    }
    if (threshold < CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS) {
        threshold = CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS;
    }
    return threshold;
}

static void cprisk_single_step_calibrate_if_needed_i(void) {
    if (atomic_load(&s_single_step_calibrated) != 0u) {
        return;
    }

    while (atomic_flag_test_and_set(&s_single_step_calibration_lock)) {
    }

    if (atomic_load(&s_single_step_calibrated) == 0u) {
        uint64_t samples[CPRISK_SINGLE_STEP_CALIBRATION_SAMPLES];
        memset(samples, 0, sizeof(samples));
        for (size_t i = 0; i < CPRISK_SINGLE_STEP_CALIBRATION_SAMPLES; i++) {
            samples[i] = cprisk_single_step_measure_once_i();
        }

        for (size_t i = 1; i < CPRISK_SINGLE_STEP_CALIBRATION_SAMPLES; i++) {
            uint64_t key = samples[i];
            size_t j = i;
            while (j > 0u && samples[j - 1u] > key) {
                samples[j] = samples[j - 1u];
                j--;
            }
            samples[j] = key;
        }

        uint64_t baseline =
            samples[CPRISK_SINGLE_STEP_CALIBRATION_SAMPLES / 2u];
        if (baseline == 0u) {
            baseline = CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS / 2u;
        }

        atomic_store(&s_single_step_baseline_ns, baseline);
        atomic_store(&s_single_step_threshold_ns,
                     cprisk_single_step_threshold_from_baseline_i(baseline));
        atomic_store(&s_single_step_calibrated, 1u);
    }

    atomic_flag_clear(&s_single_step_calibration_lock);
}

static uint64_t cprisk_add_u64_saturating_i(uint64_t a, uint64_t b) {
    if (UINT64_MAX - a < b) {
        return UINT64_MAX;
    }
    return a + b;
}

static uint64_t cprisk_cntpct_delta_ns_i(uint64_t t0, uint64_t t1) {
#if CPRISK_TIMING_CNTPCT_AVAILABLE
    static uint64_t s_cntfrq = 0u;
    if (s_cntfrq == 0u) {
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(s_cntfrq));
    }
    if (s_cntfrq == 0u || t1 < t0) {
        return 0u;
    }
    const uint64_t dt = t1 - t0;
    return (dt / s_cntfrq) * 1000000000ull +
           ((dt % s_cntfrq) * 1000000000ull) / s_cntfrq;
#else
    (void)t0;
    (void)t1;
    return 0u;
#endif
}

static uint64_t cprisk_u64_abs_diff_i(uint64_t a, uint64_t b) {
    return a > b ? a - b : b - a;
}

static uint32_t cprisk_clock_crosscheck_i(uint64_t median_ref_ns) {
#if CPRISK_TIMING_CNTPCT_AVAILABLE
    static uint64_t s_cntfrq_chk = 0u;
    if (s_cntfrq_chk == 0u) {
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(s_cntfrq_chk));
    }
    if (s_cntfrq_chk == 0u) {
        return 0u;
    }

    uint64_t ct0 = 0u;
    uint64_t ct1 = 0u;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(ct0));
    const uint64_t ma0 = mach_absolute_time();
    struct timespec ts0;
    clock_gettime(CLOCK_MONOTONIC, &ts0);
    const uint64_t ck0 =
        (uint64_t)ts0.tv_sec * 1000000000ull + (uint64_t)ts0.tv_nsec;

    for (volatile int spin = 0; spin < 96; spin++) {
        (void)0;
    }

    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(ct1));
    const uint64_t ma1 = mach_absolute_time();
    struct timespec ts1;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    const uint64_t ck1 =
        (uint64_t)ts1.tv_sec * 1000000000ull + (uint64_t)ts1.tv_nsec;

    const uint64_t dc = cprisk_cntpct_delta_ns_i(ct0, ct1);
    uint64_t dm = 0u;
    if (ma1 >= ma0) {
        dm = cprisk_mach_abs_to_ns_i(ma1 - ma0);
    } else {
        dm = cprisk_mach_abs_to_ns_i(ma0 - ma1);
    }
    const uint64_t dck = cprisk_u64_abs_diff_i(ck0, ck1);

    const uint64_t skew_cm = cprisk_u64_abs_diff_i(dc, dm);
    const uint64_t skew_mk = cprisk_u64_abs_diff_i(dm, dck);
    const uint64_t skew_ck = cprisk_u64_abs_diff_i(dc, dck);

    uint64_t thresh_ns = 5000000ull;
    if (median_ref_ns > 2000000ull) {
        thresh_ns = median_ref_ns / 4u;
        if (thresh_ns < 4000000ull) {
            thresh_ns = 4000000ull;
        }
        if (thresh_ns > 30000000ull) {
            thresh_ns = 30000000ull;
        }
    }

    if (skew_cm > thresh_ns || skew_mk > thresh_ns || skew_ck > thresh_ns) {
        return CPRISK_TIMING_ANOMALY_CLOCK_SKEW;
    }
#else
    (void)median_ref_ns;
#endif
    return 0u;
}

/*
 * Compare elapsed time for the fixed arithmetic workload as seen by CNTPCT_EL0
 * vs mach_absolute_time. Pure virtualization / DBI time hooks may desynchronize
 * the two (complements CPRISK_TIMING_ANOMALY_CLOCK_SKEW short-spin check).
 */
static uint32_t cprisk_dual_clock_workload_skew_i(void) {
#if CPRISK_TIMING_CNTPCT_AVAILABLE
    uint64_t c0 = 0u;
    uint64_t c1 = 0u;
    const uint64_t m0 = mach_absolute_time();
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(c0));
    (void)cprisk_single_step_workload_i();
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(c1));
    const uint64_t m1 = mach_absolute_time();

    const uint64_t d_cnt_ns = cprisk_cntpct_delta_ns_i(c0, c1);
    uint64_t d_mach_ns = 0u;
    if (m1 >= m0) {
        d_mach_ns = cprisk_mach_abs_to_ns_i(m1 - m0);
    } else {
        d_mach_ns = cprisk_mach_abs_to_ns_i(m0 - m1);
    }

    const uint64_t dmax = d_cnt_ns > d_mach_ns ? d_cnt_ns : d_mach_ns;
    if (dmax < 8000u) {
        return 0u;
    }
    const uint64_t skew_ns = cprisk_u64_abs_diff_i(d_cnt_ns, d_mach_ns);
    if (skew_ns > dmax / 4u) {
        return CPRISK_TIMING_ANOMALY_DUAL_CLOCK_DRIFT;
    }
#endif
    return 0u;
}

static void cprisk_sort_u64_samples_i(uint64_t *samples, size_t count) {
    if (!samples || count <= 1u) {
        return;
    }
    for (size_t i = 1u; i < count; i++) {
        uint64_t key = samples[i];
        size_t j = i;
        while (j > 0u && samples[j - 1u] > key) {
            samples[j] = samples[j - 1u];
            j--;
        }
        samples[j] = key;
    }
}

static uint32_t cprisk_timing_probe_eval_i(
    uint64_t *median_ns_out,
    uint64_t *max_ns_out,
    uint64_t *threshold_ns_out
) {
    uint64_t samples[CPRISK_TIMING_SAMPLE_COUNT];
    memset(samples, 0, sizeof(samples));
    for (size_t i = 0u; i < CPRISK_TIMING_SAMPLE_COUNT; i++) {
        samples[i] = cprisk_single_step_measure_once_i();
    }
    cprisk_sort_u64_samples_i(samples, CPRISK_TIMING_SAMPLE_COUNT);

    const uint64_t median_ns = samples[CPRISK_TIMING_SAMPLE_COUNT / 2u];
    const uint64_t max_ns = samples[CPRISK_TIMING_SAMPLE_COUNT - 1u];

    uint64_t baseline_ns = atomic_load(&s_single_step_baseline_ns);
    if (baseline_ns == 0u) {
        baseline_ns = median_ns;
    }
    if (baseline_ns == 0u) {
        baseline_ns = CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS / 2u;
    }

    uint64_t median_threshold_ns =
        cprisk_mul_u64_saturating_i(baseline_ns, CPRISK_TIMING_MEDIAN_MULTIPLIER);
    if (median_threshold_ns < CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS) {
        median_threshold_ns = CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS;
    }
    uint64_t spike_threshold_ns =
        cprisk_mul_u64_saturating_i(baseline_ns, CPRISK_TIMING_SPIKE_MULTIPLIER);
    if (spike_threshold_ns < median_threshold_ns) {
        spike_threshold_ns = median_threshold_ns;
    }

    uint64_t jitter_margin_ns = median_ns / CPRISK_TIMING_JITTER_DIVISOR;
    const uint64_t threshold_margin_ns = median_threshold_ns / CPRISK_TIMING_JITTER_DIVISOR;
    if (jitter_margin_ns < threshold_margin_ns) {
        jitter_margin_ns = threshold_margin_ns;
    }
    if (jitter_margin_ns < 500000ull) {
        jitter_margin_ns = 500000ull;
    }

    uint32_t anomaly_flags = 0u;
    if (median_ns > median_threshold_ns) {
        anomaly_flags |= CPRISK_TIMING_ANOMALY_MEDIAN;
    }
    if (max_ns > spike_threshold_ns) {
        anomaly_flags |= CPRISK_TIMING_ANOMALY_SPIKE;
    }
    if (max_ns > cprisk_add_u64_saturating_i(median_ns, jitter_margin_ns) &&
        max_ns > median_threshold_ns) {
        anomaly_flags |= CPRISK_TIMING_ANOMALY_JITTER;
    }

    anomaly_flags |= cprisk_clock_crosscheck_i(median_ns);
    anomaly_flags |= cprisk_dual_clock_workload_skew_i();

    if (median_ns_out) {
        *median_ns_out = median_ns;
    }
    if (max_ns_out) {
        *max_ns_out = max_ns;
    }
    if (threshold_ns_out) {
        *threshold_ns_out = median_threshold_ns;
    }

    if (median_ns > 0u) {
        if (anomaly_flags == 0u) {
            baseline_ns = baseline_ns - (baseline_ns / 8u) + (median_ns / 8u);
            atomic_store(&s_single_step_baseline_ns, baseline_ns);
            atomic_store(&s_single_step_threshold_ns,
                         cprisk_single_step_threshold_from_baseline_i(baseline_ns));
        } else if (atomic_load(&s_single_step_baseline_ns) == 0u) {
            atomic_store(&s_single_step_baseline_ns, median_ns);
            atomic_store(&s_single_step_threshold_ns,
                         cprisk_single_step_threshold_from_baseline_i(median_ns));
        }
    }

    return anomaly_flags;
}

int cprisk_detect_single_stepping(void) {
    cprisk_single_step_calibrate_if_needed_i();

    uint64_t median_ns = 0u;
    uint64_t max_ns = 0u;
    uint64_t threshold_ns = 0u;
    const uint32_t anomaly_flags =
        cprisk_timing_probe_eval_i(&median_ns, &max_ns, &threshold_ns);

    atomic_store(&s_timing_last_anomaly_flags, anomaly_flags);
    atomic_store(&s_timing_last_median_ns, median_ns);
    atomic_store(&s_timing_last_max_ns, max_ns);
    atomic_store(&s_timing_last_threshold_ns, threshold_ns);

    return anomaly_flags != 0u ? 1 : 0;
}

/* ── (g) Suspicious thread detection ──────────────────────────────── */

int cprisk_detect_suspicious_threads(void) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;

    if (task_threads(mach_task_self(), &threads, &thread_count) != KERN_SUCCESS) {
        return 0;
    }

    int suspicious = 0;

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        arm_thread_state64_t ts;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        memset(&ts, 0, sizeof(ts));

        kern_return_t kr = thread_get_state(
            threads[i], ARM_THREAD_STATE64, (thread_state_t)&ts, &count);

        if (kr == KERN_SUCCESS) {
#if defined(arm_thread_state64_get_pc)
            uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(ts);
#else
            uintptr_t pc = (uintptr_t)ts.__pc;
#endif
            if (pc != 0 && !cprisk_addr_in_any_image((const void *)pc)) {
                suspicious++;
            }
        }
    }

    vm_deallocate(mach_task_self(),
                  (vm_address_t)threads,
                  sizeof(thread_act_t) * thread_count);

    return suspicious;
}

/* ── (h) Developer Disk Image detection ───────────────────────────── */

int cprisk_detect_developer_disk(void) {
    if (cprisk_access_direct("/Developer/usr/bin/debugserver", F_OK, NULL) == 0)
        return 1;
    if (cprisk_access_direct("/Developer/usr/lib/libMainThreadChecker.dylib", F_OK, NULL) == 0)
        return 1;
    return 0;
}

/* ── (i) Aggregate probe runner ───────────────────────────────────── */

uint32_t cprisk_run_all_signal_probes(void) {
    uint32_t result = 0;

    if (cprisk_probe_debugger_via_signal())
        result |= CPRISK_PROBE_SIGNAL_TRAP;

    const int thread_exception_ports = cprisk_detect_thread_exception_ports();
    if (thread_exception_ports != 0) {
        result |= CPRISK_PROBE_THREAD_EXCEPTION_PORT;
    }

    if (cprisk_detect_hardware_breakpoints())
        result |= CPRISK_PROBE_HARDWARE_BP;

    int software_bp = 0;
    software_bp += cprisk_scan_software_breakpoints(
        (const void *)cprisk_probe_debugger_via_signal, 256);
    software_bp += cprisk_scan_software_breakpoints(
        (const void *)cprisk_probe_exception_delivery_timeout, 256);
#if defined(TARGET_OS_IOS) && TARGET_OS_IOS
    software_bp += cprisk_scan_software_breakpoints_randomized_text(0u, 0u);
#endif
    if (software_bp != 0) {
        result |= CPRISK_PROBE_SOFTWARE_BP;
    }

    if (cprisk_detect_tty_debug())
        result |= CPRISK_PROBE_TTY;

    if (cprisk_csops_debug_check())
        result |= CPRISK_PROBE_CSOPS;

    const int single_step_detected = cprisk_detect_single_stepping();
    if (single_step_detected)
        result |= CPRISK_PROBE_SINGLE_STEP;
    if (cprisk_get_last_timing_anomaly_flags() != 0u)
        result |= CPRISK_PROBE_TIMING_ANOMALY;

    if (cprisk_detect_suspicious_threads())
        result |= CPRISK_PROBE_SUSPICIOUS_THREAD;

    if (cprisk_detect_developer_disk())
        result |= CPRISK_PROBE_DEVELOPER_DISK;

    if (cprisk_probe_exception_delivery_timeout())
        result |= CPRISK_PROBE_EXCEPTION_DELIVERY_TIMEOUT;

    if (cprisk_detect_dbi_markers() > 0)
        result |= CPRISK_PROBE_DBI_MARKER;

    if (cprisk_trace_crosscheck_inconsistent() != 0)
        result |= CPRISK_PROBE_TRACE_CROSSCHECK;

    return result;
}

int cprisk_is_cntpct_clock_available(void) {
#if CPRISK_TIMING_CNTPCT_AVAILABLE
    uint64_t cntfrq = 0u;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(cntfrq));
    return cntfrq != 0u ? 1 : 0;
#else
    return 0;
#endif
}

/* ===================================================================== */
#else  /* !CPRISK_SIGNAL_PROBE_AVAILABLE — simulator / non-arm64 stubs */
/* ===================================================================== */

int cprisk_probe_debugger_via_signal(void) { return 0; }
int cprisk_detect_thread_exception_ports(void) { return 0; }
int cprisk_detect_hardware_breakpoints(void) { return 0; }

int cprisk_scan_software_breakpoints(const void *func_ptr, size_t size) {
    (void)func_ptr; (void)size;
    return 0;
}
int cprisk_scan_software_breakpoints_randomized_text(
    size_t sample_windows,
    size_t window_size
) {
    (void)sample_windows;
    (void)window_size;
    return 0;
}

int cprisk_probe_exception_delivery_timeout(void) { return 0; }
int cprisk_detect_tty_debug(void) { return 0; }
int cprisk_csops_debug_check(void) { return 0; }
int cprisk_csops_status_flags(uint32_t *flags_out, int *error_out) {
    if (flags_out != NULL) {
        *flags_out = 0u;
    }
    if (error_out != NULL) {
        *error_out = 0;
    }
    return -1;
}
int cprisk_detect_single_stepping(void) { return 0; }
int cprisk_detect_suspicious_threads(void) { return 0; }
int cprisk_detect_developer_disk(void) { return 0; }
int cprisk_detect_dbi_markers(void) { return 0; }
uint32_t cprisk_get_last_dbi_marker_flags(void) { return 0u; }
int cprisk_get_last_dbi_marker_hit_count(void) { return 0; }
uint32_t cprisk_get_last_timing_anomaly_flags(void) { return 0u; }
uint64_t cprisk_get_last_timing_probe_median_ns(void) { return 0u; }
uint64_t cprisk_get_last_timing_probe_max_ns(void) { return 0u; }
uint64_t cprisk_get_last_timing_probe_threshold_ns(void) { return 0u; }
uint32_t cprisk_run_all_signal_probes(void) { return 0; }
int cprisk_is_cntpct_clock_available(void) { return 0; }

#endif /* CPRISK_SIGNAL_PROBE_AVAILABLE */
