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
#include <sys/fcntl.h>
#include <sys/param.h>

#define CPRISK_EXCEPTION_DELIVERY_TIMEOUT_NS 10000000ull

/* ── (a) SIGTRAP signal probe ─────────────────────────────────────── */

static sigjmp_buf s_trap_jmpbuf;
static volatile sig_atomic_t s_sigtrap_flag = 0;
static sigjmp_buf s_exception_delivery_jmpbuf;
static volatile sig_atomic_t s_exception_delivery_sigtrap = 0;
static atomic_uint_fast32_t s_exception_delivery_probe_armed = 0;
static atomic_uint_fast32_t s_exception_delivery_probe_handled = 0;
static atomic_uint_fast64_t s_exception_delivery_probe_start_abs = 0;
static atomic_uint_fast64_t s_exception_delivery_probe_last_ns = 0;

static uint64_t cprisk_mach_abs_to_ns_i(uint64_t delta_abs) {
    mach_timebase_info_data_t tb;
    if (mach_timebase_info(&tb) != KERN_SUCCESS || tb.denom == 0u) {
        return 0u;
    }

    return delta_abs * tb.numer / tb.denom;
}

static void cprisk_reset_exception_delivery_probe_state_i(void) {
    atomic_store(&s_exception_delivery_probe_armed, 0u);
    atomic_store(&s_exception_delivery_probe_handled, 0u);
    atomic_store(&s_exception_delivery_probe_start_abs, 0u);
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
    const uint64_t start_abs = atomic_load(&s_exception_delivery_probe_start_abs);
    if (armed && start_abs != 0u) {
        elapsed_ns = cprisk_mach_abs_to_ns_i(mach_absolute_time() - start_abs);
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
        atomic_store(&s_exception_delivery_probe_start_abs, mach_absolute_time());
        atomic_store(&s_exception_delivery_probe_armed, 1u);
        __asm__ volatile("brk #0xC0DF");
    } else {
        const uint64_t start_abs = atomic_load(&s_exception_delivery_probe_start_abs);
        uint64_t elapsed_ns = 0u;
        if (start_abs != 0u) {
            elapsed_ns = cprisk_mach_abs_to_ns_i(mach_absolute_time() - start_abs);
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

    for (size_t i = 0; i < word_count; i++) {
        uint32_t instr = start[i];
        if ((instr & 0xFFE00000u) == 0xD4200000u &&
            instr != signal_probe_brk &&
            instr != exception_delivery_brk) {
            found++;
        }
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

/* ── (f) Single-step timing detection ─────────────────────────────── */

#define CPRISK_SINGLE_STEP_THRESHOLD_NS 50000000ull  /* 50 ms */

int cprisk_detect_single_stepping(void) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);

    uint64_t t0 = mach_absolute_time();

    volatile uint64_t acc = 0;
    for (int i = 0; i < 100; i++) {
        acc += (uint64_t)i * 7u + 3u;
    }
    (void)acc;

    uint64_t t1 = mach_absolute_time();
    uint64_t elapsed_ns = (t1 - t0) * tb.numer / tb.denom;

    return (elapsed_ns > CPRISK_SINGLE_STEP_THRESHOLD_NS) ? 1 : 0;
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

    if (cprisk_detect_hardware_breakpoints())
        result |= CPRISK_PROBE_HARDWARE_BP;

    if (cprisk_scan_software_breakpoints(
            (const void *)cprisk_probe_debugger_via_signal, 256) +
        cprisk_scan_software_breakpoints(
            (const void *)cprisk_probe_exception_delivery_timeout, 256))
        result |= CPRISK_PROBE_SOFTWARE_BP;

    if (cprisk_detect_tty_debug())
        result |= CPRISK_PROBE_TTY;

    if (cprisk_csops_debug_check())
        result |= CPRISK_PROBE_CSOPS;

    if (cprisk_detect_single_stepping())
        result |= CPRISK_PROBE_SINGLE_STEP;

    if (cprisk_detect_suspicious_threads())
        result |= CPRISK_PROBE_SUSPICIOUS_THREAD;

    if (cprisk_detect_developer_disk())
        result |= CPRISK_PROBE_DEVELOPER_DISK;

    if (cprisk_probe_exception_delivery_timeout())
        result |= CPRISK_PROBE_EXCEPTION_DELIVERY_TIMEOUT;

    return result;
}

/* ===================================================================== */
#else  /* !CPRISK_SIGNAL_PROBE_AVAILABLE — simulator / non-arm64 stubs */
/* ===================================================================== */

int cprisk_probe_debugger_via_signal(void) { return 0; }
int cprisk_detect_hardware_breakpoints(void) { return 0; }

int cprisk_scan_software_breakpoints(const void *func_ptr, size_t size) {
    (void)func_ptr; (void)size;
    return 0;
}

int cprisk_probe_exception_delivery_timeout(void) { return 0; }
int cprisk_detect_tty_debug(void) { return 0; }
int cprisk_csops_debug_check(void) { return 0; }
int cprisk_detect_single_stepping(void) { return 0; }
int cprisk_detect_suspicious_threads(void) { return 0; }
int cprisk_detect_developer_disk(void) { return 0; }
uint32_t cprisk_run_all_signal_probes(void) { return 0; }

#endif /* CPRISK_SIGNAL_PROBE_AVAILABLE */
