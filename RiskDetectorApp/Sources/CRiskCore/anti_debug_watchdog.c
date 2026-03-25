#include "include/CRiskCore.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_secure_zero.h"
#include "include/cprisk_memory_guard.h"
#include "cprisk_cff.h"

#include <TargetConditionals.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <objc/message.h>

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR) && \
    (!defined(TARGET_OS_TV) || !TARGET_OS_TV) && \
    (!defined(TARGET_OS_WATCH) || !TARGET_OS_WATCH)

#define CPRISK_WATCHDOG_THREAD_COUNT 2u
#define CPRISK_WATCHDOG_PRIMARY_ID 0u
#define CPRISK_WATCHDOG_SECONDARY_ID 1u
#define CPRISK_WATCHDOG_DEFAULT_INTERVAL_MS 850u
#define CPRISK_WATCHDOG_INTERVAL_JITTER_MS 450u
#define CPRISK_WATCHDOG_MID_CADENCE 3u
#define CPRISK_WATCHDOG_LOW_CADENCE 9u
#define CPRISK_WATCHDOG_SHORT_INTERVAL_MIN_MS 350u
#define CPRISK_WATCHDOG_SHORT_INTERVAL_MAX_MS 1100u
#define CPRISK_WATCHDOG_SLEEP_SLICE_NS 100000000L
#define CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES 256u
#define CPRISK_WATCHDOG_RANDOM_TEXT_WINDOWS 8u
#define CPRISK_WATCHDOG_RANDOM_TEXT_WINDOW_BYTES 768u
#define CPRISK_WATCHDOG_SOFTWARE_BP_STRONG_THRESHOLD 4
#define CPRISK_WATCHDOG_PEER_STALL_MIN_NS 3500000000ull

/* Integrity poison: high-confidence anomalies use immediate lane commit; the bundled weaker
 * probe hits in the primary iteration use staged escalation (see cprisk_integrity.c). */
#define CPRISK_WD_HIGH_RISK_POISON_MASK \
    (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_IMAGE_WHITELIST)

#define CPRISK_WD_POISON_TRIGGER_BUNDLE_MASK \
    (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SIGNAL_PROBE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_HARDWARE_BP | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_CSOPS_DEBUGGED | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_MARKER | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE | \
     CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL)

enum {
    CPRISK_WATCHDOG_STATE_STOPPED = 0,
    CPRISK_WATCHDOG_STATE_RUNNING = 1,
    CPRISK_WATCHDOG_STATE_STOPPING = 2,
};

typedef struct cprisk_shadow_token {
    uintptr_t value;
} cprisk_shadow_token_t;

static pthread_mutex_t s_watchdog_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t s_watchdog_threads[CPRISK_WATCHDOG_THREAD_COUNT];
static uint32_t s_watchdog_started_mask = 0u;
static int s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
static atomic_int s_watchdog_stop_requested = 0;
static atomic_uint_fast32_t s_watchdog_worker_active[CPRISK_WATCHDOG_THREAD_COUNT];
static atomic_uint_fast64_t s_watchdog_heartbeat_ns[CPRISK_WATCHDOG_THREAD_COUNT];
static atomic_uint_fast64_t s_watchdog_deadline_ns[CPRISK_WATCHDOG_THREAD_COUNT];
static atomic_uint_fast64_t s_watchdog_prng_state = 0u;
static atomic_uint_fast32_t s_watchdog_peer_stall_latch = 0u;
static atomic_uint_fast32_t s_watchdog_shadow_stack_latch = 0u;
typedef struct {
    mach_msg_header_t header;
    uint32_t worker_id;
    uint32_t sequence;
} cprisk_watchdog_mailbox_msg_t;
static mach_port_t s_watchdog_mailbox_ports[CPRISK_WATCHDOG_THREAD_COUNT];
static atomic_uint_fast64_t s_watchdog_mailbox_last_recv_ns[CPRISK_WATCHDOG_THREAD_COUNT];
static uint32_t s_watchdog_mailbox_send_seq[CPRISK_WATCHDOG_THREAD_COUNT];
static atomic_uint_fast32_t s_watchdog_mailbox_ready = 0u;
static atomic_uint_fast32_t s_watchdog_mailbox_last_peer_seq[CPRISK_WATCHDOG_THREAD_COUNT];
static atomic_uint_fast32_t s_watchdog_mailbox_peer_seq_initialized[CPRISK_WATCHDOG_THREAD_COUNT];

#define CPRISK_WATCHDOG_PROLOGUE_BYTES 16u
/* Monitored symbols: VM/trace/whitebox/deny-attach/signal probe/JIT decrypt + watchdog entry wrappers + shared body. */
#define CPRISK_WATCHDOG_PROLOGUE_SLOTS 10u
/*
 * pthread_create start_routine uses a small thunk so the exported pthread entry is not the
 * watchdog body address. The real worker is reached via PAC-signed (arm64e) or volatile
 * indirection. Peer-liveness is additionally carried over per-worker Mach receive ports,
 * so the stall detector does not rely only on shared-memory heartbeats.
 */
/* Intermediate bridge between pthread thunk and worker body (LE: "CPRISKBR") — PAC hop before main_impl. */
#define CPRISK_WATCHDOG_PTHREAD_BRIDGE_PAC_DISC 0x43505249534B4252ULL
/* arm64e: pthread start_routine uses PAC-signed pointer to the thunk (not raw __TEXT address). */
#define CPRISK_WATCHDOG_PTHREAD_THUNK_PAC_DISC 0x43505249534B5448ULL
/* Bit in last_prologue_fail_mask when libsystem pthread_create prologue mismatches baseline. */
#define CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_PTHREAD_CREATE (1u << 31)
/* Bit when libsystem/libdyld dlsym (import resolve chain) prologue mismatches baseline. */
#define CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DLSYM (1u << 30)
/* objc_msgSend (libobjc) — Frida / method swizzling hook surface. */
#define CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OBJC_MSGSEND (1u << 29)
/* _dyld_image_count — libdyld enumeration entry used by image scans / hook tools. */
#define CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DYLD_IMAGE_COUNT (1u << 28)

static uint8_t s_watchdog_prologue_ref[CPRISK_WATCHDOG_PROLOGUE_SLOTS][CPRISK_WATCHDOG_PROLOGUE_BYTES];
/* Previous-iteration snapshot for intra-run drift detection (cross-check vs ctor baseline). */
static uint8_t s_watchdog_prologue_last_ok[CPRISK_WATCHDOG_PROLOGUE_SLOTS][CPRISK_WATCHDOG_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_watchdog_prologue_last_ok_valid = 0u;
static uint8_t s_watchdog_pthread_create_ref[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static uint8_t s_watchdog_pthread_create_last_ok[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_watchdog_pthread_create_last_ok_valid = 0u;
static uint8_t s_watchdog_dlsym_ref[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static uint8_t s_watchdog_dlsym_last_ok[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_watchdog_dlsym_last_ok_valid = 0u;
static uint8_t s_watchdog_objc_msgsend_ref[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static uint8_t s_watchdog_objc_msgsend_last_ok[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_watchdog_objc_msgsend_last_ok_valid = 0u;
static uint8_t s_watchdog_dyld_image_count_ref[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static uint8_t s_watchdog_dyld_image_count_last_ok[CPRISK_WATCHDOG_PROLOGUE_BYTES];
static atomic_uint_fast32_t s_watchdog_dyld_image_count_last_ok_valid = 0u;
static atomic_uint_fast32_t s_watchdog_prologue_captured = 0u;
static atomic_uint_fast64_t s_watchdog_dyld_suspicious_events = 0u;
static atomic_uint_fast32_t s_watchdog_dyld_flags = 0u;
static atomic_uint_fast32_t s_watchdog_dyld_registered = 0u;

extern uint64_t cprisk_get_last_exception_delivery_probe_ns(void);
extern void cprisk_text_encrypt_service_idle(void);
extern int cprisk_vm_execute(uint64_t func_id, cprisk_vm_run_result_t *out);
extern int cprisk_whitebox_evaluate_domain(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
);
extern int cprisk_get_last_exception_delivery_probe_handled(void);
extern int cprisk_text_jit_decrypt(void *fault_addr);
extern cprisk_vm_flow_t cprisk_vm_dispatch_leaf_wb_wrapped_i(
    cprisk_vm_interp_frame_t *fr,
    uint8_t op_raw,
    uint8_t logical,
    uint64_t imm,
    uint32_t pc,
    uint32_t hvar,
    cprisk_vm_oph_fn materialized);

static void *cprisk_watchdog_pthread_thunk(void *arg);
static void *cprisk_watchdog_thread_main_bridge(void *arg);
static void *cprisk_watchdog_thread_main_impl(void *arg);
static void cprisk_watchdog_reset_mailboxes_locked(void);
static int cprisk_watchdog_init_mailboxes_locked(void);
static void cprisk_watchdog_mailbox_send_i(uint32_t worker_id);
static void cprisk_watchdog_mailbox_drain_i(uint32_t worker_id, uint64_t now_ns);
static int cprisk_watchdog_mach_peer_verify_i(uint32_t worker_id);
static void cprisk_watchdog_mark_peer_stall_i(void);

static void *s_watchdog_bridge_signed_fp;
static void *s_watchdog_thunk_signed_fp;

__attribute__((constructor(4)))
static void cprisk_watchdog_sign_main_entry_i(void) {
    s_watchdog_bridge_signed_fp = cprisk_pac_sign_function_pointer(
        (const void *)&cprisk_watchdog_thread_main_bridge,
        (uintptr_t)CPRISK_WATCHDOG_PTHREAD_BRIDGE_PAC_DISC);
    s_watchdog_thunk_signed_fp = cprisk_pac_sign_function_pointer(
        (const void *)&cprisk_watchdog_pthread_thunk,
        (uintptr_t)CPRISK_WATCHDOG_PTHREAD_THUNK_PAC_DISC);
}

static cprisk_anti_debug_watchdog_snapshot_t s_watchdog_snapshot = {
    .supported = 1u,
    .running = 0u,
    .thread_active = 0u,
    .stop_requested = 0u,
    .interval_seconds = 3u,
    .anomaly_flags = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE,
    .last_traced = 0u,
    .last_exception_port_healthy = 0u,
    .last_exception_query_succeeded = 0u,
    .last_exception_reclaim_attempted = 0u,
    .last_exception_hijack_detected = 0u,
    .last_deny_attach_result = 0,
    .last_deny_attach_errno = 0,
    .last_exception_query_kern_return = 0,
    .last_exception_register_kern_return = 0,
    .iteration_count = 0u,
    .traced_event_count = 0u,
    .deny_attach_error_count = 0u,
    .exception_anomaly_count = 0u,
    .last_check_monotonic_ns = 0u,
    .last_signal_probe_result = 0u,
    .last_hardware_bp_detected = 0u,
    .last_software_bp_detected = 0u,
    .last_csops_debugged = 0u,
    .last_suspicious_thread_count = 0u,
    .last_single_step_detected = 0u,
    .last_tty_detected = 0u,
    .last_developer_disk_detected = 0u,
    .last_exception_delivery_timeout_detected = 0u,
    .last_exception_delivery_probe_handled = 0u,
    .last_exception_delivery_probe_ns = 0u,
    .signal_probe_anomaly_count = 0u,
    .hardware_bp_anomaly_count = 0u,
    .software_bp_anomaly_count = 0u,
    .csops_anomaly_count = 0u,
    .suspicious_thread_anomaly_count = 0u,
    .exception_delivery_timeout_anomaly_count = 0u,
    .peer_watchdog_anomaly_count = 0u,
    .shadow_stack_anomaly_count = 0u,
    .last_peer_watchdog_stalled = 0u,
    .last_shadow_stack_mismatch = 0u,
    .last_dbi_detected = 0u,
    .last_dbi_marker_flags = 0u,
    .last_timing_anomaly_flags = 0u,
    .last_timing_probe_median_ns = 0u,
    .last_timing_probe_max_ns = 0u,
    .last_timing_probe_threshold_ns = 0u,
    .dbi_anomaly_count = 0u,
    .timing_anomaly_count = 0u,
    .prologue_integrity_anomaly_count = 0u,
    .dyld_injection_anomaly_count = 0u,
    .last_prologue_fail_mask = 0u,
    .last_dyld_injection_flags = 0u,
    .last_csops_status_flags = 0u,
    .last_amfi_probe_bits = 0u,
    .last_get_task_allow_suspect = 0u,
    .last_deny_attach_verify_bits = 0u,
    .deny_attach_verify_anomaly_count = 0u,
    .amfi_cs_flags_anomaly_count = 0u,
    .get_task_allow_anomaly_count = 0u,
    .vm_mprotect_crosscheck_mismatch_total = 0u,
    .vm_mprotect_mach_trap_mismatch_total = 0u,
};

static void *cprisk_watchdog_thread_main_bridge(void *arg) {
    return cprisk_watchdog_thread_main_impl(arg);
}

static void *cprisk_watchdog_pthread_thunk(void *arg) {
    void *fn = cprisk_pac_auth_function_pointer(
        s_watchdog_bridge_signed_fp,
        (uintptr_t)CPRISK_WATCHDOG_PTHREAD_BRIDGE_PAC_DISC);
    if (fn == NULL) {
        const uint32_t wid = (uint32_t)(uintptr_t)arg;
        if (wid < CPRISK_WATCHDOG_THREAD_COUNT) {
            atomic_store(&s_watchdog_worker_active[wid], 0u);
        }
        pthread_mutex_lock(&s_watchdog_mutex);
        s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return NULL;
    }
    typedef void *(*cprisk_wd_start_fn)(void *);
    return ((cprisk_wd_start_fn)fn)(arg);
}

static inline uint32_t cprisk_wd_amfi_flags_from_probe_bits_i(uint32_t amfi_probe_bits) {
    uint32_t flags = 0u;
    if ((amfi_probe_bits & CPRISK_AMFI_PROBE_CS_DEBUGGED) != 0u ||
        (amfi_probe_bits & CPRISK_AMFI_PROBE_CS_VALID_ABSENT) != 0u ||
        (amfi_probe_bits & CPRISK_AMFI_PROBE_CS_HARD_ABSENT) != 0u ||
        (amfi_probe_bits & CPRISK_AMFI_PROBE_CS_KILL_ABSENT) != 0u) {
        flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS;
    }
    return flags;
}

static inline int cprisk_wd_csops_debug_probe_inline_i(void) {
    return cprisk_csops_debug_check();
}

static uint64_t cprisk_monotonic_time_ns(void) {
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

    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static void cprisk_watchdog_fill_prologue_addrs_i(const void **addrs) {
    addrs[0] = (const void *)&cprisk_vm_execute;
    addrs[1] = (const void *)&cprisk_is_being_traced;
    addrs[2] = (const void *)&cprisk_whitebox_evaluate_domain;
    addrs[3] = (const void *)&cprisk_deny_attach;
    addrs[4] = (const void *)&cprisk_probe_debugger_via_signal;
    addrs[5] = (const void *)&cprisk_text_jit_decrypt;
    addrs[6] = (const void *)&cprisk_watchdog_pthread_thunk;
    addrs[7] = (const void *)&cprisk_watchdog_thread_main_bridge;
    addrs[8] = (const void *)&cprisk_watchdog_thread_main_impl;
    addrs[9] = (const void *)&cprisk_vm_dispatch_leaf_wb_wrapped_i;
}

static void cprisk_watchdog_capture_prologue_once_i(void) {
    if (atomic_load(&s_watchdog_prologue_captured) != 0u) {
        return;
    }
    const void *addrs[CPRISK_WATCHDOG_PROLOGUE_SLOTS];
    cprisk_watchdog_fill_prologue_addrs_i(addrs);
    for (uint32_t i = 0u; i < CPRISK_WATCHDOG_PROLOGUE_SLOTS; i++) {
        memcpy(s_watchdog_prologue_ref[i], addrs[i], CPRISK_WATCHDOG_PROLOGUE_BYTES);
    }
    memcpy(s_watchdog_pthread_create_ref, (const void *)&pthread_create, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    memcpy(s_watchdog_dlsym_ref, (const void *)&dlsym, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    memcpy(s_watchdog_objc_msgsend_ref, (const void *)&objc_msgSend, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    memcpy(s_watchdog_dyld_image_count_ref, (const void *)&_dyld_image_count, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    atomic_store(&s_watchdog_prologue_captured, 1u);
}

/*
 * Early baseline: priority 10 runs before most other CRiskCore constructors (e.g. 101+),
 * shrinking the window where hooks can win before the first snapshot.
 */
__attribute__((constructor(10)))
static void cprisk_watchdog_prologue_early_ctor_i(void) {
    cprisk_watchdog_capture_prologue_once_i();
}

static int cprisk_watchdog_verify_pthread_create_prologue_i(uint32_t *mask_out) {
    if (atomic_load(&s_watchdog_prologue_captured) == 0u) {
        cprisk_watchdog_capture_prologue_once_i();
    }
    uint8_t live[CPRISK_WATCHDOG_PROLOGUE_BYTES];
    /* TOCTOU: snapshot libsystem code into a stack shadow before compare (not direct memcmp on r-x). */
    memcpy(live, (const void *)&pthread_create, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    if (atomic_load_explicit(&s_watchdog_pthread_create_last_ok_valid, memory_order_relaxed) != 0u &&
        memcmp(s_watchdog_pthread_create_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_PTHREAD_CREATE;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    if (memcmp(s_watchdog_pthread_create_ref, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_PTHREAD_CREATE;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    memcpy(s_watchdog_pthread_create_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    atomic_store_explicit(&s_watchdog_pthread_create_last_ok_valid, 1u, memory_order_release);
    return 1;
}

static int cprisk_watchdog_verify_dlsym_prologue_i(uint32_t *mask_out) {
    if (atomic_load(&s_watchdog_prologue_captured) == 0u) {
        cprisk_watchdog_capture_prologue_once_i();
    }
    uint8_t live[CPRISK_WATCHDOG_PROLOGUE_BYTES];
    memcpy(live, (const void *)&dlsym, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    if (atomic_load_explicit(&s_watchdog_dlsym_last_ok_valid, memory_order_relaxed) != 0u &&
        memcmp(s_watchdog_dlsym_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DLSYM;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    if (memcmp(s_watchdog_dlsym_ref, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DLSYM;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    memcpy(s_watchdog_dlsym_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    atomic_store_explicit(&s_watchdog_dlsym_last_ok_valid, 1u, memory_order_release);
    return 1;
}

int cprisk_verify_dlsym_prologue(void) {
    uint32_t mask = 0u;
    return cprisk_watchdog_verify_dlsym_prologue_i(&mask);
}

static int cprisk_watchdog_verify_objc_msgsend_prologue_i(uint32_t *mask_out) {
    if (atomic_load(&s_watchdog_prologue_captured) == 0u) {
        cprisk_watchdog_capture_prologue_once_i();
    }
    uint8_t live[CPRISK_WATCHDOG_PROLOGUE_BYTES];
    memcpy(live, (const void *)&objc_msgSend, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    if (atomic_load_explicit(&s_watchdog_objc_msgsend_last_ok_valid, memory_order_relaxed) != 0u &&
        memcmp(s_watchdog_objc_msgsend_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OBJC_MSGSEND;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    if (memcmp(s_watchdog_objc_msgsend_ref, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OBJC_MSGSEND;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    memcpy(s_watchdog_objc_msgsend_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    atomic_store_explicit(&s_watchdog_objc_msgsend_last_ok_valid, 1u, memory_order_release);
    return 1;
}

static int cprisk_watchdog_verify_dyld_image_count_prologue_i(uint32_t *mask_out) {
    if (atomic_load(&s_watchdog_prologue_captured) == 0u) {
        cprisk_watchdog_capture_prologue_once_i();
    }
    uint8_t live[CPRISK_WATCHDOG_PROLOGUE_BYTES];
    memcpy(live, (const void *)&_dyld_image_count, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    if (atomic_load_explicit(&s_watchdog_dyld_image_count_last_ok_valid, memory_order_relaxed) != 0u &&
        memcmp(s_watchdog_dyld_image_count_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DYLD_IMAGE_COUNT;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    if (memcmp(s_watchdog_dyld_image_count_ref, live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
        *mask_out |= CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DYLD_IMAGE_COUNT;
        cprisk_integrity_poison_watchdog_lane_now();
        return 0;
    }
    memcpy(s_watchdog_dyld_image_count_last_ok, live, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    atomic_store_explicit(&s_watchdog_dyld_image_count_last_ok_valid, 1u, memory_order_release);
    return 1;
}

int cprisk_verify_runtime_hook_surface_prologues(void) {
    uint32_t mask = 0u;
    if (cprisk_watchdog_verify_objc_msgsend_prologue_i(&mask) == 0) {
        return 0;
    }
    if (cprisk_watchdog_verify_dyld_image_count_prologue_i(&mask) == 0) {
        return 0;
    }
    (void)mask;
    return 1;
}

static void cprisk_watchdog_verify_prologue_i(uint32_t *anomaly_out, uint32_t *mask_out) {
    *anomaly_out = 0u;
    *mask_out = 0u;
    if (atomic_load(&s_watchdog_prologue_captured) == 0u) {
        cprisk_watchdog_capture_prologue_once_i();
        return;
    }
    const void *addrs[CPRISK_WATCHDOG_PROLOGUE_SLOTS];
    cprisk_watchdog_fill_prologue_addrs_i(addrs);
    const int have_last =
        atomic_load_explicit(&s_watchdog_prologue_last_ok_valid, memory_order_relaxed) != 0u;
    for (uint32_t i = 0u; i < CPRISK_WATCHDOG_PROLOGUE_SLOTS; i++) {
        uint8_t live[CPRISK_WATCHDOG_PROLOGUE_BYTES];
        /* TOCTOU: compare against shadow snapshot; attacker could otherwise flip bytes mid-memcmp. */
        memcpy(live, addrs[i], CPRISK_WATCHDOG_PROLOGUE_BYTES);
        if (have_last != 0 &&
            memcmp(s_watchdog_prologue_last_ok[i], live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
            *anomaly_out |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
            *mask_out |= (1u << i);
            cprisk_integrity_poison_watchdog_lane_now();
        }
        if (memcmp(s_watchdog_prologue_ref[i], live, CPRISK_WATCHDOG_PROLOGUE_BYTES) != 0) {
            *anomaly_out |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
            *mask_out |= (1u << i);
            cprisk_integrity_poison_watchdog_lane_now();
        }
        memcpy(s_watchdog_prologue_last_ok[i], live, CPRISK_WATCHDOG_PROLOGUE_BYTES);
    }
    atomic_store_explicit(&s_watchdog_prologue_last_ok_valid, 1u, memory_order_release);
}

static int cprisk_watchdog_dyld_name_suspicious_i(const char *path, uint32_t *flags_out) {
    if (!path || !flags_out) {
        return 0;
    }
    char lowered[256];
    size_t n = 0u;
    for (; path[n] != '\0' && n + 1u < sizeof(lowered); n++) {
        char c = path[n];
        if (c >= 'A' && c <= 'Z') {
            c += (char)('a' - 'A');
        }
        lowered[n] = c;
    }
    lowered[n] = '\0';

    static const uint8_t k_e_frida[] = {0xfc, 0x82, 0x19, 0x6b, 0xa3};
    static const uint8_t k_e_gum_dash[] = {0xdc, 0x33, 0x9b, 0x4d};
    static const uint8_t k_e_cycript[] = {0x69, 0x19, 0x5c, 0x10, 0x02, 0x22, 0xca};
    static const uint8_t k_e_substrate[] = {0x36, 0x91, 0xe4, 0xaa, 0xad, 0xdb, 0xc2, 0xbd, 0x5f};
    static const uint8_t k_e_substitute[] = {
        0x3c, 0x64, 0x41, 0x26, 0x26, 0xd2, 0x4a, 0xf3, 0x5b, 0xbe};
    static const uint8_t k_e_libhooker[] = {0xd0, 0xf0, 0xd3, 0xb4, 0x00, 0x69, 0xc8, 0x8a, 0x7a};
    static const uint8_t k_e_ssl_kill[] = {0x4b, 0x7d, 0xf6, 0x3f, 0x37, 0xc9, 0x51, 0x4a};
    static const uint8_t k_e_sskill[] = {0x3d, 0x14, 0xc2, 0x31, 0x37, 0x4c};
    static const uint8_t k_e_cephei[] = {0x46, 0xdd, 0xc7, 0xe4, 0xb8, 0xbc};
    static const uint8_t k_e_rocket[] = {
        0x7a, 0x0c, 0xe4, 0xff, 0xce, 0x2b, 0xaf, 0x39, 0xa5, 0xe1, 0xf8, 0xdd, 0xba, 0x42, 0x07};
    static const uint8_t k_e_dopamine[] = {0xf4, 0x29, 0x61, 0xdb, 0x74, 0xae, 0x67, 0xef};
    static const uint8_t k_e_ellekit[] = {0x84, 0xa8, 0x44, 0x78, 0x90, 0x96, 0x8a};
    static const uint8_t k_e_qbdi[] = {0x69, 0xe7, 0x05, 0x24};
    static const uint8_t k_e_libqbdi[] = {0xf6, 0x50, 0xdd, 0xc9, 0xac, 0x79, 0x6c};
    static const uint8_t k_e_qbdipreload[] = {
        0xca, 0xa7, 0x88, 0x33, 0xe8, 0xea, 0x4c, 0x36, 0x2b, 0x09, 0x43};

    static const struct {
        uint32_t key_id;
        const uint8_t *enc;
        size_t enc_len;
        uint32_t flag;
    } k_rows[] = {
        {1u, k_e_frida, sizeof(k_e_frida), 1u << 0},
        {2u, k_e_gum_dash, sizeof(k_e_gum_dash), 1u << 1},
        {3u, k_e_cycript, sizeof(k_e_cycript), 1u << 2},
        {4u, k_e_substrate, sizeof(k_e_substrate), 1u << 3},
        {5u, k_e_substitute, sizeof(k_e_substitute), 1u << 4},
        {6u, k_e_libhooker, sizeof(k_e_libhooker), 1u << 5},
        {7u, k_e_ssl_kill, sizeof(k_e_ssl_kill), 1u << 6},
        {8u, k_e_sskill, sizeof(k_e_sskill), 1u << 7},
        {9u, k_e_cephei, sizeof(k_e_cephei), 1u << 8},
        {10u, k_e_rocket, sizeof(k_e_rocket), 1u << 9},
        {11u, k_e_dopamine, sizeof(k_e_dopamine), 1u << 10},
        {12u, k_e_ellekit, sizeof(k_e_ellekit), 1u << 11},
        {13u, k_e_qbdi, sizeof(k_e_qbdi), 1u << 12},
        {14u, k_e_libqbdi, sizeof(k_e_libqbdi), 1u << 13},
        {15u, k_e_qbdipreload, sizeof(k_e_qbdipreload), 1u << 14},
    };

    const uint32_t D = CPRISK_OBF_TAG_DOMAIN_WD_DYLD;
    uint32_t f = 0u;
    for (size_t i = 0u; i < sizeof(k_rows) / sizeof(k_rows[0]); i++) {
        char needle[40];
        memset(needle, 0, sizeof(needle));
        if (k_rows[i].enc_len + 1u > sizeof(needle)) {
            continue;
        }
        if (cprisk_obf_decode_sha256_tag(
                D,
                k_rows[i].key_id,
                k_rows[i].enc,
                k_rows[i].enc_len,
                needle,
                sizeof(needle)) != 0) {
            continue;
        }
        const char *h = lowered;
        const char *nd = needle;
        for (; *h != '\0'; h++) {
            const char *a = h;
            const char *b = nd;
            while (*a != '\0' && *b != '\0' && *a == *b) {
                a++;
                b++;
            }
            if (*b == '\0') {
                f |= k_rows[i].flag;
                break;
            }
        }
        cprisk_secure_zero(needle, sizeof(needle));
    }
    *flags_out = f;
    return f != 0u ? 1 : 0;
}

static void cprisk_watchdog_dyld_add_image_i(const struct mach_header *mh, intptr_t slide) {
    (void)slide;
    const uint32_t count = _dyld_image_count();
    const char *name = NULL;
    for (uint32_t i = 0u; i < count; i++) {
        if (_dyld_get_image_header(i) == mh) {
            name = _dyld_get_image_name(i);
            break;
        }
    }
    uint32_t flags = 0u;
    if (!cprisk_watchdog_dyld_name_suspicious_i(name, &flags)) {
        return;
    }
    atomic_fetch_or(&s_watchdog_dyld_flags, flags);
    atomic_fetch_add(&s_watchdog_dyld_suspicious_events, 1ull);
    cprisk_integrity_poison_watchdog_lane_now();
}

static void cprisk_watchdog_register_dyld_observer_once_i(void) {
    if (atomic_exchange(&s_watchdog_dyld_registered, 1u) != 0u) {
        return;
    }
    _dyld_register_func_for_add_image(cprisk_watchdog_dyld_add_image_i);
}

static uint64_t cprisk_prng_next_i(uint64_t state) {
    if (state == 0u) {
        state = 0x9E3779B97F4A7C15ULL;
    }
    state ^= state << 7u;
    state ^= state >> 9u;
    state ^= state << 8u;
    return state;
}

static uint64_t cprisk_watchdog_random_u64_i(void) {
    uint_fast64_t current = atomic_load(&s_watchdog_prng_state);
    if (current == 0u) {
        uint64_t seed = 0u;
        int err = 0;
        if (cprisk_getentropy_direct(&seed, sizeof(seed), &err) != 0 || seed == 0u) {
            seed = cprisk_monotonic_time_ns() ^ (uint64_t)(uintptr_t)&seed ^ 0xA5A5A5A5u;
        }
        atomic_store(&s_watchdog_prng_state, seed);
        current = seed;
    }

    for (;;) {
        const uint_fast64_t next = cprisk_prng_next_i((uint64_t)current);
        uint_fast64_t expected = current;
        if (atomic_compare_exchange_weak(&s_watchdog_prng_state, &expected, next)) {
            return next;
        }
        current = expected;
    }
}

static int cprisk_watchdog_scan_software_breakpoints_i(void) {
    int detected = 0;

    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_deny_attach,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_deny_attach_status,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_probe_debugger_via_signal,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_probe_exception_delivery_timeout,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_register_exception_handler,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
    detected += cprisk_scan_software_breakpoints(
        (const void *)cprisk_verify_exception_handler,
        CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES);
#if defined(TARGET_OS_IOS) && TARGET_OS_IOS
    /*
     * Randomized full-text sampling is high-value on iOS device binaries,
     * but macOS test binaries often embed intentional BRK opcodes in debug
     * paths and can cause noisy false positives.
     */
    detected += cprisk_scan_software_breakpoints_randomized_text(
        CPRISK_WATCHDOG_RANDOM_TEXT_WINDOWS,
        CPRISK_WATCHDOG_RANDOM_TEXT_WINDOW_BYTES);
#endif

    return detected;
}

static uintptr_t cprisk_shadow_mix_i(uintptr_t ret_addr, uintptr_t frame_addr) {
    return ret_addr ^ (frame_addr << 11u) ^ (frame_addr >> 7u) ^ (uintptr_t)0x7A6CE1B5u;
}

static cprisk_shadow_token_t cprisk_shadow_push_i(void) {
    cprisk_shadow_token_t token;
    token.value = 0u;
#if defined(__has_builtin)
#if __has_builtin(__builtin_return_address) && __has_builtin(__builtin_frame_address)
    token.value = cprisk_shadow_mix_i(
        (uintptr_t)__builtin_return_address(0),
        (uintptr_t)__builtin_frame_address(0));
#endif
#endif
    return token;
}

static int cprisk_shadow_check_i(cprisk_shadow_token_t token) {
    if (token.value == 0u) {
        return 1;
    }
#if defined(__has_builtin)
#if __has_builtin(__builtin_return_address) && __has_builtin(__builtin_frame_address)
    const uintptr_t now = cprisk_shadow_mix_i(
        (uintptr_t)__builtin_return_address(0),
        (uintptr_t)__builtin_frame_address(0));
    return now == token.value ? 1 : 0;
#endif
#endif
    return 1;
}

static void cprisk_watchdog_refresh_thread_active_locked(void) {
    const uint32_t active0 = atomic_load(&s_watchdog_worker_active[0]) != 0u ? 1u : 0u;
    const uint32_t active1 = atomic_load(&s_watchdog_worker_active[1]) != 0u ? 1u : 0u;
    s_watchdog_snapshot.thread_active = (active0 | active1);
}

static void cprisk_watchdog_reset_locked(void) {
    s_watchdog_snapshot.running = 0u;
    s_watchdog_snapshot.thread_active = 0u;
    s_watchdog_snapshot.stop_requested = 0u;
    s_watchdog_snapshot.interval_seconds = 1u;
    s_watchdog_snapshot.anomaly_flags = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE;
    s_watchdog_snapshot.last_traced = 0u;
    s_watchdog_snapshot.last_exception_port_healthy = 0u;
    s_watchdog_snapshot.last_exception_query_succeeded = 0u;
    s_watchdog_snapshot.last_exception_reclaim_attempted = 0u;
    s_watchdog_snapshot.last_exception_hijack_detected = 0u;
    s_watchdog_snapshot.last_deny_attach_result = 0;
    s_watchdog_snapshot.last_deny_attach_errno = 0;
    s_watchdog_snapshot.last_exception_query_kern_return = 0;
    s_watchdog_snapshot.last_exception_register_kern_return = 0;
    s_watchdog_snapshot.iteration_count = 0u;
    s_watchdog_snapshot.traced_event_count = 0u;
    s_watchdog_snapshot.deny_attach_error_count = 0u;
    s_watchdog_snapshot.exception_anomaly_count = 0u;
    s_watchdog_snapshot.last_check_monotonic_ns = 0u;
    s_watchdog_snapshot.last_signal_probe_result = 0u;
    s_watchdog_snapshot.last_hardware_bp_detected = 0u;
    s_watchdog_snapshot.last_software_bp_detected = 0u;
    s_watchdog_snapshot.last_csops_debugged = 0u;
    s_watchdog_snapshot.last_suspicious_thread_count = 0u;
    s_watchdog_snapshot.last_single_step_detected = 0u;
    s_watchdog_snapshot.last_tty_detected = 0u;
    s_watchdog_snapshot.last_developer_disk_detected = 0u;
    s_watchdog_snapshot.last_exception_delivery_timeout_detected = 0u;
    s_watchdog_snapshot.last_exception_delivery_probe_handled = 0u;
    s_watchdog_snapshot.last_exception_delivery_probe_ns = 0u;
    s_watchdog_snapshot.signal_probe_anomaly_count = 0u;
    s_watchdog_snapshot.hardware_bp_anomaly_count = 0u;
    s_watchdog_snapshot.software_bp_anomaly_count = 0u;
    s_watchdog_snapshot.csops_anomaly_count = 0u;
    s_watchdog_snapshot.suspicious_thread_anomaly_count = 0u;
    s_watchdog_snapshot.exception_delivery_timeout_anomaly_count = 0u;
    s_watchdog_snapshot.peer_watchdog_anomaly_count = 0u;
    s_watchdog_snapshot.shadow_stack_anomaly_count = 0u;
    s_watchdog_snapshot.last_peer_watchdog_stalled = 0u;
    s_watchdog_snapshot.last_shadow_stack_mismatch = 0u;
    s_watchdog_snapshot.last_dbi_detected = 0u;
    s_watchdog_snapshot.last_dbi_marker_flags = 0u;
    s_watchdog_snapshot.last_timing_anomaly_flags = 0u;
    s_watchdog_snapshot.last_timing_probe_median_ns = 0u;
    s_watchdog_snapshot.last_timing_probe_max_ns = 0u;
    s_watchdog_snapshot.last_timing_probe_threshold_ns = 0u;
    s_watchdog_snapshot.dbi_anomaly_count = 0u;
    s_watchdog_snapshot.timing_anomaly_count = 0u;
    s_watchdog_snapshot.prologue_integrity_anomaly_count = 0u;
    s_watchdog_snapshot.dyld_injection_anomaly_count = 0u;
    s_watchdog_snapshot.last_prologue_fail_mask = 0u;
    s_watchdog_snapshot.last_dyld_injection_flags = 0u;
    s_watchdog_snapshot.last_csops_status_flags = 0u;
    s_watchdog_snapshot.last_amfi_probe_bits = 0u;
    s_watchdog_snapshot.last_get_task_allow_suspect = 0u;
    s_watchdog_snapshot.last_deny_attach_verify_bits = 0u;
    s_watchdog_snapshot.deny_attach_verify_anomaly_count = 0u;
    s_watchdog_snapshot.amfi_cs_flags_anomaly_count = 0u;
    s_watchdog_snapshot.get_task_allow_anomaly_count = 0u;
    s_watchdog_snapshot.vm_mprotect_crosscheck_mismatch_total = 0u;
    s_watchdog_snapshot.vm_mprotect_mach_trap_mismatch_total = 0u;
    atomic_store(&s_watchdog_dyld_flags, 0u);
    atomic_store(&s_watchdog_dyld_suspicious_events, 0ull);
    cprisk_watchdog_reset_mailboxes_locked();
    /* Intentionally retain prologue / pthread_create / dlsym baselines across restarts (early ctor snapshot). */
}

static int cprisk_watchdog_should_stop(void) {
    return atomic_load(&s_watchdog_stop_requested) != 0;
}

int cprisk_watchdog_probe_should_stop(void) {
    return cprisk_watchdog_should_stop();
}

static void cprisk_watchdog_reset_mailboxes_locked(void) {
    atomic_store(&s_watchdog_mailbox_ready, 0u);
    for (uint32_t i = 0u; i < CPRISK_WATCHDOG_THREAD_COUNT; i++) {
        if (s_watchdog_mailbox_ports[i] != MACH_PORT_NULL) {
            mach_port_destroy(mach_task_self(), s_watchdog_mailbox_ports[i]);
            s_watchdog_mailbox_ports[i] = MACH_PORT_NULL;
        }
        atomic_store(&s_watchdog_mailbox_last_recv_ns[i], 0u);
        s_watchdog_mailbox_send_seq[i] = 0u;
        atomic_store(&s_watchdog_mailbox_last_peer_seq[i], 0u);
        atomic_store(&s_watchdog_mailbox_peer_seq_initialized[i], 0u);
    }
}

static int cprisk_watchdog_init_mailboxes_locked(void) {
    cprisk_watchdog_reset_mailboxes_locked();
    for (uint32_t i = 0u; i < CPRISK_WATCHDOG_THREAD_COUNT; i++) {
        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
        if (kr != KERN_SUCCESS) {
            cprisk_watchdog_reset_mailboxes_locked();
            return -1;
        }
        kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
        if (kr != KERN_SUCCESS) {
            mach_port_destroy(mach_task_self(), port);
            cprisk_watchdog_reset_mailboxes_locked();
            return -1;
        }
        s_watchdog_mailbox_ports[i] = port;
        atomic_store(&s_watchdog_mailbox_last_recv_ns[i], 0u);
        s_watchdog_mailbox_send_seq[i] = 0u;
        atomic_store(&s_watchdog_mailbox_last_peer_seq[i], 0u);
        atomic_store(&s_watchdog_mailbox_peer_seq_initialized[i], 0u);
    }
    atomic_store(&s_watchdog_mailbox_ready, 1u);
    return 0;
}

/*
 * Mach cross-check beyond pthread heartbeats: receive port ownership, peer thread
 * suspend count (debugger/thread_suspend), and mailbox monotonic sequence (replay).
 */
static int cprisk_watchdog_mach_peer_verify_i(uint32_t worker_id) {
    if (atomic_load_explicit(&s_watchdog_mailbox_ready, memory_order_acquire) == 0u) {
        return 0;
    }
    mach_port_t recv = s_watchdog_mailbox_ports[worker_id];
    if (recv != MACH_PORT_NULL) {
        mach_port_type_t ptypes = 0;
        if (mach_port_type(mach_task_self(), recv, &ptypes) != KERN_SUCCESS ||
            (ptypes & MACH_PORT_TYPE_RECEIVE) == 0) {
            return 1;
        }
    }
    const uint32_t peer_id =
        worker_id == CPRISK_WATCHDOG_PRIMARY_ID
            ? CPRISK_WATCHDOG_SECONDARY_ID
            : CPRISK_WATCHDOG_PRIMARY_ID;
    if (atomic_load(&s_watchdog_worker_active[peer_id]) == 0u) {
        return 0;
    }
    if ((s_watchdog_started_mask & (1u << peer_id)) == 0u) {
        return 0;
    }
    const pthread_t peer_pt = s_watchdog_threads[peer_id];
    thread_t peer_thr = pthread_mach_thread_np(peer_pt);
    if (peer_thr == MACH_PORT_NULL) {
        return 1;
    }
    thread_basic_info_data_t bi;
    mach_msg_type_number_t bicount = THREAD_BASIC_INFO_COUNT;
    if (thread_info(peer_thr, THREAD_BASIC_INFO, (thread_info_t)&bi, &bicount) != KERN_SUCCESS) {
        return 1;
    }
    if (bi.suspend_count != 0) {
        return 1;
    }
    return 0;
}

static void cprisk_watchdog_mailbox_send_i(uint32_t worker_id) {
    if (atomic_load_explicit(&s_watchdog_mailbox_ready, memory_order_acquire) == 0u) {
        return;
    }
    const uint32_t peer_id =
        worker_id == CPRISK_WATCHDOG_PRIMARY_ID
            ? CPRISK_WATCHDOG_SECONDARY_ID
            : CPRISK_WATCHDOG_PRIMARY_ID;
    mach_port_t remote = s_watchdog_mailbox_ports[peer_id];
    if (remote == MACH_PORT_NULL) {
        return;
    }
    cprisk_watchdog_mailbox_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = (mach_msg_size_t)sizeof(msg);
    msg.header.msgh_remote_port = remote;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_id = 0x43505744; /* "CPWD" */
    msg.worker_id = worker_id;
    msg.sequence = ++s_watchdog_mailbox_send_seq[worker_id];
    (void)mach_msg(&msg.header,
                   MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                   msg.header.msgh_size,
                   0,
                   MACH_PORT_NULL,
                   0,
                   MACH_PORT_NULL);
}

static void cprisk_watchdog_mailbox_drain_i(uint32_t worker_id, uint64_t now_ns) {
    if (atomic_load_explicit(&s_watchdog_mailbox_ready, memory_order_acquire) == 0u) {
        return;
    }
    mach_port_t recv_port = s_watchdog_mailbox_ports[worker_id];
    if (recv_port == MACH_PORT_NULL) {
        return;
    }
    for (uint32_t i = 0u; i < 4u; i++) {
        cprisk_watchdog_mailbox_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        kern_return_t kr = mach_msg(&msg.header,
                                    MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                    0,
                                    (mach_msg_size_t)sizeof(msg),
                                    recv_port,
                                    0,
                                    MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            break;
        }
        if (msg.header.msgh_id == 0x43505744) {
            const uint32_t peer_id =
                worker_id == CPRISK_WATCHDOG_PRIMARY_ID
                    ? CPRISK_WATCHDOG_SECONDARY_ID
                    : CPRISK_WATCHDOG_PRIMARY_ID;
            if (msg.worker_id != peer_id) {
                cprisk_watchdog_mark_peer_stall_i();
            } else {
                const uint32_t prev = atomic_load_explicit(
                    &s_watchdog_mailbox_last_peer_seq[worker_id], memory_order_relaxed);
                const uint32_t inited = atomic_load_explicit(
                    &s_watchdog_mailbox_peer_seq_initialized[worker_id], memory_order_relaxed);
                if (inited == 0u) {
                    atomic_store_explicit(
                        &s_watchdog_mailbox_last_peer_seq[worker_id], msg.sequence, memory_order_relaxed);
                    atomic_store_explicit(
                        &s_watchdog_mailbox_peer_seq_initialized[worker_id], 1u, memory_order_release);
                } else {
                    if (msg.sequence <= prev) {
                        cprisk_watchdog_mark_peer_stall_i();
                    }
                    atomic_store_explicit(
                        &s_watchdog_mailbox_last_peer_seq[worker_id], msg.sequence, memory_order_relaxed);
                }
            }
            atomic_store(&s_watchdog_mailbox_last_recv_ns[worker_id], now_ns);
        }
    }
}

static uint32_t cprisk_watchdog_pick_interval_ms_i(uint32_t anomaly_flags) {
    const uint64_t rnd = cprisk_watchdog_random_u64_i();
    if (anomaly_flags != CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE) {
        const uint32_t span =
            CPRISK_WATCHDOG_SHORT_INTERVAL_MAX_MS - CPRISK_WATCHDOG_SHORT_INTERVAL_MIN_MS + 1u;
        return CPRISK_WATCHDOG_SHORT_INTERVAL_MIN_MS + (uint32_t)(rnd % span);
    }

    const uint32_t span = CPRISK_WATCHDOG_INTERVAL_JITTER_MS * 2u + 1u;
    const int32_t offset = (int32_t)(rnd % span) - (int32_t)CPRISK_WATCHDOG_INTERVAL_JITTER_MS;
    int32_t candidate = (int32_t)CPRISK_WATCHDOG_DEFAULT_INTERVAL_MS + offset;
    if (candidate < (int32_t)CPRISK_WATCHDOG_SHORT_INTERVAL_MIN_MS) {
        candidate = (int32_t)CPRISK_WATCHDOG_SHORT_INTERVAL_MIN_MS;
    }
    return (uint32_t)candidate;
}

static void cprisk_watchdog_sleep_interval_ms_i(uint32_t interval_ms) {
    struct timespec req;
    req.tv_sec = 0;
    req.tv_nsec = CPRISK_WATCHDOG_SLEEP_SLICE_NS;
    uint32_t elapsed = 0u;
    while (elapsed < interval_ms) {
        if (cprisk_watchdog_should_stop()) {
            return;
        }
        nanosleep(&req, NULL);
        elapsed += 100u;
    }
}

static void cprisk_watchdog_publish_deadline_i(uint32_t worker_id, uint32_t interval_ms) {
    const uint64_t now_ns = cprisk_monotonic_time_ns();
    uint64_t budget_ns = (uint64_t)interval_ms * 3ull * 1000000ull;
    if (budget_ns < CPRISK_WATCHDOG_PEER_STALL_MIN_NS) {
        budget_ns = CPRISK_WATCHDOG_PEER_STALL_MIN_NS;
    }
    atomic_store(&s_watchdog_deadline_ns[worker_id], now_ns + budget_ns);
}

static int cprisk_watchdog_peer_stalled_i(uint32_t worker_id, uint32_t interval_ms) {
    const uint32_t peer_id =
        worker_id == CPRISK_WATCHDOG_PRIMARY_ID
            ? CPRISK_WATCHDOG_SECONDARY_ID
            : CPRISK_WATCHDOG_PRIMARY_ID;
    if (atomic_load(&s_watchdog_worker_active[peer_id]) == 0u) {
        return 0;
    }

    const uint64_t now_ns = cprisk_monotonic_time_ns();
    uint64_t peer_ns = atomic_load(&s_watchdog_heartbeat_ns[peer_id]);
    const uint64_t peer_mailbox_ns = atomic_load(&s_watchdog_mailbox_last_recv_ns[worker_id]);
    if (peer_mailbox_ns != 0u && now_ns > peer_mailbox_ns) {
        peer_ns = peer_mailbox_ns;
    }
    const uint64_t peer_deadline_ns = atomic_load(&s_watchdog_deadline_ns[peer_id]);
    if (peer_ns == 0u || now_ns <= peer_ns) {
        return 0;
    }

    uint64_t threshold_ns = (uint64_t)interval_ms * 2ull * 1000000ull;
    if (threshold_ns < CPRISK_WATCHDOG_PEER_STALL_MIN_NS) {
        threshold_ns = CPRISK_WATCHDOG_PEER_STALL_MIN_NS;
    }
    if (peer_deadline_ns != 0u && now_ns > peer_deadline_ns &&
        (now_ns - peer_ns) > (threshold_ns / 2ull)) {
        return 1;
    }
    return (now_ns - peer_ns) > threshold_ns ? 1 : 0;
}

static void cprisk_watchdog_mark_peer_stall_i(void) {
    atomic_store(&s_watchdog_peer_stall_latch, 1u);
    cprisk_integrity_poison_watchdog_lane_now();

    pthread_mutex_lock(&s_watchdog_mutex);
    s_watchdog_snapshot.anomaly_flags |=
        CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;
    s_watchdog_snapshot.last_peer_watchdog_stalled = 1u;
    s_watchdog_snapshot.peer_watchdog_anomaly_count += 1u;
    pthread_mutex_unlock(&s_watchdog_mutex);
}

static uint32_t cprisk_watchdog_run_secondary_iteration_i(uint32_t inherited_flags) {
    const cprisk_shadow_token_t shadow_token = cprisk_shadow_push_i();
    uint32_t anomaly_flags =
        inherited_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;

    if (cprisk_is_being_traced_sysctl_only() != 0 || cprisk_mach_trace_suspicious() != 0) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED;
        cprisk_integrity_poison_watchdog_lane_now();
    }

    const int software_bp = cprisk_scan_software_breakpoints_randomized_text(
        CPRISK_WATCHDOG_RANDOM_TEXT_WINDOWS / 2u,
        CPRISK_WATCHDOG_RANDOM_TEXT_WINDOW_BYTES / 2u
    );
    const int single_step = cprisk_detect_single_stepping();
    const uint32_t timing_anomaly_flags = cprisk_get_last_timing_anomaly_flags();
    const uint64_t timing_median_ns = cprisk_get_last_timing_probe_median_ns();
    const uint64_t timing_max_ns = cprisk_get_last_timing_probe_max_ns();
    const uint64_t timing_threshold_ns = cprisk_get_last_timing_probe_threshold_ns();
    int shadow_mismatch = 0;

    if (software_bp >= CPRISK_WATCHDOG_SOFTWARE_BP_STRONG_THRESHOLD) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP;
    }
    if (cprisk_scan_instant_return_key_symbols_prefix() != 0) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH;
    }
    if (single_step != 0) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SINGLE_STEP;
    }
    if (timing_anomaly_flags != 0u) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL;
    }
    if (!cprisk_shadow_check_i(shadow_token)) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK;
        shadow_mismatch = 1;
        atomic_store(&s_watchdog_shadow_stack_latch, 1u);
    }

    if (anomaly_flags != CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE) {
        if ((anomaly_flags & CPRISK_WD_HIGH_RISK_POISON_MASK) != 0u) {
            cprisk_integrity_poison_watchdog_lane_now();
        } else {
            cprisk_integrity_poison_watchdog_lane();
        }
    }

    pthread_mutex_lock(&s_watchdog_mutex);
    if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP) != 0u) {
        s_watchdog_snapshot.last_software_bp_detected = 1u;
        s_watchdog_snapshot.software_bp_anomaly_count += 1u;
    }
    if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SINGLE_STEP) != 0u) {
        s_watchdog_snapshot.last_single_step_detected = 1u;
    }
    s_watchdog_snapshot.last_timing_anomaly_flags = timing_anomaly_flags;
    s_watchdog_snapshot.last_timing_probe_median_ns = timing_median_ns;
    s_watchdog_snapshot.last_timing_probe_max_ns = timing_max_ns;
    s_watchdog_snapshot.last_timing_probe_threshold_ns = timing_threshold_ns;
    if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL) != 0u) {
        s_watchdog_snapshot.timing_anomaly_count += 1u;
    }
    if (shadow_mismatch != 0) {
        s_watchdog_snapshot.last_shadow_stack_mismatch = 1u;
        s_watchdog_snapshot.shadow_stack_anomaly_count += 1u;
    }
    if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL) != 0u) {
        s_watchdog_snapshot.last_peer_watchdog_stalled = 1u;
        s_watchdog_snapshot.peer_watchdog_anomaly_count += 1u;
    }
    s_watchdog_snapshot.anomaly_flags |= anomaly_flags;
    pthread_mutex_unlock(&s_watchdog_mutex);

    return anomaly_flags;
}

static uint32_t cprisk_watchdog_run_iteration_i(int run_mid_checks, int run_low_checks) {
    const cprisk_shadow_token_t shadow_token = cprisk_shadow_push_i();
    int deny_errno = 0;
    int deny_result = 0;
    int deny_verify_suspicious = 0;
    uint32_t deny_verify_bits = 0u;
    uint32_t csops_flags_snapshot = 0u;
    uint32_t amfi_probe_bits = 0u;
    uint32_t get_task_allow_suspect = 0u;
    int traced = 0;
    int traced_sys = 0;
    int traced_mach = 0;
    int trace_crosscheck = 0;
    cprisk_exception_handler_snapshot_t exception_snapshot;
    memset(&exception_snapshot, 0, sizeof(exception_snapshot));
    uint32_t anomaly_flags = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE;
    int signal_probe = 0;
    int software_bp = 0;
    int software_bp_strong = 0;
    int instant_ret_patch = 0;
    int hw_bp = 0;
    int csops_dbg = 0;
    int suspicious_threads = 0;
    int single_step = 0;
    int dbi_markers = 0;
    int tty = 0;
    int dev_disk = 0;
    uint32_t dbi_marker_flags = 0u;
    uint32_t timing_anomaly_flags = 0u;
    uint64_t timing_median_ns = 0u;
    uint64_t timing_max_ns = 0u;
    uint64_t timing_threshold_ns = 0u;
    int exception_delivery_timeout = 0;
    int exception_delivery_probe_handled = 0;
    uint64_t exception_delivery_probe_ns = 0u;
    uint64_t poison_mix = cprisk_monotonic_time_ns();
    cprisk_text_encrypt_service_idle();
    int peer_stall = 0;
    int shadow_mismatch = 0;
    int thread_exception_ports = 0;
    const int mid_checks = run_mid_checks != 0;
    const int low_checks = run_low_checks != 0;
    const int dbi_checks = mid_checks || low_checks;
    const uint32_t seed = 0x6D8E41B7u;
    const uint32_t runtime_hint =
        (uint32_t)atomic_load(&s_watchdog_stop_requested) ^
        (uint32_t)poison_mix ^
        0x13579BDFu;
    uint32_t prologue_anom = 0u;
    uint32_t prologue_mask = 0u;
    cprisk_watchdog_verify_prologue_i(&prologue_anom, &prologue_mask);
    uint32_t dlsym_fail_mask = 0u;
    if (cprisk_watchdog_verify_dlsym_prologue_i(&dlsym_fail_mask) == 0) {
        prologue_anom |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        prologue_mask |= dlsym_fail_mask;
    }
    uint32_t objc_dyld_hook_mask = 0u;
    if (cprisk_watchdog_verify_objc_msgsend_prologue_i(&objc_dyld_hook_mask) == 0) {
        prologue_anom |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
    }
    if (cprisk_watchdog_verify_dyld_image_count_prologue_i(&objc_dyld_hook_mask) == 0) {
        prologue_anom |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
    }
    if (objc_dyld_hook_mask != 0u) {
        prologue_mask |= objc_dyld_hook_mask;
    }
    uint32_t svc_stub_anom = 0u;
    if (cprisk_verify_svc_stub_integrity() != 0u) {
        svc_stub_anom = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY;
        cprisk_integrity_poison_watchdog_lane_now();
    }
    uint32_t vm_image_whitelist_anom = 0u;
    const uint32_t vm_guard_tick = cprisk_memory_guard_image_vm_tick();
    if ((vm_guard_tick & (CPRISK_MEM_GUARD_TICK_IMAGE_LIST_CHANGED |
                          CPRISK_MEM_GUARD_TICK_UNKNOWN_EXECUTABLE_RX |
                          CPRISK_MEM_GUARD_TICK_EXECUTABLE_WRITE)) != 0u) {
        vm_image_whitelist_anom = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_IMAGE_WHITELIST;
        cprisk_integrity_poison_watchdog_lane_now();
    }
    if (vm_image_whitelist_anom == 0u && low_checks) {
        const int layout_drift = cprisk_vm_dyld_image_layout_digest_differs_from_baseline();
        if (layout_drift == 1) {
            vm_image_whitelist_anom = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_IMAGE_WHITELIST;
            cprisk_integrity_poison_watchdog_lane_now();
        }
    }
    const uint32_t vm_cc_total = cprisk_get_vm_mprotect_crosscheck_mismatch_count();
    const uint32_t vm_mt_total = cprisk_get_vm_mprotect_mach_trap_mismatch_count();
    uint32_t vm_mprotect_anom = 0u;
    if (vm_cc_total > 0u || vm_mt_total > 0u) {
        vm_mprotect_anom = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE;
        cprisk_integrity_poison_watchdog_lane_now();
    }
    const uint32_t dyld_flags_now = (uint32_t)atomic_load(&s_watchdog_dyld_flags);
    cprisk_cff_config_t cff_config;

    memset(&cff_config, 0, sizeof(cff_config));
    cff_config.seed = seed;
    cff_config.runtime_salt = cprisk_cff_runtime_salt(seed, runtime_hint);
    cff_config.entry_state = 0x11u;
    cff_config.iteration_budget = 24u;
    cff_config.release_build = (uint8_t)CPRISK_CFF_RELEASE_BUILD;
    cff_config.enable_fake_states = (uint8_t)CPRISK_CFF_ENABLE_FAKE_STATE;
    /*
     * Prefer the non-linear Feistel+S-box codec on the watchdog hot path so
     * state I/O is no longer dominated by linear XOR-MBA identities that
     * GAMBA-style algebraic simplifiers are designed to collapse. Keep
     * mba_layers pinned high to retain the dual-dispatch decode path instead
     * of the mba_layers <= 1 shortcut.
     */
    cff_config.codec_style = (uint8_t)CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN;
    /* Prefer real per-codec handler table dispatch (not only direct decode). */
    cff_config.dispatch_style = (uint8_t)CPRISK_CFF_DISPATCH_FN_TABLE;
    cff_config.mba_layers = 5u;
    cff_config.symex_guard_budget = CPRISK_CFF_RELEASE_BUILD ? 3u : 0u;
    cff_config.default_action = CPRISK_CFF_RELEASE_BUILD
        ? CPRISK_CFF_DEFAULT_POISON
        : CPRISK_CFF_DEFAULT_FAIL_CLOSED;

    CPR_CFF_BEGIN_EX(cff_config)
        CPR_CFF_CASE(0x11u): {
            deny_result = cprisk_deny_attach_status(&deny_errno);
            traced_sys = cprisk_is_being_traced_sysctl_only();
            traced_mach = cprisk_mach_trace_suspicious();
            traced = cprisk_is_being_traced_redundant();
            trace_crosscheck = cprisk_trace_crosscheck_inconsistent();
            cprisk_amfi_entitlement_watchdog_probe(
                &csops_flags_snapshot,
                &get_task_allow_suspect,
                &amfi_probe_bits
            );
            deny_verify_suspicious = cprisk_deny_attach_effective_verify(
                deny_result,
                deny_errno,
                &deny_verify_bits
            );
            if (deny_result != 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH;
            }
            if (deny_verify_suspicious != 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY;
                cprisk_integrity_poison_watchdog_lane_now();
            }
            anomaly_flags |= cprisk_wd_amfi_flags_from_probe_bits_i(amfi_probe_bits);
            if (get_task_allow_suspect != 0u) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW;
            }
            if ((anomaly_flags & (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW)) != 0u) {
                cprisk_integrity_poison_watchdog_lane_now();
            }
            if (traced != 0 || traced_sys != 0 || traced_mach != 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED;
            }
            if ((traced_sys != 0 || traced_mach != 0) && traced == 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE;
                cprisk_integrity_poison_watchdog_lane_now();
            }
            if (trace_crosscheck != 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACE_CROSSCHECK;
            }

            if (cprisk_cff_should_visit_fake_state(cpr_cff_ctx, cpr_cff_state_) &&
                cpr_cff_ctx->fake_state_budget != 0u) {
                cpr_cff_ctx->fake_state_budget -= 1u;
                CPR_CFF_GOTO(0x18u);
            }
            CPR_CFF_GOTO(0x12u);
        }

        CPR_CFF_CASE(0x12u): {
            cprisk_verify_exception_handler();
            memset(&exception_snapshot, 0, sizeof(exception_snapshot));
            (void)cprisk_get_exception_handler_snapshot(&exception_snapshot);

            if (exception_snapshot.supported != 0u) {
                if (exception_snapshot.last_query_succeeded == 0u) {
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_QUERY;
                }
                if (exception_snapshot.last_hijack_detected != 0u ||
                    exception_snapshot.last_reclaim_attempted != 0u ||
                    exception_snapshot.port_matches == 0u) {
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT;
                }
            }
            thread_exception_ports = cprisk_detect_thread_exception_ports();
            if (thread_exception_ports > 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT;
            }
            CPR_CFF_GOTO(0x13u);
        }

        CPR_CFF_CASE(0x13u): {
            signal_probe = cprisk_probe_debugger_via_signal();
            if (mid_checks) {
                software_bp = cprisk_watchdog_scan_software_breakpoints_i();
                software_bp_strong = software_bp >= CPRISK_WATCHDOG_SOFTWARE_BP_STRONG_THRESHOLD;
                instant_ret_patch = cprisk_scan_instant_return_key_symbols_prefix();
                hw_bp = cprisk_detect_hardware_breakpoints();
                csops_dbg = cprisk_wd_csops_debug_probe_inline_i();
                suspicious_threads = cprisk_detect_suspicious_threads();
                single_step = cprisk_detect_single_stepping();
                timing_anomaly_flags = cprisk_get_last_timing_anomaly_flags();
                timing_median_ns = cprisk_get_last_timing_probe_median_ns();
                timing_max_ns = cprisk_get_last_timing_probe_max_ns();
                timing_threshold_ns = cprisk_get_last_timing_probe_threshold_ns();
            }
            if (low_checks) {
                tty = cprisk_detect_tty_debug();
                dev_disk = cprisk_detect_developer_disk();
                exception_delivery_timeout = cprisk_probe_exception_delivery_timeout();
                exception_delivery_probe_handled =
                    cprisk_get_last_exception_delivery_probe_handled();
                exception_delivery_probe_ns =
                    cprisk_get_last_exception_delivery_probe_ns();
            }
            if (dbi_checks) {
                dbi_markers = cprisk_detect_dbi_markers();
                dbi_marker_flags = cprisk_get_last_dbi_marker_flags();
            }
            CPR_CFF_GOTO(0x14u);
        }

        CPR_CFF_CASE(0x14u): {
            if (signal_probe != 0)
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SIGNAL_PROBE;
            if (mid_checks) {
                if (software_bp_strong != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP;
                if (instant_ret_patch != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH;
                if (hw_bp != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_HARDWARE_BP;
                if (csops_dbg != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_CSOPS_DEBUGGED;
                if (suspicious_threads > 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SUSPICIOUS_THREAD;
                if (single_step != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SINGLE_STEP;
                if (timing_anomaly_flags != 0u)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL;
            }
            if (low_checks) {
                if (tty != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TTY;
                if (dev_disk != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DEVELOPER_DISK;
                if (exception_delivery_timeout != 0)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT;
            }
            if (dbi_checks) {
                if (dbi_markers > 0 && dbi_marker_flags != 0u)
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_MARKER;
                if ((dbi_marker_flags & CPRISK_DBI_MARKER_STALKER_CORREL) != 0u ||
                    (dbi_marker_flags & CPRISK_DBI_MARKER_ANON_EXEC_SLAB) != 0u) {
                    anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL;
                }
            }

            anomaly_flags |=
                prologue_anom | svc_stub_anom | vm_mprotect_anom | vm_image_whitelist_anom;
            if (dyld_flags_now != 0u) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION;
            }

            if (!cprisk_shadow_check_i(shadow_token)) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK;
                shadow_mismatch = 1;
                atomic_store(&s_watchdog_shadow_stack_latch, 1u);
            }
            if (atomic_exchange(&s_watchdog_peer_stall_latch, 0u) != 0u) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;
                peer_stall = 1;
            }
            if (atomic_exchange(&s_watchdog_shadow_stack_latch, 0u) != 0u) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK;
                shadow_mismatch = 1;
            }

            if (cprisk_cff_should_visit_fake_state(cpr_cff_ctx, cpr_cff_state_) &&
                cpr_cff_ctx->fake_state_budget != 0u) {
                cpr_cff_ctx->fake_state_budget -= 1u;
                CPR_CFF_GOTO(0x18u);
            }
            CPR_CFF_GOTO(0x15u);
        }

        CPR_CFF_CASE(0x15u): {
            const uint32_t high_risk_flags =
                (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_IMAGE_WHITELIST);
            if ((anomaly_flags & high_risk_flags) != 0u) {
                cprisk_cff_trigger_symbolic_explosion(cpr_cff_ctx, anomaly_flags & high_risk_flags);
            }
            if ((anomaly_flags & (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SIGNAL_PROBE |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_HARDWARE_BP |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_CSOPS_DEBUGGED |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_MARKER |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY |
                 CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_IMAGE_WHITELIST)) != 0u) {
                if ((anomaly_flags & CPRISK_WD_HIGH_RISK_POISON_MASK) != 0u) {
                    cprisk_integrity_poison_watchdog_lane_now();
                } else if ((anomaly_flags & CPRISK_WD_POISON_TRIGGER_BUNDLE_MASK) != 0u) {
                    cprisk_integrity_poison_watchdog_lane();
                }
            }
            CPR_CFF_GOTO(0x16u);
        }

        CPR_CFF_CASE(0x16u): {
            pthread_mutex_lock(&s_watchdog_mutex);
            s_watchdog_snapshot.iteration_count += 1u;
            s_watchdog_snapshot.last_check_monotonic_ns = cprisk_monotonic_time_ns();
            s_watchdog_snapshot.last_deny_attach_result = deny_result;
            s_watchdog_snapshot.last_deny_attach_errno = deny_errno;
            s_watchdog_snapshot.last_traced = traced != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_exception_port_healthy =
                (exception_snapshot.port_matches != 0u && thread_exception_ports == 0)
                    ? 1u : 0u;
            s_watchdog_snapshot.last_exception_query_succeeded = exception_snapshot.last_query_succeeded;
            s_watchdog_snapshot.last_exception_reclaim_attempted = exception_snapshot.last_reclaim_attempted;
            s_watchdog_snapshot.last_exception_hijack_detected = exception_snapshot.last_hijack_detected;
            s_watchdog_snapshot.last_exception_query_kern_return = exception_snapshot.last_query_kern_return;
            s_watchdog_snapshot.last_exception_register_kern_return = exception_snapshot.last_register_kern_return;
            s_watchdog_snapshot.anomaly_flags = anomaly_flags;
            s_watchdog_snapshot.vm_mprotect_crosscheck_mismatch_total = (uint64_t)vm_cc_total;
            s_watchdog_snapshot.vm_mprotect_mach_trap_mismatch_total = (uint64_t)vm_mt_total;
            if (deny_result != 0) {
                s_watchdog_snapshot.deny_attach_error_count += 1u;
            }
            if (traced != 0 || traced_sys != 0 || traced_mach != 0) {
                s_watchdog_snapshot.traced_event_count += 1u;
            }
            if ((anomaly_flags & (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_QUERY |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACE_CROSSCHECK |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE)) != 0u) {
                s_watchdog_snapshot.exception_anomaly_count += 1u;
            }
            s_watchdog_snapshot.last_signal_probe_result = signal_probe != 0 ? 1u : 0u;
            if (mid_checks) {
                s_watchdog_snapshot.last_hardware_bp_detected = hw_bp != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_software_bp_detected = software_bp_strong != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_csops_debugged = csops_dbg != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_suspicious_thread_count =
                    (uint32_t)(suspicious_threads > 0 ? suspicious_threads : 0);
                s_watchdog_snapshot.last_single_step_detected = single_step != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_timing_anomaly_flags = timing_anomaly_flags;
                s_watchdog_snapshot.last_timing_probe_median_ns = timing_median_ns;
                s_watchdog_snapshot.last_timing_probe_max_ns = timing_max_ns;
                s_watchdog_snapshot.last_timing_probe_threshold_ns = timing_threshold_ns;
            }
            if (low_checks) {
                s_watchdog_snapshot.last_tty_detected = tty != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_developer_disk_detected = dev_disk != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_exception_delivery_timeout_detected =
                    exception_delivery_timeout != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_exception_delivery_probe_handled =
                    exception_delivery_probe_handled != 0 ? 1u : 0u;
                s_watchdog_snapshot.last_exception_delivery_probe_ns =
                    exception_delivery_probe_ns;
            }
            if (dbi_checks) {
                s_watchdog_snapshot.last_dbi_detected = dbi_markers > 0 ? 1u : 0u;
                s_watchdog_snapshot.last_dbi_marker_flags = dbi_marker_flags;
            }
            s_watchdog_snapshot.last_peer_watchdog_stalled = peer_stall != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_shadow_stack_mismatch = shadow_mismatch != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_prologue_fail_mask = prologue_mask;
            s_watchdog_snapshot.last_dyld_injection_flags = dyld_flags_now;
            s_watchdog_snapshot.last_csops_status_flags = csops_flags_snapshot;
            s_watchdog_snapshot.last_amfi_probe_bits = amfi_probe_bits;
            s_watchdog_snapshot.last_get_task_allow_suspect = get_task_allow_suspect;
            s_watchdog_snapshot.last_deny_attach_verify_bits = deny_verify_bits;
            if (deny_verify_suspicious != 0) {
                s_watchdog_snapshot.deny_attach_verify_anomaly_count += 1u;
            }
            if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS) != 0u) {
                s_watchdog_snapshot.amfi_cs_flags_anomaly_count += 1u;
            }
            if ((anomaly_flags & CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW) != 0u) {
                s_watchdog_snapshot.get_task_allow_anomaly_count += 1u;
            }
            s_watchdog_snapshot.dyld_injection_anomaly_count =
                (uint64_t)atomic_load(&s_watchdog_dyld_suspicious_events);
            if (prologue_mask != 0u) {
                s_watchdog_snapshot.prologue_integrity_anomaly_count += 1u;
            }
            if (signal_probe != 0)
                s_watchdog_snapshot.signal_probe_anomaly_count += 1u;
            if (mid_checks) {
                if (hw_bp != 0)
                    s_watchdog_snapshot.hardware_bp_anomaly_count += 1u;
                if (software_bp_strong != 0)
                    s_watchdog_snapshot.software_bp_anomaly_count += 1u;
                if (csops_dbg != 0)
                    s_watchdog_snapshot.csops_anomaly_count += 1u;
                if (suspicious_threads > 0)
                    s_watchdog_snapshot.suspicious_thread_anomaly_count += 1u;
                if (timing_anomaly_flags != 0u)
                    s_watchdog_snapshot.timing_anomaly_count += 1u;
            }
            if (low_checks) {
                if (exception_delivery_timeout != 0)
                    s_watchdog_snapshot.exception_delivery_timeout_anomaly_count += 1u;
            }
            if (dbi_checks) {
                if (dbi_markers > 0 && dbi_marker_flags != 0u)
                    s_watchdog_snapshot.dbi_anomaly_count += 1u;
            }
            if (shadow_mismatch != 0)
                s_watchdog_snapshot.shadow_stack_anomaly_count += 1u;
            pthread_mutex_unlock(&s_watchdog_mutex);
            CPR_CFF_RETURN(anomaly_flags);
        }

        CPR_CFF_CASE(0x18u): {
            poison_mix ^= ((uint64_t)anomaly_flags << 17u) ^
                          ((uint64_t)(signal_probe != 0) << 9u) ^
                          0x9E3779B97F4A7C15ULL;
            CPR_CFF_GOTO(0x12u);
        }
    CPR_CFF_END();
    return anomaly_flags;
}

static void *cprisk_watchdog_thread_main_impl(void *arg) {
    const uint32_t worker_id = (uint32_t)(uintptr_t)arg;
    atomic_store(&s_watchdog_worker_active[worker_id], 1u);
    atomic_store(&s_watchdog_heartbeat_ns[worker_id], cprisk_monotonic_time_ns());
    cprisk_watchdog_publish_deadline_i(worker_id, CPRISK_WATCHDOG_DEFAULT_INTERVAL_MS);

    pthread_mutex_lock(&s_watchdog_mutex);
    cprisk_watchdog_refresh_thread_active_locked();
    pthread_mutex_unlock(&s_watchdog_mutex);

    uint32_t last_anomaly_flags = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE;
    uint32_t loop_counter = 0u;

    for (;;) {
        if (cprisk_watchdog_should_stop()) {
            break;
        }

        const uint64_t now_ns = cprisk_monotonic_time_ns();
        atomic_store(&s_watchdog_heartbeat_ns[worker_id], now_ns);
        cprisk_watchdog_mailbox_send_i(worker_id);
        cprisk_watchdog_mailbox_drain_i(worker_id, now_ns);
        if (cprisk_watchdog_mach_peer_verify_i(worker_id) != 0) {
            cprisk_watchdog_mark_peer_stall_i();
            last_anomaly_flags |=
                CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;
        }
        if (cprisk_watchdog_peer_stalled_i(worker_id,
                                           CPRISK_WATCHDOG_DEFAULT_INTERVAL_MS) != 0) {
            cprisk_watchdog_mark_peer_stall_i();
            last_anomaly_flags |=
                CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;
        }

        loop_counter += 1u;
        const int run_mid_checks =
            ((loop_counter % CPRISK_WATCHDOG_MID_CADENCE) == 0u) ||
            (last_anomaly_flags != CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE);
        const int run_low_checks =
            ((loop_counter % CPRISK_WATCHDOG_LOW_CADENCE) == 0u) ||
            ((last_anomaly_flags & (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED |
                                    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT |
                                    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACE_CROSSCHECK)) != 0u);

        if (worker_id == CPRISK_WATCHDOG_PRIMARY_ID) {
            last_anomaly_flags = cprisk_watchdog_run_iteration_i(
                run_mid_checks,
                run_low_checks
            );
        } else {
            /* Pass12 __TEXT: same idle sweep as primary so plaintext pages are not
             * serviced only on the primary thread's jittered interval (~0.35–1.1s). */
            cprisk_text_encrypt_service_idle();
            if (run_mid_checks) {
                last_anomaly_flags = cprisk_watchdog_run_secondary_iteration_i(
                    last_anomaly_flags &
                    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL
                );
            } else {
                last_anomaly_flags &= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL;
            }
        }

        if (cprisk_watchdog_should_stop()) {
            break;
        }

        const uint32_t interval_ms =
            cprisk_watchdog_pick_interval_ms_i(last_anomaly_flags);
        cprisk_watchdog_publish_deadline_i(worker_id, interval_ms);
        if (worker_id == CPRISK_WATCHDOG_PRIMARY_ID) {
            pthread_mutex_lock(&s_watchdog_mutex);
            s_watchdog_snapshot.interval_seconds = (interval_ms + 999u) / 1000u;
            pthread_mutex_unlock(&s_watchdog_mutex);
        }
        cprisk_watchdog_sleep_interval_ms_i(interval_ms);
    }

    atomic_store(&s_watchdog_worker_active[worker_id], 0u);
    atomic_store(&s_watchdog_heartbeat_ns[worker_id], 0u);
    atomic_store(&s_watchdog_deadline_ns[worker_id], 0u);
    pthread_mutex_lock(&s_watchdog_mutex);
    cprisk_watchdog_refresh_thread_active_locked();
    pthread_mutex_unlock(&s_watchdog_mutex);
    return NULL;
}

int cprisk_start_anti_debug_watchdog(void) {
    pthread_mutex_lock(&s_watchdog_mutex);
    if (s_watchdog_state != CPRISK_WATCHDOG_STATE_STOPPED) {
        pthread_mutex_unlock(&s_watchdog_mutex);
        return 0;
    }

    cprisk_watchdog_reset_locked();
    s_watchdog_snapshot.running = 1u;
    s_watchdog_state = CPRISK_WATCHDOG_STATE_RUNNING;
    s_watchdog_started_mask = 0u;
    atomic_store(&s_watchdog_stop_requested, 0);
    atomic_store(&s_watchdog_peer_stall_latch, 0u);
    atomic_store(&s_watchdog_shadow_stack_latch, 0u);
    cprisk_watchdog_register_dyld_observer_once_i();
    for (uint32_t i = 0; i < CPRISK_WATCHDOG_THREAD_COUNT; i++) {
        atomic_store(&s_watchdog_worker_active[i], 0u);
        atomic_store(&s_watchdog_heartbeat_ns[i], 0u);
        atomic_store(&s_watchdog_deadline_ns[i], 0u);
    }
    (void)cprisk_watchdog_init_mailboxes_locked();

    uint32_t libsys_mask = 0u;
    if (cprisk_watchdog_verify_pthread_create_prologue_i(&libsys_mask) == 0) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        s_watchdog_snapshot.last_prologue_fail_mask = libsys_mask;
        s_watchdog_snapshot.prologue_integrity_anomaly_count += 1u;
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = EACCES;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return -1;
    }
    if (cprisk_watchdog_verify_dlsym_prologue_i(&libsys_mask) == 0) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        s_watchdog_snapshot.last_prologue_fail_mask = libsys_mask;
        s_watchdog_snapshot.prologue_integrity_anomaly_count += 1u;
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = EACCES;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return -1;
    }
    if (cprisk_watchdog_verify_objc_msgsend_prologue_i(&libsys_mask) == 0) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        s_watchdog_snapshot.last_prologue_fail_mask = libsys_mask;
        s_watchdog_snapshot.prologue_integrity_anomaly_count += 1u;
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = EACCES;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return -1;
    }
    if (cprisk_watchdog_verify_dyld_image_count_prologue_i(&libsys_mask) == 0) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE;
        s_watchdog_snapshot.last_prologue_fail_mask = libsys_mask;
        s_watchdog_snapshot.prologue_integrity_anomaly_count += 1u;
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = EACCES;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return -1;
    }

    {
        void *thunk_expect = cprisk_pac_sign_function_pointer(
            (const void *)&cprisk_watchdog_pthread_thunk,
            (uintptr_t)CPRISK_WATCHDOG_PTHREAD_THUNK_PAC_DISC);
        void *bridge_expect = cprisk_pac_sign_function_pointer(
            (const void *)&cprisk_watchdog_thread_main_bridge,
            (uintptr_t)CPRISK_WATCHDOG_PTHREAD_BRIDGE_PAC_DISC);
        if (s_watchdog_thunk_signed_fp != thunk_expect || s_watchdog_bridge_signed_fp != bridge_expect) {
            s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
            s_watchdog_snapshot.running = 0u;
            s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY;
            s_watchdog_snapshot.last_deny_attach_result = -1;
            s_watchdog_snapshot.last_deny_attach_errno = EACCES;
            pthread_mutex_unlock(&s_watchdog_mutex);
            return -1;
        }
    }

    void *(*wd_pthread_start)(void *) = (void *(*)(void *))s_watchdog_thunk_signed_fp;
    const int rc_primary = pthread_create(&s_watchdog_threads[CPRISK_WATCHDOG_PRIMARY_ID],
                                          NULL,
                                          wd_pthread_start,
                                          (void *)(uintptr_t)CPRISK_WATCHDOG_PRIMARY_ID);
    if (rc_primary != 0) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = rc_primary;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return -1;
    }
    s_watchdog_started_mask |= (1u << CPRISK_WATCHDOG_PRIMARY_ID);

    const int rc_secondary = pthread_create(&s_watchdog_threads[CPRISK_WATCHDOG_SECONDARY_ID],
                                            NULL,
                                            wd_pthread_start,
                                            (void *)(uintptr_t)CPRISK_WATCHDOG_SECONDARY_ID);
    if (rc_secondary == 0) {
        s_watchdog_started_mask |= (1u << CPRISK_WATCHDOG_SECONDARY_ID);
    } else {
        /* Keep running with primary watchdog as compatibility fallback. */
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = rc_secondary;
    }

    cprisk_vm_dyld_image_layout_digest_baseline_snapshot();

    pthread_mutex_unlock(&s_watchdog_mutex);
    (void)cprisk_start_anti_dump_probe(5);
    return 0;
}

void cprisk_stop_anti_debug_watchdog(void) {
    pthread_t threads_to_join[CPRISK_WATCHDOG_THREAD_COUNT];
    uint32_t join_count = 0u;

    pthread_mutex_lock(&s_watchdog_mutex);
    if (s_watchdog_state == CPRISK_WATCHDOG_STATE_RUNNING) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPING;
        s_watchdog_snapshot.stop_requested = 1u;
        atomic_store(&s_watchdog_stop_requested, 1);
        for (uint32_t i = 0; i < CPRISK_WATCHDOG_THREAD_COUNT; i++) {
            if ((s_watchdog_started_mask & (1u << i)) != 0u) {
                threads_to_join[join_count++] = s_watchdog_threads[i];
            }
        }
    }
    pthread_mutex_unlock(&s_watchdog_mutex);

    for (uint32_t i = 0; i < join_count; i++) {
        pthread_join(threads_to_join[i], NULL);
    }

    pthread_mutex_lock(&s_watchdog_mutex);
    if (s_watchdog_state == CPRISK_WATCHDOG_STATE_STOPPING) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.thread_active = 0u;
        s_watchdog_snapshot.stop_requested = 0u;
        s_watchdog_started_mask = 0u;
        atomic_store(&s_watchdog_stop_requested, 0);
        for (uint32_t i = 0; i < CPRISK_WATCHDOG_THREAD_COUNT; i++) {
            atomic_store(&s_watchdog_worker_active[i], 0u);
            atomic_store(&s_watchdog_heartbeat_ns[i], 0u);
            atomic_store(&s_watchdog_deadline_ns[i], 0u);
        }
        cprisk_watchdog_reset_mailboxes_locked();
    }
    pthread_mutex_unlock(&s_watchdog_mutex);

    cprisk_stop_anti_dump_probe();
}

void cprisk_watchdog_note_guard_page_fault(void) {
    pthread_mutex_lock(&s_watchdog_mutex);
    s_watchdog_snapshot.anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GUARD_PAGE;
    s_watchdog_snapshot.signal_probe_anomaly_count += 1u;
    pthread_mutex_unlock(&s_watchdog_mutex);
}

int cprisk_get_anti_debug_watchdog_snapshot(
    cprisk_anti_debug_watchdog_snapshot_t *out_snapshot
) {
    if (out_snapshot == NULL) {
        return -1;
    }

    pthread_mutex_lock(&s_watchdog_mutex);
    *out_snapshot = s_watchdog_snapshot;
    pthread_mutex_unlock(&s_watchdog_mutex);
    /* Live libc fallback counters (not only on watchdog iteration). */
    out_snapshot->libc_fallback_used_mask = cprisk_get_libc_fallback_used_mask();
    out_snapshot->libc_fallback_event_total = cprisk_get_libc_fallback_event_total();
    return 0;
}

#else

int cprisk_verify_dlsym_prologue(void) {
    return 1;
}

int cprisk_verify_runtime_hook_surface_prologues(void) {
    return 1;
}

int cprisk_start_anti_debug_watchdog(void) {
    (void)cprisk_start_anti_dump_probe(5);
    return 0;
}

void cprisk_stop_anti_debug_watchdog(void) {
    cprisk_stop_anti_dump_probe();
    (void)0;
}

void cprisk_watchdog_note_guard_page_fault(void) {}

int cprisk_get_anti_debug_watchdog_snapshot(
    cprisk_anti_debug_watchdog_snapshot_t *out_snapshot
) {
    if (out_snapshot == NULL) {
        return -1;
    }

    memset(out_snapshot, 0, sizeof(*out_snapshot));
    /* Keep libc fallback observability consistent with the full watchdog path. */
    out_snapshot->libc_fallback_used_mask = cprisk_get_libc_fallback_used_mask();
    out_snapshot->libc_fallback_event_total = cprisk_get_libc_fallback_event_total();
    return 0;
}

#endif
