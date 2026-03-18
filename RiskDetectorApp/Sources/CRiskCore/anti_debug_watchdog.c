#include "include/CRiskCore.h"
#include "cprisk_cff.h"

#include <TargetConditionals.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR) && \
    (!defined(TARGET_OS_TV) || !TARGET_OS_TV) && \
    (!defined(TARGET_OS_WATCH) || !TARGET_OS_WATCH)

#define CPRISK_WATCHDOG_INTERVAL_SECONDS 3u
#define CPRISK_WATCHDOG_SLEEP_SLICE_NS 200000000L
#define CPRISK_WATCHDOG_SOFTWARE_BP_SCAN_BYTES 256u

enum {
    CPRISK_WATCHDOG_STATE_STOPPED = 0,
    CPRISK_WATCHDOG_STATE_RUNNING = 1,
    CPRISK_WATCHDOG_STATE_STOPPING = 2,
};

static pthread_mutex_t s_watchdog_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t s_watchdog_thread;
static int s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
static atomic_int s_watchdog_stop_requested = 0;
extern uint64_t cprisk_get_last_exception_delivery_probe_ns(void);
extern int cprisk_get_last_exception_delivery_probe_handled(void);

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

    return detected;
}

static cprisk_anti_debug_watchdog_snapshot_t s_watchdog_snapshot = {
    .supported = 1u,
    .running = 0u,
    .thread_active = 0u,
    .stop_requested = 0u,
    .interval_seconds = CPRISK_WATCHDOG_INTERVAL_SECONDS,
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
};

static uint64_t cprisk_monotonic_time_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }

    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static void cprisk_watchdog_reset_locked(void) {
    s_watchdog_snapshot.running = 0u;
    s_watchdog_snapshot.thread_active = 0u;
    s_watchdog_snapshot.stop_requested = 0u;
    s_watchdog_snapshot.interval_seconds = CPRISK_WATCHDOG_INTERVAL_SECONDS;
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
}

static int cprisk_watchdog_should_stop(void) {
    return atomic_load(&s_watchdog_stop_requested) != 0;
}

static void cprisk_watchdog_sleep_interval(void) {
    struct timespec req;
    req.tv_sec = 0;
    req.tv_nsec = CPRISK_WATCHDOG_SLEEP_SLICE_NS;

    for (uint32_t elapsed_ms = 0u;
         elapsed_ms < (CPRISK_WATCHDOG_INTERVAL_SECONDS * 1000u);
         elapsed_ms += 200u) {
        if (cprisk_watchdog_should_stop()) {
            return;
        }
        nanosleep(&req, NULL);
    }
}

static void cprisk_watchdog_run_iteration(void) {
    int deny_errno = 0;
    int deny_result = 0;
    int traced = 0;
    cprisk_exception_handler_snapshot_t exception_snapshot;
    memset(&exception_snapshot, 0, sizeof(exception_snapshot));
    uint32_t anomaly_flags = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE;
    int signal_probe = 0;
    int software_bp = 0;
    int hw_bp = 0;
    int csops_dbg = 0;
    int suspicious_threads = 0;
    int single_step = 0;
    int tty = 0;
    int dev_disk = 0;
    int exception_delivery_timeout = 0;
    int exception_delivery_probe_handled = 0;
    uint64_t exception_delivery_probe_ns = 0u;
    uint64_t poison_mix = cprisk_monotonic_time_ns();
    const uint32_t seed = 0x6D8E41B7u;
    const uint32_t runtime_hint =
        (uint32_t)atomic_load(&s_watchdog_stop_requested) ^
        (uint32_t)poison_mix ^
        0x13579BDFu;
    cprisk_cff_config_t cff_config;

    memset(&cff_config, 0, sizeof(cff_config));
    cff_config.seed = seed;
    cff_config.runtime_salt = cprisk_cff_runtime_salt(seed, runtime_hint);
    cff_config.entry_state = 0x11u;
    cff_config.iteration_budget = 24u;
    cff_config.release_build = (uint8_t)CPRISK_CFF_RELEASE_BUILD;
    cff_config.enable_fake_states = (uint8_t)CPRISK_CFF_ENABLE_FAKE_STATE;
    cff_config.default_action = CPRISK_CFF_RELEASE_BUILD
        ? CPRISK_CFF_DEFAULT_POISON
        : CPRISK_CFF_DEFAULT_FAIL_CLOSED;

    CPR_CFF_BEGIN_EX(cff_config)
        CPR_CFF_CASE(0x11u): {
            deny_result = cprisk_deny_attach_status(&deny_errno);
            traced = cprisk_is_being_traced();
            if (deny_result != 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH;
            }
            if (traced != 0) {
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED;
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
            CPR_CFF_GOTO(0x13u);
        }

        CPR_CFF_CASE(0x13u): {
            signal_probe = cprisk_probe_debugger_via_signal();
            software_bp = cprisk_watchdog_scan_software_breakpoints_i();
            hw_bp = cprisk_detect_hardware_breakpoints();
            csops_dbg = cprisk_csops_debug_check();
            suspicious_threads = cprisk_detect_suspicious_threads();
            single_step = cprisk_detect_single_stepping();
            tty = cprisk_detect_tty_debug();
            dev_disk = cprisk_detect_developer_disk();
            exception_delivery_timeout = cprisk_probe_exception_delivery_timeout();
            exception_delivery_probe_handled =
                cprisk_get_last_exception_delivery_probe_handled();
            exception_delivery_probe_ns =
                cprisk_get_last_exception_delivery_probe_ns();
            CPR_CFF_GOTO(0x14u);
        }

        CPR_CFF_CASE(0x14u): {
            if (signal_probe != 0)
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SIGNAL_PROBE;
            if (software_bp != 0)
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP;
            if (hw_bp != 0)
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_HARDWARE_BP;
            if (csops_dbg != 0)
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_CSOPS_DEBUGGED;
            if (suspicious_threads > 0)
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SUSPICIOUS_THREAD;
            if (single_step != 0)
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SINGLE_STEP;
            if (tty != 0)
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TTY;
            if (dev_disk != 0)
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DEVELOPER_DISK;
            if (exception_delivery_timeout != 0)
                anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT;

            if (cprisk_cff_should_visit_fake_state(cpr_cff_ctx, cpr_cff_state_) &&
                cpr_cff_ctx->fake_state_budget != 0u) {
                cpr_cff_ctx->fake_state_budget -= 1u;
                CPR_CFF_GOTO(0x18u);
            }
            CPR_CFF_GOTO(0x15u);
        }

        CPR_CFF_CASE(0x15u): {
            if ((anomaly_flags & (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SIGNAL_PROBE |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_HARDWARE_BP |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_CSOPS_DEBUGGED |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT)) != 0u) {
                cprisk_force_integrity_poison();
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
            s_watchdog_snapshot.last_exception_port_healthy = exception_snapshot.port_matches;
            s_watchdog_snapshot.last_exception_query_succeeded = exception_snapshot.last_query_succeeded;
            s_watchdog_snapshot.last_exception_reclaim_attempted = exception_snapshot.last_reclaim_attempted;
            s_watchdog_snapshot.last_exception_hijack_detected = exception_snapshot.last_hijack_detected;
            s_watchdog_snapshot.last_exception_query_kern_return = exception_snapshot.last_query_kern_return;
            s_watchdog_snapshot.last_exception_register_kern_return = exception_snapshot.last_register_kern_return;
            s_watchdog_snapshot.anomaly_flags = anomaly_flags;
            if (deny_result != 0) {
                s_watchdog_snapshot.deny_attach_error_count += 1u;
            }
            if (traced != 0) {
                s_watchdog_snapshot.traced_event_count += 1u;
            }
            if ((anomaly_flags & (CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_QUERY |
                                  CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT)) != 0u) {
                s_watchdog_snapshot.exception_anomaly_count += 1u;
            }
            s_watchdog_snapshot.last_signal_probe_result = signal_probe != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_hardware_bp_detected = hw_bp != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_software_bp_detected = software_bp != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_csops_debugged = csops_dbg != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_suspicious_thread_count = (uint32_t)(suspicious_threads > 0 ? suspicious_threads : 0);
            s_watchdog_snapshot.last_single_step_detected = single_step != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_tty_detected = tty != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_developer_disk_detected = dev_disk != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_exception_delivery_timeout_detected =
                exception_delivery_timeout != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_exception_delivery_probe_handled =
                exception_delivery_probe_handled != 0 ? 1u : 0u;
            s_watchdog_snapshot.last_exception_delivery_probe_ns =
                exception_delivery_probe_ns;
            if (signal_probe != 0)
                s_watchdog_snapshot.signal_probe_anomaly_count += 1u;
            if (hw_bp != 0)
                s_watchdog_snapshot.hardware_bp_anomaly_count += 1u;
            if (software_bp != 0)
                s_watchdog_snapshot.software_bp_anomaly_count += 1u;
            if (csops_dbg != 0)
                s_watchdog_snapshot.csops_anomaly_count += 1u;
            if (suspicious_threads > 0)
                s_watchdog_snapshot.suspicious_thread_anomaly_count += 1u;
            if (exception_delivery_timeout != 0)
                s_watchdog_snapshot.exception_delivery_timeout_anomaly_count += 1u;
            pthread_mutex_unlock(&s_watchdog_mutex);
            CPR_CFF_RETURN_VOID();
        }

        CPR_CFF_CASE(0x18u): {
            /* Fake state: mix entropy then always resume at 0x12
             * (exception handler verification).  Must NOT jump to
             * 0x15 because that skips the detection probes at 0x13
             * and anomaly aggregation at 0x14, producing a false-
             * negative snapshot with all-zero detection results. */
            poison_mix ^= ((uint64_t)anomaly_flags << 17u) ^
                          ((uint64_t)(signal_probe != 0) << 9u) ^
                          0x9E3779B97F4A7C15ULL;
            CPR_CFF_GOTO(0x12u);
        }
    CPR_CFF_END();
}

static void *cprisk_watchdog_thread_main(void *arg) {
    (void)arg;

    pthread_mutex_lock(&s_watchdog_mutex);
    s_watchdog_snapshot.thread_active = 1u;
    pthread_mutex_unlock(&s_watchdog_mutex);

    for (;;) {
        if (cprisk_watchdog_should_stop()) {
            break;
        }

        cprisk_watchdog_run_iteration();

        if (cprisk_watchdog_should_stop()) {
            break;
        }

        cprisk_watchdog_sleep_interval();
    }

    pthread_mutex_lock(&s_watchdog_mutex);
    s_watchdog_snapshot.thread_active = 0u;
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
    atomic_store(&s_watchdog_stop_requested, 0);

    const int rc = pthread_create(&s_watchdog_thread, NULL, cprisk_watchdog_thread_main, NULL);
    if (rc != 0) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.last_deny_attach_result = -1;
        s_watchdog_snapshot.last_deny_attach_errno = rc;
        pthread_mutex_unlock(&s_watchdog_mutex);
        return -1;
    }

    pthread_mutex_unlock(&s_watchdog_mutex);
    return 0;
}

void cprisk_stop_anti_debug_watchdog(void) {
    pthread_t thread = (pthread_t)0;
    int should_join = 0;

    pthread_mutex_lock(&s_watchdog_mutex);
    if (s_watchdog_state == CPRISK_WATCHDOG_STATE_RUNNING) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPING;
        s_watchdog_snapshot.stop_requested = 1u;
        atomic_store(&s_watchdog_stop_requested, 1);
        thread = s_watchdog_thread;
        should_join = 1;
    }
    pthread_mutex_unlock(&s_watchdog_mutex);

    if (should_join) {
        pthread_join(thread, NULL);
    }

    pthread_mutex_lock(&s_watchdog_mutex);
    if (s_watchdog_state == CPRISK_WATCHDOG_STATE_STOPPING) {
        s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
        s_watchdog_snapshot.running = 0u;
        s_watchdog_snapshot.thread_active = 0u;
        s_watchdog_snapshot.stop_requested = 0u;
        atomic_store(&s_watchdog_stop_requested, 0);
    }
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
    return 0;
}

#else

int cprisk_start_anti_debug_watchdog(void) {
    return 0;
}

void cprisk_stop_anti_debug_watchdog(void) {
    (void)0;
}

int cprisk_get_anti_debug_watchdog_snapshot(
    cprisk_anti_debug_watchdog_snapshot_t *out_snapshot
) {
    if (out_snapshot == NULL) {
        return -1;
    }

    memset(out_snapshot, 0, sizeof(*out_snapshot));
    return 0;
}

#endif
