#include "include/CRiskCore.h"

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

enum {
    CPRISK_WATCHDOG_STATE_STOPPED = 0,
    CPRISK_WATCHDOG_STATE_RUNNING = 1,
    CPRISK_WATCHDOG_STATE_STOPPING = 2,
};

static pthread_mutex_t s_watchdog_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t s_watchdog_thread;
static int s_watchdog_state = CPRISK_WATCHDOG_STATE_STOPPED;
static atomic_int s_watchdog_stop_requested = 0;
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
    const int deny_result = cprisk_deny_attach_status(&deny_errno);
    const int traced = cprisk_is_being_traced();

    cprisk_verify_exception_handler();

    cprisk_exception_handler_snapshot_t exception_snapshot;
    memset(&exception_snapshot, 0, sizeof(exception_snapshot));
    (void)cprisk_get_exception_handler_snapshot(&exception_snapshot);

    uint32_t anomaly_flags = CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE;
    if (deny_result != 0) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH;
    }
    if (traced != 0) {
        anomaly_flags |= CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED;
    }
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
                          CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_QUERY)) != 0u) {
        s_watchdog_snapshot.exception_anomaly_count += 1u;
    }
    pthread_mutex_unlock(&s_watchdog_mutex);
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
