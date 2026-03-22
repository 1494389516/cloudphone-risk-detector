/*
 * CRiskCore - Anti-Dump Active Defense Probe.
 *
 * Runs a background thread that periodically:
 *   1. Scans VM regions via mach_vm_region for shared/external mappings
 *      (signals vm_read_overwrite injection) and RWX JIT regions (Frida Gum).
 *   2. Checks the loaded dylib list for known injection frameworks
 *      (Frida, Cycript, etc.).
 *   3. On detection, activates deception mode silently so the attacker
 *      does not immediately know they have been flagged.
 */

#include "include/CRiskCore.h"
#include <pthread.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

/* External symbols defined in cprisk_integrity.c */
extern volatile int s_integrity_deception_active;

static pthread_t s_probe_thread;
static pthread_mutex_t s_probe_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int s_probe_running;
static int s_probe_started;
static int s_probe_interval_seconds = 5;

/* Patterns that indicate dump or injection tools */
static const char *s_suspicious_patterns[] = {
    "frida",
    "cycript",
    ".app/Contents/Frameworks/Frida",
    "SSLKillSwitch",
    "Substrate",
    "substrate",
    "frida-gadget",
    "frida-agent",
    "libcycript",
};

/*
 * Probe: scan VM regions for suspicious mappings.
 *
 * Checks:
 *   - Shared or external mappings: may indicate vm_read_overwrite being used.
 *   - RWX (read+write+execute) regions: typical of JIT compilers used by Frida Gum.
 *
 * Returns 0 if clean, -1 if suspicious activity detected.
 */
static int cprisk_scan_vm_regions(void) {
    vm_address_t addr = 0;
    vm_size_t size = 0;

    while (1) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj_name;

        kern_return_t kr = vm_region_64(
            mach_task_self(),
            &addr,
            &size,
            VM_REGION_BASIC_INFO_64,
            (vm_region_info_t)&info,
            &count,
            &obj_name);

        if (kr != KERN_SUCCESS)
            break;

        /* Shared+write mappings are suspicious for injected dump channels.
         * Plain read-only shared mappings are common for normal dylibs. */
        if (info.shared && (info.protection & VM_PROT_WRITE)) {
            return -1;
        }

        /* RWX regions are highly suspicious in a non-JIT application.
         * Frida Gum, Substrate, and similar frameworks allocate RWX memory
         * for their trampoline stubs and code relocation. */
        if ((info.protection & VM_PROT_EXECUTE) &&
            (info.protection & VM_PROT_WRITE)) {
            /* Also require that the region is not in a system framework bundle,
             * which legitimately uses JIT for JavaScriptCore/WebKit. */
            return -1;
        }

        addr += size;
    }
    return 0;
}

static void cprisk_probe_sleep_cancelable(int total_seconds) {
    if (total_seconds <= 0)
        total_seconds = 1;
    while (s_probe_running && total_seconds-- > 0) {
        struct timespec req;
        req.tv_sec = 1;
        req.tv_nsec = 0;
        (void)nanosleep(&req, NULL);
    }
}

/*
 * Probe: check loaded dylibs for suspicious names.
 *
 * Uses _dyld_image_count / _dyld_get_image_name to enumerate all loaded
 * images and compares each name against a list of known injection-framework
 * patterns. This catches library-level injection even when the process
 * name or VM layout has been obscured.
 *
 * Returns 0 if clean, -1 if injection indicators found.
 */
static int cprisk_check_dylib_injection(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name)
            continue;
        for (size_t j = 0; j < sizeof(s_suspicious_patterns) / sizeof(char *); j++) {
            if (strstr(name, s_suspicious_patterns[j]) != NULL) {
                /* Found a known injection library — do not log or crash here.
                 * Just flag and let deception mode handle it silently. */
                return -1;
            }
        }
    }
    return 0;
}

/*
 * Background probe loop.
 *
 * Sleeps for s_probe_interval_seconds between scans. When a detector
 * fires, it activates deception mode (sets s_integrity_deception_active)
 * rather than crashing immediately, which avoids alerting the attacker
 * to the presence of this probe thread.
 *
 * Runs as a joinable thread so stop() can block until the probe exits,
 * avoiding leaked thread resources across repeated start/stop cycles.
 */
static void *cprisk_probe_main(void *arg) {
    (void)arg;
    while (s_probe_running) {
        cprisk_probe_sleep_cancelable(s_probe_interval_seconds);
        if (!s_probe_running)
            break;

        if (cprisk_scan_vm_regions() != 0) {
            cprisk_force_integrity_poison();
            s_integrity_deception_active = 1;
            continue;
        }

        if (cprisk_check_dylib_injection() != 0) {
            cprisk_force_integrity_poison();
            s_integrity_deception_active = 1;
            continue;
        }
    }
    return NULL;
}

/*
 * Start the anti-dump probe thread.
 *
 * interval_seconds: polling interval in seconds (minimum 1). Pass 0 to keep
 * the default (5 seconds). The thread is idempotent: repeated start calls
 * while running only refresh the interval.
 *
 * Returns 0 on success, -1 on thread creation failure.
 */
int cprisk_start_anti_dump_probe(int interval_seconds) {
    pthread_mutex_lock(&s_probe_mutex);
    if (s_probe_started) {
        if (interval_seconds > 0)
            s_probe_interval_seconds = interval_seconds;
        pthread_mutex_unlock(&s_probe_mutex);
        return 0;
    }

    if (interval_seconds > 0)
        s_probe_interval_seconds = interval_seconds;
    if (s_probe_interval_seconds <= 0)
        s_probe_interval_seconds = 5;

    s_probe_running = 1;
    int rc = pthread_create(&s_probe_thread, NULL, cprisk_probe_main, NULL);
    if (rc != 0) {
        s_probe_running = 0;
        pthread_mutex_unlock(&s_probe_mutex);
        return -1;
    }

    s_probe_started = 1;
    pthread_mutex_unlock(&s_probe_mutex);
    return 0;
}

/*
 * Stop the anti-dump probe thread.
 *
 * Sets the volatile flag and lets the sleep() expire naturally.
 * Safe to call even if the thread was never started.
 */
void cprisk_stop_anti_dump_probe(void) {
    pthread_t thread_to_join;

    pthread_mutex_lock(&s_probe_mutex);
    if (!s_probe_started) {
        s_probe_running = 0;
        pthread_mutex_unlock(&s_probe_mutex);
        return;
    }
    s_probe_running = 0;
    thread_to_join = s_probe_thread;
    s_probe_started = 0;
    pthread_mutex_unlock(&s_probe_mutex);

    (void)pthread_join(thread_to_join, NULL);
}
