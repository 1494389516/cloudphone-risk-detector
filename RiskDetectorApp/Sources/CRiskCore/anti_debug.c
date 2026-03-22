/*
 * CRiskCore - Anti-debug via SVC direct deny-attach syscall.
 * Bypasses user-space hooks by invoking the kernel trap path directly.
 *
 * ARM64 iOS: deny-attach syscall #26, request code = 31.
 * Darwin ABI: x16 = syscall number, x0-x3 = args.
 *
 * Also provides P_TRACED detection via sysctl to detect if the process is
 * currently being traced (debugger attached).
 */

#include "include/CRiskCore.h"

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#endif

void cprisk_deny_attach(void) {
    (void)cprisk_deny_attach_status(NULL);
}

int cprisk_deny_attach_status(int *error_out) {
#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    register long x0 __asm("x0") = 31;  /* PT_DENY_ATTACH */
    register long x1 __asm("x1") = 0;   /* pid = 0 (self) */
    register long x2 __asm("x2") = 0;   /* addr = 0 */
    register long x3 __asm("x3") = 0;   /* data = 0 */
    register long x16 __asm("x16") = 26; /* deny-attach syscall number */
    unsigned int did_error = 0;

    /* SVC #0x80: direct BSD syscall, bypasses libc hook surface */
    __asm__ volatile (
        "svc #0x80\n"
        "cset %w[did_error], cs\n"
        : "+r"(x0), [did_error] "=r"(did_error)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x16)
        : "cc", "memory"
    );

    if (did_error) {
        if (error_out != NULL) {
            *error_out = (int)x0;
        }
        return -1;
    }

    if (error_out != NULL) {
        *error_out = 0;
    }
    return (int)x0;
#else
    /* No-op on simulator, x86_64, or non-Apple */
    if (error_out != NULL) {
        *error_out = 0;
    }
    return 0;
#endif
}

static atomic_uint_fast32_t s_trace_crosscheck_inconsistent = 0u;
static atomic_uint_fast32_t s_trace_crosscheck_streak = 0u;
static atomic_uint_fast32_t s_mach_port_baseline = 0u;

int cprisk_is_being_traced_sysctl_only(void) {
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    int mib[4];
    struct kinfo_proc info;
    size_t size = sizeof(info);

    memset(&info, 0, size);
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = (int)cprisk_getpid_direct();

    if (cprisk_sysctl_direct(mib, 4, &info, &size, NULL, 0, NULL) != 0)
        return 0;  /* assume not traced on query failure */

    return ((info.kp_proc.p_flag & P_TRACED) != 0) ? 1 : 0;
#else
    return 0;
#endif
}

int cprisk_mach_trace_suspicious(void) {
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    int suspicious = 0;

    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    const exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS;
    kern_return_t kr = task_get_exception_ports(
        mach_task_self(),
        mask,
        masks,
        &count,
        ports,
        behaviors,
        flavors);
    if (kr != KERN_SUCCESS) {
        suspicious += 1;
    } else {
        int has_breakpoint_port = 0;
        for (mach_msg_type_number_t i = 0; i < count; i++) {
            if ((masks[i] & EXC_MASK_BREAKPOINT) != 0u &&
                ports[i] != MACH_PORT_NULL) {
                has_breakpoint_port = 1;
            }
            if (ports[i] != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), ports[i]);
            }
        }
        if (!has_breakpoint_port) {
            /* Weak signal only: missing task-level breakpoint port can happen
               on some builds, so do not score it as a hard anomaly. */
            suspicious += 0;
        }
    }

    task_extmod_info_data_t extmod;
    mach_msg_type_number_t extmod_count = TASK_EXTMOD_INFO_COUNT;
    memset(&extmod, 0, sizeof(extmod));
    if (task_info(
            mach_task_self(),
            TASK_EXTMOD_INFO,
            (task_info_t)&extmod,
            &extmod_count) == KERN_SUCCESS) {
        if (extmod.extmod_statistics.task_for_pid_count > 0) {
            suspicious += 1;
        }
    }

    if (cprisk_detect_thread_exception_ports() > 0) {
        suspicious += 2;
    }

    mach_port_name_array_t names = MACH_PORT_NULL;
    mach_msg_type_number_t names_count = 0;
    mach_port_type_array_t types = MACH_PORT_NULL;
    mach_msg_type_number_t types_count = 0;
    if (mach_port_names(mach_task_self(), &names, &names_count, &types, &types_count) == KERN_SUCCESS) {
        const uint32_t observed_count = (uint32_t)names_count;
        const uint32_t baseline = atomic_load(&s_mach_port_baseline);
        if (baseline == 0u) {
            atomic_store(&s_mach_port_baseline, observed_count);
        } else if (observed_count > baseline + 64u) {
            /* A sudden Mach port surge often appears after debugger/injector attach. */
            suspicious += 1;
        }

        if (names != MACH_PORT_NULL && names_count > 0) {
            vm_deallocate(
                mach_task_self(),
                (vm_address_t)names,
                (vm_size_t)(sizeof(mach_port_name_t) * (size_t)names_count)
            );
        }
        if (types != MACH_PORT_NULL && types_count > 0) {
            vm_deallocate(
                mach_task_self(),
                (vm_address_t)types,
                (vm_size_t)(sizeof(mach_port_type_t) * (size_t)types_count)
            );
        }
    }

    return suspicious > 0 ? 1 : 0;
#else
    return 0;
#endif
}

int cprisk_trace_crosscheck_inconsistent(void) {
    return atomic_load(&s_trace_crosscheck_inconsistent) != 0u ? 1 : 0;
}

int cprisk_is_being_traced(void) {
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    const int unix_traced = cprisk_is_being_traced_sysctl_only();
    const int mach_suspicious = cprisk_mach_trace_suspicious();
    const int inconsistent = (unix_traced != 0) != (mach_suspicious != 0);
    uint32_t streak = atomic_load(&s_trace_crosscheck_streak);

    atomic_store(&s_trace_crosscheck_inconsistent, inconsistent ? 1u : 0u);
    if (inconsistent) {
        if (streak != UINT32_MAX) {
            streak += 1u;
        }
        atomic_store(&s_trace_crosscheck_streak, streak);
        if (streak >= 2u && mach_suspicious != 0) {
            cprisk_force_integrity_poison();
        }
    } else {
        streak = 0u;
        atomic_store(&s_trace_crosscheck_streak, 0u);
    }

    return (unix_traced != 0 || mach_suspicious != 0 || streak >= 2u) ? 1 : 0;
#else
    (void)0;
    return 0;
#endif
}

int cprisk_deny_attach_effective_verify(int deny_attach_rc, int deny_attach_errno, uint32_t *detail_bits_out) {
    (void)deny_attach_errno;
    if (detail_bits_out != NULL) {
        *detail_bits_out = 0u;
    }
#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    if (deny_attach_rc != 0) {
        return 0;
    }

    struct kinfo_proc a;
    struct kinfo_proc b;
    size_t sz_a = sizeof(a);
    size_t sz_b = sizeof(b);
    int mib[4];

    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = (int)cprisk_getpid_direct();

    if (cprisk_sysctl_direct(mib, 4, &a, &sz_a, NULL, 0, NULL) != 0) {
        return 0;
    }
    if (cprisk_sysctl_direct(mib, 4, &b, &sz_b, NULL, 0, NULL) != 0) {
        return 0;
    }

    if (a.kp_proc.p_pid != b.kp_proc.p_pid) {
        if (detail_bits_out != NULL) {
            *detail_bits_out |= 1u;
        }
        return 1;
    }
    if (a.kp_proc.p_flag != b.kp_proc.p_flag) {
        if (detail_bits_out != NULL) {
            *detail_bits_out |= 2u;
        }
        return 1;
    }
    if ((pid_t)a.kp_proc.p_pid != cprisk_getpid_direct()) {
        if (detail_bits_out != NULL) {
            *detail_bits_out |= 4u;
        }
        return 1;
    }
    return 0;
#else
    (void)deny_attach_rc;
    return 0;
#endif
}

void cprisk_amfi_entitlement_watchdog_probe(
    uint32_t *cs_flags_out,
    uint32_t *get_task_allow_suspect_out,
    uint32_t *amfi_anomaly_bits_out
) {
    if (cs_flags_out != NULL) {
        *cs_flags_out = 0u;
    }
    if (get_task_allow_suspect_out != NULL) {
        *get_task_allow_suspect_out = 0u;
    }
    if (amfi_anomaly_bits_out != NULL) {
        *amfi_anomaly_bits_out = 0u;
    }

#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#ifndef CS_VALID
#define CS_VALID 0x00000001u
#endif
#ifndef CS_HARD
#define CS_HARD 0x00000100u
#endif
#ifndef CS_KILL
#define CS_KILL 0x00400000u
#endif
#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000u
#endif

    uint32_t flags = 0u;
    int cs_err = 0;
    if (cprisk_csops_status_flags(&flags, &cs_err) == 0) {
        if (cs_flags_out != NULL) {
            *cs_flags_out = flags;
        }
        if (amfi_anomaly_bits_out != NULL) {
            if ((flags & CS_DEBUGGED) != 0u) {
                *amfi_anomaly_bits_out |= CPRISK_AMFI_PROBE_CS_DEBUGGED;
            }
            if (flags != 0u && (flags & CS_VALID) == 0u) {
                *amfi_anomaly_bits_out |= CPRISK_AMFI_PROBE_CS_VALID_ABSENT;
            }
            if (flags != 0u && (flags & CS_HARD) == 0u) {
                *amfi_anomaly_bits_out |= CPRISK_AMFI_PROBE_CS_HARD_ABSENT;
            }
            if (flags != 0u && (flags & CS_KILL) == 0u) {
                *amfi_anomaly_bits_out |= CPRISK_AMFI_PROBE_CS_KILL_ABSENT;
            }
        }
    }

    mach_port_t tport = MACH_PORT_NULL;
    const kern_return_t kr = task_for_pid(mach_task_self(), cprisk_getpid_direct(), &tport);
    if (tport != MACH_PORT_NULL && tport != mach_task_self()) {
        (void)mach_port_deallocate(mach_task_self(), tport);
    }

    /*
     * Without get-task-allow, task_for_pid is expected to fail for third-party apps.
     * KERN_SUCCESS implies an entitlement-class capability surfaced to user space.
     */
    if (kr == KERN_SUCCESS) {
        if (get_task_allow_suspect_out != NULL) {
            *get_task_allow_suspect_out = 1u;
        }
    }
#else
    (void)0;
#endif
}
