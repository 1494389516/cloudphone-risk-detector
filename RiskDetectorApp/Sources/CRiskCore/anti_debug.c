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
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/proc.h>
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

int cprisk_is_being_traced(void) {
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
    (void)0;
    return 0;
#endif
}
