/*
 * CRiskCore - Anti-debug via SVC direct syscall for ptrace(PT_DENY_ATTACH).
 * Bypasses user-space hooks (e.g. Frida on ptrace) by invoking the syscall directly.
 *
 * ARM64 iOS: ptrace syscall #26, PT_DENY_ATTACH = 31.
 * Darwin ABI: x16 = syscall number, x0-x3 = args.
 */

#include "include/CRiskCore.h"

#if defined(__APPLE__)
#include <TargetConditionals.h>
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
    register long x16 __asm("x16") = 26; /* ptrace syscall number */
    unsigned int did_error = 0;

    /* SVC #0x80: direct BSD syscall, bypasses libc/ptrace hooks */
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
