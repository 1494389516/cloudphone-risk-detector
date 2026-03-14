/*
 * CRiskCore - Anti-debug via SVC direct syscall for ptrace(PT_DENY_ATTACH).
 * Bypasses user-space hooks (e.g. Frida on ptrace) by invoking the syscall directly.
 *
 * ARM64 iOS: ptrace syscall #26, PT_DENY_ATTACH = 31.
 * Darwin ABI: x16 = syscall number, x0-x3 = args.
 */

#include "CRiskCore.h"

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

void cprisk_deny_attach(void) {
#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* SVC #0x80: direct BSD syscall, bypasses libc/ptrace hooks */
    __asm__ volatile (
        "mov x16, #26\n"   /* ptrace syscall number */
        "mov x0, #31\n"    /* PT_DENY_ATTACH */
        "mov x1, #0\n"     /* pid = 0 (self) */
        "mov x2, #0\n"     /* addr = 0 */
        "mov x3, #0\n"     /* data = 0 */
        "svc #0x80\n"
        :
        :
        : "x0", "x1", "x2", "x3", "x16", "memory"
    );
#else
    /* No-op on simulator, x86_64, or non-Apple */
    (void)0;
#endif
}
