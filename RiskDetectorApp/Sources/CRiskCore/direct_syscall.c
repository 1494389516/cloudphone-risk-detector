#include "include/CRiskCore.h"

#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_DIRECT_SYSCALLS_AVAILABLE 1
#else
#define CPRISK_DIRECT_SYSCALLS_AVAILABLE 0
#endif

static int cprisk_finish_errno(int result, int *error_out) {
    if (error_out != NULL) {
        *error_out = (result == 0) ? 0 : errno;
    }
    return result;
}

static long cprisk_direct_syscall6(
    long syscall_number,
    long arg0,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    int *error_out
) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    register long x0 __asm("x0") = arg0;
    register long x1 __asm("x1") = arg1;
    register long x2 __asm("x2") = arg2;
    register long x3 __asm("x3") = arg3;
    register long x4 __asm("x4") = arg4;
    register long x5 __asm("x5") = arg5;
    register long x16 __asm("x16") = syscall_number;
    unsigned int did_error = 0;

    __asm__ volatile(
        "svc #0x80\n"
        "cset %w[did_error], cs\n"
        : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), [did_error] "=r"(did_error)
        : "r"(x16)
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
    return x0;
#else
    (void)syscall_number;
    (void)arg0;
    (void)arg1;
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;
    if (error_out != NULL) {
        *error_out = ENOTSUP;
    }
    return -1;
#endif
}

int cprisk_sysctlbyname_direct(
    const char *name,
    void *oldp,
    size_t *oldlenp,
    const void *newp,
    size_t newlen,
    int *error_out
) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_sysctlbyname,
        (long)(uintptr_t)name,
        (long)(uintptr_t)oldp,
        (long)(uintptr_t)oldlenp,
        (long)(uintptr_t)newp,
        (long)newlen,
        0,
        error_out
    );
#else
    return cprisk_finish_errno(sysctlbyname(name, oldp, oldlenp, (void *)newp, newlen), error_out);
#endif
}

int cprisk_sysctl_direct(
    int *name,
    unsigned int namelen,
    void *oldp,
    size_t *oldlenp,
    const void *newp,
    size_t newlen,
    int *error_out
) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_sysctl,
        (long)(uintptr_t)name,
        (long)namelen,
        (long)(uintptr_t)oldp,
        (long)(uintptr_t)oldlenp,
        (long)(uintptr_t)newp,
        (long)newlen,
        error_out
    );
#else
    return cprisk_finish_errno(sysctl(name, namelen, oldp, oldlenp, (void *)newp, newlen), error_out);
#endif
}

int cprisk_stat_direct(const char *path, struct stat *sb, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    /*
     * modern Darwin arm64 exposes 64-bit inode/layout through struct stat,
     * so the direct syscall should use the stat64 entry rather than SYS_stat.
     */
    return (int)cprisk_direct_syscall6(
        SYS_stat64,
        (long)(uintptr_t)path,
        (long)(uintptr_t)sb,
        0,
        0,
        0,
        0,
        error_out
    );
#else
    return cprisk_finish_errno(stat(path, sb), error_out);
#endif
}

int cprisk_lstat_direct(const char *path, struct stat *sb, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_lstat64,
        (long)(uintptr_t)path,
        (long)(uintptr_t)sb,
        0,
        0,
        0,
        0,
        error_out
    );
#else
    return cprisk_finish_errno(lstat(path, sb), error_out);
#endif
}

int cprisk_access_direct(const char *path, int amode, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_access,
        (long)(uintptr_t)path,
        (long)amode,
        0,
        0,
        0,
        0,
        error_out
    );
#else
    return cprisk_finish_errno(access(path, amode), error_out);
#endif
}
