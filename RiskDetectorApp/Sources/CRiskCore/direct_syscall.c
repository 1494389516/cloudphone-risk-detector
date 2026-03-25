#include "include/CRiskCore.h"

/*
 * Direct SVC stubs are arm64-device only. Every libc / arc4random substitute records
 * cprisk_note_libc_fallback_used(...) so libc_fallback_used_mask + event_total are never
 * silently consumed-only-in-C: watchdog snapshot and Swift risk layers read the same bits.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <stdatomic.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_DIRECT_SYSCALLS_AVAILABLE 1
#else
#define CPRISK_DIRECT_SYSCALLS_AVAILABLE 0
#endif

#if !CPRISK_DIRECT_SYSCALLS_AVAILABLE
/* Process-wide tag: this build cannot emit SVC syscall templates; libc substitutes are expected. */
__attribute__((constructor))
static void cprisk_direct_syscall_note_unsupported_build(void) {
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_UNSUPPORTED_PLATFORM);
}
#endif

static int cprisk_finish_errno(int result, int *error_out) {
    if (error_out != NULL) {
        *error_out = (result == 0) ? 0 : errno;
    }
    return result;
}

static volatile uint32_t s_cprisk_libc_fallback_used_mask = 0u;
static atomic_uint_fast32_t s_cprisk_libc_fallback_event_total;

void cprisk_note_libc_fallback_used(uint32_t bits) {
    s_cprisk_libc_fallback_used_mask |= bits;
    atomic_fetch_add_explicit(&s_cprisk_libc_fallback_event_total, 1u, memory_order_relaxed);
}

uint32_t cprisk_get_libc_fallback_used_mask(void) {
    return s_cprisk_libc_fallback_used_mask;
}

uint32_t cprisk_get_libc_fallback_event_total(void) {
    return (uint32_t)atomic_load_explicit(&s_cprisk_libc_fallback_event_total, memory_order_relaxed);
}

void cprisk_reset_libc_fallback_used_mask(void) {
    s_cprisk_libc_fallback_used_mask = 0u;
    atomic_store_explicit(&s_cprisk_libc_fallback_event_total, 0u, memory_order_relaxed);
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
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCALL_STUB_FALLBACK);
    if (error_out != NULL) {
        *error_out = ENOTSUP;
    }
    return -1;
#endif
}

/*
 * Zero-argument syscall template – optimised for hot-path calls
 * (getpid / getppid / getuid) that never fail and return a single value.
 */
static long cprisk_direct_syscall0(long syscall_number) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    register long x0 __asm("x0");
    register long x16 __asm("x16") = syscall_number;
    __asm__ volatile(
        "svc #0x80\n"
        : "=r"(x0)
        : "r"(x16)
        : "cc", "memory"
    );
    return x0;
#else
    (void)syscall_number;
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCALL_STUB_FALLBACK);
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
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCTL);
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
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCTL);
    return cprisk_finish_errno(sysctl(name, namelen, oldp, oldlenp, (void *)newp, newlen), error_out);
#endif
}

int cprisk_stat_direct(const char *path, struct stat *sb, int *error_out) {
    if (sb != NULL) {
        memset(sb, 0, sizeof(*sb));
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_stat64,
        (long)(uintptr_t)path,
        (long)(uintptr_t)sb,
        0, 0, 0, 0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_STAT_PATH);
    return cprisk_finish_errno(sb ? stat(path, sb) : access(path, F_OK), error_out);
#endif
}

int cprisk_lstat_direct(const char *path, struct stat *sb, int *error_out) {
    if (sb != NULL) {
        memset(sb, 0, sizeof(*sb));
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_lstat64,
        (long)(uintptr_t)path,
        (long)(uintptr_t)sb,
        0, 0, 0, 0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_STAT_PATH);
    return cprisk_finish_errno(sb ? lstat(path, sb) : access(path, F_OK), error_out);
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
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_STAT_PATH);
    return cprisk_finish_errno(access(path, amode), error_out);
#endif
}

int cprisk_probe_path_snapshot(const char *path, cprisk_path_probe_snapshot_t *out_snapshot) {
    if (path == NULL || out_snapshot == NULL) {
        return -1;
    }

    out_snapshot->available_mask = CPRISK_PATH_PROBE_ACCESS | CPRISK_PATH_PROBE_STAT | CPRISK_PATH_PROBE_FOPEN;
    out_snapshot->exists_mask = 0;

    if (cprisk_access_direct(path, F_OK, NULL) == 0) {
        out_snapshot->exists_mask |= CPRISK_PATH_PROBE_ACCESS;
    }

    struct stat sb;
    memset(&sb, 0, sizeof(sb));
    if (cprisk_stat_direct(path, &sb, NULL) == 0) {
        out_snapshot->exists_mask |= CPRISK_PATH_PROBE_STAT;
    }

    FILE *fp = fopen(path, "rb");
    if (fp != NULL) {
        out_snapshot->exists_mask |= CPRISK_PATH_PROBE_FOPEN;
        (void)fclose(fp);
    }

    return 0;
}

/* ── getpid / getppid / getuid ─────────────────────────────────────── */

pid_t cprisk_getpid_direct(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (pid_t)cprisk_direct_syscall0(SYS_getpid);
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_IDS);
    return getpid();
#endif
}

pid_t cprisk_getppid_direct(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (pid_t)cprisk_direct_syscall0(SYS_getppid);
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_IDS);
    return getppid();
#endif
}

uid_t cprisk_getuid_direct(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (uid_t)cprisk_direct_syscall0(SYS_getuid);
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_IDS);
    return getuid();
#endif
}

/* ── open / close / read ───────────────────────────────────────────── */

int cprisk_open_direct(const char *path, int flags, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_open,
        (long)(uintptr_t)path,
        (long)flags,
        0,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO);
    int fd = open(path, flags);
    if (error_out != NULL) {
        *error_out = (fd >= 0) ? 0 : errno;
    }
    return fd;
#endif
}

int cprisk_close_direct(int fd, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_close,
        (long)fd,
        0,
        0,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO);
    return cprisk_finish_errno(close(fd), error_out);
#endif
}

ssize_t cprisk_read_direct(int fd, void *buf, size_t nbyte, int *error_out) {
    if (nbyte > (size_t)SSIZE_MAX) {
        if (error_out != NULL)
            *error_out = EINVAL;
        return -1;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (ssize_t)cprisk_direct_syscall6(
        SYS_read,
        (long)fd,
        (long)(uintptr_t)buf,
        (long)nbyte,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO);
    ssize_t n = read(fd, buf, nbyte);
    if (error_out != NULL) {
        *error_out = (n >= 0) ? 0 : errno;
    }
    return n;
#endif
}

/* ── socket / connect ──────────────────────────────────────────────── */

int cprisk_socket_direct(int domain, int type, int protocol, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_socket,
        (long)domain,
        (long)type,
        (long)protocol,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO);
    int fd = socket(domain, type, protocol);
    if (error_out != NULL) {
        *error_out = (fd >= 0) ? 0 : errno;
    }
    return fd;
#endif
}

int cprisk_connect_direct(int sockfd, const struct sockaddr *addr, socklen_t addrlen, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_connect,
        (long)sockfd,
        (long)(uintptr_t)addr,
        (long)addrlen,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO);
    return cprisk_finish_errno(connect(sockfd, addr, addrlen), error_out);
#endif
}

/* ── mprotect ──────────────────────────────────────────────────────── */

#ifndef SYS_mprotect
#if defined(__APPLE__)
#define SYS_mprotect 74
#else
#error "SYS_mprotect not defined for this platform"
#endif
#endif

int cprisk_mprotect_direct(void *addr, size_t len, int prot, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_mprotect,
        (long)(uintptr_t)addr,
        (long)len,
        (long)prot,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_MPROTECT);
    return cprisk_finish_errno(mprotect(addr, len, prot), error_out);
#endif
}

/* ── getentropy ────────────────────────────────────────────────────── */

#ifndef SYS_getentropy
#if defined(__APPLE__)
#define SYS_getentropy 500   /* Darwin arm64 getentropy trap number */
#else
#error "SYS_getentropy not defined for this platform"
#endif
#endif

int cprisk_getentropy_direct(void *buf, size_t buflen, int *error_out) {
    if (buflen > 256) {
        if (error_out != NULL) {
            *error_out = EINVAL;
        }
        return -1;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_getentropy,
        (long)(uintptr_t)buf,
        (long)buflen,
        0,
        0,
        0,
        0,
        error_out
    );
#else
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_GETENTROPY);
    arc4random_buf(buf, buflen);
    if (error_out != NULL) {
        *error_out = 0;
    }
    return 0;
#endif
}

/* ── csops (code signing) ───────────────────────────────────────────── */

#ifndef SYS_csops
#if defined(__APPLE__)
#define SYS_csops 169
#else
#error "SYS_csops not defined for this platform"
#endif
#endif

int cprisk_csops_direct(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, int *error_out) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    return (int)cprisk_direct_syscall6(
        SYS_csops,
        (long)pid,
        (long)ops,
        (long)(uintptr_t)useraddr,
        (long)usersize,
        0,
        0,
        error_out
    );
#else
    (void)pid;
    (void)ops;
    (void)useraddr;
    (void)usersize;
    cprisk_note_libc_fallback_used(CPRISK_LIBC_FALLBACK_USED_DIRECT_CSOPS_UNAVAILABLE);
    if (error_out != NULL) {
        *error_out = ENOTSUP;
    }
    return -1;
#endif
}

/* ── SVC stub integrity (early snapshot vs periodic compare) ───────── */

#define CPRISK_SVC_STUB_SNAPSHOT_BYTES 48u
#define CPRISK_SVC0_STUB_SNAPSHOT_BYTES 32u

static uint8_t s_cprisk_syscall6_text_ref[CPRISK_SVC_STUB_SNAPSHOT_BYTES];
static volatile int s_cprisk_syscall6_text_ready = 0;
static uint8_t s_cprisk_syscall0_text_ref[CPRISK_SVC0_STUB_SNAPSHOT_BYTES];
static volatile int s_cprisk_syscall0_text_ready = 0;

extern uint32_t cprisk_deny_attach_stub_integrity_mask(void);

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
static inline int cprisk_arm64_word_is_svc_i(uint32_t w) {
    /* A64 `svc #imm` family: top byte 0xd4, low 5 bits 0x1 (imm16 embedded). */
    return ((w & 0xff000000u) == 0xd4000000u) && ((w & 0x1fu) == 0x1u);
}

int cprisk_stub_contains_svc_opcode(const void *fn, size_t len) {
    if (!fn || len < 4u) {
        return 0;
    }
    const uint8_t *p = (const uint8_t *)fn;
    const size_t n = len / 4u;
    for (size_t i = 0; i < n; i++) {
        uint32_t w;
        memcpy(&w, p + i * 4u, sizeof(w));
        if (cprisk_arm64_word_is_svc_i(w)) {
            return 1;
        }
    }
    return 0;
}
#else
int cprisk_stub_contains_svc_opcode(const void *fn, size_t len) {
    (void)fn;
    (void)len;
    return 1;
}
#endif

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
__attribute__((constructor(8)))
static void cprisk_svc_stub_capture_syscall6_i(void) {
    memcpy(
        s_cprisk_syscall6_text_ref,
        (const void *)&cprisk_direct_syscall6,
        CPRISK_SVC_STUB_SNAPSHOT_BYTES);
    s_cprisk_syscall6_text_ready = 1;
}

__attribute__((constructor(8)))
static void cprisk_svc_stub_capture_syscall0_i(void) {
    memcpy(
        s_cprisk_syscall0_text_ref,
        (const void *)&cprisk_direct_syscall0,
        CPRISK_SVC0_STUB_SNAPSHOT_BYTES);
    s_cprisk_syscall0_text_ready = 1;
}

static uint32_t cprisk_direct_syscall6_stub_integrity_mask_i(void) {
    if (!s_cprisk_syscall6_text_ready) {
        return 0u;
    }
    uint8_t live[CPRISK_SVC_STUB_SNAPSHOT_BYTES];
    memcpy(live, (const void *)&cprisk_direct_syscall6, sizeof(live));
    if (memcmp(live, s_cprisk_syscall6_text_ref, sizeof(live)) != 0) {
        return 1u;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    if (!cprisk_stub_contains_svc_opcode((const void *)&cprisk_direct_syscall6, sizeof(live))) {
        return 1u;
    }
#endif
    return 0u;
}

static uint32_t cprisk_direct_syscall0_stub_integrity_mask_i(void) {
    if (!s_cprisk_syscall0_text_ready) {
        return 0u;
    }
    uint8_t live[CPRISK_SVC0_STUB_SNAPSHOT_BYTES];
    memcpy(live, (const void *)&cprisk_direct_syscall0, sizeof(live));
    if (memcmp(live, s_cprisk_syscall0_text_ref, sizeof(live)) != 0) {
        return 1u;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    if (!cprisk_stub_contains_svc_opcode((const void *)&cprisk_direct_syscall0, sizeof(live))) {
        return 1u;
    }
#endif
    return 0u;
}
#else
static uint32_t cprisk_direct_syscall6_stub_integrity_mask_i(void) {
    return 0u;
}

static uint32_t cprisk_direct_syscall0_stub_integrity_mask_i(void) {
    return 0u;
}
#endif

uint32_t cprisk_verify_svc_stub_integrity(void) {
    const uint32_t a = cprisk_direct_syscall6_stub_integrity_mask_i();
    const uint32_t b = cprisk_deny_attach_stub_integrity_mask();
    const uint32_t c = cprisk_direct_syscall0_stub_integrity_mask_i();
    return a | (b << 1) | (c << 2);
}
