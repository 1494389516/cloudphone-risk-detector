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
#include "include/cprisk_instruction_cache.h"
#include "include/cprisk_sha256.h"

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <mach/mach.h>
#include <mach/vm_region.h>
#endif

#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_DIRECT_SYSCALLS_AVAILABLE 1
#else
#define CPRISK_DIRECT_SYSCALLS_AVAILABLE 0
#endif

/* Snapshot sizes for SVC templates + RX relocation (keep in sync with integrity section). */
#define CPRISK_SVC_STUB_SNAPSHOT_BYTES 48u
#define CPRISK_SVC0_STUB_SNAPSHOT_BYTES 32u
#define CPRISK_SVC_STUB_CHUNK_BYTES 16u
#define CPRISK_SVC_STUB6_CHUNKS 3u
#define CPRISK_SVC_STUB0_CHUNKS 2u

#ifndef CPRISK_STUB_PAGE_MASK
#define CPRISK_STUB_PAGE_MASK ((uintptr_t)0xFFFu)
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

typedef long (*cprisk_svc6_fn_t)(
    long syscall_number,
    long arg0,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    int *error_out);

typedef long (*cprisk_svc0_fn_t)(long syscall_number);

#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
#define CPRISK_DIRECT_SYSCALL_MAYBE_UNUSED
#else
#define CPRISK_DIRECT_SYSCALL_MAYBE_UNUSED __attribute__((unused))
#endif

static CPRISK_DIRECT_SYSCALL_MAYBE_UNUSED long cprisk_direct_syscall6_template(
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
static CPRISK_DIRECT_SYSCALL_MAYBE_UNUSED long cprisk_direct_syscall0_template(long syscall_number) {
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

#undef CPRISK_DIRECT_SYSCALL_MAYBE_UNUSED

#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
static cprisk_svc6_fn_t s_svc6_active = cprisk_direct_syscall6_template;
static cprisk_svc0_fn_t s_svc0_active = cprisk_direct_syscall0_template;
#endif

#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
static void *s_svc_rx_page;
static size_t s_svc_rx_page_size;
static uintptr_t s_svc6_rx_offset;
static uintptr_t s_svc0_rx_offset;
static uint64_t s_svc_rx_page_hash_ref;
static uint64_t s_svc_rx_stub_roll_ref;
static uint8_t s_svc6_reloc_body_sha256[32];
static uint8_t s_svc0_reloc_body_sha256[32];
static volatile int s_svc_reloc_ready;

/*
 * Mach readback: ensure the relocated stub page is still mapped RX (no write),
 * covering remaps / mprotect tampering that leaves bytes intact.
 * Also consult vm_region_recurse leaf info so max_prot cannot retain write+exec
 * (W^X / hook remap) even when cur protection looks RX.
 */
static int cprisk_svc_rx_page_mach_leaf_ok_i(void) {
    if (s_svc_rx_page == NULL || s_svc_rx_page_size == 0u) {
        return 0;
    }
    const uintptr_t stub_lo = (uintptr_t)s_svc_rx_page;
    const uintptr_t stub_hi = stub_lo + s_svc_rx_page_size;
    const uintptr_t page0 = stub_lo & ~CPRISK_STUB_PAGE_MASK;
    vm_address_t addr = (vm_address_t)page0;
    natural_t depth = 0u;
    for (unsigned guard = 0u; guard < 32u; guard++) {
        vm_size_t sz = 0u;
        vm_region_submap_info_data_64_t sub;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = vm_region_recurse_64(
            mach_task_self(),
            &addr,
            &sz,
            &depth,
            (vm_region_recurse_info_t)&sub,
            &count);
        if (kr != KERN_SUCCESS) {
            return 0;
        }
        if (sub.is_submap != 0) {
            depth += 1u;
            continue;
        }
        const uintptr_t reg_lo = (uintptr_t)addr;
        const uintptr_t reg_hi = reg_lo + (uintptr_t)sz;
        if (reg_lo > stub_lo || stub_hi > reg_hi) {
            return 0;
        }
        const vm_prot_t need = (vm_prot_t)(VM_PROT_READ | VM_PROT_EXECUTE);
        if ((sub.protection & need) != need) {
            return 0;
        }
        if ((sub.protection & VM_PROT_WRITE) != 0) {
            return 0;
        }
        if ((sub.max_protection & VM_PROT_WRITE) != 0) {
            return 0;
        }
        /* Private MAP_ANON page used for relocated stubs — not a shared pmap mapping. */
        if (sub.is_shared != 0) {
            return 0;
        }
        return 1;
    }
    return 0;
}

static int cprisk_svc_rx_page_mach_prot_ok_i(void) {
    if (s_svc_rx_page == NULL || s_svc_rx_page_size == 0u) {
        return 0;
    }
    const uintptr_t page0 = (uintptr_t)s_svc_rx_page & ~CPRISK_STUB_PAGE_MASK;
    vm_address_t region_addr = (vm_address_t)page0;
    vm_size_t region_sz = 0u;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj_name = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(
        mach_task_self(),
        &region_addr,
        &region_sz,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&info,
        &count,
        &obj_name);
    if (kr != KERN_SUCCESS) {
        return 0;
    }
    const uintptr_t stub_lo = (uintptr_t)s_svc_rx_page;
    const uintptr_t stub_hi = stub_lo + s_svc_rx_page_size;
    const uintptr_t reg_hi = (uintptr_t)region_addr + (uintptr_t)region_sz;
    if (stub_lo < (uintptr_t)region_addr || stub_hi > reg_hi) {
        return 0;
    }
    const vm_prot_t need = (vm_prot_t)(VM_PROT_READ | VM_PROT_EXECUTE);
    if ((info.protection & need) != need) {
        return 0;
    }
    if ((info.protection & VM_PROT_WRITE) != 0) {
        return 0;
    }
    if (obj_name != MACH_PORT_NULL) {
        (void)mach_port_deallocate(mach_task_self(), obj_name);
    }
    if (cprisk_svc_rx_page_mach_leaf_ok_i() == 0) {
        return 0;
    }
    return 1;
}

static uint64_t cprisk_fnv1a64_fold_i(const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0u; i < n; i++) {
        h ^= (uint64_t)b[i];
        h *= 1099511628211ULL;
    }
    return h;
}

__attribute__((constructor(3)))
static void cprisk_svc_stub_rx_reloc_ctor_i(void) {
    const size_t ps = (size_t)getpagesize();
    const size_t need = CPRISK_SVC_STUB_SNAPSHOT_BYTES + CPRISK_SVC0_STUB_SNAPSHOT_BYTES + 64u;
    if (ps < need + 4u) {
        return;
    }
    uint64_t r = 0u;
    int ge = 0;
    if (cprisk_getentropy_direct(&r, sizeof(r), &ge) != 0) {
        r = (uint64_t)(uintptr_t)&cprisk_svc_stub_rx_reloc_ctor_i ^ 0xA5A5A5A5u;
    }
    void *pg = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (pg == MAP_FAILED) {
        return;
    }
    memset(pg, 0, ps);
    const uint64_t span = (uint64_t)(ps - need);
    const uintptr_t o6 = (uintptr_t)((r % (span / 4u)) * 4u);
    uintptr_t o0 = o6 + CPRISK_SVC_STUB_SNAPSHOT_BYTES + 8u + ((r >> 40) & 15u) * 4u;
    if (o0 + CPRISK_SVC0_STUB_SNAPSHOT_BYTES > ps) {
        o0 = o6 + CPRISK_SVC_STUB_SNAPSHOT_BYTES + 8u;
    }
    if (o0 + CPRISK_SVC0_STUB_SNAPSHOT_BYTES > ps) {
        munmap(pg, ps);
        return;
    }
    memcpy((uint8_t *)pg + o6, (const void *)&cprisk_direct_syscall6_template, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
    memcpy((uint8_t *)pg + o0, (const void *)&cprisk_direct_syscall0_template, CPRISK_SVC0_STUB_SNAPSHOT_BYTES);
    {
        cprisk_sha256_ctx ctx6;
        cprisk_sha256_init(&ctx6);
        cprisk_sha256_update(&ctx6, (const uint8_t *)pg + o6, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
        cprisk_sha256_final(&ctx6, s_svc6_reloc_body_sha256);
        cprisk_sha256_ctx ctx0;
        cprisk_sha256_init(&ctx0);
        cprisk_sha256_update(&ctx0, (const uint8_t *)pg + o0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES);
        cprisk_sha256_final(&ctx0, s_svc0_reloc_body_sha256);
    }
    cprisk_flush_instruction_cache((uint8_t *)pg + o6, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
    cprisk_flush_instruction_cache((uint8_t *)pg + o0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES);

    int mperr = 0;
    if (cprisk_mprotect_direct(pg, ps, PROT_READ | PROT_EXEC, &mperr) != 0) {
        munmap(pg, ps);
        return;
    }

    typedef long (*t0)(long);
    t0 test0 = (t0)((uint8_t *)pg + o0);
    const pid_t tp = (pid_t)test0(SYS_getpid);
    if (tp != (pid_t)getpid()) {
        munmap(pg, ps);
        return;
    }

    uint64_t h = cprisk_fnv1a64_fold_i(pg, ps);
    h ^= (uint64_t)o6 << 48;
    h ^= (uint64_t)o0 << 32;
    h ^= 0x8E61F7A91D3C5B09ULL;

    const uint8_t *p6 = (const uint8_t *)pg + o6;
    const uint8_t *p0 = (const uint8_t *)pg + o0;
    uint64_t roll = cprisk_fnv1a64_fold_i(p6, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
    roll ^= cprisk_fnv1a64_fold_i(p6 + CPRISK_SVC_STUB_SNAPSHOT_BYTES / 4u,
                                  CPRISK_SVC_STUB_SNAPSHOT_BYTES - CPRISK_SVC_STUB_SNAPSHOT_BYTES / 4u);
    roll ^= cprisk_fnv1a64_fold_i(p0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES) << 1u;

    s_svc_rx_page = pg;
    s_svc_rx_page_size = ps;
    s_svc6_rx_offset = o6;
    s_svc0_rx_offset = o0;
    s_svc_rx_page_hash_ref = h;
    s_svc_rx_stub_roll_ref = roll;
    s_svc6_active = (cprisk_svc6_fn_t)((uint8_t *)pg + o6);
    s_svc0_active = (cprisk_svc0_fn_t)((uint8_t *)pg + o0);
    s_svc_reloc_ready = 1;
}
#endif

#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
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
    return s_svc6_active(
        syscall_number,
        arg0,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        error_out);
}

static long cprisk_direct_syscall0(long syscall_number) {
    return s_svc0_active(syscall_number);
}
#endif

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

/* ── SVC stub integrity (FNV-1a chunk hashes + rolling verify + SVC scan) ─ */

extern uint32_t cprisk_deny_attach_stub_integrity_mask(void);
extern uint32_t cprisk_deny_attach_stub_sha256_page_mask(void);
extern void cprisk_deny_attach_stub_page_sha256_digest(uint8_t out_digest[32]);

uint64_t cprisk_svc_stub_chunk_hash_fnv16(const uint8_t *chunk16, uintptr_t stub_fn_addr) {
    const uint64_t fnv_offset = 14695981039346656037ULL;
    const uint64_t fnv_prime = 1099511628211ULL;
    uint64_t h = fnv_offset;
    if (!chunk16) {
        return 0u;
    }
    for (size_t i = 0; i < CPRISK_SVC_STUB_CHUNK_BYTES; i++) {
        h ^= (uint64_t)chunk16[i];
        h *= fnv_prime;
    }
    const uintptr_t page = stub_fn_addr & ~CPRISK_STUB_PAGE_MASK;
    h ^= (uint64_t)page;
    h *= fnv_prime;
    return h;
}

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
static uint64_t s_cprisk_syscall6_chunk_expected[CPRISK_SVC_STUB6_CHUNKS];
static volatile int s_cprisk_syscall6_text_ready = 0;
static atomic_uint_fast32_t s_cprisk_syscall6_stub_tick;

static uint64_t s_cprisk_syscall0_chunk_expected[CPRISK_SVC_STUB0_CHUNKS];
static volatile int s_cprisk_syscall0_text_ready = 0;
static atomic_uint_fast32_t s_cprisk_syscall0_stub_tick;

static int cprisk_svc_stub_chunks_match_rolling_i(
    const uint8_t *live,
    uintptr_t stub_addr,
    uint32_t nchunks,
    const uint64_t *expected,
    atomic_uint_fast32_t *tick_atom
) {
    const uint32_t t = atomic_fetch_add_explicit(tick_atom, 1u, memory_order_relaxed) + 1u;
    const int full = (t % 4u) == 0u;
    if (full) {
        for (uint32_t c = 0; c < nchunks; c++) {
            const uint64_t h = cprisk_svc_stub_chunk_hash_fnv16(
                live + (size_t)c * CPRISK_SVC_STUB_CHUNK_BYTES,
                stub_addr);
            if (h != expected[c]) {
                return 0;
            }
        }
        return 1;
    }
    const uint32_t idx = (t - 1u) % nchunks;
    const uint64_t h = cprisk_svc_stub_chunk_hash_fnv16(
        live + (size_t)idx * CPRISK_SVC_STUB_CHUNK_BYTES,
        stub_addr);
    return h == expected[idx] ? 1 : 0;
}

__attribute__((constructor(8)))
static void cprisk_svc_stub_capture_syscall6_i(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    const void *src6 = (s_svc_reloc_ready != 0 && s_svc_rx_page != NULL)
                           ? (const void *)((const uint8_t *)s_svc_rx_page + s_svc6_rx_offset)
                           : (const void *)&cprisk_direct_syscall6_template;
#else
    const void *src6 = (const void *)&cprisk_direct_syscall6_template;
#endif
    const uintptr_t base = (uintptr_t)src6;
    uint8_t snap[CPRISK_SVC_STUB_SNAPSHOT_BYTES];
    memcpy(snap, src6, sizeof(snap));
    for (uint32_t c = 0; c < CPRISK_SVC_STUB6_CHUNKS; c++) {
        s_cprisk_syscall6_chunk_expected[c] =
            cprisk_svc_stub_chunk_hash_fnv16(snap + (size_t)c * CPRISK_SVC_STUB_CHUNK_BYTES, base);
    }
    s_cprisk_syscall6_text_ready = 1;
}

__attribute__((constructor(8)))
static void cprisk_svc_stub_capture_syscall0_i(void) {
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    const void *src0 = (s_svc_reloc_ready != 0 && s_svc_rx_page != NULL)
                           ? (const void *)((const uint8_t *)s_svc_rx_page + s_svc0_rx_offset)
                           : (const void *)&cprisk_direct_syscall0_template;
#else
    const void *src0 = (const void *)&cprisk_direct_syscall0_template;
#endif
    const uintptr_t base = (uintptr_t)src0;
    uint8_t snap[CPRISK_SVC0_STUB_SNAPSHOT_BYTES];
    memcpy(snap, src0, sizeof(snap));
    for (uint32_t c = 0; c < CPRISK_SVC_STUB0_CHUNKS; c++) {
        s_cprisk_syscall0_chunk_expected[c] =
            cprisk_svc_stub_chunk_hash_fnv16(snap + (size_t)c * CPRISK_SVC_STUB_CHUNK_BYTES, base);
    }
    s_cprisk_syscall0_text_ready = 1;
}

static uint32_t cprisk_direct_syscall6_stub_integrity_mask_i(void) {
    if (!s_cprisk_syscall6_text_ready) {
        return 0u;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
    if (s_svc_reloc_ready && s_svc_rx_page != NULL) {
        if (!cprisk_svc_rx_page_mach_prot_ok_i()) {
            return 1u;
        }
        uint64_t h = cprisk_fnv1a64_fold_i(s_svc_rx_page, s_svc_rx_page_size);
        h ^= (uint64_t)s_svc6_rx_offset << 48;
        h ^= (uint64_t)s_svc0_rx_offset << 32;
        h ^= 0x8E61F7A91D3C5B09ULL;
        if (h != s_svc_rx_page_hash_ref) {
            return 1u;
        }
        const uint8_t *p6 = (const uint8_t *)s_svc_rx_page + s_svc6_rx_offset;
        const uint8_t *p0 = (const uint8_t *)s_svc_rx_page + s_svc0_rx_offset;
        uint64_t roll = cprisk_fnv1a64_fold_i(p6, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
        roll ^= cprisk_fnv1a64_fold_i(
            p6 + CPRISK_SVC_STUB_SNAPSHOT_BYTES / 4u,
            CPRISK_SVC_STUB_SNAPSHOT_BYTES - CPRISK_SVC_STUB_SNAPSHOT_BYTES / 4u);
        roll ^= cprisk_fnv1a64_fold_i(p0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES) << 1u;
        if (roll != s_svc_rx_stub_roll_ref) {
            return 1u;
        }
        uint8_t live[CPRISK_SVC_STUB_SNAPSHOT_BYTES];
        memcpy(live, p6, sizeof(live));
        if (!cprisk_svc_stub_chunks_match_rolling_i(
                live,
                (uintptr_t)p6,
                CPRISK_SVC_STUB6_CHUNKS,
                s_cprisk_syscall6_chunk_expected,
                &s_cprisk_syscall6_stub_tick)) {
            return 1u;
        }
        if (!cprisk_stub_contains_svc_opcode(p6, CPRISK_SVC_STUB_SNAPSHOT_BYTES)) {
            return 1u;
        }
        if (!cprisk_stub_contains_svc_opcode(p0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES)) {
            return 1u;
        }
        uint8_t h6b[32];
        cprisk_sha256_ctx ctxb;
        cprisk_sha256_init(&ctxb);
        cprisk_sha256_update(&ctxb, p6, CPRISK_SVC_STUB_SNAPSHOT_BYTES);
        cprisk_sha256_final(&ctxb, h6b);
        if (memcmp(h6b, s_svc6_reloc_body_sha256, 32) != 0) {
            return 1u;
        }
        uint8_t h0b[32];
        cprisk_sha256_init(&ctxb);
        cprisk_sha256_update(&ctxb, p0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES);
        cprisk_sha256_final(&ctxb, h0b);
        if (memcmp(h0b, s_svc0_reloc_body_sha256, 32) != 0) {
            return 1u;
        }
        return 0u;
    }
#endif
    uint8_t live[CPRISK_SVC_STUB_SNAPSHOT_BYTES];
    memcpy(live, (const void *)&cprisk_direct_syscall6_template, sizeof(live));
    const uintptr_t base = (uintptr_t)(void *)&cprisk_direct_syscall6_template;
    if (!cprisk_svc_stub_chunks_match_rolling_i(
            live,
            base,
            CPRISK_SVC_STUB6_CHUNKS,
            s_cprisk_syscall6_chunk_expected,
            &s_cprisk_syscall6_stub_tick)) {
        return 1u;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    if (!cprisk_stub_contains_svc_opcode((const void *)&cprisk_direct_syscall6_template, sizeof(live))) {
        return 1u;
    }
#endif
    return 0u;
}

static uint32_t cprisk_direct_syscall0_stub_integrity_mask_i(void) {
    if (!s_cprisk_syscall0_text_ready) {
        return 0u;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
    if (s_svc_reloc_ready && s_svc_rx_page != NULL) {
        const uint8_t *p0 = (const uint8_t *)s_svc_rx_page + s_svc0_rx_offset;
        uint8_t live[CPRISK_SVC0_STUB_SNAPSHOT_BYTES];
        memcpy(live, p0, sizeof(live));
        if (!cprisk_svc_stub_chunks_match_rolling_i(
                live,
                (uintptr_t)p0,
                CPRISK_SVC_STUB0_CHUNKS,
                s_cprisk_syscall0_chunk_expected,
                &s_cprisk_syscall0_stub_tick)) {
            return 1u;
        }
        if (!cprisk_stub_contains_svc_opcode(p0, CPRISK_SVC0_STUB_SNAPSHOT_BYTES)) {
            return 1u;
        }
        return 0u;
    }
#endif
    uint8_t live[CPRISK_SVC0_STUB_SNAPSHOT_BYTES];
    memcpy(live, (const void *)&cprisk_direct_syscall0_template, sizeof(live));
    const uintptr_t base = (uintptr_t)(void *)&cprisk_direct_syscall0_template;
    if (!cprisk_svc_stub_chunks_match_rolling_i(
            live,
            base,
            CPRISK_SVC_STUB0_CHUNKS,
            s_cprisk_syscall0_chunk_expected,
            &s_cprisk_syscall0_stub_tick)) {
        return 1u;
    }
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE
    if (!cprisk_stub_contains_svc_opcode((const void *)&cprisk_direct_syscall0_template, sizeof(live))) {
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

#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
static uint8_t s_sha256_pg6_ref[32];
static uint8_t s_sha256_pg0_ref[32];
static int s_sha256_pg_ref_ready;

static void cprisk_svc_stub_resolve_live_page_hashes_i(uint8_t h6[32], uint8_t h0[32], uint8_t hd[32]) {
    const void *src6 = (s_svc_reloc_ready != 0 && s_svc_rx_page != NULL)
                           ? (const void *)((const uint8_t *)s_svc_rx_page + s_svc6_rx_offset)
                           : (const void *)&cprisk_direct_syscall6_template;
    const void *src0 = (s_svc_reloc_ready != 0 && s_svc_rx_page != NULL)
                           ? (const void *)((const uint8_t *)s_svc_rx_page + s_svc0_rx_offset)
                           : (const void *)&cprisk_direct_syscall0_template;
    cprisk_sha256_text_page(src6, h6);
    cprisk_sha256_text_page(src0, h0);
    cprisk_deny_attach_stub_page_sha256_digest(hd);
}

static void cprisk_sha256_pg_ref_lazy_i(void) {
    if (s_sha256_pg_ref_ready) {
        return;
    }
    uint8_t h6[32], h0[32], hd[32];
    cprisk_svc_stub_resolve_live_page_hashes_i(h6, h0, hd);
    memcpy(s_sha256_pg6_ref, h6, sizeof(s_sha256_pg6_ref));
    memcpy(s_sha256_pg0_ref, h0, sizeof(s_sha256_pg0_ref));
    (void)hd;
    s_sha256_pg_ref_ready = 1;
}

static uint32_t cprisk_svc_stub_sha256_aux_mask_i(void) {
    cprisk_sha256_pg_ref_lazy_i();
    uint8_t h6[32], h0[32], hd[32];
    cprisk_svc_stub_resolve_live_page_hashes_i(h6, h0, hd);
    (void)hd;
    uint32_t m = 0u;
    if (memcmp(h6, s_sha256_pg6_ref, 32) != 0) {
        m |= 1u << 3;
    }
    if (memcmp(h0, s_sha256_pg0_ref, 32) != 0) {
        m |= 1u << 4;
    }
    return m;
}

static uint8_t s_stub_sha256_roll[32];
static uint64_t s_stub_sha256_roll_ctr;

static void cprisk_svc_stub_sha256_roll_step_i(const uint8_t h6[32], const uint8_t h0[32], const uint8_t hd[32]) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, s_stub_sha256_roll, 32);
    cprisk_sha256_update(&ctx, h6, 32);
    cprisk_sha256_update(&ctx, h0, 32);
    cprisk_sha256_update(&ctx, hd, 32);
    s_stub_sha256_roll_ctr++;
    uint8_t le[8];
    for (unsigned i = 0; i < 8; i++) {
        le[i] = (uint8_t)(s_stub_sha256_roll_ctr >> (8u * i));
    }
    cprisk_sha256_update(&ctx, le, 8);
    cprisk_sha256_final(&ctx, s_stub_sha256_roll);
}
#else
static uint32_t cprisk_svc_stub_sha256_aux_mask_i(void) {
    return 0u;
}
#endif

uint32_t cprisk_verify_svc_stub_integrity(void) {
    const uint32_t a = cprisk_direct_syscall6_stub_integrity_mask_i();
    const uint32_t b = cprisk_deny_attach_stub_integrity_mask();
    const uint32_t c = cprisk_direct_syscall0_stub_integrity_mask_i();
    const uint32_t sha_mask = cprisk_svc_stub_sha256_aux_mask_i();
    const uint32_t deny_sha_mask = cprisk_deny_attach_stub_sha256_page_mask();
    const uint32_t m = a | (b << 1) | (c << 2) | sha_mask | deny_sha_mask;
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
    {
        uint8_t rh6[32], rh0[32], rhd[32];
        cprisk_svc_stub_resolve_live_page_hashes_i(rh6, rh0, rhd);
        cprisk_svc_stub_sha256_roll_step_i(rh6, rh0, rhd);
    }
#endif
    return m;
}

/*
 * Bounds of the mmap'd RX page holding relocated SVC syscall templates (device arm64 only).
 * memory_guard skips this range when classifying anonymous RX so our own stub slab is not
 * conflated with foreign Stalker/Gum-style executable mappings.
 */
void cprisk_svc_reloc_rx_page_whitelist_bounds(uintptr_t *out_lo, uintptr_t *out_hi) {
    uintptr_t lo = 0u;
    uintptr_t hi = 0u;
#if CPRISK_DIRECT_SYSCALLS_AVAILABLE && defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
    if (s_svc_reloc_ready && s_svc_rx_page != NULL && s_svc_rx_page_size > 0u) {
        lo = (uintptr_t)s_svc_rx_page;
        hi = lo + (uintptr_t)s_svc_rx_page_size;
    }
#endif
    if (out_lo != NULL) {
        *out_lo = lo;
    }
    if (out_hi != NULL) {
        *out_hi = hi;
    }
}
