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
#include <sys/mman.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include "include/cprisk_instruction_cache.h"
#endif

#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__) && \
    (defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_DENY_ATTACH_DEVICE_AVAILABLE 1
#else
#define CPRISK_DENY_ATTACH_DEVICE_AVAILABLE 0
#endif

void cprisk_deny_attach(void) {
    (void)cprisk_deny_attach_status(NULL);
}

#define CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES 48u

static int cprisk_deny_attach_status_template(int *error_out) {
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
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

static int (*s_deny_attach_fn)(int *) = cprisk_deny_attach_status_template;

#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE

static void *s_deny_rx_page;
static size_t s_deny_rx_page_size;
static uintptr_t s_deny_rx_offset;
static uint64_t s_deny_rx_page_hash_ref;
static uint64_t s_deny_rx_stub_roll_ref;
static volatile int s_deny_reloc_ready;

static uint64_t cprisk_deny_fnv1a64_i(const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0u; i < n; i++) {
        h ^= (uint64_t)b[i];
        h *= 1099511628211ULL;
    }
    return h;
}

__attribute__((constructor(3)))
static void cprisk_deny_attach_rx_reloc_ctor_i(void) {
    const size_t ps = (size_t)getpagesize();
    if (ps < CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES + 64u) {
        return;
    }
    uint64_t r = 0u;
    int ge = 0;
    if (cprisk_getentropy_direct(&r, sizeof(r), &ge) != 0) {
        r = (uint64_t)(uintptr_t)&cprisk_deny_attach_rx_reloc_ctor_i ^ 0x5A5A5A5Au;
    }
    void *pg = mmap(NULL, ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (pg == MAP_FAILED) {
        return;
    }
    memset(pg, 0, ps);
    const uintptr_t max_off = ps - CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES - 8u;
    const uintptr_t off = (uintptr_t)((r % (max_off / 4u)) * 4u);
    memcpy((uint8_t *)pg + off, (const void *)&cprisk_deny_attach_status_template, CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES);
    cprisk_flush_instruction_cache((uint8_t *)pg + off, CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES);

    int mperr = 0;
    if (cprisk_mprotect_direct(pg, ps, PROT_READ | PROT_EXEC, &mperr) != 0) {
        munmap(pg, ps);
        return;
    }

    uint64_t h = cprisk_deny_fnv1a64_i(pg, ps);
    h ^= (uint64_t)off << 40;
    h ^= 0x3D3C2B1A0F0E0D0CULL;

    const uint8_t *pd = (const uint8_t *)pg + off;
    uint64_t roll = cprisk_deny_fnv1a64_i(pd, CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES);
    roll ^= cprisk_deny_fnv1a64_i(
        pd + CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES / 4u,
        CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES - CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES / 4u);

    s_deny_rx_page = pg;
    s_deny_rx_page_size = ps;
    s_deny_rx_offset = off;
    s_deny_rx_page_hash_ref = h;
    s_deny_rx_stub_roll_ref = roll;
    s_deny_attach_fn = (int (*)(int *))((uint8_t *)pg + off);
    s_deny_reloc_ready = 1;
}
#endif

int cprisk_deny_attach_status(int *error_out) {
    return s_deny_attach_fn(error_out);
}

#define CPRISK_DENY_ATTACH_CHUNKS 3u
#define CPRISK_DENY_ATTACH_CHUNK 16u

static uint64_t s_cprisk_deny_attach_chunk_expected[CPRISK_DENY_ATTACH_CHUNKS];
static volatile int s_cprisk_deny_attach_text_ready = 0;
static atomic_uint_fast32_t s_cprisk_deny_attach_stub_tick;

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
static uint8_t s_deny_page_sha256_ref[32];

__attribute__((constructor(8)))
static void cprisk_svc_stub_capture_deny_attach_i(void) {
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
    const void *src = (s_deny_reloc_ready != 0 && s_deny_rx_page != NULL)
                           ? (const void *)((const uint8_t *)s_deny_rx_page + s_deny_rx_offset)
                           : (const void *)&cprisk_deny_attach_status_template;
#else
    const void *src = (const void *)&cprisk_deny_attach_status_template;
#endif
    const uintptr_t base = (uintptr_t)src;
    uint8_t snap[CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES];
    memcpy(snap, src, sizeof(snap));
    for (uint32_t c = 0; c < CPRISK_DENY_ATTACH_CHUNKS; c++) {
        s_cprisk_deny_attach_chunk_expected[c] =
            cprisk_svc_stub_chunk_hash_fnv16(snap + (size_t)c * CPRISK_DENY_ATTACH_CHUNK, base);
    }
    cprisk_sha256_text_page(src, s_deny_page_sha256_ref);
    s_cprisk_deny_attach_text_ready = 1;
}
#endif

uint32_t cprisk_deny_attach_stub_integrity_mask(void) {
#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
    if (!s_cprisk_deny_attach_text_ready) {
        return 0u;
    }
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
    if (s_deny_reloc_ready != 0 && s_deny_rx_page != NULL) {
        uint64_t h = cprisk_deny_fnv1a64_i(s_deny_rx_page, s_deny_rx_page_size);
        h ^= (uint64_t)s_deny_rx_offset << 40;
        h ^= 0x3D3C2B1A0F0E0D0CULL;
        if (h != s_deny_rx_page_hash_ref) {
            return 1u;
        }
        const uint8_t *pd = (const uint8_t *)s_deny_rx_page + s_deny_rx_offset;
        uint64_t roll = cprisk_deny_fnv1a64_i(pd, CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES);
        roll ^= cprisk_deny_fnv1a64_i(
            pd + CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES / 4u,
            CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES - CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES / 4u);
        if (roll != s_deny_rx_stub_roll_ref) {
            return 1u;
        }
        uint8_t live[CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES];
        memcpy(live, pd, sizeof(live));
        const uint32_t t =
            atomic_fetch_add_explicit(&s_cprisk_deny_attach_stub_tick, 1u, memory_order_relaxed) + 1u;
        const int full = (t % 4u) == 0u;
        if (full) {
            for (uint32_t c = 0; c < CPRISK_DENY_ATTACH_CHUNKS; c++) {
                const uint64_t ch = cprisk_svc_stub_chunk_hash_fnv16(
                    live + (size_t)c * CPRISK_DENY_ATTACH_CHUNK,
                    (uintptr_t)pd);
                if (ch != s_cprisk_deny_attach_chunk_expected[c]) {
                    return 1u;
                }
            }
        } else {
            const uint32_t idx = (t - 1u) % CPRISK_DENY_ATTACH_CHUNKS;
            const uint64_t ch = cprisk_svc_stub_chunk_hash_fnv16(
                live + (size_t)idx * CPRISK_DENY_ATTACH_CHUNK,
                (uintptr_t)pd);
            if (ch != s_cprisk_deny_attach_chunk_expected[idx]) {
                return 1u;
            }
        }
        if (!cprisk_stub_contains_svc_opcode(pd, CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES)) {
            return 1u;
        }
        return 0u;
    }
#endif
    uint8_t live[CPRISK_DENY_ATTACH_STUB_SNAPSHOT_BYTES];
    memcpy(live, (const void *)&cprisk_deny_attach_status_template, sizeof(live));
    const uintptr_t base = (uintptr_t)(void *)&cprisk_deny_attach_status_template;
    const uint32_t t =
        atomic_fetch_add_explicit(&s_cprisk_deny_attach_stub_tick, 1u, memory_order_relaxed) + 1u;
    const int full = (t % 4u) == 0u;
    if (full) {
        for (uint32_t c = 0; c < CPRISK_DENY_ATTACH_CHUNKS; c++) {
            const uint64_t ch = cprisk_svc_stub_chunk_hash_fnv16(
                live + (size_t)c * CPRISK_DENY_ATTACH_CHUNK,
                base);
            if (ch != s_cprisk_deny_attach_chunk_expected[c]) {
                return 1u;
            }
        }
    } else {
        const uint32_t idx = (t - 1u) % CPRISK_DENY_ATTACH_CHUNKS;
        const uint64_t ch = cprisk_svc_stub_chunk_hash_fnv16(
            live + (size_t)idx * CPRISK_DENY_ATTACH_CHUNK,
            base);
        if (ch != s_cprisk_deny_attach_chunk_expected[idx]) {
            return 1u;
        }
    }
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
    if (!cprisk_stub_contains_svc_opcode((const void *)&cprisk_deny_attach_status_template, sizeof(live))) {
        return 1u;
    }
#endif
    return 0u;
#else
    return 0u;
#endif
}

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
void cprisk_deny_attach_stub_page_sha256_digest(uint8_t out_digest[32]) {
    if (!out_digest) {
        return;
    }
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
    const void *src =
        (s_deny_reloc_ready != 0 && s_deny_rx_page != NULL)
            ? (const void *)((const uint8_t *)s_deny_rx_page + s_deny_rx_offset)
            : (const void *)&cprisk_deny_attach_status_template;
    cprisk_sha256_text_page(src, out_digest);
#elif (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__)
    cprisk_sha256_text_page((const void *)&cprisk_deny_attach_status_template, out_digest);
#else
    memset(out_digest, 0, 32);
#endif
}

uint32_t cprisk_deny_attach_stub_sha256_page_mask(void) {
#if (defined(__arm64__) || defined(__aarch64__)) && defined(__APPLE__)
    uint8_t live[32];
    cprisk_deny_attach_stub_page_sha256_digest(live);
    return memcmp(live, s_deny_page_sha256_ref, 32) != 0 ? (1u << 5) : 0u;
#else
    return 0u;
#endif
}
#else
void cprisk_deny_attach_stub_page_sha256_digest(uint8_t out_digest[32]) {
    if (out_digest) {
        memset(out_digest, 0, 32);
    }
}

uint32_t cprisk_deny_attach_stub_sha256_page_mask(void) {
    return 0u;
}
#endif

static atomic_uint_fast32_t s_trace_crosscheck_inconsistent = 0u;
static atomic_uint_fast32_t s_trace_crosscheck_streak = 0u;
static atomic_uint_fast32_t s_mach_port_baseline = 0u;
static atomic_uint_fast32_t s_trace_probe_counter = 0u;

int cprisk_is_being_traced_sysctl_only(void) {
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    int mib[4];
    struct kinfo_proc info;
    size_t size = sizeof(info);

    memset(&info, 0, size);
    /* MIB values constructed at runtime via XOR to avoid static integer-pattern
     * matching (equivalent to DexHelper-style stack string construction for paths).
     * CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1 — decoded only during execution. */
    mib[0] = (int)(0x2Au ^ 0x2Bu);          /* CTL_KERN  = 1  */
    mib[1] = (int)(0xF8u ^ 0xF6u);          /* KERN_PROC = 14 */
    mib[2] = (int)(0x55u ^ 0x54u);          /* KERN_PROC_PID = 1 */
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
        } else if (observed_count > baseline && (observed_count - baseline) > 64u) {
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

static int cprisk_trace_probe_fast_i(void) {
    return cprisk_is_being_traced_sysctl_only() != 0 ? 1 : 0;
}

static int cprisk_trace_probe_slow_i(void) {
    int suspicious = 0;
    if (cprisk_mach_trace_suspicious() != 0) {
        suspicious = 1;
    }

    const uint32_t seq = atomic_fetch_add(&s_trace_probe_counter, 1u) + 1u;
    if ((seq & 3u) == 0u && cprisk_detect_thread_exception_ports() > 0) {
        suspicious = 1;
    }
    /*
     * Sampled DBI footprint check: if markers are present but sysctl P_TRACED is
     * clear (common under DBI / JIT layers), slow vs fast probes disagree and
     * cprisk_trace_crosscheck_inconsistent() surfaces the evasion pattern.
     */
    if ((seq & 7u) == 0u && cprisk_detect_dbi_markers() > 0) {
        suspicious = 1;
    }

    return suspicious;
}

static int cprisk_trace_eval_aggregate_i(void) {
#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    const int fast_traced = cprisk_trace_probe_fast_i();
    const int slow_traced = cprisk_trace_probe_slow_i();
    const int inconsistent = (fast_traced != 0) != (slow_traced != 0);
    uint32_t streak = atomic_load(&s_trace_crosscheck_streak);

    atomic_store(&s_trace_crosscheck_inconsistent, inconsistent ? 1u : 0u);
    if (inconsistent) {
        if (streak != UINT32_MAX) {
            streak += 1u;
        }
        atomic_store(&s_trace_crosscheck_streak, streak);
        if (streak >= 2u && slow_traced != 0) {
            cprisk_integrity_poison_antidebug_lane();
        }
    } else {
        streak = 0u;
        atomic_store(&s_trace_crosscheck_streak, 0u);
    }

    return (fast_traced != 0 || slow_traced != 0 || streak >= 2u) ? 1 : 0;
#else
    return 0;
#endif
}

int cprisk_is_being_traced(void) {
    return cprisk_trace_eval_aggregate_i();
}

/*
 * Redundant export: identical semantics via shared static aggregate to dilute
 * single-symbol hook value (call-sites can alternate without changing logic).
 */
int cprisk_is_being_traced_alt(void) {
    return cprisk_trace_eval_aggregate_i();
}

int cprisk_is_being_traced_redundant(void) {
    const int traced_sys = cprisk_is_being_traced_sysctl_only();
    const int traced_mach = cprisk_mach_trace_suspicious();
    if (traced_sys != 0 || traced_mach != 0) {
        return 1;
    }
    return cprisk_is_being_traced_alt();
}

int cprisk_deny_attach_effective_verify(int deny_attach_rc, int deny_attach_errno, uint32_t *detail_bits_out) {
    uint32_t detail_bits = 0u;
    if (detail_bits_out != NULL) {
        *detail_bits_out = 0u;
    }
#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
    if (deny_attach_rc != 0) {
        return 0;
    }

    struct kinfo_proc a;
    struct kinfo_proc b;
    struct kinfo_proc c;
    struct kinfo_proc libc_shadow;
    size_t sz_a = sizeof(a);
    size_t sz_b = sizeof(b);
    size_t sz_c = sizeof(c);
    size_t sz_libc = sizeof(libc_shadow);
    int mib[4];
    const pid_t self_pid = cprisk_getpid_direct();

    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    memset(&c, 0, sizeof(c));
    memset(&libc_shadow, 0, sizeof(libc_shadow));
    mib[0] = (int)(0x2Au ^ 0x2Bu);          /* CTL_KERN  = 1  */
    mib[1] = (int)(0xF8u ^ 0xF6u);          /* KERN_PROC = 14 */
    mib[2] = (int)(0x55u ^ 0x54u);          /* KERN_PROC_PID = 1 */
    mib[3] = (int)self_pid;

    if (cprisk_sysctl_direct(mib, 4, &a, &sz_a, NULL, 0, NULL) != 0) {
        return 0;
    }
    if (cprisk_sysctl_direct(mib, 4, &b, &sz_b, NULL, 0, NULL) != 0) {
        return 0;
    }
    if (cprisk_sysctl_direct(mib, 4, &c, &sz_c, NULL, 0, NULL) == 0) {
        if (a.kp_proc.p_flag != c.kp_proc.p_flag) {
            detail_bits |= CPRISK_DENY_ATTACH_VERIFY_FLAG_MISMATCH;
        }
        if ((pid_t)c.kp_proc.p_pid != self_pid) {
            detail_bits |= CPRISK_DENY_ATTACH_VERIFY_SELF_PID_MISMATCH;
        }
    }
    int libc_sys_err = 0;
    if (cprisk_sysctl_direct(mib, 4, &libc_shadow, &sz_libc, NULL, 0, &libc_sys_err) == 0) {
        if ((pid_t)libc_shadow.kp_proc.p_pid != (pid_t)a.kp_proc.p_pid ||
            ((libc_shadow.kp_proc.p_flag ^ a.kp_proc.p_flag) & (uint32_t)P_TRACED) != 0u) {
            detail_bits |= CPRISK_DENY_ATTACH_VERIFY_LIBC_DIRECT_DIVERGENCE;
        }
    }

    if (a.kp_proc.p_pid != b.kp_proc.p_pid) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_PID_MISMATCH;
    }
    if (a.kp_proc.p_flag != b.kp_proc.p_flag) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_FLAG_MISMATCH;
    }
    if ((pid_t)a.kp_proc.p_pid != self_pid || (pid_t)b.kp_proc.p_pid != self_pid) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_SELF_PID_MISMATCH;
    }
    if (sz_a != sizeof(a) || sz_b != sizeof(b)) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_SIZE_MISMATCH;
    }
    if (((uint32_t)a.kp_proc.p_flag & (uint32_t)P_TRACED) != 0u ||
        ((uint32_t)b.kp_proc.p_flag & (uint32_t)P_TRACED) != 0u) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_TRACE_FLAG_SET;
    }
    if (deny_attach_errno != 0) {
        detail_bits |= CPRISK_DENY_ATTACH_VERIFY_LIBC_DIRECT_DIVERGENCE;
    }

    if (detail_bits_out != NULL) {
        *detail_bits_out = detail_bits;
    }
    return detail_bits != 0u ? 1 : 0;
#else
    (void)deny_attach_rc;
    (void)deny_attach_errno;
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

#if CPRISK_DENY_ATTACH_DEVICE_AVAILABLE
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
