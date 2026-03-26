/*
 * cprisk_signal_probe.c — Low-level anti-debug probes using signals,
 * hardware breakpoint detection, timing analysis, Mach thread inspection,
 * csops CS_DEBUGGED check, and Developer Disk Image detection.
 *
 * Mach vs POSIX memory protection divergence is surfaced via
 * cprisk_get_vm_mprotect_* counters and the anti-debug watchdog snapshot.
 *
 * All functions return 0 (safe default) on simulator / non-arm64 platforms.
 */

#include "include/CRiskCore.h"
#include "include/cprisk_crypto_trace.h"

#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <objc/message.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#endif

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_SIGNAL_PROBE_AVAILABLE 1
#else
#define CPRISK_SIGNAL_PROBE_AVAILABLE 0
#endif

/*
 * ARM64 instant-return prefix scan (pure opcode match). Kept outside
 * CPRISK_SIGNAL_PROBE_AVAILABLE so iOS Simulator tests can validate patterns
 * without enabling Mach/signal probes.
 */
#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__))
#define CPRISK_ARM64_INSTR_RET_IR 0xD65F03C0u
#define CPRISK_ARM64_MOV_X0_X0_IR 0xAA0003E0u
#define CPRISK_ARM64_MOV_W0_W0_IR 0x2A0003E0u
#define CPRISK_ARM64_HINT_NOP_IR 0xD503201Fu
#define CPRISK_ARM64_BRANCH_MASK_IR 0x7C000000u
#define CPRISK_ARM64_BRANCH_OP_IR 0x14000000u
#define CPRISK_ARM64_BR_MASK_IR 0xFFFFFC1Fu
#define CPRISK_ARM64_BR_OP_IR 0xD61F0000u
#define CPRISK_ARM64_BLR_OP_IR 0xD63F0000u
#define CPRISK_ARM64_LDR_LITERAL_MASK_IR 0xFF000000u
#define CPRISK_ARM64_LDR_LITERAL_OP_IR 0x58000000u
#define CPRISK_ARM64_ADRP_MASK_IR 0x9F000000u
#define CPRISK_ARM64_ADRP_OP_IR 0x90000000u
#define CPRISK_ARM64_ADD_IMM_64_MASK_IR 0xFFC00000u
#define CPRISK_ARM64_ADD_IMM_64_OP_IR 0x91000000u

static int cprisk_arm64_is_b_imm_i(uint32_t instr) {
    return (instr & CPRISK_ARM64_BRANCH_MASK_IR) == CPRISK_ARM64_BRANCH_OP_IR;
}

static int cprisk_arm64_is_br_reg_i(uint32_t instr) {
    return (instr & CPRISK_ARM64_BR_MASK_IR) == CPRISK_ARM64_BR_OP_IR;
}

static int cprisk_arm64_is_blr_reg_i(uint32_t instr) {
    return (instr & CPRISK_ARM64_BR_MASK_IR) == CPRISK_ARM64_BLR_OP_IR;
}

static int cprisk_arm64_is_ldr_literal_reg_i(uint32_t instr, uint32_t reg) {
    return (instr & CPRISK_ARM64_LDR_LITERAL_MASK_IR) == CPRISK_ARM64_LDR_LITERAL_OP_IR &&
           (instr & 0x1Fu) == reg;
}

static int cprisk_arm64_is_adrp_reg_i(uint32_t instr, uint32_t reg) {
    return (instr & CPRISK_ARM64_ADRP_MASK_IR) == CPRISK_ARM64_ADRP_OP_IR &&
           (instr & 0x1Fu) == reg;
}

static int cprisk_arm64_is_add_imm_same_reg_i(uint32_t instr, uint32_t reg) {
    if ((instr & CPRISK_ARM64_ADD_IMM_64_MASK_IR) != CPRISK_ARM64_ADD_IMM_64_OP_IR) {
        return 0;
    }
    const uint32_t rd = instr & 0x1Fu;
    const uint32_t rn = (instr >> 5u) & 0x1Fu;
    return rd == reg && rn == reg;
}

int cprisk_scan_arm64_instant_return_nop_patch_prefix(const void *func_ptr, size_t prefix_bytes) {
    if (!func_ptr || prefix_bytes < 8u) {
        return 0;
    }

    const uint32_t *words = (const uint32_t *)func_ptr;
    const uint32_t w0 = words[0];
    const uint32_t w1 = words[1];
    if (w1 != CPRISK_ARM64_INSTR_RET_IR) {
        return 0;
    }
    if (w0 == CPRISK_ARM64_MOV_X0_X0_IR ||
        w0 == CPRISK_ARM64_MOV_W0_W0_IR ||
        w0 == CPRISK_ARM64_HINT_NOP_IR) {
        return 1;
    }
    return 0;
}

int cprisk_scan_arm64_suspicious_trampoline_prefix(const void *func_ptr, size_t prefix_bytes) {
    if (!func_ptr || prefix_bytes < 8u) {
        return 0;
    }

    const uint32_t *words = (const uint32_t *)func_ptr;
    const uint32_t w0 = words[0];
    const uint32_t w1 = words[1];
    if (cprisk_arm64_is_b_imm_i(w0) || cprisk_arm64_is_br_reg_i(w0) || cprisk_arm64_is_blr_reg_i(w0)) {
        return 1;
    }

    if ((cprisk_arm64_is_ldr_literal_reg_i(w0, 16u) || cprisk_arm64_is_ldr_literal_reg_i(w0, 17u)) &&
        (cprisk_arm64_is_br_reg_i(w1) || cprisk_arm64_is_blr_reg_i(w1))) {
        return 1;
    }

    if (prefix_bytes >= 12u) {
        const uint32_t w2 = words[2];
        if (((cprisk_arm64_is_adrp_reg_i(w0, 16u) && cprisk_arm64_is_add_imm_same_reg_i(w1, 16u)) ||
             (cprisk_arm64_is_adrp_reg_i(w0, 17u) && cprisk_arm64_is_add_imm_same_reg_i(w1, 17u))) &&
            (cprisk_arm64_is_br_reg_i(w2) || cprisk_arm64_is_blr_reg_i(w2))) {
            return 1;
        }
    }

    return 0;
}

int cprisk_scan_instant_return_key_symbols_prefix(void) {
    int found = 0;
    found += cprisk_scan_arm64_instant_return_nop_patch_prefix(
        (const void *)cprisk_deny_attach, 8u);
    found += cprisk_scan_arm64_instant_return_nop_patch_prefix(
        (const void *)cprisk_deny_attach_status, 8u);
    found += cprisk_scan_arm64_instant_return_nop_patch_prefix(
        (const void *)cprisk_probe_debugger_via_signal, 8u);
    found += cprisk_scan_arm64_instant_return_nop_patch_prefix(
        (const void *)cprisk_probe_exception_delivery_timeout, 8u);
    found += cprisk_scan_arm64_instant_return_nop_patch_prefix(
        (const void *)cprisk_register_exception_handler, 8u);
    found += cprisk_scan_arm64_instant_return_nop_patch_prefix(
        (const void *)cprisk_verify_exception_handler, 8u);
    return found;
}

int cprisk_scan_hook_surface_trampoline_prefixes(void) {
    int found = 0;
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)dlsym, 12u);
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)dlopen, 12u);
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)objc_msgSend, 12u);
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)_dyld_get_image_name, 12u);
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)_dyld_image_count, 12u);
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)pthread_create, 12u);
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)sysctl, 12u);
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)sysctlbyname, 12u);
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)mprotect, 12u);
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)mach_msg, 12u);
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)task_get_exception_ports, 12u);
    found += cprisk_scan_arm64_suspicious_trampoline_prefix((const void *)task_swap_exception_ports, 12u);
    return found;
}

#elif defined(__APPLE__)

int cprisk_scan_arm64_instant_return_nop_patch_prefix(const void *func_ptr, size_t prefix_bytes) {
    (void)func_ptr;
    (void)prefix_bytes;
    return 0;
}

int cprisk_scan_arm64_suspicious_trampoline_prefix(const void *func_ptr, size_t prefix_bytes) {
    (void)func_ptr;
    (void)prefix_bytes;
    return 0;
}

int cprisk_scan_instant_return_key_symbols_prefix(void) { return 0; }

int cprisk_scan_hook_surface_trampoline_prefixes(void) { return 0; }

#endif /* __APPLE__ arm64 / fallback */

/* ===================================================================== */
#if CPRISK_SIGNAL_PROBE_AVAILABLE
/* ===================================================================== */

#include <TargetConditionals.h>
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <mach/mach_time.h>
#if !(defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE)
#include <mach/mach_vm.h>
#endif
#include <mach-o/dyld.h>
#include <crt_externs.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <time.h>
#include "include/cprisk_macho.h"

#define CPRISK_EXCEPTION_DELIVERY_TIMEOUT_NS 10000000ull
#define CPRISK_SINGLE_STEP_DEFAULT_THRESHOLD_NS 50000000ull
#define CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS 5000000ull
#define CPRISK_SINGLE_STEP_THRESHOLD_MULTIPLIER 16ull
#define CPRISK_SINGLE_STEP_CALIBRATION_SAMPLES 9u
#define CPRISK_TIMING_SAMPLE_COUNT 7u
#define CPRISK_TIMING_MEDIAN_MULTIPLIER 14ull
#define CPRISK_TIMING_SPIKE_MULTIPLIER 22ull
#define CPRISK_TIMING_JITTER_DIVISOR 4ull
#define CPRISK_SOFTWARE_BP_RANDOM_DEFAULT_WINDOWS 8u
#define CPRISK_SOFTWARE_BP_RANDOM_DEFAULT_WINDOW_BYTES 768u
#define CPRISK_DBI_EXECMEM_REGION_BUDGET 8192u
#define CPRISK_DBI_EXECMEM_TIME_BUDGET_NS 20000000ull

#if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
typedef vm_address_t cprisk_vm_region_address_t;
typedef vm_size_t cprisk_vm_region_size_t;
#define CPRISK_VM_REGION_MIN_ADDRESS_I ((vm_address_t)VM_MIN_ADDRESS)
static kern_return_t cprisk_vm_region_recurse_i(
    vm_map_t target_task,
    cprisk_vm_region_address_t *address,
    cprisk_vm_region_size_t *size,
    natural_t *nesting_depth,
    vm_region_recurse_info_t info,
    mach_msg_type_number_t *info_count
) {
    return vm_region_recurse(target_task, address, size, nesting_depth, info, info_count);
}
#else
typedef mach_vm_address_t cprisk_vm_region_address_t;
typedef mach_vm_size_t cprisk_vm_region_size_t;
#define CPRISK_VM_REGION_MIN_ADDRESS_I ((mach_vm_address_t)MACH_VM_MIN_ADDRESS)
static kern_return_t cprisk_vm_region_recurse_i(
    vm_map_t target_task,
    cprisk_vm_region_address_t *address,
    cprisk_vm_region_size_t *size,
    natural_t *nesting_depth,
    vm_region_recurse_info_t info,
    mach_msg_type_number_t *info_count
) {
    return mach_vm_region_recurse(target_task, address, size, nesting_depth, info, info_count);
}
#endif

/* ── (a) SIGTRAP signal probe ─────────────────────────────────────── */

static sigjmp_buf s_trap_jmpbuf;
static volatile sig_atomic_t s_sigtrap_flag = 0;
static sigjmp_buf s_exception_delivery_jmpbuf;
static volatile sig_atomic_t s_exception_delivery_sigtrap = 0;
static atomic_uint_fast32_t s_exception_delivery_probe_armed = 0;
static atomic_uint_fast32_t s_exception_delivery_probe_handled = 0;
static atomic_uint_fast64_t s_exception_delivery_probe_start_ns = 0;
static atomic_uint_fast64_t s_exception_delivery_probe_last_ns = 0;
static atomic_uint_fast64_t s_single_step_baseline_ns = 0;
static atomic_uint_fast64_t s_single_step_threshold_ns = 0;
static atomic_uint_fast32_t s_single_step_calibrated = 0;
static atomic_flag s_single_step_calibration_lock = ATOMIC_FLAG_INIT;
static atomic_uint_fast32_t s_dbi_last_marker_flags = 0;
static atomic_uint_fast32_t s_dbi_last_hit_count = 0;
static atomic_uint_fast32_t s_timing_last_anomaly_flags = 0;
static atomic_uint_fast64_t s_timing_last_median_ns = 0;
static atomic_uint_fast64_t s_timing_last_max_ns = 0;
static atomic_uint_fast64_t s_timing_last_threshold_ns = 0;

int cprisk_watchdog_probe_should_stop(void);

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_TIMING_CNTPCT_AVAILABLE 1
#else
#define CPRISK_TIMING_CNTPCT_AVAILABLE 0
#endif

static uint64_t cprisk_mach_abs_to_ns_i(uint64_t delta_abs) {
    mach_timebase_info_data_t tb;
    if (mach_timebase_info(&tb) != KERN_SUCCESS || tb.denom == 0u) {
        return 0u;
    }

    return delta_abs / tb.denom * tb.numer + (delta_abs % tb.denom) * tb.numer / tb.denom;
}

static uint64_t cprisk_monotonic_now_ns_i(void) {
#if CPRISK_TIMING_CNTPCT_AVAILABLE
    static _Atomic uint64_t s_cntfrq = 0u;
    uint64_t freq = atomic_load_explicit(&s_cntfrq, memory_order_relaxed);
    if (freq == 0u) {
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
        atomic_store_explicit(&s_cntfrq, freq, memory_order_relaxed);
    }
    if (freq != 0u) {
        uint64_t ticks = 0u;
        __asm__ volatile("mrs %0, cntpct_el0" : "=r"(ticks));
        return (ticks / freq) * 1000000000ull +
               ((ticks % freq) * 1000000000ull) / freq;
    }
#endif
    return cprisk_mach_abs_to_ns_i(mach_absolute_time());
}

static uint64_t cprisk_random_u64_i(void) {
    uint64_t value = 0u;
    int err = 0;
    if (cprisk_getentropy_direct(&value, sizeof(value), &err) == 0) {
        return value;
    }
    (void)err;
    value = cprisk_monotonic_now_ns_i();
    value ^= ((uint64_t)(uintptr_t)&value << 21u);
    value ^= value >> 7u;
    value ^= value << 13u;
    return value;
}

static uint64_t cprisk_prng_next_i(uint64_t *state) {
    uint64_t x = *state;
    if (x == 0u) {
        x = 0xC3A5C85C97CB3127ULL;
    }
    x ^= x << 7u;
    x ^= x >> 9u;
    x ^= x << 8u;
    *state = x;
    return x;
}

static int cprisk_ascii_tolower_i(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }
    return c;
}

static int cprisk_contains_token_ascii_i(const char *haystack, const char *needle) {
    if (!haystack || !needle || needle[0] == '\0') {
        return 0;
    }

    size_t nlen = 0u;
    while (needle[nlen] != '\0') {
        nlen++;
    }
    if (nlen == 0u) {
        return 0;
    }

    for (size_t i = 0u; haystack[i] != '\0'; i++) {
        size_t j = 0u;
        while (j < nlen) {
            const int hc = cprisk_ascii_tolower_i((unsigned char)haystack[i + j]);
            const int nc = cprisk_ascii_tolower_i((unsigned char)needle[j]);
            if (haystack[i + j] == '\0' || hc != nc) {
                break;
            }
            j++;
        }
        if (j == nlen) {
            return 1;
        }
    }
    return 0;
}

static int cprisk_contains_any_token_i(
    const char *text,
    const char *const *tokens,
    size_t token_count
) {
    if (!text || !tokens || token_count == 0u) {
        return 0;
    }

    for (size_t i = 0u; i < token_count; i++) {
        if (tokens[i] && cprisk_contains_token_ascii_i(text, tokens[i])) {
            return 1;
        }
    }
    return 0;
}

typedef struct {
    uint32_t key_id;
    const uint8_t *enc;
    size_t enc_len;
} cprisk_obf_token_ref_t;

static int cprisk_contains_any_obf_token_i(
    const char *text,
    const cprisk_obf_token_ref_t *tokens,
    size_t token_count
) {
    if (!text || !tokens || token_count == 0u) {
        return 0;
    }
    for (size_t i = 0u; i < token_count; i++) {
        char buf[64];
        memset(buf, 0, sizeof(buf));
        if (tokens[i].enc_len + 1u > sizeof(buf)) {
            continue;
        }
        if (cprisk_obf_decode_sha256_tag(
                CPRISK_OBF_TAG_DOMAIN_SIGNAL_DBI,
                tokens[i].key_id,
                tokens[i].enc,
                tokens[i].enc_len,
                buf,
                sizeof(buf)) != 0) {
            cprisk_secure_zero(buf, sizeof(buf));
            continue;
        }
        const int hit = cprisk_contains_token_ascii_i(text, buf);
        cprisk_secure_zero(buf, sizeof(buf));
        if (hit) {
            return 1;
        }
    }
    return 0;
}

static int cprisk_getenv_obf_nonempty_i(const cprisk_obf_token_ref_t *token) {
    if (!token || !token->enc || token->enc_len == 0u) {
        return 0;
    }
    char key[64];
    memset(key, 0, sizeof(key));
    if (token->enc_len + 1u > sizeof(key)) {
        return 0;
    }
    if (cprisk_obf_decode_sha256_tag(
            CPRISK_OBF_TAG_DOMAIN_SIGNAL_DBI,
            token->key_id,
            token->enc,
            token->enc_len,
            key,
            sizeof(key)) != 0) {
        cprisk_secure_zero(key, sizeof(key));
        return 0;
    }
    const char *value = getenv(key);
    cprisk_secure_zero(key, sizeof(key));
    return (value && value[0] != '\0') ? 1 : 0;
}

static const uint8_t e1[] = {0x60, 0x9b, 0x38, 0x23, 0x09, 0x05};
static const uint8_t e2[] = {0x63, 0x00, 0x98, 0x2c, 0x05, 0xd8, 0x55, 0xdf};
static const uint8_t e3[] = {0x11, 0x0f, 0x34, 0x3a, 0xec, 0x9a, 0xae};
static const uint8_t e4[] = {0x9c, 0x3a, 0x07, 0x7f, 0x25, 0xdf, 0x19, 0x08, 0x7e, 0x83, 0xfa, 0x1e, 0x6f};
static const uint8_t e5[] = {0x2f, 0xbd, 0xe0, 0x2c, 0x76, 0x5f, 0xeb, 0xd9, 0x3a, 0x7b, 0xf4, 0x78, 0x7f, 0xdb, 0x22, 0x24, 0x4a};
static const uint8_t e6[] = {0x66, 0x25, 0x6c, 0x08, 0x6b, 0x0f, 0x00, 0xaf, 0x6a, 0x3f, 0xd1, 0xf4, 0x6b, 0x8f};
static const uint8_t e7[] = {0x13, 0xd9, 0x7a, 0x1a, 0xfa, 0x8b, 0x4c, 0xac, 0x2e, 0x0e, 0x12, 0xc9, 0xee, 0xb7, 0xb6, 0x14};
static const uint8_t e8[] = {0x66, 0x04, 0xd7, 0x14, 0x1f, 0xb2, 0x78, 0xfb, 0x74, 0x1a, 0x70, 0x58, 0x7d, 0x1a, 0x36, 0xa0, 0xe1};
static const uint8_t e9[] = {0x70, 0x2a, 0x6b, 0x64, 0xf6, 0x3e, 0x5c, 0x42, 0xa1, 0x3f, 0x0b, 0x76};
static const uint8_t e10[] = {0x02, 0xda, 0x25, 0x2d, 0x67, 0x6d, 0x2e, 0x69, 0xeb, 0xf4, 0xd6, 0xd2, 0x9f};
static const uint8_t e11[] = {0x8e, 0x80, 0xd0, 0xcc, 0xbe, 0x13, 0xab, 0xbf, 0x4a, 0x9c, 0x00, 0x3b};
static const uint8_t e12[] = {0x6b, 0xac, 0xb0, 0x6c, 0x20, 0xaa, 0x3b, 0xc2};
static const uint8_t e13[] = {0x38, 0xc4, 0x3b, 0xa9, 0x1f, 0x42, 0x5b, 0x13};
static const uint8_t e14[] = {0x4c, 0x57, 0xdc, 0x4d, 0x0a, 0xcb, 0x40, 0x81, 0x9a, 0x73, 0x3f, 0x84, 0xed, 0xf4, 0x88, 0xf6, 0x4a, 0x48, 0x2a};
static const uint8_t e15[] = {0xcf, 0x74, 0x0c, 0x5c, 0x1c, 0x55, 0x7e, 0x81, 0x52, 0xe9, 0x86};
static const uint8_t e16[] = {0xb4, 0xe2, 0xc6, 0xad, 0x9f, 0x8c, 0x69, 0xd8, 0x26, 0x84};
static const uint8_t e17[] = {0x06, 0x2b, 0x8d, 0x58, 0x98, 0x43, 0xe7, 0x91, 0x67, 0x0f, 0x6a, 0x53, 0x5e, 0x62, 0xad, 0xf4, 0x38, 0x93, 0x63, 0x0a, 0x7d, 0xd3};
static const uint8_t e18[] = {0x20, 0x2d, 0x0e, 0xf7, 0xf3, 0x7f, 0x11, 0x45, 0xff, 0xca, 0x1d, 0x0e};
static const uint8_t e19[] = {0xaf, 0xd1, 0x5a, 0x2b, 0x88, 0x12, 0xa6, 0x5a, 0x06, 0x5d, 0x21, 0x5a};
static const uint8_t e20[] = {0xcd, 0x17, 0x66, 0x0a, 0xe8, 0xb6, 0x73, 0xf1, 0x57, 0x05, 0x59};
static const uint8_t e21[] = {0x29, 0xfd, 0x76, 0x34, 0xdd, 0x4d, 0xc5, 0xaf, 0xe4, 0x67, 0x0e, 0x3c, 0xa9};
static const uint8_t e22[] = {0x2a, 0x9c, 0xc6, 0x21, 0x41, 0x6e, 0xe9, 0x50, 0xae, 0x0c, 0xfb, 0x92, 0x14, 0x45};
static const uint8_t e23[] = {0x8b, 0x52, 0x2c, 0x9a, 0xa5, 0xe3, 0xa7, 0xa3, 0x37, 0x44, 0x76, 0xd6, 0x5b, 0x7e};
static const uint8_t e24[] = {0x0b, 0x0a, 0x62, 0xbd, 0x9e, 0x2b, 0xf0, 0xf7};
static const uint8_t e25[] = {0x89, 0x64, 0x04, 0x92, 0xa2, 0x8e, 0xb1, 0xca, 0x9c, 0x1f, 0x71, 0x7e, 0xc7, 0xd7, 0xb7, 0x9d, 0xc2, 0xdc, 0x49, 0xb8, 0x46};
static const uint8_t e26[] = {0x75, 0x1d, 0x28, 0x17, 0x32, 0x19, 0xe7, 0xff, 0xcd, 0xad, 0xbc, 0x33, 0x6c, 0xd5, 0x59, 0x80, 0x4c};
static const uint8_t e27[] = {0x04, 0x4c, 0x3a, 0x0c, 0xa6, 0x56, 0xe7, 0x15, 0x39, 0x5f};
static const uint8_t e28[] = {0x3e, 0x7c, 0x2d, 0x5d, 0x7b};
static const uint8_t e29[] = {0xa0, 0x27, 0xfe, 0x2e, 0x7d, 0xd3};
static const uint8_t e30[] = {0xfe, 0x05, 0x46, 0xc9, 0x22};
static const uint8_t e31[] = {0x4f, 0x13, 0x7a, 0x9f, 0x8f, 0x0c, 0xd4, 0x80, 0x2e};
static const uint8_t e32[] = {0x54, 0xf8, 0x8a, 0xd5, 0xbd, 0x92, 0x90, 0x66, 0x5b, 0xc0, 0x5b, 0x7f};
static const uint8_t e33[] = {0xe8, 0xdb, 0x6c, 0x57, 0xa4};
static const uint8_t e34[] = {0x8e, 0x67, 0x5e, 0x6a, 0x23, 0x53, 0xcf, 0x6f};
static const uint8_t e35[] = {0x3f, 0x37, 0x6b, 0x4f, 0x08, 0x24, 0xc4, 0xe8, 0xf5};
static const uint8_t e36[] = {0xe7, 0xff, 0x8f, 0x49, 0x69, 0x67, 0xaa, 0xdc};
static const uint8_t e37[] = {0x16, 0x2c, 0xb5, 0xe8, 0xc8, 0xa0, 0x48, 0x38};
static const uint8_t e38[] = {0xc2, 0x18, 0xb2, 0x6f, 0x03, 0x11, 0x47, 0x4a};
static const uint8_t e39[] = {0x93, 0x24, 0xe7, 0xe9};
static const uint8_t e40[] = {0x9b, 0xd3, 0x39, 0x06, 0x93, 0x3a, 0x2c};
static const uint8_t e41[] = {0x28, 0xd3, 0xe5, 0xc5, 0x54, 0x72, 0x7f, 0x96, 0x16, 0xca, 0xc6};
static const uint8_t e42[] = {0x46, 0x03, 0x16, 0x14, 0x2a, 0x6a};
static const uint8_t e43[] = {0x75, 0x9c, 0xbb, 0x2c, 0x41, 0xb1, 0xfc, 0x53, 0xba};
static const uint8_t e44[] = {0xd8, 0x6e, 0x52, 0x5c, 0xf7, 0xaa, 0x57};
static const uint8_t e45[] = {0x87, 0x09, 0xfe, 0x64, 0x17, 0xf5, 0x8b, 0xda, 0x52, 0x19};
static const uint8_t e46[] = {0x41, 0x36, 0x01, 0x47, 0x1a, 0x26, 0xa3, 0x98, 0xd7};
static const uint8_t e47[] = {0x69, 0xe4, 0x8f, 0xa7, 0x17, 0x8d};
static const uint8_t e48[] = {0xbb, 0xed, 0xd0, 0x91, 0x6c, 0x27, 0x0c, 0x48, 0x2a};
static const uint8_t e49[] = {0xe0, 0xa1, 0xa4, 0x05, 0xea, 0x13, 0x05, 0xa1};
static const uint8_t e50[] = {0x7a, 0xc8, 0x15, 0xd2};
static const uint8_t e51[] = {0x43, 0xfe, 0x15, 0xb5, 0xda, 0x99, 0x2a, 0x64, 0xef, 0xa8, 0x39, 0xc2};
static const uint8_t e52[] = {0x19, 0xd5, 0x96, 0xfa, 0xe2, 0x2f, 0x0c, 0xdb, 0xff, 0xe7, 0x68};
static const uint8_t e53[] = {0x58, 0xda, 0xcf, 0x2c, 0xa6, 0x6e, 0x21, 0x02};
static const uint8_t e54[] = {0xb5, 0x01, 0xf1, 0xf9, 0x8c, 0x01, 0x69, 0x38, 0x10, 0xe0};
static const uint8_t e55[] = {0xc8, 0xd3, 0x9a, 0x1f, 0xb3, 0x24, 0xbe, 0x4b};

#define CPRISK_OBF_ROW(id) { id##u, e##id, sizeof(e##id) }

static const cprisk_obf_token_ref_t k_dbi_strict_env_rows[] = {
    CPRISK_OBF_ROW(1),  CPRISK_OBF_ROW(2),  CPRISK_OBF_ROW(3),  CPRISK_OBF_ROW(4),
    CPRISK_OBF_ROW(5),  CPRISK_OBF_ROW(6),  CPRISK_OBF_ROW(7),  CPRISK_OBF_ROW(8),
    CPRISK_OBF_ROW(9),  CPRISK_OBF_ROW(10), CPRISK_OBF_ROW(11), CPRISK_OBF_ROW(12),
    CPRISK_OBF_ROW(13), CPRISK_OBF_ROW(14), CPRISK_OBF_ROW(15), CPRISK_OBF_ROW(16),
    CPRISK_OBF_ROW(17), CPRISK_OBF_ROW(18), CPRISK_OBF_ROW(19), CPRISK_OBF_ROW(20),
    CPRISK_OBF_ROW(21), CPRISK_OBF_ROW(22), CPRISK_OBF_ROW(23), CPRISK_OBF_ROW(24),
};

static const cprisk_obf_token_ref_t k_dbi_tokenized_env_rows[] = {
    CPRISK_OBF_ROW(25), CPRISK_OBF_ROW(26), CPRISK_OBF_ROW(27),
};

static const cprisk_obf_token_ref_t k_dbi_env_token_rows[] = {
    CPRISK_OBF_ROW(28), CPRISK_OBF_ROW(29), CPRISK_OBF_ROW(30), CPRISK_OBF_ROW(31),
    CPRISK_OBF_ROW(32), CPRISK_OBF_ROW(33), CPRISK_OBF_ROW(34), CPRISK_OBF_ROW(35),
    CPRISK_OBF_ROW(36), CPRISK_OBF_ROW(37), CPRISK_OBF_ROW(38), CPRISK_OBF_ROW(39),
    CPRISK_OBF_ROW(40), CPRISK_OBF_ROW(41), CPRISK_OBF_ROW(42), CPRISK_OBF_ROW(43),
    CPRISK_OBF_ROW(44), CPRISK_OBF_ROW(45), CPRISK_OBF_ROW(46), CPRISK_OBF_ROW(47),
    CPRISK_OBF_ROW(48), CPRISK_OBF_ROW(49), CPRISK_OBF_ROW(50), CPRISK_OBF_ROW(51),
    CPRISK_OBF_ROW(52),
};

static const cprisk_obf_token_ref_t k_dbi_image_rows[] = {
    CPRISK_OBF_ROW(28), CPRISK_OBF_ROW(29), CPRISK_OBF_ROW(31), CPRISK_OBF_ROW(32),
    CPRISK_OBF_ROW(33), CPRISK_OBF_ROW(34), CPRISK_OBF_ROW(35), CPRISK_OBF_ROW(36),
    CPRISK_OBF_ROW(37), CPRISK_OBF_ROW(38), CPRISK_OBF_ROW(39), CPRISK_OBF_ROW(40),
    CPRISK_OBF_ROW(41), CPRISK_OBF_ROW(42), CPRISK_OBF_ROW(44), CPRISK_OBF_ROW(45),
    CPRISK_OBF_ROW(46), CPRISK_OBF_ROW(47), CPRISK_OBF_ROW(48), CPRISK_OBF_ROW(49),
    CPRISK_OBF_ROW(50), CPRISK_OBF_ROW(51), CPRISK_OBF_ROW(52),
};

static const cprisk_obf_token_ref_t k_dbi_thread_rows[] = {
    CPRISK_OBF_ROW(31), CPRISK_OBF_ROW(33), CPRISK_OBF_ROW(53), CPRISK_OBF_ROW(38),
    CPRISK_OBF_ROW(34), CPRISK_OBF_ROW(36), CPRISK_OBF_ROW(37), CPRISK_OBF_ROW(28),
    CPRISK_OBF_ROW(54), CPRISK_OBF_ROW(55), CPRISK_OBF_ROW(39), CPRISK_OBF_ROW(41),
    CPRISK_OBF_ROW(44), CPRISK_OBF_ROW(47), CPRISK_OBF_ROW(50),
};

static uint32_t cprisk_detect_dbi_env_markers_i(int *hit_count_out) {
    int hit_count = 0;
    uint32_t flags = 0u;

    for (size_t i = 0u; i < sizeof(k_dbi_strict_env_rows) / sizeof(k_dbi_strict_env_rows[0]); i++) {
        if (cprisk_getenv_obf_nonempty_i(&k_dbi_strict_env_rows[i])) {
            flags |= CPRISK_DBI_MARKER_ENV;
            hit_count++;
        }
    }

    for (size_t i = 0u; i < sizeof(k_dbi_tokenized_env_rows) / sizeof(k_dbi_tokenized_env_rows[0]); i++) {
        char key[64];
        memset(key, 0, sizeof(key));
        if (cprisk_obf_decode_sha256_tag(
                CPRISK_OBF_TAG_DOMAIN_SIGNAL_DBI,
                k_dbi_tokenized_env_rows[i].key_id,
                k_dbi_tokenized_env_rows[i].enc,
                k_dbi_tokenized_env_rows[i].enc_len,
                key,
                sizeof(key)) != 0) {
            cprisk_secure_zero(key, sizeof(key));
            continue;
        }
        const char *value = getenv(key);
        cprisk_secure_zero(key, sizeof(key));
        if (!value || value[0] == '\0') {
            continue;
        }
        if (cprisk_contains_any_obf_token_i(
                value, k_dbi_env_token_rows, sizeof(k_dbi_env_token_rows) / sizeof(k_dbi_env_token_rows[0]))) {
            flags |= CPRISK_DBI_MARKER_ENV;
            hit_count++;
        }
    }

    if (hit_count_out) {
        *hit_count_out = hit_count;
    }
    return flags;
}

/*
 * Bounded scan of the entire environ table for DBI/QBDI substring markers.
 * Catches renamed or custom env vars that strict-key checks miss.
 */
static uint32_t cprisk_detect_dbi_environ_scan_i(int *hit_count_out) {
    int hit_count = 0;
    uint32_t flags = 0u;

    char ***penv = _NSGetEnviron();
    if (!penv || *penv == NULL) {
        if (hit_count_out) {
            *hit_count_out = 0;
        }
        return 0u;
    }

    for (char **e = *penv; *e != NULL; e++) {
        const char *line = *e;
        if (!line || line[0] == '\0') {
            continue;
        }
        size_t walk = 0u;
        while (line[walk] != '\0' && walk < 4096u) {
            walk++;
        }
        if (walk >= 4096u) {
            continue;
        }
        if (cprisk_contains_any_obf_token_i(
                line,
                k_dbi_env_token_rows,
                sizeof(k_dbi_env_token_rows) / sizeof(k_dbi_env_token_rows[0]))) {
            flags |= CPRISK_DBI_MARKER_ENVIRON_SCAN;
            hit_count++;
            break;
        }
    }

    if (hit_count_out) {
        *hit_count_out = hit_count;
    }
    return flags;
}

static uint32_t cprisk_detect_dbi_image_markers_i(int *hit_count_out) {
    uint32_t flags = 0u;
    int hit_count = 0;
    const uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0u; i < image_count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name || name[0] == '\0') {
            continue;
        }
        if (cprisk_contains_any_obf_token_i(
                name, k_dbi_image_rows, sizeof(k_dbi_image_rows) / sizeof(k_dbi_image_rows[0]))) {
            flags |= CPRISK_DBI_MARKER_IMAGE;
            hit_count++;
        }
    }

    if (hit_count_out) {
        *hit_count_out = hit_count;
    }
    return flags;
}

static uint32_t cprisk_detect_dbi_thread_markers_i(int *hit_count_out) {
    uint32_t flags = 0u;
    int hit_count = 0;
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    if (task_threads(mach_task_self(), &threads, &thread_count) != KERN_SUCCESS) {
        if (hit_count_out) {
            *hit_count_out = 0;
        }
        return 0u;
    }

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        char name[64];
        memset(name, 0, sizeof(name));
        pthread_t pthread_handle = pthread_from_mach_thread_np(threads[i]);
        if ((uintptr_t)pthread_handle == 0u) {
            continue;
        }
        if (pthread_getname_np(pthread_handle, name, sizeof(name)) != 0 || name[0] == '\0') {
            continue;
        }
        if (cprisk_contains_any_obf_token_i(
                name, k_dbi_thread_rows, sizeof(k_dbi_thread_rows) / sizeof(k_dbi_thread_rows[0]))) {
            flags |= CPRISK_DBI_MARKER_THREAD;
            hit_count++;
        }
    }

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(
        mach_task_self(),
        (vm_address_t)threads,
        sizeof(thread_act_t) * thread_count);

    if (hit_count_out) {
        *hit_count_out = hit_count;
    }
    return flags;
}

/*
 * Anonymous VM user tags used for MAP_ANON regions on Darwin (see vm_statistics.h VM_MEMORY_*).
 * Matches CloudPhoneRiskKit RWXMemoryScanner anonymousUserTags (240–245).
 */
static int cprisk_vm_user_tag_is_anonymous_i(unsigned int user_tag) {
    return (user_tag >= 240u && user_tag <= 245u) ? 1 : 0;
}

static uint32_t cprisk_detect_dbi_execmem_i(int *hit_count_out) {
    uint32_t flags = 0u;
    int exec_write_hits = 0;
    int anon_exec_slab_hits = 0;
    int foreign_mapped_exec_hits = 0;
    cprisk_vm_region_address_t addr = CPRISK_VM_REGION_MIN_ADDRESS_I;
    uint32_t scanned_regions = 0u;
    const uint64_t start_ns = cprisk_monotonic_now_ns_i();

    while (1) {
        if (cprisk_watchdog_probe_should_stop()) {
            break;
        }
        if (scanned_regions >= CPRISK_DBI_EXECMEM_REGION_BUDGET) {
            break;
        }
        if (start_ns != 0u) {
            const uint64_t now_ns = cprisk_monotonic_now_ns_i();
            if (now_ns > start_ns &&
                now_ns - start_ns >= CPRISK_DBI_EXECMEM_TIME_BUDGET_NS) {
                break;
            }
        }
        cprisk_vm_region_size_t region_size = 0u;
        natural_t depth = 0u;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = cprisk_vm_region_recurse_i(
            mach_task_self(),
            &addr,
            &region_size,
            &depth,
            (vm_region_recurse_info_t)&info,
            &info_count
        );
        if (kr != KERN_SUCCESS) {
            break;
        }
        scanned_regions += 1u;
        if (info.is_submap) {
            depth += 1u;
            continue;
        }
        const vm_prot_t prot = info.protection;
        const int has_x = (prot & VM_PROT_EXECUTE) != 0;
        const int has_w = (prot & VM_PROT_WRITE) != 0;

        if (has_x && has_w) {
            flags |= CPRISK_DBI_MARKER_EXEC_WRITE;
            exec_write_hits++;
        }

        /*
         * File-backed or non-anonymous RX mapping whose sample points all fall outside
         * dyld-reported Mach-O segments (whitelist diff vs task VM).
         */
        if (has_x && !has_w && region_size > 0u &&
            !cprisk_vm_user_tag_is_anonymous_i(info.user_tag)) {
            const uintptr_t a0 = (uintptr_t)addr;
            const uintptr_t a1 = a0 + (uintptr_t)(region_size >> 1);
            const uintptr_t a2 = a0 + (uintptr_t)(region_size - 1u);
            if (cprisk_addr_in_any_image_executable((const void *)a0) == 0 &&
                cprisk_addr_in_any_image_executable((const void *)a1) == 0 &&
                cprisk_addr_in_any_image_executable((const void *)a2) == 0) {
                flags |= CPRISK_DBI_MARKER_FOREIGN_MAPPED_EXEC;
                foreign_mapped_exec_hits++;
            }
        }

        /*
         * Stalker/Gum often materialize trampolines or finalized trace slabs as private
         * anonymous RX (W^X) mappings outside any dyld image — distinct from generic RWX.
         */
        if (has_x && !has_w && region_size > 0u &&
            region_size <= (cprisk_vm_region_size_t)(512u * 1024u) &&
            cprisk_vm_user_tag_is_anonymous_i(info.user_tag) != 0 &&
            (info.share_mode == 0u || info.share_mode == 3u) &&
            cprisk_addr_in_any_image_executable((const void *)(uintptr_t)addr) == 0) {
            flags |= CPRISK_DBI_MARKER_ANON_EXEC_SLAB;
            anon_exec_slab_hits++;
        }

        if (exec_write_hits >= 4 || anon_exec_slab_hits >= 1 || foreign_mapped_exec_hits >= 1) {
            break;
        }

        if (region_size == 0u || addr > UINT64_MAX - region_size) {
            break;
        }
        addr += region_size;
    }

    const int hit_total = exec_write_hits + anon_exec_slab_hits + foreign_mapped_exec_hits;
    if (hit_count_out) {
        *hit_count_out = hit_total;
    }
    return flags;
}

int cprisk_vm_probe_anonymous_exec_outside_images(void) {
    int hits = 0;
    const uint32_t f = cprisk_detect_dbi_execmem_i(&hits);
    return (f & CPRISK_DBI_MARKER_ANON_EXEC_SLAB) != 0u ? 1 : 0;
}

static uint64_t cprisk_mul_u64_saturating_i(uint64_t a, uint64_t b) {
    if (a == 0u || b == 0u) {
        return 0u;
    }
    if (a > UINT64_MAX / b) {
        return UINT64_MAX;
    }
    return a * b;
}

int cprisk_detect_dbi_markers(void) {
    int env_hits = 0;
    int image_hits = 0;
    int thread_hits = 0;
    int environ_scan_hits = 0;
    int execmem_hits = 0;

    uint32_t marker_flags = 0u;
    if (_dyld_image_count() < 6u) {
        marker_flags |= CPRISK_DBI_MARKER_DYLD_IMAGE_COUNT_LOW;
    }
    marker_flags |= cprisk_detect_dbi_env_markers_i(&env_hits);
    marker_flags |= cprisk_detect_dbi_environ_scan_i(&environ_scan_hits);
    marker_flags |= cprisk_detect_dbi_image_markers_i(&image_hits);
    marker_flags |= cprisk_detect_dbi_thread_markers_i(&thread_hits);
    marker_flags |= cprisk_detect_dbi_execmem_i(&execmem_hits);

    /*
     * Cross-correlate Mach thread PCs outside any image with anonymous exec / RWX JIT surfaces.
     * This matches Frida Stalker-style "foreign code" threads feeding off Gum slabs.
     */
    if (cprisk_detect_suspicious_threads() > 0 &&
        (marker_flags & (CPRISK_DBI_MARKER_ANON_EXEC_SLAB | CPRISK_DBI_MARKER_EXEC_WRITE)) != 0u) {
        marker_flags |= CPRISK_DBI_MARKER_STALKER_CORREL;
    }

    int correl_hit = 0;
    if ((marker_flags & CPRISK_DBI_MARKER_STALKER_CORREL) != 0u) {
        correl_hit = 1;
    }

    const int total_hits =
        env_hits + environ_scan_hits + image_hits + thread_hits + execmem_hits + correl_hit;
    atomic_store(&s_dbi_last_marker_flags, marker_flags);
    atomic_store(&s_dbi_last_hit_count, total_hits > 0 ? (uint32_t)total_hits : 0u);
    return total_hits;
}

uint32_t cprisk_get_last_dbi_marker_flags(void) {
    return atomic_load(&s_dbi_last_marker_flags);
}

int cprisk_get_last_dbi_marker_hit_count(void) {
    return (int)atomic_load(&s_dbi_last_hit_count);
}

uint32_t cprisk_get_last_timing_anomaly_flags(void) {
    uint32_t flags = atomic_load(&s_timing_last_anomaly_flags);
    const uint32_t crypto = cprisk_crypto_trace_peek_flags_i();
    if ((crypto & CPRISK_CRYPTO_TRACE_FLAG_SLOW) != 0u) {
        flags |= CPRISK_TIMING_ANOMALY_CRYPTO_TRACE;
    }
    if ((crypto & CPRISK_CRYPTO_TRACE_FLAG_CNT_MACH_SKEW) != 0u) {
        flags |= CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_SKEW;
    }
    if ((crypto & CPRISK_CRYPTO_TRACE_FLAG_INVARIANT_FAIL) != 0u) {
        flags |= CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_INVARIANT;
    }
    return flags;
}

uint64_t cprisk_get_last_timing_probe_median_ns(void) {
    return atomic_load(&s_timing_last_median_ns);
}

uint64_t cprisk_get_last_timing_probe_max_ns(void) {
    const uint64_t probe_max = atomic_load(&s_timing_last_max_ns);
    const uint64_t crypto_max = cprisk_crypto_trace_last_ns_i();
    return probe_max > crypto_max ? probe_max : crypto_max;
}

uint64_t cprisk_get_last_timing_probe_threshold_ns(void) {
    const uint64_t probe_threshold = atomic_load(&s_timing_last_threshold_ns);
    const uint64_t crypto_threshold = cprisk_crypto_trace_threshold_ns_i();
    return probe_threshold > crypto_threshold ? probe_threshold : crypto_threshold;
}

static void cprisk_reset_exception_delivery_probe_state_i(void) {
    atomic_store(&s_exception_delivery_probe_armed, 0u);
    atomic_store(&s_exception_delivery_probe_handled, 0u);
    atomic_store(&s_exception_delivery_probe_start_ns, 0u);
    atomic_store(&s_exception_delivery_probe_last_ns, 0u);
}

static void cprisk_sigtrap_handler_i(int sig) {
    (void)sig;
    s_sigtrap_flag = 1;
    siglongjmp(s_trap_jmpbuf, 1);
}

static void cprisk_exception_delivery_sigtrap_handler_i(int sig) {
    (void)sig;
    s_exception_delivery_sigtrap = 1;
    siglongjmp(s_exception_delivery_jmpbuf, 1);
}

int cprisk_probe_debugger_via_signal(void) {
    s_sigtrap_flag = 0;

    struct sigaction sa, prev;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cprisk_sigtrap_handler_i;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGTRAP, &sa, &prev);

    if (sigsetjmp(s_trap_jmpbuf, 1) == 0) {
        /*
         * BRK #0xC0DE triggers EXC_BREAKPOINT → SIGTRAP.
         * Debugger intercepts the Mach exception first; if present,
         * our signal handler never fires and s_sigtrap_flag stays 0.
         * The immediate 0xC0DE distinguishes this from normal BRK traps
         * so the project's Mach exception handler can let it pass through.
         */
        __asm__ volatile("brk #0xC0DE");
    }

    sigaction(SIGTRAP, &prev, NULL);

    return s_sigtrap_flag ? 0 : 1;
}

int cprisk_exception_handler_should_passthrough_brk_imm(uint16_t brk_imm) {
    return brk_imm == (uint16_t)CPRISK_BRK_IMM_SIGNAL_PROBE;
}

int cprisk_exception_handler_consume_reserved_brk_imm(uint16_t brk_imm) {
    if (brk_imm != (uint16_t)CPRISK_BRK_IMM_EXCEPTION_DELIVERY_PROBE) {
        return 0;
    }

    const int armed = atomic_load(&s_exception_delivery_probe_armed) != 0u;
    uint64_t elapsed_ns = 0u;
    const uint64_t start_ns = atomic_load(&s_exception_delivery_probe_start_ns);
    if (armed && start_ns != 0u) {
        const uint64_t now_ns = cprisk_monotonic_now_ns_i();
        if (now_ns >= start_ns) {
            elapsed_ns = now_ns - start_ns;
        }
    }

    atomic_store(&s_exception_delivery_probe_last_ns, elapsed_ns);
    atomic_store(&s_exception_delivery_probe_handled, armed ? 1u : 0u);
    atomic_store(&s_exception_delivery_probe_armed, 0u);
    return 1;
}

uint64_t cprisk_get_last_exception_delivery_probe_ns(void) {
    return atomic_load(&s_exception_delivery_probe_last_ns);
}

int cprisk_get_last_exception_delivery_probe_handled(void) {
    return atomic_load(&s_exception_delivery_probe_handled) != 0u ? 1 : 0;
}

int cprisk_probe_exception_delivery_timeout(void) {
    cprisk_reset_exception_delivery_probe_state_i();
    s_exception_delivery_sigtrap = 0;

    struct sigaction sa, prev;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cprisk_exception_delivery_sigtrap_handler_i;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGTRAP, &sa, &prev);

    if (sigsetjmp(s_exception_delivery_jmpbuf, 1) == 0) {
        atomic_store(&s_exception_delivery_probe_start_ns, cprisk_monotonic_now_ns_i());
        atomic_store(&s_exception_delivery_probe_armed, 1u);
        __asm__ volatile("brk #0xC0DF");
    } else {
        const uint64_t start_ns = atomic_load(&s_exception_delivery_probe_start_ns);
        uint64_t elapsed_ns = 0u;
        if (start_ns != 0u) {
            const uint64_t now_ns = cprisk_monotonic_now_ns_i();
            if (now_ns >= start_ns) {
                elapsed_ns = now_ns - start_ns;
            }
        }
        atomic_store(&s_exception_delivery_probe_last_ns, elapsed_ns);
        atomic_store(&s_exception_delivery_probe_armed, 0u);
        atomic_store(&s_exception_delivery_probe_handled, 0u);
    }

    sigaction(SIGTRAP, &prev, NULL);

    const uint64_t elapsed_ns = atomic_load(&s_exception_delivery_probe_last_ns);
    const int handled = atomic_load(&s_exception_delivery_probe_handled) != 0u;
    return (!handled || elapsed_ns > CPRISK_EXCEPTION_DELIVERY_TIMEOUT_NS) ? 1 : 0;
}

/* ── (b) Thread exception-port detection ──────────────────────────── */

static mach_port_t cprisk_expected_exception_port_i(void) {
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    mach_port_t expected = MACH_PORT_NULL;

    const exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS;
    kern_return_t kr = task_get_exception_ports(
        mach_task_self(),
        mask,
        masks,
        &count,
        ports,
        behaviors,
        flavors
    );
    if (kr == KERN_SUCCESS) {
        for (mach_msg_type_number_t i = 0; i < count; i++) {
            if ((masks[i] & EXC_MASK_BREAKPOINT) != 0u) {
                expected = ports[i];
            }
            if (ports[i] != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), ports[i]);
            }
        }
    }
    return expected;
}

int cprisk_detect_thread_exception_ports(void) {
    const mach_port_t expected_port = cprisk_expected_exception_port_i();
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    const exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS;

    if (task_threads(mach_task_self(), &threads, &thread_count) != KERN_SUCCESS) {
        return 0;
    }

    int mismatched = 0;
    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        exception_mask_t masks[EXC_TYPES_COUNT];
        mach_port_t ports[EXC_TYPES_COUNT];
        exception_behavior_t behaviors[EXC_TYPES_COUNT];
        thread_state_flavor_t flavors[EXC_TYPES_COUNT];
        mach_msg_type_number_t count = EXC_TYPES_COUNT;

        kern_return_t kr = thread_get_exception_ports(
            threads[i],
            mask,
            masks,
            &count,
            ports,
            behaviors,
            flavors
        );
        if (kr != KERN_SUCCESS) {
            continue;
        }

        int thread_mismatch = 0;
        for (mach_msg_type_number_t j = 0; j < count; j++) {
            if ((masks[j] & EXC_MASK_BREAKPOINT) == 0u) {
                if (ports[j] != MACH_PORT_NULL) {
                    mach_port_deallocate(mach_task_self(), ports[j]);
                }
                continue;
            }
            if (ports[j] != MACH_PORT_NULL &&
                (expected_port == MACH_PORT_NULL || ports[j] != expected_port)) {
                thread_mismatch = 1;
            }
            if (ports[j] != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), ports[j]);
            }
        }

        if (thread_mismatch) {
            mismatched++;
        }
    }

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(),
                  (vm_address_t)threads,
                  sizeof(thread_act_t) * thread_count);

    return mismatched;
}

/* ── (b) Hardware breakpoint detection ────────────────────────────── */

int cprisk_detect_hardware_breakpoints(void) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;

    if (task_threads(mach_task_self(), &threads, &thread_count) != KERN_SUCCESS) {
        return 0;
    }

    int detected = 0;

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        arm_debug_state64_t dbg;
        mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
        memset(&dbg, 0, sizeof(dbg));

        kern_return_t kr = thread_get_state(
            threads[i], ARM_DEBUG_STATE64, (thread_state_t)&dbg, &count);

        if (kr == KERN_SUCCESS) {
            for (int j = 0; j < 16; j++) {
                if (dbg.__bcr[j] & 1u) detected++;
                if (dbg.__wcr[j] & 1u) detected++;
            }
        }
    }

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(),
                  (vm_address_t)threads,
                  sizeof(thread_act_t) * thread_count);

    return detected;
}

/* ── (c) Software breakpoint scan ─────────────────────────────────── */

int cprisk_scan_software_breakpoints(const void *func_ptr, size_t size) {
    if (!func_ptr || size < 4) return 0;

    const uint32_t *start = (const uint32_t *)func_ptr;
    size_t word_count = size / 4;
    int found = 0;

    /*
     * ARM64 BRK encoding: 0xD4200000 | (imm16 << 5)
     * Exclude our reserved BRK probes to avoid self-detection.
     */
    const uint32_t signal_probe_brk =
        0xD4200000u | ((uint32_t)CPRISK_BRK_IMM_SIGNAL_PROBE << 5);
    const uint32_t exception_delivery_brk =
        0xD4200000u | ((uint32_t)CPRISK_BRK_IMM_EXCEPTION_DELIVERY_PROBE << 5);
    const uint32_t runtime_gate_brk =
        0xD4200000u | ((uint32_t)CPRISK_BRK_IMM_RUNTIME_GATE << 5);

    for (size_t i = 0; i < word_count; i++) {
        uint32_t instr = start[i];
        if ((instr & 0xFFE00000u) == 0xD4200000u &&
            instr != signal_probe_brk &&
            instr != exception_delivery_brk &&
            instr != runtime_gate_brk) {
            found++;
        }
    }

    return found;
}

struct cprisk_text_exec_section_i {
    const uint8_t *base;
    size_t size;
};

static size_t cprisk_collect_text_exec_sections_i(
    const struct mach_header_64 *hdr,
    struct cprisk_text_exec_section_i *out_sections,
    size_t out_capacity
) {
    if (!hdr || !out_sections || out_capacity == 0u) {
        return 0u;
    }

    const intptr_t slide = cprisk_compute_slide(hdr);
    const uint8_t *cursor = (const uint8_t *)(hdr + 1);
    const uint8_t *end = cursor + hdr->sizeofcmds;
    size_t count = 0u;

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (cursor + sizeof(struct load_command) > end) {
            break;
        }
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize == 0u || cursor + lc->cmdsize > end) {
            break;
        }
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cursor;
            const size_t seg_header_size = sizeof(struct segment_command_64);
            const size_t sec_table_size =
                (size_t)seg->nsects * sizeof(struct section_64);
            if (sec_table_size / sizeof(struct section_64) != (size_t)seg->nsects ||
                seg_header_size + sec_table_size > (size_t)lc->cmdsize) {
                cursor += lc->cmdsize;
                continue;
            }
            if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                const struct section_64 *sections =
                    (const struct section_64 *)(cursor + sizeof(*seg));
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    const struct section_64 *sec = &sections[s];
                    const uint32_t attrs = sec->flags & SECTION_ATTRIBUTES_USR;
                    const int executable =
                        (attrs & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)) != 0u ||
                        strncmp(sec->sectname, "__text", 16) == 0;
                    if (!executable || sec->size < 4u) {
                        continue;
                    }
                    if (count >= out_capacity) {
                        return count;
                    }
                    out_sections[count].base =
                        (const uint8_t *)((uintptr_t)sec->addr + (uintptr_t)slide);
                    out_sections[count].size = (size_t)sec->size;
                    count++;
                }
            }
        }
        cursor += lc->cmdsize;
    }

    return count;
}

int cprisk_scan_software_breakpoints_randomized_text(
    size_t sample_windows,
    size_t window_size
) {
    if (sample_windows == 0u) {
        sample_windows = CPRISK_SOFTWARE_BP_RANDOM_DEFAULT_WINDOWS;
    }
    if (window_size < 16u) {
        window_size = CPRISK_SOFTWARE_BP_RANDOM_DEFAULT_WINDOW_BYTES;
    }

    const struct mach_header_64 *hdr =
        cprisk_find_own_header((const void *)cprisk_scan_software_breakpoints_randomized_text);
    if (!hdr) {
        return 0;
    }

    struct cprisk_text_exec_section_i sections[32];
    const size_t section_count =
        cprisk_collect_text_exec_sections_i(hdr, sections, sizeof(sections) / sizeof(sections[0]));
    if (section_count == 0u) {
        return 0;
    }

    uint64_t rng = cprisk_random_u64_i() ^ (uint64_t)(uintptr_t)hdr;
    const size_t start_idx = (size_t)(cprisk_prng_next_i(&rng) % section_count);
    size_t windows = sample_windows;
    if (windows > section_count * 4u) {
        windows = section_count * 4u;
    }

    int found = 0;
    for (size_t i = 0; i < windows; i++) {
        const size_t idx = (start_idx + i) % section_count;
        const uint8_t *base = sections[idx].base;
        size_t sec_size = sections[idx].size;
        if (!base || sec_size < 4u) {
            continue;
        }

        size_t sample_size = window_size;
        if (sample_size > sec_size) {
            sample_size = sec_size;
        }

        size_t offset = 0u;
        const size_t max_offset = sec_size - sample_size;
        if (max_offset > 0u) {
            offset = (size_t)(cprisk_prng_next_i(&rng) % (max_offset + 1u));
        }

        offset &= ~(size_t)0x3u;
        if (offset >= sec_size) {
            continue;
        }
        sample_size = sec_size - offset < sample_size ? (sec_size - offset) : sample_size;
        sample_size &= ~(size_t)0x3u;
        if (sample_size < 4u) {
            continue;
        }

        found += cprisk_scan_software_breakpoints(base + offset, sample_size);
    }

    return found;
}

/* ── (d) TTY debug detection ──────────────────────────────────────── */

int cprisk_detect_tty_debug(void) {
    if (!isatty(STDOUT_FILENO)) return 0;

    char path[MAXPATHLEN];
    memset(path, 0, sizeof(path));

    if (fcntl(STDOUT_FILENO, F_GETPATH, path) == -1) return 0;

    if (path[0] == '/' && path[1] == 'd' && path[2] == 'e' &&
        path[3] == 'v' && path[4] == '/') {
        const char *name = path + 5;
        if ((name[0] == 't' && name[1] == 't' && name[2] == 'y' && name[3] == 's') ||
            (name[0] == 'p' && name[1] == 't' && name[2] == 's')) {
            return 1;
        }
    }

    return 0;
}

/* ── (e) csops CS_DEBUGGED check ──────────────────────────────────── */

#ifndef CS_OPS_STATUS
#define CS_OPS_STATUS 0
#endif

#ifndef CS_DEBUGGED
#define CS_DEBUGGED 0x10000000u
#endif

int cprisk_csops_debug_check(void) {
    uint32_t flags = 0;
    pid_t pid = cprisk_getpid_direct();
    int err = 0;

    if (cprisk_csops_direct(pid, CS_OPS_STATUS, &flags, sizeof(flags), &err) != 0)
        return 0;

    return (flags & CS_DEBUGGED) ? 1 : 0;
}

int cprisk_csops_status_flags(uint32_t *flags_out, int *error_out) {
    uint32_t flags = 0u;
    pid_t pid = cprisk_getpid_direct();

    if (flags_out != NULL) {
        *flags_out = 0u;
    }
    if (error_out != NULL) {
        *error_out = 0;
    }

    int err = 0;
    if (cprisk_csops_direct(pid, CS_OPS_STATUS, &flags, sizeof(flags), &err) != 0) {
        if (error_out != NULL) {
            *error_out = err;
        }
        return -1;
    }

    if (flags_out != NULL) {
        *flags_out = flags;
    }
    return 0;
}

/* ── (f) Single-step timing detection ─────────────────────────────── */

static uint64_t cprisk_single_step_workload_i(void) {
    volatile uint64_t acc = 0x9E3779B97F4A7C15ULL;
    for (int i = 0; i < 320; i++) {
        acc ^= ((uint64_t)i * 0x100000001B3ULL) + 0x9E37u;
        acc = (acc << 5u) | (acc >> 59u);
    }
    return acc;
}

static uint64_t cprisk_single_step_measure_once_i(void) {
    const uint64_t t0 = cprisk_monotonic_now_ns_i();
    const uint64_t acc = cprisk_single_step_workload_i();
    (void)acc;
    const uint64_t t1 = cprisk_monotonic_now_ns_i();
    if (t1 < t0) {
        return 0u;
    }
    return t1 - t0;
}

static uint64_t cprisk_single_step_threshold_from_baseline_i(uint64_t baseline_ns) {
    if (baseline_ns == 0u) {
        return CPRISK_SINGLE_STEP_DEFAULT_THRESHOLD_NS;
    }
    uint64_t threshold = baseline_ns * CPRISK_SINGLE_STEP_THRESHOLD_MULTIPLIER;
    if (threshold / CPRISK_SINGLE_STEP_THRESHOLD_MULTIPLIER != baseline_ns) {
        threshold = UINT64_MAX;
    }
    if (threshold < CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS) {
        threshold = CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS;
    }
    return threshold;
}

static void cprisk_single_step_calibrate_if_needed_i(void) {
    if (atomic_load(&s_single_step_calibrated) != 0u) {
        return;
    }

    while (atomic_flag_test_and_set(&s_single_step_calibration_lock)) {
    }

    if (atomic_load(&s_single_step_calibrated) == 0u) {
        uint64_t samples[CPRISK_SINGLE_STEP_CALIBRATION_SAMPLES];
        memset(samples, 0, sizeof(samples));
        for (size_t i = 0; i < CPRISK_SINGLE_STEP_CALIBRATION_SAMPLES; i++) {
            samples[i] = cprisk_single_step_measure_once_i();
        }

        for (size_t i = 1; i < CPRISK_SINGLE_STEP_CALIBRATION_SAMPLES; i++) {
            uint64_t key = samples[i];
            size_t j = i;
            while (j > 0u && samples[j - 1u] > key) {
                samples[j] = samples[j - 1u];
                j--;
            }
            samples[j] = key;
        }

        uint64_t baseline =
            samples[CPRISK_SINGLE_STEP_CALIBRATION_SAMPLES / 2u];
        if (baseline == 0u) {
            baseline = CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS / 2u;
        }

        atomic_store(&s_single_step_baseline_ns, baseline);
        atomic_store(&s_single_step_threshold_ns,
                     cprisk_single_step_threshold_from_baseline_i(baseline));
        atomic_store(&s_single_step_calibrated, 1u);
    }

    atomic_flag_clear(&s_single_step_calibration_lock);
}

static uint64_t cprisk_add_u64_saturating_i(uint64_t a, uint64_t b) {
    if (UINT64_MAX - a < b) {
        return UINT64_MAX;
    }
    return a + b;
}

static uint64_t cprisk_cntpct_delta_ns_i(uint64_t t0, uint64_t t1) {
#if CPRISK_TIMING_CNTPCT_AVAILABLE
    static uint64_t s_cntfrq = 0u;
    if (s_cntfrq == 0u) {
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(s_cntfrq));
    }
    if (s_cntfrq == 0u || t1 < t0) {
        return 0u;
    }
    const uint64_t dt = t1 - t0;
    return (dt / s_cntfrq) * 1000000000ull +
           ((dt % s_cntfrq) * 1000000000ull) / s_cntfrq;
#else
    (void)t0;
    (void)t1;
    return 0u;
#endif
}

static uint64_t cprisk_u64_abs_diff_i(uint64_t a, uint64_t b) {
    return a > b ? a - b : b - a;
}

static uint32_t cprisk_clock_crosscheck_i(uint64_t median_ref_ns) {
#if CPRISK_TIMING_CNTPCT_AVAILABLE
    static uint64_t s_cntfrq_chk = 0u;
    if (s_cntfrq_chk == 0u) {
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(s_cntfrq_chk));
    }
    if (s_cntfrq_chk == 0u) {
        return 0u;
    }

    uint64_t ct0 = 0u;
    uint64_t ct1 = 0u;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(ct0));
    const uint64_t ma0 = mach_absolute_time();
    struct timespec ts0;
    clock_gettime(CLOCK_MONOTONIC, &ts0);
    const uint64_t ck0 =
        (uint64_t)ts0.tv_sec * 1000000000ull + (uint64_t)ts0.tv_nsec;

    for (volatile int spin = 0; spin < 96; spin++) {
        (void)0;
    }

    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(ct1));
    const uint64_t ma1 = mach_absolute_time();
    struct timespec ts1;
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    const uint64_t ck1 =
        (uint64_t)ts1.tv_sec * 1000000000ull + (uint64_t)ts1.tv_nsec;

    const uint64_t dc = cprisk_cntpct_delta_ns_i(ct0, ct1);
    uint64_t dm = 0u;
    if (ma1 >= ma0) {
        dm = cprisk_mach_abs_to_ns_i(ma1 - ma0);
    } else {
        dm = cprisk_mach_abs_to_ns_i(ma0 - ma1);
    }
    const uint64_t dck = cprisk_u64_abs_diff_i(ck0, ck1);

    const uint64_t skew_cm = cprisk_u64_abs_diff_i(dc, dm);
    const uint64_t skew_mk = cprisk_u64_abs_diff_i(dm, dck);
    const uint64_t skew_ck = cprisk_u64_abs_diff_i(dc, dck);

    uint64_t thresh_ns = 5000000ull;
    if (median_ref_ns > 2000000ull) {
        thresh_ns = median_ref_ns / 4u;
        if (thresh_ns < 4000000ull) {
            thresh_ns = 4000000ull;
        }
        if (thresh_ns > 30000000ull) {
            thresh_ns = 30000000ull;
        }
    }

    if (skew_cm > thresh_ns || skew_mk > thresh_ns || skew_ck > thresh_ns) {
        return CPRISK_TIMING_ANOMALY_CLOCK_SKEW;
    }
#else
    (void)median_ref_ns;
#endif
    return 0u;
}

/*
 * Compare elapsed time for the fixed arithmetic workload as seen by CNTPCT_EL0
 * vs mach_absolute_time. Pure virtualization / DBI time hooks may desynchronize
 * the two (complements CPRISK_TIMING_ANOMALY_CLOCK_SKEW short-spin check).
 */
static uint32_t cprisk_dual_clock_workload_skew_i(void) {
#if CPRISK_TIMING_CNTPCT_AVAILABLE
    uint64_t c0 = 0u;
    uint64_t c1 = 0u;
    const uint64_t m0 = mach_absolute_time();
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(c0));
    (void)cprisk_single_step_workload_i();
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(c1));
    const uint64_t m1 = mach_absolute_time();

    const uint64_t d_cnt_ns = cprisk_cntpct_delta_ns_i(c0, c1);
    uint64_t d_mach_ns = 0u;
    if (m1 >= m0) {
        d_mach_ns = cprisk_mach_abs_to_ns_i(m1 - m0);
    } else {
        d_mach_ns = cprisk_mach_abs_to_ns_i(m0 - m1);
    }

    const uint64_t dmax = d_cnt_ns > d_mach_ns ? d_cnt_ns : d_mach_ns;
    if (dmax < 8000u) {
        return 0u;
    }
    const uint64_t skew_ns = cprisk_u64_abs_diff_i(d_cnt_ns, d_mach_ns);
    if (skew_ns > dmax / 4u) {
        return CPRISK_TIMING_ANOMALY_DUAL_CLOCK_DRIFT;
    }
#endif
    return 0u;
}

static void cprisk_sort_u64_samples_i(uint64_t *samples, size_t count) {
    if (!samples || count <= 1u) {
        return;
    }
    for (size_t i = 1u; i < count; i++) {
        uint64_t key = samples[i];
        size_t j = i;
        while (j > 0u && samples[j - 1u] > key) {
            samples[j] = samples[j - 1u];
            j--;
        }
        samples[j] = key;
    }
}

static uint32_t cprisk_timing_probe_eval_i(
    uint64_t *median_ns_out,
    uint64_t *max_ns_out,
    uint64_t *threshold_ns_out
) {
    uint64_t samples[CPRISK_TIMING_SAMPLE_COUNT];
    memset(samples, 0, sizeof(samples));
    for (size_t i = 0u; i < CPRISK_TIMING_SAMPLE_COUNT; i++) {
        samples[i] = cprisk_single_step_measure_once_i();
    }
    cprisk_sort_u64_samples_i(samples, CPRISK_TIMING_SAMPLE_COUNT);

    const uint64_t median_ns = samples[CPRISK_TIMING_SAMPLE_COUNT / 2u];
    const uint64_t max_ns = samples[CPRISK_TIMING_SAMPLE_COUNT - 1u];

    uint64_t baseline_ns = atomic_load(&s_single_step_baseline_ns);
    if (baseline_ns == 0u) {
        baseline_ns = median_ns;
    }
    if (baseline_ns == 0u) {
        baseline_ns = CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS / 2u;
    }

    uint64_t median_threshold_ns =
        cprisk_mul_u64_saturating_i(baseline_ns, CPRISK_TIMING_MEDIAN_MULTIPLIER);
    if (median_threshold_ns < CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS) {
        median_threshold_ns = CPRISK_SINGLE_STEP_THRESHOLD_FLOOR_NS;
    }
    uint64_t spike_threshold_ns =
        cprisk_mul_u64_saturating_i(baseline_ns, CPRISK_TIMING_SPIKE_MULTIPLIER);
    if (spike_threshold_ns < median_threshold_ns) {
        spike_threshold_ns = median_threshold_ns;
    }

    uint64_t jitter_margin_ns = median_ns / CPRISK_TIMING_JITTER_DIVISOR;
    const uint64_t threshold_margin_ns = median_threshold_ns / CPRISK_TIMING_JITTER_DIVISOR;
    if (jitter_margin_ns < threshold_margin_ns) {
        jitter_margin_ns = threshold_margin_ns;
    }
    if (jitter_margin_ns < 500000ull) {
        jitter_margin_ns = 500000ull;
    }

    uint32_t anomaly_flags = 0u;
    if (median_ns > median_threshold_ns) {
        anomaly_flags |= CPRISK_TIMING_ANOMALY_MEDIAN;
    }
    if (max_ns > spike_threshold_ns) {
        anomaly_flags |= CPRISK_TIMING_ANOMALY_SPIKE;
    }
    if (max_ns > cprisk_add_u64_saturating_i(median_ns, jitter_margin_ns) &&
        max_ns > median_threshold_ns) {
        anomaly_flags |= CPRISK_TIMING_ANOMALY_JITTER;
    }

    anomaly_flags |= cprisk_clock_crosscheck_i(median_ns);
    anomaly_flags |= cprisk_dual_clock_workload_skew_i();

    if (median_ns_out) {
        *median_ns_out = median_ns;
    }
    if (max_ns_out) {
        *max_ns_out = max_ns;
    }
    if (threshold_ns_out) {
        *threshold_ns_out = median_threshold_ns;
    }

    if (median_ns > 0u) {
        if (anomaly_flags == 0u) {
            baseline_ns = baseline_ns - (baseline_ns / 8u) + (median_ns / 8u);
            atomic_store(&s_single_step_baseline_ns, baseline_ns);
            atomic_store(&s_single_step_threshold_ns,
                         cprisk_single_step_threshold_from_baseline_i(baseline_ns));
        } else if (atomic_load(&s_single_step_baseline_ns) == 0u) {
            atomic_store(&s_single_step_baseline_ns, median_ns);
            atomic_store(&s_single_step_threshold_ns,
                         cprisk_single_step_threshold_from_baseline_i(median_ns));
        }
    }

    return anomaly_flags;
}

int cprisk_detect_single_stepping(void) {
    cprisk_single_step_calibrate_if_needed_i();

    uint64_t median_ns = 0u;
    uint64_t max_ns = 0u;
    uint64_t threshold_ns = 0u;
    const uint32_t anomaly_flags =
        cprisk_timing_probe_eval_i(&median_ns, &max_ns, &threshold_ns);

    atomic_store(&s_timing_last_anomaly_flags, anomaly_flags);
    atomic_store(&s_timing_last_median_ns, median_ns);
    atomic_store(&s_timing_last_max_ns, max_ns);
    atomic_store(&s_timing_last_threshold_ns, threshold_ns);

    return anomaly_flags != 0u ? 1 : 0;
}

/* ── (g) Suspicious thread detection ──────────────────────────────── */

int cprisk_detect_suspicious_threads(void) {
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;

    if (task_threads(mach_task_self(), &threads, &thread_count) != KERN_SUCCESS) {
        return 0;
    }

    int suspicious = 0;

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        arm_thread_state64_t ts;
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        memset(&ts, 0, sizeof(ts));

        kern_return_t kr = thread_get_state(
            threads[i], ARM_THREAD_STATE64, (thread_state_t)&ts, &count);

        if (kr == KERN_SUCCESS) {
#if defined(arm_thread_state64_get_pc)
            uintptr_t pc = (uintptr_t)arm_thread_state64_get_pc(ts);
#else
            uintptr_t pc = (uintptr_t)ts.__pc;
#endif
            if (pc != 0 && !cprisk_addr_in_any_image_executable((const void *)pc)) {
                suspicious++;
            }
        }
    }

    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(),
                  (vm_address_t)threads,
                  sizeof(thread_act_t) * thread_count);

    return suspicious;
}

/* ── (h) Developer Disk Image detection ───────────────────────────── */

static void cprisk_xor_dec_path_i(const uint8_t *enc, size_t enc_len, uint8_t xor_key, char *out, size_t out_cap) {
    if (!enc || !out || enc_len + 1u > out_cap || out_cap == 0u) {
        if (out && out_cap > 0u) {
            out[0] = '\0';
        }
        return;
    }
    for (size_t i = 0u; i < enc_len; i++) {
        out[i] = (char)(enc[i] ^ xor_key);
    }
    out[enc_len] = '\0';
}

int cprisk_detect_developer_disk(void) {
    /* XOR-obfuscated paths (0x5A) — avoid contiguous ASCII literals in __TEXT/__cstring. */
    static const uint8_t k_p1[] = {
        117, 30, 63, 44, 63, 54, 53, 42, 63, 40, 117, 47, 41, 40, 117, 56, 51, 52, 117, 62, 63, 56, 47, 61, 41, 63, 40, 44, 63, 40};
    static const uint8_t k_p2[] = {
        117, 30, 63, 44, 63, 54, 53, 42, 63, 40, 117, 47, 41, 40, 117, 54, 51, 56, 117, 54, 51, 56, 23, 59, 51, 52, 14, 50, 40, 63, 59, 62, 25, 50, 63, 57, 49, 63, 40, 116, 62, 35, 54, 51, 56};
    char buf[64];
    cprisk_xor_dec_path_i(k_p1, sizeof(k_p1), 0x5Au, buf, sizeof(buf));
    if (buf[0] != '\0' && cprisk_access_direct(buf, F_OK, NULL) == 0) {
        cprisk_secure_zero(buf, sizeof(buf));
        return 1;
    }
    cprisk_secure_zero(buf, sizeof(buf));
    cprisk_xor_dec_path_i(k_p2, sizeof(k_p2), 0x5Au, buf, sizeof(buf));
    if (buf[0] != '\0' && cprisk_access_direct(buf, F_OK, NULL) == 0) {
        cprisk_secure_zero(buf, sizeof(buf));
        return 1;
    }
    cprisk_secure_zero(buf, sizeof(buf));
    return 0;
}

/* ── (i) Aggregate probe runner ───────────────────────────────────── */

uint32_t cprisk_run_all_signal_probes(void) {
    uint32_t result = 0;

    if (cprisk_probe_debugger_via_signal())
        result |= CPRISK_PROBE_SIGNAL_TRAP;

    const int thread_exception_ports = cprisk_detect_thread_exception_ports();
    if (thread_exception_ports != 0) {
        result |= CPRISK_PROBE_THREAD_EXCEPTION_PORT;
    }

    if (cprisk_detect_hardware_breakpoints())
        result |= CPRISK_PROBE_HARDWARE_BP;

    int software_bp = 0;
    software_bp += cprisk_scan_software_breakpoints(
        (const void *)cprisk_probe_debugger_via_signal, 256);
    software_bp += cprisk_scan_software_breakpoints(
        (const void *)cprisk_probe_exception_delivery_timeout, 256);
#if defined(TARGET_OS_IOS) && TARGET_OS_IOS
    software_bp += cprisk_scan_software_breakpoints_randomized_text(0u, 0u);
#endif
    if (software_bp != 0) {
        result |= CPRISK_PROBE_SOFTWARE_BP;
    }

    if (cprisk_scan_instant_return_key_symbols_prefix() != 0) {
        result |= CPRISK_PROBE_INSTANT_RETURN_PATCH;
    }

    if (cprisk_detect_tty_debug())
        result |= CPRISK_PROBE_TTY;

    if (cprisk_csops_debug_check())
        result |= CPRISK_PROBE_CSOPS;

    const int single_step_detected = cprisk_detect_single_stepping();
    if (single_step_detected)
        result |= CPRISK_PROBE_SINGLE_STEP;
    if (cprisk_get_last_timing_anomaly_flags() != 0u)
        result |= CPRISK_PROBE_TIMING_ANOMALY;

    if (cprisk_detect_suspicious_threads())
        result |= CPRISK_PROBE_SUSPICIOUS_THREAD;

    if (cprisk_detect_developer_disk())
        result |= CPRISK_PROBE_DEVELOPER_DISK;

    if (cprisk_probe_exception_delivery_timeout())
        result |= CPRISK_PROBE_EXCEPTION_DELIVERY_TIMEOUT;

    if (cprisk_detect_dbi_markers() > 0)
        result |= CPRISK_PROBE_DBI_MARKER;

    if (cprisk_trace_crosscheck_inconsistent() != 0)
        result |= CPRISK_PROBE_TRACE_CROSSCHECK;

    return result;
}

int cprisk_is_cntpct_clock_available(void) {
#if CPRISK_TIMING_CNTPCT_AVAILABLE
    uint64_t cntfrq = 0u;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(cntfrq));
    return cntfrq != 0u ? 1 : 0;
#else
    return 0;
#endif
}

/* ===================================================================== */
#else  /* !CPRISK_SIGNAL_PROBE_AVAILABLE — simulator / non-arm64 stubs */
/* ===================================================================== */

int cprisk_probe_debugger_via_signal(void) { return 0; }
int cprisk_detect_thread_exception_ports(void) { return 0; }
int cprisk_detect_hardware_breakpoints(void) { return 0; }

int cprisk_scan_software_breakpoints(const void *func_ptr, size_t size) {
    (void)func_ptr; (void)size;
    return 0;
}
int cprisk_scan_software_breakpoints_randomized_text(
    size_t sample_windows,
    size_t window_size
) {
    (void)sample_windows;
    (void)window_size;
    return 0;
}

int cprisk_probe_exception_delivery_timeout(void) { return 0; }
int cprisk_detect_tty_debug(void) { return 0; }
int cprisk_csops_debug_check(void) { return 0; }
int cprisk_csops_status_flags(uint32_t *flags_out, int *error_out) {
    if (flags_out != NULL) {
        *flags_out = 0u;
    }
    if (error_out != NULL) {
        *error_out = ENOTSUP;
    }
    return -1;
}
int cprisk_detect_single_stepping(void) { return 0; }
int cprisk_detect_suspicious_threads(void) { return 0; }
int cprisk_detect_developer_disk(void) { return 0; }
int cprisk_detect_dbi_markers(void) { return 0; }
int cprisk_vm_probe_anonymous_exec_outside_images(void) { return 0; }
uint32_t cprisk_get_last_dbi_marker_flags(void) { return 0u; }
int cprisk_get_last_dbi_marker_hit_count(void) { return 0; }
uint32_t cprisk_get_last_timing_anomaly_flags(void) {
    uint32_t f = 0u;
    const uint32_t c = cprisk_crypto_trace_peek_flags_i();
    if ((c & CPRISK_CRYPTO_TRACE_FLAG_SLOW) != 0u) {
        f |= CPRISK_TIMING_ANOMALY_CRYPTO_TRACE;
    }
    if ((c & CPRISK_CRYPTO_TRACE_FLAG_CNT_MACH_SKEW) != 0u) {
        f |= CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_SKEW;
    }
    if ((c & CPRISK_CRYPTO_TRACE_FLAG_INVARIANT_FAIL) != 0u) {
        f |= CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_INVARIANT;
    }
    return f;
}
uint64_t cprisk_get_last_timing_probe_median_ns(void) { return 0u; }
uint64_t cprisk_get_last_timing_probe_max_ns(void) { return cprisk_crypto_trace_last_ns_i(); }
uint64_t cprisk_get_last_timing_probe_threshold_ns(void) { return cprisk_crypto_trace_threshold_ns_i(); }
uint32_t cprisk_run_all_signal_probes(void) {
#if defined(__arm64__) || defined(__aarch64__)
    uint32_t r = 0u;
    if (cprisk_scan_instant_return_key_symbols_prefix() != 0) {
        r |= CPRISK_PROBE_INSTANT_RETURN_PATCH;
    }
    return r;
#else
    return 0u;
#endif
}
int cprisk_is_cntpct_clock_available(void) { return 0; }

#endif /* CPRISK_SIGNAL_PROBE_AVAILABLE */
