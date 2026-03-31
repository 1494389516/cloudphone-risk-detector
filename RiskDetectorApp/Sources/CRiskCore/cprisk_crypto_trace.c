/*
 * cprisk_crypto_trace.c — Mach time + orthogonal trace sentinels for crypto primitive paths.
 */

#include "include/cprisk_crypto_trace.h"

#include <TargetConditionals.h>
#include <mach/mach_time.h>
#include <stdatomic.h>

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
#define CPRISK_CRYPTO_TRACE_ARM64_DEVICE 1
#else
#define CPRISK_CRYPTO_TRACE_ARM64_DEVICE 0
#endif

/* Conservative: native runs are sub-µs; DBI/Stalker often pushes this to 10µs+. */
enum { CPRISK_CRYPTO_TRACE_SLOW_NS = 25000u };

/* Golden digest for the 64-round inline workload (uint64 wrap). */
static const uint64_t k_cprisk_crypto_trace_acc_expected =
    UINT64_C(0x05F45B2ECA50430B);

static mach_timebase_info_data_t s_timebase;
static uint32_t s_timebase_ready;

static atomic_uint_fast32_t s_trace_flags;
static atomic_uint_fast64_t s_trace_last_ns;

static void cprisk_crypto_trace_timebase_once_i(void) {
    if (s_timebase_ready != 0u)
        return;
    (void)mach_timebase_info(&s_timebase);
    s_timebase_ready = 1u;
}

static uint64_t cprisk_crypto_trace_ticks_to_ns_i(uint64_t delta_ticks) {
    cprisk_crypto_trace_timebase_once_i();
    if (s_timebase.denom == 0u)
        return 0u;
    return delta_ticks / (uint64_t)s_timebase.denom * (uint64_t)s_timebase.numer +
           (delta_ticks % (uint64_t)s_timebase.denom) * (uint64_t)s_timebase.numer / (uint64_t)s_timebase.denom;
}

#if CPRISK_CRYPTO_TRACE_ARM64_DEVICE
static uint64_t cprisk_crypto_cntpct_delta_ns_i(uint64_t c0, uint64_t c1) {
    static _Atomic uint64_t s_cntfrq = 0u;
    uint64_t freq = atomic_load_explicit(&s_cntfrq, memory_order_relaxed);
    if (freq == 0u) {
        __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
        atomic_store_explicit(&s_cntfrq, freq, memory_order_relaxed);
    }
    if (freq == 0u || c1 < c0) {
        return 0u;
    }
    const uint64_t dt = c1 - c0;
    return (dt / freq) * 1000000000ull +
           ((dt % freq) * 1000000000ull) / freq;
}

static uint64_t cprisk_crypto_u64_abs_diff_i(uint64_t a, uint64_t b) {
    return a > b ? a - b : b - a;
}
#endif

uint64_t cprisk_crypto_trace_now_i(void) {
    cprisk_crypto_trace_timebase_once_i();
    return mach_absolute_time();
}

void cprisk_crypto_trace_record_span_ticks_i(uint64_t delta_ticks) {
    const uint64_t ns = cprisk_crypto_trace_ticks_to_ns_i(delta_ticks);
    if (ns == 0u)
        return;
    atomic_store(&s_trace_last_ns, ns);
    if (ns > (uint64_t)CPRISK_CRYPTO_TRACE_SLOW_NS)
        atomic_fetch_or(&s_trace_flags, CPRISK_CRYPTO_TRACE_FLAG_SLOW);
}

void cprisk_crypto_trace_primitive_enter_i(void) {
#if CPRISK_CRYPTO_TRACE_ARM64_DEVICE
    uint64_t cntpct0 = 0u;
    uint64_t cntpct1 = 0u;
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(cntpct0));
#endif

    const uint64_t t0 = cprisk_crypto_trace_now_i();
    volatile uint64_t acc = UINT64_C(0xC6A4A7935BD1E995);
    for (unsigned n = 0u; n < 64u; n++) {
        acc ^= acc * UINT64_C(6364136223846793005) + (uint64_t)n;
    }
    const uint64_t t1 = cprisk_crypto_trace_now_i();

#if CPRISK_CRYPTO_TRACE_ARM64_DEVICE
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(cntpct1));
#endif

    if (acc != k_cprisk_crypto_trace_acc_expected) {
        atomic_fetch_or(&s_trace_flags, CPRISK_CRYPTO_TRACE_FLAG_INVARIANT_FAIL);
    }

    (void)acc;
    cprisk_crypto_trace_record_span_ticks_i(t1 - t0);

#if CPRISK_CRYPTO_TRACE_ARM64_DEVICE
    /*
     * Orthogonal to pure mach_absolute_time dilation: DBI that patches or
     * virtualizes one clock but not the other (or scales them differently)
     * leaves CNTPCT_EL0-derived ns and mach-derived ns in disagreement for the
     * same bounded workload — including cases where wall-clock ratios look
     * “natural” relative to a baseline.
     */
    {
        const uint64_t d_cnt_ns = cprisk_crypto_cntpct_delta_ns_i(cntpct0, cntpct1);
        uint64_t d_mach_ns = 0u;
        if (t1 >= t0) {
            d_mach_ns = cprisk_crypto_trace_ticks_to_ns_i(t1 - t0);
        } else {
            d_mach_ns = cprisk_crypto_trace_ticks_to_ns_i(t0 - t1);
        }
        const uint64_t dmax = d_cnt_ns > d_mach_ns ? d_cnt_ns : d_mach_ns;
        if (dmax >= 8000u) {
            const uint64_t skew_ns = cprisk_crypto_u64_abs_diff_i(d_cnt_ns, d_mach_ns);
            if (skew_ns > dmax / 4u) {
                atomic_fetch_or(&s_trace_flags, CPRISK_CRYPTO_TRACE_FLAG_CNT_MACH_SKEW);
            }
        }
    }
#endif
}

uint32_t cprisk_crypto_trace_peek_flags_i(void) {
    return (uint32_t)atomic_load(&s_trace_flags);
}

uint64_t cprisk_crypto_trace_last_ns_i(void) {
    return (uint64_t)atomic_load(&s_trace_last_ns);
}

uint64_t cprisk_crypto_trace_threshold_ns_i(void) {
    return (uint64_t)CPRISK_CRYPTO_TRACE_SLOW_NS;
}

uint32_t cprisk_crypto_trace_consume_flags_i(void) {
    return (uint32_t)atomic_exchange(&s_trace_flags, 0u);
}
