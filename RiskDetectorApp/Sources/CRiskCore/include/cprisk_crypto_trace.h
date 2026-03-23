/*
 * cprisk_crypto_trace.h — Timing / trace sentinel for SHA-256 and HMAC entry paths.
 *
 * Surfaces (1) gross slowdown on a tiny workload, (2) CNTPCT_EL0 vs Mach
 * disagreement on the same region (orthogonal to pure wall dilation), and
 * (3) deterministic LCG digest mismatch if execution is perturbed.
 */

#ifndef CPRISK_CRYPTO_TRACE_H
#define CPRISK_CRYPTO_TRACE_H

#include <stdint.h>

enum {
    CPRISK_CRYPTO_TRACE_FLAG_SLOW = 1u << 0,
    /** CNTPCT-derived elapsed vs mach_absolute_time elapsed disagree (arm64 device). */
    CPRISK_CRYPTO_TRACE_FLAG_CNT_MACH_SKEW = 1u << 1,
    /** Deterministic micro-workload result diverged from the golden uint64 digest. */
    CPRISK_CRYPTO_TRACE_FLAG_INVARIANT_FAIL = 1u << 2,
};

uint64_t cprisk_crypto_trace_now_i(void);
void cprisk_crypto_trace_record_span_ticks_i(uint64_t delta_ticks);
void cprisk_crypto_trace_primitive_enter_i(void);
uint32_t cprisk_crypto_trace_peek_flags_i(void);
uint64_t cprisk_crypto_trace_last_ns_i(void);
uint64_t cprisk_crypto_trace_threshold_ns_i(void);

/** Atomically ORs observed flags and returns the previous value (for tests/diagnostics). */
uint32_t cprisk_crypto_trace_consume_flags_i(void);

#endif /* CPRISK_CRYPTO_TRACE_H */
