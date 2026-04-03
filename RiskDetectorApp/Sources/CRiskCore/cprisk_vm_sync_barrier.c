/*
 * cprisk_vm_sync_barrier.c
 * CRiskCore
 *
 * VM execution synchronisation barrier — see cprisk_vm_sync_barrier.h for
 * full design rationale.
 *
 * Summary: inserts an external data dependency every 64 VM instructions to
 * break the speculative batch-execution model used by optimised trace engines.
 */

#include "include/cprisk_vm_sync_barrier.h"
#include "include/cprisk_emulator_detect.h"
#include "include/CRiskCore.h"

#include <stdatomic.h>
#include <string.h>

/* ── Global watchdog counter (written by watchdog thread) ────────────────── */

static _Atomic(uint32_t) s_watchdog_counter = 0u;

/*
 * Process-global stuck flag.
 * Set to 1 the first time any VM frame detects a stuck watchdog.
 * Never reset — once stuck, always stuck (a real device would have threads).
 * Read by cprisk_vm_sync_barrier_global_stuck() for signing-layer poison.
 */
static _Atomic(uint32_t) s_global_stuck = 0u;

void cprisk_vm_sync_barrier_note_watchdog_tick(void) {
    /* Relaxed store: the watchdog and the VM run on different threads;
     * we only need eventual visibility, not synchronisation. */
    atomic_fetch_add_explicit(&s_watchdog_counter, 1u, memory_order_relaxed);
}

uint32_t cprisk_vm_sync_barrier_get_watchdog(void) {
    return atomic_load_explicit(&s_watchdog_counter, memory_order_relaxed);
}

/* ── Barrier context ─────────────────────────────────────────────────────── */

void cprisk_vm_sync_barrier_init(cprisk_vm_sync_barrier_ctx_t *ctx) {
    if (!ctx) return;
    ctx->step_counter      = 0u;
    ctx->last_watchdog_val = atomic_load_explicit(&s_watchdog_counter, memory_order_relaxed);
    ctx->accumulated_mix   = 0u;
    ctx->no_advance_count  = 0u;
    ctx->watchdog_stuck    = 0u;
}

int cprisk_vm_sync_barrier_watchdog_stuck(const cprisk_vm_sync_barrier_ctx_t *ctx) {
    if (!ctx) return 0;
    return (int)ctx->watchdog_stuck;
}

uint32_t cprisk_vm_sync_barrier_global_stuck(void) {
    return atomic_load_explicit(&s_global_stuck, memory_order_acquire);
}

/*
 * Fast inline avalanche used to mix the watchdog value into the accumulator.
 * Must be cheap (< 5 ns) since it runs every 64 VM instructions.
 */
static inline uint32_t sb_avalanche32(uint32_t x) {
    x ^= x >> 16u;
    x *= 0x7FEB352Du;
    x ^= x >> 15u;
    x *= 0x846CA68Bu;
    x ^= x >> 16u;
    return x;
}

int cprisk_vm_sync_barrier_step(cprisk_vm_sync_barrier_ctx_t *ctx,
                                 uint8_t acc_inout[4],
                                 uint32_t pc) {
    if (!ctx || !acc_inout) return 0;

    ctx->step_counter += 1u;
    if ((ctx->step_counter % CPRISK_VM_SYNC_BARRIER_INTERVAL) != 0u)
        return 0;

    /* Read the external watchdog counter — this is the mandatory data
     * dependency that a batch-trace engine cannot pre-compute without
     * actually running the watchdog thread. */
    const uint32_t wdog_now = atomic_load_explicit(&s_watchdog_counter,
                                                    memory_order_acquire);

    /*
     * Mix the watchdog value into acc[0] using an avalanche function keyed
     * by pc so the perturbation is instruction-position-specific.
     *
     * The mix term is accumulated in ctx->accumulated_mix so that the
     * hardening layer (FNV chain) can reconstruct and cancel it on the
     * recovery / output path — net semantic effect on the final VM result
     * is zero, but the batch-trace engine cannot skip the read.
     *
     * mix = avalanche(watchdog XOR pc XOR step_counter)
     *
     * We XOR only bit-0 of the high byte of acc[0] so the perturbation is
     * a single-bit flip — invisible to casual inspection but sufficient to
     * create the data dependency.  The recovery path (cprisk_vm_hardening)
     * sees the flipped bit and restores it via the FNV chain delta.
     */
    const uint32_t delta_wdog = wdog_now ^ ctx->last_watchdog_val;

    /* Track whether the watchdog is actually advancing.
     * On unidbg, the watchdog pthread typically never runs, so the counter
     * never moves.  After STUCK_THRESHOLD consecutive barrier fires with no
     * change, flag the context as stuck. */
    if (delta_wdog == 0u) {
        ctx->no_advance_count += 1u;
        if (ctx->no_advance_count >= CPRISK_VM_SYNC_BARRIER_STUCK_THRESHOLD) {
            ctx->watchdog_stuck = 1u;
            /* Propagate to the process-global flag so the signing layer can
             * read it without access to the VM frame context. */
            atomic_store_explicit(&s_global_stuck, 1u, memory_order_release);
            /* Also update the emulator-detect cache so the signing-layer
             * HKDF poison path sees the stuck flag even if the full probe
             * ran before the watchdog was detected as stuck. */
            cprisk_emulator_mark_watchdog_stuck();
        }
    } else {
        ctx->no_advance_count = 0u;
        ctx->watchdog_stuck   = 0u;
        /* Note: s_global_stuck is intentionally NOT cleared here.  On a real
         * device the watchdog always advances; if it ever stopped advancing
         * (stuck=1) then recovered, that itself is anomalous. */
    }

    const uint32_t mix = sb_avalanche32(delta_wdog ^ pc ^ ctx->step_counter ^ 0xBAADF00Du);

    /* Single-bit injection into acc[0] — sufficient for the data dependency */
    acc_inout[0] ^= (uint8_t)(mix & 0x01u);

    ctx->accumulated_mix ^= mix;
    ctx->last_watchdog_val = wdog_now;
    return 1;
}
