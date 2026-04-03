#ifndef CPRISK_VM_SYNC_BARRIER_H
#define CPRISK_VM_SYNC_BARRIER_H

/*
 * cprisk_vm_sync_barrier.h
 *
 * VM execution synchronisation barrier.
 *
 * Counter-measure: Native batch-trace pipeline (unidbg魔改版 §7.1 future work).
 *
 * unidbg's remaining bottleneck after the Java-layer optimisations is the
 * JNI boundary crossing and the N × reg_read() calls per instruction.  The
 * logical next step (already partially implemented as a "binary trace format")
 * is to move the hot loop — disassembly + register capture + formatting — fully
 * into a native C layer that processes a *batch* of instructions without
 * returning to Java between each one.
 *
 * A pure batch approach can pre-compute all VM states for a block of bytecode
 * if each instruction's inputs depend only on prior outputs within the batch
 * (no external data dependencies).  If the batch is self-contained, the
 * tracer can speculatively execute the whole block and emit a formatted trace
 * in one shot.
 *
 * The sync barrier breaks this by inserting a mandatory *external* read every
 * CPRISK_VM_SYNC_BARRIER_INTERVAL steps.  The external state is a value
 * maintained by the watchdog thread (an atomically-updated counter) that the
 * VM must read and mix into its accumulator.  Key properties:
 *
 * 1. **Data dependency**: the acc after step N depends on a value not available
 *    until the watchdog has executed at least once since step N-interval.
 * 2. **Non-predictable**: the watchdog counter is updated at ~1 Hz with jitter;
 *    no batch-trace pipeline can pre-compute its value.
 * 3. **Cheap**: one atomic load per K=64 steps; negligible overhead vs
 *    the existing CFF/VM hardening.
 * 4. **Correct**: the accumulator is also perturbed by cprisk_vm_hardening
 *    (FNV chain + MBA); the barrier term is additive and cancelled by the
 *    same hardening on the recovery path.  Net semantic effect on the final
 *    VM output is zero.
 *
 * API:
 *   cprisk_vm_sync_barrier_init():  call once at VM frame initialisation.
 *   cprisk_vm_sync_barrier_step():  call on every instruction; returns
 *     non-zero when it fires (so callers can measure overhead if needed).
 *   cprisk_vm_sync_barrier_note_watchdog_tick(): watchdog thread calls this
 *     to advance the external counter.
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* How often (in VM instructions) to fire the barrier. */
#ifndef CPRISK_VM_SYNC_BARRIER_INTERVAL
#define CPRISK_VM_SYNC_BARRIER_INTERVAL 64u
#endif

typedef struct cprisk_vm_sync_barrier_ctx {
    uint32_t step_counter;        /* local instruction counter */
    uint32_t last_watchdog_val;   /* last observed watchdog tick */
    uint32_t accumulated_mix;     /* running mix term (subtracted at recovery) */
    uint32_t no_advance_count;    /* consecutive barrier fires with no watchdog advance */
    uint32_t watchdog_stuck;      /* 1 when watchdog appears not advancing (unidbg heuristic) */
} cprisk_vm_sync_barrier_ctx_t;

/* How many consecutive barrier intervals with no watchdog advance before flagging stuck. */
#ifndef CPRISK_VM_SYNC_BARRIER_STUCK_THRESHOLD
#define CPRISK_VM_SYNC_BARRIER_STUCK_THRESHOLD 3u
#endif

/** Initialise a per-frame barrier context. */
void cprisk_vm_sync_barrier_init(cprisk_vm_sync_barrier_ctx_t *ctx);

/**
 * Advance the barrier by one instruction step.
 *
 * Every CPRISK_VM_SYNC_BARRIER_INTERVAL calls this reads the external
 * watchdog counter, mixes it into `acc_inout[0]`, and updates ctx.
 *
 * @param ctx       Per-frame barrier context (mutated).
 * @param acc_inout VM accumulator bytes [0..3] (acc_inout[0] mutated).
 * @param pc        Current virtual PC (used as mixing key).
 * @returns 1 if the barrier fired this step, 0 otherwise.
 */
int cprisk_vm_sync_barrier_step(cprisk_vm_sync_barrier_ctx_t *ctx,
                                 uint8_t acc_inout[4],
                                 uint32_t pc);

/**
 * Called by the watchdog thread to advance the external counter.
 * Thread-safe (uses stdatomic).
 */
void cprisk_vm_sync_barrier_note_watchdog_tick(void);

/** Read the current watchdog counter value (for testing). */
uint32_t cprisk_vm_sync_barrier_get_watchdog(void);

/**
 * Returns non-zero if the watchdog counter appears stuck (not advancing).
 * This is a strong indicator that the watchdog thread is not running —
 * consistent with unidbg's limited thread emulation.
 */
int cprisk_vm_sync_barrier_watchdog_stuck(const cprisk_vm_sync_barrier_ctx_t *ctx);

/**
 * Returns non-zero when ANY VM frame has detected a stuck watchdog since
 * process start.  Uses a process-global atomic so the result persists even
 * after the originating VM frame is torn down.
 *
 * Used by the signing layer to poison the HKDF derivation when the watchdog
 * is absent (strong unidbg indicator), causing the resulting HMAC to differ
 * from what the server expects — silently and without an observable crash.
 */
uint32_t cprisk_vm_sync_barrier_global_stuck(void);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_VM_SYNC_BARRIER_H */
