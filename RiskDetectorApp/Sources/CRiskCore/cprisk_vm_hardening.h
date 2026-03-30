/*
 *  cprisk_vm_hardening.h
 *  CRiskCore
 *
 *  Unified hardening integration layer for the VM interpreter.
 *
 *  This header declares initialization and per-step hook functions that
 *  wire five hardening modules into cprisk_vm_interp_loop_a/b:
 *
 *    1. VM state integrity (FNV-1a checksum chain)
 *    2. Instruction reordering & fake dependencies (runtime pseudo-dep injection)
 *    3. Runtime on-demand bytecode decryption (basic-block XOR + re-encrypt)
 *    4. Path explosion (opaque predicates, MBA decoys, anti-symbolic-execution)
 *    5. VM × CFF deep fusion (Feistel-encoded PC, state transitions)
 */

#ifndef CPRISK_VM_HARDENING_H
#define CPRISK_VM_HARDENING_H

#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "vm_integrity.h"
#include "vm_cff_fusion.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 *  Initialization — called once per VM run from cprisk_vm_prepare_program_i
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Initialize all five hardening sub-modules inside \p fr.
 *  Safe to call even when individual features are compiled out (no-ops). */
void cprisk_vm_hardening_init(cprisk_vm_interp_frame_t *fr);

/* ═══════════════════════════════════════════════════════════════════════════
 *  Per-step hooks — called from the main VM loop bodies
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Task 1: Integrity checkpoint — verify VM state consistency.
 *  Called AFTER each instruction execution.
 *  On corruption: silently sets fr->vm_integrity_corrupted = 1 and poisons
 *  opaque_chain / acc state (no crash, no abort). */
void cprisk_vm_hardening_integrity_checkpoint(cprisk_vm_interp_frame_t *fr,
                                               uint32_t pc,
                                               uint32_t logical_op);

/** Task 2: Fake dependency injection — mix pseudo-dependencies into acc/opaque.
 *  Called periodically (every 8 steps) when anti_symbolic_heavy is enabled.
 *  Inserts MBA-derived false data dependencies that complicate data-flow analysis. */
void cprisk_vm_hardening_fake_dep_inject(cprisk_vm_interp_frame_t *fr,
                                          uint32_t pc,
                                          uint32_t hvar);

/** Task 3: On-demand decrypt — ensure current basic block is decrypted.
 *  Called BEFORE instruction fetch.  Uses XOR-based basic-block encryption
 *  with per-block keys derived from func_id + block_id.
 *  Re-encrypts the previous block when transitioning to a new one. */
void cprisk_vm_hardening_ondemand_decrypt(cprisk_vm_interp_frame_t *fr,
                                           uint32_t pc);

/** Task 4: Path explosion checkpoint — opaque predicate + decoy insertion.
 *  Called every VM_PATH_EXPLOSION_DECOY_DENSITY steps.
 *  Inserts opaque predicate checkpoints that force symbolic executors to
 *  explore exponentially many false paths. */
void cprisk_vm_hardening_path_explosion(cprisk_vm_interp_frame_t *fr,
                                         uint32_t pc);

/** Task 5: CFF fusion transition — encode/decode PC through Feistel network.
 *  Called after each branch or every 32 steps on fall-through.
 *  Maintains an encoded state that binds VM control flow to the CFF layer. */
void cprisk_vm_hardening_cff_transition(cprisk_vm_interp_frame_t *fr,
                                         uint32_t current_pc,
                                         uint32_t next_pc_hint,
                                         int is_branch);

/** Task 5: CFF fusion integrity — verify Feistel round-trip consistency.
 *  Called periodically (every 128 steps). */
void cprisk_vm_hardening_cff_verify(cprisk_vm_interp_frame_t *fr);

/* ═══════════════════════════════════════════════════════════════════════════
 *  Cleanup — called once per VM run from finish_run
 * ═══════════════════════════════════════════════════════════════════════════ */

/** Secure-clear all hardening state from \p fr. */
void cprisk_vm_hardening_cleanup(cprisk_vm_interp_frame_t *fr);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_VM_HARDENING_H */
