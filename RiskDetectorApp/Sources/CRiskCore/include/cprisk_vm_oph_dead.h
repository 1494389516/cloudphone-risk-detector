#ifndef CPRISK_VM_OPH_DEAD_H
#define CPRISK_VM_OPH_DEAD_H

/*
 * cprisk_vm_oph_dead.h
 * CRiskCore
 *
 * Dead handler pool (P1 — handler address space inflation).
 *
 * Problem:
 *   A dynamic analysis tool (Frida, unidbg) that traces the VM can build a
 *   complete opcode→handler-address mapping by executing one instruction of
 *   each logical opcode and recording which function was called.  With the
 *   original dispatch table every live opcode maps to exactly one (or now N,
 *   after v7.5 variant expansion) handler body.  The *total* set of reachable
 *   handler addresses is small and enumerable.
 *
 * Solution:
 *   Inject CPRISK_VM_DEAD_HANDLER_COUNT additional handler functions whose
 *   addresses are folded into session entropy at session-start, but whose
 *   opcode values never appear in real bytecode emitted by the Pass 13 producer.
 *
 *   Effect on an attacker tracing function-pointer resolution:
 *     - The combined handler surface grows from ~40 to ~88+ functions.
 *     - There is no external signal distinguishing live handlers from dead
 *       handlers: both have valid C signatures, both take fr/op/logical/imm/pc/hvar.
 *     - Dead handlers execute CPRISK_VM_FLOW_LEAVE + set POISON_UNKNOWN_OPCODE
 *       when reached, which is also what cprisk_vm_oph_unknown does — so the
 *       attacker cannot reliably distinguish "dead" from "just-not-triggered-yet"
 *       by behaviour alone.
 *
 * v7.5 dispersion (no static fn-pointer table):
 *   The previous design kept a static const cprisk_vm_oph_fn array in __const
 *   so the linker would retain bodies and the touch routine could iterate.
 *   This made the entire dead set enumerable via a single dref pass: "for
 *   offset in __const range, if u64@offset matches a handler-shaped body, it's
 *   a dispatch slot" — exactly the kanxue thread-290993 attack pattern.
 *
 *   The table has been removed.  cprisk_vm_dead_touch_i now takes the address
 *   of each handler inline via &fn at its own ADRP+ADD site, with non-linear
 *   mixing steps interleaved between batches.  Static dref of __const finds no
 *   8-byte fn-pointer constants; recovering the dead set requires reverse-
 *   engineering the touch routine itself, not pattern matching.
 *
 * Integration:
 *   cprisk_vm_entry / cprisk_vm_execute calls cprisk_vm_dead_touch_i() once per
 *   session to derive a fold hash from all 32 inline-referenced handlers,
 *   mixing it into session_mix.  This ensures the dead handler addresses are
 *   loaded at runtime (preventing the linker from stripping bodies via
 *   --gc-sections) and that the hash appears in the session state consumed by
 *   vv_select_index.
 */

#include "cprisk_vm_interpreter_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CPRISK_VM_DEAD_HANDLER_COUNT 32u

/*
 * Touch the dead handler table and fold all function-pointer addresses into
 * a 32-bit hash that is XOR'd into fr->session_mix.  Call once per session
 * after the frame is initialised but before the first instruction dispatch.
 */
void cprisk_vm_dead_touch_i(cprisk_vm_interp_frame_t *fr);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_VM_OPH_DEAD_H */
