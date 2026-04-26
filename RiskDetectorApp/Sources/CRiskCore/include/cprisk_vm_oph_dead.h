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
 *   addresses appear in the global dead_handler_table[] but whose opcode
 *   values never appear in real bytecode emitted by the Pass 13 producer.
 *
 *   Effect on an attacker tracing function-pointer resolution:
 *     - The combined handler surface grows from ~40 to ~56 functions.
 *     - There is no external signal distinguishing live handlers from dead
 *       handlers: both have valid C signatures, both take fr/op/logical/imm/pc/hvar,
 *       both appear in a function-pointer table that is scanned at session start.
 *     - Dead handlers execute CPRISK_VM_FLOW_LEAVE + set POISON_UNKNOWN_OPCODE
 *       when reached, which is also what cprisk_vm_oph_unknown does — so the
 *       attacker cannot reliably distinguish "dead" from "just-not-triggered-yet"
 *       by behaviour alone.
 *
 * Integration:
 *   cprisk_vm_entry / cprisk_vm_execute calls cprisk_vm_dead_touch_i() once per
 *   session to derive a fold hash from the table, mixing it into session_mix.
 *   This ensures the dead handler addresses are loaded at runtime (preventing
 *   the linker from stripping the dead_handler_table via --gc-sections) and that
 *   the hash appears in the session state consumed by vv_select_index.
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
