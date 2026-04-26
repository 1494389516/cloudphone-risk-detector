/*
 * cprisk_vm_oph_dead.c
 * CRiskCore
 *
 * Dead handler pool — 16 handler-shaped functions that are reachable via the
 * global dead_handler_table[] but whose opcode values never appear in real
 * bytecode produced by the Pass 13 VMProtector.
 *
 * See cprisk_vm_oph_dead.h for design rationale.
 *
 * Each function is deliberately distinct (different mixing constants, different
 * operand sequencing) so they produce different ARM64 encodings and cannot be
 * collapsed by a deduplication pass.  All unconditionally return FLOW_LEAVE
 * and set POISON_UNKNOWN_OPCODE — matching the behaviour of cprisk_vm_oph_unknown
 * — making them behaviourally indistinguishable from "valid but unissued" opcodes.
 */

#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"
#include "include/cprisk_vm_oph_dead.h"

/* Each dead handler uses a unique mixing constant so its code body differs. */
#define DEAD_BODY(id, K)                                                        \
static cprisk_vm_flow_t cprisk_vm_oph_dead_##id(                                \
        cprisk_vm_interp_frame_t *fr,                                           \
        uint8_t op_raw, uint8_t logical, uint64_t imm,                          \
        uint32_t pc, uint32_t hvar) {                                           \
    (void)logical; (void)imm; (void)pc;                                         \
    const uint32_t fold =                                                        \
        (uint32_t)op_raw ^ hvar ^ fr->opaque_chain ^ fr->session_mix ^ (K);    \
    fr->opaque_chain ^= fold;   /* visible side-effect prevents elimination */  \
    fr->out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;                   \
    return CPRISK_VM_FLOW_LEAVE;                                                 \
}

DEAD_BODY(0,  0xD0D0D0D0u)
DEAD_BODY(1,  0x1E1E1E1Eu)
DEAD_BODY(2,  0x2F2F2F2Fu)
DEAD_BODY(3,  0x3A3A3A3Au)
DEAD_BODY(4,  0x4B4B4B4Bu)
DEAD_BODY(5,  0x5C5C5C5Cu)
DEAD_BODY(6,  0x6D6D6D6Du)
DEAD_BODY(7,  0x7E7E7E7Eu)
DEAD_BODY(8,  0x81818181u)
DEAD_BODY(9,  0x92929292u)
DEAD_BODY(a,  0xA3A3A3A3u)
DEAD_BODY(b,  0xB4B4B4B4u)
DEAD_BODY(c,  0xC5C5C5C5u)
DEAD_BODY(d,  0xD6D6D6D6u)
DEAD_BODY(e,  0xE7E7E7E7u)
DEAD_BODY(f,  0xF8F8F8F8u)

/* Global table — all 16 pointers are loaded at session start by cprisk_vm_dead_touch_i. */
static const cprisk_vm_oph_fn s_dead_handler_table[CPRISK_VM_DEAD_HANDLER_COUNT] = {
    cprisk_vm_oph_dead_0,
    cprisk_vm_oph_dead_1,
    cprisk_vm_oph_dead_2,
    cprisk_vm_oph_dead_3,
    cprisk_vm_oph_dead_4,
    cprisk_vm_oph_dead_5,
    cprisk_vm_oph_dead_6,
    cprisk_vm_oph_dead_7,
    cprisk_vm_oph_dead_8,
    cprisk_vm_oph_dead_9,
    cprisk_vm_oph_dead_a,
    cprisk_vm_oph_dead_b,
    cprisk_vm_oph_dead_c,
    cprisk_vm_oph_dead_d,
    cprisk_vm_oph_dead_e,
    cprisk_vm_oph_dead_f,
};

/*
 * Fold all 16 handler addresses into a 32-bit hash and XOR it into
 * fr->session_mix.  This serves two purposes:
 *
 *   1. Forces the linker to keep all 16 function bodies (their addresses are
 *      taken and consumed at runtime — --gc-sections / COMDAT folding cannot
 *      remove them).
 *   2. Binds the dead-handler layout to the session entropy: if the binary is
 *      modified and the handler addresses change, session_mix changes, which
 *      propagates into vv_select_index and alters every subsequent variant
 *      selection (low-key integrity signal).
 */
void cprisk_vm_dead_touch_i(cprisk_vm_interp_frame_t *fr) {
    uint32_t fold = 0x4C4C4C4Cu;
    for (uint32_t i = 0u; i < CPRISK_VM_DEAD_HANDLER_COUNT; i++) {
        const uintptr_t addr = (uintptr_t)(const void *)s_dead_handler_table[i];
        fold ^= (uint32_t)addr;
        fold ^= (uint32_t)(addr >> 17u);
        fold ^= (uint32_t)(addr >> 32u);
        fold  = (fold << 5u) | (fold >> 27u);   /* ROTL32 5 */
    }
    fr->session_mix ^= fold;
}
