/*
 * cprisk_vm_oph_dead.c
 * CRiskCore
 *
 * Dead handler pool — 32 handler-shaped functions whose addresses are folded
 * into session entropy at session-start, but whose opcode values never appear
 * in real bytecode produced by the Pass 13 VMProtector.
 *
 * See cprisk_vm_oph_dead.h for design rationale.
 *
 * Each function is deliberately distinct (different mixing constants, different
 * operand sequencing) so they produce different ARM64 encodings and cannot be
 * collapsed by a deduplication pass.  All unconditionally return FLOW_LEAVE
 * and set POISON_UNKNOWN_OPCODE — matching the behaviour of cprisk_vm_oph_unknown
 * — making them behaviourally indistinguishable from "valid but unissued" opcodes.
 *
 * v7.5 dispersion: the previous design kept a single static const fn-pointer
 * table in __const, which let an attacker enumerate the entire dead pool with
 * one dref scan ("for offset in __const range: if u64@offset matches a known
 * handler then we've found a dispatch slot").  See kanxue thread-290993 for
 * the exact attack pattern.
 *
 * The table has been removed.  Function addresses are taken inline inside
 * cprisk_vm_dead_touch_i via a macro — each reference is its own ADRP+ADD pair
 * scattered with mixing operations, so static dref of __const finds no
 * 8-byte function pointer constants to enumerate.  Recovering the dead set
 * now requires reverse-engineering the touch routine itself, not pattern
 * matching on data sections.
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
/* Second batch (v7.5+): doubles handler-catalog noise without changing semantics. */
DEAD_BODY(10, 0x09090909u)
DEAD_BODY(11, 0x1A1A1A1Au)
DEAD_BODY(12, 0x2B2B2B2Bu)
DEAD_BODY(13, 0x3C3C3C3Cu)
DEAD_BODY(14, 0x4D4D4D4Du)
DEAD_BODY(15, 0x5E5E5E5Eu)
DEAD_BODY(16, 0x6F6F6F6Fu)
DEAD_BODY(17, 0x70707070u)
DEAD_BODY(18, 0x88888888u)
DEAD_BODY(19, 0x99999999u)
DEAD_BODY(1a, 0xAAAAAAAAu)
DEAD_BODY(1b, 0xBBBBBBBBu)
DEAD_BODY(1c, 0xCCCCCCCCu)
DEAD_BODY(1d, 0xDDDDDDDDu)
DEAD_BODY(1e, 0xEEEEEEEEu)
DEAD_BODY(1f, 0xFFFFFFFFu)

/*
 * Fold all 32 handler addresses into a 32-bit hash and XOR it into
 * fr->session_mix.  Three properties:
 *
 *   1. Forces the linker to keep all 32 function bodies (their addresses are
 *      taken and consumed — --gc-sections / COMDAT folding cannot remove them).
 *   2. Binds the dead-handler layout to session entropy: if the binary is
 *      modified and addresses shift, session_mix changes, propagating into
 *      vv_select_index and altering every subsequent variant selection
 *      (low-key integrity signal).
 *   3. **No static fn-pointer table**: each address is taken inline at its own
 *      ADRP+ADD site rather than via a __const array, so a dref scan of data
 *      sections finds no enumerable dispatch slots.  Recovering the dead set
 *      requires reverse-engineering this routine, not pattern matching.
 *
 * The macro deliberately interleaves a non-trivial mix step between each
 * reference so the address loads do NOT appear as a contiguous block of
 * ADRP+ADD pairs that an attacker could pattern-match in __text.
 */
#define CPRISK_VM_DEAD_FOLD_ONE(fold_var, fn)                                  \
    do {                                                                       \
        const uintptr_t _cprisk_addr = (uintptr_t)(const void *)&(fn);          \
        (fold_var) ^= (uint32_t)_cprisk_addr;                                   \
        (fold_var) ^= (uint32_t)(_cprisk_addr >> 17u);                          \
        (fold_var) ^= (uint32_t)(_cprisk_addr >> 32u);                          \
        (fold_var)  = ((fold_var) << 5u) | ((fold_var) >> 27u);   /* ROTL32 5 */ \
    } while (0)

void cprisk_vm_dead_touch_i(cprisk_vm_interp_frame_t *fr) {
    uint32_t fold = 0x4C4C4C4Cu;

    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_0);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_1);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_2);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_3);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_4);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_5);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_6);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_7);
    /* extra avalanche between batches keeps the fold non-linear so an attacker
     * cannot trivially solve for individual addresses by isolating the rotor. */
    fold = (fold * 0x9E3779B9u) ^ (fold >> 13u);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_8);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_9);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_a);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_b);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_c);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_d);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_e);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_f);
    fold = (fold * 0x85EBCA6Bu) ^ (fold >> 11u);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_10);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_11);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_12);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_13);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_14);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_15);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_16);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_17);
    fold = (fold * 0xC2B2AE35u) ^ (fold >> 16u);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_18);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_19);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_1a);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_1b);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_1c);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_1d);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_1e);
    CPRISK_VM_DEAD_FOLD_ONE(fold, cprisk_vm_oph_dead_1f);

    fr->session_mix ^= fold;
}

#undef CPRISK_VM_DEAD_FOLD_ONE
