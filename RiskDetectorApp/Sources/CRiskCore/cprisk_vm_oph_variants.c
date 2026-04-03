/*
 * cprisk_vm_oph_variants.c
 * CRiskCore
 *
 * Polymorphic variant pool for high-frequency VM opcodes.
 *
 * Counter-measure: Capstone L1/L2 handler-address caching in unidbg魔改版.
 *
 * Problem:
 *   unidbg's optimised trace engine caches Capstone disassembly results keyed
 *   by instruction address.  The VM opcode dispatch in cprisk_vm_oph_table.c
 *   calls a *fixed* function pointer for each logical opcode — e.g., NOP always
 *   calls cprisk_vm_oph_nop at the same address.  After the first execution the
 *   L1 slot for every instruction inside cprisk_vm_oph_nop is warmed; subsequent
 *   calls hit the cache without invoking Capstone again.  Across millions of VM
 *   iterations the same handler code is re-used from cache with zero disassembly
 *   overhead.
 *
 * Solution:
 *   Provide N semantically-equivalent implementations for the same logical opcode
 *   and select among them at runtime using a key derived from (func_id, steps,
 *   opaque_chain).  Each invocation of the same opcode may execute a *different*
 *   function body residing at a *different* code address.  Because Capstone's L1
 *   cache is keyed by address, the cache is only useful if the same address is
 *   re-used — which now happens only 1/N of the time.
 *
 *   Variants are named _v0 (canonical, forwards to existing handler), _v1, _v2.
 *   The _v1/_v2 bodies expand the same semantic operation through different
 *   instruction sequences: shifted-rotate, sub-negate, and double-fold paths.
 *   These are semantically identical to the canonical handlers (produce the same
 *   acc/pc/steps result) but their ARM64 encodings are distinct, ensuring
 *   Capstone sees a different instruction stream on each cache-miss path.
 *
 * Usage:
 *   cprisk_vm_oph_table.c calls cprisk_vm_oph_select_variant() to pick which
 *   variant to dispatch, instead of always calling the canonical handler.
 */

#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"
#include "include/cprisk_vm_oph_variants.h"

#include <string.h>

/* ── Internal helpers ─────────────────────────────────────────────────────── */

static inline uint32_t vv_avalanche32(uint32_t x) {
    x ^= x >> 16u;
    x *= 0x7FEB352Du;
    x ^= x >> 15u;
    x *= 0x846CA68Bu;
    x ^= x >> 16u;
    return x;
}

/*
 * Derive a 2-bit variant index [0, N-1] from execution context.
 * Mixes func_id, step count, opaque_chain, and logical opcode so that:
 *   - The same opcode at the same PC in the same function picks the same
 *     variant on a given run (deterministic within a run → correct semantics).
 *   - Different functions / different step counts produce different indices.
 *   - The index changes across function invocations because opaque_chain is
 *     updated by the VM hardening layer on every instruction.
 */
static inline uint32_t vv_select_index(const cprisk_vm_interp_frame_t *fr,
                                        uint8_t logical,
                                        uint32_t n_variants) {
    const uint32_t mix = vv_avalanche32(
        (uint32_t)fr->func_id ^
        (uint32_t)(fr->func_id >> 32u) ^
        (uint32_t)fr->steps ^
        fr->opaque_chain ^
        fr->session_mix ^
        ((uint32_t)logical * 0x9E3779B9u)
    );
    return mix % n_variants;
}

/* ── NOP variants ─────────────────────────────────────────────────────────── */

/* v0: canonical (delegates to existing handler) */
cprisk_vm_flow_t cprisk_vm_oph_nop_v0(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    return cprisk_vm_oph_nop(fr, op_raw, logical, imm, pc, hvar);
}

/*
 * v1: NOP via double-XOR identity (a ^ b ^ b == a).
 * Expands to: load acc-byte, XOR with session_mix, XOR back with session_mix.
 * Semantically identical: acc unchanged, but instruction stream differs.
 */
cprisk_vm_flow_t cprisk_vm_oph_nop_v1(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)op_raw; (void)logical; (void)imm; (void)hvar;
    /* Double-XOR identity: acc[pc&3] ^= mask; acc[pc&3] ^= mask  — net zero */
    const uint8_t mask = (uint8_t)(fr->session_mix ^ (uint32_t)pc ^ 0xA5u);
    const uint32_t slot = pc & 3u;
    fr->acc[slot] ^= mask;
    fr->acc[slot] ^= mask;   /* cancels out */
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * v2: NOP via add-then-subtract identity.
 * opaque_chain += delta; opaque_chain -= delta  — net zero to output, but
 * cprisk_vm_hardening reads opaque_chain between instructions so it sees the
 * momentary perturbation — this is intentional (fake dependency injection).
 */
cprisk_vm_flow_t cprisk_vm_oph_nop_v2(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)op_raw; (void)logical; (void)imm;
    const uint32_t delta = vv_avalanche32(hvar ^ (uint32_t)fr->steps ^ 0x4E4F5076u);
    fr->opaque_chain += delta;
    fr->opaque_chain -= delta;   /* net zero */
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* ── XOR_MIX variants ──────────────────────────────────────────────────────── */

/* v0: canonical */
cprisk_vm_flow_t cprisk_vm_oph_xor_mix_v0(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw,
                                            uint8_t logical,
                                            uint64_t imm,
                                            uint32_t pc,
                                            uint32_t hvar) {
    return cprisk_vm_oph_xor_mix(fr, op_raw, logical, imm, pc, hvar);
}

/*
 * v1: XOR via shift-fold path.
 * Computes the same mix_imm as the canonical handler but through a split
 * left-shift/right-shift sequence rather than a combined rotation.
 * ((imm << 17) | (imm >> 47)) == ROTL64(imm, 17).
 */
cprisk_vm_flow_t cprisk_vm_oph_xor_mix_v1(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw,
                                            uint8_t logical,
                                            uint64_t imm,
                                            uint32_t pc,
                                            uint32_t hvar) {
    (void)op_raw; (void)logical;
    /* Split rotation into two shifts to produce a different instruction stream
     * while computing the identical mix_imm value. */
    const uint64_t lo_shift = imm << 17u;
    const uint64_t hi_shift = imm >> 47u;
    const uint64_t rotated  = lo_shift | hi_shift;
    const uint64_t family_tag = (uint64_t)fr->semantic_family << 56u;
    uint64_t mix_imm = imm ^ rotated ^ family_tag;
    cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                                  hvar ^ 1u, fr->semantic_family ^ 1u,
                                  fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * v2: XOR via NOT-NOT identity path.
 * Computes mix_imm via ~(~imm ^ mask) which equals imm ^ mask, then applies
 * the same raw_region.  Different instruction encoding, identical result.
 */
cprisk_vm_flow_t cprisk_vm_oph_xor_mix_v2(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw,
                                            uint8_t logical,
                                            uint64_t imm,
                                            uint32_t pc,
                                            uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t rot_mask  = (imm << 17u) | (imm >> 47u);
    const uint64_t fam_tag   = (uint64_t)fr->semantic_family << 56u;
    /* ~(~imm ^ m) == imm ^ m for any m — double-NOT fold */
    const uint64_t mix_imm   = ~(~imm ^ rot_mask ^ fam_tag);   /* == imm ^ rot_mask ^ fam_tag */
    cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                                  hvar ^ 1u, fr->semantic_family ^ 1u,
                                  fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* ── ADD variants ──────────────────────────────────────────────────────────── */

/* v0: canonical */
cprisk_vm_flow_t cprisk_vm_oph_add_v0(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    return cprisk_vm_oph_add(fr, op_raw, logical, imm, pc, hvar);
}

/*
 * v1: ADD via sub-negate identity.
 * acc += imm  is equivalent to  acc -= (-imm).  Use two's complement:
 * -imm == (~imm + 1).  Different instruction sequence, same result.
 */
cprisk_vm_flow_t cprisk_vm_oph_add_v1(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)op_raw;
    /* Transform imm through negate-negate identity before passing to the
     * canonical poly helper so the immediate value arrives via a different
     * code path (different ARM64 encoding) but is semantically unchanged. */
    const uint64_t negated_imm  = (~imm) + 1u;          /* -imm (two's complement) */
    const uint64_t recovered_imm = (~negated_imm) + 1u; /* -(-imm) == imm */
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0xADD1u
    );
    cprisk_vm_lane_apply_poly_i(
        fr->acc, 0u, recovered_imm,
        (uint32_t)fr->steps, hvar,
        fr->semantic_family, fr->func_id, pc, route
    );
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, 0u, recovered_imm, route, pc, hvar);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * v2: ADD via double-add-subtract path.
 * acc += imm  via:  acc += (imm + K); acc -= K  where K is a per-invocation
 * constant derived from session state.  Semantically identical, structurally
 * different — generates a longer instruction sequence that the Capstone cache
 * must disassemble separately.
 */
cprisk_vm_flow_t cprisk_vm_oph_add_v2(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)op_raw;
    const uint64_t K = (uint64_t)vv_avalanche32(fr->session_mix ^ hvar ^ 0xADD2u);
    const uint64_t imm_plus_K  = imm + K;
    const uint64_t route64 = (uint64_t)cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0xADD2u
    );
    const uint32_t route = (uint32_t)route64;

    /* Step 1: add (imm + K) */
    cprisk_vm_lane_apply_poly_i(
        fr->acc, 0u, imm_plus_K,
        (uint32_t)fr->steps, hvar,
        fr->semantic_family, fr->func_id, pc, route
    );
    /* Step 2: subtract K to cancel — net result is acc += imm */
    cprisk_vm_lane_apply_poly_i(
        fr->acc, 0u, K,
        (uint32_t)fr->steps, hvar ^ 0xFFFFFFFFu,
        fr->semantic_family ^ 0xFFu, fr->func_id ^ 0xFFFFFFFFFFFFFFFFULL, pc ^ 0xFFFFFFFFu,
        route ^ 0xFFFFFFFFu
    );
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, 0u, imm, route, pc, hvar);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* ── Variant selector ──────────────────────────────────────────────────────── */

#define CPRISK_VM_OPH_N_VARIANTS 3u

cprisk_vm_flow_t cprisk_vm_oph_select_nop(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw,
                                           uint8_t logical,
                                           uint64_t imm,
                                           uint32_t pc,
                                           uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS] = {
        cprisk_vm_oph_nop_v0,
        cprisk_vm_oph_nop_v1,
        cprisk_vm_oph_nop_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

cprisk_vm_flow_t cprisk_vm_oph_select_xor_mix(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw,
                                               uint8_t logical,
                                               uint64_t imm,
                                               uint32_t pc,
                                               uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS] = {
        cprisk_vm_oph_xor_mix_v0,
        cprisk_vm_oph_xor_mix_v1,
        cprisk_vm_oph_xor_mix_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

cprisk_vm_flow_t cprisk_vm_oph_select_add(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw,
                                           uint8_t logical,
                                           uint64_t imm,
                                           uint32_t pc,
                                           uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS] = {
        cprisk_vm_oph_add_v0,
        cprisk_vm_oph_add_v1,
        cprisk_vm_oph_add_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}
