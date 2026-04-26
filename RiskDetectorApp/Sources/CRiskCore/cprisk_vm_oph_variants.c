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
 *   and select among them at runtime using a key derived from (func_id,
 *   opaque_chain, opaque_session_mix).  Each invocation of the same opcode may
 *   execute a *different*
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
 * Derive a variant index [0, N-1] from execution context.
 *
 * v7.5 entropy fix: removed fr->steps (sequential, predictable — an attacker
 * tracing N invocations can map (func_id, steps_mod_N) → variant_index and
 * precompute the full dispatch schedule).
 *
 * Replacement sources:
 *   - fr->opaque_chain    : updated every instruction by the VM hardening layer
 *                           (non-monotonic, depends on opcode sequence)
 *   - fr->opaque_session_mix : derived at session start, stable within a run but
 *                              changes between runs (breaks cross-run correlation)
 *   - fr->func_id / logical  : stable identifiers kept for determinism guarantee
 *
 * Selection is deterministic within a single function execution (correct
 * semantics) but unpredictable across sessions and across positions in the
 * bytecode stream.
 */
static inline uint32_t vv_select_index(const cprisk_vm_interp_frame_t *fr,
                                        uint8_t logical,
                                        uint32_t n_variants) {
    const uint32_t mix = vv_avalanche32(
        (uint32_t)fr->func_id ^
        (uint32_t)(fr->func_id >> 32u) ^
        fr->opaque_chain ^
        fr->opaque_session_mix ^
        fr->session_mix ^
        ((uint32_t)logical * 0x9E3779B9u)
    );
    /* Bias-free reduction via Lemire's method for n_variants <= 256. */
    return (uint32_t)(((uint64_t)mix * (uint64_t)n_variants) >> 32u);
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
    (void)op_raw; (void)logical; (void)imm; (void)pc;
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
    (void)op_raw; (void)logical;
    /* Transform imm through negate-negate identity before passing to the
     * canonical poly helper so the immediate value arrives via a different
     * code path (different ARM64 encoding) but is semantically unchanged. */
    const uint64_t negated_imm  = (~imm) + 1u;          /* -imm (two's complement) */
    const uint64_t recovered_imm = (~negated_imm) + 1u; /* -(-imm) == imm */
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0xADD1u
    );
    cprisk_vm_lane_apply_poly_i(
        fr->acc, fr->acc_lane_map[0], recovered_imm,
        (uint32_t)fr->steps, hvar,
        fr->semantic_family, fr->func_id, pc, route
    );
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[0], recovered_imm, route, pc, hvar);
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
    (void)op_raw; (void)logical;
    const uint64_t K = (uint64_t)vv_avalanche32(fr->session_mix ^ hvar ^ 0xADD2u);
    const uint64_t imm_plus_K  = imm + K;
    const uint64_t route64 = (uint64_t)cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0xADD2u
    );
    const uint32_t route = (uint32_t)route64;

    /* Step 1: add (imm + K) */
    cprisk_vm_lane_apply_poly_i(
        fr->acc, fr->acc_lane_map[0], imm_plus_K,
        (uint32_t)fr->steps, hvar,
        fr->semantic_family, fr->func_id, pc, route
    );
    /* Step 2: subtract K to cancel — net result is acc += imm */
    cprisk_vm_lane_apply_poly_i(
        fr->acc, fr->acc_lane_map[0], K,
        (uint32_t)fr->steps, hvar ^ 0xFFFFFFFFu,
        fr->semantic_family ^ 0xFFu, fr->func_id ^ 0xFFFFFFFFFFFFFFFFULL, pc ^ 0xFFFFFFFFu,
        route ^ 0xFFFFFFFFu
    );
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[0], imm, route, pc, hvar);
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

/* ═══════════════════════════════════════════════════════════════════════════
 * v7.5: Variants for OR_LANE / AND_LANE / SUB_LANE / ROL_ACC / BRANCH_REL
 *
 * Coverage rationale: the original pool only covered 3 of 23 opcodes (13%).
 * The remaining 87% had stable handler addresses, giving dynamic analysis
 * tools a trivial 1:1 opcode→address mapping after a single execution.
 * Adding variant pools for these high-frequency opcodes raises the enumeration
 * cost from O(1) to O(N_variants × executions) for each covered opcode.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── OR_LANE variants ─────────────────────────────────────────────────────── */

/* v0: canonical */
cprisk_vm_flow_t cprisk_vm_oph_or_lane_v0(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw, uint8_t logical,
                                           uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_or_lane(fr, op_raw, logical, imm, pc, hvar);
}

/*
 * v1: split-operand route.  Same route value as canonical (hvar ^ opaque_chain ^
 * session_mix ^ 0x0F0Fu → avalanche32) but computed through explicit intermediate
 * variables.  Different instruction sequence, identical result.
 */
cprisk_vm_flow_t cprisk_vm_oph_or_lane_v1(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw, uint8_t logical,
                                           uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)pc;
    const uint32_t a = hvar ^ fr->opaque_chain;
    const uint32_t b = fr->session_mix ^ 0x0F0Fu;
    const uint32_t route = cprisk_vmp_avalanche32_i(a ^ b);
    cprisk_vm_bitwise_lane_poly_i(
        fr->acc, logical, imm, (uint32_t)fr->steps, hvar,
        fr->semantic_family, route);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc,
                                         fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * v2: complement-fold route.  ~(~x) == x: double-NOT on the mix before
 * avalanche.  Produces identical route, different ARM64 MVN/EOR encoding.
 */
cprisk_vm_flow_t cprisk_vm_oph_or_lane_v2(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw, uint8_t logical,
                                           uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)pc;
    const uint32_t raw = hvar ^ fr->opaque_chain ^ fr->session_mix ^ 0x0F0Fu;
    const uint32_t route = cprisk_vmp_avalanche32_i(~(~raw));   /* ~(~x) == x */
    cprisk_vm_bitwise_lane_poly_i(
        fr->acc, logical, imm, (uint32_t)fr->steps, hvar,
        fr->semantic_family, route);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc,
                                         fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* ── AND_LANE variants ────────────────────────────────────────────────────── */

/* v0: canonical */
cprisk_vm_flow_t cprisk_vm_oph_and_lane_v0(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_and_lane(fr, op_raw, logical, imm, pc, hvar);
}

/* v1: paired-shift route computation (shift-left then shift-right same amount → identity). */
cprisk_vm_flow_t cprisk_vm_oph_and_lane_v1(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)pc;
    /* (x << 1 >> 1) kills the MSB, but we XOR it back immediately → net identity */
    const uint32_t base = hvar ^ fr->opaque_chain ^ fr->session_mix ^ 0xF0F0u;
    const uint32_t fold = ((base << 1u) >> 1u) ^ (base & 0x80000000u);
    const uint32_t route = cprisk_vmp_avalanche32_i(fold);
    cprisk_vm_bitwise_lane_poly_i(
        fr->acc, logical, imm, (uint32_t)fr->steps, hvar,
        fr->semantic_family, route);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc,
                                         fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* v2: add-subtract identity route path. */
cprisk_vm_flow_t cprisk_vm_oph_and_lane_v2(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)pc;
    const uint32_t k = fr->opaque_chain ^ 0xF0F0u;
    /* (x + k - k) == x, but prevents constant folding since k is runtime. */
    const uint32_t base = (hvar ^ fr->session_mix) + k - k;
    const uint32_t route = cprisk_vmp_avalanche32_i(base ^ fr->opaque_chain);
    cprisk_vm_bitwise_lane_poly_i(
        fr->acc, logical, imm, (uint32_t)fr->steps, hvar,
        fr->semantic_family, route);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc,
                                         fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* ── SUB_LANE variants ────────────────────────────────────────────────────── */

/* v0: canonical */
cprisk_vm_flow_t cprisk_vm_oph_sub_lane_v0(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_sub_lane(fr, op_raw, logical, imm, pc, hvar);
}

/*
 * v1: imm via add-then-restore identity.
 * imm_eff = (imm + session_mix) - session_mix == imm.
 * Passes the recovered imm to the same lane poly path → identical accumulator result.
 */
cprisk_vm_flow_t cprisk_vm_oph_sub_lane_v1(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t noise   = (uint64_t)fr->session_mix ^ (uint64_t)fr->opaque_chain;
    const uint64_t imm_eff = (imm + noise) - noise;   /* == imm */
    const uint32_t route   = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0x5B2u);
    cprisk_vm_lane_apply_poly_i(fr->acc, fr->acc_lane_map[1], imm_eff,
        (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc, route);
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[1], imm_eff, route, pc, hvar);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc,
                                         fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * v2: double-negate imm path.  -(-imm) == imm in two's complement; emits
 * two NEG instructions before the lane poly call → distinct ARM64 encoding.
 */
cprisk_vm_flow_t cprisk_vm_oph_sub_lane_v2(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t neg1    = (~imm) + 1u;              /* -imm (two's complement) */
    const uint64_t imm_eff = (~neg1) + 1u;             /* -(-imm) == imm */
    const uint32_t route   = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0x5B2u);
    cprisk_vm_lane_apply_poly_i(fr->acc, fr->acc_lane_map[1], imm_eff,
        (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc, route);
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[1], imm_eff, route, pc, hvar);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc,
                                         fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* ── ROL_ACC variants ─────────────────────────────────────────────────────── */

/* v0: canonical */
cprisk_vm_flow_t cprisk_vm_oph_rol_acc_v0(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw, uint8_t logical,
                                           uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_rol_acc(fr, op_raw, logical, imm, pc, hvar);
}

/*
 * v1: imm via session-add-subtract identity.
 * rot_imm = (imm + session_mix) - session_mix == imm.
 * cprisk_vm_rol_acc_i uses imm mod rotation_width; identity preserves the value.
 */
cprisk_vm_flow_t cprisk_vm_oph_rol_acc_v1(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw, uint8_t logical,
                                           uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical; (void)pc; (void)hvar;
    const uint64_t s       = (uint64_t)fr->session_mix;
    const uint64_t rot_imm = (imm + s) - s;   /* == imm, runtime-opaque to compiler */
    cprisk_vm_rol_acc_i(fr->acc, rot_imm);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc,
                                         fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * v2: double-negate rotation amount.  -(-imm) == imm; generates two's-
 * complement negation sequence before the rol_acc call.
 */
cprisk_vm_flow_t cprisk_vm_oph_rol_acc_v2(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw, uint8_t logical,
                                           uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical; (void)pc; (void)hvar;
    const uint64_t neg     = (~imm) + 1u;
    const uint64_t rot_imm = (~neg)  + 1u;   /* -(-imm) == imm */
    cprisk_vm_rol_acc_i(fr->acc, rot_imm);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc,
                                         fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* ── BRANCH_REL variants ──────────────────────────────────────────────────── */

/* v0: canonical */
cprisk_vm_flow_t cprisk_vm_oph_branch_rel_v0(cprisk_vm_interp_frame_t *fr,
                                              uint8_t op_raw, uint8_t logical,
                                              uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_branch_rel(fr, op_raw, logical, imm, pc, hvar);
}

/*
 * v1: double-negate delta.  -(-(int64_t)imm) == (int64_t)imm.
 * Emits two's-complement negation twice before the branch target set call.
 */
cprisk_vm_flow_t cprisk_vm_oph_branch_rel_v1(cprisk_vm_interp_frame_t *fr,
                                              uint8_t op_raw, uint8_t logical,
                                              uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical; (void)hvar;
    const int64_t neg   = -(int64_t)(uint64_t)imm;
    const int64_t delta =  -neg;   /* == (int64_t)imm */
    if (!cprisk_vm_set_branch_target_ctx_i(fr->bh, &fr->encoded_pc,
                                            fr->vpc_a, fr->vpc_b, fr->blen,
                                            pc, delta, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * v2: XOR-fold delta identity.  (imm ^ K) ^ K == imm for any K.
 * Uses session_mix as K; compiler cannot constant-fold away the runtime XOR.
 */
cprisk_vm_flow_t cprisk_vm_oph_branch_rel_v2(cprisk_vm_interp_frame_t *fr,
                                              uint8_t op_raw, uint8_t logical,
                                              uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical; (void)hvar;
    const uint64_t key   = (uint64_t)fr->session_mix ^ (uint64_t)fr->opaque_chain;
    const int64_t  delta = (int64_t)((imm ^ key) ^ key);   /* == (int64_t)imm */
    if (!cprisk_vm_set_branch_target_ctx_i(fr->bh, &fr->encoded_pc,
                                            fr->vpc_a, fr->vpc_b, fr->blen,
                                            pc, delta, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* ── Selectors for new opcode variant pools ───────────────────────────────── */

#define CPRISK_VM_OPH_N_VARIANTS_LANE 3u

cprisk_vm_flow_t cprisk_vm_oph_select_or_lane(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_or_lane_v0,
        cprisk_vm_oph_or_lane_v1,
        cprisk_vm_oph_or_lane_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

cprisk_vm_flow_t cprisk_vm_oph_select_and_lane(cprisk_vm_interp_frame_t *fr,
                                                uint8_t op_raw, uint8_t logical,
                                                uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_and_lane_v0,
        cprisk_vm_oph_and_lane_v1,
        cprisk_vm_oph_and_lane_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

cprisk_vm_flow_t cprisk_vm_oph_select_sub_lane(cprisk_vm_interp_frame_t *fr,
                                                uint8_t op_raw, uint8_t logical,
                                                uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_sub_lane_v0,
        cprisk_vm_oph_sub_lane_v1,
        cprisk_vm_oph_sub_lane_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

cprisk_vm_flow_t cprisk_vm_oph_select_rol_acc(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_rol_acc_v0,
        cprisk_vm_oph_rol_acc_v1,
        cprisk_vm_oph_rol_acc_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

cprisk_vm_flow_t cprisk_vm_oph_select_branch_rel(cprisk_vm_interp_frame_t *fr,
                                                  uint8_t op_raw, uint8_t logical,
                                                  uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_branch_rel_v0,
        cprisk_vm_oph_branch_rel_v1,
        cprisk_vm_oph_branch_rel_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

/* ── MUL_LANE variants ────────────────────────────────────────────────────── */

/* v0: canonical */
cprisk_vm_flow_t cprisk_vm_oph_mul_lane_v0(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_mul_lane(fr, op_raw, logical, imm, pc, hvar);
}

/*
 * v1: imm via add-noise-restore identity.  (imm + N) - N == imm where N is
 * derived from runtime-opaque session state, preventing the compiler from
 * folding the operation away.  Result identical to canonical handler.
 */
cprisk_vm_flow_t cprisk_vm_oph_mul_lane_v1(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t noise   = (uint64_t)fr->session_mix ^ (uint64_t)fr->opaque_chain ^ 0x6D31u;
    const uint64_t imm_eff = (imm + noise) - noise;   /* == imm */
    const uint32_t route   = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0x6D3u);
    cprisk_vm_lane_apply_poly_i(fr->acc, fr->acc_lane_map[2], imm_eff,
        (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc, route);
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[2], imm_eff, route, pc, hvar);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc,
                                         fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * v2: imm via XOR-fold identity.  (imm ^ K) ^ K == imm.  Generates a different
 * ARM64 instruction sequence (two EOR ops vs the canonical's straight pass-through)
 * so the Capstone L1/L2 cache sees a distinct address pattern for v2 invocations.
 */
cprisk_vm_flow_t cprisk_vm_oph_mul_lane_v2(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t key     = (uint64_t)fr->session_mix ^ ((uint64_t)fr->opaque_chain << 32u);
    const uint64_t imm_eff = (imm ^ key) ^ key;   /* == imm */
    const uint32_t route   = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0x6D3u);
    cprisk_vm_lane_apply_poly_i(fr->acc, fr->acc_lane_map[2], imm_eff,
        (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc, route);
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[2], imm_eff, route, pc, hvar);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc,
                                         fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_select_mul_lane(cprisk_vm_interp_frame_t *fr,
                                                uint8_t op_raw, uint8_t logical,
                                                uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_mul_lane_v0,
        cprisk_vm_oph_mul_lane_v1,
        cprisk_vm_oph_mul_lane_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

/* ── ADD_ROL_ACC variants ─────────────────────────────────────────────────── */

/*
 * ADD_ROL_ACC is a fused opcode: low-32(imm) feeds the add lane, high-32(imm)
 * is the rotation amount.  Variants apply independent identity transforms to
 * each half so both the lane-poly and the rol call receive the correct values
 * while the ARM64 instruction sequence differs across invocations.
 */

/* v0: canonical */
cprisk_vm_flow_t cprisk_vm_oph_add_rol_acc_v0(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_add_rol_acc(fr, op_raw, logical, imm, pc, hvar);
}

/*
 * v1: double-negate add half + add-noise-restore rotation half.
 * -(-x) == x  and  (x + N) - N == x — different NEG/ADD/SUB sequence.
 */
cprisk_vm_flow_t cprisk_vm_oph_add_rol_acc_v1(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t raw_add  = imm & 0xFFFFFFFFu;
    const uint64_t raw_rol  = imm >> 32u;
    const uint64_t neg_add  = (~raw_add) + 1u;
    const uint64_t imm_add  = (~neg_add) + 1u;              /* == raw_add */
    const uint64_t noise    = (uint64_t)fr->session_mix ^ (uint64_t)fr->opaque_chain ^ 0xA001u;
    const uint64_t imm_rol  = (raw_rol + noise) - noise;    /* == raw_rol */
    const uint32_t route    = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0xADDu ^ 0xF15510F0u);
    cprisk_vm_lane_apply_poly_i(
        fr->acc, fr->acc_lane_map[0], imm_add,
        (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc, route);
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[0], imm_add, route, pc, hvar);
    cprisk_vm_rol_acc_i(fr->acc, imm_rol);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * v2: XOR-fold add half + double-negate rotation half.
 * (x ^ K) ^ K == x  and  -(-x) == x — different EOR/NEG sequence.
 */
cprisk_vm_flow_t cprisk_vm_oph_add_rol_acc_v2(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t raw_add  = imm & 0xFFFFFFFFu;
    const uint64_t raw_rol  = imm >> 32u;
    const uint64_t key      = (uint64_t)fr->session_mix ^ ((uint64_t)fr->opaque_chain << 17u);
    const uint64_t imm_add  = (raw_add ^ key) ^ key;        /* == raw_add */
    const uint64_t neg_rol  = (~raw_rol) + 1u;
    const uint64_t imm_rol  = (~neg_rol) + 1u;              /* == raw_rol */
    const uint32_t route    = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0xADDu ^ 0xF15510F0u);
    cprisk_vm_lane_apply_poly_i(
        fr->acc, fr->acc_lane_map[0], imm_add,
        (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc, route);
    cprisk_vm_diophantine_lane_poly_sidefx_i(fr, fr->acc_lane_map[0], imm_add, route, pc, hvar);
    cprisk_vm_rol_acc_i(fr->acc, imm_rol);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_select_add_rol_acc(cprisk_vm_interp_frame_t *fr,
                                                   uint8_t op_raw, uint8_t logical,
                                                   uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_add_rol_acc_v0,
        cprisk_vm_oph_add_rol_acc_v1,
        cprisk_vm_oph_add_rol_acc_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

/* ── BRANCH_COND variants ─────────────────────────────────────────────────── */

/*
 * cprisk_vm_branch_cond_mixed_eval_i takes uint32_t insn = (uint32_t)imm.  The
 * predicate result depends on (insn, fr->acc, fr->steps, semantic_family,
 * mixed_predicate_profile) — none of which we modify.  The variants only
 * transform imm through low-32-bit identity operations before the eval call.
 */

/* v0: canonical */
cprisk_vm_flow_t cprisk_vm_oph_branch_cond_v0(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_branch_cond(fr, op_raw, logical, imm, pc, hvar);
}

/* v1: imm via add-noise-restore identity, applied to the low 32 bits. */
cprisk_vm_flow_t cprisk_vm_oph_branch_cond_v1(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    const uint32_t noise   = fr->session_mix ^ fr->opaque_chain ^ 0xBC11u;
    const uint32_t lo_eff  = ((uint32_t)imm + noise) - noise;   /* == low32(imm) */
    const uint64_t imm_eff = (imm & 0xFFFFFFFF00000000ULL) | (uint64_t)lo_eff;
    return cprisk_vm_oph_branch_cond(fr, op_raw, logical, imm_eff, pc, hvar);
}

/* v2: imm via XOR-fold identity on low 32 bits — different ARM64 EOR sequence. */
cprisk_vm_flow_t cprisk_vm_oph_branch_cond_v2(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    const uint32_t key     = fr->session_mix ^ (fr->opaque_chain << 7u) ^ 0xBC22u;
    const uint32_t lo_eff  = ((uint32_t)imm ^ key) ^ key;       /* == low32(imm) */
    const uint64_t imm_eff = (imm & 0xFFFFFFFF00000000ULL) | (uint64_t)lo_eff;
    return cprisk_vm_oph_branch_cond(fr, op_raw, logical, imm_eff, pc, hvar);
}

cprisk_vm_flow_t cprisk_vm_oph_select_branch_cond(cprisk_vm_interp_frame_t *fr,
                                                   uint8_t op_raw, uint8_t logical,
                                                   uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_branch_cond_v0,
        cprisk_vm_oph_branch_cond_v1,
        cprisk_vm_oph_branch_cond_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Emitter-family variant pools: MOV_WIDE / ADR_ADD / COND_SELECT / LOAD_STORE
 *
 * The shared cprisk_vm_oph_emitter_family multiplexer has been split into
 * per-opcode canonical handlers in cprisk_vm_oph_emitter.c.  This enables
 * a variant pool per opcode: v1 applies a double-negate identity to imm before
 * computing mix_imm; v2 applies an XOR-fold identity.  Both transforms leave
 * imm bitwise unchanged, so mix_imm and the acc/steps update are identical to
 * the canonical handler — only the ARM64 instruction sequence differs.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── MOV_WIDE variants (logical 8, shift 1) ───────────────────────────────── */

cprisk_vm_flow_t cprisk_vm_oph_mov_wide_v0(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_mov_wide(fr, op_raw, logical, imm, pc, hvar);
}

/* v1: double-negate imm before mix_imm derivation */
cprisk_vm_flow_t cprisk_vm_oph_mov_wide_v1(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t neg     = (~imm) + 1u;
    const uint64_t imm_eff = (~neg) + 1u;                   /* == imm */
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_MOV_WIDE << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm_eff ^ op_salt ^ (imm_eff >> 1u);
    if (((CPRISK_VM_OP_MOV_WIDE ^ fr->mixed_predicate_profile) & 1u) != 0u)
        cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                                      hvar ^ (uint32_t)CPRISK_VM_OP_MOV_WIDE,
                                      fr->semantic_family, fr->func_id, pc);
    else
        cprisk_vm_add_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                               hvar ^ (uint32_t)CPRISK_VM_OP_MOV_WIDE,
                               fr->semantic_family, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* v2: XOR-fold imm before mix_imm derivation */
cprisk_vm_flow_t cprisk_vm_oph_mov_wide_v2(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t key     = (uint64_t)fr->session_mix ^ (uint64_t)fr->opaque_chain;
    const uint64_t imm_eff = (imm ^ key) ^ key;              /* == imm */
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_MOV_WIDE << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm_eff ^ op_salt ^ (imm_eff >> 1u);
    if (((CPRISK_VM_OP_MOV_WIDE ^ fr->mixed_predicate_profile) & 1u) != 0u)
        cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                                      hvar ^ (uint32_t)CPRISK_VM_OP_MOV_WIDE,
                                      fr->semantic_family, fr->func_id, pc);
    else
        cprisk_vm_add_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                               hvar ^ (uint32_t)CPRISK_VM_OP_MOV_WIDE,
                               fr->semantic_family, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_select_mov_wide(cprisk_vm_interp_frame_t *fr,
                                                uint8_t op_raw, uint8_t logical,
                                                uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_mov_wide_v0,
        cprisk_vm_oph_mov_wide_v1,
        cprisk_vm_oph_mov_wide_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

/* ── ADR_ADD variants (logical 9, shift 2) ────────────────────────────────── */

cprisk_vm_flow_t cprisk_vm_oph_adr_add_v0(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw, uint8_t logical,
                                           uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_adr_add(fr, op_raw, logical, imm, pc, hvar);
}

/* v1: double-negate imm */
cprisk_vm_flow_t cprisk_vm_oph_adr_add_v1(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw, uint8_t logical,
                                           uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t neg     = (~imm) + 1u;
    const uint64_t imm_eff = (~neg) + 1u;
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_ADR_ADD << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm_eff ^ op_salt ^ (imm_eff >> 2u);
    if (((CPRISK_VM_OP_ADR_ADD ^ fr->mixed_predicate_profile) & 1u) != 0u)
        cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                                      hvar ^ (uint32_t)CPRISK_VM_OP_ADR_ADD,
                                      fr->semantic_family, fr->func_id, pc);
    else
        cprisk_vm_add_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                               hvar ^ (uint32_t)CPRISK_VM_OP_ADR_ADD,
                               fr->semantic_family, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* v2: XOR-fold imm */
cprisk_vm_flow_t cprisk_vm_oph_adr_add_v2(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw, uint8_t logical,
                                           uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t key     = (uint64_t)fr->session_mix ^ ((uint64_t)fr->opaque_chain << 13u);
    const uint64_t imm_eff = (imm ^ key) ^ key;
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_ADR_ADD << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm_eff ^ op_salt ^ (imm_eff >> 2u);
    if (((CPRISK_VM_OP_ADR_ADD ^ fr->mixed_predicate_profile) & 1u) != 0u)
        cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                                      hvar ^ (uint32_t)CPRISK_VM_OP_ADR_ADD,
                                      fr->semantic_family, fr->func_id, pc);
    else
        cprisk_vm_add_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                               hvar ^ (uint32_t)CPRISK_VM_OP_ADR_ADD,
                               fr->semantic_family, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_select_adr_add(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_adr_add_v0,
        cprisk_vm_oph_adr_add_v1,
        cprisk_vm_oph_adr_add_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

/* ── COND_SELECT variants (logical 10, shift 3) ───────────────────────────── */

cprisk_vm_flow_t cprisk_vm_oph_cond_select_v0(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_cond_select(fr, op_raw, logical, imm, pc, hvar);
}

/* v1: double-negate imm */
cprisk_vm_flow_t cprisk_vm_oph_cond_select_v1(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t neg     = (~imm) + 1u;
    const uint64_t imm_eff = (~neg) + 1u;
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_COND_SELECT << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm_eff ^ op_salt ^ (imm_eff >> 3u);
    if (((CPRISK_VM_OP_COND_SELECT ^ fr->mixed_predicate_profile) & 1u) != 0u)
        cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                                      hvar ^ (uint32_t)CPRISK_VM_OP_COND_SELECT,
                                      fr->semantic_family, fr->func_id, pc);
    else
        cprisk_vm_add_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                               hvar ^ (uint32_t)CPRISK_VM_OP_COND_SELECT,
                               fr->semantic_family, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* v2: XOR-fold imm */
cprisk_vm_flow_t cprisk_vm_oph_cond_select_v2(cprisk_vm_interp_frame_t *fr,
                                               uint8_t op_raw, uint8_t logical,
                                               uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t key     = (uint64_t)fr->session_mix ^ ((uint64_t)fr->opaque_chain << 19u);
    const uint64_t imm_eff = (imm ^ key) ^ key;
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_COND_SELECT << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm_eff ^ op_salt ^ (imm_eff >> 3u);
    if (((CPRISK_VM_OP_COND_SELECT ^ fr->mixed_predicate_profile) & 1u) != 0u)
        cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                                      hvar ^ (uint32_t)CPRISK_VM_OP_COND_SELECT,
                                      fr->semantic_family, fr->func_id, pc);
    else
        cprisk_vm_add_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                               hvar ^ (uint32_t)CPRISK_VM_OP_COND_SELECT,
                               fr->semantic_family, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_select_cond_select(cprisk_vm_interp_frame_t *fr,
                                                   uint8_t op_raw, uint8_t logical,
                                                   uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_cond_select_v0,
        cprisk_vm_oph_cond_select_v1,
        cprisk_vm_oph_cond_select_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}

/* ── LOAD_STORE variants (logical 11, shift 4, always raw_region) ─────────── */

cprisk_vm_flow_t cprisk_vm_oph_load_store_v0(cprisk_vm_interp_frame_t *fr,
                                              uint8_t op_raw, uint8_t logical,
                                              uint64_t imm, uint32_t pc, uint32_t hvar) {
    return cprisk_vm_oph_load_store(fr, op_raw, logical, imm, pc, hvar);
}

/* v1: double-negate imm */
cprisk_vm_flow_t cprisk_vm_oph_load_store_v1(cprisk_vm_interp_frame_t *fr,
                                              uint8_t op_raw, uint8_t logical,
                                              uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t neg     = (~imm) + 1u;
    const uint64_t imm_eff = (~neg) + 1u;
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_LOAD_STORE << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm_eff ^ op_salt ^ (imm_eff >> 4u);
    cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                                  hvar ^ (uint32_t)CPRISK_VM_OP_LOAD_STORE,
                                  fr->semantic_family, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

/* v2: XOR-fold imm */
cprisk_vm_flow_t cprisk_vm_oph_load_store_v2(cprisk_vm_interp_frame_t *fr,
                                              uint8_t op_raw, uint8_t logical,
                                              uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t key     = (uint64_t)fr->session_mix ^ ((uint64_t)fr->opaque_chain << 23u);
    const uint64_t imm_eff = (imm ^ key) ^ key;
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_LOAD_STORE << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm_eff ^ op_salt ^ (imm_eff >> 4u);
    cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                                  hvar ^ (uint32_t)CPRISK_VM_OP_LOAD_STORE,
                                  fr->semantic_family, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_select_load_store(cprisk_vm_interp_frame_t *fr,
                                                  uint8_t op_raw, uint8_t logical,
                                                  uint64_t imm, uint32_t pc, uint32_t hvar) {
    static const cprisk_vm_oph_fn variants[CPRISK_VM_OPH_N_VARIANTS_LANE] = {
        cprisk_vm_oph_load_store_v0,
        cprisk_vm_oph_load_store_v1,
        cprisk_vm_oph_load_store_v2,
    };
    const uint32_t idx = vv_select_index(fr, logical, CPRISK_VM_OPH_N_VARIANTS_LANE);
    return variants[idx](fr, op_raw, logical, imm, pc, hvar);
}
