/*
 * cprisk_vm_oph_emitter.c
 * CRiskCore
 *
 * Per-opcode canonical handlers for the emitter family:
 *   MOV_WIDE / ADR_ADD / COND_SELECT / LOAD_STORE
 *
 * These were previously all dispatched through the shared cprisk_vm_oph_emitter_family
 * multiplexer.  Splitting them into dedicated handlers lets variant pools be attached
 * to each opcode individually, matching the pattern used by the lane/branch families.
 *
 * The semantics are identical to the original multiplexer — only the opcode constant
 * and the shift amount differ per handler.  For LOAD_STORE the mixed_predicate_profile
 * branch is elided because the condition was always true (logical == LOAD_STORE).
 */

#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

/* MOV_WIDE — logical 8, shift 1 */
cprisk_vm_flow_t cprisk_vm_oph_mov_wide(cprisk_vm_interp_frame_t *fr,
                                         uint8_t op_raw, uint8_t logical,
                                         uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_MOV_WIDE << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm ^ op_salt ^ (imm >> 1u);
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

/* ADR_ADD — logical 9, shift 2 */
cprisk_vm_flow_t cprisk_vm_oph_adr_add(cprisk_vm_interp_frame_t *fr,
                                         uint8_t op_raw, uint8_t logical,
                                         uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_ADR_ADD << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm ^ op_salt ^ (imm >> 2u);
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

/* COND_SELECT — logical 10, shift 3 */
cprisk_vm_flow_t cprisk_vm_oph_cond_select(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw, uint8_t logical,
                                            uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_COND_SELECT << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm ^ op_salt ^ (imm >> 3u);
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

/* LOAD_STORE — logical 11, shift 4; always raw_region (original condition was always true) */
cprisk_vm_flow_t cprisk_vm_oph_load_store(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw, uint8_t logical,
                                           uint64_t imm, uint32_t pc, uint32_t hvar) {
    (void)op_raw; (void)logical;
    const uint64_t op_salt = ((uint64_t)CPRISK_VM_OP_LOAD_STORE << 52u)
                           ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    const uint64_t mix_imm = imm ^ op_salt ^ (imm >> 4u);
    cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps,
                                  hvar ^ (uint32_t)CPRISK_VM_OP_LOAD_STORE,
                                  fr->semantic_family, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
