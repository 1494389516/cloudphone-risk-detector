#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

cprisk_vm_flow_t cprisk_vm_oph_vreg_mov(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)pc;
    (void)hvar;
    cprisk_vm_vreg_mov_i(fr->vregs, fr->acc, imm);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_vreg_alu(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)pc;
    (void)hvar;
    cprisk_vm_vreg_alu_i(fr->vregs, imm);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_vreg_mem(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)hvar;
    cprisk_vm_vreg_mem_i(fr->vregs, fr->acc, imm);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_emitter_family(cprisk_vm_interp_frame_t *fr,
                                              uint8_t op_raw,
                                              uint8_t logical,
                                              uint64_t imm,
                                              uint32_t pc,
                                              uint32_t hvar) {
    (void)op_raw;
    uint64_t op_salt = ((uint64_t)logical << 52u) ^ ((uint64_t)(uint32_t)fr->steps << 11u);
    uint64_t mix_imm = imm ^ op_salt ^ (imm >> (((uint32_t)logical & 7u) + 1u));
    if (logical == CPRISK_VM_OP_LOAD_STORE || (((uint32_t)logical ^ fr->mixed_predicate_profile) & 1u) != 0u) {
        cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps, hvar ^ logical, fr->semantic_family, fr->func_id, pc);
    } else {
        cprisk_vm_add_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps, hvar ^ logical, fr->semantic_family, fr->func_id, pc);
    }
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
