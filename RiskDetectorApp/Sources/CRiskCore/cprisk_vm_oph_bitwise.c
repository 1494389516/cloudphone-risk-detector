#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

cprisk_vm_flow_t cprisk_vm_oph_xor_mix(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    uint64_t mix_imm = imm ^ ((imm << 17u) | (imm >> 47u)) ^ ((uint64_t)fr->semantic_family << 56u);
    cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps, hvar ^ 1u, fr->semantic_family ^ 1u, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_or_lane(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)op_raw;
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ fr->opaque_chain ^ fr->session_mix ^ 0x0F0Fu
    );
    cprisk_vm_bitwise_lane_poly_i(
        fr->acc,
        logical,
        imm,
        (uint32_t)fr->steps,
        hvar,
        fr->semantic_family,
        route
    );
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_and_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw;
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ fr->opaque_chain ^ fr->session_mix ^ 0xF0F0u
    );
    cprisk_vm_bitwise_lane_poly_i(
        fr->acc,
        logical,
        imm,
        (uint32_t)fr->steps,
        hvar,
        fr->semantic_family,
        route
    );
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_rol_acc(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)pc;
    (void)hvar;
    cprisk_vm_rol_acc_i(fr->acc, imm);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
