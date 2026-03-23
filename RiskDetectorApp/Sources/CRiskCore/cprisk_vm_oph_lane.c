#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

cprisk_vm_flow_t cprisk_vm_oph_add(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0xADDu
    );
    cprisk_vm_lane_apply_poly_i(
        fr->acc,
        0u,
        imm,
        (uint32_t)fr->steps,
        hvar,
        fr->semantic_family,
        fr->func_id,
        pc,
        route
    );
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_sub_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0x5B2u
    );
    cprisk_vm_lane_apply_poly_i(
        fr->acc,
        1u,
        imm,
        (uint32_t)fr->steps,
        hvar,
        fr->semantic_family,
        fr->func_id,
        pc,
        route
    );
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_mul_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    const uint32_t route = cprisk_vmp_avalanche32_i(
        hvar ^ (uint32_t)fr->steps ^ fr->opaque_chain ^ fr->session_mix ^ 0x6D3u
    );
    cprisk_vm_lane_apply_poly_i(
        fr->acc,
        2u,
        imm,
        (uint32_t)fr->steps,
        hvar,
        fr->semantic_family,
        fr->func_id,
        pc,
        route
    );
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
