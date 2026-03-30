#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

#include <string.h>

cprisk_vm_flow_t cprisk_vm_oph_poison(cprisk_vm_interp_frame_t *fr,
                                      uint8_t op_raw,
                                      uint8_t logical,
                                      uint64_t imm,
                                      uint32_t pc,
                                      uint32_t hvar) {
    (void)imm;
    (void)pc;
    (void)hvar;
    fr->out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
    cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op_raw, (uint32_t)logical);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_unknown(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar) {
    (void)imm;
    (void)pc;
    (void)hvar;
    fr->out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
    cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op_raw, (uint32_t)logical);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_nop(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)imm;
    (void)pc;
    (void)hvar;
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_halt(cprisk_vm_interp_frame_t *fr,
                                    uint8_t op_raw,
                                    uint8_t logical,
                                    uint64_t imm,
                                    uint32_t pc,
                                    uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)imm;
    (void)pc;
    (void)hvar;
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    fr->out->status = CPRISK_VM_STATUS_OK;
    return CPRISK_VM_FLOW_LEAVE;
}

cprisk_vm_flow_t cprisk_vm_oph_ret(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)imm;
    (void)pc;
    (void)hvar;
    if (fr->return_sp > 0u) {
        fr->return_sp -= 1u;
        fr->encoded_pc = fr->return_stack[fr->return_sp];
        fr->steps += 1u;
        return CPRISK_VM_FLOW_CONTINUE;
    }
    if (fr->vm_snap_sp > 0u) {
        fr->vm_snap_sp -= 1u;
        fr->encoded_pc = fr->vm_snap[fr->vm_snap_sp].resume_enc_pc;
        fr->code = fr->vm_snap[fr->vm_snap_sp].snap_code;
        fr->blen = fr->vm_snap[fr->vm_snap_sp].snap_blen;
        fr->vpc_a = fr->vm_snap[fr->vm_snap_sp].snap_vpc_a;
        fr->vpc_b = fr->vm_snap[fr->vm_snap_sp].snap_vpc_b;
        fr->semantic_family = fr->vm_snap[fr->vm_snap_sp].snap_semantic_family;
        fr->mixed_predicate_profile = fr->vm_snap[fr->vm_snap_sp].snap_mixed_predicate_profile;
        fr->max_subcall_depth = fr->vm_snap[fr->vm_snap_sp].snap_max_subcall_depth;
        memcpy(fr->return_stack, fr->vm_snap[fr->vm_snap_sp].snap_ret_stack, sizeof(fr->return_stack));
        fr->return_sp = fr->vm_snap[fr->vm_snap_sp].snap_ret_sp;
        memcpy(fr->vregs, fr->vm_snap[fr->vm_snap_sp].snap_vregs, sizeof(fr->vregs));
        fr->steps += 1u;
        return CPRISK_VM_FLOW_CONTINUE;
    }
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    fr->out->status = CPRISK_VM_STATUS_OK;
    return CPRISK_VM_FLOW_LEAVE;
}

cprisk_vm_flow_t cprisk_vm_oph_raw_region(cprisk_vm_interp_frame_t *fr,
                                          uint8_t op_raw,
                                          uint8_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    uint64_t imm_use = imm;
    if ((fr->dispatch_hdr_flags & CPRISK_VMP_DH_FLAG_OPAQUE_VPC_CATEGORY) != 0u) {
        const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
        imm_use ^= cprisk_vmp_raw_lane_mask_u64_i(fr->func_id, pc_index, fr->raw_bind_root);
    }
    cprisk_vm_raw_region_apply_i(fr->acc, imm_use, (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc);
    if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
