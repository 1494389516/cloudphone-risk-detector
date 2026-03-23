#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

cprisk_vm_flow_t cprisk_vm_oph_branch_rel(cprisk_vm_interp_frame_t *fr,
                                          uint8_t op_raw,
                                          uint8_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)hvar;
    int64_t delta = (int64_t)(uint64_t)imm;
    if (!cprisk_vm_set_branch_target_ctx_i(
            fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_branch_cond(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw,
                                           uint8_t logical,
                                           uint64_t imm,
                                           uint32_t pc,
                                           uint32_t hvar) {
    (void)hvar;
    int taken = 0;
    int64_t delta = 0;
    if (!cprisk_vm_branch_cond_mixed_eval_i(
            (uint32_t)imm,
            fr->acc,
            fr->steps,
            fr->semantic_family,
            fr->mixed_predicate_profile,
            &taken,
            &delta
        )) {
        fr->out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
        cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op_raw, (uint32_t)logical);
        if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
            return CPRISK_VM_FLOW_LEAVE;
        fr->steps += 1u;
        return CPRISK_VM_FLOW_CONTINUE;
    }
    if (taken) {
        if (!cprisk_vm_set_branch_target_ctx_i(
                fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
            return CPRISK_VM_FLOW_LEAVE;
    } else {
        if (!cprisk_vm_enc_pc_advance_ctx_i(fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->out))
            return CPRISK_VM_FLOW_LEAVE;
    }
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t cprisk_vm_oph_call(cprisk_vm_interp_frame_t *fr,
                                    uint8_t op_raw,
                                    uint8_t logical,
                                    uint64_t imm,
                                    uint32_t pc,
                                    uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)hvar;
    if (fr->return_sp >= fr->max_subcall_depth) {
        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        return CPRISK_VM_FLOW_LEAVE;
    }
    uint64_t ret_pc = (uint64_t)pc + CPRISK_VM_INSN_WIDTH;
    uint64_t ret_enc = 0u;
    if (!cprisk_vm_encode_pc_i(fr->bh, (uint32_t)ret_pc, fr->vpc_a, fr->vpc_b, &ret_enc, fr->out)) {
        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        return CPRISK_VM_FLOW_LEAVE;
    }
    fr->return_stack[fr->return_sp] = ret_enc;
    fr->return_sp += 1u;
    int64_t delta = (int64_t)(uint64_t)imm;
    if (!cprisk_vm_set_branch_target_ctx_i(
            fr->bh, &fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
