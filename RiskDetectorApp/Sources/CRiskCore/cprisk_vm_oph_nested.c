#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"

#include <string.h>

cprisk_vm_flow_t cprisk_vm_oph_vm_call_func(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw,
                                            uint8_t logical,
                                            uint64_t imm,
                                            uint32_t pc,
                                            uint32_t hvar) {
    (void)op_raw;
    (void)logical;
    (void)hvar;
    if (fr->vm_snap_sp >= CPRISK_VM_MAX_VM_NEST_DEPTH) {
        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        return CPRISK_VM_FLOW_LEAVE;
    }
    uint64_t callee_id = imm;
    uint64_t ret_pc = (uint64_t)pc + CPRISK_VM_INSN_WIDTH;
    uint64_t ret_enc = 0u;
    if (!cprisk_vm_encode_pc_i(fr->bh, (uint32_t)ret_pc, fr->vpc_a, fr->vpc_b, &ret_enc, fr->out)) {
        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        return CPRISK_VM_FLOW_LEAVE;
    }
    memcpy(fr->vm_snap[fr->vm_snap_sp].snap_vregs, fr->vregs, sizeof(fr->vregs));
    fr->vm_snap[fr->vm_snap_sp].resume_enc_pc = ret_enc;
    fr->vm_snap[fr->vm_snap_sp].snap_code = fr->code;
    fr->vm_snap[fr->vm_snap_sp].snap_blen = fr->blen;
    fr->vm_snap[fr->vm_snap_sp].snap_vpc_a = fr->vpc_a;
    fr->vm_snap[fr->vm_snap_sp].snap_vpc_b = fr->vpc_b;
    fr->vm_snap[fr->vm_snap_sp].snap_semantic_family = fr->semantic_family;
    fr->vm_snap[fr->vm_snap_sp].snap_mixed_predicate_profile = fr->mixed_predicate_profile;
    fr->vm_snap[fr->vm_snap_sp].snap_max_subcall_depth = fr->max_subcall_depth;
    memcpy(fr->vm_snap[fr->vm_snap_sp].snap_ret_stack, fr->return_stack, sizeof(fr->return_stack));
    fr->vm_snap[fr->vm_snap_sp].snap_ret_sp = fr->return_sp;
    fr->vm_snap[fr->vm_snap_sp].snap_acc_lane_map[0] = fr->acc_lane_map[0];
    fr->vm_snap[fr->vm_snap_sp].snap_acc_lane_map[1] = fr->acc_lane_map[1];
    fr->vm_snap[fr->vm_snap_sp].snap_acc_lane_map[2] = fr->acc_lane_map[2];
    fr->vm_snap_sp += 1u;
    memset(fr->vregs, 0, sizeof(fr->vregs));

    const cprisk_vmp_bytecode_entry_t *callee_ent = NULL;
    uint32_t callee_idx = 0u;
    for (; callee_idx < fr->bh->entry_count; callee_idx++) {
        const uint8_t *cep = fr->b_sec + fr->bc_hdr_total + (size_t)callee_idx * fr->entry_stride;
        const cprisk_vmp_bytecode_entry_t *ce = (const cprisk_vmp_bytecode_entry_t *)(const void *)cep;
        if (ce->function_id == callee_id) {
            callee_ent = ce;
            break;
        }
    }
    if (!callee_ent) {
        fr->vm_snap_sp -= 1u;
        memcpy(fr->vregs, fr->vm_snap[fr->vm_snap_sp].snap_vregs, sizeof(fr->vregs));
        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        return CPRISK_VM_FLOW_LEAVE;
    }
    fr->vpc_a = 1u;
    fr->vpc_b = 0u;
    cprisk_vmp_read_vpc_affine_i(fr->b_sec, fr->bh, callee_id, &fr->vpc_a, &fr->vpc_b);
    if ((fr->bh->reserved & CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC) != 0u) {
        const uint8_t *selp = fr->b_sec + fr->bc_hdr_total + (size_t)callee_idx * fr->entry_stride;
        uint64_t pe_raw_a = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t));
        uint64_t pe_raw_b = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t) + 8u);
        /* Derive XOR mask for per-entry VPC decryption */
        uint64_t pe_mask_state = callee_id + UINT64_C(0x53504556);
        uint64_t pe_mask_a = cprisk_splitmix64_next_i(&pe_mask_state);
        pe_mask_a = (pe_mask_a << 32) | cprisk_splitmix64_next_i(&pe_mask_state);
        uint64_t pe_mask_b = cprisk_splitmix64_next_i(&pe_mask_state);
        pe_mask_b = (pe_mask_b << 32) | cprisk_splitmix64_next_i(&pe_mask_state);
        fr->vpc_a = pe_raw_a ^ pe_mask_a;
        fr->vpc_b = pe_raw_b ^ pe_mask_b;
    }
    fr->code = fr->b_sec + callee_ent->bytecode_offset;
    fr->blen = callee_ent->bytecode_length;
    if (!cprisk_vm_encode_pc_i(fr->bh, 0u, fr->vpc_a, fr->vpc_b, &fr->encoded_pc, fr->out))
        return CPRISK_VM_FLOW_LEAVE;
    uint32_t sf = 1u, mp = 0u, msd = 4u;
    if (!cprisk_vm_entry_profile_decode_i(
            callee_ent->reserved,
            &sf,
            &mp,
            &msd
        )) {
        cprisk_vm_entry_profile_fallback_i(
            callee_id,
            fr->bh->reserved,
            &sf,
            &mp,
            &msd
        );
    }
    if (sf == 0u)
        sf = 1u;
    if (msd == 0u)
        msd = 1u;
    if (msd > CPRISK_VM_MAX_SUBCALL_DEPTH)
        msd = CPRISK_VM_MAX_SUBCALL_DEPTH;
    fr->semantic_family = sf;
    fr->mixed_predicate_profile = mp;
    fr->max_subcall_depth = msd;
    {
        static const uint8_t s_lane_perms[8][3] = {
            {0u,1u,2u},{0u,2u,1u},{1u,0u,2u},{1u,2u,0u},
            {2u,0u,1u},{2u,1u,0u},{0u,1u,2u},{0u,1u,2u},
        };
        const uint32_t idx = ((callee_ent->reserved >> 24u) == CPRISK_VMP_ENTRY_PROFILE_MAGIC)
            ? (callee_ent->reserved & 0x7u) : 0u;
        fr->acc_lane_map[0] = s_lane_perms[idx][0];
        fr->acc_lane_map[1] = s_lane_perms[idx][1];
        fr->acc_lane_map[2] = s_lane_perms[idx][2];
    }
    fr->return_sp = 0u;
    memset(fr->return_stack, 0, sizeof(fr->return_stack));
    if (fr->vpc_a == 0u) {
        fr->vm_snap_sp -= 1u;
        memcpy(fr->vregs, fr->vm_snap[fr->vm_snap_sp].snap_vregs, sizeof(fr->vregs));
        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        return CPRISK_VM_FLOW_LEAVE;
    }
    fr->steps += 1u;
    return CPRISK_VM_FLOW_CONTINUE;
}
