#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"
#include "include/cprisk_vm_oph_variants.h"

static uintptr_t cprisk_vm_oph_materialize_key_i(const cprisk_vm_interp_frame_t *fr,
                                                 uint8_t logical,
                                                 uint32_t hvar,
                                                 uint32_t stage) {
    uint32_t mix =
        (uint32_t)fr->func_id ^
        (uint32_t)(fr->func_id >> 32u) ^
        fr->session_mix ^
        fr->opaque_chain ^
        ((uint32_t)logical * 0x9E3779B9u) ^
        (hvar * 0x85EBCA6Bu) ^
        (fr->path_lane * 0xC2B2AE35u) ^
        ((uint32_t)fr->steps * 0x27D4EB2Du) ^
        (stage * 0x165667B1u);
    mix = cprisk_vmp_avalanche32_i(mix ^ (mix >> 16u));
    return
        (uintptr_t)mix ^
        ((uintptr_t)mix << 17u) ^
        ((uintptr_t)(mix ^ 0xA5A55A5Au) << 33u) ^
        (uintptr_t)0x9E3779B97F4A7C15ULL;
}

static cprisk_vm_oph_fn cprisk_vm_oph_materialize_i(const cprisk_vm_interp_frame_t *fr,
                                                    uint8_t logical,
                                                    uint32_t hvar,
                                                    uint32_t stage,
                                                    cprisk_vm_oph_fn fn) {
    const uintptr_t key = cprisk_vm_oph_materialize_key_i(fr, logical, hvar, stage);
    const uintptr_t enc = ((uintptr_t)(const void *)fn) ^ key;
    return (cprisk_vm_oph_fn)(uintptr_t)(enc ^ key);
}

static cprisk_vm_flow_t cprisk_vm_dispatch_leaf_i(cprisk_vm_interp_frame_t *fr,
                                                  uint8_t op_raw,
                                                  uint8_t logical,
                                                  uint64_t imm,
                                                  uint32_t pc,
                                                  uint32_t hvar,
                                                  uint32_t stage,
                                                  cprisk_vm_oph_fn fn) {
    const cprisk_vm_oph_fn materialized =
        cprisk_vm_oph_materialize_i(fr, logical, hvar, stage, fn);
    return cprisk_vm_dispatch_leaf_wb_wrapped_i(fr, op_raw, logical, imm, pc, hvar, materialized);
}

static cprisk_vm_flow_t cprisk_vm_dispatch_core_family_i(cprisk_vm_interp_frame_t *fr,
                                                         uint8_t op_raw,
                                                         uint8_t logical,
                                                         uint64_t imm,
                                                         uint32_t pc,
                                                         uint32_t hvar) {
    switch (logical) {
    case CPRISK_VM_OP_NOP:
        /* Polymorphic variant pool: rotates among 3 NOP implementations to
         * defeat Capstone L1/L2 address-keyed disassembly caching. */
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x11u, cprisk_vm_oph_select_nop);
    case CPRISK_VM_OP_RET:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x12u, cprisk_vm_oph_ret);
    case CPRISK_VM_OP_RAW_REGION:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x13u, cprisk_vm_oph_raw_region);
    case CPRISK_VM_OP_HALT:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x14u, cprisk_vm_oph_halt);
    default:
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    }
}

static cprisk_vm_flow_t cprisk_vm_dispatch_lane_family_i(cprisk_vm_interp_frame_t *fr,
                                                         uint8_t op_raw,
                                                         uint8_t logical,
                                                         uint64_t imm,
                                                         uint32_t pc,
                                                         uint32_t hvar) {
    switch (logical) {
    case CPRISK_VM_OP_ADD:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x21u, cprisk_vm_oph_select_add);
    case CPRISK_VM_OP_ADD_ROL_ACC:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x29u, cprisk_vm_oph_add_rol_acc);
    case CPRISK_VM_OP_SUB_LANE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x22u, cprisk_vm_oph_sub_lane);
    case CPRISK_VM_OP_MUL_LANE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x23u, cprisk_vm_oph_mul_lane);
    case CPRISK_VM_OP_XOR_MIX:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x24u, cprisk_vm_oph_select_xor_mix);
    case CPRISK_VM_OP_OR_LANE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x25u, cprisk_vm_oph_or_lane);
    case CPRISK_VM_OP_AND_LANE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x26u, cprisk_vm_oph_and_lane);
    case CPRISK_VM_OP_ROL_ACC:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x27u, cprisk_vm_oph_rol_acc);
    default:
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    }
}

static cprisk_vm_flow_t cprisk_vm_dispatch_branch_family_i(cprisk_vm_interp_frame_t *fr,
                                                           uint8_t op_raw,
                                                           uint8_t logical,
                                                           uint64_t imm,
                                                           uint32_t pc,
                                                           uint32_t hvar) {
    switch (logical) {
    case CPRISK_VM_OP_BRANCH_REL:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x31u, cprisk_vm_oph_branch_rel);
    case CPRISK_VM_OP_BRANCH_IND:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x35u, cprisk_vm_oph_branch_ind);
    case CPRISK_VM_OP_BRANCH_COND:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x32u, cprisk_vm_oph_branch_cond);
    case CPRISK_VM_OP_CALL:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x33u, cprisk_vm_oph_call);
    default:
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    }
}

static cprisk_vm_flow_t cprisk_vm_dispatch_emitter_family_i(cprisk_vm_interp_frame_t *fr,
                                                            uint8_t op_raw,
                                                            uint8_t logical,
                                                            uint64_t imm,
                                                            uint32_t pc,
                                                            uint32_t hvar) {
    switch (logical) {
    case CPRISK_VM_OP_MOV_WIDE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x41u, cprisk_vm_oph_emitter_family);
    case CPRISK_VM_OP_ADR_ADD:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x42u, cprisk_vm_oph_emitter_family);
    case CPRISK_VM_OP_COND_SELECT:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x43u, cprisk_vm_oph_emitter_family);
    case CPRISK_VM_OP_LOAD_STORE:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x44u, cprisk_vm_oph_emitter_family);
    default:
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    }
}

static cprisk_vm_flow_t cprisk_vm_dispatch_vreg_family_i(cprisk_vm_interp_frame_t *fr,
                                                         uint8_t op_raw,
                                                         uint8_t logical,
                                                         uint64_t imm,
                                                         uint32_t pc,
                                                         uint32_t hvar) {
    switch (logical) {
    case CPRISK_VM_OP_VM_CALL_FUNC:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x51u, cprisk_vm_oph_vm_call_func);
    case CPRISK_VM_OP_VREG_MOV:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x52u, cprisk_vm_oph_vreg_mov);
    case CPRISK_VM_OP_VREG_ALU:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x53u, cprisk_vm_oph_vreg_alu);
    case CPRISK_VM_OP_VREG_MEM:
        return cprisk_vm_dispatch_leaf_i(fr, op_raw, logical, imm, pc, hvar, 0x54u, cprisk_vm_oph_vreg_mem);
    default:
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    }
}

cprisk_vm_flow_t cprisk_vm_dispatch_oph_materialized_i(cprisk_vm_interp_frame_t *fr,
                                                       uint8_t op_raw,
                                                       uint8_t logical,
                                                       uint64_t imm,
                                                       uint32_t pc,
                                                       uint32_t hvar) {
    if (logical <= CPRISK_VM_OP_HALT)
        return cprisk_vm_dispatch_core_family_i(fr, op_raw, logical, imm, pc, hvar);
    if (logical == CPRISK_VM_OP_ADD || logical == CPRISK_VM_OP_SUB_LANE || logical == CPRISK_VM_OP_MUL_LANE
        || logical == CPRISK_VM_OP_ADD_ROL_ACC
        || (logical >= CPRISK_VM_OP_XOR_MIX && logical <= CPRISK_VM_OP_ROL_ACC)) {
        return cprisk_vm_dispatch_lane_family_i(fr, op_raw, logical, imm, pc, hvar);
    }
    if ((logical >= CPRISK_VM_OP_BRANCH_REL && logical <= CPRISK_VM_OP_CALL) || logical == CPRISK_VM_OP_BRANCH_IND)
        return cprisk_vm_dispatch_branch_family_i(fr, op_raw, logical, imm, pc, hvar);
    if (logical >= CPRISK_VM_OP_MOV_WIDE && logical <= CPRISK_VM_OP_LOAD_STORE)
        return cprisk_vm_dispatch_emitter_family_i(fr, op_raw, logical, imm, pc, hvar);
    if (logical == CPRISK_VM_OP_VM_CALL_FUNC || (logical >= CPRISK_VM_OP_VREG_MOV && logical <= CPRISK_VM_OP_VREG_MEM))
        return cprisk_vm_dispatch_vreg_family_i(fr, op_raw, logical, imm, pc, hvar);
    return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
}
