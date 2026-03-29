/*
 *  vm_cff_fusion.h
 *  CRiskCore
 */

#ifndef VM_CFF_FUSION_H
#define VM_CFF_FUSION_H

#include <stdint.h>
#include <stddef.h>

#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t func_id;
    uint8_t  bytecode_hash[32];
    uint32_t rk[8];
    uint32_t encoded_state;
    uint32_t cff_magic;
    uint32_t trace_buffer[16];
    uint32_t trace_pos;
    uint32_t opaque_chain;
    uint8_t  state_encoded;
    uint8_t  corruption_detected;
    uint8_t  reserved[2];
} vm_cff_fusion_ctx_t;

void vm_cff_fusion_init(vm_cff_fusion_ctx_t *ctx,
                         uint64_t func_id,
                         const uint8_t *bytecode_hash);

uint32_t vm_cff_fusion_encode_pc(vm_cff_fusion_ctx_t *ctx, uint32_t pc);

uint32_t vm_cff_fusion_decode_pc(vm_cff_fusion_ctx_t *ctx, uint32_t encoded_pc);

void vm_cff_fusion_transition(vm_cff_fusion_ctx_t *ctx,
                               uint32_t current_encoded,
                               uint32_t *next_encoded,
                               uint32_t branch_hint);

cprisk_vm_flow_t vm_op_cff_encode_execute(cprisk_vm_interp_frame_t *fr,
                                           uint64_t imm);

cprisk_vm_flow_t vm_op_cff_decode_execute(cprisk_vm_interp_frame_t *fr,
                                           uint64_t imm);

cprisk_vm_flow_t vm_op_cff_transition_execute(cprisk_vm_interp_frame_t *fr,
                                               uint64_t imm);

void vm_cff_fusion_apply_to_interp(cprisk_vm_interp_frame_t *fr);

void vm_cff_fusion_verify_integrity(vm_cff_fusion_ctx_t *ctx);

uint32_t vm_cff_fusion_get_opacity(vm_cff_fusion_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
