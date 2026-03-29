/*
 *  vm_cff_fusion.c
 *  CRiskCore
 */

#include "include/CRiskCore.h"
#include "include/cprisk_cff.h"
#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "vm_cff_fusion.h"

#include <string.h>

#define VM_CFF_FEISTEL_ROUNDS       8
#define VM_CFF_MAGIC_INIT           0xCFF0CFF0u
#define VM_CFF_STATE_MASK           0x0FFFFFFFu

static uint32_t vm_cff_feistel_f(uint32_t right, uint32_t round_key) {
    uint32_t x = right ^ round_key;
    x = ((x << 7) | (x >> 25)) ^ 0x9E3779B9u;
    x = ((x * 0x85EBCA6Bu) >> 16) ^ x;
    x = ((x << 13) | (x >> 19)) ^ 0xC2B2AE35u;
    return x & VM_CFF_STATE_MASK;
}

static uint32_t vm_cff_encode_state_i(uint32_t state, const uint32_t *rk) {
    uint32_t left = (state >> 14) & VM_CFF_STATE_MASK;
    uint32_t right = state & VM_CFF_STATE_MASK;

    for (int r = 0; r < VM_CFF_FEISTEL_ROUNDS; r++) {
        uint32_t f_out = vm_cff_feistel_f(right, rk[r]);
        uint32_t new_left = right;
        uint32_t new_right = (left ^ f_out) & VM_CFF_STATE_MASK;
        left = new_left;
        right = new_right;
    }

    return ((left & 0x3FFF) << 14) | (right & 0x3FFF);
}

static uint32_t vm_cff_decode_state_i(uint32_t encoded, const uint32_t *rk) {
    uint32_t left = (encoded >> 14) & 0x3FFF;
    uint32_t right = encoded & 0x3FFF;

    for (int r = VM_CFF_FEISTEL_ROUNDS - 1; r >= 0; r--) {
        uint32_t f_out = vm_cff_feistel_f(left, rk[r]);
        uint32_t new_right = left;
        uint32_t new_left = (right ^ f_out) & 0x3FFF;
        right = new_right;
        left = new_left;
    }

    return ((left & VM_CFF_STATE_MASK) << 14) | (right & VM_CFF_STATE_MASK);
}

void vm_cff_fusion_init(vm_cff_fusion_ctx_t *ctx,
                         uint64_t func_id,
                         const uint8_t *bytecode_hash) {
    if (!ctx) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->func_id = func_id;

    if (bytecode_hash) {
        memcpy(ctx->bytecode_hash, bytecode_hash, 32);
    }

    ctx->cff_magic = VM_CFF_MAGIC_INIT;
    ctx->encoded_state = VM_CFF_MAGIC_INIT;

    uint8_t seed_material[64];
    memcpy(seed_material, &func_id, sizeof(func_id));
    memcpy(seed_material + 8, bytecode_hash ? bytecode_hash : &func_id, 32);

    uint8_t hash_out[32];
    cprisk_sha256(seed_material, 40, hash_out);

    for (int i = 0; i < 8; i++) {
        ctx->rk[i] = ((uint32_t)hash_out[i * 4] << 24) |
                     ((uint32_t)hash_out[i * 4 + 1] << 16) |
                     ((uint32_t)hash_out[i * 4 + 2] << 8) |
                     (uint32_t)hash_out[i * 4 + 3];
    }

    cprisk_secure_zero(seed_material, sizeof(seed_material));
    cprisk_secure_zero(hash_out, sizeof(hash_out));

    ctx->state_encoded = 1;
}

uint32_t vm_cff_fusion_encode_pc(vm_cff_fusion_ctx_t *ctx, uint32_t pc) {
    if (!ctx || !ctx->state_encoded) {
        return pc;
    }

    uint32_t encoded = vm_cff_encode_state_i(pc, ctx->rk);

    ctx->trace_buffer[ctx->trace_pos % 16] = encoded;
    ctx->trace_pos++;

    return encoded;
}

uint32_t vm_cff_fusion_decode_pc(vm_cff_fusion_ctx_t *ctx, uint32_t encoded_pc) {
    if (!ctx || !ctx->state_encoded) {
        return encoded_pc;
    }

    return vm_cff_decode_state_i(encoded_pc, ctx->rk);
}

void vm_cff_fusion_transition(vm_cff_fusion_ctx_t *ctx,
                               uint32_t current_encoded,
                               uint32_t *next_encoded,
                               uint32_t branch_hint) {
    if (!ctx || !next_encoded) {
        return;
    }

    uint32_t current_plain = vm_cff_decode_state_i(current_encoded, ctx->rk);
    uint32_t next_plain;

    if (branch_hint == 0) {
        next_plain = current_plain + 1;
    } else {
        next_plain = branch_hint;
    }

    *next_encoded = vm_cff_encode_state_i(next_plain, ctx->rk);

    ctx->encoded_state = *next_encoded;

    uint8_t mix_input[8];
    memcpy(mix_input, &current_encoded, 4);
    memcpy(mix_input + 4, next_encoded, 4);

    uint8_t mix_hash[32];
    cprisk_sha256(mix_input, 8, mix_hash);

    ctx->opaque_chain ^= ((uint32_t)mix_hash[0] << 24) |
                         ((uint32_t)mix_hash[1] << 16) |
                         ((uint32_t)mix_hash[2] << 8) |
                         (uint32_t)mix_hash[3];

    cprisk_secure_zero(mix_hash, sizeof(mix_hash));
}

cprisk_vm_flow_t vm_op_cff_encode_execute(cprisk_vm_interp_frame_t *fr,
                                           uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    uint32_t slot = imm & 0x1F;
    uint32_t mix_with_acc = (imm >> 5) & 1;

    uint32_t value_to_encode;

    if (slot < 32) {
        value_to_encode = fr->acc[slot];
    } else {
        value_to_encode = (uint32_t)imm >> 8;
    }

    uint32_t encoded = vm_cff_encode_state_i(value_to_encode, fr->cff_rk);

    if (mix_with_acc) {
        encoded ^= ((uint32_t)fr->acc[0] << 24) |
                   ((uint32_t)fr->acc[1] << 16) |
                   ((uint32_t)fr->acc[2] << 8) |
                   (uint32_t)fr->acc[3];
    }

    if (slot < 32) {
        fr->acc[slot] = (uint8_t)(encoded & 0xFF);
        fr->acc[(slot + 1) & 31] = (uint8_t)((encoded >> 8) & 0xFF);
        fr->acc[(slot + 2) & 31] = (uint8_t)((encoded >> 16) & 0xFF);
        fr->acc[(slot + 3) & 31] = (uint8_t)((encoded >> 24) & 0xFF);
    }

    fr->opaque_chain ^= encoded;

    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t vm_op_cff_decode_execute(cprisk_vm_interp_frame_t *fr,
                                           uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    uint32_t slot = imm & 0x1F;

    uint32_t encoded_value = 0;
    if (slot < 32) {
        encoded_value = ((uint32_t)fr->acc[slot]) |
                        (((uint32_t)fr->acc[(slot + 1) & 31]) << 8) |
                        (((uint32_t)fr->acc[(slot + 2) & 31]) << 16) |
                        (((uint32_t)fr->acc[(slot + 3) & 31]) << 24);
    }

    uint32_t decoded = vm_cff_decode_state_i(encoded_value, fr->cff_rk);

    if (slot < 32) {
        fr->acc[slot] = (uint8_t)(decoded & 0xFF);
        fr->acc[(slot + 1) & 31] = (uint8_t)((decoded >> 8) & 0xFF);
        fr->acc[(slot + 2) & 31] = (uint8_t)((decoded >> 16) & 0xFF);
        fr->acc[(slot + 3) & 31] = (uint8_t)((decoded >> 24) & 0xFF);
    }

    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t vm_op_cff_transition_execute(cprisk_vm_interp_frame_t *fr,
                                               uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    uint32_t target_pc_hint = (uint32_t)(imm & 0xFFFFFF);
    uint32_t use_acc_as_hint = (imm >> 24) & 1;

    if (use_acc_as_hint) {
        target_pc_hint = ((uint32_t)fr->acc[0]) |
                         (((uint32_t)fr->acc[1]) << 8) |
                         (((uint32_t)fr->acc[2]) << 16);
    }

    /* Build temporary ctx from flat frame fields */
    vm_cff_fusion_ctx_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.func_id = fr->func_id;
    memcpy(tmp.rk, fr->cff_rk, sizeof(tmp.rk));
    tmp.encoded_state = fr->cff_encoded_state;
    tmp.cff_magic = fr->cff_magic;
    memcpy(tmp.trace_buffer, fr->cff_trace_buffer, sizeof(tmp.trace_buffer));
    tmp.trace_pos = fr->cff_trace_pos;
    tmp.state_encoded = fr->cff_state_encoded;
    tmp.corruption_detected = fr->cff_corruption_detected;
    tmp.opaque_chain = fr->opaque_chain;
    memcpy(tmp.bytecode_hash, fr->cff_bytecode_hash, sizeof(tmp.bytecode_hash));

    uint32_t current_encoded = (uint32_t)fr->cff_vpc;
    uint32_t next_encoded;

    vm_cff_fusion_transition(&tmp, current_encoded, &next_encoded, target_pc_hint);

    /* Write back modified fields to frame */
    memcpy(fr->cff_rk, tmp.rk, sizeof(fr->cff_rk));
    fr->cff_encoded_state = tmp.encoded_state;
    fr->cff_magic = tmp.cff_magic;
    memcpy(fr->cff_trace_buffer, tmp.trace_buffer, sizeof(fr->cff_trace_buffer));
    fr->cff_trace_pos = tmp.trace_pos;
    fr->cff_state_encoded = tmp.state_encoded;
    fr->cff_corruption_detected = tmp.corruption_detected;
    fr->opaque_chain = tmp.opaque_chain;

    fr->cff_vpc = next_encoded;

    cprisk_secure_zero(&tmp, sizeof(tmp));

    return CPRISK_VM_FLOW_CONTINUE;
}

void vm_cff_fusion_apply_to_interp(cprisk_vm_interp_frame_t *fr) {
    if (!fr) {
        return;
    }

    vm_cff_fusion_ctx_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    vm_cff_fusion_init(&tmp, fr->func_id, fr->cff_bytecode_hash);

    /* Copy round keys to frame */
    for (int i = 0; i < 8; i++) {
        fr->cff_rk[i] = tmp.rk[i];
    }

    /* Encode initial VPC */
    uint32_t encoded_vpc = vm_cff_fusion_encode_pc(&tmp, (uint32_t)fr->cff_vpc);
    fr->cff_vpc = encoded_vpc;

    /* Copy other state to frame */
    fr->cff_encoded_state = tmp.encoded_state;
    fr->cff_magic = tmp.cff_magic;
    fr->cff_state_encoded = tmp.state_encoded;
    memcpy(fr->cff_trace_buffer, tmp.trace_buffer, sizeof(fr->cff_trace_buffer));
    fr->cff_trace_pos = tmp.trace_pos;

    cprisk_secure_zero(&tmp, sizeof(tmp));
}

void vm_cff_fusion_verify_integrity(vm_cff_fusion_ctx_t *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->cff_magic != VM_CFF_MAGIC_INIT) {
        ctx->corruption_detected = 1;
        return;
    }

    if (ctx->trace_pos > 0) {
        uint32_t last_encoded = ctx->trace_buffer[(ctx->trace_pos - 1) % 16];
        uint32_t decoded = vm_cff_decode_state_i(last_encoded, ctx->rk);
        uint32_t re_encoded = vm_cff_encode_state_i(decoded, ctx->rk);

        if (re_encoded != last_encoded) {
            ctx->corruption_detected = 1;
        }
    }
}

uint32_t vm_cff_fusion_get_opacity(vm_cff_fusion_ctx_t *ctx) {
    if (!ctx) {
        return 0;
    }

    uint32_t opacity = 0;

    for (int i = 0; i < 8; i++) {
        opacity ^= ctx->rk[i];
        opacity = ((opacity << 3) | (opacity >> 29)) ^ 0x9E3779B9u;
    }

    opacity ^= ctx->opaque_chain;
    opacity ^= ctx->trace_pos * 0xC2B2AE35u;

    return opacity;
}
