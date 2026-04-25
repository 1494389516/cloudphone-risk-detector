/*
 *  vm_cff_fusion.c
 *  CRiskCore
 */

#include "include/CRiskCore.h"
#include "include/cprisk_cff.h"
#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_ops.h"
#include "vm_cff_fusion.h"

#include <string.h>

#define VM_CFF_FEISTEL_ROUNDS       8
#define VM_CFF_MAGIC_INIT           0xCFF0CFF0u
#define VM_CFF_STATE_MASK           0x0FFFFFFFu

/* 4-bit nibble S-box (bijective, generated from AES-like affine map).
 * Note: this is only used as a non-linear PRF inside the Feistel round
 * function; encryption strength derives from the round count and key
 * schedule, not from the S-box width. */
static const uint8_t vm_cff_sbox4[16] = {
    0x6, 0xB, 0x3, 0x8, 0xD, 0x0, 0xA, 0xF,
    0x2, 0xC, 0x5, 0x1, 0xE, 0x9, 0x7, 0x4
};

/*
 * Distinct pre/post whitening derivation. Previous code XORed two round-key
 * pairs (`rk[0] ^ rk[7]` for pre, `rk[3] ^ rk[5]` for post): when the four
 * keys happened to satisfy `rk[0] ^ rk[7] == rk[3] ^ rk[5]` (probability
 * ~ 2^-32) the pre and post masks would cancel, weakening the cipher.
 *
 * The two helpers below mix the round keys through `avalanche32` and use
 * structurally different combiners (XOR + rotate vs. modular add + rotate)
 * so the outputs are distinct functions of the key schedule even on
 * adversarially chosen keys.
 */
static uint32_t vm_cff_whiten_pre_i(const uint32_t *rk) {
    const uint32_t a = cprisk_vmp_avalanche32_i(rk[0]);
    const uint32_t b = cprisk_vmp_avalanche32_i(rk[7]);
    const uint32_t mix = a ^ ((b << 13) | (b >> 19));
    return cprisk_vmp_avalanche32_i(mix ^ 0x9E3779B9u);
}

static uint32_t vm_cff_whiten_post_i(const uint32_t *rk) {
    const uint32_t a = cprisk_vmp_avalanche32_i(rk[3]);
    const uint32_t b = cprisk_vmp_avalanche32_i(rk[5]);
    const uint32_t mix = (a + b) ^ ((a >> 11) | (a << 21));
    return cprisk_vmp_avalanche32_i(mix ^ 0xC2B2AE35u);
}

static uint32_t vm_cff_feistel_f(uint32_t right, uint32_t round_key) {
    uint32_t x = right ^ round_key;

    /* 4-bit nibble S-box substitution (low 2 nibbles) */
    uint8_t lo = vm_cff_sbox4[x & 0xF];
    uint8_t hi = vm_cff_sbox4[(x >> 4) & 0xF];
    x = (x & ~0xFFu) | ((uint32_t)hi << 4) | (uint32_t)lo;

    /* Avalanche mixing with rotations */
    x = ((x << 7) | (x >> 25)) ^ 0x9E3779B9u;
    x = ((x * 0x85EBCA6Bu) >> 16) ^ x;
    x = ((x << 13) | (x >> 19)) ^ 0xC2B2AE35u;

    /* Second S-box pass on different nibbles (bytes 1-2) */
    lo = vm_cff_sbox4[(x >> 8) & 0xF];
    hi = vm_cff_sbox4[(x >> 12) & 0xF];
    x = (x & ~(0xFFu << 8)) | ((uint32_t)hi << 12) | ((uint32_t)lo << 8);

    return x & VM_CFF_STATE_MASK;
}

static uint32_t vm_cff_encode_state_i(uint32_t state, const uint32_t *rk) {
    uint32_t left = (state >> 14) & 0x3FFF;
    uint32_t right = state & 0x3FFF;

    /* Pre-whitening with structurally distinct derivation (no cancellation
     * with post-whitening for any choice of round keys). */
    const uint32_t pre_whiten = vm_cff_whiten_pre_i(rk);
    left ^= (pre_whiten >> 14) & 0x3FFF;
    right ^= pre_whiten & 0x3FFF;

    for (int r = 0; r < VM_CFF_FEISTEL_ROUNDS; r++) {
        uint32_t f_out = vm_cff_feistel_f(right, rk[r]);
        uint32_t new_left = right;
        uint32_t new_right = (left ^ f_out) & 0x3FFF;
        left = new_left;
        right = new_right;
    }

    const uint32_t post_whiten = vm_cff_whiten_post_i(rk);
    left ^= (post_whiten >> 14) & 0x3FFF;
    right ^= post_whiten & 0x3FFF;

    return ((left & 0x3FFF) << 14) | (right & 0x3FFF);
}

static uint32_t vm_cff_decode_state_i(uint32_t encoded, const uint32_t *rk) {
    uint32_t left = (encoded >> 14) & 0x3FFF;
    uint32_t right = encoded & 0x3FFF;

    /* Decode: undo post-whitening first, then pre-whitening last (reverse order). */
    const uint32_t post_whiten = vm_cff_whiten_post_i(rk);
    left ^= (post_whiten >> 14) & 0x3FFF;
    right ^= post_whiten & 0x3FFF;

    for (int r = VM_CFF_FEISTEL_ROUNDS - 1; r >= 0; r--) {
        uint32_t f_out = vm_cff_feistel_f(left, rk[r]);
        uint32_t new_right = left;
        uint32_t new_left = (right ^ f_out) & 0x3FFF;
        right = new_right;
        left = new_left;
    }

    const uint32_t pre_whiten = vm_cff_whiten_pre_i(rk);
    left ^= (pre_whiten >> 14) & 0x3FFF;
    right ^= pre_whiten & 0x3FFF;

    return ((left & 0x3FFF) << 14) | (right & 0x3FFF);
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
    if (bytecode_hash) {
        memcpy(seed_material + 8, bytecode_hash, 32);
    } else {
        memset(seed_material + 8, 0, 24);
        memcpy(seed_material + 8 + 24, &func_id, 8);
    }

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

    cprisk_secure_zero(mix_input, sizeof(mix_input));
    cprisk_secure_zero(mix_hash, sizeof(mix_hash));
}

cprisk_vm_flow_t vm_op_cff_encode_execute(cprisk_vm_interp_frame_t *fr,
                                           uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    /* `slot` is masked to 5 bits so the `slot >= 32` branch was dead; the dead
     * else used `imm >> 8` as the value-to-encode, then discarded the result
     * because no writeback path existed. Drop the dead path entirely. */
    const uint32_t slot = (uint32_t)(imm & 0x1Fu);
    const uint32_t mix_with_acc = (uint32_t)((imm >> 5) & 1u);
    if (slot >= 32u) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    const uint32_t value_to_encode = fr->acc[slot];

    uint32_t encoded = vm_cff_encode_state_i(value_to_encode, fr->cff_rk);

    if (mix_with_acc) {
        encoded ^= ((uint32_t)fr->acc[0] << 24) |
                   ((uint32_t)fr->acc[1] << 16) |
                   ((uint32_t)fr->acc[2] << 8) |
                   (uint32_t)fr->acc[3];
    }

    fr->acc[slot] = (uint8_t)(encoded & 0xFF);
    fr->acc[(slot + 1u) & 31u] = (uint8_t)((encoded >> 8) & 0xFF);
    fr->acc[(slot + 2u) & 31u] = (uint8_t)((encoded >> 16) & 0xFF);
    fr->acc[(slot + 3u) & 31u] = (uint8_t)((encoded >> 24) & 0xFF);

    fr->opaque_chain ^= encoded;

    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t vm_op_cff_decode_execute(cprisk_vm_interp_frame_t *fr,
                                           uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    /* `slot` is `imm & 0x1F` so it is always in [0, 31]; the prior `if (slot < 32)`
     * guards were dead branches that read as if a fall-through path existed. We
     * keep the bound explicit anyway in case the mask changes. */
    const uint32_t slot = (uint32_t)(imm & 0x1Fu);
    if (slot >= 32u) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    const uint32_t encoded_value =
        ((uint32_t)fr->acc[slot]) |
        (((uint32_t)fr->acc[(slot + 1u) & 31u]) << 8) |
        (((uint32_t)fr->acc[(slot + 2u) & 31u]) << 16) |
        (((uint32_t)fr->acc[(slot + 3u) & 31u]) << 24);

    const uint32_t decoded = vm_cff_decode_state_i(encoded_value, fr->cff_rk);

    fr->acc[slot] = (uint8_t)(decoded & 0xFF);
    fr->acc[(slot + 1u) & 31u] = (uint8_t)((decoded >> 8) & 0xFF);
    fr->acc[(slot + 2u) & 31u] = (uint8_t)((decoded >> 16) & 0xFF);
    fr->acc[(slot + 3u) & 31u] = (uint8_t)((decoded >> 24) & 0xFF);

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

    /* Constant-time compare on the magic to avoid leaking via early-exit timing
     * which sub-bytes of `cff_magic` were corrupted. */
    uint32_t magic_diff = ctx->cff_magic ^ VM_CFF_MAGIC_INIT;
    magic_diff |= magic_diff >> 16;
    magic_diff |= magic_diff >> 8;
    if ((magic_diff & 1u) != 0u) {
        ctx->corruption_detected = 1;
        return;
    }

    if (ctx->trace_pos > 0) {
        const uint32_t last_encoded = ctx->trace_buffer[(ctx->trace_pos - 1u) % 16u];
        const uint32_t decoded = vm_cff_decode_state_i(last_encoded, ctx->rk);
        const uint32_t re_encoded = vm_cff_encode_state_i(decoded, ctx->rk);

        /* Fold a 32-bit not-equal into a single bit without branching on
         * intermediate bytes. */
        uint32_t diff = re_encoded ^ last_encoded;
        diff |= diff >> 16;
        diff |= diff >> 8;
        diff |= diff >> 4;
        diff |= diff >> 2;
        diff |= diff >> 1;
        ctx->corruption_detected |= (uint8_t)(diff & 1u);
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
