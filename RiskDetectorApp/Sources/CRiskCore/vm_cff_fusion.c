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
/* Full 32-bit state space (16+16 Feistel halves). The previous 28-bit mask
 * (0x0FFFFFFFu) was an artifact of the 14+14 layout used with the 4-bit
 * nibble S-box; the 8-bit S-box-based round function below uses both bytes
 * of each half, so the encoded state covers the full uint32 range. */

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

/*
 * 16-bit Feistel round function with 8-bit S-box (shared with `cprisk_cff`
 * Feistel-SPN: same per-build randomized 256-byte permutation, removing the
 * weakly diffusing 4-bit nibble S-box that previously left half of each
 * round's input bits untouched). Two SPN passes per round + key-schedule
 * folding keep diffusion per-round at full half-block.
 */
static uint16_t vm_cff_feistel_f(uint16_t right, uint32_t round_key) {
    const uint16_t kl = (uint16_t)(round_key & 0xFFFFu);
    const uint16_t kh = (uint16_t)((round_key >> 16) & 0xFFFFu);
    uint32_t x = (uint32_t)(right ^ kl);

    /* First SPN pass on both bytes of the half. */
    const uint8_t s0 = cprisk_cff_spn_sbox_lookup((uint8_t)(x & 0xFFu));
    const uint8_t s1 = cprisk_cff_spn_sbox_lookup((uint8_t)((x >> 8) & 0xFFu));
    uint32_t y = (uint32_t)s0 | ((uint32_t)s1 << 8);

    /* Avalanche with key-schedule fold (uses high half of round_key). */
    y ^= (uint32_t)kh;
    y = ((y << 7) | (y >> 25)) ^ 0x9E3779B9u;
    y = ((y * 0x85EBCA6Bu) >> 16) ^ y;
    y = ((y << 13) | (y >> 19)) ^ 0xC2B2AE35u;

    /* Second SPN pass after avalanche — full per-byte substitution. */
    const uint8_t t0 = cprisk_cff_spn_sbox_lookup((uint8_t)(y & 0xFFu));
    const uint8_t t1 = cprisk_cff_spn_sbox_lookup((uint8_t)((y >> 8) & 0xFFu));

    return (uint16_t)((uint32_t)t0 | ((uint32_t)t1 << 8));
}

static uint32_t vm_cff_encode_state_i(uint32_t state, const uint32_t *rk) {
    /* 16+16 split — full state space, no truncation. */
    uint16_t left = (uint16_t)((state >> 16) & 0xFFFFu);
    uint16_t right = (uint16_t)(state & 0xFFFFu);

    /* Pre-whitening with structurally distinct derivation. */
    const uint32_t pre_whiten = vm_cff_whiten_pre_i(rk);
    left ^= (uint16_t)((pre_whiten >> 16) & 0xFFFFu);
    right ^= (uint16_t)(pre_whiten & 0xFFFFu);

    for (int r = 0; r < VM_CFF_FEISTEL_ROUNDS; r++) {
        const uint16_t f_out = vm_cff_feistel_f(right, rk[r]);
        const uint16_t new_left = right;
        const uint16_t new_right = (uint16_t)(left ^ f_out);
        left = new_left;
        right = new_right;
    }

    const uint32_t post_whiten = vm_cff_whiten_post_i(rk);
    left ^= (uint16_t)((post_whiten >> 16) & 0xFFFFu);
    right ^= (uint16_t)(post_whiten & 0xFFFFu);

    return ((uint32_t)left << 16) | (uint32_t)right;
}

static uint32_t vm_cff_decode_state_i(uint32_t encoded, const uint32_t *rk) {
    uint16_t left = (uint16_t)((encoded >> 16) & 0xFFFFu);
    uint16_t right = (uint16_t)(encoded & 0xFFFFu);

    /* Decode: undo post-whitening first, then pre-whitening last. */
    const uint32_t post_whiten = vm_cff_whiten_post_i(rk);
    left ^= (uint16_t)((post_whiten >> 16) & 0xFFFFu);
    right ^= (uint16_t)(post_whiten & 0xFFFFu);

    for (int r = VM_CFF_FEISTEL_ROUNDS - 1; r >= 0; r--) {
        const uint16_t f_out = vm_cff_feistel_f(left, rk[r]);
        const uint16_t new_right = left;
        const uint16_t new_left = (uint16_t)(right ^ f_out);
        right = new_right;
        left = new_left;
    }

    const uint32_t pre_whiten = vm_cff_whiten_pre_i(rk);
    left ^= (uint16_t)((pre_whiten >> 16) & 0xFFFFu);
    right ^= (uint16_t)(pre_whiten & 0xFFFFu);

    return ((uint32_t)left << 16) | (uint32_t)right;
}

/*
 * Per-position keystream for the trace ring buffer. The trace previously held
 * encoded PCs in plaintext, so a memory dump trivially reconstructed the
 * function's recent control flow. XOR-mask each entry with a deterministic
 * per-position byte stream derived from the round keys; verify_integrity
 * peels the mask before re-encoding for the round-trip check.
 *
 * Keystream is reproducible (no per-write nonce) so the in-context format
 * stays read/write symmetric without storing extra state.
 */
static uint32_t vm_cff_trace_keystream_i(const uint32_t *rk, uint32_t pos) {
    const uint32_t base = rk[pos & 7u] ^ (pos * 0x9E3779B9u);
    const uint32_t mix = cprisk_vmp_avalanche32_i(base ^ rk[(pos + 3u) & 7u]);
    return cprisk_vmp_avalanche32_i(mix ^ 0xA24BAED5u ^ ((pos << 11) | (pos >> 21)));
}

/*
 * Domain-separated SHA256 chain. Two SHA256 calls with distinct domain tags
 * derive 64 bytes of pseudo-random output from the IKM (function id +
 * bytecode hash). This is HKDF-Expand-style without the HMAC overhead —
 * appropriate because the IKM is already a hash output (high entropy) and
 * we use it for symmetric-key derivation, not authentication.
 *
 * Output layout:
 *   bytes  [0..31] — 8 round keys (rk[0..7]), big-endian per 4-byte stride
 *   bytes [32..63] — reserved for future expansion (zeroed after use); the
 *                    second-block material is currently consumed only to
 *                    guarantee full SHA256 mixing of the IKM under both
 *                    domain tags, hardening against truncation attacks
 *                    against any single block.
 */
static void vm_cff_kdf_expand(const uint8_t *ikm, size_t ikm_len, uint8_t out[64]) {
    /* Worst-case input size: 8 (func_id) + 32 (bytecode_hash) + 4 (tag) = 44. */
    uint8_t buf[64];
    if (ikm_len > sizeof(buf) - 4u) {
        ikm_len = sizeof(buf) - 4u;
    }
    memcpy(buf, ikm, ikm_len);

    /* Block 1 — domain "rk\1\0" */
    buf[ikm_len + 0] = 'r';
    buf[ikm_len + 1] = 'k';
    buf[ikm_len + 2] = 0x01;
    buf[ikm_len + 3] = 0x00;
    cprisk_sha256(buf, ikm_len + 4u, &out[0]);

    /* Block 2 — domain "wh\2\0", chained with block 1 to extend entropy. */
    buf[ikm_len + 0] = 'w';
    buf[ikm_len + 1] = 'h';
    buf[ikm_len + 2] = 0x02;
    buf[ikm_len + 3] = 0x00;
    cprisk_sha256(buf, ikm_len + 4u, &out[32]);

    cprisk_secure_zero(buf, sizeof(buf));
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

    /*
     * IKM = func_id (8 bytes) || bytecode_hash (32 bytes if provided, else
     * func_id-derived padding to keep the length stable). Previously this
     * was packed into a 64-byte buffer with 24 trailing bytes left
     * uninitialized — `cprisk_secure_zero` cleaned them up but those bytes
     * were never hashed anyway. Use a precisely-sized buffer.
     */
    uint8_t ikm[40];
    memcpy(ikm, &func_id, sizeof(func_id));
    if (bytecode_hash) {
        memcpy(ikm + 8, bytecode_hash, 32);
    } else {
        /* Stable fallback: hash func_id under a fixed pad rather than
         * leaving zero bytes that would cause two distinct functions with
         * empty bytecode_hash to share a key derivation prefix. */
        for (size_t i = 0; i < 32u; i += 8u) {
            const uint64_t pad = func_id ^ (0xA24BAED5C2B2AE35ULL + (uint64_t)i);
            memcpy(ikm + 8u + i, &pad, sizeof(pad));
        }
    }

    uint8_t prk[64];
    vm_cff_kdf_expand(ikm, sizeof(ikm), prk);

    for (int i = 0; i < 8; i++) {
        ctx->rk[i] = ((uint32_t)prk[i * 4] << 24) |
                     ((uint32_t)prk[i * 4 + 1] << 16) |
                     ((uint32_t)prk[i * 4 + 2] << 8) |
                     (uint32_t)prk[i * 4 + 3];
    }

    cprisk_secure_zero(ikm, sizeof(ikm));
    cprisk_secure_zero(prk, sizeof(prk));

    ctx->state_encoded = 1;
}

uint32_t vm_cff_fusion_encode_pc(vm_cff_fusion_ctx_t *ctx, uint32_t pc) {
    if (!ctx || !ctx->state_encoded) {
        return pc;
    }

    const uint32_t encoded = vm_cff_encode_state_i(pc, ctx->rk);

    /* Store the trace under a per-position keystream so a memory dump cannot
     * recover the encoded PC sequence directly. The function returns the
     * raw encoded value (callers need it as the next vpc); only the in-ctx
     * trace history is masked. */
    const uint32_t pos = ctx->trace_pos;
    ctx->trace_buffer[pos % 16u] = encoded ^ vm_cff_trace_keystream_i(ctx->rk, pos);
    ctx->trace_pos = pos + 1u;

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
        const uint32_t last_pos = ctx->trace_pos - 1u;
        /* Trace is keystream-masked on write; peel before round-tripping. */
        const uint32_t last_encoded =
            ctx->trace_buffer[last_pos % 16u] ^ vm_cff_trace_keystream_i(ctx->rk, last_pos);
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
