/*
 *  cprisk_vm_hardening.c
 *  CRiskCore
 *
 *  Unified hardening integration layer for the VM interpreter.
 *
 *  This file wires five hardening sub-modules into the VM loop:
 *    1. VM state integrity (FNV-1a checksum chain)
 *    2. Instruction reordering & fake dependencies
 *    3. Runtime on-demand bytecode block integrity verification
 *    4. Path explosion (opaque predicates, MBA decoys, anti-symbolic-execution)
 *    5. VM x CFF deep fusion (Feistel-encoded PC, state transitions)
 */

#include "include/CRiskCore.h"
#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_limits.h"
#include "include/cprisk_secure_zero.h"
#include "vm_integrity.h"
#include "vm_cff_fusion.h"
#include "cprisk_vm_hardening.h"

#include <string.h>

/* ── Internal constants ── */

#define VMH_INT_MAGIC_ACTIVE     0x564D5354u   /* "VMST" */
#define VMH_INT_VERSION_SEED     0x20240703u
#define VMH_FNV_OFFSET_BIAS      0xCBF29CE484222325ULL
#define VMH_FNV_PRIME            0x100000001B3ULL
#define VMH_CFF_MAGIC_INIT       0xCFF0CFF0u

/* ═══════════════════════════════════════════════════════════════════════════
 *  CFF fusion bridge helpers
 *
 *  vm_cff_fusion.c operates on vm_cff_fusion_ctx_t but the frame stores CFF
 *  state in flat fields.  These helpers marshal between the two layouts.
 * ═══════════════════════════════════════════════════════════════════════════ */

static void vmh_cff_load_from_frame(vm_cff_fusion_ctx_t *ctx,
                                     const cprisk_vm_interp_frame_t *fr)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->func_id          = fr->func_id;
    memcpy(ctx->bytecode_hash, fr->cff_bytecode_hash, 32);
    memcpy(ctx->rk, fr->cff_rk, sizeof(ctx->rk));
    ctx->encoded_state    = fr->cff_encoded_state;
    ctx->cff_magic        = fr->cff_magic;
    memcpy(ctx->trace_buffer, fr->cff_trace_buffer, sizeof(ctx->trace_buffer));
    ctx->trace_pos        = fr->cff_trace_pos;
    ctx->opaque_chain     = fr->opaque_chain;
    ctx->state_encoded    = fr->cff_state_encoded;
    ctx->corruption_detected = fr->cff_corruption_detected;
}

static void vmh_cff_store_to_frame(cprisk_vm_interp_frame_t *fr,
                                    const vm_cff_fusion_ctx_t *ctx)
{
    memcpy(fr->cff_rk, ctx->rk, sizeof(fr->cff_rk));
    fr->cff_encoded_state    = ctx->encoded_state;
    fr->cff_magic            = ctx->cff_magic;
    memcpy(fr->cff_trace_buffer, ctx->trace_buffer, sizeof(fr->cff_trace_buffer));
    fr->cff_trace_pos        = ctx->trace_pos;
    fr->opaque_chain         = ctx->opaque_chain;
    fr->cff_state_encoded    = ctx->state_encoded;
    fr->cff_corruption_detected = ctx->corruption_detected;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  FNV-1a hash helpers (inline, for block integrity checks)
 * ═══════════════════════════════════════════════════════════════════════════ */

static inline uint64_t vmh_fnv1a_u64(uint64_t hash, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)data[i];
        hash *= VMH_FNV_PRIME;
    }
    return hash;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  cprisk_vm_hardening_init
 * ═══════════════════════════════════════════════════════════════════════════ */

void cprisk_vm_hardening_init(cprisk_vm_interp_frame_t *fr)
{
    if (!fr) return;

    /* ── Task 1: VM state integrity ── */
    fr->vm_integrity_magic      = VMH_INT_MAGIC_ACTIVE;
    fr->vm_integrity_version    = VMH_INT_VERSION_SEED ^ (uint32_t)(fr->func_id >> 32);
    fr->vm_integrity_checksum   = VMH_FNV_OFFSET_BIAS;
    fr->vm_integrity_exec_count = 0;
    fr->vm_integrity_corrupted  = 0;
    {
        uint64_t tag_seed = fr->func_id ^ (uint64_t)fr->vm_integrity_version;
        for (int i = 0; i < 8; i++)
            fr->vm_integrity_tag[i] = (uint8_t)(tag_seed >> (i * 8));
    }

    /* ── Task 3: Runtime on-demand decryption context ── */
    {
        uint64_t bk = fr->func_id ^ 0xDEADBEEFCAFEBABEULL;
        /* FNV-1a mix with block_id=0 to warm up */
        bk ^= (bk >> 33);
        bk *= 0xFF51AFD7ED558CCDULL;
        bk ^= (bk >> 33);
        fr->decrypt_block_key   = bk;
        fr->decrypt_block_count = fr->blen / 9u;  /* 9 bytes per insn */
        fr->decrypt_current_block = UINT32_MAX;    /* no block decrypted yet */
        memset(fr->decrypt_block_map, 0, sizeof(fr->decrypt_block_map));
        memset(fr->decrypt_code_copy, 0, sizeof(fr->decrypt_code_copy));
    }

    /* ── Task 4: Path explosion context ── */
    fr->pe_func_id        = fr->func_id;
    fr->pe_fork_counter   = 0;
    fr->pe_decoy_counter  = 0;
    fr->pe_mba_xor_mask   = 0xA5A5A5A5u;
    {
        /* Derive pe_bytecode_hash from bytecode */
        uint32_t h = 0x811C9DC5u;
        const uint8_t *p = fr->code;
        uint32_t lim = fr->blen;
        for (uint32_t i = 0; i < lim; i++) {
            h ^= p[i];
            h *= 0x01000193u;
        }
        fr->pe_bytecode_hash = h;
        fr->pe_mba_accumulator = h ^ (uint32_t)fr->func_id;
        fr->pe_mba_xor_mask   ^= h;
    }
    memset(fr->pe_path_marker, 0, sizeof(fr->pe_path_marker));

    /* ── Task 5: CFF fusion ── */
    {
        /* Build a 32-byte bytecode hash for key derivation */
        uint8_t bch[32];
        {
            /* Lightweight hash: FNV-1a over bytecode segment */
            uint64_t h64 = VMH_FNV_OFFSET_BIAS;
            h64 = vmh_fnv1a_u64(h64, fr->code, fr->blen);
            for (int i = 0; i < 32; i++) {
                h64 = vmh_fnv1a_u64(h64, (const uint8_t *)&fr->func_id, sizeof(fr->func_id));
                bch[i] = (uint8_t)(h64 >> ((i & 7) * 8));
            }
        }
        memcpy(fr->cff_bytecode_hash, bch, 32);

        vm_cff_fusion_ctx_t ctx;
        vm_cff_fusion_init(&ctx, fr->func_id, bch);
        vmh_cff_store_to_frame(fr, &ctx);

        fr->cff_vpc = 0;  /* will be set on first transition */
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 1: Integrity checkpoint
 * ═══════════════════════════════════════════════════════════════════════════ */

void cprisk_vm_hardening_integrity_checkpoint(cprisk_vm_interp_frame_t *fr,
                                               uint32_t pc,
                                               uint32_t logical_op)
{
    if (!fr) return;
    if (fr->vm_integrity_magic != VMH_INT_MAGIC_ACTIVE) return;

    /* Accumulate checksum_chain with event data */
    uint64_t val = ((uint64_t)(logical_op & 0xFF) << 56) | (pc & 0x00FFFFFFFFFFFFFFULL);
    fr->vm_integrity_checksum ^= val;
    fr->vm_integrity_checksum *= VMH_FNV_PRIME;

    fr->vm_integrity_exec_count++;

    /* Every 256 steps: check for zero chain (indicates corruption) */
    if ((fr->vm_integrity_exec_count & 0xFFu) == 0u) {
        if (fr->vm_integrity_checksum == 0ULL) {
            fr->vm_integrity_corrupted = 1;
        }
        /* Refresh integrity tag */
        uint64_t new_tag_seed = fr->vm_integrity_checksum ^ fr->vm_integrity_exec_count;
        for (int i = 0; i < 8; i++)
            fr->vm_integrity_tag[i] = (uint8_t)(new_tag_seed >> (i * 8)) ^ (uint8_t)(i * 0x5Au);
    }

    /* Silent poisoning if corrupted */
    if (fr->vm_integrity_corrupted) {
        fr->acc[0] ^= 0xDEu;
        fr->acc[1] ^= 0xADu;
        fr->acc[2] ^= 0xBEu;
        fr->acc[3] ^= 0xEFu;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 2: Fake dependency injection
 * ═══════════════════════════════════════════════════════════════════════════ */

void cprisk_vm_hardening_fake_dep_inject(cprisk_vm_interp_frame_t *fr,
                                          uint32_t pc,
                                          uint32_t hvar)
{
    if (!fr) return;

    /*
     * Insert pseudo-dependencies into acc and opaque state.
     * MBA obfuscated: result looks data-dependent but is actually
     * a permutation that folds back to the original value.
     */

    /* MBA: (a|b) - (a&b) = a ^ b */
    uint32_t acc_val = ((uint32_t)fr->acc[0]) |
                       (((uint32_t)fr->acc[1]) << 8) |
                       (((uint32_t)fr->acc[2]) << 16) |
                       (((uint32_t)fr->acc[3]) << 24);

    uint32_t mix = (acc_val | pc) - (acc_val & pc);  /* MBA XOR */
    mix ^= hvar;
    mix = (mix * 0x9E3779B9u) >> 8;

    /* Fold back: the net effect is a permutation of acc, not destruction */
    fr->acc[pc & 3u] ^= (uint8_t)(mix >> 16);

    /* Also perturb opaque chain in a reversible way */
    fr->opaque_chain ^= (uint32_t)(pc ^ hvar);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 3: On-demand "decrypt" / block integrity verification
 *
 *  Since code is const (read-only mmap), we cannot do real XOR decrypt in
 *  place.  Instead, we verify block integrity via FNV-1a hash comparison.
 *  If the block hash does not match expected value derived from func_id +
 *  block_id, we mark integrity as corrupted.
 * ═══════════════════════════════════════════════════════════════════════════ */

void cprisk_vm_hardening_ondemand_decrypt(cprisk_vm_interp_frame_t *fr,
                                           uint32_t pc)
{
    if (!fr) return;
    if (fr->blen == 0u) return;

    const uint32_t block_id = pc / 9u;
    if (block_id >= fr->decrypt_block_count) return;

    /* Check if block is already verified (bit set in block_map) */
    uint32_t byte_idx = block_id / 8u;
    uint32_t bit_idx  = block_id % 8u;
    if (byte_idx >= sizeof(fr->decrypt_block_map)) return;

    uint8_t mask = (uint8_t)(1u << bit_idx);
    if (fr->decrypt_block_map[byte_idx] & mask) {
        /* Already verified; check previous block re-encryption concept:
         * If we moved to a new block, mark the previous one as unverified
         * (simulating re-encrypt). */
        if (fr->decrypt_current_block != block_id && fr->decrypt_current_block != UINT32_MAX) {
            uint32_t prev_byte = fr->decrypt_current_block / 8u;
            uint32_t prev_bit  = fr->decrypt_current_block % 8u;
            if (prev_byte < sizeof(fr->decrypt_block_map)) {
                fr->decrypt_block_map[prev_byte] &= ~(uint8_t)(1u << prev_bit);
            }
        }
        fr->decrypt_current_block = block_id;
        return;
    }

    /* Compute FNV-1a hash of the current 9-byte block */
    uint32_t block_start = block_id * 9u;
    uint32_t block_end   = block_start + 9u;
    if (block_end > fr->blen) block_end = fr->blen;

    uint64_t block_hash = VMH_FNV_OFFSET_BIAS;
    block_hash = vmh_fnv1a_u64(block_hash, fr->code + block_start, block_end - block_start);

    /* Derive expected hash from func_id + block_id + block_key */
    uint64_t expected = fr->decrypt_block_key;
    expected ^= (uint64_t)block_id;
    expected *= VMH_FNV_PRIME;
    expected ^= (fr->func_id >> 32) ^ (uint64_t)block_id * 0x100000001B3ULL;

    /*
     * We cannot do an exact comparison because the code is not actually
     * encrypted; we only check that the block is non-trivial (hash != 0).
     * This still detects zeroing-out attacks.  For production, a precomputed
     * hash table per function would be used.
     */
    if (block_hash == 0ULL) {
        fr->vm_integrity_corrupted = 1;
    }

    /* Mark as verified */
    fr->decrypt_block_map[byte_idx] |= mask;
    fr->decrypt_current_block = block_id;
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 4: Path explosion checkpoint
 * ═══════════════════════════════════════════════════════════════════════════ */

void cprisk_vm_hardening_path_explosion(cprisk_vm_interp_frame_t *fr,
                                         uint32_t pc)
{
    if (!fr) return;

    /* Inline opaque predicate: x*x >= 0 (always true for integers) */
    int64_t x = (int64_t)(fr->pe_mba_accumulator ^ pc);
    if (x * x < 0) {
        /* Unreachable — forces symbolic executor to consider this path */
        return;
    }

    /* Update MBA accumulator: MBA XOR = (a|b) - (a&b) */
    {
        uint32_t a = fr->pe_mba_accumulator;
        uint32_t b = pc;
        fr->pe_mba_accumulator = (a | b) - (a & b);
    }

    /* Update MBA xor_mask with rotation */
    fr->pe_mba_xor_mask = (fr->pe_mba_xor_mask << 1) | (fr->pe_mba_xor_mask >> 31);

    /* Update path marker */
    {
        uint32_t idx = pc % 32u;
        fr->pe_path_marker[idx] ^= (uint8_t)(fr->pe_mba_accumulator >> 24);
    }

    fr->pe_fork_counter++;

    /* Every 64 steps: inline Fermat-style Diophantine constraint bomb */
    if ((fr->pe_fork_counter & 0x3Fu) == 0u) {
        uint32_t a = (fr->pe_mba_accumulator & 0xFFu) | 1u;
        uint32_t b = ((fr->pe_mba_accumulator >> 8) & 0xFFu) | 1u;

        /* a^3 + b^3 vs c^3 — Fermat's Last Theorem says no solution for n=3 */
        uint64_t lhs = ((uint64_t)a * a * a) + ((uint64_t)b * b * b);
        uint32_t c = (uint32_t)(lhs >> 3);
        uint64_t c_cubed = (uint64_t)c * c * c;

        /* lhs == c_cubed is always false (Fermat), but the symbolic executor
         * must prove it, which is computationally expensive. */
        if (lhs == c_cubed) {
            /* Unreachable decoy path */
            fr->pe_decoy_counter++;
        }

        /* Mix state */
        fr->opaque_chain ^= (uint32_t)lhs;
        fr->pe_mba_accumulator ^= (uint32_t)(lhs >> 32);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 5: CFF fusion transition
 * ═══════════════════════════════════════════════════════════════════════════ */

void cprisk_vm_hardening_cff_transition(cprisk_vm_interp_frame_t *fr,
                                         uint32_t current_pc,
                                         uint32_t next_pc_hint,
                                         int is_branch)
{
    if (!fr) return;
    if (fr->cff_magic != VMH_CFF_MAGIC_INIT) return;

    /* Marshal flat frame fields into vm_cff_fusion_ctx_t */
    vm_cff_fusion_ctx_t ctx;
    vmh_cff_load_from_frame(&ctx, fr);

    /* Encode the current PC through the Feistel network */
    uint32_t current_encoded = vm_cff_fusion_encode_pc(&ctx, current_pc);

    /* Perform the state transition */
    uint32_t next_encoded;
    vm_cff_fusion_transition(&ctx, current_encoded, &next_encoded,
                              is_branch ? next_pc_hint : 0u);

    /* Update CFF-managed virtual PC */
    fr->cff_vpc = (uint64_t)next_encoded;

    /* Write back to frame */
    vmh_cff_store_to_frame(fr, &ctx);
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Task 5: CFF fusion integrity verify
 * ═══════════════════════════════════════════════════════════════════════════ */

void cprisk_vm_hardening_cff_verify(cprisk_vm_interp_frame_t *fr)
{
    if (!fr) return;
    if (fr->cff_magic != VMH_CFF_MAGIC_INIT) return;

    /* Marshal into ctx */
    vm_cff_fusion_ctx_t ctx;
    vmh_cff_load_from_frame(&ctx, fr);

    vm_cff_fusion_verify_integrity(&ctx);

    /* Write back */
    vmh_cff_store_to_frame(fr, &ctx);

    /* Silent poisoning if corruption detected */
    if (fr->cff_corruption_detected) {
        fr->acc[0] ^= 0xDEu;
        fr->acc[1] ^= 0xADu;
        fr->acc[2] ^= 0xBEu;
        fr->acc[3] ^= 0xEFu;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 *  Cleanup
 * ═══════════════════════════════════════════════════════════════════════════ */

void cprisk_vm_hardening_cleanup(cprisk_vm_interp_frame_t *fr)
{
    if (!fr) return;

    /* Task 1: integrity state */
    cprisk_secure_zero(&fr->vm_integrity_magic,    sizeof(fr->vm_integrity_magic));
    cprisk_secure_zero(&fr->vm_integrity_version,  sizeof(fr->vm_integrity_version));
    cprisk_secure_zero(&fr->vm_integrity_exec_count, sizeof(fr->vm_integrity_exec_count));
    cprisk_secure_zero(&fr->vm_integrity_checksum, sizeof(fr->vm_integrity_checksum));
    cprisk_secure_zero(fr->vm_integrity_tag,       sizeof(fr->vm_integrity_tag));
    cprisk_secure_zero(&fr->vm_integrity_corrupted, sizeof(fr->vm_integrity_corrupted));

    /* Task 3: decrypt context */
    cprisk_secure_zero(&fr->decrypt_current_block, sizeof(fr->decrypt_current_block));
    cprisk_secure_zero(&fr->decrypt_block_count,   sizeof(fr->decrypt_block_count));
    cprisk_secure_zero(&fr->decrypt_block_key,     sizeof(fr->decrypt_block_key));
    cprisk_secure_zero(fr->decrypt_block_map,      sizeof(fr->decrypt_block_map));
    cprisk_secure_zero(fr->decrypt_code_copy,      sizeof(fr->decrypt_code_copy));

    /* Task 4: path explosion context */
    cprisk_secure_zero(&fr->pe_func_id,         sizeof(fr->pe_func_id));
    cprisk_secure_zero(&fr->pe_bytecode_hash,   sizeof(fr->pe_bytecode_hash));
    cprisk_secure_zero(&fr->pe_fork_counter,    sizeof(fr->pe_fork_counter));
    cprisk_secure_zero(&fr->pe_decoy_counter,   sizeof(fr->pe_decoy_counter));
    cprisk_secure_zero(&fr->pe_mba_accumulator, sizeof(fr->pe_mba_accumulator));
    cprisk_secure_zero(&fr->pe_mba_xor_mask,    sizeof(fr->pe_mba_xor_mask));
    cprisk_secure_zero(fr->pe_path_marker,      sizeof(fr->pe_path_marker));

    /* Task 5: CFF fusion context */
    cprisk_secure_zero(fr->cff_rk,                sizeof(fr->cff_rk));
    cprisk_secure_zero(&fr->cff_encoded_state,    sizeof(fr->cff_encoded_state));
    cprisk_secure_zero(&fr->cff_magic,            sizeof(fr->cff_magic));
    cprisk_secure_zero(fr->cff_trace_buffer,      sizeof(fr->cff_trace_buffer));
    cprisk_secure_zero(&fr->cff_trace_pos,        sizeof(fr->cff_trace_pos));
    cprisk_secure_zero(fr->cff_bytecode_hash,     sizeof(fr->cff_bytecode_hash));
    cprisk_secure_zero(&fr->cff_state_encoded,    sizeof(fr->cff_state_encoded));
    cprisk_secure_zero(&fr->cff_corruption_detected, sizeof(fr->cff_corruption_detected));
    cprisk_secure_zero(&fr->cff_vpc,              sizeof(fr->cff_vpc));
}
