#include "include/CRiskCore.h"
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <string.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#define CPRISK_VM_MAX_STEPS 65536u
#define CPRISK_VM_INSN_WIDTH 9u
#define CPRISK_VM_MAX_SUBCALL_DEPTH 32u
#define CPRISK_VM_MAX_VM_NEST_DEPTH 8u
#define CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES ((size_t)sizeof(cprisk_vmp_bytecode_header_t))
#define CPRISK_VMP_BYTECODE_VPC_EXT_BYTES 16u

static uint64_t cprisk_read_le_u64_i(const uint8_t *p) {
    uint64_t value = 0;
    if (!p)
        return 0;
    memcpy(&value, p, sizeof(value));
    return value;
}

static uint32_t cprisk_read_le_u32_i(const uint8_t *p) {
    uint32_t value = 0;
    if (!p)
        return 0;
    memcpy(&value, p, sizeof(value));
    return value;
}

static uint64_t cprisk_splitmix64_next_i(uint64_t *state) {
    *state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = *state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static int cprisk_vmp_bytecode_has_m2_i(const cprisk_vmp_bytecode_header_t *bh) {
    if (!bh)
        return 0;
    return (bh->reserved & CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC) != 0u
        || (bh->reserved & CPRISK_VMP_BC_FLAG_HANDLER_VARIANT_SEED) != 0u;
}

static size_t cprisk_vmp_bytecode_header_total_bytes_i(const cprisk_vmp_bytecode_header_t *bh) {
    size_t total = CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES;
    if (cprisk_vmp_bytecode_has_m2_i(bh))
        total += CPRISK_VMP_BYTECODE_VPC_EXT_BYTES;
    if (bh && bh->version >= CPRISK_VMP_VERSION_V3
        && (bh->reserved & CPRISK_VMP_BC_FLAG_ENC_IMMEDIATE) != 0u)
        total += 8u;
    if (bh && bh->version >= CPRISK_VMP_VERSION_V3
        && (bh->reserved & CPRISK_VMP_BC_FLAG_ENC_OPCODE) != 0u)
        total += 8u;
    return total;
}

static size_t cprisk_vmp_bytecode_entry_stride_i(const cprisk_vmp_bytecode_header_t *bh) {
    size_t stride = sizeof(cprisk_vmp_bytecode_entry_t);
    if (bh && (bh->reserved & CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC) != 0u)
        stride += CPRISK_VMP_BYTECODE_VPC_EXT_BYTES;
    return stride;
}

static int cprisk_vmp_bytecode_version_ok_i(uint32_t v) {
    return v == CPRISK_VMP_VERSION || v == CPRISK_VMP_VERSION_M2 || v == CPRISK_VMP_VERSION_V3;
}

static void cprisk_vmp_read_vpc_affine_i(const uint8_t *b_sec,
                                       const cprisk_vmp_bytecode_header_t *bh,
                                       uint64_t *out_a,
                                       uint64_t *out_b) {
    *out_a = 1u;
    *out_b = 0u;
    if (!bh || !b_sec || !cprisk_vmp_bytecode_has_m2_i(bh))
        return;
    *out_a = cprisk_read_le_u64_i(b_sec + CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES);
    *out_b = cprisk_read_le_u64_i(b_sec + CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES + 8u);
}

static uint32_t cprisk_vm_handler_variant_i(uint32_t hdr_reserved,
                                          uint64_t func_id,
                                          uint64_t steps,
                                          uint32_t op,
                                          uint64_t imm) {
    uint32_t mix = (uint32_t)(steps ^ (uint32_t)func_id ^ (uint32_t)(func_id >> 32));
    mix ^= (uint32_t)(imm ^ (imm >> 32));
    mix ^= (uint32_t)op * 0x9E3779B9u;
    if ((hdr_reserved & CPRISK_VMP_BC_FLAG_HANDLER_VARIANT_SEED) != 0u)
        mix ^= (hdr_reserved >> 8) & 3u;
    return mix & 3u;
}

/** 16-way semantic lane selector (seed/pc/func/handler — all reachable switch arms). */
static uint32_t cprisk_vm_lane_poly16_i(uint32_t pc,
                                       uint64_t func_id,
                                       uint64_t steps,
                                       uint32_t hvar,
                                       uint32_t semantic_family) {
    uint32_t x = (uint32_t)pc ^ (uint32_t)func_id ^ (uint32_t)(func_id >> 32u);
    x ^= (uint32_t)steps ^ (uint32_t)(steps >> 32u);
    x ^= hvar * 0x9E37u;
    x ^= (semantic_family & 0xFu) * 0xC2B2u;
    return x % 16u;
}

static int cprisk_vm_entry_profile_decode_i(uint32_t entry_reserved,
                                            uint32_t *semantic_family,
                                            uint32_t *mixed_predicate_profile,
                                            uint32_t *max_subcall_depth) {
    if ((entry_reserved >> 24) != CPRISK_VMP_ENTRY_PROFILE_MAGIC)
        return 0;
    if (semantic_family)
        *semantic_family = ((entry_reserved >> CPRISK_VMP_ENTRY_SEMANTIC_FAMILY_SHIFT) & 0xFu);
    if (mixed_predicate_profile)
        *mixed_predicate_profile = ((entry_reserved >> CPRISK_VMP_ENTRY_MIXED_PRED_SHIFT) & 0xFu);
    if (max_subcall_depth)
        *max_subcall_depth = (((entry_reserved >> CPRISK_VMP_ENTRY_SUBCALL_DEPTH_SHIFT) & 0xFu) + 1u);
    return 1;
}

static void cprisk_vm_entry_profile_fallback_i(uint64_t func_id,
                                               uint32_t hdr_reserved,
                                               uint32_t *semantic_family,
                                               uint32_t *mixed_predicate_profile,
                                               uint32_t *max_subcall_depth) {
    uint64_t st = func_id ^ ((uint64_t)hdr_reserved << 32) ^ 0x45584350524F4631ULL; /* "EXCPROF1" */
    uint32_t sem = (uint32_t)(cprisk_splitmix64_next_i(&st) % 4u) + 1u;
    uint32_t mix = (uint32_t)(cprisk_splitmix64_next_i(&st) % 8u);
    uint32_t depth = (uint32_t)(cprisk_splitmix64_next_i(&st) % 8u) + 2u;
    if (semantic_family)
        *semantic_family = sem;
    if (mixed_predicate_profile)
        *mixed_predicate_profile = mix;
    if (max_subcall_depth)
        *max_subcall_depth = depth;
}

static uint8_t cprisk_vm_add_byte_bitwise_i(uint8_t a, uint8_t b) {
    while (b != 0u) {
        uint8_t carry = (uint8_t)(a & b);
        a = (uint8_t)(a ^ b);
        b = (uint8_t)(carry << 1u);
    }
    return a;
}

static uint8_t cprisk_vm_add_equiv_i(uint8_t lhs, uint8_t rhs, uint32_t style) {
    const uint32_t L = (uint32_t)lhs;
    const uint32_t R = (uint32_t)rhs;
    switch (style % 16u) {
    case 0u:
        return (uint8_t)(L + R);
    case 1u:
        return cprisk_vm_add_byte_bitwise_i(lhs, rhs);
    case 2u:
        return (uint8_t)(L - (uint32_t)(uint8_t)(~rhs + 1u));
    case 3u:
        return (uint8_t)((L ^ R) + ((L & R) << 1u)); /* a+b mod 256 */
    case 4u:
        return (uint8_t)(cprisk_vm_add_byte_bitwise_i((uint8_t)L, (uint8_t)(R ^ (uint8_t)(L & (uint8_t)(~R)))));
    case 5u:
        return (uint8_t)((L ^ R) + ((L & R) << 1u));
    case 6u:
        return (uint8_t)(L - (~R) - 1u);
    case 7u:
        return (uint8_t)(((L & R) << 1u) + (L ^ R));
    case 8u:
        return (uint8_t)((L ^ R) + ((L & R) << 1u)); /* carry identity */
    case 9u:
        return (uint8_t)(L + R + (L & R) - (L & R)); /* MBA noop */
    case 10u:
        return (uint8_t)(L + ((R ^ 0xFFu) ^ 0xFFu)); /* ≡ L+R */
    case 11u:
        return (uint8_t)(cprisk_vm_add_byte_bitwise_i(lhs, (uint8_t)(R ^ (uint8_t)(L & R))));
    case 12u:
        return (uint8_t)((L & ~R) + R + (L & R));
    case 13u:
        return (uint8_t)(L + (R & 0xFEu) + (R & 1u));
    case 14u:
        return (uint8_t)((L | R) + (L & R) - (L & R));
    default:
        return (uint8_t)((L + R) & 0xFFu);
    }
}

static uint8_t cprisk_vm_xor_equiv_i(uint8_t lhs, uint8_t rhs, uint32_t style) {
    const uint32_t L = (uint32_t)lhs;
    const uint32_t R = (uint32_t)rhs;
    switch (style % 16u) {
    case 0u:
        return (uint8_t)(L ^ R);
    case 1u:
        return (uint8_t)((lhs | rhs) & (uint8_t)(~(lhs & rhs)));
    case 2u:
        return (uint8_t)(L + R - ((L & R) << 1u));
    case 3u:
        return (uint8_t)((L | R) - (L & R));
    case 4u:
        return (uint8_t)(~(L & R) & (L | R));
    case 5u:
        return (uint8_t)((L & ~R) | (~L & R));
    case 6u:
        return (uint8_t)((L + R) - 2u * (L & R));
    case 7u:
        return (uint8_t)(L ^ R ^ ((L & R) << 1u));
    case 8u:
        return (uint8_t)((L | R) & (uint8_t)(~(L & R)));
    case 9u:
        return (uint8_t)(~(L & R) & (L | R));
    case 10u:
        return (uint8_t)((L & R) ^ L ^ R);
    case 11u:
        return (uint8_t)((L | R) ^ (L & R));
    case 12u:
        return (uint8_t)(L ^ R ^ ((L & R) & 0u));
    case 13u:
        return (uint8_t)((L & ~R) | (~L & R));
    case 14u:
        return (uint8_t)(L ^ R);
    default:
        return (uint8_t)(L ^ R);
    }
}

static void cprisk_vm_raw_region_apply_i(uint8_t acc[32],
                                         uint64_t imm,
                                         uint32_t steps,
                                         uint32_t variant,
                                         uint32_t semantic_family,
                                         uint64_t func_id,
                                         uint32_t pc) {
    uint8_t lanes[8];
    uint8_t idxs[8];
    uint8_t snapshot[8];
    const uint32_t base = (uint32_t)(steps & 0x0Fu);
    for (uint32_t i = 0; i < 8u; i++) {
        lanes[i] = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        idxs[i] = (uint8_t)((i + base) & 31u);
    }

    const uint32_t poly = cprisk_vm_lane_poly16_i(pc, func_id, steps, variant, semantic_family);
    switch (poly) {
    case 0u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = semantic_family + i;
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 1u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (int i = 7; i >= 0; i--) {
            uint32_t u = (uint32_t)i;
            uint32_t style = variant + semantic_family + u;
            acc[idxs[u]] = cprisk_vm_xor_equiv_i(snapshot[u], lanes[u], style);
        }
        break;
    case 2u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 3u + semantic_family) & 7u;
            uint32_t style = variant ^ semantic_family ^ i;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    case 3u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = (i * 3u) ^ variant ^ (uint32_t)(pc & 0xFu);
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 4u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = semantic_family + (i ^ 4u);
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 5u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (uint32_t u = 0; u < 8u; u++) {
            uint32_t style = (uint32_t)steps + u + variant;
            acc[idxs[u]] = cprisk_vm_xor_equiv_i(snapshot[u], lanes[u], style);
        }
        break;
    case 6u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 5u + variant) & 7u;
            uint32_t style = semantic_family + i * 7u;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    case 7u:
        for (int i = 0; i < 8; i += 2) {
            uint32_t style = (uint32_t)i + semantic_family;
            acc[idxs[(uint32_t)i]] = cprisk_vm_xor_equiv_i(acc[idxs[(uint32_t)i]], lanes[(uint32_t)i], style);
        }
        for (int i = 1; i < 8; i += 2) {
            uint32_t style = (uint32_t)i + variant;
            acc[idxs[(uint32_t)i]] = cprisk_vm_xor_equiv_i(acc[idxs[(uint32_t)i]], lanes[(uint32_t)i], style);
        }
        break;
    case 8u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t j = (7u - i);
            uint32_t style = variant + j * 11u;
            acc[idxs[j]] = cprisk_vm_xor_equiv_i(acc[idxs[j]], lanes[j], style);
        }
        break;
    case 9u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 7u + semantic_family * 3u) & 7u;
            uint32_t style = (uint32_t)func_id + t;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    case 10u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (uint32_t u = 0; u < 8u; u++) {
            uint32_t k = (u + 4u) & 7u;
            uint32_t style = semantic_family ^ u ^ k;
            acc[idxs[k]] = cprisk_vm_xor_equiv_i(snapshot[k], lanes[k], style);
        }
        break;
    case 11u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t ^ (variant & 7u)) & 7u;
            uint32_t style = (uint32_t)(func_id >> (t & 7u)) ^ semantic_family;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    case 12u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = pc + i + variant;
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 13u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 2u + 1u) & 7u;
            uint32_t style = variant + t + (uint32_t)(pc & 3u);
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    case 14u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (int i = 7; i >= 0; i--) {
            uint32_t u = (uint32_t)i;
            uint32_t style = (semantic_family << 1) + u ^ variant;
            acc[idxs[u]] = cprisk_vm_xor_equiv_i(snapshot[u], lanes[u], style);
        }
        break;
    default:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t + (uint32_t)(func_id & 7u)) & 7u;
            uint32_t style = variant + semantic_family + (pc & 7u) + t;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_xor_equiv_i(cur, lanes[i], style);
        }
        break;
    }
}

static int cprisk_vm_enc_pc_advance_i(uint64_t *enc_pc, uint64_t vpc_a, cprisk_vm_run_result_t *out) {
    uint64_t delta;
    if (__builtin_mul_overflow(CPRISK_VM_INSN_WIDTH, vpc_a, &delta) ||
        __builtin_add_overflow(*enc_pc, delta, enc_pc)) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    return 1;
}

static void cprisk_vm_add_apply_i(uint8_t acc[32],
                                  uint64_t imm,
                                  uint32_t steps,
                                  uint32_t variant,
                                  uint32_t semantic_family,
                                  uint64_t func_id,
                                  uint32_t pc) {
    uint8_t lanes[8];
    uint8_t idxs[8];
    uint8_t snapshot[8];
    const uint32_t base = (uint32_t)(steps & 0x0Fu);
    for (uint32_t i = 0; i < 8u; i++) {
        lanes[i] = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        idxs[i] = (uint8_t)((i + base) & 31u);
    }

    const uint32_t poly = cprisk_vm_lane_poly16_i(pc, func_id, steps, variant, semantic_family);
    switch (poly) {
    case 0u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = semantic_family + i;
            acc[idxs[i]] = cprisk_vm_add_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 1u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (int i = 7; i >= 0; i--) {
            uint32_t u = (uint32_t)i;
            uint32_t style = variant + semantic_family + u;
            acc[idxs[u]] = cprisk_vm_add_equiv_i(snapshot[u], lanes[u], style);
        }
        break;
    case 2u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 5u + variant + semantic_family) & 7u;
            uint32_t style = variant ^ semantic_family ^ i;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_add_equiv_i(cur, lanes[i], style);
        }
        break;
    case 3u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = (i * 5u) ^ (uint32_t)(pc & 0x1Fu);
            acc[idxs[i]] = cprisk_vm_add_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 4u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = semantic_family + (i ^ 3u);
            acc[idxs[i]] = cprisk_vm_add_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 5u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (uint32_t u = 0; u < 8u; u++) {
            uint32_t style = (uint32_t)steps + u * 3u;
            acc[idxs[u]] = cprisk_vm_add_equiv_i(snapshot[u], lanes[u], style);
        }
        break;
    case 6u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 3u + variant * 2u) & 7u;
            uint32_t style = semantic_family + i * 5u;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_add_equiv_i(cur, lanes[i], style);
        }
        break;
    case 7u:
        for (int i = 0; i < 8; i += 2) {
            uint32_t style = (uint32_t)i + variant;
            acc[idxs[(uint32_t)i]] = cprisk_vm_add_equiv_i(acc[idxs[(uint32_t)i]], lanes[(uint32_t)i], style);
        }
        for (int i = 1; i < 8; i += 2) {
            uint32_t style = (uint32_t)i + semantic_family;
            acc[idxs[(uint32_t)i]] = cprisk_vm_add_equiv_i(acc[idxs[(uint32_t)i]], lanes[(uint32_t)i], style);
        }
        break;
    case 8u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t j = (7u - i);
            uint32_t style = variant + j * 13u;
            acc[idxs[j]] = cprisk_vm_add_equiv_i(acc[idxs[j]], lanes[j], style);
        }
        break;
    case 9u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 11u + (uint32_t)(func_id & 7u)) & 7u;
            uint32_t style = (uint32_t)func_id + t + semantic_family;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_add_equiv_i(cur, lanes[i], style);
        }
        break;
    case 10u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (uint32_t u = 0; u < 8u; u++) {
            uint32_t k = (u ^ 3u) & 7u;
            uint32_t style = variant ^ u ^ k;
            acc[idxs[k]] = cprisk_vm_add_equiv_i(snapshot[k], lanes[k], style);
        }
        break;
    case 11u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t ^ (semantic_family & 7u)) & 7u;
            uint32_t style = (uint32_t)(func_id >> 8) ^ t;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_add_equiv_i(cur, lanes[i], style);
        }
        break;
    case 12u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = pc + i * 7u;
            acc[idxs[i]] = cprisk_vm_add_equiv_i(acc[idxs[i]], lanes[i], style);
        }
        break;
    case 13u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 2u + 3u) & 7u;
            uint32_t style = variant + t + (uint32_t)(pc & 5u);
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_add_equiv_i(cur, lanes[i], style);
        }
        break;
    case 14u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (int i = 7; i >= 0; i--) {
            uint32_t u = (uint32_t)i;
            uint32_t style = (semantic_family * 3u) + u ^ variant;
            acc[idxs[u]] = cprisk_vm_add_equiv_i(snapshot[u], lanes[u], style);
        }
        break;
    default:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t + variant) & 7u;
            uint32_t style = semantic_family + (uint32_t)(func_id & 0xFFu) + t;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_add_equiv_i(cur, lanes[i], style);
        }
        break;
    }
}

static void cprisk_vm_bitwise_lane_or_i(uint8_t acc[32],
                                        uint64_t imm,
                                        uint32_t steps,
                                        uint32_t variant,
                                        uint32_t semantic_family) {
    uint8_t lanes[8];
    uint8_t idxs[8];
    const uint32_t base = (uint32_t)(steps & 0x0Fu);
    for (uint32_t i = 0; i < 8u; i++) {
        lanes[i] = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        idxs[i] = (uint8_t)((i + base + (variant & 3u)) & 31u);
    }
    for (uint32_t i = 0; i < 8u; i++) {
        (void)semantic_family;
        (void)variant;
        acc[idxs[i]] = (uint8_t)(acc[idxs[i]] | lanes[i]);
    }
}

static void cprisk_vm_bitwise_lane_and_i(uint8_t acc[32],
                                         uint64_t imm,
                                         uint32_t steps,
                                         uint32_t variant,
                                         uint32_t semantic_family) {
    uint8_t lanes[8];
    uint8_t idxs[8];
    const uint32_t base = (uint32_t)((steps + 3u) & 0x0Fu);
    for (uint32_t i = 0; i < 8u; i++) {
        lanes[i] = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        idxs[i] = (uint8_t)((i + base) & 31u);
    }
    for (uint32_t i = 0; i < 8u; i++) {
        (void)variant;
        acc[idxs[i]] = (uint8_t)(acc[idxs[i]] & lanes[i]);
    }
}

static void cprisk_vm_rol_acc_i(uint8_t acc[32], uint64_t imm) {
    unsigned rot = (unsigned)(imm & 31u);
    uint8_t t[32];
    memcpy(t, acc, sizeof(t));
    for (unsigned i = 0; i < 32u; i++)
        acc[i] = t[(i + rot) % 32u];
}

/** Immediate: dst[2:0], src[5:3], mode[7:6] — 0=rr mov, 1=imm56@(>>8), 2=load 8B from acc[@(>>8)&31]. */
static void cprisk_vm_vreg_mov_i(uint64_t vregs[8], const uint8_t acc[32], uint64_t imm) {
    uint32_t dst = (uint32_t)(imm & 7u);
    uint32_t src = (uint32_t)((imm >> 3) & 7u);
    uint32_t mode = (uint32_t)((imm >> 6) & 3u);
    if (mode == 0u)
        vregs[dst] = vregs[src];
    else if (mode == 1u)
        vregs[dst] = imm >> 8;
    else {
        uint32_t base = (uint32_t)((imm >> 8) & 31u);
        uint64_t w = 0;
        for (uint32_t i = 0; i < 8u; i++)
            w |= (uint64_t)acc[(base + i) & 31u] << (i * 8u);
        vregs[dst] = w;
    }
}

/** Immediate: dst[2:0], a[5:3], b[8:6], op[11:9] — 0 ADD 1 XOR 2 AND 3 OR. */
static void cprisk_vm_vreg_alu_i(uint64_t vregs[8], uint64_t imm) {
    uint32_t dst = (uint32_t)(imm & 7u);
    uint32_t a = (uint32_t)((imm >> 3) & 7u);
    uint32_t b = (uint32_t)((imm >> 6) & 7u);
    uint32_t op = (uint32_t)((imm >> 9) & 7u);
    uint64_t va = vregs[a];
    uint64_t vb = vregs[b];
    uint64_t r;
    if (op == 0u)
        r = va + vb;
    else if (op == 1u)
        r = va ^ vb;
    else if (op == 2u)
        r = va & vb;
    else
        r = va | vb;
    vregs[dst] = r;
}

/** Immediate: dst[2:0], acc_base[7:3], store bit[8] — 0=load acc→vreg, 1=store vreg→acc. */
static void cprisk_vm_vreg_mem_i(uint64_t vregs[8], uint8_t acc[32], uint64_t imm) {
    uint32_t dst = (uint32_t)(imm & 7u);
    uint32_t base = (uint32_t)((imm >> 3) & 31u);
    uint32_t st = (uint32_t)((imm >> 8) & 1u);
    if (st == 0u) {
        uint64_t w = 0;
        for (uint32_t i = 0; i < 8u; i++)
            w |= (uint64_t)acc[(base + i) & 31u] << (i * 8u);
        vregs[dst] = w;
    } else {
        uint64_t w = vregs[dst];
        for (uint32_t i = 0; i < 8u; i++)
            acc[(base + i) & 31u] = (uint8_t)(w >> (i * 8u));
    }
}

static uint32_t cprisk_vm_mix32_from_acc_i(const uint8_t acc[32], uint32_t salt) {
    uint32_t m = salt ^ 0x9E3779B9u;
    for (uint32_t i = 0; i < 32u; i++) {
        m ^= (uint32_t)acc[i] << ((i & 3u) * 8u);
        m = (m << 5u) | (m >> 27u);
        m += 0x7F4A7C15u ^ (i * 0x45D9F3Bu);
    }
    return m;
}

static int cprisk_vm_eval_arm_cond_i(uint32_t cond, uint32_t n, uint32_t z, uint32_t c, uint32_t v) {
    switch (cond & 0xFu) {
    case 0x0u: return z != 0u;                 /* EQ */
    case 0x1u: return z == 0u;                 /* NE */
    case 0x2u: return c != 0u;                 /* CS/HS */
    case 0x3u: return c == 0u;                 /* CC/LO */
    case 0x4u: return n != 0u;                 /* MI */
    case 0x5u: return n == 0u;                 /* PL */
    case 0x6u: return v != 0u;                 /* VS */
    case 0x7u: return v == 0u;                 /* VC */
    case 0x8u: return (c != 0u) && (z == 0u); /* HI */
    case 0x9u: return (c == 0u) || (z != 0u); /* LS */
    case 0xAu: return n == v;                  /* GE */
    case 0xBu: return n != v;                  /* LT */
    case 0xCu: return (z == 0u) && (n == v);  /* GT */
    case 0xDu: return (z != 0u) || (n != v);  /* LE */
    case 0xEu: return 1;                       /* AL */
    default: return 0;                         /* NV */
    }
}

static uint64_t cprisk_vm_read_acc_word_i(const uint8_t acc[32], uint32_t lane_seed, uint32_t width_bytes) {
    uint64_t value = 0u;
    uint32_t base = lane_seed & 31u;
    if (width_bytes == 0u)
        width_bytes = 1u;
    for (uint32_t i = 0; i < width_bytes; i++) {
        uint32_t idx = (base + i) & 31u;
        value |= ((uint64_t)acc[idx]) << (i * 8u);
    }
    return value;
}

static int cprisk_vm_branch_cond_base_i(uint32_t insn,
                                        const uint8_t acc[32],
                                        uint64_t steps,
                                        uint32_t semantic_family,
                                        int *out_decision,
                                        int64_t *out_delta_bytes) {
    if (!out_decision || !out_delta_bytes)
        return 0;

    if ((insn & 0xFF000010u) == 0x54000000u) { /* B.cond */
        uint32_t imm19 = (insn >> 5u) & 0x7FFFFu;
        int32_t simm19 = ((int32_t)(imm19 << 13u)) >> 13u;
        *out_delta_bytes = (int64_t)simm19 * (int64_t)CPRISK_VM_INSN_WIDTH;

        uint32_t mix = cprisk_vm_mix32_from_acc_i(
            acc,
            (uint32_t)steps ^ (semantic_family * 0x9E37u) ^ (uint32_t)(insn >> 10u)
        );
        uint32_t n = (mix >> 31u) & 1u;
        uint32_t z = ((mix ^ (mix >> 16u)) & 0xFFu) == 0u;
        uint32_t c = (mix + 0x6D2B79F5u) < mix;
        uint32_t v = (((mix ^ (mix << 1u)) >> 31u) & 1u);
        *out_decision = cprisk_vm_eval_arm_cond_i(insn & 0xFu, n, z, c, v);
        return 1;
    }

    if ((insn & 0x7F000000u) == 0x34000000u) { /* CBZ/CBNZ */
        uint32_t imm19 = (insn >> 5u) & 0x7FFFFu;
        int32_t simm19 = ((int32_t)(imm19 << 13u)) >> 13u;
        *out_delta_bytes = (int64_t)simm19 * (int64_t)CPRISK_VM_INSN_WIDTH;
        uint32_t rt = insn & 31u;
        uint32_t is64 = (insn >> 31u) & 1u;
        uint32_t cbnz = (insn >> 24u) & 1u;
        uint64_t rv = cprisk_vm_read_acc_word_i(acc, rt ^ semantic_family, is64 ? 8u : 4u);
        *out_decision = cbnz ? (rv != 0u) : (rv == 0u);
        return 1;
    }

    return 0;
}

static int cprisk_vm_branch_cond_mixed_eval_i(uint32_t insn,
                                              const uint8_t acc[32],
                                              uint64_t steps,
                                              uint32_t semantic_family,
                                              uint32_t mixed_profile,
                                              int *out_taken,
                                              int64_t *out_delta_bytes) {
    int base = 0;
    if (!cprisk_vm_branch_cond_base_i(insn, acc, steps, semantic_family, &base, out_delta_bytes))
        return 0;
    uint32_t guard_mix = cprisk_vm_mix32_from_acc_i(
        acc,
        (uint32_t)(steps ^ (uint64_t)insn ^ ((uint64_t)mixed_profile << 16u))
    );
    uint32_t g0 = guard_mix & 1u;
    uint32_t g1 = (guard_mix >> 5u) & 1u;
    int decision = base;
    switch (mixed_profile & 3u) {
    case 0u:
        decision = base;
        break;
    case 1u:
        decision = (base && (int)g0) || (base && !(int)g0); /* ≡ base */
        break;
    case 2u:
        decision = (((base ? 1 : 0) ^ (int)g0) == (int)g0); /* ≡ base */
        break;
    default:
        decision = (base || (int)g1) && (base || !(int)g1); /* ≡ base */
        break;
    }
    if ((mixed_profile & 4u) != 0u) {
        uint32_t g2 = (guard_mix >> 11u) & 1u;
        decision = (decision && ((int)g2 || !(int)g2)); /* extra equivalent stage */
    }
    *out_taken = decision ? 1 : 0;
    return 1;
}

static int cprisk_vm_set_branch_target_i(uint64_t *enc_pc,
                                         uint64_t vpc_a,
                                         uint64_t vpc_b,
                                         uint32_t blen,
                                         uint32_t pc,
                                         int64_t delta_bytes,
                                         cprisk_vm_run_result_t *out) {
    if (!enc_pc)
        return 0;
    if (delta_bytes % (int64_t)CPRISK_VM_INSN_WIDTH != 0) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    int64_t target = (int64_t)(uint64_t)pc + delta_bytes;
    if (target < 0 || target % (int64_t)CPRISK_VM_INSN_WIDTH != 0
        || (uint64_t)target + CPRISK_VM_INSN_WIDTH > (uint64_t)blen) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    uint64_t scaled = 0u;
    uint64_t target_u = (uint64_t)target;
    if (__builtin_mul_overflow(target_u, vpc_a, &scaled) ||
        __builtin_add_overflow(scaled, vpc_b, &scaled)) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    *enc_pc = scaled;
    return 1;
}

static int cprisk_vmp_headers_ok_i(const uint8_t *d_s,
                                   unsigned long d_sz,
                                   const uint8_t *b_s,
                                   unsigned long b_sz,
                                   const cprisk_vmp_bytecode_header_t **out_bh) {
    if (!d_s || d_sz < sizeof(cprisk_vmp_dispatch_header_t) + CPRISK_VMP_CLASS_TABLE_BYTES)
        return 0;
    const cprisk_vmp_dispatch_header_t *dh = (const cprisk_vmp_dispatch_header_t *)(const void *)d_s;
    if (dh->magic != CPRISK_VMP_MAGIC_DISPATCH)
        return 0;
    if (dh->version != CPRISK_VMP_DISPATCH_V1 && dh->version != CPRISK_VMP_DISPATCH_V2)
        return 0;
    if (dh->class_table_size != CPRISK_VMP_CLASS_TABLE_BYTES)
        return 0;
    {
        size_t d_need = sizeof(cprisk_vmp_dispatch_header_t) + CPRISK_VMP_CLASS_TABLE_BYTES;
        if (dh->version == CPRISK_VMP_DISPATCH_V2)
            d_need += CPRISK_VMP_DISPATCH_SEED_BYTES;
        if (d_sz < d_need)
            return 0;
    }

    if (!b_s || b_sz < CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES)
        return 0;
    const cprisk_vmp_bytecode_header_t *bh = (const cprisk_vmp_bytecode_header_t *)(const void *)b_s;
    if (bh->magic != CPRISK_VMP_MAGIC_BYTECODE || !cprisk_vmp_bytecode_version_ok_i(bh->version))
        return 0;
    if ((bh->reserved & CPRISK_VMP_BC_FLAG_ENC_IMMEDIATE) != 0u
        && bh->version < CPRISK_VMP_VERSION_V3)
        return 0;
    if ((bh->reserved & CPRISK_VMP_BC_FLAG_ENC_OPCODE) != 0u
        && bh->version < CPRISK_VMP_VERSION_V3)
        return 0;
    if (bh->entry_count == 0u || bh->entry_count > 4096u)
        return 0;
    const size_t hdr_total = cprisk_vmp_bytecode_header_total_bytes_i(bh);
    if (b_sz < hdr_total)
        return 0;
    const size_t entry_stride = cprisk_vmp_bytecode_entry_stride_i(bh);
    if (b_sz < hdr_total + (unsigned long)bh->entry_count * entry_stride)
        return 0;
    if (out_bh)
        *out_bh = bh;
    return 1;
}

uint32_t cprisk_vm_query_armor_capability_bits(void) {
    const struct mach_header_64 *hdr =
        cprisk_find_own_header((const void *)&cprisk_vm_query_armor_capability_bits);
    if (!hdr)
        return 0u;
    unsigned long dsz = 0;
    unsigned long bsz = 0;
    const uint8_t *d =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_DISPATCH, &dsz);
    const uint8_t *b =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_BYTECODE, &bsz);
    if (cprisk_vmp_headers_ok_i(d, dsz, b, bsz, NULL))
        return CPRISK_ARMOR_CAP_VMP_RUNTIME;
    return 0u;
}

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
static void cprisk_vm_traced_decoy_acc_i(uint8_t acc[32]) {
    const uint8_t *src = acc;
    cprisk_sha256_ctx pctx;
    cprisk_sha256_init(&pctx);
    cprisk_sha256_update(&pctx, src, 32u);
    cprisk_sha256_final(&pctx, acc);
}
#else
static void __attribute__((unused)) cprisk_vm_traced_decoy_acc_i(uint8_t acc[32]) {
    (void)acc;
}
#endif

static void cprisk_vm_poison_mix_unknown_i(uint8_t acc[32], uint32_t opcode, uint32_t cls) {
    for (unsigned i = 0; i < 32u; i++) {
        uint8_t b = (uint8_t)(0xA5u ^ (unsigned)opcode ^ (unsigned)cls ^ i);
        acc[i] ^= b;
    }
}

/* M3: FNV-1a over interpreter text (ASLR-independent: bytes only). */
static uint32_t cprisk_vm_m3_fnv1a_bytes_i(const volatile uint8_t *p, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint32_t)p[i];
        h *= 16777619u;
    }
    return h;
}

/**
 * Bait handlers: wrong VM semantics, only referenced from provably-dead branches.
 * Kept out-of-line so the CFG shows distinct "handler" targets under disassembly.
 */
__attribute__((noinline)) static void cprisk_vm_m3_dead_bait_xor_i(uint8_t acc[32], uint32_t seed, uint32_t lane) {
    uint32_t x = (seed * 0x9E3779B9u) ^ (lane * 0x85EBCA6Bu);
    for (unsigned i = 0; i < 32u; i++)
        acc[i] ^= (uint8_t)(x >> (i & 7u));
}

__attribute__((noinline)) static void cprisk_vm_m3_dead_bait_add_i(uint8_t acc[32], uint32_t seed, uint32_t lane) {
    uint32_t x = seed + lane * 0x27d4eb2du;
    for (unsigned i = 0; i < 32u; i++)
        acc[i] = (uint8_t)(acc[i] + (uint8_t)(x + i));
}

__attribute__((noinline)) static void cprisk_vm_m3_dead_bait_roll_i(uint8_t acc[32], uint32_t seed) {
    unsigned rot = (unsigned)(seed & 31u);
    uint8_t t[32];
    memcpy(t, acc, sizeof(t));
    for (unsigned i = 0; i < 32u; i++)
        acc[i] = t[(i + rot) & 31u];
}

static void cprisk_vm_m3_dead_dispatch_i(uint8_t acc[32], uint32_t hdr_reserved, uint32_t opkind) {
    uint32_t dseed = (hdr_reserved >> 16) & 0xFFu;
    switch (opkind % 3u) {
    case 0u:
        cprisk_vm_m3_dead_bait_xor_i(acc, dseed, opkind);
        break;
    case 1u:
        cprisk_vm_m3_dead_bait_add_i(acc, dseed, opkind);
        break;
    default:
        cprisk_vm_m3_dead_bait_roll_i(acc, dseed);
        break;
    }
}

static const uint8_t *cprisk_vmp_dispatch_class_table_ptr_i(const uint8_t *d_sec,
                                                            const cprisk_vmp_dispatch_header_t *dh) {
    if (!d_sec || !dh)
        return NULL;
    if (dh->version == CPRISK_VMP_DISPATCH_V2)
        return d_sec + sizeof(cprisk_vmp_dispatch_header_t) + CPRISK_VMP_DISPATCH_SEED_BYTES;
    return d_sec + sizeof(cprisk_vmp_dispatch_header_t);
}

/* P0: one-shot keystream for dispatch v2 (build-time seed parity with VMBytecodeEmitter.dispatchKeystreamBytes). */
static void cprisk_vmp_dispatch_v2_keystream_i(uint64_t seed,
                                               uint8_t ks_out[CPRISK_VMP_CLASS_TABLE_BYTES]) {
    uint64_t state = seed ^ 0x4D4456544B455953ULL; /* "MDVTKEYS" */
    if (state == 0u)
        state = 0xDEADBEEFCAFEBABEULL;
    for (size_t i = 0; i < CPRISK_VMP_CLASS_TABLE_BYTES; i++)
        ks_out[i] = (uint8_t)cprisk_splitmix64_next_i(&state);
}

/* P0: stack-resident plaintext table; caller must cprisk_secure_zero when done. */
static void cprisk_vmp_materialize_dispatch_table_i(const uint8_t *d_sec,
                                                    const cprisk_vmp_dispatch_header_t *dh,
                                                    uint8_t out_table[CPRISK_VMP_CLASS_TABLE_BYTES]) {
    const uint8_t *payload = cprisk_vmp_dispatch_class_table_ptr_i(d_sec, dh);
    if (!payload) {
        memset(out_table, 0, CPRISK_VMP_CLASS_TABLE_BYTES);
        return;
    }
    if (dh->version == CPRISK_VMP_DISPATCH_V1
        || (dh->flags & CPRISK_VMP_DH_FLAG_CLASS_TABLE_KEYSTREAM) == 0u) {
        memcpy(out_table, payload, CPRISK_VMP_CLASS_TABLE_BYTES);
        return;
    }
    /* CPRISK_VMP_DISPATCH_V2 */
    const uint64_t seed = cprisk_read_le_u64_i(d_sec + sizeof(cprisk_vmp_dispatch_header_t));
    uint8_t ks[CPRISK_VMP_CLASS_TABLE_BYTES];
    cprisk_vmp_dispatch_v2_keystream_i(seed, ks);
    for (size_t i = 0; i < CPRISK_VMP_CLASS_TABLE_BYTES; i++)
        out_table[i] = (uint8_t)(payload[i] ^ ks[i]);
    cprisk_secure_zero(ks, sizeof(ks));
}

/* P1: per-instruction immediate mask (bytecode v3 parity with VMBytecodeEmitter.immediateXorMask). */
static uint64_t cprisk_vmp_imm_mask_u64_i(uint64_t func_id,
                                          uint32_t pc_index,
                                          uint64_t seed_root) {
    uint64_t state = func_id ^ (uint64_t)pc_index ^ seed_root ^ 0x494D4D584F523152ULL; /* "IMMXOR1R" */
    if (state == 0u)
        state = 0xDEADBEEFCAFEBABEULL;
    return cprisk_splitmix64_next_i(&state);
}

/* P1: wire opcode byte XOR (build/runtime parity with VMBytecodeEmitter.opcodeMixByte). */
static uint8_t cprisk_vmp_opcode_mix_byte_i(uint64_t func_id, uint32_t pc_index, uint64_t opcode_seed_root) {
    uint64_t state = func_id ^ (uint64_t)pc_index ^ opcode_seed_root ^ 0x4F50434D49583152ULL; /* "OPCMIX1R" */
    if (state == 0u)
        state = 0xDEADBEEFCAFEBABEULL;
    return (uint8_t)cprisk_splitmix64_next_i(&state);
}

/* Extra immediate scrub for rawRegion when dispatch marks opaque VPC category (paired with emitter). */
static uint64_t cprisk_vmp_raw_lane_mask_u64_i(uint64_t func_id, uint32_t pc_index, uint64_t bind_root) {
    uint64_t state = func_id ^ (uint64_t)pc_index ^ bind_root ^ 0x5241574C4E4D3130ULL; /* "RAWLNM10" */
    if (state == 0u)
        state = 0xDECAFBAD0BADF00DULL;
    return cprisk_splitmix64_next_i(&state);
}

static void cprisk_vm_self_fail_acc_i(uint8_t acc[32], uint64_t func_id) {
    for (unsigned i = 0; i < 32u; i++) {
        uint8_t b = (uint8_t)(0xC3u ^ (unsigned)(func_id >> (i & 15u)) ^ (i * 0x1Du));
        acc[i] ^= b;
    }
}

static uint32_t cprisk_vm_m3_self_expect_resolve_i(const struct mach_header_64 *mh) {
#if CPRISK_VM_M3_SELF_EXPECT != 0u
    (void)mh;
    return CPRISK_VM_M3_SELF_EXPECT;
#else
    unsigned long sz = 0;
    const uint8_t *p =
        cprisk_find_section(mh, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_SELF_EXPECT, &sz);
    if (p && sz >= 8u) {
        uint32_t mg = cprisk_read_le_u32_i(p);
        uint32_t fnv = cprisk_read_le_u32_i(p + 4u);
        if (mg == CPRISK_VMP_SELF_EXPECT_MAGIC)
            return fnv;
    }
    return 0u;
#endif
}

static uint32_t cprisk_vm_m3_self_expect_hmac_resolve_i(const struct mach_header_64 *mh) {
#if CPRISK_VM_M3_SELF_EXPECT != 0u
    (void)mh;
    return 0u;
#else
    unsigned long sz = 0;
    const uint8_t *p =
        cprisk_find_section(mh, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_SELF_EXPECT, &sz);
    if (!p || sz < 8u)
        return 0u;
    for (size_t o = 0; o + 8 <= sz && o < 128; o += 4) {
        uint32_t mg = cprisk_read_le_u32_i(p + o);
        if (mg == CPRISK_VMP_SELF_EXPECT_MAGIC_HMAC)
            return cprisk_read_le_u32_i(p + o + 4u);
    }
    return 0u;
#endif
}

static void cprisk_vm_selfchk_hmac_key_i(const uint8_t runtime_mat[32], uint8_t key_out[32]) {
    uint8_t buf[32 + 20];
    memcpy(buf, runtime_mat, 32);
    memcpy(buf + 32, "CPRISK_VM_M3_HMAC", (size_t)17);
    buf[32 + 17] = 0;
    cprisk_sha256(buf, 32u + 18u, key_out);
    cprisk_secure_zero(buf, sizeof(buf));
}

static void cprisk_vm_m3_selfchk_run_i(const struct mach_header_64 *hdr,
                                       uint8_t acc[32],
                                       uint64_t func_id,
                                       const cprisk_vmp_bytecode_header_t *bh,
                                       cprisk_vm_run_result_t *out) {
    const int want = (bh->reserved & CPRISK_VMP_BC_FLAG_M3_SELFCHK) != 0u;
    if (!want)
        return;

    const uint32_t exp_fnv = cprisk_vm_m3_self_expect_resolve_i(hdr);
    const uint32_t exp_hmac = cprisk_vm_m3_self_expect_hmac_resolve_i(hdr);
#if CPRISK_VM_SELFCHK_FORCE_LEGACY_FNV
    const int use_hmac = 0;
#else
    const int explicit_hmac = (bh->reserved & CPRISK_VMP_BC_FLAG_M3_SELFCHK_HMAC) != 0u;
    const int implicit_hmac =
        (CPRISK_VM_SELFCHK_PREFER_HMAC_WHEN_AMBIGUOUS != 0) && exp_hmac != 0u && exp_fnv == 0u;
    const int use_hmac = explicit_hmac || implicit_hmac;
#endif

    if (use_hmac) {
        uint8_t rt[32];
        cprisk_get_runtime_material(rt);
        uint8_t hk[32];
        cprisk_vm_selfchk_hmac_key_i(rt, hk);
        uint8_t full[32];
        cprisk_hmac_sha256(hk, 32u,
                           (const uint8_t *)(const void *)&cprisk_vm_execute,
                           (size_t)CPRISK_VM_M3_SELF_BYTES,
                           full);
        cprisk_secure_zero(hk, sizeof(hk));
        uint32_t tag32 = cprisk_read_le_u32_i(full);
        cprisk_secure_zero(full, sizeof(full));
        if (exp_hmac == 0u) {
#if CPRISK_VM_SELFCHK_POLICY >= 1
            out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_self_fail_acc_i(acc, func_id);
#endif
        } else if (tag32 != exp_hmac) {
            out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_self_fail_acc_i(acc, func_id);
        }
        return;
    }

    if (exp_fnv == 0u) {
#if CPRISK_VM_SELFCHK_POLICY >= 1
        out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
        cprisk_vm_self_fail_acc_i(acc, func_id);
#else
        /* Legacy: flag without golden/section → no-op (pipelines may opt into policy >= 1). */
#endif
    } else {
        uint32_t fnv = cprisk_vm_m3_fnv1a_bytes_i((const volatile uint8_t *)(const void *)&cprisk_vm_execute,
                                                 (size_t)CPRISK_VM_M3_SELF_BYTES);
        if (fnv != exp_fnv) {
            out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_self_fail_acc_i(acc, func_id);
        }
    }
}

static void cprisk_vm_wb_finalize_i(cprisk_vm_run_result_t *out, uint8_t acc[32]) {
    memcpy(out->acc, acc, sizeof(out->acc));
    uint8_t wb_out[32];
    int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
    out->whitebox_domain_rc = wbr;
    if (wbr == 0)
        memcpy(out->acc, wb_out, sizeof(wb_out));
}

__attribute__((noinline)) static void cprisk_vm_interp_core_marker0_i(void) {
    volatile uint32_t q = 0xC0u;
    q ^= (q << 3);
    (void)q;
}

__attribute__((noinline)) static void cprisk_vm_interp_core_marker1_i(void) {
    volatile uint32_t q = 0xC1u;
    q = (q * 7u) ^ 0x9E3779B9u;
    (void)q;
}

__attribute__((noinline)) static void cprisk_vm_interp_core_marker2_i(void) {
    volatile uint32_t q = 0xC2u;
    q |= (q >> 1);
    (void)q;
}


typedef struct {
    uint64_t resume_enc_pc;
    const uint8_t *snap_code;
    uint32_t snap_blen;
    uint64_t snap_vpc_a;
    uint64_t snap_vpc_b;
    uint32_t snap_semantic_family;
    uint32_t snap_mixed_predicate_profile;
    uint32_t snap_max_subcall_depth;
    uint64_t snap_ret_stack[CPRISK_VM_MAX_SUBCALL_DEPTH];
    uint32_t snap_ret_sp;
    uint64_t snap_vregs[8];
} cprisk_vm_vmcall_snap_t;

typedef struct {
    const struct mach_header_64 *hdr;
    const uint8_t *b_sec;
    unsigned long bsz;
    const cprisk_vmp_bytecode_header_t *bh;
    const uint8_t *dispatch_plain;
    uint32_t dispatch_hdr_flags;
    uint32_t path_lane;
    uint64_t func_id;
    cprisk_vm_run_result_t *out;

    size_t bc_hdr_total;
    size_t entry_stride;

    uint64_t vpc_a;
    uint64_t vpc_b;
    const uint8_t *code;
    uint32_t blen;
    uint64_t encoded_pc;
    uint32_t semantic_family;
    uint32_t mixed_predicate_profile;
    uint32_t max_subcall_depth;
    uint64_t return_stack[CPRISK_VM_MAX_SUBCALL_DEPTH];
    uint32_t return_sp;
    cprisk_vm_vmcall_snap_t vm_snap[CPRISK_VM_MAX_VM_NEST_DEPTH];
    uint32_t vm_snap_sp;
    uint64_t vregs[8];

    uint32_t enc_imm;
    uint32_t enc_op;
    uint64_t imm_seed_root;
    uint64_t opcode_seed_root;
    uint64_t raw_bind_root;
    uint32_t m3_opaque;
    uint32_t m3_dead;
    int vm_anti_symbolic_heavy;

    uint8_t acc[32];

    uint64_t steps;
} cprisk_vm_interp_frame_t;

static void cprisk_vm_interp_finish_run_i(cprisk_vm_interp_frame_t *fr) {
    memcpy(fr->out->acc, fr->acc, sizeof(fr->acc));
    memcpy(fr->out->vregs, fr->vregs, sizeof(fr->vregs));
    fr->out->steps = fr->steps;
    uint8_t wb_out[32];
    int wbr = cprisk_whitebox_evaluate_domain(5u, fr->out->acc, wb_out);
    fr->out->whitebox_domain_rc = wbr;
    if (wbr == 0)
        memcpy(fr->out->acc, wb_out, sizeof(wb_out));
}

static void cprisk_vm_interp_loop_a(cprisk_vm_interp_frame_t *fr)
{
    while (fr->steps < CPRISK_VM_MAX_STEPS) {
        if (fr->path_lane == 0u) {
            cprisk_vm_interp_core_marker0_i();
        } else if (fr->path_lane == 1u) {
            cprisk_vm_interp_core_marker1_i();
        } else {
            cprisk_vm_interp_core_marker2_i();
        }
        if (fr->path_lane == 1u) {
            volatile uint32_t pl = (uint32_t)fr->func_id ^ (uint32_t)(fr->steps * 0xB5297A4Du);
            (void)(pl ^ pl);
        } else if (fr->path_lane == 2u) {
            volatile uint32_t pl2 = (uint32_t)(fr->func_id >> 33) ^ (uint32_t)fr->steps;
            (void)(pl2 | 0u);
        }
        if (fr->path_lane != 1u) {
            if (fr->m3_opaque != 0u) {
                uint32_t vpc_tag = (uint32_t)(fr->encoded_pc ^ (fr->encoded_pc >> 32));
                vpc_tag ^= (uint32_t)fr->steps;
                vpc_tag ^= (uint32_t)fr->func_id ^ (uint32_t)(fr->func_id >> 32);
                if (((vpc_tag * vpc_tag) & 1u) != (vpc_tag & 1u)) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x11u);
                    continue;
                }
                volatile uint32_t vt = vpc_tag;
                if ((vt * 2u) == 1u) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0x22u);
                    continue;
                }
                volatile uint32_t vp = vpc_tag;
                if (((vp | 0u) == 0u) && vp != 0u) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_add_i(fr->acc, (fr->bh->reserved >> 16) & 0xFFu, 0x33u);
                    continue;
                }
            } else if (fr->m3_dead != 0u) {
                volatile uint32_t ds = (fr->bh->reserved >> 16) & 0xFFu;
                if ((ds * 2u) == 1u)
                    cprisk_vm_m3_dead_bait_roll_i(fr->acc, ds);
            }
        }

        if (fr->encoded_pc < fr->vpc_b) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }
        const uint64_t numer = fr->encoded_pc - fr->vpc_b;
        if (numer % fr->vpc_a != 0u) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }
        const uint64_t pc64 = numer / fr->vpc_a;
        if (pc64 > (uint64_t)UINT32_MAX) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }
        const uint32_t pc = (uint32_t)pc64;
        if ((uint64_t)pc + CPRISK_VM_INSN_WIDTH > (uint64_t)fr->blen) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }

        if (fr->path_lane == 1u) {
            if (fr->m3_opaque != 0u) {
                uint32_t vpc_tag = (uint32_t)(fr->encoded_pc ^ (fr->encoded_pc >> 32));
                vpc_tag ^= (uint32_t)fr->steps;
                vpc_tag ^= (uint32_t)fr->func_id ^ (uint32_t)(fr->func_id >> 32);
                if (((vpc_tag * vpc_tag) & 1u) != (vpc_tag & 1u)) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x11u);
                    continue;
                }
                volatile uint32_t vt = vpc_tag;
                if ((vt * 2u) == 1u) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0x22u);
                    continue;
                }
                volatile uint32_t vp = vpc_tag;
                if (((vp | 0u) == 0u) && vp != 0u) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_add_i(fr->acc, (fr->bh->reserved >> 16) & 0xFFu, 0x33u);
                    continue;
                }
            } else if (fr->m3_dead != 0u) {
                volatile uint32_t ds = (fr->bh->reserved >> 16) & 0xFFu;
                if ((ds * 2u) == 1u)
                    cprisk_vm_m3_dead_bait_roll_i(fr->acc, ds);
            }
        }

        if (fr->m3_opaque != 0u) {
            uint32_t pc_mix = pc ^ (uint32_t)(fr->steps * 0x45D9F3Bu);
            pc_mix ^= (uint32_t)(fr->blen + 0x9E3779B9u);
            if (((pc_mix * pc_mix) & 1u) != (pc_mix & 1u)) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x44u);
                continue;
            }
        }

        const uint8_t op_raw = fr->code[pc];
        uint8_t op = op_raw;
        if (fr->enc_op != 0u) {
            const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
            op = (uint8_t)(op_raw ^ cprisk_vmp_opcode_mix_byte_i(fr->func_id, pc_index, fr->opcode_seed_root));
        }
        fr->out->last_opcode = (uint32_t)op;
        const uint8_t logical = fr->dispatch_plain[(size_t)op & 0xFFu];
        fr->out->last_dispatch_class = (uint32_t)logical;
        uint64_t imm = cprisk_read_le_u64_i(fr->code + pc + 1u);
        if (fr->enc_imm != 0u) {
            const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
            imm ^= cprisk_vmp_imm_mask_u64_i(fr->func_id, pc_index, fr->imm_seed_root);
        }
        const uint32_t hvar =
            cprisk_vm_handler_variant_i(fr->bh->reserved, fr->func_id, fr->steps, (uint32_t)op, imm)
            ^ ((fr->semantic_family & 0x3u) << 1u);

        if (fr->m3_opaque != 0u) {
            uint32_t lt = (uint32_t)logical ^ (uint32_t)(fr->steps * 3u);
            lt ^= (uint32_t)(imm ^ (imm >> 32));
            volatile uint32_t lv = lt;
            if ((lv * 2u) == 1u) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, (uint32_t)op + 0x50u);
                continue;
            }
        }

        if (fr->vm_anti_symbolic_heavy) {
            volatile uint64_t sym_acc = ((uint64_t)fr->steps ^ imm) * 0xD6E8FEB783278F6BULL;
            sym_acc ^= (uint64_t)fr->func_id ^ (fr->func_id >> 33);
            for (uint32_t si = 0u; si < 3u; si++) {
                sym_acc ^= sym_acc >> 17;
                sym_acc *= 0xFF51AFD7ED558CCDULL;
                if (((sym_acc >> 40) & 0xFFFFu) == 0xA5A5u) {
                    const uint32_t lane = (si * 7u) & 31u;
                    fr->acc[lane] ^= (uint8_t)(sym_acc & 0xFFu);
                    fr->acc[(lane + 3u) & 31u] ^= (uint8_t)((sym_acc >> 8) & 0xFFu);
                }
            }
            (void)sym_acc;
        }

        if (logical == CPRISK_VM_OP_POISON) {
            fr->out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
            cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op, (uint32_t)logical);
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_HALT) {
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            fr->out->status = CPRISK_VM_STATUS_OK;
            goto vm_leave_a;
        }

        if (logical == CPRISK_VM_OP_RET) {
            if (fr->return_sp > 0u) {
                fr->return_sp -= 1u;
                fr->encoded_pc = fr->return_stack[fr->return_sp];
                fr->steps += 1u;
                continue;
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
                continue;
            }
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            fr->out->status = CPRISK_VM_STATUS_OK;
            goto vm_leave_a;
        }

        if (logical == CPRISK_VM_OP_NOP) {
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_RAW_REGION) {
            uint64_t imm_use = imm;
            if ((fr->dispatch_hdr_flags & CPRISK_VMP_DH_FLAG_OPAQUE_VPC_CATEGORY) != 0u) {
                const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
                imm_use ^= cprisk_vmp_raw_lane_mask_u64_i(fr->func_id, pc_index, fr->raw_bind_root);
            }
            cprisk_vm_raw_region_apply_i(fr->acc, imm_use, (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc);
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_ADD) {
            cprisk_vm_add_apply_i(fr->acc, imm, (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc);
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_BRANCH_REL) {
            int64_t delta = (int64_t)(uint64_t)imm;
            if (!cprisk_vm_set_branch_target_i(&fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_BRANCH_COND) {
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
                cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op, (uint32_t)logical);
                if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                    goto vm_leave_a;
                fr->steps += 1u;
                continue;
            }
            if (taken) {
                if (!cprisk_vm_set_branch_target_i(&fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
                    goto vm_leave_a;
            } else {
                if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                    goto vm_leave_a;
            }
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_CALL) {
            if (fr->return_sp >= fr->max_subcall_depth) {
                fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
                goto vm_leave_a;
            }
            uint64_t ret_pc = (uint64_t)pc + CPRISK_VM_INSN_WIDTH;
            uint64_t ret_enc = 0u;
            if (__builtin_mul_overflow(ret_pc, fr->vpc_a, &ret_enc)
                || __builtin_add_overflow(ret_enc, fr->vpc_b, &ret_enc)) {
                fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
                goto vm_leave_a;
            }
            fr->return_stack[fr->return_sp] = ret_enc;
            fr->return_sp += 1u;
            int64_t delta = (int64_t)(uint64_t)imm;
            if (!cprisk_vm_set_branch_target_i(&fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_XOR_MIX) {
            uint64_t mix_imm = imm ^ ((imm << 17u) | (imm >> 47u)) ^ ((uint64_t)fr->semantic_family << 56u);
            cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps, hvar ^ 1u, fr->semantic_family ^ 1u, fr->func_id, pc);
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_OR_LANE) {
            cprisk_vm_bitwise_lane_or_i(fr->acc, imm, (uint32_t)fr->steps, hvar, fr->semantic_family);
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_AND_LANE) {
            cprisk_vm_bitwise_lane_and_i(fr->acc, imm, (uint32_t)fr->steps, hvar, fr->semantic_family);
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_ROL_ACC) {
            cprisk_vm_rol_acc_i(fr->acc, imm);
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_VREG_MOV) {
            cprisk_vm_vreg_mov_i(fr->vregs, fr->acc, imm);
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_VREG_ALU) {
            cprisk_vm_vreg_alu_i(fr->vregs, imm);
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_VREG_MEM) {
            cprisk_vm_vreg_mem_i(fr->vregs, fr->acc, imm);
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_VM_CALL_FUNC) {
            if (fr->vm_snap_sp >= CPRISK_VM_MAX_VM_NEST_DEPTH) {
                fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
                goto vm_leave_a;
            }
            uint64_t callee_id = imm;
            uint64_t ret_pc = (uint64_t)pc + CPRISK_VM_INSN_WIDTH;
            uint64_t ret_enc = 0u;
            if (__builtin_mul_overflow(ret_pc, fr->vpc_a, &ret_enc)
                || __builtin_add_overflow(ret_enc, fr->vpc_b, &ret_enc)) {
                fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
                goto vm_leave_a;
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
                goto vm_leave_a;
            }
            fr->vpc_a = 1u;
            fr->vpc_b = 0u;
            cprisk_vmp_read_vpc_affine_i(fr->b_sec, fr->bh, &fr->vpc_a, &fr->vpc_b);
            if ((fr->bh->reserved & CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC) != 0u) {
                const uint8_t *selp = fr->b_sec + fr->bc_hdr_total + (size_t)callee_idx * fr->entry_stride;
                fr->vpc_a = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t));
                fr->vpc_b = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t) + 8u);
            }
            fr->code = fr->b_sec + callee_ent->bytecode_offset;
            fr->blen = callee_ent->bytecode_length;
            fr->encoded_pc = fr->vpc_b;
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
            fr->return_sp = 0u;
            memset(fr->return_stack, 0, sizeof(fr->return_stack));
            if (fr->vpc_a == 0u) {
                fr->vm_snap_sp -= 1u;
                memcpy(fr->vregs, fr->vm_snap[fr->vm_snap_sp].snap_vregs, sizeof(fr->vregs));
                fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
                goto vm_leave_a;
            }
            fr->steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_MOV_WIDE
            || logical == CPRISK_VM_OP_ADR_ADD
            || logical == CPRISK_VM_OP_COND_SELECT
            || logical == CPRISK_VM_OP_LOAD_STORE) {
            uint64_t op_salt = ((uint64_t)logical << 52u) ^ ((uint64_t)(uint32_t)fr->steps << 11u);
            uint64_t mix_imm = imm ^ op_salt ^ (imm >> (((uint32_t)logical & 7u) + 1u));
            if (logical == CPRISK_VM_OP_LOAD_STORE || (((uint32_t)logical ^ fr->mixed_predicate_profile) & 1u) != 0u) {
                cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps, hvar ^ logical, fr->semantic_family, fr->func_id, pc);
            } else {
                cprisk_vm_add_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps, hvar ^ logical, fr->semantic_family, fr->func_id, pc);
            }
            if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                goto vm_leave_a;
            fr->steps += 1u;
            continue;
        }

        fr->out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
        cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op, (uint32_t)logical);
        if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
            goto vm_leave_a;
        fr->steps += 1u;
        continue;

    }
vm_leave_a:
    cprisk_vm_interp_finish_run_i(fr);
}


static void cprisk_vm_interp_loop_b(cprisk_vm_interp_frame_t *fr)
{
    while (fr->steps < CPRISK_VM_MAX_STEPS) {
        if (fr->path_lane == 0u) {
            cprisk_vm_interp_core_marker0_i();
        } else if (fr->path_lane == 1u) {
            cprisk_vm_interp_core_marker1_i();
        } else {
            cprisk_vm_interp_core_marker2_i();
        }
        if (fr->path_lane == 1u) {
            volatile uint32_t pl = (uint32_t)fr->func_id ^ (uint32_t)(fr->steps * 0xB5297A4Du);
            (void)(pl ^ pl);
        } else if (fr->path_lane == 2u) {
            volatile uint32_t pl2 = (uint32_t)(fr->func_id >> 33) ^ (uint32_t)fr->steps;
            (void)(pl2 | 0u);
        }
        if (fr->path_lane != 1u) {
            if (fr->m3_opaque != 0u) {
                uint32_t vpc_tag = (uint32_t)(fr->encoded_pc ^ (fr->encoded_pc >> 32));
                vpc_tag ^= (uint32_t)fr->steps;
                vpc_tag ^= (uint32_t)fr->func_id ^ (uint32_t)(fr->func_id >> 32);
                if (((vpc_tag * vpc_tag) & 1u) != (vpc_tag & 1u)) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x11u);
                    continue;
                }
                volatile uint32_t vt = vpc_tag;
                if ((vt * 2u) == 1u) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0x22u);
                    continue;
                }
                volatile uint32_t vp = vpc_tag;
                if (((vp | 0u) == 0u) && vp != 0u) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_add_i(fr->acc, (fr->bh->reserved >> 16) & 0xFFu, 0x33u);
                    continue;
                }
            } else if (fr->m3_dead != 0u) {
                volatile uint32_t ds = (fr->bh->reserved >> 16) & 0xFFu;
                if ((ds * 2u) == 1u)
                    cprisk_vm_m3_dead_bait_roll_i(fr->acc, ds);
            }
        }

        if (fr->encoded_pc < fr->vpc_b) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }
        const uint64_t numer = fr->encoded_pc - fr->vpc_b;
        if (numer % fr->vpc_a != 0u) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }
        const uint64_t pc64 = numer / fr->vpc_a;
        if (pc64 > (uint64_t)UINT32_MAX) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }
        const uint32_t pc = (uint32_t)pc64;
        if ((uint64_t)pc + CPRISK_VM_INSN_WIDTH > (uint64_t)fr->blen) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }

        if (fr->path_lane == 1u) {
            if (fr->m3_opaque != 0u) {
                uint32_t vpc_tag = (uint32_t)(fr->encoded_pc ^ (fr->encoded_pc >> 32));
                vpc_tag ^= (uint32_t)fr->steps;
                vpc_tag ^= (uint32_t)fr->func_id ^ (uint32_t)(fr->func_id >> 32);
                if (((vpc_tag * vpc_tag) & 1u) != (vpc_tag & 1u)) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x11u);
                    continue;
                }
                volatile uint32_t vt = vpc_tag;
                if ((vt * 2u) == 1u) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0x22u);
                    continue;
                }
                volatile uint32_t vp = vpc_tag;
                if (((vp | 0u) == 0u) && vp != 0u) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_add_i(fr->acc, (fr->bh->reserved >> 16) & 0xFFu, 0x33u);
                    continue;
                }
            } else if (fr->m3_dead != 0u) {
                volatile uint32_t ds = (fr->bh->reserved >> 16) & 0xFFu;
                if ((ds * 2u) == 1u)
                    cprisk_vm_m3_dead_bait_roll_i(fr->acc, ds);
            }
        }

        if (fr->m3_opaque != 0u) {
            uint32_t pc_mix = pc ^ (uint32_t)(fr->steps * 0x45D9F3Bu);
            pc_mix ^= (uint32_t)(fr->blen + 0x9E3779B9u);
            if (((pc_mix * pc_mix) & 1u) != (pc_mix & 1u)) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x44u);
                continue;
            }
        }

        const uint8_t op_raw = fr->code[pc];
        uint8_t op = op_raw;
        if (fr->enc_op != 0u) {
            const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
            op = (uint8_t)(op_raw ^ cprisk_vmp_opcode_mix_byte_i(fr->func_id, pc_index, fr->opcode_seed_root));
        }
        fr->out->last_opcode = (uint32_t)op;
        const uint8_t logical = fr->dispatch_plain[(size_t)op & 0xFFu];
        fr->out->last_dispatch_class = (uint32_t)logical;
        uint64_t imm = cprisk_read_le_u64_i(fr->code + pc + 1u);
        if (fr->enc_imm != 0u) {
            const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
            imm ^= cprisk_vmp_imm_mask_u64_i(fr->func_id, pc_index, fr->imm_seed_root);
        }
        const uint32_t hvar =
            cprisk_vm_handler_variant_i(fr->bh->reserved, fr->func_id, fr->steps, (uint32_t)op, imm)
            ^ ((fr->semantic_family & 0x3u) << 1u);

        if (fr->m3_opaque != 0u) {
            uint32_t lt = (uint32_t)logical ^ (uint32_t)(fr->steps * 3u);
            lt ^= (uint32_t)(imm ^ (imm >> 32));
            volatile uint32_t lv = lt;
            if ((lv * 2u) == 1u) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, (uint32_t)op + 0x50u);
                continue;
            }
        }

        if (fr->vm_anti_symbolic_heavy) {
            volatile uint64_t sym_acc = ((uint64_t)fr->steps ^ imm) * 0xD6E8FEB783278F6BULL;
            sym_acc ^= (uint64_t)fr->func_id ^ (fr->func_id >> 33);
            for (uint32_t si = 0u; si < 3u; si++) {
                sym_acc ^= sym_acc >> 17;
                sym_acc *= 0xFF51AFD7ED558CCDULL;
                if (((sym_acc >> 40) & 0xFFFFu) == 0xA5A5u) {
                    const uint32_t lane = (si * 7u) & 31u;
                    fr->acc[lane] ^= (uint8_t)(sym_acc & 0xFFu);
                    fr->acc[(lane + 3u) & 31u] ^= (uint8_t)((sym_acc >> 8) & 0xFFu);
                }
            }
            (void)sym_acc;
        }

        switch (logical) {
        case CPRISK_VM_OP_POISON:
            {

                    fr->out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
                    cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op, (uint32_t)logical);
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_HALT:
            {

                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    fr->out->status = CPRISK_VM_STATUS_OK;
                    goto vm_leave_b;

            }

        case CPRISK_VM_OP_RET:
            {

                    if (fr->return_sp > 0u) {
                        fr->return_sp -= 1u;
                        fr->encoded_pc = fr->return_stack[fr->return_sp];
                        fr->steps += 1u;
                        continue;
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
                        continue;
                    }
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    fr->out->status = CPRISK_VM_STATUS_OK;
                    goto vm_leave_b;

            }

        case CPRISK_VM_OP_NOP:
            {

                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_RAW_REGION:
            {

                    uint64_t imm_use = imm;
                    if ((fr->dispatch_hdr_flags & CPRISK_VMP_DH_FLAG_OPAQUE_VPC_CATEGORY) != 0u) {
                        const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
                        imm_use ^= cprisk_vmp_raw_lane_mask_u64_i(fr->func_id, pc_index, fr->raw_bind_root);
                    }
                    cprisk_vm_raw_region_apply_i(fr->acc, imm_use, (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc);
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_ADD:
            {

                    cprisk_vm_add_apply_i(fr->acc, imm, (uint32_t)fr->steps, hvar, fr->semantic_family, fr->func_id, pc);
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_BRANCH_REL:
            {

                    int64_t delta = (int64_t)(uint64_t)imm;
                    if (!cprisk_vm_set_branch_target_i(&fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_BRANCH_COND:
            {

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
                        cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op, (uint32_t)logical);
                        if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                            goto vm_leave_b;
                        fr->steps += 1u;
                        continue;
                    }
                    if (taken) {
                        if (!cprisk_vm_set_branch_target_i(&fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
                            goto vm_leave_b;
                    } else {
                        if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                            goto vm_leave_b;
                    }
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_CALL:
            {

                    if (fr->return_sp >= fr->max_subcall_depth) {
                        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
                        goto vm_leave_b;
                    }
                    uint64_t ret_pc = (uint64_t)pc + CPRISK_VM_INSN_WIDTH;
                    uint64_t ret_enc = 0u;
                    if (__builtin_mul_overflow(ret_pc, fr->vpc_a, &ret_enc)
                        || __builtin_add_overflow(ret_enc, fr->vpc_b, &ret_enc)) {
                        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
                        goto vm_leave_b;
                    }
                    fr->return_stack[fr->return_sp] = ret_enc;
                    fr->return_sp += 1u;
                    int64_t delta = (int64_t)(uint64_t)imm;
                    if (!cprisk_vm_set_branch_target_i(&fr->encoded_pc, fr->vpc_a, fr->vpc_b, fr->blen, pc, delta, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_XOR_MIX:
            {

                    uint64_t mix_imm = imm ^ ((imm << 17u) | (imm >> 47u)) ^ ((uint64_t)fr->semantic_family << 56u);
                    cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps, hvar ^ 1u, fr->semantic_family ^ 1u, fr->func_id, pc);
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_OR_LANE:
            {

                    cprisk_vm_bitwise_lane_or_i(fr->acc, imm, (uint32_t)fr->steps, hvar, fr->semantic_family);
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_AND_LANE:
            {

                    cprisk_vm_bitwise_lane_and_i(fr->acc, imm, (uint32_t)fr->steps, hvar, fr->semantic_family);
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_ROL_ACC:
            {

                    cprisk_vm_rol_acc_i(fr->acc, imm);
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_VREG_MOV:
            {

                    cprisk_vm_vreg_mov_i(fr->vregs, fr->acc, imm);
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_VREG_ALU:
            {

                    cprisk_vm_vreg_alu_i(fr->vregs, imm);
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_VREG_MEM:
            {

                    cprisk_vm_vreg_mem_i(fr->vregs, fr->acc, imm);
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_VM_CALL_FUNC:
            {

                    if (fr->vm_snap_sp >= CPRISK_VM_MAX_VM_NEST_DEPTH) {
                        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
                        goto vm_leave_b;
                    }
                    uint64_t callee_id = imm;
                    uint64_t ret_pc = (uint64_t)pc + CPRISK_VM_INSN_WIDTH;
                    uint64_t ret_enc = 0u;
                    if (__builtin_mul_overflow(ret_pc, fr->vpc_a, &ret_enc)
                        || __builtin_add_overflow(ret_enc, fr->vpc_b, &ret_enc)) {
                        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
                        goto vm_leave_b;
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
                        goto vm_leave_b;
                    }
                    fr->vpc_a = 1u;
                    fr->vpc_b = 0u;
                    cprisk_vmp_read_vpc_affine_i(fr->b_sec, fr->bh, &fr->vpc_a, &fr->vpc_b);
                    if ((fr->bh->reserved & CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC) != 0u) {
                        const uint8_t *selp = fr->b_sec + fr->bc_hdr_total + (size_t)callee_idx * fr->entry_stride;
                        fr->vpc_a = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t));
                        fr->vpc_b = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t) + 8u);
                    }
                    fr->code = fr->b_sec + callee_ent->bytecode_offset;
                    fr->blen = callee_ent->bytecode_length;
                    fr->encoded_pc = fr->vpc_b;
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
                    fr->return_sp = 0u;
                    memset(fr->return_stack, 0, sizeof(fr->return_stack));
                    if (fr->vpc_a == 0u) {
                        fr->vm_snap_sp -= 1u;
                        memcpy(fr->vregs, fr->vm_snap[fr->vm_snap_sp].snap_vregs, sizeof(fr->vregs));
                        fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                        fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
                        goto vm_leave_b;
                    }
                    fr->steps += 1u;
                    continue;

            }

        case CPRISK_VM_OP_MOV_WIDE:
        case CPRISK_VM_OP_ADR_ADD:
        case CPRISK_VM_OP_COND_SELECT:
        case CPRISK_VM_OP_LOAD_STORE:
            {

                    uint64_t op_salt = ((uint64_t)logical << 52u) ^ ((uint64_t)(uint32_t)fr->steps << 11u);
                    uint64_t mix_imm = imm ^ op_salt ^ (imm >> (((uint32_t)logical & 7u) + 1u));
                    if (logical == CPRISK_VM_OP_LOAD_STORE || (((uint32_t)logical ^ fr->mixed_predicate_profile) & 1u) != 0u) {
                        cprisk_vm_raw_region_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps, hvar ^ logical, fr->semantic_family, fr->func_id, pc);
                    } else {
                        cprisk_vm_add_apply_i(fr->acc, mix_imm, (uint32_t)fr->steps, hvar ^ logical, fr->semantic_family, fr->func_id, pc);
                    }
                    if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                        goto vm_leave_b;
                    fr->steps += 1u;
                    continue;

            }

        default:
            {
                fr->out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
                cprisk_vm_poison_mix_unknown_i(fr->acc, (uint32_t)op, (uint32_t)logical);
                if (!cprisk_vm_enc_pc_advance_i(&fr->encoded_pc, fr->vpc_a, fr->out))
                    goto vm_leave_b;
                fr->steps += 1u;
                continue;
            }
        }

    }
vm_leave_b:
    cprisk_vm_interp_finish_run_i(fr);
}

static void cprisk_vm_run_program_i(const struct mach_header_64 *hdr,
                                    const uint8_t *b_sec,
                                    unsigned long bsz,
                                    const cprisk_vmp_bytecode_header_t *bh,
                                    const uint8_t dispatch_plain[CPRISK_VMP_CLASS_TABLE_BYTES],
                                    uint32_t dispatch_hdr_flags,
                                    uint32_t path_lane,
                                    uint64_t func_id,
                                    uint8_t acc[32],
                                    cprisk_vm_run_result_t *out) {
    const size_t bc_hdr_total = cprisk_vmp_bytecode_header_total_bytes_i(bh);
    const size_t entry_stride = cprisk_vmp_bytecode_entry_stride_i(bh);

    uint64_t vpc_a = 1u;
    uint64_t vpc_b = 0u;
    cprisk_vmp_read_vpc_affine_i(b_sec, bh, &vpc_a, &vpc_b);

    const cprisk_vmp_bytecode_entry_t *selected = NULL;
    const uint64_t table_end =
        (uint64_t)bc_hdr_total + (uint64_t)bh->entry_count * (uint64_t)entry_stride;
    for (uint32_t i = 0; i < bh->entry_count; i++) {
        const uint8_t *ep = b_sec + bc_hdr_total + (size_t)i * entry_stride;
        const cprisk_vmp_bytecode_entry_t *entry = (const cprisk_vmp_bytecode_entry_t *)(const void *)ep;
        const uint64_t off = entry->bytecode_offset;
        const uint64_t len = entry->bytecode_length;
        if (off < table_end)
            continue;
        if (off + len > bsz)
            continue;
        if (entry->function_id == func_id) {
            selected = entry;
            break;
        }
    }
    if (!selected) {
        out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        cprisk_vm_wb_finalize_i(out, acc);
        return;
    }

    if ((bh->reserved & CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC) != 0u) {
        const uint8_t *selp = (const uint8_t *)selected;
        vpc_a = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t));
        vpc_b = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t) + 8u);
    }

    const uint8_t *code = b_sec + selected->bytecode_offset;
    uint32_t blen = selected->bytecode_length;
    uint64_t encoded_pc = vpc_b;
    uint32_t semantic_family = 1u;
    uint32_t mixed_predicate_profile = 0u;
    uint32_t max_subcall_depth = 4u;
    if (!cprisk_vm_entry_profile_decode_i(
            selected->reserved,
            &semantic_family,
            &mixed_predicate_profile,
            &max_subcall_depth
        )) {
        cprisk_vm_entry_profile_fallback_i(
            func_id,
            bh->reserved,
            &semantic_family,
            &mixed_predicate_profile,
            &max_subcall_depth
        );
    }
    if (semantic_family == 0u)
        semantic_family = 1u;
    if (max_subcall_depth == 0u)
        max_subcall_depth = 1u;
    if (max_subcall_depth > CPRISK_VM_MAX_SUBCALL_DEPTH)
        max_subcall_depth = CPRISK_VM_MAX_SUBCALL_DEPTH;
    uint64_t return_stack[CPRISK_VM_MAX_SUBCALL_DEPTH];
    uint32_t return_sp = 0u;
    cprisk_vm_vmcall_snap_t vm_snap[CPRISK_VM_MAX_VM_NEST_DEPTH];
    uint32_t vm_snap_sp = 0u;
    uint64_t vregs[8];
    memset(vregs, 0, sizeof(vregs));
    if (vpc_a == 0u) {
        out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        cprisk_vm_wb_finalize_i(out, acc);
        return;
    }

    cprisk_vm_m3_selfchk_run_i(hdr, acc, func_id, bh, out);

    const uint32_t m3_opaque = (bh->reserved & CPRISK_VMP_BC_FLAG_M3_OPAQUE_CHAIN) != 0u ? 1u : 0u;
    const uint32_t m3_dead = (bh->reserved & CPRISK_VMP_BC_FLAG_M3_DEAD_HANDLERS) != 0u ? 1u : 0u;
    const uint32_t enc_imm = (bh->reserved & CPRISK_VMP_BC_FLAG_ENC_IMMEDIATE) != 0u ? 1u : 0u;
    const uint32_t enc_op = (bh->reserved & CPRISK_VMP_BC_FLAG_ENC_OPCODE) != 0u ? 1u : 0u;
    uint64_t imm_seed_root = 0u;
    if (enc_imm != 0u) {
        if (bh->version < CPRISK_VMP_VERSION_V3) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_wb_finalize_i(out, acc);
            return;
        }
        size_t imm_seed_off = CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES;
        if (cprisk_vmp_bytecode_has_m2_i(bh))
            imm_seed_off += CPRISK_VMP_BYTECODE_VPC_EXT_BYTES;
        if (bc_hdr_total < imm_seed_off + 8u || bsz < imm_seed_off + 8u) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_wb_finalize_i(out, acc);
            return;
        }
        imm_seed_root = cprisk_read_le_u64_i(b_sec + imm_seed_off);
    }
    uint64_t opcode_seed_root = 0u;
    if (enc_op != 0u) {
        if (bh->version < CPRISK_VMP_VERSION_V3) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_wb_finalize_i(out, acc);
            return;
        }
        size_t op_seed_off = CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES;
        if (cprisk_vmp_bytecode_has_m2_i(bh))
            op_seed_off += CPRISK_VMP_BYTECODE_VPC_EXT_BYTES;
        if (enc_imm != 0u)
            op_seed_off += 8u;
        if (bc_hdr_total < op_seed_off + 8u || bsz < op_seed_off + 8u) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_wb_finalize_i(out, acc);
            return;
        }
        opcode_seed_root = cprisk_read_le_u64_i(b_sec + op_seed_off);
    }
    uint64_t raw_bind_root = imm_seed_root;
    if (raw_bind_root == 0u)
        raw_bind_root = opcode_seed_root;
    if (raw_bind_root == 0u)
        raw_bind_root = func_id ^ ((uint64_t)bh->reserved << 32) ^ 0x524157524F4F5431ULL; /* "RAWROOT1" */

    out->status = CPRISK_VM_STATUS_STEP_LIMIT;

    const int vm_anti_symbolic_heavy =
        (semantic_family >= 10u) ||
        (max_subcall_depth >= 8u) ||
        ((bh->reserved & CPRISK_VMP_BC_FLAG_ANTI_SYMBOLIC_HEAVY) != 0u);

    cprisk_vm_interp_frame_t fr;
    memset(&fr, 0, sizeof(fr));
    fr.hdr = hdr;
    fr.b_sec = b_sec;
    fr.bsz = bsz;
    fr.bh = bh;
    fr.dispatch_plain = dispatch_plain;
    fr.dispatch_hdr_flags = dispatch_hdr_flags;
    fr.path_lane = path_lane;
    fr.func_id = func_id;
    fr.out = out;
    fr.bc_hdr_total = bc_hdr_total;
    fr.entry_stride = entry_stride;
    fr.vpc_a = vpc_a;
    fr.vpc_b = vpc_b;
    fr.code = code;
    fr.blen = blen;
    fr.encoded_pc = encoded_pc;
    fr.semantic_family = semantic_family;
    fr.mixed_predicate_profile = mixed_predicate_profile;
    fr.max_subcall_depth = max_subcall_depth;
    memcpy(fr.return_stack, return_stack, sizeof(return_stack));
    fr.return_sp = return_sp;
    memcpy(fr.vm_snap, vm_snap, sizeof(vm_snap));
    fr.vm_snap_sp = vm_snap_sp;
    memcpy(fr.vregs, vregs, sizeof(vregs));
    fr.enc_imm = enc_imm;
    fr.enc_op = enc_op;
    fr.imm_seed_root = imm_seed_root;
    fr.opcode_seed_root = opcode_seed_root;
    fr.raw_bind_root = raw_bind_root;
    fr.m3_opaque = m3_opaque;
    fr.m3_dead = m3_dead;
    fr.vm_anti_symbolic_heavy = vm_anti_symbolic_heavy;
    memcpy(fr.acc, acc, sizeof(fr.acc));
    fr.steps = 0u;

    if (path_lane == 0u)
        cprisk_vm_interp_loop_a(&fr);
    else
        cprisk_vm_interp_loop_b(&fr);

    memcpy(acc, fr.acc, sizeof(fr.acc));
}

static int cprisk_vm_execute_engine_i(uint64_t func_id,
                                      cprisk_vm_run_result_t *out,
                                      const void *hdr_sym,
                                      unsigned path_lane) {
    if (!out)
        return -1;

    memset(out, 0, sizeof(*out));
    out->last_opcode = 0xFFFFFFFFu;
    out->last_dispatch_class = 0xFFFFFFFFu;
    out->whitebox_domain_rc = UINT32_MAX;

    uint8_t acc[32];
    memset(acc, 0, sizeof(acc));
    (void)cprisk_get_runtime_material(acc);

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /*
     * Redundant trace probes: sysctl and Mach paths are evaluated independently
     * of the aggregated `cprisk_is_being_traced` return to mitigate single-point
     * hooks returning a false negative.
     */
    if (cprisk_is_being_traced_sysctl_only() != 0 ||
        cprisk_mach_trace_suspicious() != 0 ||
        cprisk_is_being_traced() != 0) {
        out->poison_flags |= CPRISK_VM_POISON_TRACED;
        out->status = CPRISK_VM_STATUS_TRACED_SHORTCIRCUIT;
        cprisk_vm_traced_decoy_acc_i(acc);
        memcpy(out->acc, acc, sizeof(acc));
        uint8_t wb_out[32];
        int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
        out->whitebox_domain_rc = wbr;
        if (wbr == 0)
            memcpy(out->acc, wb_out, sizeof(wb_out));
        return 0;
    }
#endif

    cprisk_frida_runtime_snapshot_t fr;
    memset(&fr, 0, sizeof(fr));
    if (cprisk_frida_runtime_snapshot(&fr) == 0 && fr.supported != 0u && fr.flags != 0u)
        out->poison_flags |= CPRISK_VM_POISON_FRIDA;

    const struct mach_header_64 *hdr = cprisk_find_own_header(hdr_sym);
    if (!hdr) {
        out->poison_flags |= CPRISK_VM_POISON_DISPATCH;
        out->status = CPRISK_VM_STATUS_INVALID_DISPATCH;
        memcpy(out->acc, acc, sizeof(acc));
        return 0;
    }

    unsigned long dsz = 0;
    unsigned long bsz = 0;
    const uint8_t *d_sec =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_DISPATCH, &dsz);
    const uint8_t *b_sec =
        cprisk_find_section(hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_BYTECODE, &bsz);

    const cprisk_vmp_bytecode_header_t *bh = NULL;
    if (!cprisk_vmp_headers_ok_i(d_sec, dsz, b_sec, bsz, &bh) || !bh) {
        out->poison_flags |= CPRISK_VM_POISON_DISPATCH | CPRISK_VM_POISON_BYTECODE;
        out->status = CPRISK_VM_STATUS_INVALID_DISPATCH;
        memcpy(out->acc, acc, sizeof(acc));
        uint8_t wb_out[32];
        int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
        out->whitebox_domain_rc = wbr;
        if (wbr == 0)
            memcpy(out->acc, wb_out, sizeof(wb_out));
        return 0;
    }

    /* P0: recover dispatch into stack buffer; XOR path clears keystream internally. */
    const cprisk_vmp_dispatch_header_t *dhdr = (const cprisk_vmp_dispatch_header_t *)(const void *)d_sec;
    uint8_t dispatch_plain[CPRISK_VMP_CLASS_TABLE_BYTES];
    cprisk_vmp_materialize_dispatch_table_i(d_sec, dhdr, dispatch_plain);

    cprisk_vm_run_program_i(
        hdr,
        b_sec,
        bsz,
        bh,
        dispatch_plain,
        dhdr->flags,
        (uint32_t)path_lane,
        func_id,
        acc,
        out
    );

    cprisk_secure_zero(dispatch_plain, sizeof(dispatch_plain));

    return 0;
}

int cprisk_vm_execute(uint64_t func_id, cprisk_vm_run_result_t *out) {
    return cprisk_vm_execute_engine_i(func_id, out, (const void *)&cprisk_vm_execute, 0u);
}

__attribute__((noinline)) static uint64_t cprisk_vm_entry_finish_lane_i(uint64_t func_id,
                                                                          const void *hdr_sym,
                                                                          unsigned path_lane) {
    cprisk_vm_run_result_t result;
    if (cprisk_vm_execute_engine_i(func_id, &result, hdr_sym, path_lane) != 0)
        return 0;
    uint64_t folded = 0;
    memcpy(&folded, result.acc, sizeof(folded));
    return folded;
}

__attribute__((noinline)) uint64_t cprisk_vm_entry(uint64_t func_id) {
#if defined(__aarch64__)
    __asm__ volatile("add x0, x0, #0");
#endif

    /*
     * M3: keep a tiny side-effectful entry prelude so policy-guided Pass9 can
     * still find rewritable entry instructions on this wrapper symbol.
     */
    volatile uint64_t prelude = func_id ^ 0x9E3779B97F4A7C15ULL;
    prelude ^= (prelude >> 17);
    prelude ^= (prelude << 7);
    (void)prelude;

    return cprisk_vm_entry_finish_lane_i(func_id, (const void *)&cprisk_vm_entry, 0u);
}

__attribute__((noinline)) uint64_t cprisk_vm_entry_alt1(uint64_t func_id) {
#if defined(__aarch64__)
    __asm__ volatile("eor x16, x0, x0");
#endif
    volatile uint64_t tag = func_id ^ 0xA5A5A5A5C3C3C3C3ULL;
    tag = (tag << 1) | (tag >> 63);
    (void)tag;
    return cprisk_vm_entry_finish_lane_i(func_id, (const void *)&cprisk_vm_entry_alt1, 1u);
}

__attribute__((noinline)) uint64_t cprisk_vm_entry_alt2(uint64_t func_id) {
#if defined(__aarch64__)
    __asm__ volatile("eor x17, x0, x0");
#endif
    volatile uint64_t tag = func_id + 0x13579BDF2468ACE1ULL;
    tag ^= tag >> 29;
    (void)tag;
    return cprisk_vm_entry_finish_lane_i(func_id, (const void *)&cprisk_vm_entry_alt2, 2u);
}
