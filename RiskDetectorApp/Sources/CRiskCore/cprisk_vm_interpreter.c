#include "include/CRiskCore.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "include/cprisk_vm_interpreter_limits.h"
#include "include/cprisk_vm_interpreter_ops.h"
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <stdatomic.h>
#include <string.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <time.h>
#include <unistd.h>
#endif

#define CPRISK_VM_MAX_STEPS 65536u
#define CPRISK_VM_DISPATCH_CACHE_BYTES 16u
#define CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES ((size_t)sizeof(cprisk_vmp_bytecode_header_t))
#define CPRISK_VMP_BYTECODE_VPC_EXT_BYTES 16u

uint64_t cprisk_read_le_u64_i(const uint8_t *p) {
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
        || (bh->reserved & CPRISK_VMP_BC_FLAG_HANDLER_VARIANT_SEED) != 0u
        || (bh->reserved & CPRISK_VMP_BC_FLAG_VPC_NONLINEAR) != 0u;
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

void cprisk_vmp_read_vpc_affine_i(const uint8_t *b_sec,
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

static int cprisk_vmp_vpc_is_nonlinear_i(const cprisk_vmp_bytecode_header_t *bh) {
    return bh != NULL && (bh->reserved & CPRISK_VMP_BC_FLAG_VPC_NONLINEAR) != 0u;
}

static uint32_t cprisk_vm_session_mix_i(void);

static uint32_t cprisk_vmp_rotl32_i(uint32_t x, uint32_t n) {
    n &= 31u;
    return n == 0u ? x : ((x << n) | (x >> (32u - n)));
}

static uint32_t cprisk_vmp_rotr32_i(uint32_t x, uint32_t n) {
    n &= 31u;
    return n == 0u ? x : ((x >> n) | (x << (32u - n)));
}

uint32_t cprisk_vmp_avalanche32_i(uint32_t x) {
    x ^= x >> 16u;
    x *= 0x7FEB352Du;
    x ^= x >> 15u;
    x *= 0x846CA68Bu;
    x ^= x >> 16u;
    return x;
}

/* 4-bit nibble permutation stored XOR-masked (no raw permutation vector in rodata). */
static const uint8_t cprisk_vmp_vpc_sbox_enc_i[16] = {
    0x9u, 0x0u, 0x3u, 0xeu, 0xcu, 0x5u, 0xfu, 0x8u,
    0x6u, 0xbu, 0xau, 0xdu, 0x1u, 0x2u, 0x4u, 0x7u,
};
#define CPRISK_VMP_VPC_SBOX_XOR_I 0x5u

static uint16_t cprisk_vmp_vpc_sub16_i(uint16_t value) {
    uint16_t out = 0u;
    for (uint32_t nib = 0u; nib < 4u; nib++) {
        const uint16_t idx = (uint16_t)((value >> (nib * 4u)) & 0xFu);
        const uint8_t mapped =
            (uint8_t)(cprisk_vmp_vpc_sbox_enc_i[idx] ^ CPRISK_VMP_VPC_SBOX_XOR_I);
        out |= (uint16_t)mapped << (nib * 4u);
    }
    return out;
}

#define CPRISK_VMP_VPC_FEISTEL_ROUNDS 8u

static uint32_t cprisk_vmp_vpc_key32_i(uint64_t a, uint64_t b) {
    return cprisk_vmp_avalanche32_i(
        (uint32_t)a ^
        (uint32_t)(a >> 32u) ^
        cprisk_vmp_rotl32_i((uint32_t)b, 7u) ^
        (uint32_t)(b >> 32u) ^
        0x564D5043u
    );
}

static uint32_t cprisk_vmp_vpc_salt32_i(uint64_t a, uint64_t b) {
    return cprisk_vmp_avalanche32_i(
        (uint32_t)b ^
        (uint32_t)(b >> 32u) ^
        cprisk_vmp_rotl32_i((uint32_t)a, 11u) ^
        (uint32_t)(a >> 32u) ^
        0x4D345650u
    );
}

static uint16_t cprisk_vmp_vpc_feistel_F_i(uint16_t r, uint32_t key, uint32_t salt, uint32_t round) {
    uint32_t rk = cprisk_vmp_avalanche32_i(key ^ salt ^ (round * 0x9E3779B9u) ^ 0xDEADBEEFu);
    uint16_t piece = (uint16_t)(r ^ (uint16_t)rk ^ (uint16_t)(rk >> 16u));
    piece = cprisk_vmp_vpc_sub16_i(piece);
    piece ^= (uint16_t)cprisk_vmp_rotr32_i(rk, (round & 7u) + 1u);
    return (uint16_t)cprisk_vmp_avalanche32_i((uint32_t)piece ^ rk ^ 0xA5C31F27u);
}

static uint32_t cprisk_vmp_vpc_feistel32_encode_i(uint32_t state, uint32_t key, uint32_t salt) {
    uint32_t v = state ^ cprisk_vmp_avalanche32_i(key ^ salt ^ 0xF1055A1u);
    uint16_t l = (uint16_t)(v >> 16);
    uint16_t r = (uint16_t)(v & 0xFFFFu);
    for (uint32_t round = 0u; round < CPRISK_VMP_VPC_FEISTEL_ROUNDS; round++) {
        const uint16_t nl = r;
        const uint16_t nr = (uint16_t)(l ^ cprisk_vmp_vpc_feistel_F_i(r, key, salt, round));
        l = nl;
        r = nr;
    }
    return (((uint32_t)l << 16) | (uint32_t)r)
        ^ cprisk_vmp_avalanche32_i(key ^ salt ^ 0xACC0DECu);
}

static uint32_t cprisk_vmp_vpc_feistel32_decode_i(uint32_t encoded_state, uint32_t key, uint32_t salt) {
    uint32_t mid = encoded_state ^ cprisk_vmp_avalanche32_i(key ^ salt ^ 0xACC0DECu);
    uint16_t l = (uint16_t)(mid >> 16);
    uint16_t r = (uint16_t)(mid & 0xFFFFu);
    for (uint32_t round = CPRISK_VMP_VPC_FEISTEL_ROUNDS; round > 0u; round--) {
        const uint32_t idx = round - 1u;
        const uint16_t pr = l;
        const uint16_t pl = (uint16_t)(r ^ cprisk_vmp_vpc_feistel_F_i(l, key, salt, idx));
        l = pl;
        r = pr;
    }
    return (((uint32_t)l << 16) | (uint32_t)r)
        ^ cprisk_vmp_avalanche32_i(key ^ salt ^ 0xF1055A1u);
}

static uint32_t cprisk_vmp_vpc_tag32_i(uint32_t encoded_pc32, uint32_t key, uint32_t salt) {
    return cprisk_vmp_avalanche32_i(
        encoded_pc32 ^
        cprisk_vmp_rotl32_i(key, 5u) ^
        cprisk_vmp_rotr32_i(salt, 3u) ^
        0xD00DFEEDu
    );
}

static uint64_t cprisk_vmp_nonlinear_encode_pc_i(uint32_t pc, uint64_t a, uint64_t b) {
    const uint32_t session = cprisk_vm_session_mix_i();
    const uint32_t key = cprisk_vmp_vpc_key32_i(a, b) ^ session;
    const uint32_t salt = cprisk_vmp_vpc_salt32_i(a, b) ^ cprisk_vmp_rotl32_i(session, 9u);
    const uint32_t enc32 = cprisk_vmp_vpc_feistel32_encode_i(pc, key, salt);
    const uint32_t tag32 = cprisk_vmp_vpc_tag32_i(enc32, key, salt);
    return ((uint64_t)tag32 << 32u) | (uint64_t)enc32;
}

static int cprisk_vmp_nonlinear_decode_pc_i(uint64_t encoded_pc,
                                            uint64_t a,
                                            uint64_t b,
                                            uint32_t *out_pc) {
    if (!out_pc) {
        return 0;
    }
    const uint32_t session = cprisk_vm_session_mix_i();
    const uint32_t key = cprisk_vmp_vpc_key32_i(a, b) ^ session;
    const uint32_t salt = cprisk_vmp_vpc_salt32_i(a, b) ^ cprisk_vmp_rotl32_i(session, 9u);
    const uint32_t enc32 = (uint32_t)encoded_pc;
    const uint32_t tag32 = (uint32_t)(encoded_pc >> 32u);
    if (tag32 != cprisk_vmp_vpc_tag32_i(enc32, key, salt)) {
        return 0;
    }
    *out_pc = cprisk_vmp_vpc_feistel32_decode_i(enc32, key, salt);
    return 1;
}

int cprisk_vm_encode_pc_i(const cprisk_vmp_bytecode_header_t *bh,
                                 uint32_t pc,
                                 uint64_t vpc_a,
                                 uint64_t vpc_b,
                                 uint64_t *out_enc,
                                 cprisk_vm_run_result_t *out) {
    if (!out_enc) {
        return 0;
    }
    if (cprisk_vmp_vpc_is_nonlinear_i(bh)) {
        *out_enc = cprisk_vmp_nonlinear_encode_pc_i(pc, vpc_a, vpc_b);
        return 1;
    }
    uint64_t scaled = 0u;
    if (__builtin_mul_overflow((uint64_t)pc, vpc_a, &scaled) ||
        __builtin_add_overflow(scaled, vpc_b, &scaled)) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    *out_enc = scaled;
    return 1;
}

static int cprisk_vm_decode_pc_i(const cprisk_vmp_bytecode_header_t *bh,
                                 uint64_t encoded_pc,
                                 uint64_t vpc_a,
                                 uint64_t vpc_b,
                                 uint32_t *out_pc,
                                 cprisk_vm_run_result_t *out) {
    if (!out_pc) {
        return 0;
    }
    if (cprisk_vmp_vpc_is_nonlinear_i(bh)) {
        if (!cprisk_vmp_nonlinear_decode_pc_i(encoded_pc, vpc_a, vpc_b, out_pc)) {
            if (out) {
                out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
                out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            }
            return 0;
        }
        return 1;
    }
    if (encoded_pc < vpc_b) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    const uint64_t numer = encoded_pc - vpc_b;
    if (vpc_a == 0u || numer % vpc_a != 0u) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    const uint64_t pc64 = numer / vpc_a;
    if (pc64 > (uint64_t)UINT32_MAX) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    *out_pc = (uint32_t)pc64;
    return 1;
}

static atomic_uint_fast32_t s_vm_session_mix_i = 0;

static uint32_t cprisk_vm_session_mix_i(void) {
    uint32_t cached = (uint32_t)atomic_load(&s_vm_session_mix_i);
    if (cached != 0u) {
        return cached;
    }

    uint32_t mix = 0xA5C31F27u;
#if defined(__APPLE__)
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        mix ^= (uint32_t)now.tv_nsec;
        mix ^= (uint32_t)now.tv_sec * 0x9E3779B9u;
    }
    mix ^= (uint32_t)getpid() * 0x45D9F3Bu;
#endif

    uint8_t session_key[CPRISK_ARMOR_KEY_SIZE];
    if (cprisk_get_session_key(session_key) == 0) {
        mix ^= cprisk_read_le_u32_i(session_key);
        mix ^= cprisk_read_le_u32_i(session_key + 12u);
        mix ^= cprisk_read_le_u32_i(session_key + 24u);
        cprisk_secure_zero(session_key, sizeof(session_key));
    }

    if (cprisk_runtime_material_ready() != 0) {
        uint8_t runtime_material[CPRISK_ARMOR_KEY_SIZE];
        if (cprisk_get_runtime_material(runtime_material) == 0) {
            mix ^= cprisk_read_le_u32_i(runtime_material + 4u);
            mix ^= cprisk_read_le_u32_i(runtime_material + 20u);
            cprisk_secure_zero(runtime_material, sizeof(runtime_material));
        }
    }

    mix = cprisk_vmp_avalanche32_i(mix ^ 0x6D2B79F5u);
    if (mix == 0u) {
        mix = 0x6D2B79F5u;
    }
    atomic_store(&s_vm_session_mix_i, mix);
    return mix;
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
    mix ^= cprisk_vm_session_mix_i();
    return mix & 3u;
}

/** 32-way semantic lane selector (seed/pc/func/handler — all reachable switch arms). */
static uint32_t cprisk_vm_lane_poly32_i(uint32_t pc,
                                       uint64_t func_id,
                                       uint64_t steps,
                                       uint32_t hvar,
                                       uint32_t semantic_family) {
    uint32_t x = (uint32_t)pc ^ (uint32_t)func_id ^ (uint32_t)(func_id >> 32u);
    x ^= (uint32_t)steps ^ (uint32_t)(steps >> 32u);
    x ^= hvar * 0x9E37u;
    x ^= (semantic_family & 0xFu) * 0xC2B2u;
    x ^= cprisk_vm_session_mix_i() ^ (cprisk_vm_session_mix_i() >> 11);
    return x % 32u;
}

/** Extra no-op staging (semantic identity) before poly 16–31 paths — harder trace slicing vs poly 0–15. */
static void cprisk_vm_lane_poly_staging_i(uint8_t acc[32],
                                           uint32_t steps,
                                           uint32_t poly,
                                           uint32_t semantic_family,
                                           uint64_t func_id) {
    volatile uint32_t tag = cprisk_vmp_avalanche32_i(
        poly ^ semantic_family ^ (uint32_t)steps ^ (uint32_t)func_id ^ 0xFAC3E7A2u
    );
    for (uint32_t z = 0u; z < 12u; z++) {
        uint32_t ix = (z * 5u + (tag & 7u) + semantic_family + (uint32_t)(func_id & 7u)) & 31u;
        volatile uint8_t vv = acc[ix];
        uint8_t id = (uint8_t)(vv ^ (uint8_t)(((uint32_t)vv * 2u - (uint32_t)vv - (uint32_t)vv) & 0xFFu));
        acc[ix] = id;
    }
}

int cprisk_vm_entry_profile_decode_i(uint32_t entry_reserved,
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

void cprisk_vm_entry_profile_fallback_i(uint64_t func_id,
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

/** lane_family: 0 = ADD polymorphic, 1 = SUB (wrapping), 2 = MUL mod 256. */
static uint8_t cprisk_vm_lane_combine_i(uint8_t lhs, uint8_t rhs, uint32_t style, uint32_t lane_family) {
    if (lane_family == 1u)
        return (uint8_t)(lhs - rhs);
    if (lane_family == 2u)
        return (uint8_t)(lhs * rhs);
    return cprisk_vm_add_equiv_i(lhs, rhs, style);
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
        return (uint8_t)(L ^ R);
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

void cprisk_vm_raw_region_apply_i(uint8_t acc[32],
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

    uint32_t poly = cprisk_vm_lane_poly32_i(pc, func_id, steps, variant, semantic_family);
    if (poly >= 16u)
        cprisk_vm_lane_poly_staging_i(acc, steps, poly, semantic_family, func_id);
    poly &= 15u;
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

int cprisk_vm_enc_pc_advance_ctx_i(const cprisk_vmp_bytecode_header_t *bh,
                                          uint64_t *enc_pc,
                                          uint64_t vpc_a,
                                          uint64_t vpc_b,
                                          cprisk_vm_run_result_t *out) {
    uint32_t pc = 0u;
    if (!enc_pc || !cprisk_vm_decode_pc_i(bh, *enc_pc, vpc_a, vpc_b, &pc, out)) {
        return 0;
    }
    if ((uint64_t)pc + CPRISK_VM_INSN_WIDTH > (uint64_t)UINT32_MAX) {
        if (out) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        }
        return 0;
    }
    return cprisk_vm_encode_pc_i(
        bh,
        pc + CPRISK_VM_INSN_WIDTH,
        vpc_a,
        vpc_b,
        enc_pc,
        out
    );
}

static void cprisk_vm_lane_family_apply_i(uint8_t acc[32],
                                          uint64_t imm,
                                          uint32_t steps,
                                          uint32_t variant,
                                          uint32_t semantic_family,
                                          uint64_t func_id,
                                          uint32_t pc,
                                          uint32_t lane_family) {
    uint8_t lanes[8];
    uint8_t idxs[8];
    uint8_t snapshot[8];
    const uint32_t base = (uint32_t)(steps & 0x0Fu);
    for (uint32_t i = 0; i < 8u; i++) {
        lanes[i] = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        idxs[i] = (uint8_t)((i + base) & 31u);
    }

    uint32_t poly = cprisk_vm_lane_poly32_i(pc, func_id, steps, variant, semantic_family);
    if (poly >= 16u)
        cprisk_vm_lane_poly_staging_i(acc, steps, poly, semantic_family, func_id);
    poly &= 15u;
    switch (poly) {
    case 0u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = semantic_family + i;
            acc[idxs[i]] = cprisk_vm_lane_combine_i(acc[idxs[i]], lanes[i], style, lane_family);
        }
        break;
    case 1u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (int i = 7; i >= 0; i--) {
            uint32_t u = (uint32_t)i;
            uint32_t style = variant + semantic_family + u;
            acc[idxs[u]] = cprisk_vm_lane_combine_i(snapshot[u], lanes[u], style, lane_family);
        }
        break;
    case 2u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 5u + variant + semantic_family) & 7u;
            uint32_t style = variant ^ semantic_family ^ i;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    case 3u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = (i * 5u) ^ (uint32_t)(pc & 0x1Fu);
            acc[idxs[i]] = cprisk_vm_lane_combine_i(acc[idxs[i]], lanes[i], style, lane_family);
        }
        break;
    case 4u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = semantic_family + (i ^ 3u);
            acc[idxs[i]] = cprisk_vm_lane_combine_i(acc[idxs[i]], lanes[i], style, lane_family);
        }
        break;
    case 5u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (uint32_t u = 0; u < 8u; u++) {
            uint32_t style = (uint32_t)steps + u * 3u;
            acc[idxs[u]] = cprisk_vm_lane_combine_i(snapshot[u], lanes[u], style, lane_family);
        }
        break;
    case 6u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 3u + variant * 2u) & 7u;
            uint32_t style = semantic_family + i * 5u;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    case 7u:
        for (int i = 0; i < 8; i += 2) {
            uint32_t style = (uint32_t)i + variant;
            acc[idxs[(uint32_t)i]] = cprisk_vm_lane_combine_i(acc[idxs[(uint32_t)i]], lanes[(uint32_t)i], style, lane_family);
        }
        for (int i = 1; i < 8; i += 2) {
            uint32_t style = (uint32_t)i + semantic_family;
            acc[idxs[(uint32_t)i]] = cprisk_vm_lane_combine_i(acc[idxs[(uint32_t)i]], lanes[(uint32_t)i], style, lane_family);
        }
        break;
    case 8u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t j = (7u - i);
            uint32_t style = variant + j * 13u;
            acc[idxs[j]] = cprisk_vm_lane_combine_i(acc[idxs[j]], lanes[j], style, lane_family);
        }
        break;
    case 9u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 11u + (uint32_t)(func_id & 7u)) & 7u;
            uint32_t style = (uint32_t)func_id + t + semantic_family;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    case 10u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (uint32_t u = 0; u < 8u; u++) {
            uint32_t k = (u ^ 3u) & 7u;
            uint32_t style = variant ^ u ^ k;
            acc[idxs[k]] = cprisk_vm_lane_combine_i(snapshot[k], lanes[k], style, lane_family);
        }
        break;
    case 11u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t ^ (semantic_family & 7u)) & 7u;
            uint32_t style = (uint32_t)(func_id >> 8) ^ t;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    case 12u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint32_t style = pc + i * 7u;
            acc[idxs[i]] = cprisk_vm_lane_combine_i(acc[idxs[i]], lanes[i], style, lane_family);
        }
        break;
    case 13u:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t * 2u + 3u) & 7u;
            uint32_t style = variant + t + (uint32_t)(pc & 5u);
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    case 14u:
        for (uint32_t i = 0; i < 8u; i++)
            snapshot[i] = acc[idxs[i]];
        for (int i = 7; i >= 0; i--) {
            uint32_t u = (uint32_t)i;
            uint32_t style = (semantic_family * 3u) + u ^ variant;
            acc[idxs[u]] = cprisk_vm_lane_combine_i(snapshot[u], lanes[u], style, lane_family);
        }
        break;
    default:
        for (uint32_t t = 0; t < 8u; t++) {
            uint32_t i = (t + variant) & 7u;
            uint32_t style = semantic_family + (uint32_t)(func_id & 0xFFu) + t;
            uint8_t cur = acc[idxs[i]];
            acc[idxs[i]] = cprisk_vm_lane_combine_i(cur, lanes[i], style, lane_family);
        }
        break;
    }
}

void cprisk_vm_add_apply_i(uint8_t acc[32],
                                  uint64_t imm,
                                  uint32_t steps,
                                  uint32_t variant,
                                  uint32_t semantic_family,
                                  uint64_t func_id,
                                  uint32_t pc) {
    cprisk_vm_lane_family_apply_i(acc, imm, steps, variant, semantic_family, func_id, pc, 0u);
}

static void cprisk_vm_sub_apply_i(uint8_t acc[32],
                                  uint64_t imm,
                                  uint32_t steps,
                                  uint32_t variant,
                                  uint32_t semantic_family,
                                  uint64_t func_id,
                                  uint32_t pc) {
    cprisk_vm_lane_family_apply_i(acc, imm, steps, variant, semantic_family, func_id, pc, 1u);
}

static void cprisk_vm_mul_apply_i(uint8_t acc[32],
                                  uint64_t imm,
                                  uint32_t steps,
                                  uint32_t variant,
                                  uint32_t semantic_family,
                                  uint64_t func_id,
                                  uint32_t pc) {
    cprisk_vm_lane_family_apply_i(acc, imm, steps, variant, semantic_family, func_id, pc, 2u);
}

typedef void (*cprisk_vm_lane_apply_fp_i)(uint8_t acc[32],
                                          uint64_t imm,
                                          uint32_t steps,
                                          uint32_t variant,
                                          uint32_t semantic_family,
                                          uint64_t func_id,
                                          uint32_t pc);

static uint64_t cprisk_vm_imm_neg_bytes_u64_i(uint64_t imm) {
    uint64_t out = 0u;
    for (unsigned i = 0u; i < 8u; i++) {
        uint8_t lb = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        out |= (uint64_t)(uint8_t)(0u - lb) << (i * 8u);
    }
    return out;
}

void cprisk_vm_lane_apply_poly_i(uint8_t acc[32],
                                        uint32_t family,
                                        uint64_t imm,
                                        uint32_t steps,
                                        uint32_t variant,
                                        uint32_t semantic_family,
                                        uint64_t func_id,
                                        uint32_t pc,
                                        uint32_t route) {
    static const cprisk_vm_lane_apply_fp_i s_lane_handlers[3] = {
        cprisk_vm_add_apply_i,
        cprisk_vm_sub_apply_i,
        cprisk_vm_mul_apply_i,
    };
    if (family > 2u)
        return;
    /*
     * Branch-level polymorphism (semantic family 0/1): alternate decomposition
     * a+b ≡ a-(-b), a-b ≡ a+(-b) per byte lane (uint8 wrap).
     */
    if (family == 0u && (route & 8u) != 0u) {
        const uint64_t imm_neg = cprisk_vm_imm_neg_bytes_u64_i(imm);
        cprisk_vm_lane_family_apply_i(
            acc, imm_neg, steps, variant, semantic_family, func_id, pc, 1u);
        return;
    }
    if (family == 1u && (route & 8u) != 0u) {
        const uint64_t imm_neg = cprisk_vm_imm_neg_bytes_u64_i(imm);
        cprisk_vm_lane_family_apply_i(
            acc, imm_neg, steps, variant, semantic_family, func_id, pc, 0u);
        return;
    }
    if ((route & 1u) != 0u) {
        s_lane_handlers[family](acc, imm, steps, variant, semantic_family, func_id, pc);
        return;
    }

    uint64_t imm_shadow = imm;
    uint32_t variant_shadow = variant;
    if ((route & 2u) != 0u) {
        const uint32_t salt = cprisk_vmp_avalanche32_i(
            (uint32_t)func_id ^ (uint32_t)(func_id >> 32u) ^ steps ^ route ^ family
        );
        imm_shadow = (imm ^ (uint64_t)salt) ^ (uint64_t)salt;
        variant_shadow = variant ^ (salt & 3u) ^ (salt & 3u);
    }
    cprisk_vm_lane_family_apply_i(
        acc,
        imm_shadow,
        steps,
        variant_shadow,
        semantic_family,
        func_id,
        pc,
        family
    );
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

void cprisk_vm_bitwise_lane_poly_i(uint8_t acc[32],
                                          uint32_t logical,
                                          uint64_t imm,
                                          uint32_t steps,
                                          uint32_t variant,
                                          uint32_t semantic_family,
                                          uint32_t route) {
    if ((route & 1u) != 0u) {
        if (logical == CPRISK_VM_OP_OR_LANE)
            cprisk_vm_bitwise_lane_or_i(acc, imm, steps, variant, semantic_family);
        else
            cprisk_vm_bitwise_lane_and_i(acc, imm, steps, variant, semantic_family);
        return;
    }

    uint8_t lanes[8];
    uint8_t idxs[8];
    const uint32_t base =
        logical == CPRISK_VM_OP_OR_LANE ? (uint32_t)(steps & 0x0Fu) : (uint32_t)((steps + 3u) & 0x0Fu);
    for (uint32_t i = 0u; i < 8u; i++) {
        lanes[i] = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
        idxs[i] = (uint8_t)((i + base + ((logical == CPRISK_VM_OP_OR_LANE) ? (variant & 3u) : 0u)) & 31u);
    }
    for (int32_t i = 7; i >= 0; i--) {
        if (logical == CPRISK_VM_OP_OR_LANE)
            acc[idxs[(uint32_t)i]] = (uint8_t)(acc[idxs[(uint32_t)i]] | lanes[(uint32_t)i]);
        else
            acc[idxs[(uint32_t)i]] = (uint8_t)(acc[idxs[(uint32_t)i]] & lanes[(uint32_t)i]);
    }
}

void cprisk_vm_rol_acc_i(uint8_t acc[32], uint64_t imm) {
    unsigned rot = (unsigned)(imm & 31u);
    uint8_t t[32];
    memcpy(t, acc, sizeof(t));
    for (unsigned i = 0; i < 32u; i++)
        acc[i] = t[(i + rot) % 32u];
}

/** Immediate: dst[2:0], src[5:3], mode[7:6] — 0=rr mov, 1=imm56@(>>8), 2=load 8B from acc[@(>>8)&31]. */
void cprisk_vm_vreg_mov_i(uint64_t vregs[8], const uint8_t acc[32], uint64_t imm) {
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
void cprisk_vm_vreg_alu_i(uint64_t vregs[8], uint64_t imm) {
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
void cprisk_vm_vreg_mem_i(uint64_t vregs[8], uint8_t acc[32], uint64_t imm) {
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

int cprisk_vm_branch_cond_mixed_eval_i(uint32_t insn,
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

int cprisk_vm_set_branch_target_ctx_i(const cprisk_vmp_bytecode_header_t *bh,
                                             uint64_t *enc_pc,
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
    uint64_t target_u = (uint64_t)target;
    return cprisk_vm_encode_pc_i(bh, (uint32_t)target_u, vpc_a, vpc_b, enc_pc, out);
}

#define cprisk_vm_enc_pc_advance_i(enc_pc, vpc_a, out) \
    cprisk_vm_enc_pc_advance_ctx_i(fr->bh, enc_pc, vpc_a, fr->vpc_b, out)

#define cprisk_vm_set_branch_target_i(enc_pc, vpc_a, vpc_b, blen, pc, delta_bytes, out) \
    cprisk_vm_set_branch_target_ctx_i(fr->bh, enc_pc, vpc_a, vpc_b, blen, pc, delta_bytes, out)

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

void cprisk_vm_poison_mix_unknown_i(uint8_t acc[32], uint32_t opcode, uint32_t cls) {
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

static uint32_t cprisk_vm_m3_fnv1a_continue_i(uint32_t h, const volatile uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        h ^= (uint32_t)p[i];
        h *= 16777619u;
    }
    return h;
}

#if CPRISK_VM_M3_SELF_INCLUDE_LOOP
#if CPRISK_VM_M3_SELF_EXEC_BYTES + CPRISK_VM_M3_SELF_LOOP_BYTES + CPRISK_VM_M3_SELF_DISPATCH_BYTES \
    != CPRISK_VM_M3_SELF_BYTES
#error "CPRISK_VM_M3_SELF_EXEC_BYTES + CPRISK_VM_M3_SELF_LOOP_BYTES + CPRISK_VM_M3_SELF_DISPATCH_BYTES must equal CPRISK_VM_M3_SELF_BYTES"
#endif
#endif

void cprisk_vm_interp_loop_a(struct cprisk_vm_interp_frame *fr);
uint8_t cprisk_vm_dispatch_lookup(struct cprisk_vm_interp_frame *fr, uint32_t op, uint32_t pc_index);

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
    uint32_t reserved;
} cprisk_vm_selfchk_span_header_t;

typedef struct {
    uint64_t vmaddr;
    uint32_t length;
    uint32_t kind;
} cprisk_vm_selfchk_span_entry_t;

#if defined(__APPLE__)
#define CPRISK_VM_SELFCHK_SPAN_SECTION_ATTR "__DATA," CPRISK_ARMOR_SECTION_VMP_SELF_SPANS
__attribute__((used, section(CPRISK_VM_SELFCHK_SPAN_SECTION_ATTR)))
#endif
static const struct {
    cprisk_vm_selfchk_span_header_t header;
    cprisk_vm_selfchk_span_entry_t entries[3];
} cprisk_vm_selfchk_spans_i = {
    {
        CPRISK_VMP_SELF_SPAN_MAGIC,
        CPRISK_VMP_SELF_SPAN_VERSION,
        3u,
        0u,
    },
    {
        { (uint64_t)(uintptr_t)(const void *)&cprisk_vm_execute,
          (uint32_t)CPRISK_VM_M3_SELF_EXEC_BYTES,
          CPRISK_VMP_SELF_SPAN_KIND_EXEC },
        { (uint64_t)(uintptr_t)(const void *)&cprisk_vm_interp_loop_a,
          (uint32_t)CPRISK_VM_M3_SELF_LOOP_BYTES,
          CPRISK_VMP_SELF_SPAN_KIND_LOOP_A },
        { (uint64_t)(uintptr_t)(const void *)&cprisk_vm_dispatch_lookup,
          (uint32_t)CPRISK_VM_M3_SELF_DISPATCH_BYTES,
          CPRISK_VMP_SELF_SPAN_KIND_DISPATCH },
    },
};

_Static_assert(sizeof(cprisk_vm_selfchk_spans_i) == 64u, "CPSV (__swift5_mdvsi) blob size must match ABI");

static int cprisk_vm_selfchk_span_layout_resolve_i(const struct mach_header_64 *mh,
                                                   const cprisk_vm_selfchk_span_entry_t **out_entries,
                                                   uint32_t *out_count,
                                                   size_t *out_total_bytes) {
    if (out_entries)
        *out_entries = NULL;
    if (out_count)
        *out_count = 0u;
    if (out_total_bytes)
        *out_total_bytes = 0u;
    if (!mh || !out_entries || !out_count)
        return 0;

    unsigned long sz = 0;
    const uint8_t *sec =
        cprisk_find_section(mh, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_SELF_SPANS, &sz);
    if (!sec || sz < sizeof(cprisk_vm_selfchk_span_header_t))
        return 0;

    const cprisk_vm_selfchk_span_header_t *header =
        (const cprisk_vm_selfchk_span_header_t *)(const void *)sec;
    if (header->magic != CPRISK_VMP_SELF_SPAN_MAGIC ||
        header->version != CPRISK_VMP_SELF_SPAN_VERSION ||
        header->count == 0u) {
        return 0;
    }
    if (header->count != 3u)
        return 0;

    size_t need = sizeof(cprisk_vm_selfchk_span_header_t)
        + (size_t)header->count * sizeof(cprisk_vm_selfchk_span_entry_t);
    if (need > (size_t)sz)
        return 0;

    const cprisk_vm_selfchk_span_entry_t *entries =
        (const cprisk_vm_selfchk_span_entry_t *)(const void *)(sec + sizeof(*header));
    size_t total = 0u;
    for (uint32_t i = 0u; i < header->count; i++) {
        if (entries[i].vmaddr == 0u || entries[i].length == 0u)
            return 0;
        total += (size_t)entries[i].length;
    }

    *out_entries = entries;
    *out_count = header->count;
    if (out_total_bytes)
        *out_total_bytes = total;
    return 1;
}

#if defined(__APPLE__)
/**
 * If `__swift5_mdvsi` is present, it must match the compile-time CPSV blob (tamper / drift detection).
 * Absent section: OK (legacy layout path).
 */
static int cprisk_vm_m3_selfchk_cpsv_image_matches_static_i(const struct mach_header_64 *mh) {
    unsigned long sz = 0;
    const uint8_t *p =
        cprisk_find_section(mh, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_VMP_SELF_SPANS, &sz);
    if (!p)
        return 0;
    if (sz != sizeof(cprisk_vm_selfchk_spans_i))
        return -1;
    return memcmp(p, &cprisk_vm_selfchk_spans_i, sizeof(cprisk_vm_selfchk_spans_i)) != 0 ? -1 : 0;
}
#endif

static void cprisk_vm_selfchk_legacy_collect_msg_i(uint8_t msg[CPRISK_VM_M3_SELF_BYTES]) {
#if CPRISK_VM_M3_SELF_INCLUDE_LOOP
    memcpy(msg, (const void *)&cprisk_vm_execute, (size_t)CPRISK_VM_M3_SELF_EXEC_BYTES);
    memcpy(msg + CPRISK_VM_M3_SELF_EXEC_BYTES,
           (const void *)&cprisk_vm_interp_loop_a,
           (size_t)CPRISK_VM_M3_SELF_LOOP_BYTES);
    memcpy(
        msg + CPRISK_VM_M3_SELF_EXEC_BYTES + CPRISK_VM_M3_SELF_LOOP_BYTES,
        (const void *)&cprisk_vm_dispatch_lookup,
        (size_t)CPRISK_VM_M3_SELF_DISPATCH_BYTES
    );
#else
    memcpy(msg, (const void *)&cprisk_vm_execute, (size_t)CPRISK_VM_M3_SELF_BYTES);
#endif
}

static void cprisk_vm_selfchk_collect_msg_i(const struct mach_header_64 *hdr,
                                            uint8_t msg[CPRISK_VM_M3_SELF_BYTES]) {
    const cprisk_vm_selfchk_span_entry_t *entries = NULL;
    uint32_t count = 0u;
    size_t total = 0u;
    if (cprisk_vm_selfchk_span_layout_resolve_i(hdr, &entries, &count, &total)
        && total == (size_t)CPRISK_VM_M3_SELF_BYTES) {
        size_t offset = 0u;
        for (uint32_t i = 0u; i < count; i++) {
            size_t len = (size_t)entries[i].length;
            memcpy(msg + offset, (const void *)(uintptr_t)entries[i].vmaddr, len);
            offset += len;
        }
        return;
    }
    cprisk_vm_selfchk_legacy_collect_msg_i(msg);
}

static uint32_t cprisk_vm_selfchk_observed_fnv_i(const struct mach_header_64 *hdr) {
    const cprisk_vm_selfchk_span_entry_t *entries = NULL;
    uint32_t count = 0u;
    size_t total = 0u;
    if (cprisk_vm_selfchk_span_layout_resolve_i(hdr, &entries, &count, &total)
        && total == (size_t)CPRISK_VM_M3_SELF_BYTES) {
        uint32_t fnv = 2166136261u;
        for (uint32_t i = 0u; i < count; i++) {
            fnv = cprisk_vm_m3_fnv1a_continue_i(
                fnv,
                (const volatile uint8_t *)(const void *)(uintptr_t)entries[i].vmaddr,
                (size_t)entries[i].length
            );
        }
        return fnv;
    }
#if CPRISK_VM_M3_SELF_INCLUDE_LOOP
    uint32_t fnv = 2166136261u;
    fnv = cprisk_vm_m3_fnv1a_continue_i(
        fnv,
        (const volatile uint8_t *)(const void *)&cprisk_vm_execute,
        (size_t)CPRISK_VM_M3_SELF_EXEC_BYTES
    );
    fnv = cprisk_vm_m3_fnv1a_continue_i(
        fnv,
        (const volatile uint8_t *)(const void *)&cprisk_vm_interp_loop_a,
        (size_t)CPRISK_VM_M3_SELF_LOOP_BYTES
    );
    fnv = cprisk_vm_m3_fnv1a_continue_i(
        fnv,
        (const volatile uint8_t *)(const void *)&cprisk_vm_dispatch_lookup,
        (size_t)CPRISK_VM_M3_SELF_DISPATCH_BYTES
    );
    return fnv;
#else
    return cprisk_vm_m3_fnv1a_bytes_i(
        (const volatile uint8_t *)(const void *)&cprisk_vm_execute,
        (size_t)CPRISK_VM_M3_SELF_BYTES
    );
#endif
}

static uint64_t cprisk_vm_m3_seal_mix_from_digest_u32_i(uint32_t d) {
    uint64_t x = (uint64_t)d ^ ((uint64_t)d << 32);
    x ^= 0xC6A4A7935BD1E995ULL;
    x = cprisk_splitmix64_next_i(&x);
    x ^= cprisk_splitmix64_next_i(&x);
    if (x == 0u)
        x = 0xA5A5A5A5CAFEBABEULL;
    return x;
}

/**
 * Bait handlers: wrong VM semantics, only referenced from provably-dead branches.
 * Kept out-of-line so the CFG shows distinct "handler" targets under disassembly.
 */
__attribute__((noinline)) static void cprisk_vm_m3_dead_bait_xor_i(uint8_t acc[32], uint32_t seed, uint32_t lane) {
    uint32_t x = (seed * 0x9E3779B9u) ^ (lane * 0x85EBCA6Bu);
    uint8_t scratch[32];
    for (unsigned i = 0; i < 32u; i++) {
        x = cprisk_vmp_avalanche32_i(x ^ (uint32_t)i ^ 0xA53C1F27u);
        scratch[(i * 5u) & 31u] = (uint8_t)(acc[i] ^ (uint8_t)x);
        acc[i] ^= (uint8_t)(x >> (i & 7u));
        acc[i] ^= scratch[(i * 5u) & 31u];
    }
}

__attribute__((noinline)) static void cprisk_vm_m3_dead_bait_add_i(uint8_t acc[32], uint32_t seed, uint32_t lane) {
    uint32_t x = seed + lane * 0x27d4eb2du;
    uint8_t scratch[16];
    for (unsigned i = 0; i < 32u; i++) {
        x = cprisk_vmp_avalanche32_i(x + i * 0x9E3779B9u);
        scratch[i & 15u] ^= (uint8_t)(x >> ((i & 3u) * 8u));
        acc[i] = (uint8_t)(acc[i] + (uint8_t)(x + i) + scratch[i & 15u]);
    }
}

__attribute__((noinline)) static void cprisk_vm_m3_dead_bait_roll_i(uint8_t acc[32], uint32_t seed) {
    unsigned rot = (unsigned)(seed & 31u);
    uint8_t t[32];
    memcpy(t, acc, sizeof(t));
    for (unsigned i = 0; i < 32u; i++) {
        const uint8_t lhs = t[(i + rot) & 31u];
        const uint8_t rhs = t[(i * 7u + rot) & 31u];
        acc[i] = (uint8_t)(lhs ^ cprisk_vm_add_byte_bitwise_i(rhs, (uint8_t)(seed + i)));
    }
}

__attribute__((noinline)) static void cprisk_vm_m3_dead_heavy_shadow_i(uint8_t acc[32], uint32_t seed) {
    uint8_t save[32];
    memcpy(save, acc, sizeof(save));
    uint64_t lane[4];
    memcpy(lane, acc, sizeof(lane));
    for (unsigned j = 0; j < 4u; j++)
        lane[j] ^= (uint64_t)(seed + j * 0x9E3779B9u) * UINT64_C(0xD6E8FEB783278F6B);
    for (unsigned r = 0; r < 4u; r++) {
        for (unsigned i = 0; i < 32u; i++) {
            uint32_t ix = (i + r * 7u + (seed & 0xFFu)) & 31u;
            acc[ix] ^= (uint8_t)((lane[(i / 8u) & 3u] >> ((i % 8u) * 8u)) & 0xFFu);
        }
        lane[0] ^= lane[3] ^ ((uint64_t)seed << (17u + (r & 3u)));
        lane[1] = (lane[1] << 13) | (lane[1] >> 51);
        lane[2] ^= (uint64_t)acc[(seed + r * 3u) & 31u] * UINT64_C(0x100000001B3);
    }
    memcpy(acc, save, sizeof(save));
}

/**
 * Decoys in read-only const data: resemble handler RVA / stream-XOR / class tags.
 * Values are not executable pointers; XOR-mixed into opaque predicates only.
 */
static const struct {
    uint64_t faux_text_rva;
    uint64_t stream_xor;
    uint32_t class_tag;
    uint32_t pad;
} cprisk_vmp_relro_handler_decoy[] = {
    { UINT64_C(0x1F0E1D2C3B4A5968), UINT64_C(0xEEDDAABBCCDD0011), 0x4856484Bu, 0u },
    { UINT64_C(0x2E3D4C5B6A7988A7), UINT64_C(0xFF10FFEEDDCCBBAA), 0x4D455441u, 0u },
    { UINT64_C(0x4030201080706050), UINT64_C(0xBADCAFE00B01E0E1), 0x4445434Fu, 0u },
    { UINT64_C(0xF0E1D2C3B4A59687), UINT64_C(0x1122334455667788), 0x42415432u, 0u },
};

static uint32_t cprisk_vmp_relro_bait_mix_i(void) {
    uint32_t acc = 0u;
    for (unsigned i = 0u; i < 4u; i++) {
        const uint64_t sx = cprisk_vmp_relro_handler_decoy[i].stream_xor;
        uint32_t lo = (uint32_t)sx;
        uint32_t hi = (uint32_t)(sx >> 32);
        uint64_t w = cprisk_vmp_relro_handler_decoy[i].faux_text_rva
            ^ ((uint64_t)cprisk_vmp_rotl32_i(lo, 8) | ((uint64_t)cprisk_vmp_rotr32_i(hi, 9) << 32));
        acc ^= cprisk_vmp_avalanche32_i((uint32_t)w ^ cprisk_vmp_relro_handler_decoy[i].class_tag ^ (unsigned)i * 0x9E37u);
    }
    return acc;
}

static void cprisk_vm_m3_dead_dispatch_i(uint8_t acc[32], uint32_t hdr_reserved, uint32_t opkind) {
    uint32_t dseed = (hdr_reserved >> 16) & 0xFFu;
    switch (opkind % 6u) {
    case 0u:
        cprisk_vm_m3_dead_bait_xor_i(acc, dseed, opkind);
        break;
    case 1u:
        cprisk_vm_m3_dead_bait_add_i(acc, dseed, opkind);
        break;
    case 2u:
        cprisk_vm_m3_dead_bait_roll_i(acc, dseed);
        break;
    case 3u:
        cprisk_vm_m3_dead_bait_xor_i(acc, dseed ^ 0x55u, opkind + 0x11u);
        cprisk_vm_m3_dead_bait_roll_i(acc, dseed ^ 0xA5u);
        break;
    case 4u:
        cprisk_vm_m3_dead_bait_add_i(acc, dseed ^ 0x3Cu, opkind + 0x29u);
        cprisk_vm_m3_dead_bait_xor_i(acc, dseed ^ 0xC3u, opkind + 0x41u);
        break;
    default:
        cprisk_vm_m3_dead_heavy_shadow_i(acc, dseed ^ (opkind * 0x27D4EB2Du));
        cprisk_vm_m3_dead_bait_roll_i(acc, dseed ^ 0x5Au);
        break;
    }
}

typedef struct {
    const void *target;
    uint64_t bias;
    uint32_t salt;
    uint32_t rotate;
} cprisk_vm_dispatch_bait_meta_t;

#if defined(__APPLE__)
__attribute__((used, section("__DATA_CONST,__const")))
#endif
static const cprisk_vm_dispatch_bait_meta_t cprisk_vm_dispatch_bait_meta_i[] = {
    { (const void *)&cprisk_vm_m3_dead_bait_xor_i, UINT64_C(0x6A09E667F3BCC909), 0x9E3779B9u, 5u },
    { (const void *)&cprisk_vm_m3_dead_bait_add_i, UINT64_C(0xBB67AE8584CAA73B), 0x85EBCA6Bu, 11u },
    { (const void *)&cprisk_vm_m3_dead_bait_roll_i, UINT64_C(0x3C6EF372FE94F82B), 0xC2B2AE35u, 17u },
    { (const void *)&cprisk_vm_m3_dead_heavy_shadow_i, UINT64_C(0xA54FF53A5F1D36F1), 0x27D4EB2Du, 23u },
};

static uint32_t cprisk_vm_dispatch_bait_seed_i(uint32_t lane, uint32_t logical) {
    const cprisk_vm_dispatch_bait_meta_t *meta =
        &cprisk_vm_dispatch_bait_meta_i[(lane ^ logical) & 3u];
    uint64_t x =
        ((uint64_t)(uintptr_t)meta->target ^ meta->bias) ^
        ((uint64_t)meta->salt << 32u) ^
        ((uint64_t)meta->rotate << 11u);
    x ^= x >> (meta->rotate & 31u);
    return cprisk_vmp_avalanche32_i((uint32_t)x ^ (uint32_t)(x >> 32u));
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
static void __attribute__((unused)) cprisk_vmp_dispatch_v2_keystream_i(uint64_t seed,
                                                                       uint8_t ks_out[CPRISK_VMP_CLASS_TABLE_BYTES]) {
    uint64_t state = seed ^ 0x4D4456544B455953ULL; /* "MDVTKEYS" */
    if (state == 0u)
        state = 0xDEADBEEFCAFEBABEULL;
    for (size_t i = 0; i < CPRISK_VMP_CLASS_TABLE_BYTES; i++)
        ks_out[i] = (uint8_t)cprisk_splitmix64_next_i(&state);
}

static uint64_t cprisk_vmp_dispatch_keystream_seed_i(const uint8_t *d_sec,
                                                     const cprisk_vmp_dispatch_header_t *dh) {
    if (!d_sec || !dh)
        return 0u;
    if (dh->version != CPRISK_VMP_DISPATCH_V2
        || (dh->flags & CPRISK_VMP_DH_FLAG_CLASS_TABLE_KEYSTREAM) == 0u) {
        return 0u;
    }
    return cprisk_read_le_u64_i(d_sec + sizeof(cprisk_vmp_dispatch_header_t));
}

static uint8_t cprisk_vmp_dispatch_fault_byte_i(uint64_t fault_mask,
                                                uint64_t func_id,
                                                uint32_t pc_index,
                                                uint32_t op) {
    if (fault_mask == 0u)
        return 0u;
    uint64_t state =
        fault_mask ^
        func_id ^
        ((uint64_t)pc_index << 17u) ^
        ((uint64_t)op << 33u) ^
        0x4453504641554C54ULL; /* "DSPFAULT" */
    return (uint8_t)cprisk_splitmix64_next_i(&state);
}

static uint8_t cprisk_vmp_opcode_fault_byte_i(uint64_t fault_mask,
                                              uint64_t func_id,
                                              uint32_t pc_index,
                                              uint8_t op_raw) {
    return cprisk_vmp_dispatch_fault_byte_i(
        fault_mask ^ 0x4F50434F4445464AULL, /* "OPCODEFJ" */
        func_id,
        pc_index,
        (uint32_t)op_raw
    );
}

static uint64_t cprisk_vmp_imm_fault_mask_u64_i(uint64_t fault_mask,
                                                uint64_t func_id,
                                                uint32_t pc_index) {
    if (fault_mask == 0u)
        return 0u;
    uint64_t state =
        fault_mask ^
        func_id ^
        ((uint64_t)pc_index << 23u) ^
        0x494D4D4641554C54ULL; /* "IMMFAULT" */
    return cprisk_splitmix64_next_i(&state);
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
uint64_t cprisk_vmp_raw_lane_mask_u64_i(uint64_t func_id, uint32_t pc_index, uint64_t bind_root) {
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
    /*
     * KDF: SHA256( runtime_mat || decode(label) || session_bind_8 )
     * Label bytes are XOR-mixed at rest (no plaintext "CPRISK..." in .text/.rodata).
     * session_bind_8 = first 8 bytes of session key when active, else zeros (matches
     * link-time CPSH injection with zero session).
     */
    static const uint8_t cprisk_vm_selfchk_lbl_enc[18] = {
        0x19u, 0x0au, 0x08u, 0x13u, 0x09u, 0x11u, 0x05u, 0x0cu, 0x17u, 0x05u, 0x17u, 0x69u,
        0x05u, 0x12u, 0x17u, 0x1bu, 0x19u, 0x5au,
    };
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, runtime_mat, 32u);
    for (size_t i = 0; i < sizeof(cprisk_vm_selfchk_lbl_enc); i++)
        buf[32u + i] = cprisk_vm_selfchk_lbl_enc[i] ^ 0x5Au;
    uint8_t sk[32];
    memset(sk, 0, sizeof(sk));
    if (cprisk_get_session_key(sk) == 0)
        memcpy(buf + 50u, sk, 8u);
    cprisk_secure_zero(sk, sizeof(sk));
    cprisk_sha256(buf, 32u + 18u + 8u, key_out);
    cprisk_secure_zero(buf, sizeof(buf));
}

static uint64_t cprisk_vm_selfchk_fault_mask_i(uint64_t func_id,
                                               uint32_t hdr_reserved,
                                               uint32_t expected_tag,
                                               uint32_t observed_tag) {
    uint64_t state =
        func_id ^
        ((uint64_t)hdr_reserved << 19u) ^
        ((uint64_t)expected_tag << 32u) ^
        (uint64_t)observed_tag ^
        0x53454C464641554CULL; /* "SELFFAUL" */
    if (cprisk_runtime_material_ready() != 0) {
        uint8_t runtime_material[CPRISK_ARMOR_KEY_SIZE];
        if (cprisk_get_runtime_material(runtime_material) == 0) {
            state ^= cprisk_read_le_u64_i(runtime_material + 0u);
            state ^= cprisk_read_le_u64_i(runtime_material + 16u);
            cprisk_secure_zero(runtime_material, sizeof(runtime_material));
        }
    }
    state ^= (uint64_t)cprisk_vm_session_mix_i() << 7u;
    state = cprisk_splitmix64_next_i(&state);
    if (state == 0u)
        state = 0xD9E57B1C4A62F30DULL;
    return state;
}

static void cprisk_vm_m3_selfchk_run_i(const struct mach_header_64 *hdr,
                                       uint8_t acc[32],
                                       uint64_t func_id,
                                       const cprisk_vmp_bytecode_header_t *bh,
                                       cprisk_vm_run_result_t *out,
                                       uint64_t *out_fault_mask,
                                       uint64_t *out_seal_mix) {
    const int want = (bh->reserved & CPRISK_VMP_BC_FLAG_M3_SELFCHK) != 0u;
    if (out_fault_mask)
        *out_fault_mask = 0u;
    if (out_seal_mix)
        *out_seal_mix = 0u;
    if (!want)
        return;

#if defined(__APPLE__)
    if (hdr != NULL && cprisk_vm_m3_selfchk_cpsv_image_matches_static_i(hdr) != 0) {
        out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
        cprisk_vm_self_fail_acc_i(acc, func_id);
        if (out_fault_mask)
            *out_fault_mask = cprisk_vm_selfchk_fault_mask_i(func_id, bh->reserved, 0u, 0u);
        if (out_seal_mix && out_fault_mask)
            *out_seal_mix = *out_fault_mask;
        return;
    }
#endif

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
        uint8_t msg[CPRISK_VM_M3_SELF_BYTES];
        cprisk_vm_selfchk_collect_msg_i(hdr, msg);
        cprisk_hmac_sha256(hk, 32u, msg, sizeof(msg), full);
        cprisk_secure_zero(hk, sizeof(hk));
        uint32_t tag32 = cprisk_read_le_u32_i(full);
        cprisk_secure_zero(full, sizeof(full));
        if (exp_hmac == 0u) {
#if CPRISK_VM_SELFCHK_POLICY >= 1
            out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_self_fail_acc_i(acc, func_id);
            if (out_fault_mask)
                *out_fault_mask = cprisk_vm_selfchk_fault_mask_i(func_id, bh->reserved, exp_hmac, tag32);
            if (out_seal_mix && out_fault_mask)
                *out_seal_mix = *out_fault_mask;
#endif
        } else if (tag32 != exp_hmac) {
            out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_self_fail_acc_i(acc, func_id);
            if (out_fault_mask)
                *out_fault_mask = cprisk_vm_selfchk_fault_mask_i(func_id, bh->reserved, exp_hmac, tag32);
            if (out_seal_mix && out_fault_mask)
                *out_seal_mix = *out_fault_mask;
        } else {
            if (out_seal_mix)
                *out_seal_mix = cprisk_vm_m3_seal_mix_from_digest_u32_i(tag32);
        }
        return;
    }

    if (exp_fnv == 0u) {
#if CPRISK_VM_SELFCHK_POLICY >= 1
        out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
        cprisk_vm_self_fail_acc_i(acc, func_id);
        if (out_fault_mask)
            *out_fault_mask = cprisk_vm_selfchk_fault_mask_i(func_id, bh->reserved, exp_fnv, 0u);
        if (out_seal_mix && out_fault_mask)
            *out_seal_mix = *out_fault_mask;
#else
        /* Legacy: flag without golden/section → no-op (pipelines may opt into policy >= 1). */
#endif
    } else {
        uint32_t fnv = cprisk_vm_selfchk_observed_fnv_i(hdr);
        if (fnv != exp_fnv) {
            out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
            cprisk_vm_self_fail_acc_i(acc, func_id);
            if (out_fault_mask)
                *out_fault_mask = cprisk_vm_selfchk_fault_mask_i(func_id, bh->reserved, exp_fnv, fnv);
            if (out_seal_mix && out_fault_mask)
                *out_seal_mix = *out_fault_mask;
        } else {
            if (out_seal_mix)
                *out_seal_mix = cprisk_vm_m3_seal_mix_from_digest_u32_i(fnv);
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

static void cprisk_vm_trace_sidefx_i(cprisk_vm_interp_frame_t *fr,
                                     uint32_t logical,
                                     uint64_t imm,
                                     uint32_t pc,
                                     uint32_t hvar) {
    if (!fr) {
        return;
    }

    uint64_t state =
        fr->func_id ^
        imm ^
        ((uint64_t)logical << 40u) ^
        ((uint64_t)pc << 12u) ^
        fr->steps ^
        (uint64_t)fr->session_mix;
    const uint32_t base = (pc + hvar + (uint32_t)fr->steps) & 31u;
    const uint32_t vreg_idx = (logical ^ hvar ^ fr->session_mix) & 7u;
    uint8_t snapshot[8];
    for (uint32_t i = 0u; i < 8u; i++) {
        snapshot[i] = fr->acc[(base + i) & 31u];
    }
    const uint64_t vreg_orig = fr->vregs[vreg_idx];

    for (uint32_t i = 0u; i < 8u; i++) {
        state = cprisk_splitmix64_next_i(&state);
        const uint32_t lane = (base + ((i * 5u + hvar) & 7u)) & 31u;
        fr->acc[lane] = cprisk_vm_xor_equiv_i(
            snapshot[i],
            (uint8_t)state,
            fr->session_mix + logical + hvar + i
        );
        fr->trace_scratch[(pc + logical + i) & 63u] ^=
            (uint8_t)(state >> ((i & 7u) * 8u));
    }

    fr->vregs[vreg_idx] = vreg_orig ^ state ^ ((uint64_t)logical << 48u);
    fr->trace_shadow[(logical + hvar) & 3u] ^=
        fr->vregs[vreg_idx] + ((uint64_t)pc << 17u) + fr->steps;

    for (uint32_t i = 0u; i < 8u; i++) {
        fr->acc[(base + i) & 31u] = snapshot[i];
    }
    fr->vregs[vreg_idx] = vreg_orig;
}

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

static void cprisk_vm_dispatch_cache_segment_enter_i(uint32_t base);

static void cprisk_vm_dispatch_fill_cache_i(cprisk_vm_interp_frame_t *fr, uint32_t op) {
    const uint8_t *payload = cprisk_vmp_dispatch_class_table_ptr_i(fr->dispatch_sec, fr->dispatch_hdr);
    const uint32_t base = op & ~(CPRISK_VM_DISPATCH_CACHE_BYTES - 1u);
    fr->dispatch_cache_base = base;
    fr->dispatch_cache_count = 0u;
    if (!payload) {
        memset(fr->dispatch_cache, CPRISK_VM_OP_POISON, sizeof(fr->dispatch_cache));
        return;
    }

    cprisk_vm_dispatch_cache_segment_enter_i(base);

    uint64_t state = fr->dispatch_decode_seed ^ 0x4D4456544B455953ULL; /* "MDVTKEYS" */
    if (state == 0u)
        state = 0xDEADBEEFCAFEBABEULL;
    if (fr->dispatch_hdr->version == CPRISK_VMP_DISPATCH_V2
        && (fr->dispatch_hdr_flags & CPRISK_VMP_DH_FLAG_CLASS_TABLE_KEYSTREAM) != 0u) {
        for (uint32_t skip = 0u; skip < base; skip++)
            (void)cprisk_splitmix64_next_i(&state);
    }

    for (uint32_t i = 0u; i < CPRISK_VM_DISPATCH_CACHE_BYTES && (base + i) < CPRISK_VMP_CLASS_TABLE_BYTES; i++) {
        uint8_t logical = payload[base + i];
        if (fr->dispatch_hdr->version == CPRISK_VMP_DISPATCH_V2
            && (fr->dispatch_hdr_flags & CPRISK_VMP_DH_FLAG_CLASS_TABLE_KEYSTREAM) != 0u) {
            logical ^= (uint8_t)cprisk_splitmix64_next_i(&state);
        }
        fr->dispatch_cache[i] = logical;
        fr->dispatch_cache_count += 1u;
    }
}

uint8_t cprisk_vm_dispatch_lookup(cprisk_vm_interp_frame_t *fr,
                                  uint32_t op,
                                  uint32_t pc_index) {
    if (fr->dispatch_cache_count == 0u
        || op < fr->dispatch_cache_base
        || op >= fr->dispatch_cache_base + fr->dispatch_cache_count) {
        cprisk_vm_dispatch_fill_cache_i(fr, op);
    }
    uint8_t logical = CPRISK_VM_OP_POISON;
    if (op >= fr->dispatch_cache_base
        && op < fr->dispatch_cache_base + fr->dispatch_cache_count) {
        logical = fr->dispatch_cache[op - fr->dispatch_cache_base];
    }
    logical ^= cprisk_vmp_dispatch_fault_byte_i(fr->decode_fault_mask, fr->func_id, pc_index, op);
    return logical;
}

__attribute__((noinline)) static void cprisk_vm_dispatch_seg_stub0_i(void) {
    volatile uint32_t u = 0x30u;
    u ^= u << 2;
    (void)u;
}
__attribute__((noinline)) static void cprisk_vm_dispatch_seg_stub1_i(void) {
    volatile uint32_t u = 0x31u;
    u = (u * 7u) ^ 0x9E3779B9u;
    (void)u;
}
__attribute__((noinline)) static void cprisk_vm_dispatch_seg_stub2_i(void) {
    volatile uint32_t u = 0x32u;
    u |= u >> 3;
    (void)u;
}
__attribute__((noinline)) static void cprisk_vm_dispatch_seg_stub3_i(void) {
    volatile uint32_t u = 0x33u;
    u ^= u * 0x9E37u;
    (void)u;
}

static void cprisk_vm_dispatch_cache_segment_enter_i(uint32_t base) {
    typedef void (*stub_fn)(void);
    static const stub_fn stub[4] = {
        cprisk_vm_dispatch_seg_stub0_i,
        cprisk_vm_dispatch_seg_stub1_i,
        cprisk_vm_dispatch_seg_stub2_i,
        cprisk_vm_dispatch_seg_stub3_i,
    };
    stub[(base >> 6) & 3u]();
}

__attribute__((noinline)) static void cprisk_vm_lg_spread0_i(void) {
    volatile int q = 0;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread1_i(void) {
    volatile int q = 1;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread2_i(void) {
    volatile int q = 2;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread3_i(void) {
    volatile int q = 3;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread4_i(void) {
    volatile int q = 4;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread5_i(void) {
    volatile int q = 5;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread6_i(void) {
    volatile int q = 6;
    (void)q;
}
__attribute__((noinline)) static void cprisk_vm_lg_spread7_i(void) {
    volatile int q = 7;
    (void)q;
}

static uint32_t cprisk_vm_interp_loop_b_cluster_slot_i(uint8_t logical) {
    if (logical == CPRISK_VM_OP_POISON || logical == CPRISK_VM_OP_HALT)
        return 0u;
    if (logical == CPRISK_VM_OP_NOP || logical == CPRISK_VM_OP_RET)
        return 1u;
    if (logical == CPRISK_VM_OP_RAW_REGION || logical == CPRISK_VM_OP_ADD || logical == CPRISK_VM_OP_SUB_LANE
        || logical == CPRISK_VM_OP_MUL_LANE)
        return 2u;
    if (logical == CPRISK_VM_OP_BRANCH_REL || logical == CPRISK_VM_OP_BRANCH_COND || logical == CPRISK_VM_OP_CALL)
        return 3u;
    if (logical >= CPRISK_VM_OP_XOR_MIX && logical <= CPRISK_VM_OP_ROL_ACC)
        return 4u;
    if (logical >= CPRISK_VM_OP_VREG_MOV && logical <= CPRISK_VM_OP_VREG_MEM)
        return 5u;
    if (logical == CPRISK_VM_OP_VM_CALL_FUNC)
        return 6u;
    return 7u;
}

static void cprisk_vm_interp_loop_b_cluster_spread_i(uint8_t logical) {
    typedef void (*stub_fn)(void);
    static const stub_fn tbl[8] = {
        cprisk_vm_lg_spread0_i,
        cprisk_vm_lg_spread1_i,
        cprisk_vm_lg_spread2_i,
        cprisk_vm_lg_spread3_i,
        cprisk_vm_lg_spread4_i,
        cprisk_vm_lg_spread5_i,
        cprisk_vm_lg_spread6_i,
        cprisk_vm_lg_spread7_i,
    };
    tbl[cprisk_vm_interp_loop_b_cluster_slot_i(logical) & 7u]();
}

static void cprisk_vm_opaque_runtime_init_i(cprisk_vm_interp_frame_t *fr) {
    uint32_t nonce = fr->session_mix ^ cprisk_vm_dispatch_bait_seed_i(fr->path_lane, 0u);
    fr->opaque_pid = 1;
    fr->opaque_clock_rc = 0;
#if defined(__APPLE__)
    fr->opaque_pid = (int32_t)getpid();
    struct timespec ts;
    memset(&ts, 0, sizeof(ts));
    fr->opaque_clock_rc = clock_gettime(CLOCK_MONOTONIC, &ts);
    nonce ^= (uint32_t)ts.tv_nsec;
    nonce ^= (uint32_t)ts.tv_sec * 0x9E3779B9u;
#endif
    fr->opaque_rt_nonce = cprisk_vmp_avalanche32_i(nonce ^ (uint32_t)fr->func_id ^ (uint32_t)(fr->func_id >> 32u));
    if (fr->opaque_rt_nonce == 0u)
        fr->opaque_rt_nonce = 0x6D2B79F5u;
    fr->opaque_chain = fr->opaque_rt_nonce ^ cprisk_vm_dispatch_bait_seed_i(fr->path_lane, fr->path_lane + 1u);
}

static uint32_t cprisk_vm_opaque_chain_advance_i(cprisk_vm_interp_frame_t *fr,
                                                 uint32_t logical,
                                                 uint64_t imm,
                                                 uint32_t pc,
                                                 uint32_t stage) {
    uint32_t acc_mix = cprisk_vm_mix32_from_acc_i(
        fr->acc,
        fr->opaque_chain ^ logical ^ pc ^ (stage * 0x45D9F3Bu)
    );
    uint32_t chain =
        fr->opaque_chain ^
        acc_mix ^
        (uint32_t)imm ^
        (uint32_t)(imm >> 32u) ^
        fr->opaque_rt_nonce ^
        cprisk_vm_dispatch_bait_seed_i(stage ^ logical, fr->path_lane) ^
        cprisk_vmp_relro_bait_mix_i();
    chain = cprisk_vmp_avalanche32_i(chain);
    if (chain == 0u)
        chain = 0xA511E9B3u ^ stage;
    fr->opaque_chain = chain;
    return chain;
}

static int cprisk_vm_opaque_dead_branch_i(cprisk_vm_interp_frame_t *fr,
                                          uint32_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t stage) {
    const uint32_t chain = cprisk_vm_opaque_chain_advance_i(fr, logical, imm, pc, stage);
    const uint32_t rel = cprisk_vmp_relro_bait_mix_i();
    uint32_t p = cprisk_vmp_avalanche32_i(
        chain ^ rel ^ stage * 0x9E3779B9u ^ (uint32_t)pc ^ (uint32_t)(logical * 0xC2B2u)
    );
    p ^= (uint32_t)(imm ^ (imm >> 32));
    uint32_t q = cprisk_vmp_rotl32_i(p, (stage & 15u) + 1u)
        ^ cprisk_vmp_rotr32_i((uint32_t)(imm >> 11), 7);

    if (p != 0u && (p + 0xFFFFFFFFu) == 0u && p != 1u)
        return 1;
    if ((q | 0u) == 0u && q != 0u)
        return 1;
    if ((q * 2u) == 1u)
        return 1;
    if (q != 0u && q < (q - 1u))
        return 1;
    if ((p | p) < (p & p))
        return 1;
    uint32_t r = cprisk_vmp_avalanche32_i(chain ^ fr->opaque_rt_nonce ^ rel ^ (uint32_t)fr->steps);
    if (r != 0u && (r + 0xFFFFFFFFu) == 0u && r != 1u)
        return 1;
    (void)fr->opaque_pid;
    (void)fr->opaque_clock_rc;
    return 0;
}

/* Opcode handlers and \c cprisk_vm_oph_table live in \c cprisk_vm_oph_*.c. */

static cprisk_vm_flow_t cprisk_vm_dispatch_oph_core_i(cprisk_vm_interp_frame_t *fr,
                                                      uint8_t op_raw,
                                                      uint8_t logical,
                                                      uint64_t imm,
                                                      uint32_t pc,
                                                      uint32_t hvar) {
    if (logical == CPRISK_VM_OP_POISON)
        return cprisk_vm_oph_poison(fr, op_raw, logical, imm, pc, hvar);
    if (logical >= CPRISK_VM_OPH_TABLE_LEN)
        return cprisk_vm_oph_unknown(fr, op_raw, logical, imm, pc, hvar);
    return cprisk_vm_oph_table[logical](fr, op_raw, logical, imm, pc, hvar);
}

void cprisk_vm_interp_loop_a(struct cprisk_vm_interp_frame *fr)
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
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x11u,
                        fr->encoded_pc ^ fr->func_id,
                        (uint32_t)fr->steps,
                        0x11u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x11u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x22u,
                        fr->encoded_pc + ((uint64_t)fr->session_mix << 17u),
                        (uint32_t)fr->steps,
                        0x22u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0x22u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x33u,
                        fr->encoded_pc ^ (uint64_t)fr->opaque_chain,
                        (uint32_t)fr->steps,
                        0x33u
                    )) {
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

        uint32_t pc = 0u;
        if (!cprisk_vm_decode_pc_i(fr->bh, fr->encoded_pc, fr->vpc_a, fr->vpc_b, &pc, fr->out)) {
            break;
        }
        if ((uint64_t)pc + CPRISK_VM_INSN_WIDTH > (uint64_t)fr->blen) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }

        if (fr->path_lane == 1u) {
            if (fr->m3_opaque != 0u) {
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x11u,
                        fr->encoded_pc ^ fr->func_id,
                        pc,
                        0x41u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x11u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x22u,
                        fr->encoded_pc + ((uint64_t)fr->session_mix << 17u),
                        pc,
                        0x42u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0x22u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x33u,
                        fr->encoded_pc ^ (uint64_t)fr->opaque_chain,
                        pc,
                        0x43u
                    )) {
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
            if (cprisk_vm_opaque_dead_branch_i(fr, 0x44u, fr->encoded_pc ^ fr->blen, pc, 0x44u)) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x44u);
                continue;
            }
        }

        const uint8_t op_raw = fr->code[pc];
        uint8_t op = op_raw;
        const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
        if (fr->enc_op != 0u) {
            op = (uint8_t)(op_raw ^ cprisk_vmp_opcode_mix_byte_i(fr->func_id, pc_index, fr->opcode_seed_root));
        }
        op ^= cprisk_vmp_opcode_fault_byte_i(fr->decode_fault_mask, fr->func_id, pc_index, op_raw);
        fr->out->last_opcode = (uint32_t)op;
        const uint8_t logical = cprisk_vm_dispatch_lookup(fr, (uint32_t)op & 0xFFu, pc_index);
        fr->out->last_dispatch_class = (uint32_t)logical;
        uint64_t imm = cprisk_read_le_u64_i(fr->code + pc + 1u);
        if (fr->enc_imm != 0u) {
            imm ^= cprisk_vmp_imm_mask_u64_i(fr->func_id, pc_index, fr->imm_seed_root);
        }
        imm ^= cprisk_vmp_imm_fault_mask_u64_i(fr->decode_fault_mask, fr->func_id, pc_index);
        const uint32_t hvar =
            cprisk_vm_handler_variant_i(fr->bh->reserved, fr->func_id, fr->steps, (uint32_t)op, imm)
            ^ ((fr->semantic_family & 0x3u) << 1u);

        if (fr->m3_opaque != 0u) {
            if (cprisk_vm_opaque_dead_branch_i(fr, (uint32_t)logical, imm, pc, 0x50u)) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, (uint32_t)op + 0x50u);
                continue;
            }
        }

        if (fr->m3_dead != 0u || fr->vm_anti_symbolic_heavy) {
            cprisk_vm_trace_sidefx_i(fr, (uint32_t)logical, imm, pc, hvar);
        }

        if (fr->vm_anti_symbolic_heavy) {
            uint64_t rt_mix = 0u;
#if defined(__APPLE__)
            struct timespec sym_ts;
            if (clock_gettime(CLOCK_MONOTONIC, &sym_ts) == 0) {
                rt_mix = (uint64_t)sym_ts.tv_nsec ^ ((uint64_t)sym_ts.tv_sec * 0x9E3779B97F4A7C15ULL);
            }
#endif
            volatile uint64_t sym_acc =
                (((uint64_t)fr->steps ^ imm) * 0xD6E8FEB783278F6BULL) ^ rt_mix;
            sym_acc ^= (uint64_t)fr->func_id ^ (fr->func_id >> 33);
#if defined(__APPLE__)
            sym_acc ^= (uint64_t)getpid() * 0x100000001B3ULL;
#endif
            const uint32_t cap = 3u + (uint32_t)((rt_mix ^ sym_acc ^ (uint64_t)fr->steps) & 7u);
            for (uint32_t si = 0u; si < cap; si++) {
                sym_acc ^= sym_acc >> 17;
                sym_acc *= 0xFF51AFD7ED558CCDULL;
                sym_acc ^= (uint64_t)(si * 0x9E3779B1u) + (rt_mix & 0xFFFFFFFFu);
                if (((sym_acc >> 40) & 0xFFFFu) == 0xA5A5u) {
                    const uint32_t lane = (si * 7u) & 31u;
                    fr->acc[lane] ^= (uint8_t)(sym_acc & 0xFFu);
                    fr->acc[(lane + 3u) & 31u] ^= (uint8_t)((sym_acc >> 8) & 0xFFu);
                }
            }
            (void)sym_acc;
        }

        {
            const cprisk_vm_flow_t flow =
                cprisk_vm_dispatch_oph_core_i(fr, op, logical, imm, pc, hvar);
            if (flow == CPRISK_VM_FLOW_LEAVE)
                goto vm_leave_a;
            continue;
        }

    }
vm_leave_a:
    cprisk_vm_interp_finish_run_i(fr);
}


static void cprisk_vm_interp_loop_b(struct cprisk_vm_interp_frame *fr)
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
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x11u,
                        fr->encoded_pc ^ fr->func_id,
                        (uint32_t)fr->steps,
                        0x11u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x11u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x22u,
                        fr->encoded_pc + ((uint64_t)fr->session_mix << 17u),
                        (uint32_t)fr->steps,
                        0x22u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0x22u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x33u,
                        fr->encoded_pc ^ (uint64_t)fr->opaque_chain,
                        (uint32_t)fr->steps,
                        0x33u
                    )) {
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

        uint32_t pc = 0u;
        if (!cprisk_vm_decode_pc_i(fr->bh, fr->encoded_pc, fr->vpc_a, fr->vpc_b, &pc, fr->out)) {
            break;
        }
        if ((uint64_t)pc + CPRISK_VM_INSN_WIDTH > (uint64_t)fr->blen) {
            fr->out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            fr->out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }

        if (fr->path_lane == 1u) {
            if (fr->m3_opaque != 0u) {
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x11u,
                        fr->encoded_pc ^ fr->func_id,
                        pc,
                        0x41u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x11u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x22u,
                        fr->encoded_pc + ((uint64_t)fr->session_mix << 17u),
                        pc,
                        0x42u
                    )) {
                    if (fr->m3_dead != 0u)
                        cprisk_vm_m3_dead_bait_xor_i(fr->acc, (fr->bh->reserved >> 8) & 0xFFu, 0x22u);
                    continue;
                }
                if (cprisk_vm_opaque_dead_branch_i(
                        fr,
                        0x33u,
                        fr->encoded_pc ^ (uint64_t)fr->opaque_chain,
                        pc,
                        0x43u
                    )) {
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
            if (cprisk_vm_opaque_dead_branch_i(fr, 0x44u, fr->encoded_pc ^ fr->blen, pc, 0x44u)) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, 0x44u);
                continue;
            }
        }

        /*
         * Loop B: alternate fetch/decode path — load immediate first, then opcode (semantically identical;
         * differs from loop A micro-order for static analysis / symbolic tooling).
         */
        volatile uint64_t loop_b_fetch_tag = fr->encoded_pc ^ (fr->steps * 0x5F3759DFu);
        (void)loop_b_fetch_tag;
        uint64_t imm = cprisk_read_le_u64_i(fr->code + pc + 1u);
        const uint32_t pc_index = pc / CPRISK_VM_INSN_WIDTH;
        if (fr->enc_imm != 0u) {
            imm ^= cprisk_vmp_imm_mask_u64_i(fr->func_id, pc_index, fr->imm_seed_root);
        }
        imm ^= cprisk_vmp_imm_fault_mask_u64_i(fr->decode_fault_mask, fr->func_id, pc_index);
        const uint8_t op_raw = fr->code[pc];
        uint8_t op = op_raw;
        if (fr->enc_op != 0u) {
            op = (uint8_t)(op_raw ^ cprisk_vmp_opcode_mix_byte_i(fr->func_id, pc_index, fr->opcode_seed_root));
        }
        op ^= cprisk_vmp_opcode_fault_byte_i(fr->decode_fault_mask, fr->func_id, pc_index, op_raw);
        fr->out->last_opcode = (uint32_t)op;
        const uint8_t logical = cprisk_vm_dispatch_lookup(fr, (uint32_t)op & 0xFFu, pc_index);
        fr->out->last_dispatch_class = (uint32_t)logical;
        const uint32_t hvar =
            cprisk_vm_handler_variant_i(fr->bh->reserved, fr->func_id, fr->steps, (uint32_t)op, imm)
            ^ ((fr->semantic_family & 0x3u) << 1u);

        if (fr->m3_opaque != 0u) {
            if (cprisk_vm_opaque_dead_branch_i(fr, (uint32_t)logical, imm, pc, 0x50u)) {
                if (fr->m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(fr->acc, fr->bh->reserved, (uint32_t)op + 0x50u);
                continue;
            }
        }

        if (fr->m3_dead != 0u || fr->vm_anti_symbolic_heavy) {
            cprisk_vm_trace_sidefx_i(fr, (uint32_t)logical, imm, pc, hvar);
        }

        if (fr->vm_anti_symbolic_heavy) {
            uint64_t rt_mix = 0u;
#if defined(__APPLE__)
            struct timespec sym_ts;
            if (clock_gettime(CLOCK_MONOTONIC, &sym_ts) == 0) {
                rt_mix = (uint64_t)sym_ts.tv_nsec ^ ((uint64_t)sym_ts.tv_sec * 0x9E3779B97F4A7C15ULL);
            }
#endif
            volatile uint64_t sym_acc =
                (((uint64_t)fr->steps ^ imm) * 0xD6E8FEB783278F6BULL) ^ rt_mix;
            sym_acc ^= (uint64_t)fr->func_id ^ (fr->func_id >> 33);
#if defined(__APPLE__)
            sym_acc ^= (uint64_t)getpid() * 0x100000001B3ULL;
#endif
            const uint32_t cap = 3u + (uint32_t)((rt_mix ^ sym_acc ^ (uint64_t)fr->steps) & 7u);
            for (uint32_t si = 0u; si < cap; si++) {
                sym_acc ^= sym_acc >> 17;
                sym_acc *= 0xFF51AFD7ED558CCDULL;
                sym_acc ^= (uint64_t)(si * 0x9E3779B1u) + (rt_mix & 0xFFFFFFFFu);
                if (((sym_acc >> 40) & 0xFFFFu) == 0xA5A5u) {
                    const uint32_t lane = (si * 7u) & 31u;
                    fr->acc[lane] ^= (uint8_t)(sym_acc & 0xFFu);
                    fr->acc[(lane + 3u) & 31u] ^= (uint8_t)((sym_acc >> 8) & 0xFFu);
                }
            }
            (void)sym_acc;
        }

        cprisk_vm_interp_loop_b_cluster_spread_i(logical);

        {
            const cprisk_vm_flow_t flow =
                cprisk_vm_dispatch_oph_core_i(fr, op, logical, imm, pc, hvar);
            if (flow == CPRISK_VM_FLOW_LEAVE)
                goto vm_leave_b;
            continue;
        }

    }
vm_leave_b:
    cprisk_vm_interp_finish_run_i(fr);
}

static void cprisk_vm_run_program_i(const struct mach_header_64 *hdr,
                                    const uint8_t *d_sec,
                                    const cprisk_vmp_dispatch_header_t *dhdr,
                                    const uint8_t *b_sec,
                                    unsigned long bsz,
                                    const cprisk_vmp_bytecode_header_t *bh,
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
    uint64_t encoded_pc = 0u;
    if (!cprisk_vm_encode_pc_i(bh, 0u, vpc_a, vpc_b, &encoded_pc, out)) {
        cprisk_vm_wb_finalize_i(out, acc);
        return;
    }
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

    uint64_t decode_fault_mask = 0u;
    uint64_t m3_seal_mix = 0u;
    cprisk_vm_m3_selfchk_run_i(hdr, acc, func_id, bh, out, &decode_fault_mask, &m3_seal_mix);

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
    if ((bh->reserved & CPRISK_VMP_BC_FLAG_M3_SELFCHK) != 0u && m3_seal_mix != 0u) {
        imm_seed_root ^= m3_seal_mix;
        opcode_seed_root ^= (m3_seal_mix << 1u) ^ (m3_seal_mix >> 61u);
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
    fr.dispatch_sec = d_sec;
    fr.dispatch_hdr = dhdr;
    fr.dispatch_hdr_flags = dhdr ? dhdr->flags : 0u;
    fr.dispatch_decode_seed = cprisk_vmp_dispatch_keystream_seed_i(d_sec, dhdr);
    if ((bh->reserved & CPRISK_VMP_BC_FLAG_M3_SELFCHK) != 0u && m3_seal_mix != 0u)
        fr.dispatch_decode_seed ^= m3_seal_mix;
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
    fr.session_mix = cprisk_vm_session_mix_i();
    fr.decode_fault_mask = decode_fault_mask;
    memcpy(fr.acc, acc, sizeof(fr.acc));
    cprisk_vm_opaque_runtime_init_i(&fr);
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

    const cprisk_vmp_dispatch_header_t *dhdr = (const cprisk_vmp_dispatch_header_t *)(const void *)d_sec;

    cprisk_vm_run_program_i(
        hdr,
        d_sec,
        dhdr,
        b_sec,
        bsz,
        bh,
        (uint32_t)path_lane,
        func_id,
        acc,
        out
    );

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

typedef struct {
    uint64_t func_id;
    const void *hdr_sym;
    uint32_t lane;
    uint32_t ticket;
} cprisk_vm_entry_ticket_t;

typedef uint64_t (*cprisk_vm_entry_finish_ticket_fp_i)(const cprisk_vm_entry_ticket_t *ticket);
typedef uint64_t (*cprisk_vm_entry_finish_pack32_fp_i)(uint32_t lo,
                                                       uint32_t hi,
                                                       uint32_t lane,
                                                       uint32_t ticket,
                                                       const void *hdr_sym);

static uint32_t cprisk_vm_entry_ticket_i(uint64_t func_id, const void *hdr_sym, uint32_t lane) {
    uint32_t mix =
        (uint32_t)func_id ^
        (uint32_t)(func_id >> 32u) ^
        (uint32_t)(uintptr_t)hdr_sym ^
        (uint32_t)(((uintptr_t)hdr_sym) >> 32u) ^
        (lane * 0x9E3779B9u) ^
        cprisk_vm_session_mix_i();
    mix = cprisk_vmp_avalanche32_i(mix ^ cprisk_vm_dispatch_bait_seed_i(lane, lane + 1u));
    if (mix == 0u)
        mix = 0xA5C31F27u ^ lane;
    return mix;
}

__attribute__((noinline)) static uint64_t cprisk_vm_entry_finish_ticket_i(const cprisk_vm_entry_ticket_t *ticket) {
    if (!ticket || !ticket->hdr_sym)
        return 0u;
    if (ticket->ticket != cprisk_vm_entry_ticket_i(ticket->func_id, ticket->hdr_sym, ticket->lane))
        return 0u;
    return cprisk_vm_entry_finish_lane_i(ticket->func_id, ticket->hdr_sym, ticket->lane);
}

__attribute__((noinline)) static uint64_t cprisk_vm_entry_finish_pack32_i(uint32_t lo,
                                                                           uint32_t hi,
                                                                           uint32_t lane,
                                                                           uint32_t ticket,
                                                                           const void *hdr_sym) {
    const uint64_t func_id = ((uint64_t)hi << 32u) | (uint64_t)lo;
    if (ticket != cprisk_vm_entry_ticket_i(func_id, hdr_sym, lane))
        return 0u;
    return cprisk_vm_entry_finish_lane_i(func_id, hdr_sym, lane);
}

__attribute__((noinline)) uint64_t cprisk_vm_entry(uint64_t func_id) {
#if defined(__aarch64__)
    __asm__ volatile("add x0, x0, #0");
#endif

    /*
     * M3: keep a tiny side-effectful entry prelude so policy-guided Pass9 can
     * still find rewritable entry instructions on this wrapper symbol.
     */
    volatile uint64_t prelude = func_id ^ 0x9E3779B97F4A7C15ULL ^ (uint64_t)cprisk_vm_session_mix_i();
    prelude ^= (prelude >> 17);
    prelude ^= (prelude << 7);
    cprisk_vm_entry_ticket_t ticket;
    ticket.func_id = func_id;
    ticket.hdr_sym = (const void *)&cprisk_vm_entry;
    ticket.lane = 0u;
    ticket.ticket = cprisk_vm_entry_ticket_i(func_id, ticket.hdr_sym, ticket.lane) ^ (uint32_t)prelude;
    ticket.ticket ^= (uint32_t)prelude;
    if (((uint32_t)prelude & 1u) == 0u) {
        cprisk_vm_entry_finish_ticket_fp_i fp = cprisk_vm_entry_finish_ticket_i;
        return fp(&ticket);
    }
    return cprisk_vm_entry_finish_ticket_i(&ticket);
}

__attribute__((noinline)) uint64_t cprisk_vm_entry_alt1(uint64_t func_id) {
#if defined(__aarch64__)
    __asm__ volatile("eor x16, x0, x0");
#endif
    uint32_t lo = (uint32_t)func_id;
    uint32_t hi = (uint32_t)(func_id >> 32u);
    volatile uint32_t ledger = cprisk_vmp_avalanche32_i(lo ^ cprisk_vmp_rotl32_i(hi, 7u) ^ 0xA5A5C3C3u);
    ledger ^= cprisk_vm_dispatch_bait_seed_i(1u, hi & 3u);
    cprisk_vm_entry_finish_pack32_fp_i fp = cprisk_vm_entry_finish_pack32_i;
    const uint32_t ticket = cprisk_vm_entry_ticket_i(func_id, (const void *)&cprisk_vm_entry_alt1, 1u)
        ^ ledger ^ ledger;
    return fp(lo, hi, 1u, ticket, (const void *)&cprisk_vm_entry_alt1);
}

__attribute__((noinline)) uint64_t cprisk_vm_entry_alt2(uint64_t func_id) {
#if defined(__aarch64__)
    __asm__ volatile("eor x17, x0, x0");
#endif
    cprisk_vm_entry_ticket_t ticket;
    memset(&ticket, 0, sizeof(ticket));
    ticket.func_id = func_id ^ UINT64_C(0x13579BDF2468ACE1);
    ticket.func_id ^= UINT64_C(0x13579BDF2468ACE1);
    ticket.hdr_sym = (const void *)&cprisk_vm_entry_alt2;
    ticket.lane = 2u;
    ticket.ticket = cprisk_vm_entry_ticket_i(func_id, ticket.hdr_sym, ticket.lane);
    if ((ticket.ticket & 1u) != 0u) {
        cprisk_vm_entry_finish_ticket_fp_i fp = cprisk_vm_entry_finish_ticket_i;
        return fp(&ticket);
    }
    return cprisk_vm_entry_finish_ticket_i(&ticket);
}
