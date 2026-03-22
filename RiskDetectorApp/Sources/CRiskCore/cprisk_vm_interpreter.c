#include "include/CRiskCore.h"
#include "include/cprisk_macho.h"

#include <string.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#define CPRISK_VM_MAX_STEPS 65536u
#define CPRISK_VM_INSN_WIDTH 9u
#define CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES ((size_t)sizeof(cprisk_vmp_bytecode_header_t))
#define CPRISK_VMP_BYTECODE_VPC_EXT_BYTES 16u

static uint64_t cprisk_read_le_u64_i(const uint8_t *p) {
    uint64_t value = 0;
    if (!p)
        return 0;
    memcpy(&value, p, sizeof(value));
    return value;
}

static size_t cprisk_vmp_bytecode_header_total_bytes_i(uint32_t version) {
    if (version == CPRISK_VMP_VERSION_M2)
        return CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES + CPRISK_VMP_BYTECODE_VPC_EXT_BYTES;
    return CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES;
}

static size_t cprisk_vmp_bytecode_entry_stride_i(const cprisk_vmp_bytecode_header_t *bh) {
    size_t stride = sizeof(cprisk_vmp_bytecode_entry_t);
    if (bh && (bh->reserved & CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC) != 0u)
        stride += CPRISK_VMP_BYTECODE_VPC_EXT_BYTES;
    return stride;
}

static int cprisk_vmp_bytecode_version_ok_i(uint32_t v) {
    return v == CPRISK_VMP_VERSION || v == CPRISK_VMP_VERSION_M2;
}

static void cprisk_vmp_read_vpc_affine_i(const uint8_t *b_sec,
                                       uint32_t version,
                                       uint64_t *out_a,
                                       uint64_t *out_b) {
    *out_a = 1u;
    *out_b = 0u;
    if (version != CPRISK_VMP_VERSION_M2 || !b_sec)
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

static void cprisk_vm_raw_region_apply_i(uint8_t acc[32], uint64_t imm, uint32_t steps, uint32_t variant) {
    /* Three semantic-equivalent implementations; index update order is identical across variants. */
    switch (variant % 3u) {
    case 0u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint8_t lane = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
            acc[(i + (uint32_t)(steps & 0x0Fu)) & 31u] ^= lane;
        }
        break;
    case 1u: {
        uint32_t i = 0;
        while (i < 8u) {
            uint8_t lane = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
            uint32_t idx = (i + (uint32_t)(steps & 0x0Fu)) & 31u;
            acc[idx] ^= lane;
            i++;
        }
    } break;
    default: {
        for (int k = 0; k < 8; k++) {
            uint32_t i = (uint32_t)k;
            uint8_t lane = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
            acc[(i + (uint32_t)(steps & 0x0Fu)) & 31u] ^= lane;
        }
    } break;
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

static void cprisk_vm_add_apply_i(uint8_t acc[32], uint64_t imm, uint32_t steps, uint32_t variant) {
    switch (variant % 3u) {
    case 0u:
        for (uint32_t i = 0; i < 8u; i++) {
            uint8_t lane = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
            uint32_t idx = (i + (uint32_t)(steps & 0x0Fu)) & 31u;
            acc[idx] = (uint8_t)(acc[idx] + lane);
        }
        break;
    case 1u: {
        uint32_t i = 0;
        while (i < 8u) {
            uint8_t lane = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
            uint32_t idx = (i + (uint32_t)(steps & 0x0Fu)) & 31u;
            uint8_t t = acc[idx];
            acc[idx] = (uint8_t)(t + lane);
            i++;
        }
    } break;
    default: {
        for (int k = 0; k < 8; k++) {
            uint32_t i = (uint32_t)k;
            uint8_t lane = (uint8_t)((imm >> (i * 8u)) & 0xFFu);
            uint32_t idx = (i + (uint32_t)(steps & 0x0Fu)) & 31u;
            acc[idx] = (uint8_t)(acc[idx] + lane);
        }
    } break;
    }
}

static int cprisk_vmp_headers_ok_i(const uint8_t *d_s,
                                   unsigned long d_sz,
                                   const uint8_t *b_s,
                                   unsigned long b_sz,
                                   const cprisk_vmp_bytecode_header_t **out_bh) {
    if (!d_s || d_sz < sizeof(cprisk_vmp_dispatch_header_t) + CPRISK_VMP_CLASS_TABLE_BYTES)
        return 0;
    const cprisk_vmp_dispatch_header_t *dh = (const cprisk_vmp_dispatch_header_t *)(const void *)d_s;
    if (dh->magic != CPRISK_VMP_MAGIC_DISPATCH || dh->version != CPRISK_VMP_VERSION)
        return 0;
    if (dh->class_table_size != CPRISK_VMP_CLASS_TABLE_BYTES)
        return 0;

    if (!b_s || b_sz < CPRISK_VMP_BYTECODE_HEADER_CORE_BYTES)
        return 0;
    const cprisk_vmp_bytecode_header_t *bh = (const cprisk_vmp_bytecode_header_t *)(const void *)b_s;
    if (bh->magic != CPRISK_VMP_MAGIC_BYTECODE || !cprisk_vmp_bytecode_version_ok_i(bh->version))
        return 0;
    if (bh->entry_count == 0u || bh->entry_count > 4096u)
        return 0;
    const size_t hdr_total = cprisk_vmp_bytecode_header_total_bytes_i(bh->version);
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

int cprisk_vm_execute(uint64_t func_id, cprisk_vm_run_result_t *out) {
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
    if (cprisk_is_being_traced()) {
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

    const struct mach_header_64 *hdr =
        cprisk_find_own_header((const void *)&cprisk_vm_execute);
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

    const uint8_t *dispatch = d_sec + sizeof(cprisk_vmp_dispatch_header_t);
    const size_t bc_hdr_total = cprisk_vmp_bytecode_header_total_bytes_i(bh->version);
    const size_t entry_stride = cprisk_vmp_bytecode_entry_stride_i(bh);

    uint64_t vpc_a = 1u;
    uint64_t vpc_b = 0u;
    cprisk_vmp_read_vpc_affine_i(b_sec, bh->version, &vpc_a, &vpc_b);

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
        memcpy(out->acc, acc, sizeof(acc));
        return 0;
    }

    if ((bh->reserved & CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC) != 0u) {
        const uint8_t *selp = (const uint8_t *)selected;
        vpc_a = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t));
        vpc_b = cprisk_read_le_u64_i(selp + sizeof(cprisk_vmp_bytecode_entry_t) + 8u);
    }

    const uint8_t *code = b_sec + selected->bytecode_offset;
    const uint32_t blen = selected->bytecode_length;
    /* Affine VPC: encoded_pc = vpc * vpc_a + vpc_b; start at vpc=0. */
    uint64_t encoded_pc = vpc_b;
    if (vpc_a == 0u) {
        out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
        out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
        memcpy(out->acc, acc, sizeof(acc));
        return 0;
    }

    if ((bh->reserved & CPRISK_VMP_BC_FLAG_M3_SELFCHK) != 0u && CPRISK_VM_M3_SELF_EXPECT != 0u) {
        uint32_t fnv = cprisk_vm_m3_fnv1a_bytes_i((const volatile uint8_t *)(const void *)&cprisk_vm_execute,
                                                 (size_t)CPRISK_VM_M3_SELF_BYTES);
        if (fnv != CPRISK_VM_M3_SELF_EXPECT) {
            out->poison_flags |= CPRISK_VM_POISON_SELF_INTEGRITY | CPRISK_VM_POISON_BYTECODE;
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            memcpy(out->acc, acc, sizeof(acc));
            uint8_t wb_out[32];
            int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
            out->whitebox_domain_rc = wbr;
            if (wbr == 0)
                memcpy(out->acc, wb_out, sizeof(wb_out));
            return 0;
        }
    }

    const uint32_t m3_opaque = (bh->reserved & CPRISK_VMP_BC_FLAG_M3_OPAQUE_CHAIN) != 0u ? 1u : 0u;
    const uint32_t m3_dead = (bh->reserved & CPRISK_VMP_BC_FLAG_M3_DEAD_HANDLERS) != 0u ? 1u : 0u;

    out->status = CPRISK_VM_STATUS_STEP_LIMIT;

    uint64_t steps = 0u;
    while (steps < CPRISK_VM_MAX_STEPS) {
        if (m3_opaque != 0u) {
            uint32_t vpc_tag = (uint32_t)(encoded_pc ^ (encoded_pc >> 32));
            vpc_tag ^= (uint32_t)steps;
            vpc_tag ^= (uint32_t)func_id ^ (uint32_t)(func_id >> 32);
            /* Opaque true: n^2 and n share parity (same low bit). */
            if (((vpc_tag * vpc_tag) & 1u) != (vpc_tag & 1u)) {
                if (m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(acc, bh->reserved, 0x11u);
                continue;
            }
            /* Opaque false: 2*x==1 is unsatisfiable in uint32 modular arithmetic. */
            volatile uint32_t vt = vpc_tag;
            if ((vt * 2u) == 1u) {
                if (m3_dead != 0u)
                    cprisk_vm_m3_dead_bait_xor_i(acc, (bh->reserved >> 8) & 0xFFu, 0x22u);
                continue;
            }
            /* VPC-shaped bait chain (still dead): (x|0)==0 && x!=0 */
            volatile uint32_t vp = vpc_tag;
            if (((vp | 0u) == 0u) && vp != 0u) {
                if (m3_dead != 0u)
                    cprisk_vm_m3_dead_bait_add_i(acc, (bh->reserved >> 16) & 0xFFu, 0x33u);
                continue;
            }
        } else if (m3_dead != 0u) {
            volatile uint32_t ds = (bh->reserved >> 16) & 0xFFu;
            if ((ds * 2u) == 1u)
                cprisk_vm_m3_dead_bait_roll_i(acc, ds);
        }

        if (encoded_pc < vpc_b) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }
        const uint64_t numer = encoded_pc - vpc_b;
        if (numer % vpc_a != 0u) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }
        const uint64_t pc64 = numer / vpc_a;
        if (pc64 > (uint64_t)UINT32_MAX) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }
        const uint32_t pc = (uint32_t)pc64;
        if ((uint64_t)pc + CPRISK_VM_INSN_WIDTH > (uint64_t)blen) {
            out->status = CPRISK_VM_STATUS_INVALID_BYTECODE;
            out->poison_flags |= CPRISK_VM_POISON_BYTECODE;
            break;
        }

        if (m3_opaque != 0u) {
            /* Second opaque layer around decoded PC (stable semantics). */
            uint32_t pc_mix = pc ^ (uint32_t)(steps * 0x45D9F3Bu);
            pc_mix ^= (uint32_t)(blen + 0x9E3779B9u);
            if (((pc_mix * pc_mix) & 1u) != (pc_mix & 1u)) {
                if (m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(acc, bh->reserved, 0x44u);
                continue;
            }
        }

        const uint8_t op = code[pc];
        out->last_opcode = (uint32_t)op;
        const uint8_t logical = dispatch[(size_t)op & 0xFFu];
        out->last_dispatch_class = (uint32_t)logical;
        const uint64_t imm = cprisk_read_le_u64_i(code + pc + 1u);
        const uint32_t hvar =
            cprisk_vm_handler_variant_i(bh->reserved, func_id, steps, (uint32_t)op, imm);

        if (m3_opaque != 0u) {
            uint32_t lt = (uint32_t)logical ^ (uint32_t)(steps * 3u);
            lt ^= (uint32_t)(imm ^ (imm >> 32));
            volatile uint32_t lv = lt;
            /* Always-false: no uint32 satisfies 2*x == 1. */
            if ((lv * 2u) == 1u) {
                if (m3_dead != 0u)
                    cprisk_vm_m3_dead_dispatch_i(acc, bh->reserved, (uint32_t)op + 0x50u);
                continue;
            }
        }

        if (logical == CPRISK_VM_OP_POISON) {
            out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
            cprisk_vm_poison_mix_unknown_i(acc, (uint32_t)op, (uint32_t)logical);
            if (!cprisk_vm_enc_pc_advance_i(&encoded_pc, vpc_a, out))
                break;
            steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_HALT || logical == CPRISK_VM_OP_RET) {
            if (!cprisk_vm_enc_pc_advance_i(&encoded_pc, vpc_a, out))
                break;
            steps += 1u;
            out->status = CPRISK_VM_STATUS_OK;
            break;
        }

        if (logical == CPRISK_VM_OP_NOP) {
            if (!cprisk_vm_enc_pc_advance_i(&encoded_pc, vpc_a, out))
                break;
            steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_RAW_REGION) {
            cprisk_vm_raw_region_apply_i(acc, imm, (uint32_t)steps, hvar);
            if (!cprisk_vm_enc_pc_advance_i(&encoded_pc, vpc_a, out))
                break;
            steps += 1u;
            continue;
        }

        if (logical == CPRISK_VM_OP_ADD) {
            cprisk_vm_add_apply_i(acc, imm, (uint32_t)steps, hvar);
            if (!cprisk_vm_enc_pc_advance_i(&encoded_pc, vpc_a, out))
                break;
            steps += 1u;
            continue;
        }

        out->poison_flags |= CPRISK_VM_POISON_UNKNOWN_OPCODE;
        cprisk_vm_poison_mix_unknown_i(acc, (uint32_t)op, (uint32_t)logical);
        if (!cprisk_vm_enc_pc_advance_i(&encoded_pc, vpc_a, out))
            break;
        steps += 1u;
    }

    memcpy(out->acc, acc, sizeof(acc));
    out->steps = steps;

    uint8_t wb_out[32];
    int wbr = cprisk_whitebox_evaluate_domain(5u, out->acc, wb_out);
    out->whitebox_domain_rc = wbr;
    if (wbr == 0)
        memcpy(out->acc, wb_out, sizeof(wb_out));

    return 0;
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

    cprisk_vm_run_result_t result;
    if (cprisk_vm_execute(func_id, &result) != 0)
        return 0;
    uint64_t folded = 0;
    memcpy(&folded, result.acc, sizeof(folded));
    return folded;
}
