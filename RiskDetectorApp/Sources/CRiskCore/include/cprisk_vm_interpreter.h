#ifndef CPRISK_VM_INTERPRETER_H
#define CPRISK_VM_INTERPRETER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Build-time producer + runtime consumer ABI (Pass13 VMProtector). */
#define CPRISK_VMP_MAGIC_DISPATCH 0x44565043u /* "CPVD" little-endian */
#define CPRISK_VMP_MAGIC_BYTECODE 0x4D565043u /* "CPVM" little-endian */
#define CPRISK_VMP_VERSION 1u
/** M2: optional VPC affine + extended header (global vpc_a/vpc_b after base header). */
#define CPRISK_VMP_VERSION_M2 2u
/** V3: optional immediate keystream seed appended after M2 extension. */
#define CPRISK_VMP_VERSION_V3 3u
/** Dispatch section \c cprisk_vmp_dispatch_header_t::version: plaintext 256-byte class table (legacy). */
#define CPRISK_VMP_DISPATCH_V1 1u
/**
 * Dispatch section version 2: 256-byte XOR-protected class table; runtime derives a one-shot keystream
 * from root runtime material + header (see CRiskCore interpreter). On-disk table stays non-plaintext.
 */
#define CPRISK_VMP_DISPATCH_V2 2u
#define CPRISK_VMP_CLASS_TABLE_BYTES 256u
#define CPRISK_VMP_DISPATCH_SEED_BYTES 8u

/** Bitmask in \c cprisk_vmp_bytecode_header_t::reserved (producer may set). */
#define CPRISK_VMP_BC_FLAG_NONE 0u
/** When set, \c reserved also carries a 2-bit handler variant seed (see M2). */
#define CPRISK_VMP_BC_FLAG_HANDLER_VARIANT_SEED 0x00000001u
/** Each bytecode entry is followed by 16 bytes: vpc_a, vpc_b (LE uint64 each). */
#define CPRISK_VMP_BC_FLAG_PER_ENTRY_VPC 0x00000002u
/** M3: dispatch loop uses opaque predicate gates (non-linear CFG, semantics unchanged). */
#define CPRISK_VMP_BC_FLAG_M3_OPAQUE_CHAIN 0x00000004u
/** M3: inject unreachable / bait handler paths (seed from \c reserved bits 16–23). */
#define CPRISK_VMP_BC_FLAG_M3_DEAD_HANDLERS 0x00000008u
/** M3: run interpreter entry self-check (rolling hash vs \c CPRISK_VM_M3_SELF_EXPECT). */
#define CPRISK_VMP_BC_FLAG_M3_SELFCHK 0x00000010u
/** P1: immediates in bytecode (8 bytes after opcode) are XOR-mixed; decipher per-instruction before semantics. */
#define CPRISK_VMP_BC_FLAG_ENC_IMMEDIATE 0x00000020u
/** P1: raw wire opcode bytes XOR-mixed per insn (requires v3 header + 8-byte opcode seed after optional imm seed). */
#define CPRISK_VMP_BC_FLAG_ENC_OPCODE 0x00000040u
/** Heavy / high-intensity VM paths: enable lightweight anti-symbolic bait (opt-in with semantic family thresholds). */
#define CPRISK_VMP_BC_FLAG_ANTI_SYMBOLIC_HEAVY 0x00000080u
/** M3: when combined with \c CPRISK_VMP_BC_FLAG_M3_SELFCHK, verify HMAC-SHA256 (truncated) vs \c __swift5_mdvsk CPSH blob instead of FNV. */
#define CPRISK_VMP_BC_FLAG_M3_SELFCHK_HMAC 0x00000100u
/** M4: interpret the 16-byte VPC metadata block as non-linear Feistel/SPN material instead of plain affine A/B. */
#define CPRISK_VMP_BC_FLAG_VPC_NONLINEAR 0x00000400u
/**
 * When set, runtime takes a SHA256 baseline of each function's bytecode blob at entry and re-checks on a step
 * cadence + selected control-flow boundaries (see CRiskCore VM interpreter). Backward-compatible when unset.
 * Periodic re-hashes are throttled against the last successful check; an early-step check and
 * return/halt/nested-call boundaries run more eagerly.
 */
#define CPRISK_VMP_BC_FLAG_BC_SEG_RUNTIME_SHA256 0x00000800u

/** White-box PRF domain used for per-dispatch session-bound side effects (feeds opaque/session chain). */
#define CPRISK_VM_WB_HANDLER_SIDE_DOMAIN 7u

/** Dispatch header flags (`cprisk_vmp_dispatch_header_t::flags`). */
#define CPRISK_VMP_DH_FLAG_HANDLER_DUPLICATION 0x00000001u
#define CPRISK_VMP_DH_FLAG_OPAQUE_VPC_CATEGORY 0x00000002u
#define CPRISK_VMP_DH_FLAG_DEAD_HANDLER_META 0x00000004u
#define CPRISK_VMP_DH_FLAG_VPC_PRED_META 0x00000008u
#define CPRISK_VMP_DH_FLAG_CLASS_TABLE_KEYSTREAM 0x00000010u

enum {
    CPRISK_VM_STATUS_OK = 0,
    CPRISK_VM_STATUS_INVALID_DISPATCH = 1,
    CPRISK_VM_STATUS_INVALID_BYTECODE = 2,
    CPRISK_VM_STATUS_TRACED_SHORTCIRCUIT = 3,
    CPRISK_VM_STATUS_STEP_LIMIT = 4,
};

enum {
    CPRISK_VM_POISON_NONE = 0u,
    CPRISK_VM_POISON_UNKNOWN_OPCODE = 1u << 0,
    CPRISK_VM_POISON_TRACED = 1u << 1,
    CPRISK_VM_POISON_FRIDA = 1u << 2,
    CPRISK_VM_POISON_DISPATCH = 1u << 3,
    CPRISK_VM_POISON_BYTECODE = 1u << 4,
    /** M3: interpreter entry self-check mismatch (tamper / unexpected layout). */
    CPRISK_VM_POISON_SELF_INTEGRITY = 1u << 5,
};

/**
 * M3 optional: rolling FNV-1a (32-bit) over three **concatenated** TEXT windows (no address
 * mixing): \c CPRISK_VM_M3_SELF_EXEC_BYTES at \c cprisk_vm_execute, then
 * \c CPRISK_VM_M3_SELF_LOOP_BYTES at \c cprisk_vm_interp_loop_a (main interpret loop prefix),
 * then \c CPRISK_VM_M3_SELF_DISPATCH_BYTES at \c cprisk_vm_dispatch_lookup (dispatch decode path).
 * Loop/dispatch windows are intentionally wider than the legacy 48/32 split so tamper in the
 * hot loop/dispatch path invalidates CPSF/CPSH together with runtime decode seeds (see self-check
 * wiring in the lane-specific VM execute paths).
 * Sum equals \c CPRISK_VM_M3_SELF_BYTES; \c cprisk-armor \c VMSelfExpectInjector hashes the same
 * layout from Mach-O symtab (post-link CPSF/CPSH).
 * When 0, the self-check is skipped even if \c CPRISK_VMP_BC_FLAG_M3_SELFCHK is set.
 * Enable a strict check by defining this at compile time to the fingerprint for your
 * toolchain; re-derive after material interpreter changes.
 *
 * Additional sources (when macro is 0): optional \c CPRISK_ARMOR_SECTION_VMP_SELF_EXPECT
 * section (magic + LE u32 expect value). See \c CPRISK_VMP_SELF_EXPECT_MAGIC.
 *
 * \c CPRISK_VM_SELFCHK_POLICY: 0 = legacy (no expect → skip check). 1 = strict: bytecode flag
 * without any expect source poisons (opt-in for pipelines that always embed expect).
 */
#if !defined(CPRISK_VM_M3_SELF_EXPECT)
#define CPRISK_VM_M3_SELF_EXPECT 0u
#endif
#if !defined(CPRISK_VM_M3_SELF_BYTES)
#define CPRISK_VM_M3_SELF_BYTES 176u
#endif
/** Split of \c CPRISK_VM_M3_SELF_BYTES: VM entry + main loop prefix + dispatch lookup (must sum to total). */
#if !defined(CPRISK_VM_M3_SELF_EXEC_BYTES)
#define CPRISK_VM_M3_SELF_EXEC_BYTES 48u
#endif
#if !defined(CPRISK_VM_M3_SELF_LOOP_BYTES)
#define CPRISK_VM_M3_SELF_LOOP_BYTES 64u
#endif
#if !defined(CPRISK_VM_M3_SELF_DISPATCH_BYTES)
#define CPRISK_VM_M3_SELF_DISPATCH_BYTES 64u
#endif
#if !defined(CPRISK_VM_M3_SELF_INCLUDE_LOOP)
#define CPRISK_VM_M3_SELF_INCLUDE_LOOP 1
#endif
#if !defined(CPRISK_VM_SELFCHK_POLICY)
#define CPRISK_VM_SELFCHK_POLICY 0
#endif
/** If 1, \c CPRISK_VMP_BC_FLAG_M3_SELFCHK without \c CPRISK_VMP_BC_FLAG_M3_SELFCHK_HMAC still prefers HMAC when a CPSH blob is present (else FNV/CPSF). */
#if !defined(CPRISK_VM_SELFCHK_PREFER_HMAC_WHEN_AMBIGUOUS)
#define CPRISK_VM_SELFCHK_PREFER_HMAC_WHEN_AMBIGUOUS 1
#endif
/** Force legacy FNV path even when HMAC flag is set (toolchain bring-up). */
#if !defined(CPRISK_VM_SELFCHK_FORCE_LEGACY_FNV)
#define CPRISK_VM_SELFCHK_FORCE_LEGACY_FNV 0
#endif
/** Little-endian magic for the optional \c __swift5_mdvsk self-expect blob (ASCII "CPSF"). */
#define CPRISK_VMP_SELF_EXPECT_MAGIC 0x46535043u
/** Little-endian magic for HMAC self-expect (ASCII "CPSH") — LE u32 tag (e.g. first 4 bytes of HMAC-SHA256). */
#define CPRISK_VMP_SELF_EXPECT_MAGIC_HMAC 0x48535043u

/* Logical opcode IDs generated by VMProtector/VMIR.swift. */
enum {
    CPRISK_VM_OP_NOP = 0u,
    CPRISK_VM_OP_RET = 1u,
    CPRISK_VM_OP_RAW_REGION = 2u,
    CPRISK_VM_OP_HALT = 3u,
    /** M2: byte-lane add into acc (multiple semantic-equivalent handler paths). */
    CPRISK_VM_OP_ADD = 4u,
    /** PC-relative branch (unconditional `B`); immediate = signed VM bytecode byte delta (AArch64 imm26×9). */
    CPRISK_VM_OP_BRANCH_REL = 5u,
    /** `B.cond` / `CBZ` / `CBNZ` — immediate carries AArch64 insn word; predicate uses accumulator-derived flags. */
    CPRISK_VM_OP_BRANCH_COND = 6u,
    /** `BL` — push return PC then branch like `CPRISK_VM_OP_BRANCH_REL`. */
    CPRISK_VM_OP_CALL = 7u,
    /** MOVZ/MOVN/MOVK-family surrogate semantic op. */
    CPRISK_VM_OP_MOV_WIDE = 8u,
    /** ADRP+ADD surrogate semantic op. */
    CPRISK_VM_OP_ADR_ADD = 9u,
    /** CSEL/CSET surrogate semantic op. */
    CPRISK_VM_OP_COND_SELECT = 10u,
    /** LDR/STR surrogate semantic op. */
    CPRISK_VM_OP_LOAD_STORE = 11u,
    /** EOR-family surrogate semantic op. */
    CPRISK_VM_OP_XOR_MIX = 12u,
    /** Byte-lane OR into acc (polymorphic lanes; wire via dispatch table). */
    CPRISK_VM_OP_OR_LANE = 13u,
    /** Byte-lane AND into acc. */
    CPRISK_VM_OP_AND_LANE = 14u,
    /** Rotate 32-byte acc left by (imm & 31). */
    CPRISK_VM_OP_ROL_ACC = 15u,
    /** Nested VM: immediate = callee \c function_id; runs callee bytecode then resumes (depth-capped). */
    CPRISK_VM_OP_VM_CALL_FUNC = 16u,
    /** Virtual GPR mov / imm / acc window (see interpreter immediate layout). */
    CPRISK_VM_OP_VREG_MOV = 17u,
    /** Virtual GPR 64-bit ALU (ADD/XOR/AND) between two regs, result to dst. */
    CPRISK_VM_OP_VREG_ALU = 18u,
    /** Load 8 acc bytes into vreg or store vreg into acc (minimal load/store). */
    CPRISK_VM_OP_VREG_MEM = 19u,
    /** Byte-lane subtract (wrapping uint8) — AArch64 SUB surrogate. */
    CPRISK_VM_OP_SUB_LANE = 20u,
    /** Byte-lane multiply mod 256 — AArch64 MADD-as-MUL surrogate. */
    CPRISK_VM_OP_MUL_LANE = 21u,
    CPRISK_VM_OP_POISON = 0xFFu
};

/** `cprisk_vmp_bytecode_entry_t::reserved` extended profile marker in bits 24...31. */
#define CPRISK_VMP_ENTRY_PROFILE_MAGIC 0xA5u
/** Bits 16...19 encode `(max_subcall_depth - 1)` when profile marker is present. */
#define CPRISK_VMP_ENTRY_SUBCALL_DEPTH_SHIFT 16u
/** Bits 12...15 encode mixed predicate profile id when profile marker is present. */
#define CPRISK_VMP_ENTRY_MIXED_PRED_SHIFT 12u
/** Bits 8...11 encode semantic family id when profile marker is present. */
#define CPRISK_VMP_ENTRY_SEMANTIC_FAMILY_SHIFT 8u

typedef struct cprisk_vmp_dispatch_header {
    uint32_t magic;
    uint32_t version;
    uint32_t class_table_size;
    uint32_t flags;
} cprisk_vmp_dispatch_header_t;

typedef struct cprisk_vmp_bytecode_header {
    uint32_t magic;
    uint32_t version;
    uint32_t entry_count;
    /** Legacy: 0. M2: \c CPRISK_VMP_BC_FLAG_* ; low bits may select handler variant seed. */
    uint32_t reserved;
} cprisk_vmp_bytecode_header_t;

typedef struct cprisk_vmp_bytecode_entry {
    uint64_t function_id;
    uint64_t original_entry_vma;
    uint32_t tier;
    uint32_t bytecode_offset;
    uint32_t bytecode_length;
    uint32_t reserved;
} cprisk_vmp_bytecode_entry_t;

typedef struct cprisk_vm_run_result {
    uint32_t status;
    uint32_t poison_flags;
    uint32_t whitebox_domain_rc;
    uint8_t acc[32];
    uint64_t steps;
    uint32_t last_opcode;
    uint32_t last_dispatch_class;
    /** Eight virtual 64-bit GPRs (interpreter-visible state at VM halt). */
    uint64_t vregs[8];
} cprisk_vm_run_result_t;

/// Execute VM bytecode for the given function id.
/// Returns a 64-bit value folded from VM accumulator (reserved for ABI compatibility).
uint64_t cprisk_vm_entry(uint64_t func_id);

/// Alternate VM entry symbols (same semantics as \c cprisk_vm_entry); kept distinct for CFF / linker \c -u wiring.
uint64_t cprisk_vm_entry_alt1(uint64_t func_id);
uint64_t cprisk_vm_entry_alt2(uint64_t func_id);

/// Debug/testing entry: execute VM and emit detailed run result.
/// Returns 0 on success, -1 on invalid input.
int cprisk_vm_execute(uint64_t func_id, cprisk_vm_run_result_t *out);

/// Returns \c CPRISK_ARMOR_CAP_VMP_RUNTIME when both VMP sections parse as minimally valid.
uint32_t cprisk_vm_query_armor_capability_bits(void);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_VM_INTERPRETER_H */
