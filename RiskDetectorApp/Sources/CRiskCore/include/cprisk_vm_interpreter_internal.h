#ifndef CPRISK_VM_INTERPRETER_INTERNAL_H
#define CPRISK_VM_INTERPRETER_INTERNAL_H

#include "cprisk_vm_interpreter.h"
#include "cprisk_vm_interpreter_limits.h"
#include "cprisk_vm_sync_barrier.h"
#include "cprisk_emulator_detect.h"

#include <stddef.h>
#include <stdint.h>

/** Shared SplitMix64 PRNG step (used by VPC affine mask derivation and other cross-TU utilities). */
static inline uint64_t cprisk_splitmix64_next_i(uint64_t *state) {
    *state += UINT64_C(0x9E3779B97F4A7C15);
    uint64_t z = *state;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

struct mach_header_64;
struct cprisk_vm_interp_frame;
typedef struct cprisk_vm_interp_frame cprisk_vm_interp_frame_t;

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
    uint8_t snap_acc_lane_map[3]; /* caller's per-function lane permutation */
    uint8_t snap_acc_lane_pad;   /* explicit alignment pad */
} cprisk_vm_vmcall_snap_t;

struct cprisk_vm_interp_frame {
    const struct mach_header_64 *hdr;
    const uint8_t *b_sec;
    unsigned long bsz;
    const cprisk_vmp_bytecode_header_t *bh;
    const uint8_t *dispatch_sec;
    const cprisk_vmp_dispatch_header_t *dispatch_hdr;
    uint32_t dispatch_hdr_flags;
    uint64_t dispatch_decode_seed;
    uint32_t dispatch_cache_base;
    uint32_t dispatch_cache_count;
    uint8_t dispatch_cache[CPRISK_VM_DISPATCH_CACHE_BYTES];
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
    uint32_t session_mix;
    /** Per-function accumulator lane permutation: acc_lane_map[i] maps the i-th
     *  opcode family (0=add, 1=sub, 2=mul) to the physical lane index passed to
     *  cprisk_vm_lane_apply_poly_i.  Decoded from entry->reserved bits [2:0] at
     *  frame init; defaults to identity {0,1,2} for legacy (no-magic) entries. */
    uint8_t acc_lane_map[3];
    uint8_t acc_lane_pad; /* alignment */
    uint64_t decode_fault_mask;
    int32_t opaque_pid;
    int32_t opaque_clock_rc;
    int32_t opaque_port_rc;
    uint32_t opaque_rt_nonce;
    uint32_t opaque_chain;
    uint32_t opaque_runtime_fold;
    uint32_t opaque_session_mix;
    uint32_t opaque_thread_mix;
    uint32_t opaque_clock_ns;
    uint32_t opaque_port_name;

    /** When non-zero, \c bc_seg_hash_expect is valid; interpreter re-hashes bytecode periodically. */
    uint32_t bc_seg_hash_enabled;
    uint32_t bc_last_hash_step;
    uint8_t bc_seg_hash_expect[32];

    /**
     * When non-zero, \c cprisk_vm_dispatch_leaf_wb_wrapped_i already ran domain-7 WB + opaque apply for this insn
     * (currently \c CPRISK_VM_OP_XOR_MIX only); \c cprisk_vm_oph_post_handler_i skips duplicate WB side effects
     * (still runs bytecode hash checks).
     */
    uint32_t vm_wb_inline_done;

    uint8_t acc[CPRISK_VM_ACC_PRIMARY_BYTES];
    uint8_t acc_aux[CPRISK_VM_ACC_AUX_BYTES];
    uint8_t trace_scratch[64];
    uint64_t trace_shadow[4];

    uint64_t steps;
    /** Per-run step ceiling (function/session-derived); <= \c CPRISK_VM_MAX_STEPS. */
    uint64_t step_limit_cap;

    /* ── Integrated hardening modules (Tasks 1-5) ── */

    /** Task 1: VM state integrity (vm_integrity.h) */
    uint32_t vm_integrity_magic;        /* VM_INT_MAGIC_ACTIVE marker */
    uint32_t vm_integrity_version;      /* version seed */
    uint64_t vm_integrity_exec_count;   /* monotonic execution count */
    uint64_t vm_integrity_checksum;     /* FNV-1a variant chain */
    uint8_t  vm_integrity_tag[8];       /* integrity label */
    uint8_t  vm_integrity_corrupted;    /* tamper detected flag */

    /** Task 3: Runtime on-demand decryption context */
    uint32_t decrypt_current_block;     /* currently decrypted basic block ID */
    uint32_t decrypt_block_count;       /* total basic blocks */
    uint64_t decrypt_block_key;         /* per-block XOR key derived from func_id */
    uint8_t  decrypt_block_map[64];     /* bit map: block is currently decrypted */
    uint8_t  decrypt_code_copy[256];    /* scratch for decrypt-encrypt cycle */

    /** Task 4: Path explosion context (vm_path_explosion.h) */
    uint64_t pe_func_id;               /* function id for path explosion */
    uint32_t pe_bytecode_hash;          /* condensed hash of bytecode */
    uint32_t pe_fork_counter;           /* number of fork checkpoints passed */
    uint32_t pe_decoy_counter;          /* number of decoy sequences executed */
    uint32_t pe_mba_accumulator;        /* MBA state accumulator */
    uint32_t pe_mba_xor_mask;           /* MBA xor mask */
    uint8_t  pe_path_marker[32];        /* per-path marker bytes */

    /** Anti-debug inline context (vm_antidebug_inline.h)
     *  Opaque storage sized to hold vm_antidebug_ctx_t; accessed via (vm_antidebug_ctx_t*) cast. */
    uint8_t  adb_ctx_storage[48];  /* >= sizeof(vm_antidebug_ctx_t), aligned via uint64_t below */
    uint32_t adb_stall_count;
    uint64_t adb_ctx_align_;       /* alignment padding */

    /** Task 5: VM×CFF deep fusion (vm_cff_fusion.h) */
    uint32_t cff_rk[8];                /* Feistel round keys */
    uint32_t cff_encoded_state;        /* CFF encoded state */
    uint32_t cff_magic;                /* CFF init marker */
    uint32_t cff_trace_buffer[16];     /* encoded PC trace */
    uint32_t cff_trace_pos;            /* trace position */
    uint8_t  cff_bytecode_hash[32];    /* hash for key derivation */
    uint8_t  cff_state_encoded;        /* 1 if encoding active */
    uint8_t  cff_corruption_detected;  /* integrity violation flag */
    uint64_t cff_vpc;                  /* CFF-managed virtual PC */

    /** VM sync barrier context: external data dependency every 64 steps */
    cprisk_vm_sync_barrier_ctx_t sync_barrier_ctx;

    /** C-layer emulator detection flags (CPRISK_EMU_FLAG_* bitmask).
     *  Set during cprisk_vm_hardening_init(); CPRISK_EMU_FLAG_WATCHDOG_STUCK
     *  is OR'd in at runtime when the sync barrier detects a frozen watchdog. */
    uint32_t emulator_flags;
};

/**
 * Opcode handler return: CONTINUE keeps the main VM loop; LEAVE exits to vm_leave_* (finish_run).
 * Used by indirect dispatch across the split \c cprisk_vm_oph_*.c translation units.
 */
typedef enum {
    CPRISK_VM_FLOW_CONTINUE = 0,
    CPRISK_VM_FLOW_LEAVE = 1,
} cprisk_vm_flow_t;

typedef cprisk_vm_flow_t (*cprisk_vm_oph_fn)(cprisk_vm_interp_frame_t *fr,
                                             uint8_t op_raw,
                                             uint8_t logical,
                                             uint64_t imm,
                                             uint32_t pc,
                                             uint32_t hvar);

/** Dense logical opcode indices 0..23 (see cprisk_vm_interpreter.h). POISON (0xFF) is not indexed here. */
#define CPRISK_VM_OPH_TABLE_LEN 24u

/**
 * Opcode handlers are still split across \c cprisk_vm_oph_*.c, but the runtime no longer exposes a
 * plaintext global handler-pointer table. The dispatcher in \c cprisk_vm_oph_table.c resolves a
 * family first, then materializes only the selected handler pointer for the current access.
 */
cprisk_vm_flow_t cprisk_vm_dispatch_oph_materialized_i(cprisk_vm_interp_frame_t *fr,
                                                       uint8_t op_raw,
                                                       uint8_t logical,
                                                       uint64_t imm,
                                                       uint32_t pc,
                                                       uint32_t hvar);

/**
 * Opcode dispatch wrapper: for \c CPRISK_VM_OP_XOR_MIX, session-bound white-box PRF on pre-handler state,
 * self-inverse acc XOR mask derived from PRF output, then materialized handler; opaque/session updates from PRF.
 * Other opcodes delegate to the materialized handler and \c cprisk_vm_oph_post_handler_i (periodic WB).
 */
cprisk_vm_flow_t cprisk_vm_dispatch_leaf_wb_wrapped_i(cprisk_vm_interp_frame_t *fr,
                                                      uint8_t op_raw,
                                                      uint8_t logical,
                                                      uint64_t imm,
                                                      uint32_t pc,
                                                      uint32_t hvar,
                                                      cprisk_vm_oph_fn materialized);

/**
 * Post-handler hook: session-bound white-box side effect + optional bytecode segment SHA256 checks.
 * \p inner is the flow returned by the materialized opcode handler.
 */
cprisk_vm_flow_t cprisk_vm_oph_post_handler_i(cprisk_vm_interp_frame_t *fr,
                                              uint8_t logical,
                                              uint64_t imm,
                                              uint32_t pc,
                                              uint32_t hvar,
                                              cprisk_vm_flow_t inner);

cprisk_vm_flow_t cprisk_vm_oph_poison(cprisk_vm_interp_frame_t *fr,
                                      uint8_t op_raw,
                                      uint8_t logical,
                                      uint64_t imm,
                                      uint32_t pc,
                                      uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_unknown(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);

cprisk_vm_flow_t cprisk_vm_oph_nop(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_halt(cprisk_vm_interp_frame_t *fr,
                                    uint8_t op_raw,
                                    uint8_t logical,
                                    uint64_t imm,
                                    uint32_t pc,
                                    uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_ret(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_raw_region(cprisk_vm_interp_frame_t *fr,
                                          uint8_t op_raw,
                                          uint8_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_add(cprisk_vm_interp_frame_t *fr,
                                   uint8_t op_raw,
                                   uint8_t logical,
                                   uint64_t imm,
                                   uint32_t pc,
                                   uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_add_rol_acc(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw,
                                            uint8_t logical,
                                            uint64_t imm,
                                            uint32_t pc,
                                            uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_sub_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_mul_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_branch_rel(cprisk_vm_interp_frame_t *fr,
                                          uint8_t op_raw,
                                          uint8_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_branch_ind(cprisk_vm_interp_frame_t *fr,
                                          uint8_t op_raw,
                                          uint8_t logical,
                                          uint64_t imm,
                                          uint32_t pc,
                                          uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_branch_cond(cprisk_vm_interp_frame_t *fr,
                                           uint8_t op_raw,
                                           uint8_t logical,
                                           uint64_t imm,
                                           uint32_t pc,
                                           uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_call(cprisk_vm_interp_frame_t *fr,
                                    uint8_t op_raw,
                                    uint8_t logical,
                                    uint64_t imm,
                                    uint32_t pc,
                                    uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_xor_mix(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_or_lane(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_and_lane(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_rol_acc(cprisk_vm_interp_frame_t *fr,
                                       uint8_t op_raw,
                                       uint8_t logical,
                                       uint64_t imm,
                                       uint32_t pc,
                                       uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_vm_call_func(cprisk_vm_interp_frame_t *fr,
                                            uint8_t op_raw,
                                            uint8_t logical,
                                            uint64_t imm,
                                            uint32_t pc,
                                            uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_vreg_mov(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_vreg_alu(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_vreg_mem(cprisk_vm_interp_frame_t *fr,
                                        uint8_t op_raw,
                                        uint8_t logical,
                                        uint64_t imm,
                                        uint32_t pc,
                                        uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_mov_wide   (cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_adr_add   (cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_cond_select(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_load_store (cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);

#endif /* CPRISK_VM_INTERPRETER_INTERNAL_H */
