#ifndef CPRISK_VM_INTERPRETER_INTERNAL_H
#define CPRISK_VM_INTERPRETER_INTERNAL_H

#include "cprisk_vm_interpreter.h"
#include "cprisk_vm_interpreter_limits.h"

#include <stddef.h>
#include <stdint.h>

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
    uint64_t decode_fault_mask;
    int32_t opaque_pid;
    int32_t opaque_clock_rc;
    uint32_t opaque_rt_nonce;
    uint32_t opaque_chain;

    uint8_t acc[32];
    uint8_t trace_scratch[64];
    uint64_t trace_shadow[4];

    uint64_t steps;
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

/** Dense logical opcode indices 0..21 (see cprisk_vm_interpreter.h). POISON (0xFF) is not indexed here. */
#define CPRISK_VM_OPH_TABLE_LEN 22u

/**
 * Dense handler table: function pointers live in \c cprisk_vm_oph_table.c; opcode implementations are
 * split across \c cprisk_vm_oph_*.c. Main interpreter (\c cprisk_vm_interpreter.c) performs indirect
 * dispatch through this array (\c cprisk_vm_dispatch_oph_core_i).
 */
extern const cprisk_vm_oph_fn cprisk_vm_oph_table[CPRISK_VM_OPH_TABLE_LEN];

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
cprisk_vm_flow_t cprisk_vm_oph_emitter_family(cprisk_vm_interp_frame_t *fr,
                                              uint8_t op_raw,
                                              uint8_t logical,
                                              uint64_t imm,
                                              uint32_t pc,
                                              uint32_t hvar);

#endif /* CPRISK_VM_INTERPRETER_INTERNAL_H */
