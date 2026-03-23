#ifndef CPRISK_VM_INTERPRETER_OPS_H
#define CPRISK_VM_INTERPRETER_OPS_H

/**
 * Opcode-handler helpers implemented in \c cprisk_vm_interpreter.c and callable from
 * \c cprisk_vm_oph_*.c translation units. They are intentionally not \c static so the VM
 * core stays in one TU while handler bodies are split for compilation-unit dispersion.
 */

#include "cprisk_vm_interpreter.h"
#include <stdint.h>

uint64_t cprisk_read_le_u64_i(const uint8_t *p);

void cprisk_vmp_read_vpc_affine_i(const uint8_t *b_sec,
                                    const cprisk_vmp_bytecode_header_t *bh,
                                    uint64_t *out_a,
                                    uint64_t *out_b);

uint32_t cprisk_vmp_avalanche32_i(uint32_t x);

uint64_t cprisk_vmp_raw_lane_mask_u64_i(uint64_t func_id, uint32_t pc_index, uint64_t bind_root);

void cprisk_vm_poison_mix_unknown_i(uint8_t acc[32], uint32_t opcode, uint32_t cls);

int cprisk_vm_encode_pc_i(const cprisk_vmp_bytecode_header_t *bh,
                          uint32_t pc,
                          uint64_t vpc_a,
                          uint64_t vpc_b,
                          uint64_t *out_enc,
                          cprisk_vm_run_result_t *out);

int cprisk_vm_enc_pc_advance_ctx_i(const cprisk_vmp_bytecode_header_t *bh,
                                   uint64_t *enc_pc,
                                   uint64_t vpc_a,
                                   uint64_t vpc_b,
                                   cprisk_vm_run_result_t *out);

int cprisk_vm_set_branch_target_ctx_i(const cprisk_vmp_bytecode_header_t *bh,
                                      uint64_t *enc_pc,
                                      uint64_t vpc_a,
                                      uint64_t vpc_b,
                                      uint32_t blen,
                                      uint32_t pc,
                                      int64_t delta_bytes,
                                      cprisk_vm_run_result_t *out);

void cprisk_vm_raw_region_apply_i(uint8_t acc[32],
                                  uint64_t imm,
                                  uint32_t steps,
                                  uint32_t variant,
                                  uint32_t semantic_family,
                                  uint64_t func_id,
                                  uint32_t pc);

void cprisk_vm_add_apply_i(uint8_t acc[32],
                           uint64_t imm,
                           uint32_t steps,
                           uint32_t variant,
                           uint32_t semantic_family,
                           uint64_t func_id,
                           uint32_t pc);

void cprisk_vm_lane_apply_poly_i(uint8_t acc[32],
                                 uint32_t family,
                                 uint64_t imm,
                                 uint32_t steps,
                                 uint32_t variant,
                                 uint32_t semantic_family,
                                 uint64_t func_id,
                                 uint32_t pc,
                                 uint32_t route);

int cprisk_vm_branch_cond_mixed_eval_i(uint32_t insn,
                                       const uint8_t acc[32],
                                       uint64_t steps,
                                       uint32_t semantic_family,
                                       uint32_t mixed_profile,
                                       int *out_taken,
                                       int64_t *out_delta_bytes);

void cprisk_vm_bitwise_lane_poly_i(uint8_t acc[32],
                                   uint32_t logical,
                                   uint64_t imm,
                                   uint32_t steps,
                                   uint32_t variant,
                                   uint32_t semantic_family,
                                   uint32_t route);

void cprisk_vm_rol_acc_i(uint8_t acc[32], uint64_t imm);

void cprisk_vm_vreg_mov_i(uint64_t vregs[8], const uint8_t acc[32], uint64_t imm);

void cprisk_vm_vreg_alu_i(uint64_t vregs[8], uint64_t imm);

void cprisk_vm_vreg_mem_i(uint64_t vregs[8], uint8_t acc[32], uint64_t imm);

int cprisk_vm_entry_profile_decode_i(uint32_t entry_reserved,
                                     uint32_t *semantic_family,
                                     uint32_t *mixed_predicate_profile,
                                     uint32_t *max_subcall_depth);

void cprisk_vm_entry_profile_fallback_i(uint64_t func_id,
                                        uint32_t hdr_reserved,
                                        uint32_t *semantic_family,
                                        uint32_t *mixed_predicate_profile,
                                        uint32_t *max_subcall_depth);

#endif /* CPRISK_VM_INTERPRETER_OPS_H */
