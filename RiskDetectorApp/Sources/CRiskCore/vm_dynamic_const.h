/*
 *  vm_dynamic_const.h
 *  CRiskCore
 */

#ifndef VM_DYNAMIC_CONST_H
#define VM_DYNAMIC_CONST_H

#include <stdint.h>
#include <stddef.h>

#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VM_CONST_DERIVE_DOMAIN_BASE     10
#define VM_CONST_DERIVE_DOMAIN_RND      10
#define VM_CONST_DERIVE_DOMAIN_THRESH   11
#define VM_CONST_DERIVE_DOMAIN_MAGIC    12
#define VM_CONST_DERIVE_DOMAIN_CHECK    13
#define VM_CONST_DERIVE_DOMAIN_MASK     14
#define VM_CONST_DERIVE_DOMAIN_KEY      15

typedef enum {
    VM_DERIVE_OP_LOAD_ACC = 0,
    VM_DERIVE_OP_XOR_ACC = 1,
    VM_DERIVE_OP_ADD_ACC = 2,
    VM_DERIVE_OP_CMP_THRESH = 3,
    VM_DERIVE_OP_MASK_ACC = 4,
    VM_DERIVE_OP_MIX_STATE = 5,
} vm_derive_op_type_t;

uint32_t vm_const_derive_via_whitebox(uint32_t domain,
                                       uint64_t func_id,
                                       uint32_t seed);

uint32_t vm_const_derive_cmp_threshold(uint64_t func_id, uint32_t threshold_type);

uint32_t vm_const_derive_magic(uint64_t func_id, uint32_t magic_type);

uint32_t vm_const_derive_check_value(uint64_t func_id, uint32_t check_type);

uint32_t vm_const_derive_mask(uint64_t func_id, uint32_t mask_type, uint8_t bit_width);

int vm_const_derive_key_material(uint64_t func_id,
                                  uint32_t key_index,
                                  uint8_t key_out[32]);

cprisk_vm_flow_t vm_op_load_rnd_execute(cprisk_vm_interp_frame_t *fr,
                                         uint64_t imm);

cprisk_vm_flow_t vm_op_derive_execute(cprisk_vm_interp_frame_t *fr,
                                       uint64_t imm);

int vm_const_hash_function_identity(uint64_t func_id,
                                     const uint8_t *bytecode,
                                     size_t bytecode_len,
                                     uint8_t hash_out[32]);

uint32_t vm_const_derive_from_identity(uint64_t func_id, uint32_t const_index);

void vm_dynamic_const_apply_to_interp(cprisk_vm_interp_frame_t *fr);

void vm_dynamic_const_reset_for_func(uint64_t func_id);

uint32_t vm_const_get_func_cmp_threshold(uint64_t func_id,
                                          uint32_t cmp_type,
                                          uint32_t base_value);

#ifdef __cplusplus
}
#endif

#endif
