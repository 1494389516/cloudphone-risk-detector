#ifndef CPRISK_VM_OPH_VARIANTS_H
#define CPRISK_VM_OPH_VARIANTS_H

/*
 * cprisk_vm_oph_variants.h
 *
 * Polymorphic variant pool selectors — see cprisk_vm_oph_variants.c for
 * design rationale (Capstone L1/L2 cache busting via multi-body handlers).
 *
 * The cprisk_vm_oph_select_* functions are drop-in replacements for the
 * canonical handlers in cprisk_vm_oph_table.c.  They choose among N
 * semantically-equivalent variant bodies at runtime, so the ARM64 code
 * addresses executed for a given opcode differ across invocations.
 */

#include "cprisk_vm_interpreter_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Variant bodies (exposed for testing) */
cprisk_vm_flow_t cprisk_vm_oph_nop_v0(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_nop_v1(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_nop_v2(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);

cprisk_vm_flow_t cprisk_vm_oph_xor_mix_v0(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_xor_mix_v1(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_xor_mix_v2(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);

cprisk_vm_flow_t cprisk_vm_oph_add_v0(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_add_v1(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_add_v2(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);

/* Runtime selectors — use these in cprisk_vm_oph_table.c */
cprisk_vm_flow_t cprisk_vm_oph_select_nop    (cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_select_xor_mix(cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);
cprisk_vm_flow_t cprisk_vm_oph_select_add    (cprisk_vm_interp_frame_t *fr, uint8_t op_raw, uint8_t logical, uint64_t imm, uint32_t pc, uint32_t hvar);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_VM_OPH_VARIANTS_H */
