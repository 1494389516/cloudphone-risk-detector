/*
 *  vm_antidebug_inline.h
 *  CRiskCore
 */

#ifndef VM_ANTIDEBUG_INLINE_H
#define VM_ANTIDEBUG_INLINE_H

#include <stdint.h>
#include <stddef.h>
#include <signal.h>

#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VM_ADB_CLEAN = 0,
    VM_ADB_DETECTED_DEBUGGER = 1,
    VM_ADB_DETECTED_HW_BP = 2,
    VM_ADB_DETECTED_SW_BP = 3,
    VM_ADB_DETECTED_EX_PORT = 4,
    VM_ADB_DETECTED_TIMING = 5,
    VM_ADB_ERROR = 255
} vm_antidebug_result_t;

typedef enum {
    VM_ADB_RESPONSE_POISON = 0,
    VM_ADB_RESPONSE_STALL = 1,
    VM_ADB_RESPONSE_MISLEAD = 2,
    VM_ADB_RESPONSE_CRASH = 3
} vm_antidebug_response_t;

typedef enum {
    VM_ADB_TRAP_SIGNAL = 0,
    VM_ADB_TRAP_ILLEGAL = 1,
    VM_ADB_TRAP_BRK = 2,
    VM_ADB_TRAP_UDF = 3
} vm_antidebug_trap_type_t;

typedef struct {
    uint64_t func_id;
    uint32_t check_count;
    uint32_t check_interval;
    uint64_t baseline_cycles;
    uint8_t  debugger_detected;
    uint8_t  hw_breakpoint_detected;
    uint8_t  sw_breakpoint_detected;
    uint8_t  exception_port_hijacked;
    uint8_t  timing_anomaly;
    uint8_t  response_triggered;
    uint8_t  poison_applied;
    uint8_t  response_mode;
} vm_antidebug_ctx_t;

void vm_antidebug_init(vm_antidebug_ctx_t *ctx, uint64_t func_id);

vm_antidebug_result_t vm_antidebug_check_all(vm_antidebug_ctx_t *ctx);

void vm_antidebug_apply_response(vm_antidebug_ctx_t *ctx,
                                  cprisk_vm_interp_frame_t *fr);

cprisk_vm_flow_t vm_op_antidebug_check_execute(cprisk_vm_interp_frame_t *fr,
                                                uint64_t imm);

cprisk_vm_flow_t vm_op_antidebug_trap_execute(cprisk_vm_interp_frame_t *fr,
                                               uint64_t imm);

cprisk_vm_flow_t vm_op_antidebug_decoy_execute(cprisk_vm_interp_frame_t *fr,
                                                uint64_t imm);

void vm_antidebug_apply_to_interp(cprisk_vm_interp_frame_t *fr);

uint32_t vm_antidebug_get_detected_flags(vm_antidebug_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
