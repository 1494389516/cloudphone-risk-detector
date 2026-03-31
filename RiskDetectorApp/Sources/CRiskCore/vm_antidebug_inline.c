/*
 *  vm_antidebug_inline.c
 *  CRiskCore
 */

#include "include/CRiskCore.h"
#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "vm_antidebug_inline.h"

#include <string.h>

/* Frame stores adb context as opaque bytes; access via cast. */
#define VM_ADB_CTX_OF(fr_) ((vm_antidebug_ctx_t *)(void *)((fr_)->adb_ctx_storage))

#if defined(__APPLE__)
#include <TargetConditionals.h>
#if defined(TARGET_OS_IOS) && TARGET_OS_IOS
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/task.h>
#endif
#endif

#define VM_ADB_MAGIC_POISON     0xDEADBEEFu
#define VM_ADB_CHECK_INTERVAL   32

#if defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS
static int vm_adb_is_debugger_attached_i(void) {
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };

    memset(&info, 0, sizeof(info));

    if (sysctl(mib, 4, &info, &info_size, NULL, 0) == -1) {
        return -1;
    }

    return (info.kp_proc.p_flag & P_TRACED) ? 1 : 0;
}

static int vm_adb_check_hw_breakpoint_i(void) {
#if defined(__arm64__) || defined(__aarch64__)
    thread_act_t thread = mach_thread_self();
    arm_debug_state64_t state;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr;

    kr = thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&state, &count);
    mach_port_deallocate(mach_task_self(), thread);

    if (kr != KERN_SUCCESS) {
        return -1;
    }

    for (int i = 0; i < 6; i++) {
        if (state.__bvr[i] != 0 || state.__bcr[i] != 0) {
            return 1;
        }
    }

    return 0;
#else
    return 0;
#endif
}

static int vm_adb_check_sw_breakpoint_i(uintptr_t addr) {
    if (addr == 0) {
        return 0;
    }

    uint32_t inst;
    memcpy(&inst, (void *)addr, sizeof(inst));

    if (inst == 0xD4200000 || inst == 0xD4A00000) {
        return 1;
    }

    if ((inst & 0xFFE0001F) == 0xD4200000) {
        return 1;
    }

    return 0;
}

static int vm_adb_check_exception_port_i(void) {
    mach_port_t port = MACH_PORT_NULL;
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = 0;
    kern_return_t kr;

    kr = task_get_exception_ports(mach_task_self(), EXC_MASK_ALL,
                                   masks, &count, ports, behaviors, flavors);

    if (kr != KERN_SUCCESS) {
        return -1;
    }

    int result = 0;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (ports[i] != MACH_PORT_NULL) {
            if (ports[i] != mach_task_self()) {
                result = 1;
            }
            mach_port_deallocate(mach_task_self(), ports[i]);
        }
    }

    return result;
}

static uint64_t vm_adb_read_instructions_retired_i(void) {
#if defined(__arm64__) || defined(__aarch64__)
    uint64_t value = 0;

    __asm__ __volatile__ (
        "mrs %0, PMCCNTR_EL0" : "=r" (value)
    );

    return value;
#else
    return 0;
#endif
}

static int vm_adb_check_timing_anomaly_i(vm_antidebug_ctx_t *ctx) {
    if (!ctx) {
        return -1;
    }

    uint64_t start_cycles = vm_adb_read_instructions_retired_i();

    volatile uint64_t dummy = 0;
    for (int i = 0; i < 100; i++) {
        dummy ^= (uint64_t)i * 0x9E3779B97F4A7C15ULL;
    }

    (void)dummy;

    uint64_t end_cycles = vm_adb_read_instructions_retired_i();
    uint64_t elapsed = end_cycles - start_cycles;

    if (ctx->baseline_cycles == 0) {
        ctx->baseline_cycles = elapsed;
        return 0;
    }

    uint64_t threshold = ctx->baseline_cycles * 3;
    if (elapsed > threshold && ctx->check_count > 5) {
        return 1;
    }

    ctx->baseline_cycles = (ctx->baseline_cycles * 7 + elapsed) / 8;

    return 0;
}
#endif

void vm_antidebug_init(vm_antidebug_ctx_t *ctx, uint64_t func_id) {
    if (!ctx) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->func_id = func_id;
    ctx->check_interval = VM_ADB_CHECK_INTERVAL;
    ctx->response_mode = VM_ADB_RESPONSE_POISON;

#if defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS
    uint64_t start = vm_adb_read_instructions_retired_i();

    volatile uint64_t temp = 0;
    for (int i = 0; i < 100; i++) {
        temp ^= i;
    }

    (void)temp;

    ctx->baseline_cycles = vm_adb_read_instructions_retired_i() - start;
#endif
}

vm_antidebug_result_t vm_antidebug_check_all(vm_antidebug_ctx_t *ctx) {
    if (!ctx) {
        return VM_ADB_ERROR;
    }

    ctx->check_count++;

    if ((ctx->check_count % ctx->check_interval) != 0) {
        return VM_ADB_CLEAN;
    }

#if defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS
    int debugger = vm_adb_is_debugger_attached_i();
    if (debugger > 0) {
        ctx->debugger_detected = 1;
        return VM_ADB_DETECTED_DEBUGGER;
    }

    int hw_bp = vm_adb_check_hw_breakpoint_i();
    if (hw_bp > 0) {
        ctx->hw_breakpoint_detected = 1;
        return VM_ADB_DETECTED_HW_BP;
    }

    int ex_port = vm_adb_check_exception_port_i();
    if (ex_port > 0) {
        ctx->exception_port_hijacked = 1;
        return VM_ADB_DETECTED_EX_PORT;
    }

    int timing = vm_adb_check_timing_anomaly_i(ctx);
    if (timing > 0) {
        ctx->timing_anomaly = 1;
        return VM_ADB_DETECTED_TIMING;
    }
#endif

    return VM_ADB_CLEAN;
}

void vm_antidebug_apply_response(vm_antidebug_ctx_t *ctx,
                                  cprisk_vm_interp_frame_t *fr) {
    if (!ctx || !fr) {
        return;
    }

    if (!ctx->debugger_detected && !ctx->hw_breakpoint_detected &&
        !ctx->sw_breakpoint_detected && !ctx->exception_port_hijacked &&
        !ctx->timing_anomaly) {
        return;
    }

    switch (ctx->response_mode) {
        case VM_ADB_RESPONSE_POISON: {
            fr->opaque_chain ^= VM_ADB_MAGIC_POISON;
            fr->session_mix = (fr->session_mix * 0xC2B2AE35u) ^ VM_ADB_MAGIC_POISON;

            for (int i = 0; i < 32; i++) {
                fr->acc[i] ^= (uint8_t)(VM_ADB_MAGIC_POISON >> ((i % 4) * 8));
                fr->acc_aux[i] ^= (uint8_t)(VM_ADB_MAGIC_POISON >> (((i + 2) % 4) * 8));
            }

            ctx->poison_applied = 1;
            break;
        }

        case VM_ADB_RESPONSE_STALL: {
            fr->adb_stall_count += 1000;
            break;
        }

        case VM_ADB_RESPONSE_MISLEAD: {
            fr->cff_vpc = fr->cff_vpc ^ 0xDEADBEEFu;
            fr->opaque_chain ^= 0xCAFEBABEu;
            break;
        }

        case VM_ADB_RESPONSE_CRASH: {
            *(volatile uint32_t *)0 = 0xDEADBEEF;
            break;
        }

        default:
            break;
    }

    ctx->response_triggered = 1;
}

cprisk_vm_flow_t vm_op_antidebug_check_execute(cprisk_vm_interp_frame_t *fr,
                                                uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    uint32_t check_type = imm & 0xF;
    uint32_t check_depth = (imm >> 4) & 0xF;

    (void)check_depth;

    vm_antidebug_result_t result = VM_ADB_CLEAN;

#if defined(__APPLE__) && defined(TARGET_OS_IOS) && TARGET_OS_IOS
    switch (check_type) {
        case 0:
            result = vm_antidebug_check_all(VM_ADB_CTX_OF(fr));
            break;
        case 1:
            result = vm_adb_is_debugger_attached_i() > 0 ? VM_ADB_DETECTED_DEBUGGER : VM_ADB_CLEAN;
            break;
        case 2:
            result = vm_adb_check_hw_breakpoint_i() > 0 ? VM_ADB_DETECTED_HW_BP : VM_ADB_CLEAN;
            break;
        case 3:
            result = vm_adb_check_exception_port_i() > 0 ? VM_ADB_DETECTED_EX_PORT : VM_ADB_CLEAN;
            break;
        case 4:
            result = vm_adb_check_timing_anomaly_i(VM_ADB_CTX_OF(fr)) > 0 ? VM_ADB_DETECTED_TIMING : VM_ADB_CLEAN;
            break;
        default:
            result = VM_ADB_CLEAN;
            break;
    }
#endif

    fr->acc[0] = (uint8_t)result;

    if (result != VM_ADB_CLEAN) {
        vm_antidebug_apply_response(VM_ADB_CTX_OF(fr), fr);
    }

    return CPRISK_VM_FLOW_CONTINUE;
}

cprisk_vm_flow_t vm_op_antidebug_trap_execute(cprisk_vm_interp_frame_t *fr,
                                               uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    uint32_t trap_type = imm & 0xFF;

    switch (trap_type) {
        case VM_ADB_TRAP_SIGNAL: {
            raise(SIGTRAP);
            break;
        }

        case VM_ADB_TRAP_ILLEGAL: {
#if defined(__arm64__) || defined(__aarch64__)
            __asm__ __volatile__(".word 0xFFFFFFFF");
#else
            raise(SIGILL);
#endif
            break;
        }

        case VM_ADB_TRAP_BRK: {
#if defined(__arm64__) || defined(__aarch64__)
            __asm__ __volatile__("brk #0xC0DE");
#else
            __builtin_trap();
#endif
            break;
        }

        case VM_ADB_TRAP_UDF: {
#if defined(__arm64__) || defined(__aarch64__)
            __asm__ __volatile__(".word 0x00000000");
#else
            raise(SIGILL);
#endif
            break;
        }

        default: {
            volatile uint32_t *invalid = (volatile uint32_t *)0xDEADBEEF;
            *invalid = 0xCAFEBABE;
            break;
        }
    }

    return CPRISK_VM_FLOW_LEAVE;
}

cprisk_vm_flow_t vm_op_antidebug_decoy_execute(cprisk_vm_interp_frame_t *fr,
                                                uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    uint32_t decoy_type = imm & 0xF;
    (void)decoy_type;

    volatile uint64_t decoy_var = 0;
    for (int i = 0; i < 100; i++) {
        decoy_var ^= (uint64_t)i * 0x9E3779B97F4A7C15ULL;
        decoy_var = ((decoy_var << 7) | (decoy_var >> 57));
    }

    fr->opaque_chain ^= (uint32_t)(decoy_var ^ (decoy_var >> 32));

    return CPRISK_VM_FLOW_CONTINUE;
}

void vm_antidebug_apply_to_interp(cprisk_vm_interp_frame_t *fr) {
    if (!fr) {
        return;
    }

    vm_antidebug_init(VM_ADB_CTX_OF(fr), fr->func_id);
    VM_ADB_CTX_OF(fr)->response_mode = VM_ADB_RESPONSE_POISON;
}

uint32_t vm_antidebug_get_detected_flags(vm_antidebug_ctx_t *ctx) {
    if (!ctx) {
        return 0;
    }

    uint32_t flags = 0;
    if (ctx->debugger_detected) flags |= 0x01;
    if (ctx->hw_breakpoint_detected) flags |= 0x02;
    if (ctx->sw_breakpoint_detected) flags |= 0x04;
    if (ctx->exception_port_hijacked) flags |= 0x08;
    if (ctx->timing_anomaly) flags |= 0x10;
    if (ctx->response_triggered) flags |= 0x80;

    return flags;
}
