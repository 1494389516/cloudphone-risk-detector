/*
 * CRiskCore - Mach EXC_BREAKPOINT exception handler registration.
 * Preempts Frida/debugger from hijacking exception ports by registering first.
 * SDK 5.3: task_set_exception_ports + periodic verification.
 *
 * Caveats:
 * - Uses EXCEPTION_STATE_IDENTITY; handler advances PC past breakpoint and replies.
 * - __TVOS_PROHIBITED/__WATCHOS_PROHIBITED on task_* APIs: may be unavailable on tvOS/watchOS.
 */

#include "include/CRiskCore.h"
#include <mach/mach.h>
#include <mach/exception_types.h>
#include <mach/exc.h>
#include <mach/ndr.h>
#include <mach/arm/thread_status.h>
#include <mach/thread_status.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <TargetConditionals.h>

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR) && \
    (!defined(TARGET_OS_TV) || !TARGET_OS_TV) && \
    (!defined(TARGET_OS_WATCH) || !TARGET_OS_WATCH)

static mach_port_t s_exception_port = MACH_PORT_NULL;
static atomic_int s_registered = 0;
static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;
static cprisk_exception_handler_snapshot_t s_status = {
    .supported = 1u,
    .registered = 0u,
    .port_matches = 0u,
    .last_query_succeeded = 0u,
    .last_reclaim_attempted = 0u,
    .last_hijack_detected = 0u,
    .early_phase_captured = 0u,
    .last_race_detected = 0u,
    .last_query_kern_return = (int32_t)KERN_FAILURE,
    .last_register_kern_return = (int32_t)KERN_FAILURE,
    .verify_count = 0u,
    .reclaim_count = 0u,
};
static uint64_t s_early_port_fingerprint = 0u;
static uint32_t s_early_port_fingerprint_valid = 0u;
static uint32_t s_late_phase_checked = 0u;

#define EXC_EXCEPTION_RAISE_STATE_IDENTITY 2403
#define MACH_EXCEPTION_RAISE_STATE_IDENTITY 2407

#pragma pack(push, 4)
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
    int flavor;
    mach_msg_type_number_t old_stateCnt;
    natural_t old_state[1296];
} __Request__mach_exception_raise_state_identity_t;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
    int flavor;
    mach_msg_type_number_t new_stateCnt;
    natural_t new_state[1296];
} __Reply__mach_exception_raise_state_identity_t;
#pragma pack(pop)

extern int cprisk_exception_handler_should_passthrough_brk_imm(uint16_t brk_imm);
extern int cprisk_exception_handler_consume_reserved_brk_imm(uint16_t brk_imm);
extern int cprisk_exception_handler_handle_runtime_gate_brk(uint16_t brk_imm, uintptr_t brk_pc);

static uint64_t cprisk_mix64_i(uint64_t value) {
    value ^= value >> 33u;
    value *= 0xff51afd7ed558ccdULL;
    value ^= value >> 33u;
    value *= 0xc4ceb9fe1a85ec53ULL;
    value ^= value >> 33u;
    return value;
}

static uint64_t cprisk_exception_port_fingerprint_i(
    const exception_mask_t *masks,
    const mach_port_t *ports,
    const exception_behavior_t *behaviors,
    const thread_state_flavor_t *flavors,
    mach_msg_type_number_t count
) {
    uint64_t fingerprint = 0x43505249534B4558ULL; /* "CPRISKEX" */
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        uint64_t lane = ((uint64_t)(uint32_t)masks[i] << 32u) ^ (uint64_t)(uint32_t)ports[i];
        lane ^= ((uint64_t)(uint32_t)behaviors[i] << 16u);
        lane ^= (uint64_t)(uint32_t)flavors[i];
        lane ^= (uint64_t)i * 0x9E3779B97F4A7C15ULL;
        fingerprint ^= cprisk_mix64_i(lane);
        fingerprint = (fingerprint << 7u) | (fingerprint >> (64u - 7u));
        fingerprint ^= 0xA5A5A5A55A5A5A5AULL;
    }
    return fingerprint ^ ((uint64_t)count << 48u);
}

static int cprisk_query_exception_port_fingerprint_i(
    exception_mask_t query_mask,
    uint64_t *out_fingerprint
) {
    if (out_fingerprint == NULL) {
        return -1;
    }

    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    kern_return_t kr = task_get_exception_ports(
        mach_task_self(), query_mask, masks, &count, ports, behaviors, flavors);
    if (kr != KERN_SUCCESS) {
        return -1;
    }

    *out_fingerprint = cprisk_exception_port_fingerprint_i(
        masks, ports, behaviors, flavors, count);
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (ports[i] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), ports[i]);
        }
    }
    return 0;
}

static int cprisk_breakpoint_immediate_from_state_i(
    int flavor,
    mach_msg_type_number_t state_count,
    const natural_t *state,
    uint16_t *out_imm,
    uintptr_t *out_pc
) {
    if (out_imm == NULL || state == NULL ||
        flavor != ARM_THREAD_STATE64 ||
        state_count < ARM_THREAD_STATE64_COUNT) {
        if (out_pc != NULL) {
            *out_pc = 0u;
        }
        return 0;
    }

    arm_thread_state64_t thread_state;
    memset(&thread_state, 0, sizeof(thread_state));
    memcpy(&thread_state, state, sizeof(thread_state));

    const uintptr_t pc = (uintptr_t)thread_state.__pc;
    if (pc == 0u) {
        if (out_pc != NULL) {
            *out_pc = 0u;
        }
        return 0;
    }

    /* Verify the PC address is readable before dereferencing to avoid
       a nested fault inside the exception handler thread. */
    vm_size_t region_size = 0;
    vm_address_t region_addr = (vm_address_t)pc;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;
    kern_return_t kr = vm_region_64(mach_task_self(), &region_addr, &region_size,
                                     VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
                                     &info_count, &object_name);
    if (object_name != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), object_name);
    if (kr != KERN_SUCCESS || region_addr > (vm_address_t)pc ||
        (vm_address_t)pc + sizeof(uint32_t) > region_addr + region_size ||
        !(info.protection & VM_PROT_READ)) {
        if (out_pc != NULL) {
            *out_pc = 0u;
        }
        return 0;
    }

    uint32_t instr = 0u;
    memcpy(&instr, (const void *)pc, sizeof(instr));
    if ((instr & 0xFFE0001Fu) != 0xD4200000u) {
        if (out_pc != NULL) {
            *out_pc = 0u;
        }
        return 0;
    }

    *out_imm = (uint16_t)((instr >> 5) & 0xFFFFu);
    if (out_pc != NULL) {
        *out_pc = pc;
    }
    return 1;
}

static int cprisk_advance_thread_pc_i(
    int flavor,
    mach_msg_type_number_t state_count,
    natural_t *state
) {
    if (state == NULL ||
        flavor != ARM_THREAD_STATE64 ||
        state_count < ARM_THREAD_STATE64_COUNT) {
        return 0;
    }

    arm_thread_state64_t thread_state;
    memset(&thread_state, 0, sizeof(thread_state));
    memcpy(&thread_state, state, sizeof(thread_state));
    thread_state.__pc += 4u;
    memcpy(state, &thread_state, sizeof(thread_state));
    return 1;
}

static void *exception_handler_thread(void *arg) {
    (void)arg;
    char req_buf[sizeof(__Request__mach_exception_raise_state_identity_t)];
    char reply_buf[sizeof(__Reply__mach_exception_raise_state_identity_t)];
    mach_msg_header_t *req = (mach_msg_header_t *)req_buf;
    mach_msg_header_t *reply = (mach_msg_header_t *)reply_buf;

    for (;;) {
        memset(req_buf, 0, sizeof(req_buf));
        req->msgh_local_port = s_exception_port;
        req->msgh_size = sizeof(req_buf);

        kern_return_t kr = mach_msg(req, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                    req->msgh_size, s_exception_port, 100, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) {
            if (kr == MACH_RCV_TIMED_OUT)
                continue;
            break;
        }

        memset(reply_buf, 0, sizeof(reply_buf));
        reply->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req->msgh_bits), 0);
        reply->msgh_remote_port = req->msgh_remote_port;
        reply->msgh_local_port = MACH_PORT_NULL;
        reply->msgh_id = req->msgh_id + 100;

        if (req->msgh_id == MACH_EXCEPTION_RAISE_STATE_IDENTITY) {
            const __Request__mach_exception_raise_state_identity_t *r =
                (const __Request__mach_exception_raise_state_identity_t *)req;
            int flavor = r->flavor;
            mach_msg_type_number_t old_stateCnt = r->old_stateCnt;
            const natural_t *old_state = r->old_state;

            __Reply__mach_exception_raise_state_identity_t *rep =
                (__Reply__mach_exception_raise_state_identity_t *)reply;
            rep->NDR = NDR_record;
            rep->RetCode = KERN_SUCCESS;
            rep->flavor = flavor;
            rep->new_stateCnt = 0;

            mach_msg_type_number_t state_count = 0;
            if (flavor == ARM_THREAD_STATE64) {
                state_count = ARM_THREAD_STATE64_COUNT;
            } else if (flavor == ARM_THREAD_STATE) {
                state_count = ARM_THREAD_STATE_COUNT;
            } else {
                rep->RetCode = KERN_FAILURE;
            }

            if (old_stateCnt > 1296)
                old_stateCnt = 1296;

            if (state_count > 0 && rep->RetCode == KERN_SUCCESS) {
                if (old_stateCnt < state_count)
                    state_count = old_stateCnt;
                if (state_count > 1296)
                    state_count = 1296;
                rep->new_stateCnt = state_count;
                memcpy(rep->new_state, old_state, state_count * sizeof(natural_t));
                
                if (r->exception == EXC_BREAKPOINT) {
                    uint16_t brk_imm = 0u;
                    uintptr_t brk_pc = 0u;
                    const int have_brk_imm = cprisk_breakpoint_immediate_from_state_i(
                        flavor, state_count, old_state, &brk_imm, &brk_pc);

                    if (!cprisk_advance_thread_pc_i(flavor, rep->new_stateCnt, rep->new_state)) {
                        rep->RetCode = KERN_FAILURE;
                    } else if (have_brk_imm &&
                               cprisk_exception_handler_should_passthrough_brk_imm(brk_imm)) {
                        rep->RetCode = KERN_FAILURE;
                    } else if (have_brk_imm) {
                        const int gate_action =
                            cprisk_exception_handler_handle_runtime_gate_brk(brk_imm, brk_pc);
                        if (gate_action < 0) {
                            rep->RetCode = KERN_FAILURE;
                        } else if (gate_action == 0) {
                            (void)cprisk_exception_handler_consume_reserved_brk_imm(brk_imm);
                        }
                    }
                } else if (r->exception == EXC_BAD_ACCESS) {
                    void *fault_addr = (void *)(uintptr_t)r->code[1];
                    extern int cprisk_jit_decrypt_page(void *fault_addr);
                    if (cprisk_jit_decrypt_page(fault_addr)) {
                        rep->RetCode = KERN_SUCCESS;
                    } else {
                        rep->RetCode = KERN_FAILURE;
                    }
                } else {
                    rep->RetCode = KERN_FAILURE;
                }
            }

            rep->Head.msgh_size = sizeof(mach_msg_header_t) + sizeof(NDR_record_t) +
                sizeof(kern_return_t) + sizeof(int) + sizeof(mach_msg_type_number_t) +
                rep->new_stateCnt * sizeof(natural_t);
            mach_msg(&rep->Head, MACH_SEND_MSG, rep->Head.msgh_size, 0, MACH_PORT_NULL,
                     MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        }
    }
    return NULL;
}

/* Caller must hold s_mutex. */
static void register_locked(int reclaiming) {
    if (atomic_load(&s_registered))
        return;

    s_status.last_reclaim_attempted = reclaiming ? 1u : 0u;
    s_status.last_register_kern_return = (int32_t)KERN_FAILURE;
    s_status.registered = 0u;
    s_status.port_matches = 0u;

    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &s_exception_port);
    if (kr != KERN_SUCCESS) {
        s_status.last_register_kern_return = (int32_t)kr;
        return;
    }

    kr = mach_port_insert_right(mach_task_self(), s_exception_port, s_exception_port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), s_exception_port);
        s_exception_port = MACH_PORT_NULL;
        s_status.last_register_kern_return = (int32_t)kr;
        return;
    }

    exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS;
    exception_mask_t old_masks[EXC_TYPES_COUNT];
    mach_port_t old_ports[EXC_TYPES_COUNT];
    exception_behavior_t old_behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t old_flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t old_count = EXC_TYPES_COUNT;

    kr = task_swap_exception_ports(mach_task_self(), mask, s_exception_port,
                                   EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64,
                                   old_masks, &old_count, old_ports, old_behaviors, old_flavors);
    s_status.last_register_kern_return = (int32_t)kr;

    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), s_exception_port);
        s_exception_port = MACH_PORT_NULL;
        return;
    }

    for (mach_msg_type_number_t i = 0; i < old_count; i++) {
        if (old_ports[i] != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), old_ports[i]);
    }

    pthread_t th;
    int rc = pthread_create(&th, NULL, exception_handler_thread, NULL);
    if (rc != 0) {
        mach_port_deallocate(mach_task_self(), s_exception_port);
        s_exception_port = MACH_PORT_NULL;
        atomic_store(&s_registered, 0);
        return;
    }
    pthread_detach(th);

    atomic_store(&s_registered, 1);
    s_status.registered = 1u;
    s_status.port_matches = 1u;
    if (reclaiming) {
        s_status.reclaim_count += 1u;
    }
}

void cprisk_register_exception_handler(void) {
    pthread_mutex_lock(&s_mutex);
    register_locked(0);
    pthread_mutex_unlock(&s_mutex);
}

void cprisk_capture_early_exception_ports(void) {
    const exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS;
    uint64_t fingerprint = 0u;

    pthread_mutex_lock(&s_mutex);
    if (cprisk_query_exception_port_fingerprint_i(mask, &fingerprint) == 0) {
        s_early_port_fingerprint = fingerprint;
        s_early_port_fingerprint_valid = 1u;
        s_late_phase_checked = 0u;
        s_status.early_phase_captured = 1u;
    } else {
        s_early_port_fingerprint = 0u;
        s_early_port_fingerprint_valid = 0u;
        s_status.early_phase_captured = 0u;
    }
    pthread_mutex_unlock(&s_mutex);
}

/*
 * TLS 回调时序加固：__mod_init_func 阶段早期抢占验证
 *
 * dyld 初始化顺序：__DATA,__thread_init → __mod_init_func（C++ constructor）
 * Frida gadget 若也使用 __thread_init，其回调可能与 CRiskCore 交错执行。
 * 若 Frida 的 __thread_init 在 CRiskCore 之后执行，会覆盖我们已注册的异常端口。
 *
 * 本 constructor(101) 在 __mod_init_func 阶段执行，此时所有 __thread_init 已完成。
 * 调用 cprisk_verify_exception_handler() 检测端口是否被劫持，若发现非自己的端口
 * 则通过 task_swap_exception_ports 再次抢占，确保异常端口最终由 SDK 持有。
 *
 * 不依赖未公开 dyld 行为，仅利用公开的 constructor 在 mod_init_func 之后执行。
 */
__attribute__((constructor(101)))
static void cprisk_early_exception_port_reclaim(void) {
    cprisk_verify_exception_handler();
}

void cprisk_verify_exception_handler(void) {
    pthread_mutex_lock(&s_mutex);
    if (!atomic_load(&s_registered) || s_exception_port == MACH_PORT_NULL) {
        s_status.registered = 0u;
        s_status.port_matches = 0u;
        s_status.last_query_succeeded = 0u;
        pthread_mutex_unlock(&s_mutex);
        return;
    }

    s_status.verify_count += 1u;
    s_status.last_query_succeeded = 0u;
    s_status.last_reclaim_attempted = 0u;
    s_status.last_hijack_detected = 0u;

    exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS;
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;

    kern_return_t kr = task_get_exception_ports(mach_task_self(), mask, masks, &count,
                                                 ports, behaviors, flavors);
    s_status.last_query_kern_return = (int32_t)kr;
    if (kr != KERN_SUCCESS) {
        pthread_mutex_unlock(&s_mutex);
        return;
    }

    s_status.last_query_succeeded = 1u;
    s_status.registered = 1u;
    if (s_early_port_fingerprint_valid != 0u && s_late_phase_checked == 0u) {
        const uint64_t current_fingerprint = cprisk_exception_port_fingerprint_i(
            masks, ports, behaviors, flavors, count);
        s_late_phase_checked = 1u;
        if (current_fingerprint != s_early_port_fingerprint) {
            s_status.last_race_detected = 1u;
            cprisk_force_integrity_poison();
        }
    }

    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if ((masks[i] & (EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS)) && ports[i] != s_exception_port) {
            s_status.last_hijack_detected = 1u;
            s_status.port_matches = 0u;
            atomic_store(&s_registered, 0);
            if (s_exception_port != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), s_exception_port);
                s_exception_port = MACH_PORT_NULL;
            }
            /* 释放 task_get_exception_ports 返回的端口引用后再重新注册 */
            for (mach_msg_type_number_t j = 0; j < count; j++) {
                if (ports[j] != MACH_PORT_NULL)
                    mach_port_deallocate(mach_task_self(), ports[j]);
            }
            register_locked(1);
            pthread_mutex_unlock(&s_mutex);
            return;
        }
        if (ports[i] != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), ports[i]);
    }
    s_status.port_matches = 1u;
    pthread_mutex_unlock(&s_mutex);
}

int cprisk_get_exception_handler_snapshot(cprisk_exception_handler_snapshot_t *out_snapshot) {
    if (out_snapshot == NULL) {
        return -1;
    }

    pthread_mutex_lock(&s_mutex);
    *out_snapshot = s_status;
    pthread_mutex_unlock(&s_mutex);
    return 0;
}

#else

void cprisk_register_exception_handler(void) {
    (void)0;
}

void cprisk_capture_early_exception_ports(void) {
    (void)0;
}

void cprisk_verify_exception_handler(void) {
    (void)0;
}

int cprisk_get_exception_handler_snapshot(cprisk_exception_handler_snapshot_t *out_snapshot) {
    if (out_snapshot == NULL) {
        return -1;
    }

    memset(out_snapshot, 0, sizeof(*out_snapshot));
    return 0;
}

#endif
