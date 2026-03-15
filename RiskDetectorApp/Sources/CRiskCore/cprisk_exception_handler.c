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
#include <string.h>
#include <TargetConditionals.h>

#if defined(__APPLE__) && (defined(__arm64__) || defined(__aarch64__)) && \
    (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR) && \
    (!defined(TARGET_OS_TV) || !TARGET_OS_TV) && \
    (!defined(TARGET_OS_WATCH) || !TARGET_OS_WATCH)

static mach_port_t s_exception_port = MACH_PORT_NULL;
static atomic_int s_registered = 0;
static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;

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
        reply->msgh_bits = req->msgh_bits & MACH_MSGH_BITS_REMOTE_MASK;
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

            if (state_count > 0 && rep->RetCode == KERN_SUCCESS) {
                if (old_stateCnt < state_count)
                    state_count = old_stateCnt;
                rep->new_stateCnt = state_count;
                memcpy(rep->new_state, old_state, state_count * sizeof(natural_t));
                
                if (r->exception == EXC_BREAKPOINT) {
                    if (flavor == ARM_THREAD_STATE64 && state_count >= 34) {
                        uint64_t *pc = (uint64_t *)(rep->new_state + 32);
                        *pc += 4;
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
static void register_locked(void) {
    if (atomic_load(&s_registered))
        return;

    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &s_exception_port);
    if (kr != KERN_SUCCESS)
        return;

    kr = mach_port_insert_right(mach_task_self(), s_exception_port, s_exception_port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), s_exception_port);
        s_exception_port = MACH_PORT_NULL;
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
    pthread_create(&th, NULL, exception_handler_thread, NULL);
    pthread_detach(th);

    atomic_store(&s_registered, 1);
}

void cprisk_register_exception_handler(void) {
    pthread_mutex_lock(&s_mutex);
    register_locked();
    pthread_mutex_unlock(&s_mutex);
}

void cprisk_verify_exception_handler(void) {
    pthread_mutex_lock(&s_mutex);
    if (!atomic_load(&s_registered) || s_exception_port == MACH_PORT_NULL) {
        pthread_mutex_unlock(&s_mutex);
        return;
    }

    exception_mask_t mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS;
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;

    kern_return_t kr = task_get_exception_ports(mach_task_self(), mask, masks, &count,
                                                 ports, behaviors, flavors);
    if (kr != KERN_SUCCESS) {
        pthread_mutex_unlock(&s_mutex);
        return;
    }

    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if ((masks[i] & (EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS)) && ports[i] != s_exception_port) {
            atomic_store(&s_registered, 0);
            if (s_exception_port != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), s_exception_port);
                s_exception_port = MACH_PORT_NULL;
            }
            register_locked();
            pthread_mutex_unlock(&s_mutex);
            return;
        }
        if (ports[i] != MACH_PORT_NULL)
            mach_port_deallocate(mach_task_self(), ports[i]);
    }
    pthread_mutex_unlock(&s_mutex);
}

#else

void cprisk_register_exception_handler(void) {
    (void)0;
}

void cprisk_verify_exception_handler(void) {
    (void)0;
}

#endif
