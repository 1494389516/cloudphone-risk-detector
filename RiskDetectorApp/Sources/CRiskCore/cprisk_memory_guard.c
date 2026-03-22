/*
 * CRiskCore - Anti-dump memory protection.
 *
 * After data-segment decryption, this module:
 *   1. Strips VM_PROT_WRITE from decrypted pages (mach_vm_protect),
 *      preventing post-decryption injection.
 *   2. Optionally plants guard (honeypot) pages with VM_PROT_NONE around
 *      the protected region. Any access triggers SIGBUS, which signals
 *      a memory-scanning/dump attempt.
 */

#include "include/cprisk_memory_guard.h"
#include "include/CRiskCore.h"

#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <mach/mach.h>

#ifndef CPRISK_PAGE_MASK
#define CPRISK_PAGE_MASK (~(uintptr_t)0xFFF)
#endif
#define CPRISK_PAGE_SIZE_4K 0x1000u

static pthread_mutex_t s_sigbus_guard_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct sigaction s_prev_sigbus_action;
static int s_sigbus_guard_installed = 0;
static struct cprisk_guard_state *s_sigbus_guard_state = NULL;

static int page_span(void *ptr, size_t len,
                     vm_address_t *page_out, vm_size_t *span_out) {
    if ((uintptr_t)ptr > UINTPTR_MAX - len)
        return -1;
    uintptr_t start = (uintptr_t)ptr & CPRISK_PAGE_MASK;
    uintptr_t end   = ((uintptr_t)ptr + len + CPRISK_PAGE_SIZE_4K - 1) & CPRISK_PAGE_MASK;
    *page_out = (vm_address_t)start;
    *span_out = (vm_size_t)(end - start);
    return 0;
}

static void cprisk_best_effort_madv_free(void *region, size_t len) {
    vm_address_t page = 0;
    vm_size_t span = 0;
    if (!region || len == 0)
        return;
    if (page_span(region, len, &page, &span) != 0 || span == 0)
        return;

    int advised = -1;
#if defined(MADV_FREE_REUSABLE)
    advised = madvise((void *)(uintptr_t)page, (size_t)span, MADV_FREE_REUSABLE);
#endif
#if defined(MADV_FREE)
    if (advised != 0)
        advised = madvise((void *)(uintptr_t)page, (size_t)span, MADV_FREE);
#endif
#if defined(MADV_DONTNEED)
    if (advised != 0)
        (void)madvise((void *)(uintptr_t)page, (size_t)span, MADV_DONTNEED);
#else
    (void)advised;
#endif
}

static int cprisk_sigbus_addr_in_guard(const struct cprisk_guard_state *state, const void *addr) {
    if (!state || !addr)
        return 0;

    uintptr_t target = (uintptr_t)addr;
    uint32_t limit = state->trap_count;
    if (limit > CPRISK_GUARD_MAX_TRAPS)
        limit = CPRISK_GUARD_MAX_TRAPS;

    for (uint32_t i = 0; i < limit; i++) {
        const void *trap_addr = state->traps[i].addr;
        size_t trap_size = state->traps[i].size;
        if (!trap_addr || trap_size == 0)
            continue;
        const uintptr_t start = (uintptr_t)trap_addr;
        const uintptr_t end = start + trap_size;
        if (target >= start && target < end)
            return 1;
    }
    return 0;
}

static void cprisk_forward_prev_sigbus(int sig, siginfo_t *info, void *uap) {
    if ((s_prev_sigbus_action.sa_flags & SA_SIGINFO) != 0) {
        void (*prev_sigaction)(int, siginfo_t *, void *) = s_prev_sigbus_action.sa_sigaction;
        if (prev_sigaction != NULL &&
            prev_sigaction != (void (*)(int, siginfo_t *, void *))SIG_IGN &&
            prev_sigaction != (void (*)(int, siginfo_t *, void *))SIG_DFL) {
            prev_sigaction(sig, info, uap);
            return;
        }
    } else {
        if (s_prev_sigbus_action.sa_handler == SIG_IGN)
            return;
        if (s_prev_sigbus_action.sa_handler != NULL &&
            s_prev_sigbus_action.sa_handler != SIG_DFL) {
            s_prev_sigbus_action.sa_handler(sig);
            return;
        }
    }

    signal(SIGBUS, SIG_DFL);
    raise(SIGBUS);
}

static void cprisk_sigbus_handler_i(int sig, siginfo_t *info, void *uap) {
    struct cprisk_guard_state *state = s_sigbus_guard_state;
    if (state != NULL && info != NULL && cprisk_sigbus_addr_in_guard(state, info->si_addr)) {
        cprisk_guard_page_fault_notify();
    }

    cprisk_forward_prev_sigbus(sig, info, uap);
}

int cprisk_install_sigbus_guard(struct cprisk_guard_state *state) {
    if (!state)
        return -1;

    pthread_mutex_lock(&s_sigbus_guard_mutex);
    if (s_sigbus_guard_installed) {
        s_sigbus_guard_state = state;
        state->poison_mode_enabled = 1u;
        pthread_mutex_unlock(&s_sigbus_guard_mutex);
        return 0;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = cprisk_sigbus_handler_i;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;

    if (sigaction(SIGBUS, &sa, &s_prev_sigbus_action) != 0) {
        pthread_mutex_unlock(&s_sigbus_guard_mutex);
        return -1;
    }

    s_sigbus_guard_installed = 1;
    s_sigbus_guard_state = state;
    state->poison_mode_enabled = 1u;
    pthread_mutex_unlock(&s_sigbus_guard_mutex);
    return 0;
}

void cprisk_remove_sigbus_guard(struct cprisk_guard_state *state) {
    pthread_mutex_lock(&s_sigbus_guard_mutex);
    if (!s_sigbus_guard_installed) {
        pthread_mutex_unlock(&s_sigbus_guard_mutex);
        return;
    }

    if (state != NULL && state != s_sigbus_guard_state) {
        pthread_mutex_unlock(&s_sigbus_guard_mutex);
        return;
    }

    (void)sigaction(SIGBUS, &s_prev_sigbus_action, NULL);
    s_sigbus_guard_installed = 0;
    s_sigbus_guard_state = NULL;
    pthread_mutex_unlock(&s_sigbus_guard_mutex);
}

int cprisk_protect_decrypted_pages(void *region, size_t len) {
    if (!region || len == 0)
        return -1;

    vm_address_t page;
    vm_size_t span;
    if (page_span(region, len, &page, &span) != 0)
        return -1;

    kern_return_t kr = vm_protect(
        mach_task_self(),
        page,
        span,
        FALSE,
        VM_PROT_READ);
    if (kr != KERN_SUCCESS)
        return -1;

    cprisk_best_effort_madv_free(region, len);
    return 0;
}

int cprisk_verify_page_protection(void *region, size_t len) {
    if (!region || len == 0)
        return 0;

    vm_address_t page;
    vm_size_t span;
    if (page_span(region, len, &page, &span) != 0)
        return 0;

    vm_address_t addr = page;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    kern_return_t kr = vm_region_64(
        mach_task_self(),
        &addr,
        &region_size,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&info,
        &count,
        &object_name);

    if (kr != KERN_SUCCESS)
        return 0;

    if (addr > page)
        return 0;

    int is_readonly = ((info.protection & VM_PROT_WRITE) == 0) &&
                      ((info.protection & VM_PROT_READ) != 0);
    return is_readonly ? 1 : 0;
}

int cprisk_unprotect_pages(void *region, size_t len) {
    if (!region || len == 0)
        return -1;

    vm_address_t page;
    vm_size_t span;
    if (page_span(region, len, &page, &span) != 0)
        return -1;

    kern_return_t kr = vm_protect(
        mach_task_self(),
        page,
        span,
        FALSE,
        VM_PROT_READ | VM_PROT_WRITE);
    return (kr == KERN_SUCCESS) ? 0 : -1;
}

int cprisk_install_memory_trap(void *region, size_t len,
                               struct cprisk_guard_state *state) {
    if (!region || len == 0 || !state)
        return -1;

    vm_address_t page;
    vm_size_t span;
    if (page_span(region, len, &page, &span) != 0)
        return -1;

    vm_address_t guard_addrs[2];
    int guard_valid[2];
    guard_valid[0] = (page >= CPRISK_PAGE_SIZE_4K);
    guard_addrs[0] = guard_valid[0] ? (page - CPRISK_PAGE_SIZE_4K) : 0;
    guard_valid[1] = 1;  /* upper guard always valid */
    guard_addrs[1] = page + span;

    int planted = 0;
    for (int i = 0; i < 2 && state->trap_count < CPRISK_GUARD_MAX_TRAPS; i++) {
        if (!guard_valid[i])
            continue;
        vm_address_t alloc_addr = guard_addrs[i];
        kern_return_t kr = vm_allocate(
            mach_task_self(),
            &alloc_addr,
            CPRISK_PAGE_SIZE_4K,
            VM_FLAGS_FIXED);

        if (kr != KERN_SUCCESS)
            continue;

        kr = vm_protect(
            mach_task_self(),
            alloc_addr,
            CPRISK_PAGE_SIZE_4K,
            FALSE,
            VM_PROT_NONE);

        if (kr != KERN_SUCCESS) {
            state->protect_failed = 1;
            vm_deallocate(mach_task_self(), alloc_addr, CPRISK_PAGE_SIZE_4K);
            continue;
        }

        state->traps[state->trap_count].addr = (void *)alloc_addr;
        state->traps[state->trap_count].size = CPRISK_PAGE_SIZE_4K;
        state->trap_count++;
        planted++;
    }

    /* Only mark traps as active when at least one guard page was actually
     * installed.  VM_FLAGS_FIXED allocation fails when the adjacent pages are
     * already mapped (standard in any __DATA segment), so planted may be 0.
     * Setting pages_protected=1 unconditionally masks this silent failure and
     * misleads any caller that inspects state->pages_protected. */
    state->pages_protected = (planted > 0) ? 1 : 0;
    if (planted > 0) {
        if (cprisk_install_sigbus_guard(state) != 0)
            state->poison_mode_enabled = 0u;
        cprisk_best_effort_madv_free(region, len);
    }
    return planted;
}

void cprisk_remove_memory_trap(struct cprisk_guard_state *state) {
    if (!state)
        return;

    uint32_t limit = state->trap_count;
    if (limit > CPRISK_GUARD_MAX_TRAPS)
        limit = CPRISK_GUARD_MAX_TRAPS;
    for (uint32_t i = 0; i < limit; i++) {
        if (state->traps[i].addr && state->traps[i].size > 0) {
            vm_deallocate(
                mach_task_self(),
                (vm_address_t)state->traps[i].addr,
                (vm_size_t)state->traps[i].size);
        }
    }
    cprisk_remove_sigbus_guard(state);
    memset(state, 0, sizeof(*state));
}
