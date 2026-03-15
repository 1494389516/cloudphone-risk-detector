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

#include <stdint.h>
#include <string.h>
#include <mach/mach.h>

#ifndef CPRISK_PAGE_MASK
#define CPRISK_PAGE_MASK (~(uintptr_t)0xFFF)
#endif
#define CPRISK_PAGE_SIZE_4K 0x1000u

static void page_span(void *ptr, size_t len,
                       vm_address_t *page_out, vm_size_t *span_out) {
    uintptr_t start = (uintptr_t)ptr & CPRISK_PAGE_MASK;
    uintptr_t end   = ((uintptr_t)ptr + len + CPRISK_PAGE_SIZE_4K - 1) & CPRISK_PAGE_MASK;
    *page_out = (vm_address_t)start;
    *span_out = (vm_size_t)(end - start);
}

int cprisk_protect_decrypted_pages(void *region, size_t len) {
    if (!region || len == 0)
        return -1;

    vm_address_t page;
    vm_size_t span;
    page_span(region, len, &page, &span);

    kern_return_t kr = vm_protect(
        mach_task_self(),
        page,
        span,
        FALSE,
        VM_PROT_READ);
    return (kr == KERN_SUCCESS) ? 0 : -1;
}

int cprisk_verify_page_protection(void *region, size_t len) {
    if (!region || len == 0)
        return 0;

    vm_address_t page;
    vm_size_t span;
    page_span(region, len, &page, &span);

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
    page_span(region, len, &page, &span);

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
    page_span(region, len, &page, &span);

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
    return planted;
}

void cprisk_remove_memory_trap(struct cprisk_guard_state *state) {
    if (!state)
        return;

    for (uint32_t i = 0; i < state->trap_count; i++) {
        if (state->traps[i].addr && state->traps[i].size > 0) {
            vm_deallocate(
                mach_task_self(),
                (vm_address_t)state->traps[i].addr,
                (vm_size_t)state->traps[i].size);
        }
    }
    memset(state, 0, sizeof(*state));
}
