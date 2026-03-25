/*
 * CRiskCore - Anti-dump memory protection.
 *
 * After data-segment decryption, this module:
 *   1. Strips VM_PROT_WRITE from decrypted pages (mach_vm_protect),
 *      preventing post-decryption injection.
 *   2. Optionally plants guard (honeypot) pages with VM_PROT_NONE around
 *      the protected region. Accesses typically raise SIGBUS or SIGSEGV; the
 *      unified handler routes known trap addresses to cprisk_guard_page_fault_notify().
 */

#include "include/cprisk_memory_guard.h"
#include "include/CRiskCore.h"

#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <mach/mach.h>
#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif
#if defined(__aarch64__)
#include <mach/arm/thread_status.h>
#endif
#if defined(__APPLE__)
#include <mach/vm_prot.h>
#include <stdint.h>
#endif

#if defined(__APPLE__) && !(defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
extern void cprisk_svc_reloc_rx_page_whitelist_bounds(uintptr_t *out_lo, uintptr_t *out_hi);
#endif

#ifndef CPRISK_PAGE_MASK
#define CPRISK_PAGE_MASK (~(uintptr_t)0xFFF)
#endif
#define CPRISK_PAGE_SIZE_4K 0x1000u

static pthread_mutex_t s_sigbus_guard_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct sigaction s_prev_sigbus_action;
static struct sigaction s_prev_sigsegv_action;
static int s_sigbus_guard_installed = 0;
static struct cprisk_guard_state *s_sigbus_guard_state = NULL;

static int s_fault_handlers_installed = 0;
static uint32_t s_mem_trap_fault_ref = 0;
static uint32_t s_text_honeypot_fault_ref = 0;
static volatile uintptr_t s_text_honeypot_lo = 0;
static volatile uintptr_t s_text_honeypot_hi = 0;

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
        if (start > UINTPTR_MAX - trap_size)
            continue;
        const uintptr_t end = start + trap_size;
        if (target >= start && target < end)
            return 1;
    }
    return 0;
}

static void cprisk_guard_fault_handler_i(int sig, siginfo_t *info, void *uap);

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

static void cprisk_forward_prev_sigsegv(int sig, siginfo_t *info, void *uap) {
    if ((s_prev_sigsegv_action.sa_flags & SA_SIGINFO) != 0) {
        void (*prev_sigaction)(int, siginfo_t *, void *) = s_prev_sigsegv_action.sa_sigaction;
        if (prev_sigaction != NULL &&
            prev_sigaction != (void (*)(int, siginfo_t *, void *))SIG_IGN &&
            prev_sigaction != (void (*)(int, siginfo_t *, void *))SIG_DFL) {
            prev_sigaction(sig, info, uap);
            return;
        }
    } else {
        if (s_prev_sigsegv_action.sa_handler == SIG_IGN)
            return;
        if (s_prev_sigsegv_action.sa_handler != NULL &&
            s_prev_sigsegv_action.sa_handler != SIG_DFL) {
            s_prev_sigsegv_action.sa_handler(sig);
            return;
        }
    }

    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}

static int cprisk_fault_handlers_install_locked(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = cprisk_guard_fault_handler_i;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;

    if (sigaction(SIGBUS, &sa, &s_prev_sigbus_action) != 0)
        return -1;
    if (sigaction(SIGSEGV, &sa, &s_prev_sigsegv_action) != 0) {
        (void)sigaction(SIGBUS, &s_prev_sigbus_action, NULL);
        return -1;
    }
    s_fault_handlers_installed = 1;
    return 0;
}

static void cprisk_fault_handlers_uninstall_locked(void) {
    if (!s_fault_handlers_installed)
        return;
    (void)sigaction(SIGBUS, &s_prev_sigbus_action, NULL);
    (void)sigaction(SIGSEGV, &s_prev_sigsegv_action, NULL);
    s_fault_handlers_installed = 0;
}

static int cprisk_fault_handlers_acquire_mem_trap_locked(void) {
    if (s_mem_trap_fault_ref + s_text_honeypot_fault_ref == 0) {
        if (cprisk_fault_handlers_install_locked() != 0)
            return -1;
    }
    s_mem_trap_fault_ref++;
    return 0;
}

static void cprisk_fault_handlers_release_mem_trap_locked(void) {
    if (s_mem_trap_fault_ref > 0)
        s_mem_trap_fault_ref--;
    if (s_mem_trap_fault_ref + s_text_honeypot_fault_ref == 0)
        cprisk_fault_handlers_uninstall_locked();
}

static int cprisk_fault_handlers_acquire_text_honeypot_locked(void) {
    if (s_mem_trap_fault_ref + s_text_honeypot_fault_ref == 0) {
        if (cprisk_fault_handlers_install_locked() != 0)
            return -1;
    }
    s_text_honeypot_fault_ref++;
    return 0;
}

static void cprisk_fault_handlers_release_text_honeypot_locked(void) {
    if (s_text_honeypot_fault_ref > 0)
        s_text_honeypot_fault_ref--;
    if (s_mem_trap_fault_ref + s_text_honeypot_fault_ref == 0)
        cprisk_fault_handlers_uninstall_locked();
}

static int cprisk_addr_in_text_honeypot(const void *addr) {
    if (!addr)
        return 0;
    uintptr_t lo = s_text_honeypot_lo;
    uintptr_t hi = s_text_honeypot_hi;
    if (lo == 0 || hi <= lo)
        return 0;
    uintptr_t t = (uintptr_t)addr;
    return (t >= lo && t < hi) ? 1 : 0;
}

static void cprisk_guard_fault_handler_i(int sig, siginfo_t *info, void *uap) {
    if (info != NULL) {
        void *addr = info->si_addr;
        if (cprisk_sigbus_addr_in_guard(s_sigbus_guard_state, addr) ||
            cprisk_addr_in_text_honeypot(addr)) {
            cprisk_guard_page_fault_notify();
        }
    }
    if (sig == SIGBUS)
        cprisk_forward_prev_sigbus(sig, info, uap);
    else
        cprisk_forward_prev_sigsegv(sig, info, uap);
}

int cprisk_register_text_honeypot_page(void *page, size_t len) {
    if (!page || len == 0)
        return -1;

    pthread_mutex_lock(&s_sigbus_guard_mutex);
    s_text_honeypot_lo = (uintptr_t)page;
    s_text_honeypot_hi = (uintptr_t)page + len;
    if (cprisk_fault_handlers_acquire_text_honeypot_locked() != 0) {
        s_text_honeypot_lo = 0;
        s_text_honeypot_hi = 0;
        pthread_mutex_unlock(&s_sigbus_guard_mutex);
        return -1;
    }
    pthread_mutex_unlock(&s_sigbus_guard_mutex);
    return 0;
}

void cprisk_unregister_text_honeypot_page(void) {
    pthread_mutex_lock(&s_sigbus_guard_mutex);
    s_text_honeypot_lo = 0;
    s_text_honeypot_hi = 0;
    cprisk_fault_handlers_release_text_honeypot_locked();
    pthread_mutex_unlock(&s_sigbus_guard_mutex);
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

    if (cprisk_fault_handlers_acquire_mem_trap_locked() != 0) {
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

    cprisk_fault_handlers_release_mem_trap_locked();
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

#if defined(__APPLE__)
static vm_prot_t cprisk_vm_prot_from_bsd_i(int prot) {
    vm_prot_t p = VM_PROT_NONE;
    if ((prot & PROT_READ) != 0)
        p |= VM_PROT_READ;
    if ((prot & PROT_WRITE) != 0)
        p |= VM_PROT_WRITE;
    if ((prot & PROT_EXEC) != 0)
        p |= VM_PROT_EXECUTE;
    return p;
}

static int cprisk_vm_prot_covers_i(vm_prot_t have, vm_prot_t need) {
    return (have & need) == need;
}
#endif

int cprisk_vm_crosscheck_mprotect(void *addr, size_t len, int bsd_prot) {
#if !defined(__APPLE__)
    (void)addr;
    (void)len;
    (void)bsd_prot;
    return 0;
#else
    if (!addr || len == 0)
        return 0;

    vm_address_t page = 0;
    vm_size_t span = 0;
    if (page_span(addr, len, &page, &span) != 0)
        return 0;

    const vm_prot_t need = cprisk_vm_prot_from_bsd_i(bsd_prot);

    vm_address_t addr_in = page;
    vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    kern_return_t kr = vm_region_64(
        mach_task_self(),
        &addr_in,
        &region_size,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&info,
        &count,
        &object_name);

    if (object_name != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), object_name);

    if (kr != KERN_SUCCESS)
        return 1;
    if (addr_in > page)
        return 1;
    if (!cprisk_vm_prot_covers_i(info.protection, need))
        return 1;

    kern_return_t kr2 = vm_protect(
        mach_task_self(),
        page,
        span,
        FALSE,
        need);
    if (kr2 != KERN_SUCCESS)
        return 2;
    return 0;
#endif
}

int cprisk_advance_ucontext_pc(void *uap, uintptr_t advance_bytes) {
    if (uap == NULL)
        return -1;

    ucontext_t *uctx = (ucontext_t *)uap;
    if (uctx->uc_mcontext == NULL)
        return -1;

#if defined(__aarch64__)
    uintptr_t step = advance_bytes != 0u ? advance_bytes : 4u;
#if defined(__DARWIN_OPAQUE_ARM_THREAD_STATE64) && __DARWIN_OPAQUE_ARM_THREAD_STATE64
    uintptr_t pc = __darwin_arm_thread_state64_get_pc(uctx->uc_mcontext->__ss);
    pc += step;
    __darwin_arm_thread_state64_set_pc_fptr(uctx->uc_mcontext->__ss, (void *)pc);
#else
    uctx->uc_mcontext->__ss.__pc += (uint64_t)step;
#endif
    return 0;
#elif defined(__x86_64__)
    uint64_t step = (uint64_t)(advance_bytes != 0u ? advance_bytes : 1u);
    uctx->uc_mcontext->__ss.__rip += step;
    return 0;
#else
    (void)advance_bytes;
    return -1;
#endif
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

    if (object_name != MACH_PORT_NULL)
        mach_port_deallocate(mach_task_self(), object_name);

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

#if defined(__APPLE__)
#define CPRISK_MEM_GUARD_VM_REGION_SCAN_MAX 96u

#if !(defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
static vm_address_t s_cprisk_mem_guard_vm_addr_cursor;
#endif

static int cprisk_mem_guard_user_tag_is_anonymous_i(unsigned int user_tag) {
    return (user_tag >= 240u && user_tag <= 245u) ? 1 : 0;
}

static int cprisk_mem_guard_user_tag_is_expected_image_i(unsigned int user_tag) {
#if defined(VM_MEMORY_DYLIB)
    if (user_tag == VM_MEMORY_DYLIB) {
        return 1;
    }
#endif
#if defined(VM_MEMORY_SHARED_PMAP)
    if (user_tag == VM_MEMORY_SHARED_PMAP) {
        return 1;
    }
#endif
    return 0;
}

uint32_t cprisk_memory_guard_image_vm_tick(void) {
    uint32_t flags = 0u;
    const int layout_diff = cprisk_vm_dyld_image_layout_digest_differs_from_baseline();
    if (layout_diff == 1) {
        flags |= CPRISK_MEM_GUARD_TICK_IMAGE_LIST_CHANGED;
    }

#if defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR
    vm_address_t addr = 0u;
#else
    vm_address_t addr = s_cprisk_mem_guard_vm_addr_cursor;
#endif
    natural_t depth = 0u;
    for (uint32_t step = 0; step < CPRISK_MEM_GUARD_VM_REGION_SCAN_MAX; step++) {
        vm_size_t sz = 0u;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        vm_address_t a = addr;
        kern_return_t kr = vm_region_recurse_64(
            mach_task_self(),
            &a,
            &sz,
            &depth,
            (vm_region_recurse_info_t)&info,
            &count);
        if (kr != KERN_SUCCESS) {
#if !(defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
            s_cprisk_mem_guard_vm_addr_cursor = 0u;
#endif
            break;
        }
        if (info.is_submap) {
            depth += 1u;
            continue;
        }
#if !(defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
        if (sz > 0u &&
            (info.protection & VM_PROT_WRITE) != 0 &&
            (info.protection & VM_PROT_EXECUTE) != 0) {
            flags |= CPRISK_MEM_GUARD_TICK_EXECUTABLE_WRITE;
        }
#endif
        const vm_prot_t rx_need = VM_PROT_READ | VM_PROT_EXECUTE;
        if (sz > 0u && (info.protection & rx_need) == rx_need) {
            const uintptr_t a0 = (uintptr_t)a;
            const uintptr_t a1 = a0 + (uintptr_t)(sz >> 1);
            const uintptr_t a2 = a0 + (uintptr_t)(sz - 1u);
            const int p0_in_image = cprisk_addr_in_any_image_executable((const void *)a0);
            const int p1_in_image = cprisk_addr_in_any_image_executable((const void *)a1);
            const int p2_in_image = cprisk_addr_in_any_image_executable((const void *)a2);
            const int all_in_image = p0_in_image != 0 && p1_in_image != 0 && p2_in_image != 0;
            const int all_outside_image = p0_in_image == 0 && p1_in_image == 0 && p2_in_image == 0;
            if (all_outside_image) {
                uintptr_t wl_lo = 0u;
                uintptr_t wl_hi = 0u;
                cprisk_svc_reloc_rx_page_whitelist_bounds(&wl_lo, &wl_hi);
                const uintptr_t ra = (uintptr_t)a;
                const uintptr_t ra_end = ra + (uintptr_t)sz;
                const int region_is_only_reloc_svc_page =
                    wl_lo != 0u && wl_hi > wl_lo && ra == wl_lo && ra_end == wl_hi;
                if (region_is_only_reloc_svc_page) {
                    /* Known anonymous RX from direct_syscall SVC stub relocation — not a foreign slab. */
                } else {
                    if (cprisk_mem_guard_user_tag_is_expected_image_i(info.user_tag) != 0) {
                        flags |= CPRISK_MEM_GUARD_TICK_IMAGE_LIST_CHANGED;
                    }
                    flags |= CPRISK_MEM_GUARD_TICK_UNKNOWN_EXECUTABLE_RX;
                    break;
                }
            }
            if (all_in_image &&
                cprisk_mem_guard_user_tag_is_anonymous_i(info.user_tag) != 0) {
                flags |= CPRISK_MEM_GUARD_TICK_IMAGE_LIST_CHANGED;
            }
        }
        if (sz == 0u || a + sz < a) {
#if !(defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
            s_cprisk_mem_guard_vm_addr_cursor = 0u;
#endif
            break;
        }
        addr = a + sz;
    }
#if !(defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
    s_cprisk_mem_guard_vm_addr_cursor = addr;
#endif
    return flags;
}
#else
uint32_t cprisk_memory_guard_image_vm_tick(void) {
    return 0u;
}
#endif
