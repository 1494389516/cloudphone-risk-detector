/*
 * cprisk_memory_guard.h — Anti-dump memory protection primitives.
 *
 * After decryption completes, these routines harden memory pages to prevent
 * runtime tampering and make memory-dump attacks more difficult:
 *   1. cprisk_protect_decrypted_pages() — strips VM_PROT_WRITE from decrypted regions
 *   2. cprisk_install_memory_trap()     — plants guard (honeypot) pages around regions
 *   3. cprisk_register_text_honeypot_page() — optional __TEXT tail PROT_NONE trap (see cprisk_text_tail_honeypot.c)
 *   4. cprisk_unprotect_pages()         — restores VM_PROT_WRITE (for re-encryption)
 *   5. cprisk_remove_memory_trap()      — deallocates guard pages
 *
 * All functions are safe to call multiple times and tolerate NULL/0-size inputs.
 */

#ifndef CPRISK_MEMORY_GUARD_H
#define CPRISK_MEMORY_GUARD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CPRISK_GUARD_MAX_TRAPS 16

struct cprisk_guard_trap {
    void  *addr;
    size_t size;
};

struct cprisk_guard_state {
    struct cprisk_guard_trap traps[CPRISK_GUARD_MAX_TRAPS];
    uint32_t trap_count;
    int      pages_protected;
    int      protect_failed;
    uint8_t  poison_mode_enabled;  /* when set, guard-page SIGBUS triggers integrity poison */
};

int  cprisk_protect_decrypted_pages(void *region, size_t len);
int  cprisk_unprotect_pages(void *region, size_t len);
int  cprisk_verify_page_protection(void *region, size_t len);
int  cprisk_install_memory_trap(void *region, size_t len,
                                struct cprisk_guard_state *state);
void cprisk_remove_memory_trap(struct cprisk_guard_state *state);

/* Register a single page inside __TEXT (must be page-aligned) for SIGBUS/SIGSEGV honeypot.
 * Returns 0 on success, -1 if signal handlers could not be installed (caller should restore prot). */
int cprisk_register_text_honeypot_page(void *page, size_t len);
void cprisk_unregister_text_honeypot_page(void);

/* Optional SIGBUS guard wiring for active anti-dump trapping.
 * install_memory_trap/remove_memory_trap already call these internally. */
int  cprisk_install_sigbus_guard(struct cprisk_guard_state *state);
void cprisk_remove_sigbus_guard(struct cprisk_guard_state *state);

/*
 * After POSIX mprotect succeeds, verify Mach VM readback + redundant vm_protect.
 * Returns 0 when consistent (or skipped), non-zero on mismatch.
 */
int cprisk_vm_crosscheck_mprotect(void *addr, size_t len, int bsd_prot);

/*
 * Advance saved program counter in a signal ucontext (best effort).
 * Returns 0 on success, -1 when ucontext layout is unavailable.
 */
int cprisk_advance_ucontext_pc(void *uap, uintptr_t advance_bytes);

/*
 * Lightweight dyld / VM consistency tick:
 *   1. Dyld layout digest (v2: paths + bases + __TEXT bounds) vs baseline snapshot
 *   2. VM scan for executable mappings inconsistent with dyld image coverage / user_tag shape
 *      (device-only; anonymous RX from the direct-syscall SVC stub reloc page is allow-listed)
 * Returns bitmask (see CPRISK_MEM_GUARD_TICK_*). Safe to call from hardened loops (watchdog).
 */
#define CPRISK_MEM_GUARD_TICK_IMAGE_LIST_CHANGED 1u
#define CPRISK_MEM_GUARD_TICK_UNKNOWN_EXECUTABLE_RX 2u
/** Writable+executable mapping in the same region (W^X / DBI-style surface). Device-only tick. */
#define CPRISK_MEM_GUARD_TICK_EXECUTABLE_WRITE 4u

uint32_t cprisk_memory_guard_image_vm_tick(void);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_MEMORY_GUARD_H */
