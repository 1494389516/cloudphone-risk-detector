/*
 * cprisk_memory_guard.h — Anti-dump memory protection primitives.
 *
 * After decryption completes, these routines harden memory pages to prevent
 * runtime tampering and make memory-dump attacks more difficult:
 *   1. cprisk_protect_decrypted_pages() — strips VM_PROT_WRITE from decrypted regions
 *   2. cprisk_install_memory_trap()     — plants guard (honeypot) pages around regions
 *   3. cprisk_unprotect_pages()         — restores VM_PROT_WRITE (for re-encryption)
 *   4. cprisk_remove_memory_trap()      — deallocates guard pages
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

/* Optional SIGBUS guard wiring for active anti-dump trapping.
 * install_memory_trap/remove_memory_trap already call these internally. */
int  cprisk_install_sigbus_guard(struct cprisk_guard_state *state);
void cprisk_remove_sigbus_guard(struct cprisk_guard_state *state);

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_MEMORY_GUARD_H */
