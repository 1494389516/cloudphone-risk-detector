/*
 * Multi-path resolution checks for the libc process-start helper entry points.
 * Compares RTLD_DEFAULT, explicit libsystem_c handle, and export-trie resolution
 * (bypasses lazy binding / interposed PLT in a different way than dlsym default).
 */

#include "include/CRiskCore.h"
#include "include/cprisk_dlsym.h"

#include <dlfcn.h>
#include <stdint.h>
#include <string.h>

#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT ((void *)(intptr_t)-2)
#endif
#ifndef RTLD_NOLOAD
#define RTLD_NOLOAD 0x20
#endif

enum {
    CPRISK_SPAWN_IFACE_F_DEFAULT_EXPLICIT_SPAWN = 1u << 0,
    CPRISK_SPAWN_IFACE_F_DEFAULT_TRIE_SPAWN = 1u << 1,
    CPRISK_SPAWN_IFACE_F_EXPLICIT_TRIE_SPAWN = 1u << 2,
    CPRISK_SPAWN_IFACE_F_DEFAULT_EXPLICIT_SPAWNP = 1u << 3,
    CPRISK_SPAWN_IFACE_F_DEFAULT_TRIE_SPAWNP = 1u << 4,
    CPRISK_SPAWN_IFACE_F_EXPLICIT_TRIE_SPAWNP = 1u << 5,
};

static uint64_t ptr_to_u64(const void *p) {
    return (uint64_t)(uintptr_t)(void *)p;
}

static void note_mismatch(
    uint64_t a,
    uint64_t b,
    uint32_t *flags,
    uint32_t bit
) {
    if (a != 0 && b != 0 && a != b) {
        *flags |= bit;
    }
}

static void probe_one_family(
    const char *sym_spawn,
    const char *sym_spawnp,
    uint64_t *out_def_sp,
    uint64_t *out_exp_sp,
    uint64_t *out_trie_sp,
    uint64_t *out_def_pp,
    uint64_t *out_exp_pp,
    uint64_t *out_trie_pp,
    uint32_t *flags
) {
    void *def_sp = dlsym(RTLD_DEFAULT, sym_spawn);
    void *def_pp = dlsym(RTLD_DEFAULT, sym_spawnp);
    *out_def_sp = ptr_to_u64(def_sp);
    *out_def_pp = ptr_to_u64(def_pp);

    void *libc = dlopen("/usr/lib/system/libsystem_c.dylib", RTLD_NOW | RTLD_NOLOAD);
    if (!libc) {
        libc = dlopen("/usr/lib/system/libsystem_c.dylib", RTLD_NOW);
    }
    void *exp_sp = libc ? dlsym(libc, sym_spawn) : NULL;
    void *exp_pp = libc ? dlsym(libc, sym_spawnp) : NULL;
    *out_exp_sp = ptr_to_u64(exp_sp);
    *out_exp_pp = ptr_to_u64(exp_pp);

    void *trie_sp = cprisk_dlsym("libsystem_c.dylib", sym_spawn);
    void *trie_pp = cprisk_dlsym("libsystem_c.dylib", sym_spawnp);
    *out_trie_sp = ptr_to_u64(trie_sp);
    *out_trie_pp = ptr_to_u64(trie_pp);

    note_mismatch(*out_def_sp, *out_exp_sp, flags, CPRISK_SPAWN_IFACE_F_DEFAULT_EXPLICIT_SPAWN);
    note_mismatch(*out_def_sp, *out_trie_sp, flags, CPRISK_SPAWN_IFACE_F_DEFAULT_TRIE_SPAWN);
    note_mismatch(*out_exp_sp, *out_trie_sp, flags, CPRISK_SPAWN_IFACE_F_EXPLICIT_TRIE_SPAWN);

    note_mismatch(*out_def_pp, *out_exp_pp, flags, CPRISK_SPAWN_IFACE_F_DEFAULT_EXPLICIT_SPAWNP);
    note_mismatch(*out_def_pp, *out_trie_pp, flags, CPRISK_SPAWN_IFACE_F_DEFAULT_TRIE_SPAWNP);
    note_mismatch(*out_exp_pp, *out_trie_pp, flags, CPRISK_SPAWN_IFACE_F_EXPLICIT_TRIE_SPAWNP);
}

int cprisk_spawn_iface_probe(cprisk_spawn_iface_probe_result_t *out) {
    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

    probe_one_family(
        "posix_spawn",
        "posix_spawnp",
        &out->addr_rtld_default_spawn,
        &out->addr_dlopen_libc_spawn,
        &out->addr_export_trie_spawn,
        &out->addr_rtld_default_spawnp,
        &out->addr_dlopen_libc_spawnp,
        &out->addr_export_trie_spawnp,
        &out->flags
    );

    return 0;
}
