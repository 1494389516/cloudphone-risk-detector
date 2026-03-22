/*
 * CRiskCore - Data segment decryptor for cprisk-armor ABI v2.
 * Consumes the packed loader descriptor section, validates each target section
 * against the current image, verifies HMAC-SHA256 authentication before
 * decrypting in place, and rolls back all previously applied entries if any
 * step fails.
 */

#include "include/CRiskCore.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <mach/vm_prot.h>
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#include "include/cprisk_dlsym.h"
#include "include/cprisk_macho.h"

typedef int (*cprisk_mprotect_func_t)(void *, size_t, int);
typedef int (*cprisk_mlock_func_t)(const void *, size_t);
typedef int (*cprisk_munlock_func_t)(const void *, size_t);

static cprisk_mprotect_func_t s_mprotect_fn = NULL;
static cprisk_mlock_func_t s_mlock_fn = NULL;
static cprisk_munlock_func_t s_munlock_fn = NULL;
static pthread_once_t s_dlsym_once = PTHREAD_ONCE_INIT;

static volatile int s_mprotect_tampered = 0;
static volatile uint32_t s_mprotect_direct_failure_count = 0u;
static volatile uint32_t s_mprotect_fallback_success_count = 0u;

static void init_dlsym_once(void) {
    s_mprotect_fn = (cprisk_mprotect_func_t)cprisk_dlsym("libsystem_kernel.dylib", "mprotect");
    s_mlock_fn = (cprisk_mlock_func_t)cprisk_dlsym("libsystem_kernel.dylib", "mlock");
    s_munlock_fn = (cprisk_munlock_func_t)cprisk_dlsym("libsystem_kernel.dylib", "munlock");
}

static inline int cprisk_hidden_mprotect(void *addr, size_t len, int prot) {
    int direct_errno = 0;
    if (cprisk_mprotect_direct(addr, len, prot, &direct_errno) == 0) {
        return 0;
    }
    s_mprotect_tampered = 1;
    s_mprotect_direct_failure_count += 1u;

    /* Safety fallback: keep legacy path for unsupported platforms/builds. */
    (void)pthread_once(&s_dlsym_once, init_dlsym_once);
    if (s_mprotect_fn) {
        int rc = s_mprotect_fn(addr, len, prot);
        if (rc == 0) {
            s_mprotect_fallback_success_count += 1u;
        } else {
            s_mprotect_tampered = 1;
        }
        return rc;
    }

    s_mprotect_tampered = 1;
    (void)direct_errno;
    return -1;
}

int cprisk_is_mprotect_tampered(void) {
    return s_mprotect_tampered;
}

uint32_t cprisk_get_mprotect_direct_failure_count(void) {
    return s_mprotect_direct_failure_count;
}

uint32_t cprisk_get_mprotect_fallback_success_count(void) {
    return s_mprotect_fallback_success_count;
}

static inline int cprisk_hidden_mlock(const void *addr, size_t len) {
    (void)pthread_once(&s_dlsym_once, init_dlsym_once);
    if (s_mlock_fn) return s_mlock_fn(addr, len);
    return -1;
}

static inline int cprisk_hidden_munlock(const void *addr, size_t len) {
    (void)pthread_once(&s_dlsym_once, init_dlsym_once);
    if (s_munlock_fn) return s_munlock_fn(addr, len);
    return -1;
}

int cprisk_armor_vm_protect(void *addr, size_t len, int prot) {
    return cprisk_hidden_mprotect(addr, len, prot);
}

#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"
#include "include/cprisk_memory_guard.h"

extern void cprisk_text_encrypt_install(const uint8_t loader_key[CPRISK_ARMOR_KEY_SIZE]);
extern void cprisk_text_encrypt_uninstall(void);
extern int cprisk_text_jit_decrypt(void *fault_addr);

_Static_assert(CPRISK_SHA256_DIGEST_LENGTH == CPRISK_ARMOR_HASH_SIZE,
               "inline SHA256 digest size must match armor ABI");

struct cprisk_loader_target {
    const struct segment_command_64 *segment;
    const struct section_64 *section;
    intptr_t slide;
};

/* ── state ─────────────────────────────────────────────────────────── */

static pthread_mutex_t s_loader_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t s_erase_header_once = PTHREAD_ONCE_INIT;

static uint8_t  s_ldr_key[CPRISK_ARMOR_KEY_SIZE];
static int      s_ldr_ready;
static int      s_ldr_loaded;
static uint64_t s_data_acc;
static struct cprisk_guard_state s_guard_state;

/* ── per-section chained key derivation state ────────────────── */
static int      s_chain_initialized = 0;
static uint8_t  s_prev_section_key[CPRISK_ARMOR_KEY_SIZE];
static uint8_t *s_section_keys = NULL;  /* count * 32 bytes */
static uint32_t s_entry_count = 0;

static struct cprisk_armor_loader_entry *s_applied_entries = NULL;
static int      *s_decrypted_flags = NULL;
static uint32_t s_applied_count = 0;

static inline uint64_t cprisk_rotl64_l(uint64_t x, int k) {
    k &= 63;  /* avoid UB: shift amount must be in [0, 63] */
    return k == 0 ? x : ((x << k) | (x >> (64 - k)));
}

static const struct mach_header_64 *cprisk_own_hdr_l(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr_l);
}

/* Generate len bytes of keystream starting at byte_offset. Used for chunked XOR.
 * seed = key[32] || sid_le[4] || nonce[nonce_len] */
static void cprisk_keystream_at_l(const uint8_t *key, uint32_t sid,
                                  const uint8_t *nonce, size_t nonce_len,
                                  size_t byte_offset,
                                  uint8_t *out, size_t len) {
    if (nonce_len > CPRISK_ARMOR_NONCE_SIZE)
        return;
    if (len == 0)
        return;

    uint8_t seed_buf[CPRISK_ARMOR_KEY_SIZE + 4 + CPRISK_ARMOR_NONCE_SIZE];
    size_t seed_len = CPRISK_ARMOR_KEY_SIZE + 4 + nonce_len;
    memcpy(seed_buf, key, CPRISK_ARMOR_KEY_SIZE);
    seed_buf[32] = (uint8_t)(sid);
    seed_buf[33] = (uint8_t)(sid >> 8);
    seed_buf[34] = (uint8_t)(sid >> 16);
    seed_buf[35] = (uint8_t)(sid >> 24);
    if (nonce_len > 0)
        memcpy(seed_buf + 36, nonce, nonce_len);

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed_buf, seed_len, blk);
    cprisk_secure_zero(seed_buf, sizeof(seed_buf));

    /* Fast-forward to byte_offset: advance through full blocks */
    size_t block_offset = byte_offset / CPRISK_SHA256_DIGEST_LENGTH;
    size_t in_block = byte_offset % CPRISK_SHA256_DIGEST_LENGTH;
    for (size_t i = 0; i < block_offset; i++) {
        uint8_t prev[CPRISK_SHA256_DIGEST_LENGTH];
        memcpy(prev, blk, CPRISK_SHA256_DIGEST_LENGTH);
        cprisk_sha256(prev, CPRISK_SHA256_DIGEST_LENGTH, blk);
        cprisk_secure_zero(prev, sizeof(prev));
    }

    size_t out_off = 0;
    if (in_block > 0) {
        size_t take = CPRISK_SHA256_DIGEST_LENGTH - in_block;
        if (take > len)
            take = len;
        memcpy(out, blk + in_block, take);
        out_off = take;
        if (out_off < len) {
            uint8_t prev[CPRISK_SHA256_DIGEST_LENGTH];
            memcpy(prev, blk, CPRISK_SHA256_DIGEST_LENGTH);
            cprisk_sha256(prev, CPRISK_SHA256_DIGEST_LENGTH, blk);
            cprisk_secure_zero(prev, sizeof(prev));
        }
    }

    while (out_off < len) {
        size_t chunk = len - out_off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH)
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        memcpy(out + out_off, blk, chunk);
        out_off += chunk;
        if (out_off < len) {
            uint8_t prev[CPRISK_SHA256_DIGEST_LENGTH];
            memcpy(prev, blk, CPRISK_SHA256_DIGEST_LENGTH);
            cprisk_sha256(prev, CPRISK_SHA256_DIGEST_LENGTH, blk);
            cprisk_secure_zero(prev, sizeof(prev));
        }
    }
    cprisk_secure_zero(blk, sizeof(blk));
}

static void cprisk_keystream_l(const uint8_t *key, uint32_t sid,
                               const uint8_t *nonce, size_t nonce_len,
                               uint8_t *out, size_t len) {
    cprisk_keystream_at_l(key, sid, nonce, nonce_len, 0, out, len);
}

/* ── per-section chained key derivation ─────────────────────── */

void cprisk_armor_derive_chained_key(
    const uint8_t *parent_key,
    uint32_t section_index,
    const uint8_t *nonce,
    size_t nonce_len,
    uint8_t depth,
    uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]
) {
    /* Level 1: HMAC(parent, index || nonce) */
    uint8_t chain_material[4 + CPRISK_ARMOR_NONCE_SIZE];
    chain_material[0] = (uint8_t)(section_index);
    chain_material[1] = (uint8_t)(section_index >> 8);
    chain_material[2] = (uint8_t)(section_index >> 16);
    chain_material[3] = (uint8_t)(section_index >> 24);
    memcpy(chain_material + 4, nonce, nonce_len);

    cprisk_hmac_sha256(parent_key, CPRISK_ARMOR_KEY_SIZE,
                       chain_material, 4 + nonce_len, out_key);
    cprisk_secure_zero(chain_material, sizeof(chain_material));

    /* Depth levels beyond 1: recursive HMAC */
    for (uint8_t d = 1; d < depth; d++) {
        uint8_t round_key[CPRISK_ARMOR_KEY_SIZE];
        memcpy(round_key, out_key, CPRISK_ARMOR_KEY_SIZE);

        uint8_t label[] = "cprisk.chained.v1.";
        cprisk_hmac_sha256(round_key, CPRISK_ARMOR_KEY_SIZE,
                           label, sizeof(label) - 1, out_key);

        uint8_t depth_material[CPRISK_ARMOR_KEY_SIZE + 1];
        memcpy(depth_material, out_key, CPRISK_ARMOR_KEY_SIZE);
        depth_material[CPRISK_ARMOR_KEY_SIZE] = d;
        cprisk_hmac_sha256(depth_material, CPRISK_ARMOR_KEY_SIZE + 1,
                           depth_material, CPRISK_ARMOR_KEY_SIZE + 1, out_key);

        cprisk_secure_zero(round_key, sizeof(round_key));
        cprisk_secure_zero(depth_material, sizeof(depth_material));
    }
}

static int cprisk_is_v3_entry(const struct cprisk_armor_loader_entry *entry) {
    return entry && entry->section_index != 0u;
}

static void cprisk_read_v3_fields(
    const struct cprisk_armor_loader_entry *entry,
    uint32_t *out_section_index,
    uint32_t *out_chained_depth
) {
    if (!entry || !out_section_index || !out_chained_depth) {
        return;
    }
    *out_section_index = entry->section_index;
    *out_chained_depth = entry->chained_key_depth;
}

static int cprisk_copy_fixed_name_l(const char raw[16], char out[17]) {
    size_t len = 0;
    while (len < 16 && raw[len] != '\0')
        len++;
    if (len == 0)
        return -1;
    memcpy(out, raw, len);
    out[len] = '\0';
    return 0;
}

static int cprisk_parse_loader_descriptor(
    const uint8_t *sec,
    unsigned long sec_sz,
    uint32_t *count_out
) {
    if (!sec || !count_out || sec_sz < sizeof(struct cprisk_armor_loader_header))
        return -1;

    const struct cprisk_armor_loader_header *loader =
        (const struct cprisk_armor_loader_header *)sec;
    if (loader->magic != CPRISK_ARMOR_LOADER_MAGIC ||
        loader->version != CPRISK_ARMOR_ABI_VERSION)
        return -1;

    uint32_t count = loader->count;
    if (count > CPRISK_MAX_ENTRY_COUNT)
        return -1;
    size_t entries_base = sizeof(struct cprisk_armor_loader_header);
    size_t entries_sz = (size_t)count * sizeof(struct cprisk_armor_loader_entry);
    if (entries_base + entries_sz > (size_t)sec_sz)
        return -1;

    *count_out = count;
    return 0;
}

static int cprisk_resolve_loader_target(
    const struct mach_header_64 *hdr,
    intptr_t slide,
    const struct cprisk_armor_loader_entry *ent,
    struct cprisk_loader_target *out
) {
    if (!hdr || !ent || !out || ent->size == 0)
        return -1;

    char segment_name[17] = {0};
    char section_name[17] = {0};
    if (cprisk_copy_fixed_name_l(ent->segment_name, segment_name) != 0 ||
        cprisk_copy_fixed_name_l(ent->section_name, section_name) != 0)
        return -1;

    const size_t page_size = 0x1000;
    if (hdr->sizeofcmds > page_size - sizeof(struct mach_header_64))
        return -1;
    const uint8_t *cursor = (const uint8_t *)(hdr + 1);
    const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        size_t remaining = (size_t)(end - cursor);
        if (lc->cmdsize == 0 || lc->cmdsize > remaining)
            break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cursor;
            size_t seg_sz = sizeof(struct segment_command_64);
            size_t sect_sz = (size_t)seg->nsects * sizeof(struct section_64);
            if (sect_sz / sizeof(struct section_64) != (size_t)seg->nsects ||
                seg_sz + sect_sz > (size_t)lc->cmdsize) {
                cursor += lc->cmdsize;
                continue;
            }
            if (strncmp(seg->segname, segment_name, 16) == 0) {
                const struct section_64 *sections =
                    (const struct section_64 *)(cursor + sizeof(*seg));
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    const struct section_64 *sec = &sections[s];
                    if (strncmp(sec->sectname, section_name, 16) != 0)
                        continue;
                    if (ent->vm_addr != sec->addr)
                        return -1;
                    if (ent->size > sec->size)
                        return -1;
                    if ((seg->initprot & VM_PROT_WRITE) == 0)
                        return -1;

                    out->segment = seg;
                    out->section = sec;
                    out->slide = slide;
                    return 0;
                }
            }
        }
        cursor += lc->cmdsize;
    }

    return -1;
}

static uint8_t *cprisk_target_ptr_l(
    const struct cprisk_loader_target *target,
    const struct cprisk_armor_loader_entry *ent
) {
    if (!target || !ent)
        return NULL;
    return (uint8_t *)((uintptr_t)ent->vm_addr + target->slide);
}

#define CPRISK_XOR_CHUNK_SIZE (64 * 1024)  /* 64KB chunks to limit peak memory */

int cprisk_armor_xor_region(uint8_t *target, size_t sz, uint32_t key_id,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *key) {
    if (!target || sz == 0 || !key)
        return -1;

    size_t chunk_sz = (sz < CPRISK_XOR_CHUNK_SIZE) ? sz : CPRISK_XOR_CHUNK_SIZE;
    uint8_t *ks = NULL;
    ks = (uint8_t *)malloc(chunk_sz);
    if (!ks)
        return -1;

    size_t off = 0;
    while (off < sz) {
        size_t todo = sz - off;
        if (todo > chunk_sz)
            todo = chunk_sz;

        cprisk_keystream_at_l(key, key_id, nonce, nonce_len, off, ks, todo);
        for (size_t i = 0; i < todo; i++)
            target[off + i] ^= ks[i];

        cprisk_secure_zero(ks, todo);
        off += todo;
    }

    cprisk_secure_zero(ks, chunk_sz);
    free(ks);
    return 0;
}

static int cprisk_page_span_l(uint8_t *target, size_t sz,
                               void **page_out, size_t *len_out) {
    if (!target || sz == 0 || !page_out || !len_out)
        return -1;
    if ((uintptr_t)target > UINTPTR_MAX - sz)
        return -1;
    if ((uintptr_t)target + sz > UINTPTR_MAX - 0xFFF)
        return -1;
    uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
    uintptr_t end = ((uintptr_t)target + sz + 0xFFF) & ~(uintptr_t)0xFFF;
    *page_out = (void *)page;
    *len_out = (size_t)(end - page);
    return 0;
}

static void cprisk_rollback_l(
    const struct mach_header_64 *hdr,
    intptr_t slide,
    const struct cprisk_armor_loader_entry *applied,
    uint32_t applied_count
) {
    while (applied_count > 0) {
        const struct cprisk_armor_loader_entry *ent = &applied[applied_count - 1];
        struct cprisk_loader_target target;
        if (cprisk_resolve_loader_target(hdr, slide, ent, &target) == 0) {
            uint8_t *ptr = cprisk_target_ptr_l(&target, ent);
            if (ptr) {
                void *page = NULL;
                size_t span = 0;
                if (cprisk_page_span_l(ptr, (size_t)ent->size, &page, &span) == 0) {
                    if (page && span > 0) {
                        if (cprisk_hidden_mprotect(page, span, PROT_READ | PROT_WRITE) != 0)
                            s_mprotect_tampered = 1;
                    }
                    (void)cprisk_armor_xor_region(ptr, (size_t)ent->size, ent->key_id,
                                              ent->nonce, CPRISK_ARMOR_NONCE_SIZE,
                                              s_ldr_key);
                    if (page && span > 0)
                        cprisk_hidden_munlock(page, span);
                }
            }
        }
        applied_count--;
    }
}

/* ── public API ────────────────────────────────────────────────────── */

int cprisk_init_data_loader(const uint8_t *key, size_t key_len) {
    if (!key || key_len != CPRISK_ARMOR_KEY_SIZE)
        return -1;
    memcpy(s_ldr_key, key, CPRISK_ARMOR_KEY_SIZE);
    s_ldr_ready = 1;
    s_ldr_loaded = 0;
    s_data_acc = 0;
    return 0;
}

int cprisk_load_protected_data(void) {
    if (!s_ldr_ready)
        return -1;
    if (s_ldr_loaded)
        return 0;

    const struct mach_header_64 *hdr = cprisk_own_hdr_l();
    if (!hdr)
        return -1;

    unsigned long sec_sz = 0;
    const uint8_t *sec = cprisk_find_section(
        hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_LOADER, &sec_sz);
    uint32_t count = 0;
    if (cprisk_parse_loader_descriptor(sec, sec_sz, &count) != 0)
        return -1;

    const struct cprisk_armor_loader_entry *entries =
        (const struct cprisk_armor_loader_entry *)(sec + sizeof(struct cprisk_armor_loader_header));
    intptr_t slide = cprisk_compute_slide(hdr);

    if (count > 0) {
        struct cprisk_armor_loader_entry *entries_tmp = NULL;
        int *flags_tmp = NULL;
        uint8_t *keys_tmp = NULL;
        entries_tmp = (struct cprisk_armor_loader_entry *)calloc((size_t)count, sizeof(struct cprisk_armor_loader_entry));
        flags_tmp = (int *)calloc((size_t)count, sizeof(*s_decrypted_flags));
        keys_tmp = (uint8_t *)calloc((size_t)count * CPRISK_ARMOR_KEY_SIZE, sizeof(uint8_t));
        if (!entries_tmp || !flags_tmp || !keys_tmp) {
            free(entries_tmp);
            free(flags_tmp);
            free(keys_tmp);
            return -1;
        }
        pthread_mutex_lock(&s_loader_mutex);
        free(s_applied_entries);
        free(s_decrypted_flags);
        free(s_section_keys);
        s_applied_entries = entries_tmp;
        s_decrypted_flags = flags_tmp;
        s_section_keys = keys_tmp;
        s_applied_count = 0;
        s_entry_count = count;
        pthread_mutex_unlock(&s_loader_mutex);
    }

    s_data_acc = 0;
    s_chain_initialized = 0;
    cprisk_secure_zero(s_prev_section_key, sizeof(s_prev_section_key));

    /* Precompute per-entry chained keys to allow out-of-order JIT faults. */
    if (s_section_keys && count > 0) {
        uint8_t parent_key[CPRISK_ARMOR_KEY_SIZE];
        memcpy(parent_key, s_ldr_key, CPRISK_ARMOR_KEY_SIZE);
        for (uint32_t i = 0; i < count; i++) {
            const struct cprisk_armor_loader_entry *ent = &entries[i];
            uint8_t *key_slot = s_section_keys + (size_t)i * CPRISK_ARMOR_KEY_SIZE;
            if (cprisk_is_v3_entry(ent)) {
                uint32_t sec_idx, chain_depth;
                cprisk_read_v3_fields(ent, &sec_idx, &chain_depth);
                if (chain_depth == 0) chain_depth = 1;
                cprisk_armor_derive_chained_key(parent_key, sec_idx, ent->nonce,
                                          CPRISK_ARMOR_NONCE_SIZE, (uint8_t)chain_depth,
                                          key_slot);
                memcpy(parent_key, key_slot, CPRISK_ARMOR_KEY_SIZE);
                s_chain_initialized = 1;
            } else {
                memcpy(key_slot, s_ldr_key, CPRISK_ARMOR_KEY_SIZE);
            }
        }
        cprisk_secure_zero(parent_key, sizeof(parent_key));
    }

    for (uint32_t i = 0; i < count; i++) {
        const struct cprisk_armor_loader_entry *ent = &entries[i];
        struct cprisk_loader_target target;
        if (cprisk_resolve_loader_target(hdr, slide, ent, &target) != 0) {
            continue;
        }

        uint8_t *ptr = cprisk_target_ptr_l(&target, ent);
        if (!ptr) {
            continue;
        }

        void *page = NULL;
        size_t span = 0;
        if (cprisk_page_span_l(ptr, (size_t)ent->size, &page, &span) != 0)
            continue;
        if (page && span > 0) {
            (void)cprisk_hidden_mlock(page, span);
            if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                s_mprotect_tampered = 1;
                cprisk_force_integrity_poison();
                cprisk_hidden_munlock(page, span);
            }
        }

        pthread_mutex_lock(&s_loader_mutex);
        if (s_applied_entries && s_decrypted_flags && s_applied_count < count) {
            memcpy(&s_applied_entries[s_applied_count], ent, sizeof(*ent));
            s_applied_count++;
        }
        pthread_mutex_unlock(&s_loader_mutex);
    }

    cprisk_secure_zero(&s_guard_state, sizeof(s_guard_state));

    cprisk_text_encrypt_install(s_ldr_key);

    s_ldr_loaded = 1;

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
    /* Poison data accumulator under debugger — downstream key derivation
       silently produces wrong material. */
    if (cprisk_is_being_traced()) {
        s_data_acc ^= 0xDEADBEEFCAFEBABEULL;
        cprisk_force_integrity_poison();
    }
#endif

    return (int)s_applied_count;
}

int cprisk_jit_decrypt_page(void *fault_addr) {
    if (cprisk_text_jit_decrypt(fault_addr))
        return 1;

    pthread_mutex_lock(&s_loader_mutex);
    if (!s_ldr_loaded || !s_applied_entries || !s_decrypted_flags) {
        pthread_mutex_unlock(&s_loader_mutex);
        return 0;
    }

    const struct mach_header_64 *hdr = cprisk_own_hdr_l();
    if (!hdr) {
        pthread_mutex_unlock(&s_loader_mutex);
        return 0;
    }
    intptr_t slide = cprisk_compute_slide(hdr);

    for (uint32_t i = 0; i < s_applied_count; i++) {
        const struct cprisk_armor_loader_entry *ent = &s_applied_entries[i];
        struct cprisk_loader_target target;
        if (cprisk_resolve_loader_target(hdr, slide, ent, &target) != 0)
            continue;

        uint8_t *ptr = cprisk_target_ptr_l(&target, ent);
        if (!ptr) continue;

        void *page = NULL;
        size_t span = 0;
        if (cprisk_page_span_l(ptr, (size_t)ent->size, &page, &span) != 0)
            continue;

        if ((uintptr_t)fault_addr >= (uintptr_t)page && (uintptr_t)fault_addr < (uintptr_t)page + span) {
            if (s_decrypted_flags[i]) {
                pthread_mutex_unlock(&s_loader_mutex);
                return 1;
            }

            /* Restore read access BEFORE touching ciphertext; the page is
             * PROT_NONE at this point — any user-space read without this
             * would trigger a nested EXC_BAD_ACCESS inside the handler. */
            if (cprisk_hidden_mprotect(page, span, PROT_READ | PROT_WRITE) != 0) {
                s_mprotect_tampered = 1;
                pthread_mutex_unlock(&s_loader_mutex);
                return 0;
            }

            /* Determine which key to use: v3 chained key or v2 global key */
            uint8_t section_key[CPRISK_ARMOR_KEY_SIZE];
            const uint8_t *decrypt_key;
            if (cprisk_is_v3_entry(ent) && s_section_keys && i < s_entry_count) {
                memcpy(section_key, s_section_keys + (size_t)i * CPRISK_ARMOR_KEY_SIZE, CPRISK_ARMOR_KEY_SIZE);
                decrypt_key = section_key;
            } else {
                /* v2 backward compatibility: use global loader key */
                decrypt_key = s_ldr_key;
            }

            /* Verify HMAC-SHA256(key, nonce || ciphertext) before decrypting */
            {
                if (ent->size > SIZE_MAX - CPRISK_ARMOR_NONCE_SIZE) {
                    if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                        s_mprotect_tampered = 1;
                        cprisk_force_integrity_poison();
                    }
                    pthread_mutex_unlock(&s_loader_mutex);
                    return 0;
                }
                size_t hmac_msg_len = CPRISK_ARMOR_NONCE_SIZE + (size_t)ent->size;
                uint8_t *hmac_msg = NULL;
                hmac_msg = (uint8_t *)malloc(hmac_msg_len);
                if (!hmac_msg) {
                    if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                        s_mprotect_tampered = 1;
                        cprisk_force_integrity_poison();
                    }
                    pthread_mutex_unlock(&s_loader_mutex);
                    return 0;
                }
                memcpy(hmac_msg, ent->nonce, CPRISK_ARMOR_NONCE_SIZE);
                memcpy(hmac_msg + CPRISK_ARMOR_NONCE_SIZE, ptr, (size_t)ent->size);
                uint8_t computed_hmac[CPRISK_ARMOR_HASH_SIZE];
                cprisk_hmac_sha256(decrypt_key, CPRISK_ARMOR_KEY_SIZE,
                                   hmac_msg, hmac_msg_len, computed_hmac);
                cprisk_secure_zero(hmac_msg, hmac_msg_len);
                free(hmac_msg);
                if (cprisk_hmac_verify(ent->hmac_tag, computed_hmac,
                                       CPRISK_ARMOR_HASH_SIZE) != 0) {
                    cprisk_secure_zero(computed_hmac, sizeof(computed_hmac));
                    if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                        s_mprotect_tampered = 1;
                        cprisk_force_integrity_poison();
                    }
                    pthread_mutex_unlock(&s_loader_mutex);
                    return 0;
                }
                cprisk_secure_zero(computed_hmac, sizeof(computed_hmac));
            }
            if (cprisk_armor_xor_region(ptr, (size_t)ent->size, ent->key_id,
                                    ent->nonce, CPRISK_ARMOR_NONCE_SIZE,
                                    decrypt_key) == 0) {
                uint8_t actual_h[CPRISK_SHA256_DIGEST_LENGTH];
                uint8_t diff[CPRISK_SHA256_DIGEST_LENGTH];
                cprisk_sha256(ptr, (size_t)ent->size, actual_h);
                for (int k = 0; k < CPRISK_SHA256_DIGEST_LENGTH; k++)
                    diff[k] = actual_h[k] ^ ent->content_hash[k];

                uint64_t actual_v = 0;
                uint64_t diff_v = 0;
                memcpy(&actual_v, actual_h, sizeof(actual_v));
                memcpy(&diff_v, diff, sizeof(diff_v));
                s_data_acc ^= cprisk_rotl64_l(actual_v, ent->key_id % 64) ^ diff_v;

                if (memcmp(actual_h, ent->content_hash, CPRISK_SHA256_DIGEST_LENGTH) != 0) {
                    (void)cprisk_armor_xor_region(ptr, (size_t)ent->size, ent->key_id,
                                              ent->nonce, CPRISK_ARMOR_NONCE_SIZE,
                                              decrypt_key);
                    if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                        s_mprotect_tampered = 1;
                        cprisk_force_integrity_poison();
                    }
                    pthread_mutex_unlock(&s_loader_mutex);
                    return 0;
                }

#if defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
                /* Perturb decrypted plaintext under debugger — data looks
                   decrypted but content is silently wrong. */
                if (cprisk_is_being_traced()) {
                    for (size_t pi = 0; pi < 4 && pi < (size_t)ent->size; pi++)
                        ptr[pi] ^= 0x01;
                    cprisk_force_integrity_poison();
                }
#endif

                s_decrypted_flags[i] = 1;
                if (cprisk_hidden_mprotect(page, span, PROT_READ) != 0) {
                    s_mprotect_tampered = 1;
                    cprisk_force_integrity_poison();
                }

                cprisk_protect_decrypted_pages(ptr, (size_t)ent->size);
                cprisk_install_memory_trap(ptr, (size_t)ent->size, &s_guard_state);
                pthread_mutex_unlock(&s_loader_mutex);
                return 1;
            } else {
                if (cprisk_hidden_mprotect(page, span, PROT_NONE) != 0) {
                    s_mprotect_tampered = 1;
                    cprisk_force_integrity_poison();
                }
                pthread_mutex_unlock(&s_loader_mutex);
                return 0;
            }
        }
    }
    pthread_mutex_unlock(&s_loader_mutex);
    return 0;
}

uint64_t cprisk_get_data_integrity_accumulator(void) {
    return s_data_acc;
}

int cprisk_get_chain_status(void) {
    return s_chain_initialized;
}

void cprisk_unload_protected_data(void) {
    cprisk_text_encrypt_uninstall();

    cprisk_remove_memory_trap(&s_guard_state);

    pthread_mutex_lock(&s_loader_mutex);
    const struct mach_header_64 *hdr = cprisk_own_hdr_l();
    if (hdr && s_ldr_loaded && s_applied_entries && s_decrypted_flags) {
        intptr_t slide = cprisk_compute_slide(hdr);
        for (uint32_t i = s_applied_count; i > 0; i--) {
            const struct cprisk_armor_loader_entry *ent = &s_applied_entries[i - 1];
            struct cprisk_loader_target target;
            if (cprisk_resolve_loader_target(hdr, slide, ent, &target) != 0)
                continue;

            uint8_t *ptr = cprisk_target_ptr_l(&target, ent);
            if (!ptr)
                continue;

            void *page = NULL;
            size_t span = 0;
            if (cprisk_page_span_l(ptr, (size_t)ent->size, &page, &span) == 0) {
                /* Restore write permission before any mutation.
                 * Pages that were mlocked+PROT_NONE but never JIT-decrypted must
                 * also be unlocked here; without this, mlock is leaked and the
                 * pages remain unswappable after stop(). */
                if (page && span > 0) {
                    if (cprisk_hidden_mprotect(page, span, PROT_READ | PROT_WRITE) != 0)
                        s_mprotect_tampered = 1;
                }
                if (s_decrypted_flags[i - 1]) {
                    /* Page was JIT-decrypted: re-encrypt before releasing. */
                    const uint8_t *reencrypt_key = s_ldr_key;
                    uint8_t tmp_key[CPRISK_ARMOR_KEY_SIZE];
                    if (cprisk_is_v3_entry(ent) && s_section_keys && (i - 1) < s_entry_count) {
                        memcpy(tmp_key, s_section_keys + (size_t)(i - 1) * CPRISK_ARMOR_KEY_SIZE, CPRISK_ARMOR_KEY_SIZE);
                        reencrypt_key = tmp_key;
                    }
                    (void)cprisk_armor_xor_region(ptr, (size_t)ent->size, ent->key_id,
                                              ent->nonce, CPRISK_ARMOR_NONCE_SIZE,
                                              reencrypt_key);
                    cprisk_secure_zero(tmp_key, sizeof(tmp_key));
                }
                if (page && span > 0)
                    cprisk_hidden_munlock(page, span);
            }
        }
    }

    if (s_applied_entries) {
        free(s_applied_entries);
        s_applied_entries = NULL;
    }
    if (s_decrypted_flags) {
        free(s_decrypted_flags);
        s_decrypted_flags = NULL;
    }
    if (s_section_keys) {
        cprisk_secure_zero(s_section_keys, (size_t)s_entry_count * CPRISK_ARMOR_KEY_SIZE);
        free(s_section_keys);
        s_section_keys = NULL;
    }
    s_entry_count = 0;
    s_applied_count = 0;

    cprisk_secure_zero(s_ldr_key, sizeof(s_ldr_key));
    cprisk_secure_zero(s_prev_section_key, sizeof(s_prev_section_key));
    s_ldr_ready = 0;
    s_ldr_loaded = 0;
    s_data_acc = 0;
    s_mprotect_direct_failure_count = 0u;
    s_mprotect_fallback_success_count = 0u;

    pthread_mutex_unlock(&s_loader_mutex);
}

static void cprisk_erase_macho_header_once(void) {
    /* Legacy path used to zero Mach-O header fields (including magic),
     * which is noisy and can break downstream tooling. The hardened path
     * restores encrypted header fields from __DATA.__swift5_mhsav when present.
     * If restore fails, fail-closed via poison without mutating the header. */
    int rc = cprisk_restore_macho_header();
    if (rc < 0)
        cprisk_force_integrity_poison();
}

void cprisk_erase_macho_header(void) {
    (void)pthread_once(&s_erase_header_once, cprisk_erase_macho_header_once);
}
