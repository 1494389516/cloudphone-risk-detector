/*
 * CRiskCore - Data segment decryptor for cprisk-armor ABI v1.
 * Consumes the packed loader descriptor section, validates each target section
 * against the current image, decrypts in place, and rolls back all previously
 * applied entries if any step fails.
 */

#include "include/CRiskCore.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <mach/vm_prot.h>
#include "include/cprisk_macho.h"
#include "include/cprisk_sha256.h"

_Static_assert(CPRISK_SHA256_DIGEST_LENGTH == CPRISK_ARMOR_HASH_SIZE,
               "inline SHA256 digest size must match armor ABI");

struct cprisk_loader_target {
    const struct segment_command_64 *segment;
    const struct section_64 *section;
    intptr_t slide;
};

/* ── state ─────────────────────────────────────────────────────────── */

static uint8_t  s_ldr_key[CPRISK_ARMOR_KEY_SIZE];
static int      s_ldr_ready;
static int      s_ldr_loaded;
static uint64_t s_data_acc;

/* ── internal ──────────────────────────────────────────────────────── */

static void cprisk_szero_l(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

static inline uint64_t cprisk_rotl64_l(uint64_t x, int k) {
    return k == 0 ? x : ((x << k) | (x >> (64 - k)));
}

static const struct mach_header_64 *cprisk_own_hdr_l(void) {
    return cprisk_find_own_header((const void *)cprisk_own_hdr_l);
}

static void cprisk_keystream_l(const uint8_t *key, uint32_t sid,
                               uint8_t *out, size_t len) {
    uint8_t seed[36];
    memcpy(seed, key, CPRISK_ARMOR_KEY_SIZE);
    seed[32] = (uint8_t)(sid);
    seed[33] = (uint8_t)(sid >> 8);
    seed[34] = (uint8_t)(sid >> 16);
    seed[35] = (uint8_t)(sid >> 24);

    uint8_t blk[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_sha256(seed, sizeof(seed), blk);
    cprisk_szero_l(seed, sizeof(seed));

    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > CPRISK_SHA256_DIGEST_LENGTH)
            chunk = CPRISK_SHA256_DIGEST_LENGTH;
        memcpy(out + off, blk, chunk);
        off += chunk;
        if (off < len) {
            uint8_t prev[CPRISK_SHA256_DIGEST_LENGTH];
            memcpy(prev, blk, CPRISK_SHA256_DIGEST_LENGTH);
            cprisk_sha256(prev, CPRISK_SHA256_DIGEST_LENGTH, blk);
            cprisk_szero_l(prev, sizeof(prev));
        }
    }
    cprisk_szero_l(blk, sizeof(blk));
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

    const uint8_t *cursor = (const uint8_t *)(hdr + 1);
    const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cursor;
        if (lc->cmdsize == 0 || cursor + lc->cmdsize > end)
            break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)cursor;
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

static int cprisk_xor_region_l(uint8_t *target, size_t sz, uint32_t key_id) {
    if (!target || sz == 0)
        return -1;

    uint8_t *ks = (uint8_t *)malloc(sz);
    if (!ks)
        return -1;

    cprisk_keystream_l(s_ldr_key, key_id, ks, sz);
    for (size_t i = 0; i < sz; i++)
        target[i] ^= ks[i];

    cprisk_szero_l(ks, sz);
    free(ks);
    return 0;
}

static void cprisk_page_span_l(uint8_t *target, size_t sz,
                               void **page_out, size_t *len_out) {
    uintptr_t page = (uintptr_t)target & ~(uintptr_t)0xFFF;
    uintptr_t end = ((uintptr_t)target + sz + 0xFFF) & ~(uintptr_t)0xFFF;
    *page_out = (void *)page;
    *len_out = (size_t)(end - page);
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
                (void)cprisk_xor_region_l(ptr, (size_t)ent->size, ent->key_id);
                void *page = NULL;
                size_t span = 0;
                cprisk_page_span_l(ptr, (size_t)ent->size, &page, &span);
                if (page && span > 0)
                    munlock(page, span);
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
    struct cprisk_armor_loader_entry *applied = NULL;

    if (count > 0) {
        applied = (struct cprisk_armor_loader_entry *)calloc((size_t)count, sizeof(*applied));
        if (!applied)
            return -1;
    }

    s_data_acc = 0;
    uint32_t applied_count = 0;

    for (uint32_t i = 0; i < count; i++) {
        const struct cprisk_armor_loader_entry *ent = &entries[i];
        struct cprisk_loader_target target;
        if (cprisk_resolve_loader_target(hdr, slide, ent, &target) != 0) {
            cprisk_rollback_l(hdr, slide, applied, applied_count);
            free(applied);
            return -1;
        }

        uint8_t *ptr = cprisk_target_ptr_l(&target, ent);
        if (!ptr || cprisk_xor_region_l(ptr, (size_t)ent->size, ent->key_id) != 0) {
            cprisk_rollback_l(hdr, slide, applied, applied_count);
            free(applied);
            return -1;
        }

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
            (void)cprisk_xor_region_l(ptr, (size_t)ent->size, ent->key_id);
            cprisk_szero_l(actual_h, sizeof(actual_h));
            cprisk_szero_l(diff, sizeof(diff));
            cprisk_rollback_l(hdr, slide, applied, applied_count);
            free(applied);
            return -1;
        }

        void *page = NULL;
        size_t span = 0;
        cprisk_page_span_l(ptr, (size_t)ent->size, &page, &span);
        if (page && span > 0)
            (void)mlock(page, span);

        memcpy(&applied[applied_count], ent, sizeof(*ent));
        applied_count++;

        cprisk_szero_l(actual_h, sizeof(actual_h));
        cprisk_szero_l(diff, sizeof(diff));
    }

    free(applied);
    s_ldr_loaded = 1;
    return (int)count;
}

uint64_t cprisk_get_data_integrity_accumulator(void) {
    return s_data_acc;
}

void cprisk_unload_protected_data(void) {
    const struct mach_header_64 *hdr = cprisk_own_hdr_l();
    if (hdr && s_ldr_loaded) {
        unsigned long sec_sz = 0;
        const uint8_t *sec = cprisk_find_section(
            hdr, CPRISK_ARMOR_SEGMENT_DATA, CPRISK_ARMOR_SECTION_LOADER, &sec_sz);
        uint32_t count = 0;
        if (cprisk_parse_loader_descriptor(sec, sec_sz, &count) == 0) {
            const struct cprisk_armor_loader_entry *entries =
                (const struct cprisk_armor_loader_entry *)(sec + sizeof(struct cprisk_armor_loader_header));
            intptr_t slide = cprisk_compute_slide(hdr);
            for (uint32_t i = count; i > 0; i--) {
                const struct cprisk_armor_loader_entry *ent = &entries[i - 1];
                struct cprisk_loader_target target;
                if (cprisk_resolve_loader_target(hdr, slide, ent, &target) != 0)
                    continue;

                uint8_t *ptr = cprisk_target_ptr_l(&target, ent);
                if (!ptr)
                    continue;

                (void)cprisk_xor_region_l(ptr, (size_t)ent->size, ent->key_id);

                void *page = NULL;
                size_t span = 0;
                cprisk_page_span_l(ptr, (size_t)ent->size, &page, &span);
                if (page && span > 0)
                    munlock(page, span);
            }
        }
    }

    cprisk_szero_l(s_ldr_key, sizeof(s_ldr_key));
    s_ldr_ready = 0;
    s_ldr_loaded = 0;
    s_data_acc = 0;
}
