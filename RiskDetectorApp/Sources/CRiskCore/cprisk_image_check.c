/*
 * cprisk_image_check.c — Address-in-image check without dladdr.
 *
 * Uses task_info + dyld_all_image_infos to iterate loaded images and
 * parse Mach-O segments. Returns 1 if addr falls within any image's
 * __TEXT/__DATA/__LINKEDIT/etc., 0 otherwise.
 *
 * Resistant to dladdr hook: does not call dladdr or _dyld_*.
 */

#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_init.h>
#include <mach/vm_prot.h>

#include "include/cprisk_sha256.h"

static int segname_eq(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 1;
}

void cprisk_sha256_text_page(const void *addr, uint8_t out_digest[32]) {
    if (!addr || !out_digest) {
        return;
    }
    long pgsz = sysconf(_SC_PAGESIZE);
    if (pgsz <= 0 || pgsz > 0x1000000l) {
        pgsz = 4096l;
    }
    const uintptr_t mask = (uintptr_t)((size_t)pgsz - 1u);
    const uint8_t *page = (const uint8_t *)((uintptr_t)addr & ~mask);
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, page, (size_t)pgsz);
    cprisk_sha256_final(&ctx, out_digest);
}

int cprisk_addr_in_any_image(const void *addr) {
    uintptr_t target = (uintptr_t)addr;

    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) != 0) {
        return 0;
    }

    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    if (!infos || !infos->infoArray) return 0;

    for (uint32_t i = 0; i < infos->infoArrayCount; i++) {
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)infos->infoArray[i].imageLoadAddress;
        if (!hdr) continue;

        if (hdr->magic != MH_MAGIC_64) continue;
        /* Guard against corrupt sizeofcmds causing pointer overflow */
        if (hdr->sizeofcmds > 0x100000u) continue;

        intptr_t slide = 0;
        int found_text = 0;
        const uint8_t *p = (const uint8_t *)(hdr + 1);
        const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;

        /* First pass: get slide from __TEXT */
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (p + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize == 0 || p + lc->cmdsize > end) break;

            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
                if (segname_eq(seg->segname, "__TEXT", 16)) {
                    slide = (intptr_t)hdr - (intptr_t)seg->vmaddr;
                    found_text = 1;
                    break;
                }
            }
            p += lc->cmdsize;
        }

        if (!found_text) continue;

        /* Second pass: check each segment */
        p = (const uint8_t *)(hdr + 1);
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (p + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize == 0 || p + lc->cmdsize > end) break;

            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
                uintptr_t runtime_start = (uintptr_t)seg->vmaddr + (uintptr_t)slide;
                if (seg->vmsize > 0 && runtime_start <= UINTPTR_MAX - seg->vmsize) {
                    uintptr_t runtime_end = runtime_start + seg->vmsize;
                    if (target >= runtime_start && target < runtime_end) {
                        return 1;
                    }
                }
            }
            p += lc->cmdsize;
        }
    }
    return 0;
}

static int seg_is_executable_mapping_i(const struct segment_command_64 *seg) {
    if (!seg) {
        return 0;
    }
    if (((seg->initprot & VM_PROT_EXECUTE) != 0) || ((seg->maxprot & VM_PROT_EXECUTE) != 0)) {
        return 1;
    }
    /* __TEXT conventionally holds executable pages even if prot bits are unusual. */
    return segname_eq(seg->segname, "__TEXT", 16) ? 1 : 0;
}

int cprisk_addr_in_any_image_executable(const void *addr) {
    uintptr_t target = (uintptr_t)addr;

    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) != 0) {
        return 0;
    }

    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    if (!infos || !infos->infoArray) return 0;

    for (uint32_t i = 0; i < infos->infoArrayCount; i++) {
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)infos->infoArray[i].imageLoadAddress;
        if (!hdr) continue;

        if (hdr->magic != MH_MAGIC_64) continue;
        if (hdr->sizeofcmds > 0x100000u) continue;

        intptr_t slide = 0;
        int found_text = 0;
        const uint8_t *p = (const uint8_t *)(hdr + 1);
        const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;

        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (p + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize == 0 || p + lc->cmdsize > end) break;

            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
                if (segname_eq(seg->segname, "__TEXT", 16)) {
                    slide = (intptr_t)hdr - (intptr_t)seg->vmaddr;
                    found_text = 1;
                    break;
                }
            }
            p += lc->cmdsize;
        }

        if (!found_text) continue;

        p = (const uint8_t *)(hdr + 1);
        for (uint32_t j = 0; j < hdr->ncmds; j++) {
            if (p + sizeof(struct load_command) > end) break;
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmdsize == 0 || p + lc->cmdsize > end) break;

            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
                if (!seg_is_executable_mapping_i(seg)) {
                    p += lc->cmdsize;
                    continue;
                }
                uintptr_t runtime_start = (uintptr_t)seg->vmaddr + (uintptr_t)slide;
                if (seg->vmsize > 0 && runtime_start <= UINTPTR_MAX - seg->vmsize) {
                    uintptr_t runtime_end = runtime_start + seg->vmsize;
                    if (target >= runtime_start && target < runtime_end) {
                        return 1;
                    }
                }
            }
            p += lc->cmdsize;
        }
    }
    return 0;
}

/*
 * Runtime __TEXT bounds for a loaded Mach-O 64 image (dyld infoArray entry).
 * Used by layout digest v2 for segment-ownership differential vs path+base alone.
 */
static int cprisk_macho64_text_runtime_bounds(
    const struct mach_header_64 *hdr,
    uintptr_t *out_start,
    uint64_t *out_size
) {
    if (!hdr || !out_start || !out_size || hdr->magic != MH_MAGIC_64 || hdr->sizeofcmds > 0x100000u) {
        return -1;
    }
    const uint8_t *p = (const uint8_t *)(hdr + 1);
    const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;
    intptr_t slide = 0;
    uintptr_t text_start = 0u;
    uint64_t text_size = 0u;
    int found_text = 0;

    for (uint32_t j = 0; j < hdr->ncmds; j++) {
        if (p + sizeof(struct load_command) > end) {
            break;
        }
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize == 0 || p + lc->cmdsize > end) {
            break;
        }
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
            if (segname_eq(seg->segname, "__TEXT", 16)) {
                slide = (intptr_t)hdr - (intptr_t)seg->vmaddr;
                text_start = (uintptr_t)seg->vmaddr + (uintptr_t)slide;
                text_size = seg->vmsize;
                found_text = 1;
                break;
            }
        }
        p += lc->cmdsize;
    }
    if (!found_text) {
        return -1;
    }
    *out_start = text_start;
    *out_size = text_size;
    return 0;
}

int cprisk_vm_dyld_image_layout_digest(uint8_t out_digest[32]) {
    if (!out_digest)
        return -1;

    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) != 0) {
        return -1;
    }

    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    if (!infos || !infos->infoArray || infos->infoArrayCount == 0u) {
        return -1;
    }

    uint32_t ic = infos->infoArrayCount;
    if (ic > 4096u) {
        return -1;
    }

    static const uint8_t k_lab[] = "cprisk.dyld.layout.v2";
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, k_lab, sizeof(k_lab) - 1u);

    uint8_t ic_le[4];
    ic_le[0] = (uint8_t)(ic & 0xFFu);
    ic_le[1] = (uint8_t)((ic >> 8) & 0xFFu);
    ic_le[2] = (uint8_t)((ic >> 16) & 0xFFu);
    ic_le[3] = (uint8_t)((ic >> 24) & 0xFFu);
    cprisk_sha256_update(&ctx, ic_le, sizeof(ic_le));

    for (uint32_t i = 0; i < ic; i++) {
        const char *path = infos->infoArray[i].imageFilePath;
        if (path) {
            size_t plen = 0;
            while (path[plen] != '\0' && plen < 4096u) {
                plen++;
            }
            cprisk_sha256_update(&ctx, (const uint8_t *)path, plen);
        }
        const uint8_t z = 0;
        cprisk_sha256_update(&ctx, &z, 1);

        const uintptr_t base = (uintptr_t)infos->infoArray[i].imageLoadAddress;
        uint8_t ble[8];
        for (unsigned b = 0; b < 8; b++) {
            ble[b] = (uint8_t)(base >> (8u * b));
        }
        cprisk_sha256_update(&ctx, ble, sizeof(ble));

        const struct mach_header_64 *mh =
            (const struct mach_header_64 *)infos->infoArray[i].imageLoadAddress;
        uintptr_t tstart = 0u;
        uint64_t tsz = 0u;
        if (!mh || mh->magic != MH_MAGIC_64 ||
            cprisk_macho64_text_runtime_bounds(mh, &tstart, &tsz) != 0) {
            tstart = 0u;
            tsz = 0u;
        }
        uint8_t tle[8];
        for (unsigned b = 0; b < 8; b++) {
            tle[b] = (uint8_t)(tstart >> (8u * b));
        }
        cprisk_sha256_update(&ctx, tle, sizeof(tle));
        uint8_t tszle[8];
        for (unsigned b = 0; b < 8; b++) {
            tszle[b] = (uint8_t)(tsz >> (8u * b));
        }
        cprisk_sha256_update(&ctx, tszle, sizeof(tszle));
    }

    cprisk_sha256_final(&ctx, out_digest);
    return 0;
}

static uint8_t s_dyld_layout_digest_baseline[32];
static atomic_int s_dyld_layout_digest_baseline_valid;

void cprisk_vm_dyld_image_layout_digest_baseline_snapshot(void) {
    uint8_t d[32];
    if (cprisk_vm_dyld_image_layout_digest(d) != 0) {
        return;
    }
    memcpy(s_dyld_layout_digest_baseline, d, sizeof(s_dyld_layout_digest_baseline));
    atomic_store_explicit(&s_dyld_layout_digest_baseline_valid, 1, memory_order_release);
}

int cprisk_vm_dyld_image_layout_digest_differs_from_baseline(void) {
    uint8_t now[32];
    if (cprisk_vm_dyld_image_layout_digest(now) != 0) {
        return -1;
    }
    if (atomic_load_explicit(&s_dyld_layout_digest_baseline_valid, memory_order_acquire) == 0) {
        memcpy(s_dyld_layout_digest_baseline, now, sizeof(s_dyld_layout_digest_baseline));
        atomic_store_explicit(&s_dyld_layout_digest_baseline_valid, 1, memory_order_release);
        return 0;
    }
    return memcmp(now, s_dyld_layout_digest_baseline, sizeof(s_dyld_layout_digest_baseline)) != 0 ? 1 : 0;
}
