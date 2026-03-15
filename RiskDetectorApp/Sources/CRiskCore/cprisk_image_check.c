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
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_init.h>

static int segname_eq(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 1;
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
