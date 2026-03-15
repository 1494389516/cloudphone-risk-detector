/*
 * cprisk_macho.h — Self-contained Mach-O header discovery & section lookup.
 *
 * Replaces dladdr() / getsectiondata() / _dyld_* to block Clean Copy attacks
 * where an attacker hooks dyld APIs to feed a pristine binary copy.
 *
 * All functions are static inline __attribute__((always_inline)) so the
 * compiler emits code directly in the caller's text section — no PLT/GOT
 * entries, no hookable symbols.
 */

#ifndef CPRISK_MACHO_H
#define CPRISK_MACHO_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <mach-o/loader.h>

/* ── Header discovery ─────────────────────────────────────────────── */

/*
 * Scan backward from addr_in_image (page-aligned) to locate the
 * mach_header_64 of the image containing that address.
 * Mach-O headers are always page-aligned and start with MH_MAGIC_64.
 * Limit: 256 MB (65536 × 4 KB pages) to prevent runaway scans.
 */
static inline __attribute__((always_inline))
const struct mach_header_64 *cprisk_find_own_header(const void *addr_in_image) {
    uintptr_t addr = (uintptr_t)addr_in_image;
    addr &= ~(uintptr_t)0xFFF;

    for (int i = 0; i < 65536; i++) {
        const struct mach_header_64 *hdr = (const struct mach_header_64 *)addr;
        if (hdr->magic == MH_MAGIC_64 &&
            hdr->cputype != 0 &&
            (hdr->filetype == MH_EXECUTE || hdr->filetype == MH_DYLIB ||
             hdr->filetype == MH_BUNDLE) &&
            hdr->ncmds > 0 && hdr->ncmds < 4096 &&
            hdr->sizeofcmds > 0 && hdr->sizeofcmds < 0x2000000u) {
            return hdr;
        }
        if (addr < 0x1000) break;
        addr -= 0x1000;
    }
    return NULL;
}

/* ── ASLR slide computation ───────────────────────────────────────── */

/*
 * Compute the ASLR slide for an image given its runtime header address.
 * slide = runtime_header_addr − __TEXT.vmaddr (the on-disk virtual address).
 */
static inline __attribute__((always_inline))
intptr_t cprisk_compute_slide(const struct mach_header_64 *hdr) {
    const uint8_t *p = (const uint8_t *)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize == 0) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)p;
            if (strncmp(seg->segname, "__TEXT", 6) == 0)
                return (intptr_t)((uintptr_t)hdr - seg->vmaddr);
        }
        p += lc->cmdsize;
    }
    return 0;
}

/* ── Section lookup ───────────────────────────────────────────────── */

/*
 * Locate a section by segment + section name, returning its runtime
 * (slid) address and size.  Drop-in replacement for getsectiondata().
 */
static inline __attribute__((always_inline))
const uint8_t *cprisk_find_section(
    const struct mach_header_64 *hdr,
    const char *seg_name,
    const char *sect_name,
    unsigned long *size_out
) {
    const intptr_t slide = cprisk_compute_slide(hdr);
    const uint8_t *p = (const uint8_t *)(hdr + 1);

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize == 0) break;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)p;
            if (strncmp(seg->segname, seg_name, 16) == 0) {
                const struct section_64 *sections =
                    (const struct section_64 *)(p + sizeof(*seg));
                for (uint32_t s = 0; s < seg->nsects; s++) {
                    if (strncmp(sections[s].sectname, sect_name, 16) == 0) {
                        if (size_out)
                            *size_out = (unsigned long)sections[s].size;
                        return (const uint8_t *)(sections[s].addr + slide);
                    }
                }
            }
        }
        p += lc->cmdsize;
    }

    if (size_out) *size_out = 0;
    return NULL;
}

#endif /* CPRISK_MACHO_H */
