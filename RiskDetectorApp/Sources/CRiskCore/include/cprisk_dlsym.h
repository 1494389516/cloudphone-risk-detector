/*
 * cprisk_dlsym.h — Custom IAT/GOT-free symbol resolver.
 *
 * Locates dyld_all_image_infos, finds the target image by name,
 * and parses its Mach-O Export Trie to find symbol addresses.
 * Avoids standard dlsym to hide external dependencies from static analysis.
 */

#ifndef CPRISK_DLSYM_H
#define CPRISK_DLSYM_H

#include <stdint.h>
#include <stddef.h>
#include <mach-o/loader.h>
#include <mach-o/dyld_images.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_init.h>

#ifndef LC_DYLD_EXPORTS_TRIE
#define LC_DYLD_EXPORTS_TRIE (0x80000033)
#endif

static inline __attribute__((always_inline))
int cprisk_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

static inline __attribute__((always_inline))
const char *cprisk_strstr(const char *haystack, const char *needle) {
    if (!*needle) return haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            h++;
            n++;
        }
        if (!*n) return haystack;
    }
    return NULL;
}

static inline __attribute__((always_inline))
size_t cprisk_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

#define CPRISK_ULEB128_MAX_ITER 10

static inline __attribute__((always_inline))
uint64_t cprisk_read_uleb128(const uint8_t **p, const uint8_t *end) {
    uint64_t result = 0;
    int bit = 0;
    int iter = 0;
    do {
        if (*p >= end || iter >= CPRISK_ULEB128_MAX_ITER)
            return 0;
        uint64_t slice = **p & 0x7f;
        result |= (slice << bit);
        bit += 7;
        iter++;
    } while (*(*p)++ & 0x80);
    return result;
}

static inline __attribute__((always_inline))
void *cprisk_walk_export_trie(const uint8_t *start, const uint8_t *end, const uint8_t *p, const char *symbol) {
    if (p >= end) return NULL;
    uint64_t terminal_size = cprisk_read_uleb128(&p, end);
    const uint8_t *children = p + terminal_size;
    if (children > end) return NULL;

    if (terminal_size != 0 && *symbol == '\0') {
        uint64_t flags = cprisk_read_uleb128(&p, end);
        if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) {
            return NULL; /* Re-exports not supported in basic resolver */
        }
        uint64_t symbol_offset = cprisk_read_uleb128(&p, end);
        return (void *)(uintptr_t)symbol_offset;
    }

    if (children >= end) return NULL;
    uint8_t child_count = *children++;
    for (uint8_t i = 0; i < child_count; i++) {
        if (children >= end) return NULL;
        const char *edge_label = (const char *)children;
        while (children < end && *children != '\0') {
            children++;
        }
        if (children >= end) return NULL;
        children++;
        uint64_t node_offset = cprisk_read_uleb128(&children, end);
        if (node_offset == 0 || (start + node_offset) >= end) continue; /* skip invalid node */
        
        int match = 1;
        int j = 0;
        while (edge_label[j] != '\0') {
            if (symbol[j] != edge_label[j]) {
                match = 0;
                break;
            }
            j++;
        }
        if (match) {
            return cprisk_walk_export_trie(start, end, start + node_offset, symbol + j);
        }
    }
    return NULL;
}

static inline __attribute__((always_inline))
void *cprisk_dlsym(const char *image_name, const char *symbol) {
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    
    if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) != 0) {
        return NULL;
    }
    
    struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *)dyld_info.all_image_info_addr;
    if (!infos) return NULL;
    
    for (uint32_t i = 0; i < infos->infoArrayCount; i++) {
        const char *path = infos->infoArray[i].imageFilePath;
        if (!path) continue;
        if (cprisk_strstr(path, image_name) != NULL) {
            const struct mach_header_64 *hdr = (const struct mach_header_64 *)infos->infoArray[i].imageLoadAddress;
            const uint8_t *p = (const uint8_t *)(hdr + 1);
            const uint8_t *end = (const uint8_t *)hdr + sizeof(struct mach_header_64) + hdr->sizeofcmds;
            intptr_t slide = 0;
            const struct segment_command_64 *linkedit = NULL;
            uint32_t export_off = 0;
            uint32_t export_size = 0;

            for (uint32_t j = 0; j < hdr->ncmds; j++) {
                if (p + sizeof(struct load_command) > end) break;
                const struct load_command *lc = (const struct load_command *)p;
                if (lc->cmdsize == 0) break;
                if (p + lc->cmdsize > end) break;
                if (lc->cmd == LC_SEGMENT_64) {
                    const struct segment_command_64 *seg = (const struct segment_command_64 *)p;
                    if (cprisk_strcmp(seg->segname, "__TEXT") == 0) {
                        slide = (intptr_t)hdr - seg->vmaddr;
                    } else if (cprisk_strcmp(seg->segname, "__LINKEDIT") == 0) {
                        linkedit = seg;
                    }
                } else if (lc->cmd == LC_DYLD_INFO || lc->cmd == LC_DYLD_INFO_ONLY) {
                    const struct dyld_info_command *cmd = (const struct dyld_info_command *)p;
                    export_off = cmd->export_off;
                    export_size = cmd->export_size;
                } else if (lc->cmd == LC_DYLD_EXPORTS_TRIE) {
                    const struct linkedit_data_command *cmd = (const struct linkedit_data_command *)p;
                    export_off = cmd->dataoff;
                    export_size = cmd->datasize;
                }
                p += lc->cmdsize;
            }

            if (linkedit && export_off != 0 && export_size != 0) {
                uintptr_t linkedit_base = linkedit->vmaddr + slide - linkedit->fileoff;
                const uint8_t *export_trie = (const uint8_t *)(linkedit_base + export_off);
                
                /* Mach-O symbols in export trie typically begin with an underscore '_' */
                char sym_with_underscore[256];
                sym_with_underscore[0] = '_';
                size_t sym_len = cprisk_strlen(symbol);
                if (sym_len > 254) sym_len = 254;
                for (size_t k = 0; k < sym_len; k++) {
                    sym_with_underscore[k + 1] = symbol[k];
                }
                sym_with_underscore[sym_len + 1] = '\0';
                
                void *offset = cprisk_walk_export_trie(export_trie, export_trie + export_size, export_trie, sym_with_underscore);
                if (offset) {
                    return (void *)((uintptr_t)hdr + (uintptr_t)offset); 
                }
            }
        }
    }
    return NULL;
}

#endif /* CPRISK_DLSYM_H */
