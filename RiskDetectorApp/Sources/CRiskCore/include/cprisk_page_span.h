#ifndef CPRISK_PAGE_SPAN_H
#define CPRISK_PAGE_SPAN_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

static inline size_t cprisk_system_page_size_i(void) {
    const long value = sysconf(_SC_PAGESIZE);
    if (value <= 0 || ((size_t)value & ((size_t)value - 1u)) != 0u)
        return 0u;
    return (size_t)value;
}

/* Explicit page size also permits deterministic 4K/16K boundary validation. */
static inline int cprisk_page_span_for_size_i(const void *ptr, size_t len,
                                              size_t size, uintptr_t *page,
                                              size_t *span) {
    if (!ptr || !len || !page || !span || !size || (size & (size - 1u)))
        return -1;
    const uintptr_t addr = (uintptr_t)ptr;
    const uintptr_t mask = size - 1u;
    if (len > UINTPTR_MAX - addr || addr + len > UINTPTR_MAX - mask)
        return -1;
    const uintptr_t start = addr & ~mask;
    const uintptr_t end = (addr + len + mask) & ~mask;
    if (end <= start)
        return -1;
    *page = start;
    *span = (size_t)(end - start);
    return 0;
}

static inline int cprisk_system_page_span_i(const void *ptr, size_t len,
                                            void **page, size_t *span) {
    uintptr_t start = 0u;
    if (!page || cprisk_page_span_for_size_i(ptr, len, cprisk_system_page_size_i(),
                                            &start, span) != 0)
        return -1;
    *page = (void *)start;
    return 0;
}
#endif
