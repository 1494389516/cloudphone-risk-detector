#ifndef CPRISK_INSTRUCTION_CACHE_H
#define CPRISK_INSTRUCTION_CACHE_H

#include <stddef.h>

#if defined(__APPLE__)
#include <libkern/OSCacheControl.h>
#endif

static inline void cprisk_flush_instruction_cache(void *address, size_t length) {
    if (address == NULL || length == 0u) {
        return;
    }

#if defined(__APPLE__)
    sys_icache_invalidate(address, length);
#else
    char *start = (char *)address;
    __builtin___clear_cache(start, start + length);
#endif
}

#endif /* CPRISK_INSTRUCTION_CACHE_H */
