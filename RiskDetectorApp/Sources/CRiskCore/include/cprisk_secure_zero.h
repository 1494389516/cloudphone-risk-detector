/*
 * cprisk_secure_zero.h — Compiler-safe secure memory wipe.
 *
 * Uses volatile writes to prevent dead-store elimination. Forced inline
 * so no PLT/GOT symbol is generated for hooking.
 */

#ifndef CPRISK_SECURE_ZERO_H
#define CPRISK_SECURE_ZERO_H

#include <stddef.h>
#include <stdint.h>

static inline __attribute__((always_inline))
void cprisk_secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) *p++ = 0;
}

#endif /* CPRISK_SECURE_ZERO_H */
