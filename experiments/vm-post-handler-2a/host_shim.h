/* Test-only: no Mach-O discovery on the Linux host. Never ship this header. */
#define CPRISK_MACHO_H
#include <stddef.h>
#include <stdint.h>
struct mach_header_64;
static inline const struct mach_header_64 *cprisk_find_own_header(const void *p) { (void)p; return NULL; }
static inline const uint8_t *cprisk_find_section(const struct mach_header_64 *h, const char *s, const char *n, unsigned long *z) { (void)h; (void)s; (void)n; if(z)*z=0; return NULL; }
