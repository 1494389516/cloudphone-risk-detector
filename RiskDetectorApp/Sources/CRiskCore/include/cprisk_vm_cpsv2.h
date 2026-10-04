/* CPSV v2 wire contract. Independent of the global armor ABI and of Mach-O.
 * All integers are little-endian. No pointers or chained-fixup slots on disk.
 * Hash message: complete 960-byte manifest, then code ranges in roster order.
 * Callers must snapshot the manifest before validation and subsequent hashing.
 */
#ifndef CPRISK_VM_CPSV2_H
#define CPRISK_VM_CPSV2_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define CPRISK_CPSV2_VERSION 2u
#define CPRISK_CPSV2_COUNT 58u
#define CPRISK_CPSV2_HEADER_BYTES 32u
#define CPRISK_CPSV2_BYTES (CPRISK_CPSV2_HEADER_BYTES + CPRISK_CPSV2_COUNT * 16u)
#define CPRISK_CPSV2_MAX_RANGE 65536u
#define CPRISK_CPSV2_MAX_TOTAL 1048576u

typedef struct { uint64_t rva; uint32_t length, kind; } cprisk_cpsv2_range;

static inline uint32_t cprisk_cpsv2_u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static inline uint64_t cprisk_cpsv2_u64(const uint8_t *p) {
    return cprisk_cpsv2_u32(p) | (uint64_t)cprisk_cpsv2_u32(p+4)<<32;
}
static inline uint32_t cprisk_cpsv2_kind(uint32_t i) {
    if (i < 6u) return i + 1u;
    uint32_t lane = (i - 6u) / 26u, op = (i - 6u) % 26u;
    return ((lane + 1u) << 8) + (op < 24u ? op : op == 24u ? 255u : 254u);
}

/* expected_rvas is independently computed from compiled function identities.
 * Validate every descriptor before any caller reads code. Output is usable
 * only on success. Subtraction-based bounds checks reject integer overflow.
 */
static inline int cprisk_cpsv2_parse(const uint8_t *p, size_t size,
                                    const uint8_t uuid[16],
                                    const uint64_t expected_rvas[CPRISK_CPSV2_COUNT],
                                    uint64_t text_rva, uint64_t text_size,
                                    cprisk_cpsv2_range out[CPRISK_CPSV2_COUNT]) {
    if (!p || !uuid || !expected_rvas || !out || size != CPRISK_CPSV2_BYTES
        || text_size > UINT64_MAX - text_rva) return 0;
    if (cprisk_cpsv2_u32(p) != 0x56535043u || cprisk_cpsv2_u32(p+4) != 2u
        || cprisk_cpsv2_u32(p+8) != CPRISK_CPSV2_COUNT || cprisk_cpsv2_u32(p+12)
        || memcmp(p+16, uuid, 16)) return 0;
    unsigned nonzero = 0;
    for (unsigned j=0; j<16; j++) nonzero |= uuid[j];
    if (!nonzero) return 0;
    size_t total = 0;
    for (uint32_t i=0; i<CPRISK_CPSV2_COUNT; i++) {
        const uint8_t *e = p + CPRISK_CPSV2_HEADER_BYTES + i*16u;
        uint64_t rva = cprisk_cpsv2_u64(e);
        uint32_t len = cprisk_cpsv2_u32(e+8), kind = cprisk_cpsv2_u32(e+12);
        if (kind != cprisk_cpsv2_kind(i) || rva != expected_rvas[i]
            || (rva & 3u) || (len & 3u) || !len || len > CPRISK_CPSV2_MAX_RANGE
            || rva < text_rva || rva - text_rva > text_size
            || len > text_size - (rva - text_rva)
            || len > CPRISK_CPSV2_MAX_TOTAL - total) return 0;
        for (uint32_t j=0; j<i; j++) {
            if (rva < out[j].rva + out[j].length && out[j].rva < rva + len) return 0;
        }
        out[i] = (cprisk_cpsv2_range){ rva, len, kind };
        total += len;
    }
    return 1;
}
#endif
