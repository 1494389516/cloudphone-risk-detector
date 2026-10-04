#include "cprisk_vm_cpsv2_hash.h"
void cprisk_crypto_trace_primitive_enter_i(void) {}
int parse(const uint8_t *p, size_t n, const uint8_t *uuid, const uint64_t *rvas,
          uint64_t start, uint64_t size) {
    cprisk_cpsv2_range ranges[CPRISK_CPSV2_COUNT];
    return cprisk_cpsv2_parse(p,n,uuid,rvas,start,size,ranges);
}
int tag(const uint8_t *p, size_t n, const uint8_t *uuid, const uint64_t *rvas,
        const uint8_t *image, size_t image_size, const uint8_t *key, uint32_t *out) {
    cprisk_cpsv2_range ranges[CPRISK_CPSV2_COUNT];
    if(!cprisk_cpsv2_parse(p,n,uuid,rvas,0,image_size,ranges)) return 0;
    *out=cprisk_cpsv2_tag(key,p,(uintptr_t)image,ranges);
    return 1;
}
uint64_t cprisk_crypto_trace_now_i(void) { return 0; }
void cprisk_crypto_trace_record_span_ticks_i(uint64_t n) { (void)n; }
