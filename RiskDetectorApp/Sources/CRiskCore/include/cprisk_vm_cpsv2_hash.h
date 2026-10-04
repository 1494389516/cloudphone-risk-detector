/* Streaming custom-pad MAC; caller must validate/snapshot the manifest first. */
#ifndef CPRISK_VM_CPSV2_HASH_H
#define CPRISK_VM_CPSV2_HASH_H
#include "cprisk_vm_cpsv2.h"
#include "cprisk_armor_abi.h"
static inline uint32_t cprisk_cpsv2_tag(const uint8_t key[32],
    const uint8_t snapshot[CPRISK_CPSV2_BYTES], uintptr_t base,
    const cprisk_cpsv2_range ranges[CPRISK_CPSV2_COUNT]) {
    uint8_t pad[64], inner[32], digest[32];
    cprisk_crypto_trace_primitive_enter_i();
    cprisk_sha256_ctx hash;
    for (unsigned i = 0; i < 64u; i++)
        pad[i] = (i < 32u ? key[i] : 0u) ^ CPRISK_HMAC_IPAD_XOR_A ^ CPRISK_HMAC_IPAD_XOR_B;
    cprisk_sha256_init(&hash);
    cprisk_sha256_update(&hash, pad, sizeof(pad));
    cprisk_sha256_update(&hash, snapshot, CPRISK_CPSV2_BYTES);
    for (unsigned i = 0; i < CPRISK_CPSV2_COUNT; i++)
        cprisk_sha256_update(&hash, (const uint8_t *)(base + ranges[i].rva), ranges[i].length);
    cprisk_sha256_final(&hash, inner);
    for (unsigned i = 0; i < 64u; i++)
        pad[i] = (i < 32u ? key[i] : 0u) ^ CPRISK_HMAC_OPAD_XOR_A ^ CPRISK_HMAC_OPAD_XOR_B;
    cprisk_sha256_init(&hash);
    cprisk_sha256_update(&hash, pad, sizeof(pad));
    cprisk_sha256_update(&hash, inner, sizeof(inner));
    cprisk_sha256_final(&hash, digest);
    uint32_t tag = cprisk_cpsv2_u32(digest);
    cprisk_secure_zero(pad, sizeof(pad));
    cprisk_secure_zero(inner, sizeof(inner));
    cprisk_secure_zero(digest, sizeof(digest));
    cprisk_secure_zero(&hash, sizeof(hash));
    return tag;
}
#endif
