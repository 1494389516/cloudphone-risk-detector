/*
 * cprisk_sha256.h — Header-only, fully-inlined FIPS-180-4 SHA-256.
 *
 * Every function is static inline __attribute__((always_inline)) so the
 * compiler is forced to emit code in the caller's text section.  No PLT/GOT
 * entry is generated, which prevents trivial Frida hooks on CC_SHA256.
 *
 * Round constants H(0) and K[] are stored XOR-mixed with a deterministic
 * per-index mask (not the standard FIPS literals on disk) and decoded at
 * runtime on the stack / in registers only.
 */

#ifndef CPRISK_SHA256_H
#define CPRISK_SHA256_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define CPRISK_SHA256_DIGEST_LENGTH 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
} cprisk_sha256_ctx;

/* ── helpers ───────────────────────────────────────────────────────── */

static inline __attribute__((always_inline))
uint32_t cprisk_sha256_rotr(uint32_t x, unsigned n) {
    return (n == 0 || n >= 32) ? x : ((x >> n) | (x << (32 - n)));
}

static inline __attribute__((always_inline))
uint32_t cprisk_sha256_ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline __attribute__((always_inline))
uint32_t cprisk_sha256_maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline __attribute__((always_inline))
uint32_t cprisk_sha256_sigma0(uint32_t x) {
    return cprisk_sha256_rotr(x, 2) ^ cprisk_sha256_rotr(x, 13) ^ cprisk_sha256_rotr(x, 22);
}

static inline __attribute__((always_inline))
uint32_t cprisk_sha256_sigma1(uint32_t x) {
    return cprisk_sha256_rotr(x, 6) ^ cprisk_sha256_rotr(x, 11) ^ cprisk_sha256_rotr(x, 25);
}

static inline __attribute__((always_inline))
uint32_t cprisk_sha256_gamma0(uint32_t x) {
    return cprisk_sha256_rotr(x, 7) ^ cprisk_sha256_rotr(x, 18) ^ (x >> 3);
}

static inline __attribute__((always_inline))
uint32_t cprisk_sha256_gamma1(uint32_t x) {
    return cprisk_sha256_rotr(x, 17) ^ cprisk_sha256_rotr(x, 19) ^ (x >> 10);
}

static inline __attribute__((always_inline))
uint32_t cprisk_sha256_load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
           ((uint32_t)p[3]);
}

static inline __attribute__((always_inline))
void cprisk_sha256_store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
}

static inline __attribute__((always_inline))
void cprisk_sha256_store_be64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >>  8);
    p[7] = (uint8_t)(v);
}

/* Deterministic mask — not the standard SHA-256 constants (reduces .rodata fingerprint). */
static inline __attribute__((always_inline))
uint32_t cprisk_sha256_const_mask_u32(unsigned idx) {
    uint64_t s = UINT64_C(0x9E3779B97F4A7C15) + (uint64_t)idx * UINT64_C(0xD6E8FEB866D1F289);
    s = (s ^ (s >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    s = (s ^ (s >> 27)) * UINT64_C(0x94D049BB133111EB);
    return (uint32_t)(s ^ (s >> 32));
}

/* XOR-mixed K[i] (FIPS §4.2.2) — decode with cprisk_sha256_const_mask_u32(i). */
static const uint32_t cprisk_sha256_K_enc[64] = {
    0x1ff61a7eu, 0x8d326f67u, 0xcc9f2631u, 0xd638196au,
    0xb209bcbcu, 0xa6bc8effu, 0xfa5592e5u, 0xa4c529fbu,
    0x45255cbcu, 0xf3522a3cu, 0x1eefc9b8u, 0xdf516ab0u,
    0x86d63f8cu, 0xe0285c37u, 0x8eb2fab6u, 0x420a8c90u,
    0x12d97705u, 0xdfb3de39u, 0x5ff9d1e7u, 0x9c9d8c1bu,
    0xd5dbf094u, 0x4455d4e3u, 0x51413ab7u, 0x68c3eae5u,
    0x814722fcu, 0x4603c5dbu, 0x61bf7829u, 0xf2dfe789u,
    0x4deb152du, 0x56c1764cu, 0x2b7d34edu, 0xb57fcc20u,
    0x341d7bb1u, 0x39685938u, 0x5138b0bdu, 0xd27b4fc0u,
    0x06b53c76u, 0x116dd297u, 0xa8246e6eu, 0xe2f56e11u,
    0xc0397d7au, 0x9c5792ddu, 0x52df66a2u, 0x2c346823u,
    0xecebc734u, 0xc3e34e6bu, 0x59cc7d81u, 0x4d52e3edu,
    0x4a7216f5u, 0xdc1009d6u, 0xa7a40b89u, 0xe49a1484u,
    0x9034708cu, 0x195d3f5au, 0x2c3d05f7u, 0x07d9692au,
    0x5304af61u, 0xf8f81383u, 0xa31c4479u, 0x23f83d83u,
    0x48eae83fu, 0xabc161c8u, 0x8610655du, 0x53269b4eu,
};

static const uint32_t cprisk_sha256_H0_enc[8] = {
    0x5d5a6f5eu, 0x05e4f43bu, 0x7436e926u, 0x8088f187u,
    0xe5aba34au, 0x683f0fd0u, 0xe17af6f6u, 0xb59c6f35u,
};

static inline __attribute__((always_inline))
uint32_t cprisk_sha256_K_dec_at(unsigned i) {
    return cprisk_sha256_K_enc[i] ^ cprisk_sha256_const_mask_u32(i);
}

/* ── block transform ───────────────────────────────────────────────── */

static inline __attribute__((always_inline))
void cprisk_sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++)
        W[i] = cprisk_sha256_load_be32(block + i * 4);
    for (int i = 16; i < 64; i++)
        W[i] = cprisk_sha256_gamma1(W[i-2]) + W[i-7] +
               cprisk_sha256_gamma0(W[i-15]) + W[i-16];

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t Ki = cprisk_sha256_K_dec_at((unsigned)i);
        uint32_t T1 = h + cprisk_sha256_sigma1(e) +
                       cprisk_sha256_ch(e, f, g) + Ki + W[i];
        uint32_t T2 = cprisk_sha256_sigma0(a) + cprisk_sha256_maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* ── public API ────────────────────────────────────────────────────── */

static inline __attribute__((always_inline))
void cprisk_sha256_init(cprisk_sha256_ctx *ctx) {
    for (unsigned j = 0; j < 8u; j++)
        ctx->state[j] = cprisk_sha256_H0_enc[j] ^ cprisk_sha256_const_mask_u32(64u + j);
    ctx->count = 0;
    memset(ctx->buffer, 0, 64);
}

static inline __attribute__((always_inline))
void cprisk_sha256_update(cprisk_sha256_ctx *ctx,
                          const uint8_t *data, size_t len) {
    size_t buf_used = (size_t)(ctx->count & 63);
    ctx->count += (uint64_t)len;

    if (buf_used > 0) {
        size_t avail = 64 - buf_used;
        if (len < avail) {
            memcpy(ctx->buffer + buf_used, data, len);
            return;
        }
        memcpy(ctx->buffer + buf_used, data, avail);
        cprisk_sha256_transform(ctx->state, ctx->buffer);
        data += avail;
        len  -= avail;
    }

    while (len >= 64) {
        cprisk_sha256_transform(ctx->state, data);
        data += 64;
        len  -= 64;
    }

    if (len > 0)
        memcpy(ctx->buffer, data, len);
}

static inline __attribute__((always_inline))
void cprisk_sha256_final(cprisk_sha256_ctx *ctx, uint8_t out[32]) {
    uint64_t total_bits = ctx->count * 8;
    size_t buf_used = (size_t)(ctx->count & 63);

    ctx->buffer[buf_used++] = 0x80;

    if (buf_used > 56) {
        memset(ctx->buffer + buf_used, 0, 64 - buf_used);
        cprisk_sha256_transform(ctx->state, ctx->buffer);
        buf_used = 0;
    }

    memset(ctx->buffer + buf_used, 0, 56 - buf_used);
    cprisk_sha256_store_be64(ctx->buffer + 56, total_bits);
    cprisk_sha256_transform(ctx->state, ctx->buffer);

    for (int i = 0; i < 8; i++)
        cprisk_sha256_store_be32(out + i * 4, ctx->state[i]);
}

static inline __attribute__((always_inline))
void cprisk_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, data, len);
    cprisk_sha256_final(&ctx, out);
}

#endif /* CPRISK_SHA256_H */
