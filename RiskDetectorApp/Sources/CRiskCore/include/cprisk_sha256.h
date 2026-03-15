/*
 * cprisk_sha256.h — Header-only, fully-inlined FIPS-180-4 SHA-256.
 *
 * Every function is static inline __attribute__((always_inline)) so the
 * compiler is forced to emit code in the caller's text section.  No PLT/GOT
 * entry is generated, which prevents trivial Frida hooks on CC_SHA256.
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

/* ── SHA-256 round constants (FIPS-180-4 §4.2.2) ──────────────────── */

static const uint32_t cprisk_sha256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

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
        uint32_t T1 = h + cprisk_sha256_sigma1(e) +
                       cprisk_sha256_ch(e, f, g) + cprisk_sha256_K[i] + W[i];
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
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
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
