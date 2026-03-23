/*
 * cprisk_sha256.h — Header-only, fully-inlined FIPS-180-4 SHA-256.
 *
 * Every function is static inline __attribute__((always_inline)) so the
 * compiler is forced to emit code in the caller's text section.  No PLT/GOT
 * entry is generated, which prevents trivial Frida hooks on CC_SHA256.
 *
 * Round constants K[] and H(0) are not stored as single XOR-masked FIPS
 * literals: each word is split across additive shares. During the round
 * transform, K is re-masked per round before being added so the canonical
 * FIPS K[i] does not need to live as one local scalar operand.
 *
 * A lightweight crypto trace hook runs on \c cprisk_sha256() one-shot and on
 * \c cprisk_hmac_sha256() entry; see cprisk_crypto_trace.h.
 */

#ifndef CPRISK_SHA256_H
#define CPRISK_SHA256_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "cprisk_crypto_trace.h"

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

/*
 * Split K[i] = K_lo[i] + K_hi[i] (unsigned wrap) — avoids storing each full
 * word as one XOR-encoded literal in rodata.
 */
static const uint32_t cprisk_sha256_K_lo[64] = {
    0x1bd35e74u, 0xd8123a8eu, 0xf9901199u, 0x5295e566u,
    0xf90e2815u, 0x762dd6dau, 0x2d276115u, 0x3e49ed60u,
    0x9fb18128u, 0x5296e670u, 0x6fb5b8b2u, 0x4e03701au,
    0x8375602du, 0xed402082u, 0xd62de7cbu, 0xed6a957fu,
    0x2205e812u, 0x1a89c3a2u, 0xfbd65a44u, 0xdb666b74u,
    0x2b230dd5u, 0x9667cf73u, 0x1f819500u, 0x8abc8fedu,
    0xfbfc9619u, 0x1badc62fu, 0xf69f3700u, 0x31a68e18u,
    0xe986909eu, 0xbd0ad8e5u, 0xf845c7ecu, 0x2608bfaeu,
    0x831456cau, 0xfbb6a911u, 0x85ecf460u, 0x61239152u,
    0x6966f060u, 0x209fa76bu, 0xf033a723u, 0xfb582994u,
    0x5c989585u, 0x438ecc92u, 0xbce7afa6u, 0xeff80cddu,
    0x8c1fd83du, 0x74394cdau, 0x21afb2c4u, 0xaacb04a5u,
    0x5a4210d2u, 0xd4fda55cu, 0x445d27b9u, 0x6078836au,
    0x67ecc505u, 0xd701e361u, 0xdb891c60u, 0x2d984313u,
    0x666b55c2u, 0xaf69a3beu, 0xbae87681u, 0xdcf8032du,
    0xa8ea219au, 0x80f5a80cu, 0x798e2fedu, 0xb5ab6993u
};

static const uint32_t cprisk_sha256_K_hi[64] = {
    0x26b6d124u, 0x99250a03u, 0xbc30ea36u, 0x971ff63fu,
    0x40489a46u, 0xe3c33b17u, 0x6518218fu, 0x6cd27175u,
    0x38562970u, 0xbfec7491u, 0xb47bcd0cu, 0x07090da9u,
    0xef48fd47u, 0x939e917cu, 0xc5ae1edcu, 0xd4315bf5u,
    0xc29581afu, 0xd53483e4u, 0x13eb4382u, 0x48a63658u,
    0x02c61e9au, 0xb40cb537u, 0x3d2f14dcu, 0xec3cf8edu,
    0x9c41bb39u, 0x8c84003eu, 0xb963f0c8u, 0x8db2f1afu,
    0xdd597b55u, 0x189cb862u, 0x0e849b65u, 0xee2069b9u,
    0xa4a2b3bbu, 0x32647827u, 0xc73f799cu, 0xf2147bc1u,
    0xfba382f4u, 0x55ca6350u, 0x918f220bu, 0x971a02f1u,
    0x4627531cu, 0x648b99b9u, 0x0563dbcau, 0xd77444c6u,
    0x45730fdcu, 0x625fb94au, 0xd25e82c1u, 0x659f9bcbu,
    0xbf62b044u, 0x4939c6acu, 0xe2eb4f93u, 0xd438394bu,
    0xd12f47aeu, 0x77d6c6e9u, 0x8013adefu, 0x3a962ce0u,
    0x0e242d2cu, 0xc93bbfb1u, 0xc9e00193u, 0xafcefedbu,
    0xe7d4de60u, 0x235ac4dfu, 0x456b740au, 0x10c60f5fu
};

static const uint32_t cprisk_sha256_H0_lo[8] = {
    0xb0b3db30u, 0x87931ee6u, 0xfad3c8eeu, 0xcfeb81bcu,
    0xc3bbf4e0u, 0x62f02117u, 0x0cc6db72u, 0x1e360382u,
};

static const uint32_t cprisk_sha256_H0_hi[8] = {
    0xb9560b37u, 0x33d48f9fu, 0x419b2a84u, 0xd564737eu,
    0x8d525d9fu, 0x38154775u, 0x12bcfe39u, 0x3daac997u,
};

/* Non-cryptographic mixing table — extra memory traffic in the transform. */
static const uint8_t cprisk_sha256_memnoise[64] = {
    0x47u, 0x1eu, 0x9cu, 0x63u, 0xb0u, 0x2fu, 0x55u, 0x88u,
    0xadu, 0x31u, 0x72u, 0x04u, 0xe8u, 0xcfu, 0x1bu, 0x5eu,
    0x92u, 0x67u, 0x38u, 0xabu, 0xd4u, 0x11u, 0x0cu, 0xf6u,
    0x29u, 0x7eu, 0x53u, 0xc1u, 0x84u, 0xdeu, 0x3au, 0x60u,
    0x15u, 0xebu, 0x9au, 0x44u, 0x77u, 0x02u, 0xfcu, 0xb3u,
    0x6du, 0x21u, 0x8eu, 0x50u, 0xc3u, 0x9du, 0x74u, 0x0au,
    0x36u, 0xe1u, 0x68u, 0xb9u, 0x4cu, 0x97u, 0x23u, 0xddu,
    0xaeu, 0x41u, 0x82u, 0x59u, 0x07u, 0xd0u, 0xcbu, 0x3eu,
};

typedef struct {
    uint32_t share0;
    uint32_t share1;
} cprisk_sha256_masked_word;

static inline __attribute__((always_inline))
uint32_t cprisk_sha256_round_mask_seed(unsigned i, uint32_t lane_seed) {
    uint32_t mem_mix = (uint32_t)cprisk_sha256_memnoise[(i * 13u) & 63u] << 24;
    mem_mix ^= (uint32_t)cprisk_sha256_memnoise[(i * 29u + 7u) & 63u] << 16;
    mem_mix ^= (uint32_t)cprisk_sha256_memnoise[(i * 37u + 19u) & 63u] << 8;
    mem_mix ^= (uint32_t)cprisk_sha256_memnoise[(i * 53u + 31u) & 63u];

    uint32_t mask = cprisk_sha256_rotr(lane_seed ^ mem_mix ^ ((i + 1u) * 0x9E3779B9u),
                                       (unsigned)((i & 7u) + 1u));
    mask += ((i + 1u) * 0x7F4A7C15u) ^ 0xA5C31F27u;
    mask ^= cprisk_sha256_rotr(lane_seed + 0x6A09E667u, (unsigned)(((i >> 1) & 7u) + 1u));
    return mask;
}

static inline __attribute__((always_inline))
cprisk_sha256_masked_word cprisk_sha256_K_masked_at(unsigned i, uint32_t lane_seed) {
    uint32_t round_mask = cprisk_sha256_round_mask_seed(i, lane_seed);
    if (round_mask == 0u ||
        round_mask == cprisk_sha256_K_hi[i] ||
        round_mask == (0u - cprisk_sha256_K_lo[i])) {
        round_mask ^= 0xB7E15162u + ((i + 1u) * 0x85EBCA6Bu);
        round_mask += 0xC4D2BE91u ^ ((i + 1u) * 0x27D4EB2Fu);
    }
    cprisk_sha256_masked_word out;
    out.share0 = cprisk_sha256_K_lo[i] + round_mask;
    out.share1 = cprisk_sha256_K_hi[i] - round_mask;
    return out;
}

static inline __attribute__((always_inline))
uint32_t cprisk_sha256_round_t1_masked(uint32_t h,
                                       uint32_t e,
                                       uint32_t f,
                                       uint32_t g,
                                       uint32_t Wi,
                                       unsigned i,
                                       uint32_t lane_seed) {
    cprisk_sha256_masked_word masked_K = cprisk_sha256_K_masked_at(i, lane_seed);
    volatile uint32_t lane0 = h + cprisk_sha256_sigma1(e);
    volatile uint32_t lane1 = Wi;
    lane0 += cprisk_sha256_ch(e, f, g);
    lane0 += masked_K.share0;
    lane1 += masked_K.share1;
    return lane0 + lane1;
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
    uint64_t trace_round16_ticks = 0u;
    volatile uint32_t noise_sink = state[0] ^ W[0] ^ 0xA5C31F27u;

    for (int i = 0; i < 64; i++) {
        uint32_t round_seed = noise_sink ^ a ^
                              cprisk_sha256_rotr(e, (unsigned)(((unsigned)i & 7u) + 1u)) ^
                              W[((unsigned)i + 9u) & 63u] ^
                              ((uint32_t)(unsigned)i * 0xA5A5A5A5u);
        uint32_t T1 = cprisk_sha256_round_t1_masked(h, e, f, g, W[i], (unsigned)i, round_seed);
        uint32_t T2 = cprisk_sha256_sigma0(a) + cprisk_sha256_maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
        if (((unsigned)i & 3u) == 0u) {
            uint32_t decoy = a ^ cprisk_sha256_rotr(e, (unsigned)(((unsigned)i & 7u) + 1u));
            decoy += W[((unsigned)i + 11u) & 63u] ^ cprisk_sha256_sigma0(c);
            decoy ^= cprisk_sha256_sigma1(g) + (uint32_t)((unsigned)i * 0x9E3779B1u);
            decoy ^= (uint32_t)cprisk_sha256_memnoise[(decoy + (uint32_t)(unsigned)i + W[(unsigned)i & 63u]) & 63u];
            noise_sink ^= decoy;
            noise_sink = cprisk_sha256_rotr(noise_sink, (unsigned)(((unsigned)i & 7u) + 1u));
        }
        if (i == 15) {
            trace_round16_ticks = cprisk_crypto_trace_now_i();
        } else if (i == 47 && trace_round16_ticks != 0u) {
            cprisk_crypto_trace_record_span_ticks_i(
                cprisk_crypto_trace_now_i() - trace_round16_ticks
            );
        }
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    for (unsigned j = 0u; j < 24u; j++) {
        uint32_t lane = state[j & 7u] ^ W[(j * 7u) & 63u] ^ noise_sink;
        lane = cprisk_sha256_sigma0(lane) ^ cprisk_sha256_gamma1(lane ^ (j * 0x51ED270Bu));
        lane ^= cprisk_sha256_sigma1(state[(j + 3u) & 7u]) + cprisk_sha256_gamma0(W[(j + 19u) & 63u]);
        noise_sink ^= lane ^ (uint32_t)cprisk_sha256_memnoise[(lane + j + state[(j + 5u) & 7u]) & 63u];
        if ((j & 1u) != 0u) {
            noise_sink = cprisk_sha256_rotr(noise_sink, (unsigned)((j & 7u) + 1u));
        }
    }
    (void)noise_sink;
}

/* ── public API ────────────────────────────────────────────────────── */

static inline __attribute__((always_inline))
void cprisk_sha256_init(cprisk_sha256_ctx *ctx) {
    for (unsigned j = 0; j < 8u; j++)
        ctx->state[j] = cprisk_sha256_H0_lo[j] + cprisk_sha256_H0_hi[j];
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
    cprisk_crypto_trace_primitive_enter_i();
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, data, len);
    cprisk_sha256_final(&ctx, out);
}

#endif /* CPRISK_SHA256_H */
