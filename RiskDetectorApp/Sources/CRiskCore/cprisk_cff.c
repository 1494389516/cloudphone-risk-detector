#include "cprisk_cff.h"

#include "include/CRiskCore.h"

#include <pthread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <sys/sysctl.h>

static uint32_t cprisk_cff_rotate_left32(uint32_t value, uint32_t shift) {
    const uint32_t amount = shift & 31u;
    if (amount == 0u) {
        return value;
    }
    return (value << amount) | (value >> (32u - amount));
}

static uint32_t cprisk_cff_rotate_right32(uint32_t value, uint32_t shift) {
    const uint32_t amount = shift & 31u;
    if (amount == 0u) {
        return value;
    }
    return (value >> amount) | (value << (32u - amount));
}

static uint32_t cprisk_cff_avalanche32(uint32_t value) {
    uint32_t mixed = value;
    mixed ^= mixed >> 16u;
    mixed *= 0x7FEB352Du;
    mixed ^= mixed >> 15u;
    mixed *= 0x846CA68Bu;
    mixed ^= mixed >> 16u;
    return mixed;
}

static uint64_t cprisk_cff_thread_fingerprint(void) {
    pthread_t current = pthread_self();
    unsigned char bytes[sizeof(pthread_t)];
    uint64_t hash = 0xCBF29CE484222325ULL;
    size_t index = 0u;

    memcpy(bytes, &current, sizeof(pthread_t));
    for (index = 0u; index < sizeof(pthread_t); ++index) {
        hash ^= (uint64_t)bytes[index];
        hash *= 0x100000001B3ULL;
    }

    return hash;
}

static uint32_t cprisk_cff_os_mix32(void) {
    char osrelease[128];
    size_t len = sizeof(osrelease);
    if (sysctlbyname("kern.osrelease", osrelease, &len, NULL, 0) != 0 || len == 0) {
        return 0xA24BAED5u;
    }

    uint32_t hash = 0x811C9DC5u;
    for (size_t i = 0; i < len && osrelease[i] != '\0'; i++) {
        hash ^= (uint32_t)(uint8_t)osrelease[i];
        hash *= 16777619u;
    }
    return hash;
}

static uint32_t cprisk_cff_dyld_mix32(void) {
    const uint32_t image_count = _dyld_image_count();
    return (image_count << 9u) ^ (image_count >> 5u) ^ 0x6C8E9CF5u;
}

static uint32_t cprisk_cff_affine_multiplier(uint32_t key, uint32_t salt) {
    return cprisk_cff_avalanche32(key ^ cprisk_cff_rotate_left32(salt, 7u) ^ 0xD1B54A35u) | 1u;
}

static uint32_t cprisk_cff_affine_addend(uint32_t key, uint32_t salt) {
    return cprisk_cff_avalanche32((key * 0x9E3779B1u) ^ salt ^ 0x94D049BBu);
}

/*
 * MBA-equivalent XOR: (a|b) - (a&b) === a ^ b (unsigned wrap).
 * Selected via seed/salt mix to keep decode/encode symmetric.
 */
static uint32_t cprisk_cff_xor_mba_u32(uint32_t a, uint32_t b) {
    return (a | b) - (a & b);
}

/*
 * Composite MBA layers (2-5): each layer is semantically XOR with a derived key;
 * syntax rotates across several MBA-equivalent identities to resist pattern
 * matching on a single (a|b)-(a&b) form.
 */
static uint32_t cprisk_cff_xor_mba_layer_u32(uint32_t x, uint32_t k, uint32_t layer_ix) {
    const uint32_t sel =
        (layer_ix + cprisk_cff_avalanche32(k ^ 0x13579BDFu) + (k >> 17u)) & 3u;
    switch (sel) {
        case 0u:
            return cprisk_cff_xor_mba_u32(x, k);
        case 1u:
            return (x & ~k) | (~x & k);
        case 2u:
            return x + k - (2u * (x & k));
        default:
            return x ^ k;
    }
}

static uint32_t cprisk_cff_mba_chain_xor_u32(uint32_t v, uint32_t key, uint32_t salt, uint8_t layers) {
    uint8_t L = layers;
    if (L < 2u) {
        return v;
    }
    if (L > 5u) {
        L = 5u;
    }
    uint32_t cur = v;
    for (uint8_t i = 0u; i < L; i++) {
        const uint32_t ki =
            cprisk_cff_avalanche32(key ^ salt ^ ((uint32_t)i * 0x9E3779B1u) ^ 0xD1B54A35u);
        cur = cprisk_cff_xor_mba_layer_u32(cur, ki, (uint32_t)i);
    }
    return cur;
}

static uint8_t cprisk_cff_normalize_mba_layers(uint32_t seed, uint8_t requested) {
    if (requested >= 2u && requested <= 5u) {
        return requested;
    }
    if (requested == 1u) {
        return 1u;
    }
    /* 0 or unset: auto 2..5 */
    return (uint8_t)(2u + (cprisk_cff_avalanche32(seed ^ 0x51ED270Bu) % 4u));
}

static uint8_t cprisk_cff_resolve_dispatch_style_u8(uint32_t seed, uint8_t requested) {
    if (requested == (uint8_t)CPRISK_CFF_DISPATCH_DIRECT ||
        requested == (uint8_t)CPRISK_CFF_DISPATCH_FN_TABLE) {
        return requested;
    }
    if (requested == (uint8_t)CPRISK_CFF_DISPATCH_COMPUTED_GOTO) {
        /* Unstable on some toolchains: use real handler-table dispatch instead. */
        return (uint8_t)CPRISK_CFF_DISPATCH_FN_TABLE;
    }
    /* AUTO */
    return (cprisk_cff_avalanche32(seed ^ 0xA5A5A5A5u) & 1u) != 0u
        ? (uint8_t)CPRISK_CFF_DISPATCH_FN_TABLE
        : (uint8_t)CPRISK_CFF_DISPATCH_DIRECT;
}

static uint32_t cprisk_cff_mod_inverse_odd32(uint32_t odd_value) {
    uint32_t inverse = odd_value;
    inverse *= 2u - odd_value * inverse;
    inverse *= 2u - odd_value * inverse;
    inverse *= 2u - odd_value * inverse;
    inverse *= 2u - odd_value * inverse;
    inverse *= 2u - odd_value * inverse;
    return inverse;
}

/*
 * SPN byte substitution: runtime decodes a project-local 8-bit bijection.
 * The table is XOR-masked in rodata and intentionally does not preserve the
 * canonical AES SubBytes mapping.
 */
static const uint8_t cprisk_cff_spn_sbox_mask[4] = {0xA7u, 0x38u, 0xC2u, 0x91u};
static const uint8_t cprisk_cff_spn_sbox_enc[256] = {
    0x4au, 0x45u, 0x34u, 0xc5u, 0xa9u, 0xecu, 0x69u, 0xa0u, 0x26u, 0x52u, 0xbeu, 0x48u, 0xa3u, 0x76u, 0x9eu, 0xe9u,
    0x7bu, 0x2du, 0xd9u, 0x5bu, 0x9bu, 0x46u, 0xb1u, 0x7bu, 0x6au, 0xe8u, 0xeau, 0x0fu, 0x54u, 0x41u, 0xb5u, 0xe3u,
    0x25u, 0x07u, 0x00u, 0x30u, 0x3eu, 0x6eu, 0x45u, 0x19u, 0x24u, 0xddu, 0x3cu, 0xbbu, 0xb1u, 0xb4u, 0xdbu, 0x73u,
    0x40u, 0x0eu, 0xe1u, 0x70u, 0x71u, 0xcau, 0xc3u, 0x96u, 0x8cu, 0x37u, 0x9cu, 0xeeu, 0x6eu, 0xd6u, 0x89u, 0xf5u,
    0xffu, 0x78u, 0xc0u, 0xbeu, 0x87u, 0x63u, 0xd3u, 0xb6u, 0x12u, 0x0fu, 0xf9u, 0x75u, 0x4eu, 0xf4u, 0xf2u, 0x8cu,
    0xe6u, 0x5bu, 0x6fu, 0xacu, 0xc2u, 0x11u, 0x1du, 0xabu, 0x50u, 0x27u, 0x11u, 0x6cu, 0x36u, 0xbeu, 0xa2u, 0x5eu,
    0x92u, 0x42u, 0x62u, 0x06u, 0xe1u, 0x8bu, 0x60u, 0x7au, 0x48u, 0x8cu, 0x7au, 0xd9u, 0xf4u, 0xabu, 0xcfu, 0x7du,
    0x32u, 0x2cu, 0x2au, 0x0cu, 0xf5u, 0xc8u, 0x9du, 0x27u, 0x2au, 0x91u, 0xecu, 0x07u, 0xe5u, 0x7du, 0x4du, 0x60u,
    0x08u, 0x5eu, 0x46u, 0xa8u, 0xd6u, 0x43u, 0x86u, 0x36u, 0x17u, 0xc7u, 0xdeu, 0x6bu, 0x60u, 0x77u, 0x07u, 0xcbu,
    0xa1u, 0x0au, 0xceu, 0x98u, 0x19u, 0xc0u, 0x58u, 0x8bu, 0x0fu, 0x2bu, 0x95u, 0x5fu, 0x02u, 0x32u, 0x73u, 0xb0u,
    0xc9u, 0x82u, 0x03u, 0x4bu, 0xf7u, 0xfcu, 0x7du, 0x14u, 0x1au, 0x9cu, 0x70u, 0xf0u, 0x9fu, 0x15u, 0xd2u, 0x1fu,
    0xb5u, 0x48u, 0x49u, 0xf3u, 0xd1u, 0xc4u, 0xcau, 0x8fu, 0x27u, 0xb2u, 0xe0u, 0x91u, 0x37u, 0xcdu, 0x61u, 0x46u,
    0xa4u, 0x0bu, 0xb7u, 0x18u, 0x44u, 0xaau, 0xc7u, 0xfau, 0x7fu, 0x14u, 0xafu, 0x5au, 0x67u, 0x8fu, 0xe4u, 0xa5u,
    0xe4u, 0x92u, 0x97u, 0x3du, 0x1eu, 0x71u, 0xa5u, 0xb4u, 0xceu, 0x1cu, 0x59u, 0x71u, 0xbfu, 0x7fu, 0x10u, 0x4cu,
    0xc8u, 0xccu, 0x6cu, 0xdbu, 0x79u, 0xe3u, 0x56u, 0x0du, 0x1cu, 0xdeu, 0x5au, 0x9au, 0xb0u, 0x9eu, 0x8fu, 0x2du,
    0xcbu, 0x65u, 0x3bu, 0x52u, 0xebu, 0xc3u, 0x04u, 0xafu, 0x76u, 0x69u, 0x9bu, 0x44u, 0xcfu, 0x4cu, 0x0au, 0x0eu,
};

static uint8_t cprisk_cff_spn_sbox_byte(uint8_t idx) {
    return (uint8_t)(cprisk_cff_spn_sbox_enc[idx] ^ cprisk_cff_spn_sbox_mask[idx & 3u]);
}

static uint16_t cprisk_cff_shadow_noise16(uint16_t r, uint32_t rk, uint32_t salt, uint32_t round) {
    volatile uint32_t sink = ((uint32_t)r << 16u) | (uint32_t)r;
    uint32_t shadow = cprisk_cff_avalanche32(rk ^ salt ^ (round * 0x51ED270Bu) ^ 0xA5C31F27u);
    for (uint32_t step = 0u; step < 4u; ++step) {
        const uint32_t lane = cprisk_cff_rotate_left32(
            shadow ^ sink ^ (step * 0x9E3779B1u),
            (uint32_t)((round + (step * 5u) + 3u) & 31u)
        );
        shadow ^= cprisk_cff_avalanche32(
            lane +
            (sink ^ cprisk_cff_rotate_right32(rk, (uint32_t)((step + 3u) & 31u))) +
            0x7F4A7C15u
        );
        sink ^= lane ^ cprisk_cff_rotate_right32(shadow, (uint32_t)((step + 7u) & 31u));
    }
    sink ^= cprisk_cff_rotate_left32(sink ^ shadow, (uint32_t)(((round * 3u) + 11u) & 31u));
    return (uint16_t)((shadow ^ sink ^ (shadow >> 16u)) & 0xFFFFu);
}

#define CPRISK_CFF_FEISTEL_ROUNDS 8u

static uint16_t cprisk_cff_feistel_F(uint16_t r, uint32_t k, uint32_t salt, uint32_t round) {
    uint32_t rk = cprisk_cff_avalanche32(k ^ salt ^ (round * 0x9E3779B9u) ^ 0xDEADBEEFu);
    uint8_t b0 = (uint8_t)(r & 0xFFu);
    uint8_t b1 = (uint8_t)((r >> 8) & 0xFFu);
    uint32_t piece = (uint32_t)cprisk_cff_spn_sbox_byte(b0 ^ (uint8_t)(rk & 0xFFu)) ^
        ((uint32_t)cprisk_cff_spn_sbox_byte(b1 ^ (uint8_t)((rk >> 8) & 0xFFu)) << 8u);
    {
        const uint16_t shadow0 = cprisk_cff_shadow_noise16(r, rk, salt, round);
        const uint16_t shadow1 = cprisk_cff_shadow_noise16(
            (uint16_t)(r ^ shadow0),
            rk ^ piece ^ 0x6C8E9CF5u,
            salt ^ 0x517CC1B7u,
            round + 1u
        );
        volatile uint32_t shadow_sink = (uint32_t)shadow0 ^ ((uint32_t)shadow1 << 16u);
        shadow_sink ^= cprisk_cff_rotate_left32(shadow_sink ^ rk, (uint32_t)((round & 7u) + 3u));
        (void)shadow_sink;
    }
    piece ^= rk ^ (rk >> 16);
    piece = cprisk_cff_avalanche32(piece);
    return (uint16_t)((piece ^ (piece >> 16)) & 0xFFFFu);
}

static uint32_t cprisk_cff_feistel32_encode_core(uint32_t state, uint32_t key, uint32_t salt) {
    uint32_t v = state ^ cprisk_cff_avalanche32(key ^ salt ^ 0xF1055A1u);
    uint16_t l = (uint16_t)(v >> 16);
    uint16_t r = (uint16_t)(v & 0xFFFFu);
    for (uint32_t rnd = 0u; rnd < CPRISK_CFF_FEISTEL_ROUNDS; rnd++) {
        const uint16_t nl = r;
        const uint16_t nr = (uint16_t)(l ^ cprisk_cff_feistel_F(r, key, salt, rnd));
        l = nl;
        r = nr;
    }
    const uint32_t mid = ((uint32_t)l << 16) | (uint32_t)r;
    return mid ^ cprisk_cff_avalanche32(key ^ salt ^ 0xACC0DECu);
}

static uint32_t cprisk_cff_feistel32_decode_core(uint32_t encoded_state, uint32_t key, uint32_t salt) {
    uint32_t mid = encoded_state ^ cprisk_cff_avalanche32(key ^ salt ^ 0xACC0DECu);
    uint16_t l = (uint16_t)(mid >> 16);
    uint16_t r = (uint16_t)(mid & 0xFFFFu);
    uint32_t rnd = CPRISK_CFF_FEISTEL_ROUNDS;
    while (rnd > 0u) {
        rnd--;
        const uint16_t pr = l;
        const uint16_t pl = (uint16_t)(r ^ cprisk_cff_feistel_F(l, key, salt, rnd));
        l = pl;
        r = pr;
    }
    const uint32_t v = ((uint32_t)l << 16) | (uint32_t)r;
    return v ^ cprisk_cff_avalanche32(key ^ salt ^ 0xF1055A1u);
}

static cprisk_cff_codec_style_t cprisk_cff_resolve_style(uint32_t seed, uint32_t entry_state, uint8_t requested_style) {
    const cprisk_cff_codec_style_t requested = (cprisk_cff_codec_style_t)requested_style;
    if (requested == CPRISK_CFF_CODEC_STYLE_XOR_ROTATE ||
        requested == CPRISK_CFF_CODEC_STYLE_ADD_ROTATE_XOR ||
        requested == CPRISK_CFF_CODEC_STYLE_AFFINE ||
        requested == CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN) {
        return requested;
    }

    /* AUTO: strongly bias toward Feistel+S-box (non-linear) vs. XOR-MBA-heavy styles. */
    const uint32_t h = cprisk_cff_avalanche32(seed ^ cprisk_cff_rotate_left32(entry_state, 11u) ^ 0x13579BDFu);
    if ((h & 3u) != 0u) {
        return CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN;
    }
    switch (h % 3u) {
        case 0u:
            return CPRISK_CFF_CODEC_STYLE_XOR_ROTATE;
        case 1u:
            return CPRISK_CFF_CODEC_STYLE_ADD_ROTATE_XOR;
        default:
            return CPRISK_CFF_CODEC_STYLE_AFFINE;
    }
}

static uint32_t cprisk_cff_opaque_selector_i(const cprisk_cff_context_t *context, uint32_t decoded_state) {
    uint32_t token = cprisk_cff_avalanche32(
        context->encoded_state ^
        decoded_state ^
        (context->runtime_salt * 0x9E3779B1u) ^
        ((uint32_t)context->codec_style << 24u) ^
        0x6C8E9CF5u
    );
    token ^= cprisk_cff_rotate_left32(token, ((context->seed >> 27u) & 31u) | 1u);
    return token;
}

static uint32_t cprisk_cff_mix_seed(uint32_t seed, uint32_t entry_state) {
    return cprisk_cff_avalanche32(seed ^ (entry_state * 0x9E3779B1u) ^ 0xA24BAED5u);
}

static uint32_t cprisk_cff_default_seed(void) {
    struct timespec now;
    uint64_t monotonic_ns = 0u;
    const uint64_t pid = (uint64_t)getpid();
    const uint64_t tid_hash = cprisk_cff_thread_fingerprint();
    const uintptr_t fn_addr_mix = (uintptr_t)&cprisk_cff_default_seed ^ (uintptr_t)&cprisk_cff_encode_state;

    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        monotonic_ns = ((uint64_t)now.tv_sec * 1000000000ULL) + (uint64_t)now.tv_nsec;
    }

    uint32_t seed = 0u;
    seed ^= (uint32_t)pid;
    seed ^= (uint32_t)(pid >> 32u);
    seed ^= (uint32_t)tid_hash;
    seed ^= (uint32_t)(tid_hash >> 32u);
    seed ^= (uint32_t)monotonic_ns;
    seed ^= (uint32_t)(monotonic_ns >> 29u);
    seed ^= (uint32_t)fn_addr_mix;
    seed ^= (uint32_t)(fn_addr_mix >> 32u);
    seed = cprisk_cff_avalanche32(seed ^ 0x91E10DA5u);
    return seed == 0u ? 1u : seed;
}

uint32_t cprisk_cff_encode_state(uint32_t state, uint32_t key, uint32_t salt) {
    return cprisk_cff_encode_state_with_style(
        state,
        key,
        salt,
        CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN
    );
}

uint32_t cprisk_cff_decode_state(uint32_t encoded_state, uint32_t key, uint32_t salt) {
    return cprisk_cff_decode_state_with_style(
        encoded_state,
        key,
        salt,
        CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN
    );
}

static uint32_t cprisk_cff_encode_state_with_style_impl(
    uint32_t state,
    uint32_t key,
    uint32_t salt,
    cprisk_cff_codec_style_t style,
    uint8_t mba_layers
) {
    switch (style) {
        case CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN:
        case CPRISK_CFF_CODEC_STYLE_AUTO:
            return cprisk_cff_feistel32_encode_core(state, key, salt);
        case CPRISK_CFF_CODEC_STYLE_ADD_ROTATE_XOR: {
            const uint32_t addend = cprisk_cff_avalanche32(key + salt + 0x7F4A7C15u);
            const uint32_t shift = (((key >> 3u) ^ salt) & 31u) | 1u;
            const uint32_t mixed = cprisk_cff_rotate_left32(state + addend, shift);
            return mixed ^ cprisk_cff_avalanche32(key ^ 0xA24BAED5u) ^ (salt * 0x165667B1u);
        }
        case CPRISK_CFF_CODEC_STYLE_AFFINE: {
            const uint32_t mask = cprisk_cff_avalanche32(key + salt + 0x51ED270Bu);
            const uint32_t multiplier = cprisk_cff_affine_multiplier(key, salt);
            const uint32_t addend = cprisk_cff_affine_addend(key, salt);
            const uint32_t masked = state ^ mask;
            return (masked * multiplier + addend) ^ cprisk_cff_rotate_left32(key, (salt & 31u) | 1u);
        }
        case CPRISK_CFF_CODEC_STYLE_XOR_ROTATE:
        default: {
            const uint32_t mix = cprisk_cff_avalanche32(key ^ salt ^ 0x9E3779B9u);
            const uint32_t shift = (mix & 31u) | 1u;
            const uint32_t saltprod = salt * 0x45D9F3Bu;
            const uint32_t use_mba =
                (cprisk_cff_avalanche32(key ^ salt ^ 0xEFCAB9A5u) & 1u) != 0u;
            uint32_t core =
                use_mba != 0u ? cprisk_cff_xor_mba_u32(state, mix) : (state ^ mix);
            if (mba_layers >= 2u) {
                core = cprisk_cff_mba_chain_xor_u32(core, key, salt, mba_layers);
            }
            const uint32_t masked = core ^ saltprod;
            return cprisk_cff_rotate_left32(masked, shift) + (key * 0x27D4EB2Du);
        }
    }
}

uint32_t cprisk_cff_encode_state_with_style(
    uint32_t state,
    uint32_t key,
    uint32_t salt,
    cprisk_cff_codec_style_t style
) {
    return cprisk_cff_encode_state_with_style_impl(state, key, salt, style, 1u);
}

static uint32_t cprisk_cff_decode_state_with_style_impl(
    uint32_t encoded_state,
    uint32_t key,
    uint32_t salt,
    cprisk_cff_codec_style_t style,
    uint8_t mba_layers
) {
    switch (style) {
        case CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN:
        case CPRISK_CFF_CODEC_STYLE_AUTO:
            return cprisk_cff_feistel32_decode_core(encoded_state, key, salt);
        case CPRISK_CFF_CODEC_STYLE_ADD_ROTATE_XOR: {
            const uint32_t addend = cprisk_cff_avalanche32(key + salt + 0x7F4A7C15u);
            const uint32_t shift = (((key >> 3u) ^ salt) & 31u) | 1u;
            const uint32_t unmasked =
                encoded_state ^ cprisk_cff_avalanche32(key ^ 0xA24BAED5u) ^ (salt * 0x165667B1u);
            return cprisk_cff_rotate_right32(unmasked, shift) - addend;
        }
        case CPRISK_CFF_CODEC_STYLE_AFFINE: {
            const uint32_t mask = cprisk_cff_avalanche32(key + salt + 0x51ED270Bu);
            const uint32_t multiplier = cprisk_cff_affine_multiplier(key, salt);
            const uint32_t inverse = cprisk_cff_mod_inverse_odd32(multiplier);
            const uint32_t addend = cprisk_cff_affine_addend(key, salt);
            const uint32_t unxored = encoded_state ^ cprisk_cff_rotate_left32(key, (salt & 31u) | 1u);
            const uint32_t unscaled = (unxored - addend) * inverse;
            return unscaled ^ mask;
        }
        case CPRISK_CFF_CODEC_STYLE_XOR_ROTATE:
        default: {
            const uint32_t mix = cprisk_cff_avalanche32(key ^ salt ^ 0x9E3779B9u);
            const uint32_t shift = (mix & 31u) | 1u;
            const uint32_t saltprod = salt * 0x45D9F3Bu;
            const uint32_t use_mba =
                (cprisk_cff_avalanche32(key ^ salt ^ 0xEFCAB9A5u) & 1u) != 0u;
            const uint32_t unshifted =
                cprisk_cff_rotate_right32(encoded_state - (key * 0x27D4EB2Du), shift);
            uint32_t core = unshifted ^ saltprod;
            if (mba_layers >= 2u) {
                core = cprisk_cff_mba_chain_xor_u32(core, key, salt, mba_layers);
            }
            return use_mba != 0u ? cprisk_cff_xor_mba_u32(core, mix) : (core ^ mix);
        }
    }
}

uint32_t cprisk_cff_decode_state_with_style(
    uint32_t encoded_state,
    uint32_t key,
    uint32_t salt,
    cprisk_cff_codec_style_t style
) {
    return cprisk_cff_decode_state_with_style_impl(encoded_state, key, salt, style, 1u);
}

uint32_t cprisk_cff_runtime_salt(uint32_t seed, uint32_t runtime_hint) {
    struct timespec now;
    uint64_t monotonic_ns = 0u;
    const uint64_t pid = (uint64_t)getpid();
    const uint64_t tid_hash = cprisk_cff_thread_fingerprint();

    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        monotonic_ns = ((uint64_t)now.tv_sec * 1000000000ULL) + (uint64_t)now.tv_nsec;
    }

    return cprisk_cff_avalanche32(
        seed ^
        runtime_hint ^
        (uint32_t)pid ^
        (uint32_t)(monotonic_ns >> 11u) ^
        (uint32_t)(tid_hash >> 17u) ^
        cprisk_cff_os_mix32() ^
        cprisk_cff_dyld_mix32() ^
        0x7F4A7C15u
    );
}

void cprisk_cff_init(cprisk_cff_context_t *context, const cprisk_cff_config_t *config) {
    cprisk_cff_config_t local_config;

    if (context == NULL) {
        return;
    }

    if (config == NULL) {
        memset(&local_config, 0, sizeof(local_config));
        local_config.seed = cprisk_cff_default_seed();
        local_config.entry_state = 0u;
        local_config.iteration_budget = CPRISK_CFF_ITERATION_BUDGET;
        local_config.release_build = (uint8_t)CPRISK_CFF_RELEASE_BUILD;
        local_config.enable_fake_states = (uint8_t)CPRISK_CFF_ENABLE_FAKE_STATE;
        local_config.codec_style = (uint8_t)CPRISK_CFF_CODEC_STYLE_AUTO;
        local_config.default_action = CPRISK_CFF_RELEASE_BUILD ? CPRISK_CFF_DEFAULT_POISON : CPRISK_CFF_DEFAULT_FAIL_CLOSED;
        config = &local_config;
    }

    memset(context, 0, sizeof(*context));
    context->seed = cprisk_cff_mix_seed(config->seed, config->entry_state);
    context->runtime_salt = config->runtime_salt != 0u
        ? config->runtime_salt
        : cprisk_cff_runtime_salt(config->seed, config->entry_state ^ 0x13579BDFu);
    context->iteration_budget = config->iteration_budget != 0u
        ? config->iteration_budget
        : CPRISK_CFF_ITERATION_BUDGET;
    context->release_build = config->release_build;
    context->enable_fake_states = config->enable_fake_states;
    context->fake_state_budget = (uint8_t)((config->enable_fake_states != 0u && config->release_build != 0u) ? 2u : 0u);
    context->codec_style = (uint8_t)cprisk_cff_resolve_style(
        context->seed,
        config->entry_state,
        config->codec_style
    );
    context->mba_layers = cprisk_cff_normalize_mba_layers(context->seed, config->mba_layers);
    context->dispatch_style = cprisk_cff_resolve_dispatch_style_u8(context->seed, config->dispatch_style);
    context->symex_guard_budget = config->symex_guard_budget;
    context->default_action = config->default_action;
    context->encoded_state = cprisk_cff_encode_state_with_style_impl(
        config->entry_state,
        context->seed,
        context->runtime_salt,
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
    context->last_decoded_state = config->entry_state;
}

void cprisk_cff_init_default(cprisk_cff_context_t *context, uint32_t seed, uint32_t entry_state) {
    cprisk_cff_config_t config;

    memset(&config, 0, sizeof(config));
    config.seed = seed;
    config.entry_state = entry_state;
    config.iteration_budget = CPRISK_CFF_ITERATION_BUDGET;
    config.release_build = (uint8_t)CPRISK_CFF_RELEASE_BUILD;
    config.enable_fake_states = (uint8_t)CPRISK_CFF_ENABLE_FAKE_STATE;
    config.codec_style = (uint8_t)CPRISK_CFF_CODEC_STYLE_AUTO;
    config.default_action = CPRISK_CFF_RELEASE_BUILD ? CPRISK_CFF_DEFAULT_POISON : CPRISK_CFF_DEFAULT_FAIL_CLOSED;
    cprisk_cff_init(context, &config);
}

uint32_t cprisk_cff_current_state(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return 0u;
    }

    context->last_decoded_state = cprisk_cff_decode_state_with_style_impl(
        context->encoded_state,
        context->seed,
        context->runtime_salt,
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
    return context->last_decoded_state;
}

uint32_t cprisk_cff_current_state_table(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return 0u;
    }

    /*
     * Alternate decode path: single resolved codec_style (AUTO is always
     * normalized at init). Avoids masking style to 2 bits, which mis-routed
     * newer styles (e.g. Feistel) to XOR.
     */
    context->last_decoded_state = cprisk_cff_decode_state_with_style_impl(
        context->encoded_state,
        context->seed,
        context->runtime_salt,
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
    return context->last_decoded_state;
}

static uint32_t cprisk_cff_dispatch_decode_direct_ctx(cprisk_cff_context_t *context) {
    context->last_decoded_state = cprisk_cff_decode_state_with_style_impl(
        context->encoded_state,
        context->seed,
        context->runtime_salt,
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
    return context->last_decoded_state;
}

static uint32_t cprisk_cff_dispatch_decode_table_ctx(cprisk_cff_context_t *context) {
    return cprisk_cff_current_state_table(context);
}

uint32_t cprisk_cff_current_state_fast(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return 0u;
    }
    if (context->mba_layers <= 1u) {
        if (context->dispatch_style == (uint8_t)CPRISK_CFF_DISPATCH_DIRECT) {
            return cprisk_cff_dispatch_decode_direct_ctx(context);
        }
        if (context->dispatch_style == (uint8_t)CPRISK_CFF_DISPATCH_FN_TABLE) {
            return cprisk_cff_current_state_table(context);
        }
    }
    return cprisk_cff_current_state_dispatch(context);
}

uint32_t cprisk_cff_current_state_dispatch(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return 0u;
    }
    typedef uint32_t (*cprisk_cff_dual_dispatch_fn)(cprisk_cff_context_t *);
    static const cprisk_cff_dual_dispatch_fn k_dual[2] = {
        cprisk_cff_dispatch_decode_direct_ctx,
        cprisk_cff_dispatch_decode_table_ctx,
    };
    const uint32_t mix =
        cprisk_cff_avalanche32(context->seed ^ context->runtime_salt ^ 0x8F82C945u);
    const uint32_t pick = (mix ^ (uint32_t)context->codec_style ^ (uint32_t)context->mba_layers) & 1u;
    return k_dual[pick](context);
}

void cprisk_cff_arm_symbolic_explosion(cprisk_cff_context_t *context, uint8_t budget) {
    if (context == NULL) {
        return;
    }
    if (budget != 0u) {
        context->symex_guard_budget = budget;
    }
}

void cprisk_cff_trigger_symbolic_explosion(cprisk_cff_context_t *context, uint32_t risk_mask) {
    if (context == NULL) {
        return;
    }
    uint32_t limit = (uint32_t)context->symex_guard_budget;
    if (limit == 0u) {
        limit = 3u;
    }
    limit *= 1u + (risk_mask & 0xFFu);
    if (limit > 96u) {
        limit = 96u;
    }
    struct timespec ts;
    uint32_t acc = risk_mask ^ context->encoded_state ^ context->seed;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        acc ^= (uint32_t)ts.tv_nsec;
        acc = cprisk_cff_rotate_left32(acc, (uint32_t)(ts.tv_sec & 31u));
    }
    acc ^= (uint32_t)getpid() ^ cprisk_cff_thread_fingerprint();
    for (uint32_t i = 0u; i < limit; i++) {
        acc = cprisk_cff_avalanche32(acc ^ i ^ (uint32_t)(i * 0x9E3779B1u));
        if ((acc & 15u) == (risk_mask & 15u)) {
            volatile uint32_t sink = acc;
            sink ^= cprisk_cff_rotate_left32(sink, (uint32_t)(i & 31u));
            (void)sink;
        }
    }
    (void)cprisk_cff_os_mix32();
}

/*
 * Opaque predicates for transitions: MBA identities + runtime-tied mixing
 * (monotonic clock, pid) so static folding cannot eliminate the guard without
 * executing environment-dependent paths.
 */
static int cprisk_cff_opaque_transition_ok(uint32_t from_decoded, uint32_t to_plain, uint32_t seed, uint32_t salt) {
    struct timespec ts;
    uint32_t rt = 0u;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        rt = (uint32_t)ts.tv_nsec ^ ((uint32_t)ts.tv_sec * 0x9E3779B1u);
    }
    const uint32_t pid_mix = (uint32_t)getpid();
    const uint32_t a = to_plain ^ salt ^ (rt & 0xFFFFu);
    const uint32_t b = seed ^ from_decoded ^ cprisk_cff_rotate_left32(pid_mix, 3u);
    const uint32_t x = a ^ b;
    if (cprisk_cff_xor_mba_u32(a, b) != x) {
        return 0;
    }
    if ((((a & ~b) | (~a & b)) != x)) {
        return 0;
    }
    if (cprisk_cff_avalanche32(x ^ rt) !=
        cprisk_cff_avalanche32(cprisk_cff_xor_mba_u32(a, b) ^ rt)) {
        return 0;
    }
    {
        const uint32_t chain = cprisk_cff_mba_chain_xor_u32(a, seed, salt, 3u);
        uint32_t manual = a;
        for (uint32_t layer = 0u; layer < 3u; layer++) {
            const uint32_t ki =
                cprisk_cff_avalanche32(seed ^ salt ^ ((uint32_t)layer * 0x9E3779B1u) ^ 0xD1B54A35u);
            manual = cprisk_cff_xor_mba_layer_u32(manual, ki, layer);
        }
        if (chain != manual) {
            return 0;
        }
    }
    const uint32_t h = cprisk_cff_avalanche32(
        seed ^ cprisk_cff_rotate_left32(to_plain, 5u) ^ 0xABADD00Du ^ (rt >> 3u)
    );
    const uint32_t p = 65521u;
    const uint64_t r =
        ((uint64_t)h + (uint64_t)pid_mix) * (uint64_t)(from_decoded ^ 0x13579BDFu ^ rt) % (uint64_t)p;
    const uint64_t sq = (r * r) % (uint64_t)p;
    const uint64_t sq_chk = ((uint64_t)r * (uint64_t)r) % (uint64_t)p;
    return sq == sq_chk ? 1 : 0;
}

void cprisk_cff_set_state(cprisk_cff_context_t *context, uint32_t next_state) {
    if (context == NULL) {
        return;
    }

    if (cprisk_cff_opaque_transition_ok(context->last_decoded_state, next_state, context->seed, context->runtime_salt) == 0) {
        cprisk_cff_poison_default(context);
        return;
    }

    context->last_decoded_state = next_state;
    context->encoded_state = cprisk_cff_encode_state_with_style_impl(
        next_state,
        context->seed,
        context->runtime_salt,
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
}

void cprisk_cff_set_encoded_state(cprisk_cff_context_t *context, uint32_t encoded_state) {
    if (context == NULL) {
        return;
    }

    context->encoded_state = encoded_state;
    context->last_decoded_state = cprisk_cff_decode_state_with_style_impl(
        encoded_state,
        context->seed,
        context->runtime_salt,
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
}

int cprisk_cff_should_visit_fake_state(const cprisk_cff_context_t *context, uint32_t decoded_state) {
    uint32_t mixed = 0u;
    uint32_t modulo = 0u;

    if (context == NULL || context->enable_fake_states == 0u || context->release_build == 0u || context->fake_state_budget == 0u) {
        return 0;
    }

    mixed = cprisk_cff_opaque_selector_i(context, decoded_state);
    {
        uint32_t h = 2166136261u;
        h ^= mixed;
        h *= 16777619u;
        h ^= decoded_state ^ context->seed;
        h *= 709607u;
        mixed ^= cprisk_cff_rotate_left32(h, (uint32_t)(context->codec_style + 3u));
    }
    modulo = 5u + ((uint32_t)context->codec_style % 3u);
    if (modulo == 0u)
        modulo = 5u;

    return (mixed % modulo) == 0u;
}

void cprisk_cff_poison_default(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return;
    }

    switch (context->default_action) {
        case CPRISK_CFF_DEFAULT_TRAP:
            __builtin_trap();
            break;
        case CPRISK_CFF_DEFAULT_POISON:
            cprisk_force_integrity_poison();
            context->iteration_budget = 0u;
            context->encoded_state = cprisk_cff_encode_state_with_style_impl(
                0xFFFF0001u,
                context->seed,
                context->runtime_salt,
                (cprisk_cff_codec_style_t)context->codec_style,
                context->mba_layers
            );
            break;
        case CPRISK_CFF_DEFAULT_FAIL_CLOSED:
        default:
            context->iteration_budget = 0u;
            context->encoded_state = cprisk_cff_encode_state_with_style_impl(
                0xFFFF0000u,
                context->seed,
                context->runtime_salt,
                (cprisk_cff_codec_style_t)context->codec_style,
                context->mba_layers
            );
            break;
    }
}

void cprisk_cff_finalize(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return;
    }

    memset(context, 0, sizeof(*context));
}
