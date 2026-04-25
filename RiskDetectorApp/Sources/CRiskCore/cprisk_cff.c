#include "include/CRiskCore.h"
#include "include/cprisk_macho.h"

#include <stdatomic.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <mach-o/dyld.h>

/*
 * OS entropy hook used by `cprisk_cff_default_seed`. `getentropy(2)` is
 * available on Apple (since iOS 10 / macOS 10.12) and on glibc 2.25+ /
 * musl 1.1.20+, which covers every platform we build for. When unavailable
 * the call returns -1 and `default_seed` falls back to its prior mix.
 */
#if defined(__APPLE__) || defined(__linux__)
#include <sys/random.h>
#define CPRISK_CFF_HAVE_GETENTROPY 1
#endif

/*
 * `cprisk_cff_thread_fingerprint` memcpy's a `pthread_t` into a 128-byte
 * scratch buffer. On Apple targets `pthread_t` is an opaque pointer (8 bytes
 * on arm64/x86_64) — well below the buffer size — but compile-time-assert it
 * to catch future toolchain changes loudly instead of corrupting the stack.
 */
_Static_assert(sizeof(pthread_t) <= 128, "pthread_t exceeds FNV scratch buffer");

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

static uint32_t cprisk_cff_derive_const32(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base) {
    const uint32_t lo = (uint32_t)(domain & 0xFFFFFFFFu);
    const uint32_t hi = (uint32_t)(domain >> 32u);
    const uint32_t spin = ((seed ^ hi ^ (salt >> 1u)) & 31u) | 1u;
    const uint32_t lane = cprisk_cff_rotate_left32(seed ^ base ^ lo, spin);
    const uint32_t mixed0 = cprisk_cff_avalanche32(seed ^ salt ^ lo ^ base);
    const uint32_t mixed1 = cprisk_cff_avalanche32(lane ^ salt ^ hi ^ (base * (seed | 1u)));
    return cprisk_cff_avalanche32(mixed0 ^ mixed1 ^ lo ^ hi) ^ base;
}

static uint32_t cprisk_cff_derive_const32_odd(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base) {
    return cprisk_cff_derive_const32(domain, seed, salt, base) | 1u;
}

/*
 * Hotspot anchors: single-site immediates + domain-tagged derivation to avoid repeating
 * the same u32 literal across chain/TLS/runtime_salt/init paths (static fingerprint noise).
 */
static uint32_t cprisk_cff_build_seed32_i(void) {
    uint64_t seed64 = cprisk_cff_runtime_spn_sbox_seed();
    if (seed64 == 0u) {
        seed64 = CPRISK_CFF_SPN_CANONICAL_SEED_U64;
    }
    return cprisk_cff_avalanche32(
        (uint32_t)seed64 ^
        cprisk_cff_rotate_left32((uint32_t)(seed64 >> 32u), 11u) ^
        0x43464642u
    );
}

/*
 * Derived FNV-1a basis / prime accessors: canonical FNV basis values are
 * replaced by build-seed-derived variants to eliminate static-scannable
 * fingerprints.  The hash quality comes from the prime multiplication, not
 * the specific basis, so an arbitrary non-zero starting point is fine for
 * these internal mixing functions.  Primes are routed through volatile to
 * keep the literal out of optimised call-sites.
 */
static uint32_t cprisk_cff_fnv32a_basis_i(void) {
    const uint32_t bs = cprisk_cff_build_seed32_i();
    return cprisk_cff_derive_const32(
        0x4346465F464E5631ull, bs, cprisk_cff_rotate_left32(bs, 5u), bs
    ) | 1u;
}

static uint64_t cprisk_cff_fnv64a_basis_i(void) {
    const uint32_t bs = cprisk_cff_build_seed32_i();
    const uint32_t lo = cprisk_cff_derive_const32(
        0x4346465F464E5634ull, bs, cprisk_cff_rotate_left32(bs, 5u), bs
    );
    const uint32_t hi = cprisk_cff_derive_const32(
        0x4346465F464E5635ull, bs, lo, bs ^ lo
    );
    return ((uint64_t)hi << 32) | (uint64_t)(lo | 1u);
}

static uint32_t cprisk_cff_fnv32a_prime_i(void) {
    volatile uint32_t a = (1u << 24) + (1u << 8);
    volatile uint32_t b = (9u << 4) + 3u;
    return a + b;
}

static uint64_t cprisk_cff_fnv64a_prime_i(void) {
    volatile uint64_t hi = (1ULL << 40);
    volatile uint64_t lo = 435ULL;
    return hi + lo;
}

static uint32_t cprisk_cff_fnv_alt_prime_i(void) {
    volatile uint32_t a = 709600u;
    volatile uint32_t b = 7u;
    return a + b;
}

static uint32_t cprisk_cff_chain_fallback_sentinel_u32(void) {
    const uint32_t base = cprisk_cff_derive_const32(
        0x4346465F43484E4Dull,
        0x4E5F434Eull,
        0x4B5F534Eu,
        0x9E3779B9u
    );
    const uint32_t v = cprisk_cff_derive_const32(0x4346465F43484E4Bull, 0u, 0u, base);
    return v == 0u ? 1u : v;
}

static uint32_t cprisk_cff_rt_salt_mix_base_u32(uint32_t seed, uint32_t runtime_hint) {
    return cprisk_cff_derive_const32(
        0x4346465F52545334ull,
        seed,
        runtime_hint,
        cprisk_cff_derive_const32(0x4346465F52545335ull, seed ^ runtime_hint, runtime_hint, 0x13579BDFu)
    );
}

static uint32_t cprisk_cff_tls_mix_derive_base_u32(void) {
    const uint32_t build_seed32 = cprisk_cff_build_seed32_i();
    const uint32_t base0 = cprisk_cff_derive_const32(
        0x4346465F544C5331ull,
        build_seed32,
        cprisk_cff_rotate_left32(build_seed32, 9u),
        0x9E3779B9u
    );
    return cprisk_cff_derive_const32(
        0x4346465F544C5332ull,
        build_seed32 ^ base0,
        cprisk_cff_rotate_left32(base0, 13u),
        0xA24BAED5u
    );
}

static uint64_t cprisk_cff_thread_fingerprint(void) {
    pthread_t current = pthread_self();
    unsigned char bytes[sizeof(pthread_t)];
    uint64_t hash = cprisk_cff_fnv64a_basis_i();
    const uint64_t prime = cprisk_cff_fnv64a_prime_i();
    size_t index = 0u;

    memcpy(bytes, &current, sizeof(pthread_t));
    for (index = 0u; index < sizeof(pthread_t); ++index) {
        hash ^= (uint64_t)bytes[index];
        hash *= prime;
    }

    return hash;
}

static uint32_t cprisk_cff_os_mix32(void) {
    char osrelease[128];
    size_t len = sizeof(osrelease);
    int err = 0;
    if (cprisk_sysctlbyname_direct("kern.osrelease", osrelease, &len, NULL, 0, &err) != 0 || len == 0) {
        return cprisk_cff_derive_const32(
            0x4346465F4F534D58ull,
            (uint32_t)getpid(),
            (uint32_t)len,
            0xA24BAED5u
        );
    }

    uint32_t hash = cprisk_cff_fnv32a_basis_i();
    const uint32_t prime = cprisk_cff_fnv32a_prime_i();
    for (size_t i = 0; i < len && osrelease[i] != '\0'; i++) {
        hash ^= (uint32_t)(uint8_t)osrelease[i];
        hash *= prime;
    }
    return hash;
}

static uint32_t cprisk_cff_dyld_mix32(void) {
    const uint32_t bs = cprisk_cff_build_seed32_i();
    const uint32_t dyld_salt_k = cprisk_cff_derive_const32(
        0x4346465F44594C31ull, bs, cprisk_cff_rotate_left32(bs, 7u), bs
    );
    const uint32_t dyld_base_k = cprisk_cff_derive_const32(
        0x4346465F44594C32ull, bs, cprisk_cff_rotate_left32(bs, 13u), bs
    );
    const uint32_t image_count = _dyld_image_count();
    return
        (image_count << 9u) ^
        (image_count >> 5u) ^
        cprisk_cff_derive_const32(0x4346465F44594C44ull, image_count, image_count ^ dyld_salt_k, dyld_base_k);
}

/*
 * Affine codec helpers. Multiplication and addition operate mod 2^32 with
 * unsigned wrap-around (well-defined per C11 6.2.5/9). The codec relies on
 * this exact wrap behavior — the inverse path uses `mod_inverse_odd32` to
 * undo `masked * multiplier` and a plain `unxored - addend` subtraction to
 * undo `+ addend`. Both round-trip exactly under uint32_t arithmetic. The
 * `| 1u` below ensures the multiplier is odd so its mod-2^32 inverse exists.
 */
static uint32_t cprisk_cff_affine_multiplier(uint32_t key, uint32_t salt) {
    const uint32_t mix_const = cprisk_cff_derive_const32(
        0x4346465F53544632ull,
        key,
        salt,
        0xD1B54A35u
    );
    return cprisk_cff_avalanche32(key ^ cprisk_cff_rotate_left32(salt, 7u) ^ mix_const) | 1u;
}

static uint32_t cprisk_cff_affine_addend(uint32_t key, uint32_t salt) {
    const uint32_t mul = cprisk_cff_derive_const32_odd(
        0x4346465F53544633ull,
        key,
        salt,
        0x9E3779B1u
    );
    const uint32_t add_const = cprisk_cff_derive_const32(
        0x4346465F53544634ull,
        key,
        salt,
        0x94D049BBu
    );
    return cprisk_cff_avalanche32((key * mul) ^ salt ^ add_const);
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
    const uint32_t selector_mix = cprisk_cff_derive_const32(
        0x4346465F4D424131ull,
        k,
        layer_ix,
        0x13579BDFu
    );
    const uint32_t sel =
        (layer_ix + cprisk_cff_avalanche32(k ^ selector_mix) + (k >> 17u)) & 3u;
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

/*
 * MBA chain. `layers == 0 || layers == 1` is the documented "bypass" path
 * and returns `v` unchanged — this is how light-tier and never-tier
 * functions opt out of MBA entirely. Audit pass flagged the silent
 * no-op as a strength regression for light tier; the behavior is
 * intentional (light tier accepts weaker obfuscation in exchange for
 * lower overhead), but the contract is documented here so future
 * readers do not "fix" it by forcing layers >= 2.
 */
static uint32_t cprisk_cff_mba_chain_xor_u32(uint32_t v, uint32_t key, uint32_t salt, uint8_t layers) {
    uint8_t L = layers;
    if (L < 2u) {
        return v;
    }
    if (L > 8u) {
        L = 8u;
    }
    uint32_t cur = v;
    for (uint8_t i = 0u; i < L; i++) {
        const uint32_t step_mul = cprisk_cff_derive_const32_odd(
            0x4346465F4D424132ull,
            key,
            salt,
            0x9E3779B1u
        );
        const uint32_t step_xor = cprisk_cff_derive_const32(
            0x4346465F4D424133ull,
            key ^ (uint32_t)i,
            salt,
            0xD1B54A35u
        );
        const uint32_t ki =
            cprisk_cff_avalanche32(key ^ salt ^ ((uint32_t)i * step_mul) ^ step_xor);
        cur = cprisk_cff_xor_mba_layer_u32(cur, ki, (uint32_t)i);
    }
    return cur;
}

static uint8_t cprisk_cff_normalize_mba_layers(uint32_t seed, uint8_t requested) {
    if (requested >= 2u && requested <= 5u) {
        return requested;
    }
    if (requested >= CPRISK_CFF_MBA_LAYERS_HEAVY_MIN && requested <= CPRISK_CFF_MBA_LAYERS_HEAVY_MAX) {
        return requested;
    }
    if (requested == 1u) {
        return 1u;
    }
    /*
     * 0 (unset) or out-of-range (>= 9): auto-pick uniformly from {2,3,4,5}.
     * Use `& 3u` to extract two bits (no modulo bias) instead of `% 4u`.
     */
    return (uint8_t)(2u + (cprisk_cff_avalanche32(
        seed ^ cprisk_cff_derive_const32(0x4346465F4D424134ull, seed, requested, 0x51ED270Bu)
    ) & 3u));
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
    return (cprisk_cff_avalanche32(
        seed ^ cprisk_cff_derive_const32(0x4346465F44535031ull, seed, requested, 0xA5A5A5A5u)
    ) & 1u) != 0u
        ? (uint8_t)CPRISK_CFF_DISPATCH_FN_TABLE
        : (uint8_t)CPRISK_CFF_DISPATCH_DIRECT;
}

/*
 * Newton–Raphson modular inverse mod 2^32. Convergence is quadratic, doubling
 * the number of correct low-order bits each step. Starting from `odd_value`
 * (which is correct in the lowest bit), 6 iterations guarantee >= 64 correct
 * bits — saturated within the 32-bit width with margin.
 *
 * Precondition: `odd_value` is odd. If even, the modular inverse does not
 * exist mod 2^32 and the iteration silently produces garbage; callers must
 * ensure oddness (see `cprisk_cff_affine_multiplier` / `_odd` helpers which
 * force the low bit set).
 */
static uint32_t cprisk_cff_mod_inverse_odd32(uint32_t odd_value) {
    /* Defense in depth: force the low bit to avoid silent corruption if a
     * caller miswires this. The cost is one OR; semantics for already-odd
     * inputs are unchanged. */
    const uint32_t v = odd_value | 1u;
    uint32_t inverse = v;
    inverse *= 2u - v * inverse;
    inverse *= 2u - v * inverse;
    inverse *= 2u - v * inverse;
    inverse *= 2u - v * inverse;
    inverse *= 2u - v * inverse;
    inverse *= 2u - v * inverse;
    return inverse;
}

/*
 * SPN byte substitution: 8-bit bijection generated at runtime from a UInt64 seed
 * (CFFSBoxPermutation256 / SplitMix64 + Fisher–Yates). Matches CloudPhoneRiskKit.
 */
static uint8_t g_cff_spn_sbox_fwd[256];
static pthread_once_t g_cff_spn_sbox_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_cff_spn_sbox_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_uint_fast32_t g_cff_spn_sbox_custom = 0;
static atomic_uint_fast64_t g_cff_spn_sbox_seed = 0;

typedef struct cprisk_cff_split_mix64 {
    uint64_t state;
} cprisk_cff_split_mix64_t;

static void cprisk_cff_split_mix64_init(cprisk_cff_split_mix64_t *rng, uint64_t seed) {
    rng->state = seed == 0u ? 1u : seed;
}

static uint64_t cprisk_cff_split_mix64_next(cprisk_cff_split_mix64_t *rng) {
    rng->state += 0x9E3779B97F4A7C15ull;
    uint64_t z = rng->state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

/*
 * Rejection-sampled uniform draw from [0, bound). Removes modulo bias when
 * `bound` does not divide 2^64. Threshold = 2^64 mod bound, computed as
 * `((uint64_t)0 - bound) % bound` (defined unsigned wrap). For bound <= 256
 * the rejection probability is at most 256/2^64 (≈ 0), but the distribution
 * is mathematically uniform.
 *
 * Cross-language contract: identical algorithm in
 * `cprisk-armor/.../CFFSBoxPermutation.swift` and
 * `CloudPhoneRiskKit/.../CFFSBoxRuntime.swift`.
 */
static uint64_t cprisk_cff_split_mix64_unbiased(cprisk_cff_split_mix64_t *rng, uint64_t bound) {
    if (bound == 0u) {
        return 0u;
    }
    const uint64_t threshold = ((uint64_t)0 - bound) % bound;
    uint64_t r;
    do {
        r = cprisk_cff_split_mix64_next(rng);
    } while (r < threshold);
    return r % bound;
}

static int cprisk_cff_spn_is_bijection_sized_u8(const uint8_t *table, size_t len) {
    if (table == NULL || len != 256u) {
        return 0;
    }
    uint8_t seen[256];
    memset(seen, 0, sizeof(seen));
    for (size_t i = 0u; i < 256u; ++i) {
        const uint8_t v = table[i];
        if (seen[v] != 0u) {
            return 0;
        }
        seen[v] = 1u;
    }
    return 1;
}

static int cprisk_cff_spn_is_bijection_u8(const uint8_t table[256]) {
    return cprisk_cff_spn_is_bijection_sized_u8(table, 256u);
}

static void cprisk_cff_spn_sbox_build_from_seed(uint64_t seed) {
    cprisk_cff_split_mix64_t rng;
    cprisk_cff_split_mix64_init(&rng, seed);
    for (size_t i = 0u; i < 256u; ++i) {
        g_cff_spn_sbox_fwd[i] = (uint8_t)i;
    }
    for (size_t i = 255u; i > 0u; --i) {
        const uint64_t j = cprisk_cff_split_mix64_unbiased(&rng, (uint64_t)(i + 1u));
        const uint8_t tmp = g_cff_spn_sbox_fwd[i];
        g_cff_spn_sbox_fwd[i] = g_cff_spn_sbox_fwd[(size_t)j];
        g_cff_spn_sbox_fwd[(size_t)j] = tmp;
    }
}

static int cprisk_cff_resolve_chain_meta_seed_i(
    const struct mach_header_64 *hdr,
    const char *section_name,
    uint64_t *out_seed
) {
    unsigned long sec_size = 0u;
    const uint8_t *sec = cprisk_find_section(
        hdr,
        CPRISK_ARMOR_SEGMENT_DATA,
        section_name,
        &sec_size
    );
    if (sec == NULL || sec_size < CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_HEADER_SIZE) {
        return 0;
    }

    struct cprisk_armor_swift_metadata_shuffle_header header;
    memcpy(&header, sec, sizeof(header));
    if (header.magic != CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_MAGIC ||
        header.abi_version != CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_ABI_VERSION) {
        return 0;
    }

    /* Overflow-safe size computation: a malformed header could claim a
     * record_count near UINT32_MAX, multiplying past size_t. */
    size_t records_total = 0u;
    if (__builtin_mul_overflow((size_t)header.record_count,
                               (size_t)CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_RECORD_SIZE,
                               &records_total)) {
        return 0;
    }
    size_t expected = 0u;
    if (__builtin_add_overflow((size_t)CPRISK_ARMOR_SWIFT_METADATA_SHUFFLE_HEADER_SIZE,
                               records_total,
                               &expected)) {
        return 0;
    }
    /*
     * Section must be EXACTLY the header+records size. Previously
     * `expected > sec_size` accepted any larger section, silently
     * tolerating truncation drift or attacker-injected trailing bytes
     * that downstream consumers might honor. Reject mismatched sizes.
     */
    if (expected != (size_t)sec_size) {
        return 0;
    }

    *out_seed = header.build_seed != 0u ? header.build_seed : CPRISK_CFF_SPN_CANONICAL_SEED_U64;
    return 1;
}

static uint64_t cprisk_cff_resolve_runtime_spn_seed_i(void) {
    const struct mach_header_64 *hdr =
        cprisk_find_own_header((const void *)(uintptr_t)&cprisk_cff_encode_state);
    if (hdr != NULL) {
        unsigned long sec_size = 0u;
        const uint8_t *sec = cprisk_find_section(
            hdr,
            CPRISK_ARMOR_SEGMENT_DATA,
            CPRISK_ARMOR_SECTION_ANTI_DEBUG_PLAN,
            &sec_size
        );
        if (sec != NULL && sec_size >= sizeof(struct cprisk_armor_antidebug_header)) {
            struct cprisk_armor_antidebug_header header;
            memcpy(&header, sec, sizeof(header));
            if (header.magic == CPRISK_ARMOR_ADBG_MAGIC &&
                header.version == CPRISK_ARMOR_ADBG_ABI_VERSION &&
                header.seed != 0u) {
                return header.seed;
            }
        }

        uint64_t chain_seed = 0u;
        if (cprisk_cff_resolve_chain_meta_seed_i(hdr, CPRISK_ARMOR_SECTION_CHAIN_META, &chain_seed) != 0) {
            return chain_seed;
        }
        if (cprisk_cff_resolve_chain_meta_seed_i(
                hdr,
                CPRISK_ARMOR_SECTION_CHAIN_META_FALLBACK,
                &chain_seed) != 0) {
            return chain_seed;
        }
    }
    return CPRISK_CFF_SPN_CANONICAL_SEED_U64;
}

/*
 * Concurrency model for the S-box state:
 *
 *  - First read: any caller hitting `cprisk_cff_spn_sbox_ensure()` triggers
 *    `pthread_once` once, which runs `init_default` under the once-lock —
 *    no other thread can read the table during that initial build.
 *  - Subsequent installs (`install_from_seed`, `install_from_bytes`): used
 *    rarely (typically armor-driven, once at startup). The previous code
 *    set `custom=1` BEFORE writing the 256-byte table, which let a
 *    concurrent reader that reached `ensure()` for the first time skip
 *    `init_default` (since `custom!=0`) and observe an uninitialized table.
 *
 * Fix:
 *  - Both installers now (a) ensure the once-init has run, then (b) take
 *    `g_cff_spn_sbox_mutex` and write the table under the mutex. The atomic
 *    `custom` / `seed` flags are stored AFTER the table write so a reader
 *    that misses the lock either sees the prior table or the new one — never
 *    a torn intermediate.
 *  - Hot-path readers (`spn_sbox_byte`) remain lock-free: they only run
 *    after `_ensure()` and accept that during a rare concurrent install
 *    they may read either the old or the new byte, both of which are valid
 *    permutation entries (every byte 0..255 maps to a byte 0..255).
 */

static void cprisk_cff_spn_sbox_init_default(void) {
    if (atomic_load(&g_cff_spn_sbox_custom) != 0u) {
        return;
    }
    const uint64_t seed = cprisk_cff_resolve_runtime_spn_seed_i();
    atomic_store(&g_cff_spn_sbox_seed, (uint_fast64_t)seed);
    cprisk_cff_spn_sbox_build_from_seed(seed);
}

static void cprisk_cff_spn_sbox_ensure(void) {
    (void)pthread_once(&g_cff_spn_sbox_once, cprisk_cff_spn_sbox_init_default);
}

void cprisk_cff_spn_sbox_install_from_seed(uint64_t seed) {
    const uint64_t normalized = seed == 0u ? 1u : seed;
    cprisk_cff_spn_sbox_ensure();
    pthread_mutex_lock(&g_cff_spn_sbox_mutex);
    cprisk_cff_spn_sbox_build_from_seed(normalized);
    atomic_store(&g_cff_spn_sbox_seed, (uint_fast64_t)normalized);
    atomic_store(&g_cff_spn_sbox_custom, 1u);
    pthread_mutex_unlock(&g_cff_spn_sbox_mutex);
}

void cprisk_cff_spn_sbox_install_from_bytes(const uint8_t forward256[256]) {
    if (forward256 == NULL) {
        return;
    }
    /*
     * Refuse non-bijective input. Previously this fell back to canonical seed,
     * which let an attacker who could call this API force a downgrade from a
     * per-build randomized table to the static canonical permutation. Now we
     * leave whatever table is currently installed; the next consumer that hits
     * `cprisk_cff_spn_sbox_ensure()` triggers the per-build init via
     * `cprisk_cff_resolve_runtime_spn_seed_i()`.
     */
    if (cprisk_cff_spn_is_bijection_u8(forward256) == 0) {
        return;
    }
    cprisk_cff_spn_sbox_ensure();
    pthread_mutex_lock(&g_cff_spn_sbox_mutex);
    memcpy(g_cff_spn_sbox_fwd, forward256, 256u);
    atomic_store(&g_cff_spn_sbox_seed, 0u);
    atomic_store(&g_cff_spn_sbox_custom, 1u);
    pthread_mutex_unlock(&g_cff_spn_sbox_mutex);
}

uint64_t cprisk_cff_runtime_spn_sbox_seed(void) {
    cprisk_cff_spn_sbox_ensure();
    return (uint64_t)atomic_load(&g_cff_spn_sbox_seed);
}

int cprisk_cff_spn_sbox_copy_forward(uint8_t out_forward256[256]) {
    if (out_forward256 == NULL) {
        return -1;
    }
    cprisk_cff_spn_sbox_ensure();
    /*
     * Take the install-mutex to guarantee a consistent snapshot. Without it,
     * a concurrent `install_from_seed` writing the table could produce a
     * caller-observable mix of the old and new permutation; the result might
     * not be a bijection, breaking any consumer that round-trips through it.
     */
    pthread_mutex_lock(&g_cff_spn_sbox_mutex);
    memcpy(out_forward256, g_cff_spn_sbox_fwd, 256u);
    pthread_mutex_unlock(&g_cff_spn_sbox_mutex);
    return 0;
}

static uint8_t cprisk_cff_spn_sbox_byte(uint8_t idx) {
    cprisk_cff_spn_sbox_ensure();
    return g_cff_spn_sbox_fwd[idx];
}

uint8_t cprisk_cff_spn_sbox_lookup(uint8_t idx) {
    return cprisk_cff_spn_sbox_byte(idx);
}

/*
 * `shadow_noise16` is a 4-step decoy mixer whose output is XOR'd into a
 * `volatile` sink and then `(void)`'d — i.e. it does not affect the Feistel
 * cipher's mathematical output, only the runtime instruction trace and timing
 * profile. The fixed 4 iterations balance instruction count against per-round
 * Feistel cost; widening the loop slows the hot dispatcher path with no
 * additional security in our threat model (instruction-level deobfuscation,
 * not chosen-plaintext cryptanalysis).
 */
static uint16_t cprisk_cff_shadow_noise16(uint16_t r, uint32_t rk, uint32_t salt, uint32_t round) {
    volatile uint32_t sink = ((uint32_t)r << 16u) | (uint32_t)r;
    const uint32_t round_mul = cprisk_cff_derive_const32_odd(
        0x4346465F53484431ull,
        rk,
        salt,
        0x51ED270Bu
    );
    const uint32_t shadow_xor = cprisk_cff_derive_const32(
        0x4346465F53484432ull,
        rk,
        salt,
        0xA5C31F27u
    );
    const uint32_t lane_mul = cprisk_cff_derive_const32_odd(
        0x4346465F53484433ull,
        rk,
        salt,
        0x9E3779B1u
    );
    const uint32_t lane_add = cprisk_cff_derive_const32(
        0x4346465F53484434ull,
        rk,
        salt,
        0x7F4A7C15u
    );
    uint32_t shadow = cprisk_cff_avalanche32(rk ^ salt ^ (round * round_mul) ^ shadow_xor);
    for (uint32_t step = 0u; step < 4u; ++step) {
        const uint32_t lane = cprisk_cff_rotate_left32(
            shadow ^ sink ^ (step * lane_mul),
            (uint32_t)((round + (step * 5u) + 3u) & 31u)
        );
        shadow ^= cprisk_cff_avalanche32(
            lane +
            (sink ^ cprisk_cff_rotate_right32(rk, (uint32_t)((step + 3u) & 31u))) +
            lane_add
        );
        sink ^= lane ^ cprisk_cff_rotate_right32(shadow, (uint32_t)((step + 7u) & 31u));
    }
    sink ^= cprisk_cff_rotate_left32(sink ^ shadow, (uint32_t)(((round * 3u) + 11u) & 31u));
    return (uint16_t)((shadow ^ sink ^ (shadow >> 16u)) & 0xFFFFu);
}

/*
 * 8-round Feistel network. This is a state-encoding primitive for CFF
 * dispatcher obfuscation, not a data-confidentiality cipher: the round
 * function combines an avalanche permutation, a SplitMix64-derived 256-byte
 * S-box (forward-only — Feistel inversion does not need an inverse table),
 * and double SPN substitution. 8 rounds yields full byte-level diffusion
 * with margin for this attack model (no chosen-plaintext oracle); higher
 * round counts only add latency on a hot dispatcher path.
 */
#define CPRISK_CFF_FEISTEL_ROUNDS 8u

static uint16_t cprisk_cff_feistel_F(uint16_t r, uint32_t k, uint32_t salt, uint32_t round) {
    const uint32_t round_mul = cprisk_cff_derive_const32_odd(
        0x4346465F46535231ull,
        k,
        salt,
        0x9E3779B9u
    );
    const uint32_t round_xor = cprisk_cff_derive_const32(
        0x4346465F46535232ull,
        k,
        salt,
        0xDEADBEEFu
    );
    uint32_t rk = cprisk_cff_avalanche32(k ^ salt ^ (round * round_mul) ^ round_xor);
    uint8_t b0 = (uint8_t)(r & 0xFFu);
    uint8_t b1 = (uint8_t)((r >> 8) & 0xFFu);
    uint32_t piece = (uint32_t)cprisk_cff_spn_sbox_byte(b0 ^ (uint8_t)(rk & 0xFFu)) ^
        ((uint32_t)cprisk_cff_spn_sbox_byte(b1 ^ (uint8_t)((rk >> 8) & 0xFFu)) << 8u);
    {
        const uint32_t shadow_k_xor = cprisk_cff_derive_const32(
            0x4346465F46535233ull,
            k,
            salt,
            0x6C8E9CF5u
        );
        const uint32_t shadow_s_xor = cprisk_cff_derive_const32(
            0x4346465F46535234ull,
            k,
            salt,
            0x517CC1B7u
        );
        const uint16_t shadow0 = cprisk_cff_shadow_noise16(r, rk, salt, round);
        const uint16_t shadow1 = cprisk_cff_shadow_noise16(
            (uint16_t)(r ^ shadow0),
            rk ^ piece ^ shadow_k_xor,
            salt ^ shadow_s_xor,
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
    const uint32_t pre_xor = cprisk_cff_derive_const32(0x4346465F46534531ull, key, salt, 0x0F1055A1u);
    const uint32_t post_xor = cprisk_cff_derive_const32(0x4346465F46534532ull, key, salt, 0x0ACC0DECu);
    uint32_t v = state ^ cprisk_cff_avalanche32(key ^ salt ^ pre_xor);
    uint16_t l = (uint16_t)(v >> 16);
    uint16_t r = (uint16_t)(v & 0xFFFFu);
    for (uint32_t rnd = 0u; rnd < CPRISK_CFF_FEISTEL_ROUNDS; rnd++) {
        const uint16_t nl = r;
        const uint16_t nr = (uint16_t)(l ^ cprisk_cff_feistel_F(r, key, salt, rnd));
        l = nl;
        r = nr;
    }
    const uint32_t mid = ((uint32_t)l << 16) | (uint32_t)r;
    return mid ^ cprisk_cff_avalanche32(key ^ salt ^ post_xor);
}

/*
 * Decode is the strict inverse of `cprisk_cff_feistel32_encode_core`:
 *   - `pre_xor` and `post_xor` use the SAME derivation as encode (must
 *     match exactly, otherwise pre/post whitening is not undone);
 *   - the round loop iterates rounds in REVERSE (R-1 → 0) with the same
 *     `feistel_F` since Feistel inversion does not need an inverse F.
 * Constants `0x0F1055A1` ("FLOSS-A1") and `0x0ACC0DEC` ("ACC0DEC") are
 * retained as call-site bases that get re-mixed through `derive_const32`.
 */
static uint32_t cprisk_cff_feistel32_decode_core(uint32_t encoded_state, uint32_t key, uint32_t salt) {
    const uint32_t pre_xor = cprisk_cff_derive_const32(0x4346465F46534531ull, key, salt, 0x0F1055A1u);
    const uint32_t post_xor = cprisk_cff_derive_const32(0x4346465F46534532ull, key, salt, 0x0ACC0DECu);
    uint32_t mid = encoded_state ^ cprisk_cff_avalanche32(key ^ salt ^ post_xor);
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
    return v ^ cprisk_cff_avalanche32(key ^ salt ^ pre_xor);
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
    const uint32_t selector_xor = cprisk_cff_derive_const32(
        0x4346465F5354594Cull,
        seed,
        entry_state,
        0x13579BDFu
    );
    const uint32_t h = cprisk_cff_avalanche32(seed ^ cprisk_cff_rotate_left32(entry_state, 11u) ^ selector_xor);
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

static _Thread_local uint32_t cprisk_cff_tls_mix32 = 0u;
static atomic_uint_fast32_t s_cff_vm_link_token = 0;
static atomic_uint_fast32_t s_cff_chain_link = 0;

static uint32_t cprisk_cff_chain_load_i(void) {
    uint_fast32_t chain = atomic_load(&s_cff_chain_link);
    if (chain == 0u) {
        /*
         * Race-free initialization: previously a concurrent caller could
         * race between the load and the store, with both threads computing
         * the sentinel and storing it. Although the value is deterministic
         * (so the race was benign), CAS makes the intent explicit and
         * prevents the second thread from clobbering a value another path
         * may legitimately have stored in between.
         */
        const uint_fast32_t sentinel =
            (uint_fast32_t)cprisk_cff_chain_fallback_sentinel_u32();
        uint_fast32_t expected = 0u;
        if (!atomic_compare_exchange_strong(&s_cff_chain_link, &expected, sentinel)) {
            /* Some other thread already initialized — adopt their value. */
            chain = expected;
        } else {
            chain = sentinel;
        }
    }
    return (uint32_t)chain;
}

static void cprisk_cff_ctx_set_last_plain_i(cprisk_cff_context_t *context, uint32_t plain) {
    const uint32_t split_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_mask_enc(context) ^ cprisk_cff_ctx_nonce_plain(context) ^ cprisk_cff_hdr_const32(
            0x4346465F43545835ull,
            cprisk_cff_ctx_mask_enc(context),
            cprisk_cff_ctx_nonce_plain(context),
            cprisk_cff_hdr_base_derive(0x4346465F42415335ull, 0x5F3759DFu)
        )
    );
    context->state_share_a = cprisk_cff_avalanche32(
        plain ^ cprisk_cff_ctx_seed_plain(context) ^ cprisk_cff_ctx_nonce_plain(context) ^ cprisk_cff_derive_const32(
            0x4346465F4354583Cull,
            cprisk_cff_ctx_mask_enc(context),
            cprisk_cff_ctx_nonce_plain(context),
            0x1A2B3C4Du
        )
    );
    context->state_share_b = plain ^ context->state_share_a ^ split_mask;
}

static void cprisk_cff_ctx_set_chain_plain_i(cprisk_cff_context_t *context, uint32_t chain) {
    const uint32_t chain_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(context) ^ cprisk_cff_ctx_nonce_plain(context) ^ cprisk_cff_hdr_const32(
            0x4346465F43545836ull,
            cprisk_cff_ctx_storage_mask(context),
            cprisk_cff_ctx_nonce_plain(context),
            cprisk_cff_hdr_base_derive(0x4346465F42415336ull, 0xC11A1E5Eu)
        )
    );
    context->chain_snapshot = chain ^ chain_mask;
}

static void cprisk_cff_ctx_set_entry_guard_plain_i(cprisk_cff_context_t *context, uint32_t guard) {
    const uint32_t guard_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(context) ^ cprisk_cff_ctx_nonce_plain(context) ^ cprisk_cff_hdr_const32(
            0x4346465F43545837ull,
            cprisk_cff_ctx_storage_mask(context),
            cprisk_cff_ctx_nonce_plain(context),
            cprisk_cff_hdr_base_derive(0x4346465F42415337ull, 0xE17A9A5Bu)
        )
    );
    context->entry_guard = guard ^ guard_mask;
}

static uint32_t cprisk_cff_opaque_selector_i(const cprisk_cff_context_t *context, uint32_t decoded_state) {
    const uint32_t seed_p = cprisk_cff_ctx_seed_plain(context);
    const uint32_t salt_p = cprisk_cff_ctx_salt_plain(context);
    const uint32_t salt_golden = salt_p * cprisk_cff_derive_const32_odd(
        0x4346465F4F505132ull,
        seed_p,
        decoded_state,
        0x9E3779B1u
    );
    uint32_t token = cprisk_cff_avalanche32(
        cprisk_cff_ctx_encoded_plain(context) ^
        decoded_state ^
        salt_golden ^
        ((uint32_t)context->codec_style << 24u) ^
        cprisk_cff_derive_const32(
            0x4346465F4F505133ull,
            seed_p,
            decoded_state,
            (uint32_t)context->codec_style ^ (seed_p >> 16u)
        )
    );
    token ^= cprisk_cff_rotate_left32(token, ((seed_p >> 27u) & 31u) | 1u);
    token ^= cprisk_cff_tls_mix32;
    return token;
}

static void cprisk_cff_refresh_vm_link_token_i(const cprisk_cff_context_t *context) {
    const uint32_t mix_const = cprisk_cff_derive_const32(
        0x4346465F4354583Full,
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        0xC0FFEE42u
    );
    uint32_t t = cprisk_cff_avalanche32(
        cprisk_cff_ctx_seed_plain(context) ^
        cprisk_cff_ctx_encoded_plain(context) ^
        cprisk_cff_ctx_salt_plain(context) ^
        cprisk_cff_ctx_last_plain(context) ^
        mix_const
    );
    if (t == 0u) {
        t = cprisk_cff_chain_fallback_sentinel_u32();
    }
    atomic_store(&s_cff_vm_link_token, (uint_fast32_t)t);
}

static void cprisk_cff_tls_bump_i(const cprisk_cff_context_t *context, uint32_t next_state) {
    const uint32_t bump_const = cprisk_cff_derive_const32(
        0x4346465F43545840ull,
        cprisk_cff_ctx_seed_plain(context),
        next_state,
        cprisk_cff_tls_mix_derive_base_u32()
    );
    cprisk_cff_tls_mix32 = cprisk_cff_avalanche32(
        cprisk_cff_tls_mix32 ^ cprisk_cff_ctx_seed_plain(context) ^ next_state ^ cprisk_cff_ctx_encoded_plain(context) ^
        bump_const
    );
}

static void cprisk_cff_chain_advance_i(cprisk_cff_context_t *context, uint32_t basis) {
    const uint32_t advance_const = cprisk_cff_derive_const32(
        0x4346465F43545841ull,
        cprisk_cff_ctx_seed_plain(context),
        basis ^ cprisk_cff_ctx_nonce_plain(context),
        cprisk_cff_tls_mix_derive_base_u32()
    );
    uint32_t next = cprisk_cff_avalanche32(
        cprisk_cff_ctx_chain_plain(context) ^
        cprisk_cff_ctx_seed_plain(context) ^
        cprisk_cff_ctx_encoded_plain(context) ^
        cprisk_cff_ctx_salt_plain(context) ^
        basis ^
        cprisk_cff_ctx_nonce_plain(context) ^
        cprisk_cff_ctx_entry_guard_plain(context) ^
        advance_const
    );
    if (next == 0u) {
        next = cprisk_cff_chain_fallback_sentinel_u32();
    }
    atomic_store(&s_cff_chain_link, (uint_fast32_t)next);
    cprisk_cff_ctx_set_chain_plain_i(context, next);
}

static void cprisk_cff_chain_finalize_i(cprisk_cff_context_t *context) {
    cprisk_cff_chain_advance_i(context, cprisk_cff_ctx_last_plain(context));
}

void cprisk_cff_chain_begin(void) {
    const uint32_t g = cprisk_cff_chain_load_i();
    const uint32_t chain_const = cprisk_cff_derive_const32(
        0x4346465F43545842ull,
        g,
        cprisk_cff_tls_mix32,
        0xCFF5B0E5u
    );
    cprisk_cff_tls_mix32 = cprisk_cff_avalanche32(cprisk_cff_tls_mix32 ^ g ^ chain_const);
}

uint32_t cprisk_cff_get_chain_link(void) {
    /* Mix in the calling thread's fingerprint so two threads observing the
     * same (deterministic) global chain still see distinct chain values
     * propagating into TLS. Audit flagged the prior version as exposing
     * cross-thread correlation when both threads called this concurrently. */
    return cprisk_cff_chain_load_i() ^ (uint32_t)cprisk_cff_thread_fingerprint();
}

uint32_t cprisk_cff_get_vm_link_token(void) {
    return (uint32_t)atomic_load(&s_cff_vm_link_token);
}

int cprisk_cff_chain_entry_verify(const cprisk_cff_context_t *context) {
    if (context == NULL) {
        return 0;
    }
    const uint32_t observed = cprisk_cff_chain_load_i();
    return cprisk_cff_chain_entry_verify_inline(context, observed);
}

/*
 * Flat 16-iteration decoy mixer — does NOT recurse into the CFF state
 * machinery, so there is no stack-blowup vector here despite the function
 * name suggesting "path" exploration. Audit pass flagged a hypothetical
 * recursion guard; the actual implementation only spins on a `volatile`
 * sink and a single `cprisk_cff_os_mix32()` syscall, which is itself
 * bounded by the OS readiness check inside `os_mix32`.
 */
void cprisk_cff_run_fake_path_decoy(const cprisk_cff_context_t *context) {
    if (context == NULL) {
        return;
    }
    const uint32_t decoy_step_mul = cprisk_cff_derive_const32_odd(
        0x4346465F46414B31ull,
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        0x9E3779B1u
    );
    uint32_t w = cprisk_cff_ctx_seed_plain(context) ^ cprisk_cff_ctx_encoded_plain(context) ^
        cprisk_cff_ctx_salt_plain(context) ^ cprisk_cff_ctx_last_plain(context);
    for (uint32_t i = 0u; i < 16u; i++) {
        w = cprisk_cff_avalanche32(w ^ i ^ (i * decoy_step_mul));
        volatile uint32_t sink = w;
        sink ^= cprisk_cff_rotate_left32(sink, (uint32_t)(i & 31u));
        sink ^= cprisk_cff_avalanche32(sink ^ cprisk_cff_ctx_seed_plain(context) ^ (uint32_t)i);
        (void)sink;
    }
    (void)cprisk_cff_os_mix32();
}

static uint32_t cprisk_cff_mix_seed(uint32_t seed, uint32_t entry_state) {
    const uint32_t mix_const = cprisk_cff_derive_const32(
        0x4346465F43545843ull,
        seed,
        entry_state,
        0xA24BAED5u
    );
    const uint32_t entry_golden = entry_state * cprisk_cff_derive_const32_odd(
        0x4346465F4D495834ull,
        seed,
        entry_state,
        0x9E3779B1u
    );
    return cprisk_cff_avalanche32(seed ^ entry_golden ^ mix_const);
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

    /*
     * Mix in 8 bytes of OS entropy when available. The previous derivation
     * was deterministic given fixed pid/tid/clock state (e.g. forensic
     * replay, low-jitter test harnesses), which let an attacker narrow the
     * seed search space. `getentropy` is a one-shot CSPRNG read; we fold it
     * into the existing avalanche so any failure simply degrades to the
     * legacy mix instead of zeroing entropy.
     */
#ifdef CPRISK_CFF_HAVE_GETENTROPY
    {
        uint8_t os_rand[8];
        if (getentropy(os_rand, sizeof(os_rand)) == 0) {
            const uint32_t lo = ((uint32_t)os_rand[0]) |
                                ((uint32_t)os_rand[1] << 8) |
                                ((uint32_t)os_rand[2] << 16) |
                                ((uint32_t)os_rand[3] << 24);
            const uint32_t hi = ((uint32_t)os_rand[4]) |
                                ((uint32_t)os_rand[5] << 8) |
                                ((uint32_t)os_rand[6] << 16) |
                                ((uint32_t)os_rand[7] << 24);
            seed ^= lo ^ cprisk_cff_rotate_left32(hi, 13u);
        }
        cprisk_secure_zero(os_rand, sizeof(os_rand));
    }
#endif

    seed = cprisk_cff_avalanche32(seed ^ cprisk_cff_tls_mix_derive_base_u32());
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
    /*
     * AUTO is normally resolved to a concrete style by `cprisk_cff_resolve_style`
     * during `cprisk_cff_init`. If a caller passes AUTO directly to
     * `cprisk_cff_encode_state_with_style` the explicit `case AUTO` here keeps
     * the contract documented: AUTO ≡ FEISTEL_SPN at the codec layer. Decode
     * mirrors the same fall-through.
     */
    switch (style) {
        case CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN:
        case CPRISK_CFF_CODEC_STYLE_AUTO:
            return cprisk_cff_feistel32_encode_core(state, key, salt);
        case CPRISK_CFF_CODEC_STYLE_ADD_ROTATE_XOR: {
            const uint32_t addend = cprisk_cff_avalanche32(key + salt + cprisk_cff_derive_const32(
                0x4346465F53544131ull,
                key,
                salt,
                0x7F4A7C15u
            ));
            const uint32_t shift = (((key >> 3u) ^ salt) & 31u) | 1u;
            const uint32_t mixed = cprisk_cff_rotate_left32(state + addend, shift);
            return mixed ^
                cprisk_cff_avalanche32(key ^ cprisk_cff_derive_const32(
                    0x4346465F53544132ull,
                    key,
                    salt,
                    0xA24BAED5u
                )) ^
                (salt * cprisk_cff_derive_const32_odd(
                    0x4346465F53544133ull,
                    key,
                    salt,
                    0x165667B1u
                ));
        }
        case CPRISK_CFF_CODEC_STYLE_AFFINE: {
            const uint32_t mask = cprisk_cff_avalanche32(key + salt + cprisk_cff_derive_const32(
                0x4346465F53544631ull,
                key,
                salt,
                0x51ED270Bu
            ));
            const uint32_t multiplier = cprisk_cff_affine_multiplier(key, salt);
            const uint32_t addend = cprisk_cff_affine_addend(key, salt);
            const uint32_t masked = state ^ mask;
            return (masked * multiplier + addend) ^ cprisk_cff_rotate_left32(key, (salt & 31u) | 1u);
        }
        case CPRISK_CFF_CODEC_STYLE_XOR_ROTATE:
        default: {
            const uint32_t mix = cprisk_cff_avalanche32(key ^ salt ^ cprisk_cff_derive_const32(
                0x4346465F53545831ull,
                key,
                salt,
                0x9E3779B9u
            ));
            const uint32_t shift = (mix & 31u) | 1u;
            const uint32_t saltprod = salt * cprisk_cff_derive_const32_odd(
                0x4346465F53545832ull,
                key,
                salt,
                0x045D9F3Bu
            );
            const uint32_t use_mba =
                (cprisk_cff_avalanche32(key ^ salt ^ cprisk_cff_derive_const32(
                    0x4346465F53545834ull,
                    key,
                    salt,
                    0xEFCAB9A5u
                )) & 1u) != 0u;
            uint32_t core =
                use_mba != 0u ? cprisk_cff_xor_mba_u32(state, mix) : (state ^ mix);
            if (mba_layers >= 2u) {
                core = cprisk_cff_mba_chain_xor_u32(core, key, salt, mba_layers);
            }
            const uint32_t masked = core ^ saltprod;
            return cprisk_cff_rotate_left32(masked, shift) + (key * cprisk_cff_derive_const32_odd(
                0x4346465F53545833ull,
                key,
                salt,
                0x27D4EB2Du
            ));
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

void cprisk_cff_state_transition_commit(cprisk_cff_context_t *context, uint32_t next_state) {
    if (context == NULL) {
        return;
    }
    {
        const uint32_t observed = cprisk_cff_chain_load_i();
        if (cprisk_cff_chain_snapshot_verify_inline(context, observed) == 0) {
            cprisk_cff_poison_default(context);
            return;
        }
    }
    cprisk_cff_ctx_set_last_plain_i(context, next_state);
    {
        const uint32_t enc_plain = cprisk_cff_encode_state_with_style_impl(
            next_state,
            cprisk_cff_ctx_seed_plain(context),
            cprisk_cff_ctx_salt_plain(context),
            (cprisk_cff_codec_style_t)context->codec_style,
            context->mba_layers
        );
        context->encoded_state = enc_plain ^ cprisk_cff_ctx_mask_enc(context);
    }
    cprisk_cff_chain_advance_i(context, next_state);
    cprisk_cff_refresh_vm_link_token_i(context);
    cprisk_cff_tls_bump_i(context, next_state);
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
            const uint32_t addend = cprisk_cff_avalanche32(key + salt + cprisk_cff_derive_const32(
                0x4346465F53544131ull,
                key,
                salt,
                0x7F4A7C15u
            ));
            const uint32_t shift = (((key >> 3u) ^ salt) & 31u) | 1u;
            const uint32_t unmasked =
                encoded_state ^
                cprisk_cff_avalanche32(key ^ cprisk_cff_derive_const32(
                    0x4346465F53544132ull,
                    key,
                    salt,
                    0xA24BAED5u
                )) ^
                (salt * cprisk_cff_derive_const32_odd(
                    0x4346465F53544133ull,
                    key,
                    salt,
                    0x165667B1u
                ));
            return cprisk_cff_rotate_right32(unmasked, shift) - addend;
        }
        case CPRISK_CFF_CODEC_STYLE_AFFINE: {
            const uint32_t mask = cprisk_cff_avalanche32(key + salt + cprisk_cff_derive_const32(
                0x4346465F53544631ull,
                key,
                salt,
                0x51ED270Bu
            ));
            const uint32_t multiplier = cprisk_cff_affine_multiplier(key, salt);
            const uint32_t inverse = cprisk_cff_mod_inverse_odd32(multiplier);
            const uint32_t addend = cprisk_cff_affine_addend(key, salt);
            const uint32_t unxored = encoded_state ^ cprisk_cff_rotate_left32(key, (salt & 31u) | 1u);
            const uint32_t unscaled = (unxored - addend) * inverse;
            return unscaled ^ mask;
        }
        case CPRISK_CFF_CODEC_STYLE_XOR_ROTATE:
        default: {
            const uint32_t mix = cprisk_cff_avalanche32(key ^ salt ^ cprisk_cff_derive_const32(
                0x4346465F53545831ull,
                key,
                salt,
                0x9E3779B9u
            ));
            const uint32_t shift = (mix & 31u) | 1u;
            const uint32_t saltprod = salt * cprisk_cff_derive_const32_odd(
                0x4346465F53545832ull,
                key,
                salt,
                0x045D9F3Bu
            );
            const uint32_t use_mba =
                (cprisk_cff_avalanche32(key ^ salt ^ cprisk_cff_derive_const32(
                    0x4346465F53545834ull,
                    key,
                    salt,
                    0xEFCAB9A5u
                )) & 1u) != 0u;
            const uint32_t unshifted =
                cprisk_cff_rotate_right32(encoded_state - (key * cprisk_cff_derive_const32_odd(
                    0x4346465F53545833ull,
                    key,
                    salt,
                    0x27D4EB2Du
                )), shift);
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

    const uint32_t salt_const = cprisk_cff_derive_const32(
        0x4346465F43545844ull,
        seed,
        runtime_hint ^ (uint32_t)(tid_hash >> 17u),
        cprisk_cff_rt_salt_mix_base_u32(seed, runtime_hint)
    );
    return cprisk_cff_avalanche32(
        seed ^
        runtime_hint ^
        (uint32_t)pid ^
        (uint32_t)(monotonic_ns >> 11u) ^
        (uint32_t)(tid_hash >> 17u) ^
        cprisk_cff_os_mix32() ^
        cprisk_cff_dyld_mix32() ^
        salt_const
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
    /*
     * Init ordering invariant (do not reorder without re-deriving):
     *
     *   1. `storage_nonce` is set BEFORE any setter that resolves
     *      `cprisk_cff_ctx_nonce_plain()` (i.e. `set_chain_plain_i`,
     *      `set_last_plain_i`, `set_entry_guard_plain_i`, and the
     *      `seed`/`runtime_salt`/`encoded_state` masking writes below).
     *   2. `storage_mask` derives only from `(uintptr_t)context` and
     *      `sizeof(*context)`, so it is well-defined the moment the struct
     *      memory exists — no dependency on any field value.
     *   3. The `mask_*` helpers all chain through `storage_mask` and
     *      `nonce_plain`; once both above are valid, every subsequent
     *      setter is order-independent.
     *
     * Audit pass flagged a suspected cycle here; the analysis above shows
     * the actual order is acyclic. Comment retained so future readers do
     * not "fix" the perceived issue by reordering and breaking masking.
     */
    {
        const uint32_t chain_plain = cprisk_cff_chain_load_i();
        const uint32_t seed_plain = cprisk_cff_mix_seed(
            config->seed ^ cprisk_cff_rotate_left32(chain_plain, 5u),
            config->entry_state ^ chain_plain
        );
        const uint32_t salt_plain = config->runtime_salt != 0u
            ? (config->runtime_salt ^ cprisk_cff_rotate_left32(chain_plain, 7u))
            : cprisk_cff_runtime_salt(
                config->seed ^ chain_plain,
                config->entry_state ^ cprisk_cff_derive_const32(
                    0x4346465F43545845ull,
                    config->seed,
                    chain_plain,
                    0x13579BDFu
                ) ^ cprisk_cff_rotate_left32(chain_plain, 3u)
            );
        const uint32_t raw_nonce = cprisk_cff_avalanche32(
            seed_plain ^
            salt_plain ^
            config->entry_state ^
            chain_plain ^
            cprisk_cff_tls_mix32 ^
            (uint32_t)cprisk_cff_thread_fingerprint() ^
            cprisk_cff_build_seed32_i() ^
            cprisk_cff_derive_const32(
                0x4346465F4E4F4E43ull,
                seed_plain,
                salt_plain ^ chain_plain,
                cprisk_cff_tls_mix32 ^ (uint32_t)cprisk_cff_thread_fingerprint()
            )
        );

        context->iteration_budget = config->iteration_budget != 0u
            ? config->iteration_budget
            : CPRISK_CFF_ITERATION_BUDGET;
        context->release_build = config->release_build;
        context->enable_fake_states = config->enable_fake_states;
        context->fake_state_budget = (uint8_t)((config->enable_fake_states != 0u && config->release_build != 0u) ? 7u : 0u);
        context->codec_style = (uint8_t)cprisk_cff_resolve_style(
            seed_plain,
            config->entry_state,
            config->codec_style
        );
        context->mba_layers = cprisk_cff_normalize_mba_layers(seed_plain, config->mba_layers);
        context->dispatch_style = cprisk_cff_resolve_dispatch_style_u8(seed_plain, config->dispatch_style);
        context->symex_guard_budget = config->symex_guard_budget;
        context->default_action = config->default_action;
        context->storage_nonce = raw_nonce ^ cprisk_cff_ctx_storage_mask(context);
        cprisk_cff_ctx_set_chain_plain_i(context, chain_plain);

        context->seed = seed_plain ^ cprisk_cff_ctx_mask_ptr(context);
        context->runtime_salt = salt_plain ^ cprisk_cff_ctx_mask_salt(context);
        cprisk_cff_ctx_set_last_plain_i(context, config->entry_state);
        cprisk_cff_ctx_set_entry_guard_plain_i(
            context,
            cprisk_cff_chain_entry_guard_expected_inline(context, chain_plain)
        );

        {
            const uint32_t enc_plain = cprisk_cff_encode_state_with_style_impl(
                config->entry_state,
                seed_plain,
                salt_plain,
                (cprisk_cff_codec_style_t)context->codec_style,
                context->mba_layers
            );
            context->encoded_state = enc_plain ^ cprisk_cff_ctx_mask_enc(context);
        }
    }
    cprisk_cff_refresh_vm_link_token_i(context);
    cprisk_cff_tls_bump_i(context, config->entry_state);
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

    const uint32_t decoded = cprisk_cff_decode_state_with_style_impl(
        cprisk_cff_ctx_encoded_plain(context),
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
    cprisk_cff_ctx_set_last_plain_i(context, decoded);
    return decoded;
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
    const uint32_t decoded = cprisk_cff_decode_state_with_style_impl(
        cprisk_cff_ctx_encoded_plain(context),
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
    cprisk_cff_ctx_set_last_plain_i(context, decoded);
    return decoded;
}

static uint32_t cprisk_cff_dispatch_decode_direct_ctx(cprisk_cff_context_t *context) {
    const uint32_t decoded = cprisk_cff_decode_state_with_style_impl(
        cprisk_cff_ctx_encoded_plain(context),
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
    );
    cprisk_cff_ctx_set_last_plain_i(context, decoded);
    return decoded;
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
    const uint32_t mix = cprisk_cff_avalanche32(
        cprisk_cff_ctx_seed_plain(context) ^
        cprisk_cff_ctx_salt_plain(context) ^
        cprisk_cff_derive_const32(
            0x4346465F43545846ull,
            cprisk_cff_ctx_seed_plain(context),
            cprisk_cff_ctx_salt_plain(context),
            0x8F82C945u
        )
    );
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
        limit = 8u;
    }
    limit *= 1u + (risk_mask & 0xFFu);
    if (limit > 160u) {
        limit = 160u;
    }
    struct timespec ts;
    uint32_t acc = risk_mask ^ cprisk_cff_ctx_encoded_plain(context) ^ cprisk_cff_ctx_seed_plain(context);
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        acc ^= (uint32_t)ts.tv_nsec;
        acc = cprisk_cff_rotate_left32(acc, (uint32_t)(ts.tv_sec & 31u));
    }
    acc ^= (uint32_t)getpid() ^ cprisk_cff_thread_fingerprint();
    const uint32_t step_mul = cprisk_cff_derive_const32_odd(
        0x4346465F43545847ull,
        cprisk_cff_ctx_seed_plain(context),
        risk_mask ^ cprisk_cff_ctx_salt_plain(context),
        0x9E3779B1u
    );
    for (uint32_t i = 0u; i < limit; i++) {
        acc = cprisk_cff_avalanche32(acc ^ i ^ (uint32_t)(i * step_mul));
        if ((acc & 15u) == (risk_mask & 15u)) {
            volatile uint32_t sink = acc;
            sink ^= cprisk_cff_rotate_left32(sink, (uint32_t)(i & 31u));
            (void)sink;
        }
    }
    (void)cprisk_cff_os_mix32();
}

void cprisk_cff_set_state(cprisk_cff_context_t *context, uint32_t next_state) {
    if (context == NULL) {
        return;
    }

    if (cprisk_cff_opaque_transition_ok_inline(
            cprisk_cff_ctx_last_plain(context),
            next_state,
            cprisk_cff_ctx_seed_plain(context),
            cprisk_cff_ctx_salt_plain(context)) == 0) {
        cprisk_cff_poison_default(context);
        return;
    }

    cprisk_cff_state_transition_commit(context, next_state);
}

void cprisk_cff_set_encoded_state(cprisk_cff_context_t *context, uint32_t encoded_state) {
    if (context == NULL) {
        return;
    }

    context->encoded_state = encoded_state ^ cprisk_cff_ctx_mask_enc(context);
    {
        const uint32_t decoded = cprisk_cff_decode_state_with_style_impl(
        encoded_state,
        cprisk_cff_ctx_seed_plain(context),
        cprisk_cff_ctx_salt_plain(context),
        (cprisk_cff_codec_style_t)context->codec_style,
        context->mba_layers
        );
        cprisk_cff_ctx_set_last_plain_i(context, decoded);
    }
    cprisk_cff_refresh_vm_link_token_i(context);
    cprisk_cff_tls_bump_i(context, cprisk_cff_ctx_last_plain(context));
}

/*
 * Note on `fake_state_budget`: the field is only initialized in
 * `cprisk_cff_init` (currently at the `7u` literal for release builds)
 * and read here. It is intentionally NOT decremented per visit — fake
 * state selection is gated by `cprisk_cff_opaque_selector_i` and the
 * `% modulo` reduction below, which produce a stable per-context decision
 * keyed on `decoded_state`. If a future change introduces decrement, use
 * a saturating decrement (clamp at zero) — uint8 wrap to 0xFF would
 * re-arm fake-state visits the policy says should be exhausted.
 */
int cprisk_cff_should_visit_fake_state(const cprisk_cff_context_t *context, uint32_t decoded_state) {
    uint32_t mixed = 0u;
    uint32_t modulo = 0u;

    if (context == NULL || context->enable_fake_states == 0u || context->release_build == 0u || context->fake_state_budget == 0u) {
        return 0;
    }

    mixed = cprisk_cff_opaque_selector_i(context, decoded_state);
    {
        uint32_t h = cprisk_cff_fnv32a_basis_i();
        h ^= mixed;
        h *= cprisk_cff_fnv32a_prime_i();
        h ^= decoded_state ^ cprisk_cff_ctx_seed_plain(context);
        h *= cprisk_cff_fnv_alt_prime_i();
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
            cprisk_integrity_poison_cff_lane();
            context->iteration_budget = 0u;
            cprisk_cff_ctx_set_last_plain_i(context, 0xFFFF0001u);
            {
                const uint32_t enc_plain = cprisk_cff_encode_state_with_style_impl(
                    0xFFFF0001u,
                    cprisk_cff_ctx_seed_plain(context),
                    cprisk_cff_ctx_salt_plain(context),
                    (cprisk_cff_codec_style_t)context->codec_style,
                    context->mba_layers
                );
                context->encoded_state = enc_plain ^ cprisk_cff_ctx_mask_enc(context);
            }
            cprisk_cff_refresh_vm_link_token_i(context);
            break;
        case CPRISK_CFF_DEFAULT_FAIL_CLOSED:
        default:
            context->iteration_budget = 0u;
            cprisk_cff_ctx_set_last_plain_i(context, 0xFFFF0000u);
            {
                const uint32_t enc_plain = cprisk_cff_encode_state_with_style_impl(
                    0xFFFF0000u,
                    cprisk_cff_ctx_seed_plain(context),
                    cprisk_cff_ctx_salt_plain(context),
                    (cprisk_cff_codec_style_t)context->codec_style,
                    context->mba_layers
                );
                context->encoded_state = enc_plain ^ cprisk_cff_ctx_mask_enc(context);
            }
            cprisk_cff_refresh_vm_link_token_i(context);
            break;
    }
}

/*
 * Finalize: clears all sensitive material (seed, salt, encoded state, share
 * splits, nonce, masks). The context struct contains no owning pointers — it
 * is plain old data — so a single `memset` is sufficient. Allocation lifetime
 * (stack / heap / arena) is the caller's responsibility; the macros
 * `CPR_CFF_BEGIN` / `CPR_CFF_BEGIN_EX` use a stack-local context whose storage
 * is naturally reclaimed when the enclosing block ends.
 */
void cprisk_cff_finalize(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return;
    }

    cprisk_cff_chain_finalize_i(context);
    memset(context, 0, sizeof(*context));
}

/* ── Dispatch Epoch Rotation ────────────────────────────────────────────────
 *
 * Counter-measure against Capstone L1/L2 disassembly-result caching used by
 * optimised unidbg trace engines.
 *
 * The epoch is a per-thread uint32 counter.  On every CFF loop iteration the
 * macro CPRISK_CFF_LOOP_STATE_PEEK calls:
 *   1. cprisk_cff_rotate_dispatch_epoch()   — advance the counter
 *   2. context->runtime_salt ^= cprisk_cff_epoch_mix_salt(ctx)  — blend in
 *   3. cprisk_cff_current_state_fast()      — decode with rotated salt
 *
 * Effect: `cprisk_cff_current_state_fast` computes a different dispatch key
 * each iteration, selecting a different code path through the state machine
 * (switchLoop / ifElseChain / dualRail / splitIndirect).  Because a different
 * ARM64 branch target is executed each iteration the Capstone L1 slot for the
 * dispatcher basic-block is *always* a miss — the slot maps to a different
 * address on every pass.  The L2 LRU fills with diverse entries that are each
 * used only once, driving effective cache utilisation toward zero.
 * ──────────────────────────────────────────────────────────────────────────── */

/*
 * `_Thread_local` is C11 standard and supported by clang/gcc on every target
 * we ship to (Apple platforms, Linux test hosts, CI). The previous non-Apple
 * fallback to a plain `static` variable silently broke the per-thread epoch
 * invariant under concurrent dispatcher loops on Linux test runs — two
 * threads would collide on the same counter and the Capstone cache-busting
 * property degenerated to round-robin. Use thread-local unconditionally.
 */
static _Thread_local uint32_t s_dispatch_epoch_tl = 0u;

void cprisk_cff_rotate_dispatch_epoch(void) {
    /* Weyl sequence step: additive with an odd constant so the counter visits
     * all 2^32 residues before repeating.  Fast and branch-free. */
    s_dispatch_epoch_tl += 0x9E3779B9u;
}

uint32_t cprisk_cff_epoch_mix_salt(const cprisk_cff_context_t *context) {
    if (!context) {
        return 0u;
    }
    /* One-step SplitMix64 collapsed to 32 bits.
     * Couples the epoch to the per-function seed so two functions at the same
     * iteration step produce orthogonal salt perturbations. */
    const uint32_t seed_plain = cprisk_cff_ctx_seed_plain(context);
    uint64_t z = ((uint64_t)s_dispatch_epoch_tl ^ (uint64_t)seed_plain) + 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30u)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27u)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31u);
    return (uint32_t)(z ^ (z >> 32u));
}
