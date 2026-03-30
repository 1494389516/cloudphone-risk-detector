#ifndef CPRISK_CFF_H
#define CPRISK_CFF_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SOURCE_LEVEL_CFF
#define SOURCE_LEVEL_CFF 1
#endif

#ifndef IR_LEVEL_CFF
#define IR_LEVEL_CFF 0
#endif

#if defined(NDEBUG)
#define CPRISK_CFF_RELEASE_BUILD 1
#else
#define CPRISK_CFF_RELEASE_BUILD 0
#endif

#ifndef CPRISK_CFF_ENABLE_FAKE_STATE
#define CPRISK_CFF_ENABLE_FAKE_STATE CPRISK_CFF_RELEASE_BUILD
#endif

#ifndef CPRISK_CFF_ITERATION_BUDGET
#define CPRISK_CFF_ITERATION_BUDGET 1024u
#endif

#ifndef CPRISK_CFF_MBA_LAYERS_MIN
#define CPRISK_CFF_MBA_LAYERS_MIN 2u
#endif

#ifndef CPRISK_CFF_MBA_LAYERS_MAX
#define CPRISK_CFF_MBA_LAYERS_MAX 8u
#endif

#ifndef CPRISK_CFF_MBA_LAYERS_HEAVY_MIN
#define CPRISK_CFF_MBA_LAYERS_HEAVY_MIN 6u
#endif

#ifndef CPRISK_CFF_MBA_LAYERS_HEAVY_MAX
#define CPRISK_CFF_MBA_LAYERS_HEAVY_MAX 8u
#endif

/**
 * Canonical Feistel SPN substitution seed — must match:
 * - CloudPhoneRiskKit `CFFSBoxMaterial.canonicalSeed`
 * - cprisk-armor `CFFSBoxPermutation256.generate(seed:)` (SplitMix64 + Fisher–Yates)
 * Mix: FNV-1a("cprisk-armor/CFFSBoxPermutation256/v1") ^ 0xA37C19E45B62D08F (registry root).
 */
#ifndef CPRISK_CFF_SPN_CANONICAL_SEED_U64
#define CPRISK_CFF_SPN_CANONICAL_SEED_U64 0x6AFD56260D3F7F05ull
#endif

typedef enum cprisk_cff_default_action {
    CPRISK_CFF_DEFAULT_FAIL_CLOSED = 0,
    CPRISK_CFF_DEFAULT_POISON = 1,
    CPRISK_CFF_DEFAULT_TRAP = 2,
} cprisk_cff_default_action_t;

typedef enum cprisk_cff_codec_style {
    CPRISK_CFF_CODEC_STYLE_AUTO = 0,
    CPRISK_CFF_CODEC_STYLE_XOR_ROTATE = 1,
    CPRISK_CFF_CODEC_STYLE_ADD_ROTATE_XOR = 2,
    CPRISK_CFF_CODEC_STYLE_AFFINE = 3,
    /**
     * Feistel + byte S-box (SPN-like round function): lookup-heavy, non-linear,
     * not a pure GF(2) XOR chain — materially harder for GAMBA/algebraic MBA
     * simplifiers than layered XOR-MBA identities on the same semantic XOR.
     */
    CPRISK_CFF_CODEC_STYLE_FEISTEL_SPN = 4,
} cprisk_cff_codec_style_t;

typedef enum cprisk_cff_dispatch_style {
    CPRISK_CFF_DISPATCH_AUTO = 0,
    CPRISK_CFF_DISPATCH_DIRECT = 1,
    CPRISK_CFF_DISPATCH_FN_TABLE = 2,
    CPRISK_CFF_DISPATCH_COMPUTED_GOTO = 3,
} cprisk_cff_dispatch_style_t;

typedef struct cprisk_cff_config {
    uint32_t seed;
    uint32_t runtime_salt;
    uint32_t entry_state;
    uint32_t iteration_budget;
    uint8_t release_build;
    uint8_t enable_fake_states;
    uint8_t codec_style;
    uint8_t dispatch_style;
    uint8_t mba_layers;
    uint8_t symex_guard_budget;
    uint8_t reserved1;
    cprisk_cff_default_action_t default_action;
} cprisk_cff_config_t;

typedef struct cprisk_cff_context {
    uint32_t seed;
    uint32_t runtime_salt;
    uint32_t encoded_state;
    uint32_t state_share_a;
    uint32_t state_share_b;
    uint32_t storage_nonce;
    uint32_t chain_snapshot;
    uint32_t entry_guard;
    uint32_t iteration_budget;
    uint8_t release_build;
    uint8_t enable_fake_states;
    uint8_t fake_state_budget;
    uint8_t codec_style;
    uint8_t dispatch_style;
    uint8_t mba_layers;
    uint8_t symex_guard_budget;
    uint8_t reserved1;
    cprisk_cff_default_action_t default_action;
} cprisk_cff_context_t;

uint32_t cprisk_cff_get_chain_link(void);

/**
 * Inlined opaque transition gate (MBA + runtime-tied mixing). Duplicated at macro call sites so a
 * single hook on a standalone C symbol cannot bypass the guard without patching each expansion.
 */
static inline uint32_t cprisk_cff_hdr_avalanche32(uint32_t value) {
    uint32_t mixed = value;
    mixed ^= mixed >> 16u;
    mixed *= 0x7FEB352Du;
    mixed ^= mixed >> 15u;
    mixed *= 0x846CA68Bu;
    mixed ^= mixed >> 16u;
    return mixed;
}

static inline uint32_t cprisk_cff_hdr_rotate_left32(uint32_t value, uint32_t shift);
static inline uint32_t cprisk_cff_hdr_const32(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base);
static inline uint32_t cprisk_cff_hdr_const32_odd(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base);

uint64_t cprisk_cff_runtime_spn_sbox_seed(void);

static inline uint32_t cprisk_cff_hdr_build_seed32_i(void) {
    uint64_t seed64 = cprisk_cff_runtime_spn_sbox_seed();
    if (seed64 == 0u) {
        seed64 = CPRISK_CFF_SPN_CANONICAL_SEED_U64;
    }
    return cprisk_cff_hdr_avalanche32(
        (uint32_t)seed64 ^
        ((uint32_t)(seed64 >> 32u) << 3) ^
        0x48445242u
    );
}

static inline uint32_t cprisk_cff_hdr_base_derive(uint64_t base_domain, uint32_t canonical_base) {
    const uint32_t bs = cprisk_cff_hdr_build_seed32_i();
    return cprisk_cff_hdr_const32(base_domain, bs, bs ^ canonical_base, canonical_base);
}

static inline uint32_t cprisk_cff_ctx_storage_mask(const cprisk_cff_context_t *ctx) {
    const uintptr_t p = (uintptr_t)ctx;
    const uint32_t ptr_mix = (uint32_t)p ^ (uint32_t)(p >> 32);
    return cprisk_cff_hdr_avalanche32(
        ptr_mix ^ cprisk_cff_hdr_const32(
            0x4346465F43545831ull,
            ptr_mix,
            (uint32_t)sizeof(*ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415331ull, 0xC0FFEE42u)
        )
    );
}

static inline uint32_t cprisk_cff_ctx_nonce_plain(const cprisk_cff_context_t *ctx) {
    return ctx->storage_nonce ^ cprisk_cff_ctx_storage_mask(ctx);
}

static inline uint32_t cprisk_cff_ctx_mask_ptr(const cprisk_cff_context_t *ctx) {
    return cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545832ull,
            cprisk_cff_ctx_storage_mask(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415332ull, 0x71E58D4Bu)
        )
    );
}

static inline uint32_t cprisk_cff_ctx_mask_salt(const cprisk_cff_context_t *ctx) {
    return cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545833ull,
            cprisk_cff_ctx_storage_mask(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415333ull, 0x0ACC0DECu)
        )
    );
}

static inline uint32_t cprisk_cff_ctx_mask_enc(const cprisk_cff_context_t *ctx) {
    return cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545834ull,
            cprisk_cff_ctx_storage_mask(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415334ull, 0x5EEDB0E5u)
        )
    );
}

static inline uint32_t cprisk_cff_ctx_seed_plain(const cprisk_cff_context_t *ctx) {
    return ctx->seed ^ cprisk_cff_ctx_mask_ptr(ctx);
}

static inline uint32_t cprisk_cff_ctx_salt_plain(const cprisk_cff_context_t *ctx) {
    return ctx->runtime_salt ^ cprisk_cff_ctx_mask_salt(ctx);
}

static inline uint32_t cprisk_cff_ctx_encoded_plain(const cprisk_cff_context_t *ctx) {
    return ctx->encoded_state ^ cprisk_cff_ctx_mask_enc(ctx);
}

static inline uint32_t cprisk_cff_ctx_last_plain(const cprisk_cff_context_t *ctx) {
    const uint32_t split_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_mask_enc(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545835ull,
            cprisk_cff_ctx_mask_enc(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415335ull, 0x5F3759DFu)
        )
    );
    return ctx->state_share_a ^ ctx->state_share_b ^ split_mask;
}

static inline uint32_t cprisk_cff_ctx_chain_plain(const cprisk_cff_context_t *ctx) {
    const uint32_t chain_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545836ull,
            cprisk_cff_ctx_storage_mask(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415336ull, 0xC11A1E5Eu)
        )
    );
    return ctx->chain_snapshot ^ chain_mask;
}

static inline uint32_t cprisk_cff_ctx_entry_guard_plain(const cprisk_cff_context_t *ctx) {
    const uint32_t guard_mask = cprisk_cff_hdr_avalanche32(
        cprisk_cff_ctx_storage_mask(ctx) ^ cprisk_cff_ctx_nonce_plain(ctx) ^ cprisk_cff_hdr_const32(
            0x4346465F43545837ull,
            cprisk_cff_ctx_storage_mask(ctx),
            cprisk_cff_ctx_nonce_plain(ctx),
            cprisk_cff_hdr_base_derive(0x4346465F42415337ull, 0xE17A9A5Bu)
        )
    );
    return ctx->entry_guard ^ guard_mask;
}

static inline uint32_t cprisk_cff_chain_entry_guard_expected_inline(
    const cprisk_cff_context_t *ctx,
    uint32_t observed_chain
) {
    return cprisk_cff_hdr_avalanche32(
        observed_chain ^
        cprisk_cff_ctx_seed_plain(ctx) ^
        cprisk_cff_ctx_salt_plain(ctx) ^
        cprisk_cff_ctx_nonce_plain(ctx) ^
        cprisk_cff_ctx_last_plain(ctx) ^
        cprisk_cff_hdr_const32(
            0x4346465F43545838ull,
            cprisk_cff_ctx_seed_plain(ctx),
            cprisk_cff_ctx_salt_plain(ctx) ^ observed_chain,
            cprisk_cff_hdr_base_derive(0x4346465F42415338ull, 0xC4A11E5Du)
        )
    );
}

static inline int cprisk_cff_chain_snapshot_verify_inline(
    const cprisk_cff_context_t *ctx,
    uint32_t observed_chain
) {
    if (ctx == NULL) {
        return 0;
    }
    return observed_chain == cprisk_cff_ctx_chain_plain(ctx) ? 1 : 0;
}

static inline int cprisk_cff_entry_guard_verify_inline(
    const cprisk_cff_context_t *ctx,
    uint32_t observed_chain
) {
    if (ctx == NULL) {
        return 0;
    }
    return cprisk_cff_chain_entry_guard_expected_inline(ctx, observed_chain) ==
            cprisk_cff_ctx_entry_guard_plain(ctx)
        ? 1
        : 0;
}

static inline int cprisk_cff_chain_entry_verify_inline(
    const cprisk_cff_context_t *ctx,
    uint32_t observed_chain
) {
    return cprisk_cff_chain_snapshot_verify_inline(ctx, observed_chain) != 0 &&
            cprisk_cff_entry_guard_verify_inline(ctx, observed_chain) != 0
        ? 1
        : 0;
}

static inline uint32_t cprisk_cff_hdr_rotate_left32(uint32_t value, uint32_t shift) {
    const uint32_t amount = shift & 31u;
    if (amount == 0u) {
        return value;
    }
    return (value << amount) | (value >> (32u - amount));
}

static inline uint32_t cprisk_cff_hdr_const32(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base) {
    const uint32_t lo = (uint32_t)(domain & 0xFFFFFFFFu);
    const uint32_t hi = (uint32_t)(domain >> 32u);
    const uint32_t spin = ((seed ^ hi ^ (salt >> 1u)) & 31u) | 1u;
    const uint32_t lane = cprisk_cff_hdr_rotate_left32(seed ^ base ^ lo, spin);
    const uint32_t mixed0 = cprisk_cff_hdr_avalanche32(seed ^ salt ^ lo ^ base);
    const uint32_t mixed1 = cprisk_cff_hdr_avalanche32(lane ^ salt ^ hi ^ (base * (seed | 1u)));
    return cprisk_cff_hdr_avalanche32(mixed0 ^ mixed1 ^ lo ^ hi) ^ base;
}

static inline uint32_t cprisk_cff_hdr_const32_odd(uint64_t domain, uint32_t seed, uint32_t salt, uint32_t base) {
    return cprisk_cff_hdr_const32(domain, seed, salt, base) | 1u;
}

static inline uint32_t cprisk_cff_opq_inline_xor_mba_u32(uint32_t a, uint32_t b) {
    return (a | b) - (a & b);
}

static inline uint32_t cprisk_cff_opq_inline_xor_mba_layer_u32(uint32_t x, uint32_t k, uint32_t layer_ix) {
    const uint32_t selector_mix = cprisk_cff_hdr_const32(
        0x4346465F48445231ull,
        k,
        layer_ix,
        cprisk_cff_hdr_base_derive(0x4346465F42415339ull, 0x13579BDFu)
    );
    const uint32_t sel =
        (layer_ix + cprisk_cff_hdr_avalanche32(k ^ selector_mix) + (k >> 17u)) & 3u;
    switch (sel) {
        case 0u:
            return cprisk_cff_opq_inline_xor_mba_u32(x, k);
        case 1u:
            return (x & ~k) | (~x & k);
        case 2u:
            return x + k - (2u * (x & k));
        default:
            return x ^ k;
    }
}

static inline uint32_t cprisk_cff_opq_inline_mba_chain_xor_u32(uint32_t v, uint32_t key, uint32_t salt) {
    uint32_t cur = v;
    for (uint32_t i = 0u; i < 3u; i++) {
        const uint32_t step_mul = cprisk_cff_hdr_const32_odd(
            0x4346465F48445232ull,
            key,
            salt,
            cprisk_cff_hdr_base_derive(0x4346465F42415341ull, 0x9E3779B1u)
        );
        const uint32_t step_xor = cprisk_cff_hdr_const32(
            0x4346465F48445233ull,
            key ^ i,
            salt,
            cprisk_cff_hdr_base_derive(0x4346465F42415342ull, 0xD1B54A35u)
        );
        const uint32_t ki =
            cprisk_cff_hdr_avalanche32(key ^ salt ^ (i * step_mul) ^ step_xor);
        cur = cprisk_cff_opq_inline_xor_mba_layer_u32(cur, ki, i);
    }
    return cur;
}

static inline int cprisk_cff_opaque_transition_ok_inline(
    uint32_t from_decoded,
    uint32_t to_plain,
    uint32_t seed,
    uint32_t salt
) {
    struct timespec ts;
    uint32_t rt = 0u;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        rt = (uint32_t)ts.tv_nsec ^ ((uint32_t)ts.tv_sec * cprisk_cff_hdr_const32_odd(
            0x4346465F48445234ull,
            seed,
            salt,
            cprisk_cff_hdr_base_derive(0x4346465F42415343ull, 0x9E3779B1u)
        ));
    }
    const uint32_t pid_mix = (uint32_t)getpid();
    const uint32_t a = to_plain ^ salt ^ (rt & 0xFFFFu);
    const uint32_t b = seed ^ from_decoded ^ cprisk_cff_hdr_rotate_left32(pid_mix, 3u);
    const uint32_t x = a ^ b;
    if (cprisk_cff_opq_inline_xor_mba_u32(a, b) != x) {
        return 0;
    }
    if ((((a & ~b) | (~a & b)) != x)) {
        return 0;
    }
    if (cprisk_cff_hdr_avalanche32(x ^ rt) !=
        cprisk_cff_hdr_avalanche32(cprisk_cff_opq_inline_xor_mba_u32(a, b) ^ rt)) {
        return 0;
    }
    {
        const uint32_t chain = cprisk_cff_opq_inline_mba_chain_xor_u32(a, seed, salt);
        uint32_t manual = a;
        for (uint32_t layer = 0u; layer < 3u; layer++) {
            const uint32_t step_mul = cprisk_cff_hdr_const32_odd(
                0x4346465F48445232ull,
                seed,
                salt,
                cprisk_cff_hdr_base_derive(0x4346465F42415341ull, 0x9E3779B1u)
            );
            const uint32_t step_xor = cprisk_cff_hdr_const32(
                0x4346465F48445233ull,
                seed ^ layer,
                salt,
                cprisk_cff_hdr_base_derive(0x4346465F42415342ull, 0xD1B54A35u)
            );
            const uint32_t ki =
                cprisk_cff_hdr_avalanche32(seed ^ salt ^ (layer * step_mul) ^ step_xor);
            manual = cprisk_cff_opq_inline_xor_mba_layer_u32(manual, ki, layer);
        }
        if (chain != manual) {
            return 0;
        }
    }
    const uint32_t h = cprisk_cff_hdr_avalanche32(
        seed ^ cprisk_cff_hdr_rotate_left32(to_plain, 5u) ^ cprisk_cff_hdr_const32(
            0x4346465F48445235ull,
            seed,
            salt ^ to_plain,
            cprisk_cff_hdr_base_derive(0x4346465F42415344ull, 0xABADD00Du)
        ) ^ (rt >> 3u)
    );
    const uint32_t p = 65521u;
    const uint64_t r =
        ((uint64_t)h + (uint64_t)pid_mix) * (uint64_t)(from_decoded ^ cprisk_cff_hdr_const32(
            0x4346465F48445236ull,
            seed,
            salt ^ rt,
            cprisk_cff_hdr_base_derive(0x4346465F42415345ull, 0x13579BDFu)
        ) ^ rt) % (uint64_t)p;
    const uint64_t sq = (r * r) % (uint64_t)p;
    const uint64_t sq_chk = ((uint64_t)r * (uint64_t)r) % (uint64_t)p;
    return sq == sq_chk ? 1 : 0;
}

uint32_t cprisk_cff_encode_state(uint32_t state, uint32_t key, uint32_t salt);
uint32_t cprisk_cff_decode_state(uint32_t encoded_state, uint32_t key, uint32_t salt);
uint32_t cprisk_cff_encode_state_with_style(uint32_t state, uint32_t key, uint32_t salt, cprisk_cff_codec_style_t style);
uint32_t cprisk_cff_decode_state_with_style(uint32_t encoded_state, uint32_t key, uint32_t salt, cprisk_cff_codec_style_t style);
uint32_t cprisk_cff_runtime_salt(uint32_t seed, uint32_t runtime_hint);

void cprisk_cff_init(cprisk_cff_context_t *context, const cprisk_cff_config_t *config);
void cprisk_cff_init_default(cprisk_cff_context_t *context, uint32_t seed, uint32_t entry_state);
uint32_t cprisk_cff_current_state(cprisk_cff_context_t *context);
/**
 * CFF loop PEEK hot path: returns the last decoded plain state without running
 * full codec/MBA decode. Kept in sync by cprisk_cff_set_state / set_encoded /
 * init / poison; use cprisk_cff_current_state() when a fresh decode is required.
 */
uint32_t cprisk_cff_current_state_fast(cprisk_cff_context_t *context);
uint32_t cprisk_cff_current_state_dispatch(cprisk_cff_context_t *context);
/** Alternate decode path: function-pointer dispatch by codec style (not the only gate). */
uint32_t cprisk_cff_current_state_table(cprisk_cff_context_t *context);
void cprisk_cff_set_state(cprisk_cff_context_t *context, uint32_t next_state);
void cprisk_cff_set_encoded_state(cprisk_cff_context_t *context, uint32_t encoded_state);
int cprisk_cff_should_visit_fake_state(const cprisk_cff_context_t *context, uint32_t decoded_state);
void cprisk_cff_arm_symbolic_explosion(cprisk_cff_context_t *context, uint8_t budget);
void cprisk_cff_trigger_symbolic_explosion(cprisk_cff_context_t *context, uint32_t risk_mask);
void cprisk_cff_poison_default(cprisk_cff_context_t *context);
void cprisk_cff_finalize(cprisk_cff_context_t *context);
int cprisk_cff_chain_entry_verify(const cprisk_cff_context_t *context);

/** Apply a verified transition (encoded state + VM link token). Caller must have passed opaque gates. */
void cprisk_cff_state_transition_commit(cprisk_cff_context_t *context, uint32_t next_state);

/** Opaque 32-bit token for cross-layer mixing (VM session_mix / dispatch cache); not a policy oracle. */
uint32_t cprisk_cff_get_vm_link_token(void);

/** Cross-function chain link (atomic); complements TLS mix for propagation between CFF regions. */
uint32_t cprisk_cff_get_chain_link(void);

void cprisk_cff_chain_begin(void);

/**
 * Build-time / runtime: install 256-byte Feistel SPN forward S-box (bijection). Matches
 * `CFFSBoxPermutation256.generate(seed:)` in cprisk-armor / CloudPhoneRiskKit.
 */
void cprisk_cff_spn_sbox_install_from_seed(uint64_t seed);

/** Optional: install precomputed forward table (must be a permutation of 0..255). */
void cprisk_cff_spn_sbox_install_from_bytes(const uint8_t forward256[256]);
uint64_t cprisk_cff_runtime_spn_sbox_seed(void);
int cprisk_cff_spn_sbox_copy_forward(uint8_t out_forward256[256]);

/** Fake-state decoy work unit: non-semantic avalanche + env mix (watchdog ghost lane). */
void cprisk_cff_run_fake_path_decoy(const cprisk_cff_context_t *context);

/**
 * Loop PEEK: hot decode path (dispatch_style + MBA layers) without a stable
 * single-symbol hook on `cprisk_cff_current_state` — implemented in cprisk_cff.c.
 */
#define CPRISK_CFF_LOOP_STATE_PEEK(ctx) cprisk_cff_current_state_fast((ctx))

#define CPRISK_CFF_CTX_STATE_INLINE(ctx) cprisk_cff_current_state_fast((ctx))

#define CPR_CFF_BEGIN(seed, entry) \
    do { \
        cprisk_cff_chain_begin(); \
        cprisk_cff_context_t cpr_cff_storage_; \
        cprisk_cff_context_t *const cpr_cff_ctx = &cpr_cff_storage_; \
        cprisk_cff_init_default(cpr_cff_ctx, (uint32_t)(seed), (uint32_t)(entry)); \
        { \
            const uint32_t cpr_cff_chain_observed_ = cprisk_cff_get_chain_link(); \
            if (cprisk_cff_chain_entry_verify_inline(cpr_cff_ctx, cpr_cff_chain_observed_) == 0) { \
                cprisk_cff_poison_default(cpr_cff_ctx); \
            } \
        } \
        if (cprisk_cff_chain_snapshot_verify_inline(cpr_cff_ctx, cprisk_cff_get_chain_link()) == 0) { \
            cprisk_cff_poison_default(cpr_cff_ctx); \
        } \
        while (cpr_cff_ctx->iteration_budget > 0u) { \
            cpr_cff_ctx->iteration_budget--; \
            const uint32_t cpr_cff_state_ = CPRISK_CFF_LOOP_STATE_PEEK(cpr_cff_ctx); \
            switch (cpr_cff_state_) {

#define CPR_CFF_BEGIN_EX(config_value) \
    do { \
        cprisk_cff_chain_begin(); \
        cprisk_cff_context_t cpr_cff_storage_; \
        cprisk_cff_context_t *const cpr_cff_ctx = &cpr_cff_storage_; \
        cprisk_cff_config_t cpr_cff_config_ = (config_value); \
        cprisk_cff_init(cpr_cff_ctx, &cpr_cff_config_); \
        { \
            const uint32_t cpr_cff_chain_observed_ = cprisk_cff_get_chain_link(); \
            if (cprisk_cff_chain_entry_verify_inline(cpr_cff_ctx, cpr_cff_chain_observed_) == 0) { \
                cprisk_cff_poison_default(cpr_cff_ctx); \
            } \
        } \
        if (cprisk_cff_chain_snapshot_verify_inline(cpr_cff_ctx, cprisk_cff_get_chain_link()) == 0) { \
            cprisk_cff_poison_default(cpr_cff_ctx); \
        } \
        while (cpr_cff_ctx->iteration_budget > 0u) { \
            cpr_cff_ctx->iteration_budget--; \
            const uint32_t cpr_cff_state_ = CPRISK_CFF_LOOP_STATE_PEEK(cpr_cff_ctx); \
            switch (cpr_cff_state_) {

#define CPR_CFF_CASE(x) case (x)

#define CPR_CFF_GOTO(x) \
    do { \
        if (cprisk_cff_chain_snapshot_verify_inline((cpr_cff_ctx), cprisk_cff_get_chain_link()) == 0) { \
            cprisk_cff_poison_default(cpr_cff_ctx); \
            continue; \
        } \
        if (cprisk_cff_opaque_transition_ok_inline( \
                cprisk_cff_ctx_last_plain((cpr_cff_ctx)), \
                (uint32_t)(x), \
                cprisk_cff_ctx_seed_plain((cpr_cff_ctx)), \
                cprisk_cff_ctx_salt_plain((cpr_cff_ctx))) == 0) { \
            cprisk_cff_poison_default(cpr_cff_ctx); \
            continue; \
        } \
        cprisk_cff_state_transition_commit(cpr_cff_ctx, (uint32_t)(x)); \
        continue; \
    } while (0)

#define CPR_CFF_RETURN(x) \
    do { \
        cprisk_cff_finalize(cpr_cff_ctx); \
        return (x); \
    } while (0)

#define CPR_CFF_RETURN_VOID() \
    do { \
        cprisk_cff_finalize(cpr_cff_ctx); \
        return; \
    } while (0)

#define CPR_CFF_POISON_DEFAULT() \
    do { \
        cprisk_cff_poison_default(cpr_cff_ctx); \
        continue; \
    } while (0)

#define CPR_CFF_END() \
                default: { \
                    CPR_CFF_POISON_DEFAULT(); \
                } \
            } \
        } \
        cprisk_cff_poison_default(cpr_cff_ctx); \
        cprisk_cff_finalize(cpr_cff_ctx); \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* CPRISK_CFF_H */
