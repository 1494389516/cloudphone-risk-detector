#ifndef CPRISK_CFF_H
#define CPRISK_CFF_H

#include <stddef.h>
#include <stdint.h>

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
#define CPRISK_CFF_MBA_LAYERS_MAX 5u
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
    uint32_t last_decoded_state;
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

uint32_t cprisk_cff_encode_state(uint32_t state, uint32_t key, uint32_t salt);
uint32_t cprisk_cff_decode_state(uint32_t encoded_state, uint32_t key, uint32_t salt);
uint32_t cprisk_cff_encode_state_with_style(uint32_t state, uint32_t key, uint32_t salt, cprisk_cff_codec_style_t style);
uint32_t cprisk_cff_decode_state_with_style(uint32_t encoded_state, uint32_t key, uint32_t salt, cprisk_cff_codec_style_t style);
uint32_t cprisk_cff_runtime_salt(uint32_t seed, uint32_t runtime_hint);

void cprisk_cff_init(cprisk_cff_context_t *context, const cprisk_cff_config_t *config);
void cprisk_cff_init_default(cprisk_cff_context_t *context, uint32_t seed, uint32_t entry_state);
uint32_t cprisk_cff_current_state(cprisk_cff_context_t *context);
/** Hot path: decode + update last_decoded_state (same semantics as current_state). */
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

/**
 * Loop PEEK: hot decode path (dispatch_style + MBA layers) without a stable
 * single-symbol hook on `cprisk_cff_current_state` — implemented in cprisk_cff.c.
 */
#define CPRISK_CFF_LOOP_STATE_PEEK(ctx) cprisk_cff_current_state_fast((ctx))

#define CPRISK_CFF_CTX_STATE_INLINE(ctx) cprisk_cff_current_state_fast((ctx))

#define CPR_CFF_BEGIN(seed, entry) \
    do { \
        cprisk_cff_context_t cpr_cff_storage_; \
        cprisk_cff_context_t *const cpr_cff_ctx = &cpr_cff_storage_; \
        cprisk_cff_init_default(cpr_cff_ctx, (uint32_t)(seed), (uint32_t)(entry)); \
        while (cpr_cff_ctx->iteration_budget > 0u) { \
            cpr_cff_ctx->iteration_budget--; \
            const uint32_t cpr_cff_state_ = CPRISK_CFF_LOOP_STATE_PEEK(cpr_cff_ctx); \
            switch (cpr_cff_state_) {

#define CPR_CFF_BEGIN_EX(config_value) \
    do { \
        cprisk_cff_context_t cpr_cff_storage_; \
        cprisk_cff_context_t *const cpr_cff_ctx = &cpr_cff_storage_; \
        cprisk_cff_config_t cpr_cff_config_ = (config_value); \
        cprisk_cff_init(cpr_cff_ctx, &cpr_cff_config_); \
        while (cpr_cff_ctx->iteration_budget > 0u) { \
            cpr_cff_ctx->iteration_budget--; \
            const uint32_t cpr_cff_state_ = CPRISK_CFF_LOOP_STATE_PEEK(cpr_cff_ctx); \
            switch (cpr_cff_state_) {

#define CPR_CFF_CASE(x) case (x)

#define CPR_CFF_GOTO(x) \
    do { \
        cprisk_cff_set_state(cpr_cff_ctx, (uint32_t)(x)); \
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
