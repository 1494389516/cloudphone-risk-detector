#include "cprisk_cff.h"

#include "include/CRiskCore.h"

#include <pthread.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
    unsigned char bytes[sizeof(current)];
    uint64_t hash = 0xCBF29CE484222325ULL;
    size_t index = 0u;

    memcpy(bytes, &current, sizeof(current));
    for (index = 0u; index < sizeof(current); ++index) {
        hash ^= (uint64_t)bytes[index];
        hash *= 0x100000001B3ULL;
    }

    return hash;
}

static uint32_t cprisk_cff_mix_seed(uint32_t seed, uint32_t entry_state) {
    return cprisk_cff_avalanche32(seed ^ (entry_state * 0x9E3779B1u) ^ 0xA24BAED5u);
}

uint32_t cprisk_cff_encode_state(uint32_t state, uint32_t key, uint32_t salt) {
    const uint32_t mix = cprisk_cff_avalanche32(key ^ salt ^ 0x9E3779B9u);
    const uint32_t shift = (mix & 31u) | 1u;
    const uint32_t masked = state ^ mix ^ (salt * 0x45D9F3Bu);
    return cprisk_cff_rotate_left32(masked, shift) + (key * 0x27D4EB2Du);
}

uint32_t cprisk_cff_decode_state(uint32_t encoded_state, uint32_t key, uint32_t salt) {
    const uint32_t mix = cprisk_cff_avalanche32(key ^ salt ^ 0x9E3779B9u);
    const uint32_t shift = (mix & 31u) | 1u;
    const uint32_t unshifted = cprisk_cff_rotate_right32(encoded_state - (key * 0x27D4EB2Du), shift);
    return unshifted ^ mix ^ (salt * 0x45D9F3Bu);
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
        local_config.seed = 0xCFF0C0DEu;
        local_config.entry_state = 0u;
        local_config.iteration_budget = CPRISK_CFF_ITERATION_BUDGET;
        local_config.release_build = (uint8_t)CPRISK_CFF_RELEASE_BUILD;
        local_config.enable_fake_states = (uint8_t)CPRISK_CFF_ENABLE_FAKE_STATE;
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
    context->default_action = config->default_action;
    context->encoded_state = cprisk_cff_encode_state(config->entry_state, context->seed, context->runtime_salt);
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
    config.default_action = CPRISK_CFF_RELEASE_BUILD ? CPRISK_CFF_DEFAULT_POISON : CPRISK_CFF_DEFAULT_FAIL_CLOSED;
    cprisk_cff_init(context, &config);
}

uint32_t cprisk_cff_current_state(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return 0u;
    }

    context->last_decoded_state = cprisk_cff_decode_state(context->encoded_state, context->seed, context->runtime_salt);
    return context->last_decoded_state;
}

void cprisk_cff_set_state(cprisk_cff_context_t *context, uint32_t next_state) {
    if (context == NULL) {
        return;
    }

    context->last_decoded_state = next_state;
    context->encoded_state = cprisk_cff_encode_state(next_state, context->seed, context->runtime_salt);
}

void cprisk_cff_set_encoded_state(cprisk_cff_context_t *context, uint32_t encoded_state) {
    if (context == NULL) {
        return;
    }

    context->encoded_state = encoded_state;
    context->last_decoded_state = cprisk_cff_decode_state(encoded_state, context->seed, context->runtime_salt);
}

int cprisk_cff_should_visit_fake_state(const cprisk_cff_context_t *context, uint32_t decoded_state) {
    uint32_t mixed = 0u;

    if (context == NULL || context->enable_fake_states == 0u || context->release_build == 0u || context->fake_state_budget == 0u) {
        return 0;
    }

    mixed = cprisk_cff_avalanche32(
        context->encoded_state ^
        decoded_state ^
        (context->runtime_salt * 0x9E3779B1u) ^
        0x6C8E9CF5u
    );

    return (mixed % 5u) == 0u;
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
            context->encoded_state = cprisk_cff_encode_state(0xFFFF0001u, context->seed, context->runtime_salt);
            break;
        case CPRISK_CFF_DEFAULT_FAIL_CLOSED:
        default:
            context->iteration_budget = 0u;
            context->encoded_state = cprisk_cff_encode_state(0xFFFF0000u, context->seed, context->runtime_salt);
            break;
    }
}

void cprisk_cff_finalize(cprisk_cff_context_t *context) {
    if (context == NULL) {
        return;
    }

    memset(context, 0, sizeof(*context));
}
