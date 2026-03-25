/*
 * CRiskCore — MTE / EMTE sysctl 探测与保守的区域绑定 canary。
 * 不支持的设备、模拟器或未定义 CPRISK_MTE_COMPILE_SUPPORT 时安全降级。
 * 为避免在旧芯片/旧工具链上触发 SIGILL，本文件不主动发射 STG/LDG 等 MTE 内存指令；
 * canary 语义退化为“绑定区域的基线摘要 + 顶字节标签快照”。
 */

#include "include/cprisk_mte_guard.h"
#include "include/CRiskCore.h"

#include "include/cprisk_secure_zero.h"
#include "include/cprisk_sha256.h"

#include <stdint.h>
#include <string.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#define CPRISK_SYSCTL_MTE "hw.optional.arm.FEAT_MTE"
#define CPRISK_SYSCTL_MTE2 "hw.optional.arm.FEAT_MTE2"
#define CPRISK_SYSCTL_MTE4 "hw.optional.arm.FEAT_MTE4"

static uint32_t s_active_canary_count;
static uint32_t s_canary_violation_count;
static int32_t s_last_self_test_rc;

static int cprisk_mte_platform_ineligible(void) {
#if defined(__APPLE__) && defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR
    return 1;
#endif
#if !defined(__aarch64__)
    return 1;
#endif
    return 0;
}

static int cprisk_sysctl_int32_named(const char *name, int32_t *out) {
    if (!name || !out)
        return -1;
    int32_t v = 0;
    size_t len = sizeof(v);
    int err = 0;
    if (cprisk_sysctlbyname_direct(name, &v, &len, NULL, 0, &err) != 0)
        return -1;
    if (len != sizeof(int32_t))
        return -1;
    *out = v;
    return 0;
}

#if defined(__aarch64__) && defined(__APPLE__) && (!defined(TARGET_OS_SIMULATOR) || !TARGET_OS_SIMULATOR)
static uint64_t cprisk_read_id_aa64pfr1_el1(void) {
    uint64_t v = 0;
    __asm__ __volatile__("mrs %0, ID_AA64PFR1_EL1" : "=r"(v));
    return v;
}
#else
static uint64_t cprisk_read_id_aa64pfr1_el1(void) {
    return 0;
}
#endif

static unsigned cprisk_id_aa64pfr1_mte_field(uint64_t id_aa64pfr1_el1) {
    return (unsigned)((id_aa64pfr1_el1 >> 8) & 0xFu);
}

static uint8_t cprisk_pointer_tag_i(const void *ptr) {
    return (uint8_t)(((uintptr_t)ptr >> 56) & 0x0Fu);
}

static void cprisk_region_hash_i(
    const void *region,
    size_t size,
    uint8_t out_hash[CPRISK_SHA256_DIGEST_LENGTH]
) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, region, size);
    cprisk_sha256_final(&ctx, out_hash);
}

static void cprisk_record_canary_violation_i(cprisk_mte_canary_state_t *state) {
    if (state != NULL)
        state->verify_failure_count += 1u;
    s_canary_violation_count += 1u;
}

int cprisk_mte_available(void) {
#if !defined(CPRISK_MTE_COMPILE_SUPPORT)
    return 0;
#else
    if (cprisk_mte_platform_ineligible())
        return 0;
    int32_t v = 0;
    if (cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE, &v) != 0)
        return 0;
    return v != 0 ? 1 : 0;
#endif
}

int cprisk_mte2_available(void) {
#if !defined(CPRISK_MTE_COMPILE_SUPPORT)
    return 0;
#else
    if (cprisk_mte_platform_ineligible())
        return 0;
    int32_t v2 = 0;
    if (cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE2, &v2) == 0 && v2 != 0)
        return 1;
    int32_t v4 = 0;
    if (cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE4, &v4) == 0 && v4 != 0)
        return 1;
    return 0;
#endif
}

int cprisk_mte_self_test(void) {
#if !defined(CPRISK_MTE_COMPILE_SUPPORT)
    s_last_self_test_rc = 0;
    return 0;
#else
    if (cprisk_mte_platform_ineligible()) {
        s_last_self_test_rc = 0;
        return 0;
    }

    int32_t sys_mte = 0;
    const int rc_sys = cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE, &sys_mte);
    const uint64_t id = cprisk_read_id_aa64pfr1_el1();
    const unsigned mte_field = cprisk_id_aa64pfr1_mte_field(id);

    if (rc_sys != 0) {
        s_last_self_test_rc = (mte_field != 0u) ? -1 : 0;
        return s_last_self_test_rc;
    }
    if (sys_mte == 0) {
        s_last_self_test_rc = (mte_field != 0u) ? -1 : 0;
        return s_last_self_test_rc;
    }

    s_last_self_test_rc = (mte_field == 0u) ? -1 : 0;
    return s_last_self_test_rc;
#endif
}

int cprisk_mte_canary_install(
    cprisk_mte_canary_state_t *state,
    void *region,
    size_t size
) {
#if !defined(CPRISK_MTE_COMPILE_SUPPORT)
    if (state != NULL)
        memset(state, 0, sizeof(*state));
    (void)region;
    (void)size;
    return 0;
#else
    if (!state || !region || size == 0u)
        return -1;

    memset(state, 0, sizeof(*state));
    if (cprisk_mte_platform_ineligible())
        return 0;
    if (cprisk_mte_available() == 0)
        return 0;

    state->guarded_region = region;
    state->region_size = size;
    state->expected_tag = cprisk_pointer_tag_i(region);
    state->installed = 1u;
    cprisk_region_hash_i(region, size, state->baseline_hash);
    s_active_canary_count += 1u;
    return 0;
#endif
}

int cprisk_mte_canary_verify(cprisk_mte_canary_state_t *state) {
#if !defined(CPRISK_MTE_COMPILE_SUPPORT)
    (void)state;
    return 0;
#else
    if (!state || state->installed == 0u)
        return 0;
    if (cprisk_mte_available() == 0)
        return 0;
    if (!state->guarded_region || state->region_size == 0u) {
        cprisk_record_canary_violation_i(state);
        return -1;
    }

    uint8_t current_hash[CPRISK_SHA256_DIGEST_LENGTH];
    cprisk_region_hash_i(state->guarded_region, state->region_size, current_hash);

    uint8_t diff = 0u;
    for (size_t i = 0; i < sizeof(current_hash); i++)
        diff |= (uint8_t)(current_hash[i] ^ state->baseline_hash[i]);
    diff |= (uint8_t)(cprisk_pointer_tag_i(state->guarded_region) ^ state->expected_tag);
    cprisk_secure_zero(current_hash, sizeof(current_hash));

    if (diff != 0u) {
        cprisk_record_canary_violation_i(state);
        return -1;
    }
    return 0;
#endif
}

void cprisk_mte_canary_remove(cprisk_mte_canary_state_t *state) {
    if (!state)
        return;
#if defined(CPRISK_MTE_COMPILE_SUPPORT)
    if (state->installed != 0u && s_active_canary_count > 0u)
        s_active_canary_count -= 1u;
#endif
    cprisk_secure_zero(state, sizeof(*state));
}

int cprisk_mte_guard_snapshot(cprisk_mte_guard_snapshot_t *out_state) {
    if (!out_state)
        return -1;
    memset(out_state, 0, sizeof(*out_state));

    int32_t mte = 0;
    int32_t m2 = 0;
    int32_t m4 = 0;
    (void)cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE, &mte);
    (void)cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE2, &m2);
    (void)cprisk_sysctl_int32_named(CPRISK_SYSCTL_MTE4, &m4);

    out_state->sysctl_mte = (uint32_t)(mte != 0 ? 1u : 0u);
    out_state->sysctl_mte2 = (uint32_t)((m2 != 0 || m4 != 0) ? 1u : 0u);
    out_state->canary_installed = s_active_canary_count > 0u ? 1u : 0u;
    out_state->last_self_test_rc = s_last_self_test_rc;
    out_state->canary_violation_count = s_canary_violation_count;
    return 0;
}
