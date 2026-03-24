#ifndef cprisk_mte_guard_h
#define cprisk_mte_guard_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cprisk_mte_canary_state {
    void *guarded_region;
    size_t region_size;
    uint8_t expected_tag;
    uint8_t installed;
    uint16_t reserved;
    uint32_t verify_failure_count;
    uint8_t baseline_hash[32];
} cprisk_mte_canary_state_t;

typedef struct cprisk_mte_guard_snapshot {
    uint32_t canary_installed;
    uint32_t sysctl_mte;
    uint32_t sysctl_mte2;
    int32_t last_self_test_rc;
    uint32_t canary_violation_count;
} cprisk_mte_guard_snapshot_t;

/// sysctl \c hw.optional.arm.FEAT_MTE 非零且编译开启 \c CPRISK_MTE_COMPILE_SUPPORT 时返回 1。
/// 模拟器、非 arm64、或 sysctl 键缺失时返回 0。
int cprisk_mte_available(void);

/// \c hw.optional.arm.FEAT_MTE2 或 \c hw.optional.arm.FEAT_MTE4（Apple EMTE 系）之一可用时返回 1。
int cprisk_mte2_available(void);

/// sysctl 与 \c ID_AA64PFR1_EL1.MTE 字段一致性自检。无 MTE 或未编译支持时返回 0。
/// 不一致或探测失败时返回 -1；实现不会主动发射 STG/LDG 等内存标记指令。
int cprisk_mte_self_test(void);

/// 将 canary 绑定到受保护内存区域。当前实现采用“区域基线摘要 + 顶字节标签快照”的保守方案：
/// 在具备 MTE 能力时记录区域 SHA-256 基线，并在复检时比较，避免在旧芯片/旧工具链上触发 SIGILL。
/// 不支持 MTE 时安全降级为 no-op（返回 0）。
int cprisk_mte_canary_install(
    cprisk_mte_canary_state_t *state,
    void *region,
    size_t size
);

/// canary 未安装返回 0；基线一致返回 0；否则返回 -1，并递增失败计数。
int cprisk_mte_canary_verify(cprisk_mte_canary_state_t *state);

void cprisk_mte_canary_remove(cprisk_mte_canary_state_t *state);

/// 诊断用：填充当前 MTE / canary 状态（指针可为 NULL 时返回 -1）。
int cprisk_mte_guard_snapshot(cprisk_mte_guard_snapshot_t *out_state);

#ifdef __cplusplus
}
#endif

#endif /* cprisk_mte_guard_h */
