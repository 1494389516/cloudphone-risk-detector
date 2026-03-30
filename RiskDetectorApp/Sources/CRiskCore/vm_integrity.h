/*
 * ============================================================================
 * VM状态完整性校验头文件 (vm_integrity.h)
 * ============================================================================
 *
 * 设计目标:
 * --------
 * 1. 轻量级: 校验操作不应显著影响VM执行性能
 * 2. 无依赖: 不依赖外部库，便于集成到CRiskCore
 * 3. 可恢复: 支持状态保存和恢复，用于异常处理
 * 4. 隐式毒化: 检测到篡改时静默污染，不暴露检测逻辑
 */

#ifndef VM_INTEGRITY_H
#define VM_INTEGRITY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 完整性状态结构体
 *
 * 字段说明:
 * - magic: 状态有效性标记
 * - version_seed: 版本兼容性校验
 * - execution_count: 执行指令计数 (单调递增)
 * - checksum_chain: 累积校验链 (FNV-1a变体)
 * - integrity_tag: 完整性标签 (8字节简化HMAC)
 */
typedef struct {
    uint32_t magic;              /* 状态魔数 */
    uint32_t version_seed;       /* 版本种子 */
    uint64_t execution_count;    /* 执行计数 */
    uint64_t checksum_chain;     /* 校验链 */
    uint8_t  integrity_tag[8];   /* 完整性标签 */
} vm_integrity_state_t;

/* 完整性检查结果 */
typedef enum {
    VM_INT_RESULT_OK = 0,                /* 状态正常 */
    VM_INT_RESULT_CORRUPTED = 1,         /* 状态已损坏 */
    VM_INT_RESULT_INVALID = 2,           /* 无效状态 */
    VM_INT_RESULT_VERSION_MISMATCH = 3,  /* 版本不匹配 */
    VM_INT_RESULT_OVERFLOW = 4,          /* 执行计数溢出 */
    VM_INT_RESULT_CHAIN_BROKEN = 5,      /* 校验链断裂 */
    VM_INT_RESULT_TAG_INVALID = 6,       /* 标签无效 */
    VM_INT_RESULT_ERROR = 7              /* 其他错误 */
} vm_integrity_result_t;

/* 错误码 */
typedef enum {
    VM_INT_OK = 0,
    VM_INT_ERROR_INVALID_PARAM = -1,
    VM_INT_ERROR_CORRUPTED = -2,
    VM_INT_ERROR_STEP_MISMATCH = -3,
    VM_INT_ERROR_CHAIN_UNCHANGED = -4
} vm_integrity_error_t;

/* 完整性事件类型 (用于更新校验链) */
typedef enum {
    VM_INT_EVENT_INIT = 0,       /* 初始化 */
    VM_INT_EVENT_FETCH = 1,      /* 取指 */
    VM_INT_EVENT_DECODE = 2,     /* 解码 */
    VM_INT_EVENT_EXECUTE = 3,    /* 执行 */
    VM_INT_EVENT_MEMORY_READ = 4,  /* 内存读 */
    VM_INT_EVENT_MEMORY_WRITE = 5, /* 内存写 */
    VM_INT_EVENT_BRANCH = 6,     /* 分支跳转 */
    VM_INT_EVENT_CALL = 7,       /* 函数调用 */
    VM_INT_EVENT_RET = 8,        /* 函数返回 */
    VM_INT_EVENT_EXCEPTION = 9   /* 异常 */
} vm_integrity_event_t;

/* 完整性违规类型 (用于毒化处理) */
typedef enum {
    VM_INT_VIOLATION_NONE = 0,
    VM_INT_VIOLATION_MAGIC_CHANGED = 1,    /* Magic值被修改 */
    VM_INT_VIOLATION_COUNT_ROLLBACK = 2,   /* 执行计数回滚 */
    VM_INT_VIOLATION_CHAIN_TAMPER = 3,     /* 校验链篡改 */
    VM_INT_VIOLATION_TAG_MISMATCH = 4,     /* 标签不匹配 */
    VM_INT_VIOLATION_UNKNOWN = 5           /* 未知违规 */
} vm_integrity_violation_t;

/* 初始化VM完整性状态 */
int vm_integrity_init(vm_integrity_state_t *state, uint64_t vm_id);

/* 执行校验点检查
 *
 * 应在关键位置调用:
 * - 每条指令执行后
 * - 函数调用/返回时
 * - 内存访问前后
 */
vm_integrity_result_t vm_integrity_check(const vm_integrity_state_t *state);

/* 更新完整性状态
 *
 * 在执行操作后调用，更新校验链
 */
int vm_integrity_update(vm_integrity_state_t *state,
                        vm_integrity_event_t event,
                        uint64_t event_data);

/* 处理完整性破坏事件
 *
 * 毒化策略: 静默标记状态为损坏，不暴露检测
 */
void vm_integrity_handle_tamper(vm_integrity_state_t *state,
                                vm_integrity_violation_t violation);

/* 验证特定操作序列的完整性 */
int vm_integrity_verify_sequence(const vm_integrity_state_t *state_before,
                                  const vm_integrity_state_t *state_after,
                                  uint32_t expected_step_count);

/* 导出/导入完整性状态 */
size_t vm_integrity_export(const vm_integrity_state_t *state,
                           uint8_t *out_buffer,
                           size_t buffer_size);
int vm_integrity_import(vm_integrity_state_t *state,
                        const uint8_t *data,
                        size_t data_size);

/* 安全清除完整性状态 */
void vm_integrity_clear(vm_integrity_state_t *state);

/* VM_CHECKPOINT宏 - 便捷的校验点调用
 *
 * 使用示例:
 *   VM_CHECKPOINT(&state, VM_INT_EVENT_EXECUTE, pc);
 */
#define VM_CHECKPOINT(state, event, data) do { \
    vm_integrity_result_t _r = vm_integrity_check(state); \
    if (_r != VM_INT_RESULT_OK) { \
        vm_integrity_handle_tamper(state, VM_INT_VIOLATION_UNKNOWN); \
    } else { \
        vm_integrity_update(state, event, data); \
    } \
} while(0)

/* VM_GUARD宏 - 带毒化的校验点
 *
 * 如果检查失败，执行毒化代码而非返回错误
 */
#define VM_GUARD(state, poison_code) do { \
    if (vm_integrity_check(state) != VM_INT_RESULT_OK) { \
        vm_integrity_handle_tamper(state, VM_INT_VIOLATION_UNKNOWN); \
        poison_code; \
    } \
} while(0)

#ifdef __cplusplus
}
#endif

#endif /* VM_INTEGRITY_H */
