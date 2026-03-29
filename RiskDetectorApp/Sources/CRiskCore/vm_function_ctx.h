#ifndef VM_FUNCTION_CTX_H
#define VM_FUNCTION_CTX_H

#include <stdint.h>
#include <stddef.h>
#include "vm_encoding.h"

/*
 * ============================================================================
 * VMP函数级VM上下文 (Function-Level VM Context)
 * ============================================================================
 *
 * 加固原理:
 * --------
 * 1. 函数级隔离: 每个受保护函数拥有完全独立的VM上下文，一个函数被攻破不影响其他函数
 * 2. 细粒度控制: 可以为不同函数选择不同的保护级别和编码方案
 * 3. 状态隔离: 函数间的执行状态完全隔离，防止信息泄露
 * 4. 动态派生: 所有密钥参数从函数ID通过WhiteBox PRF派生，无静态密钥
 *
 * 安全边界:
 * --------
 * - 每个函数的encoding_version独立选择
 * - 每个函数的opcode_xor_key独立派生
 * - 每个函数的operand_salt独立派生
 * - 每个函数的dispatch_seed独立派生
 *
 * 攻击面分析:
 * -----------
 * - 攻击者需要逐个函数分析，无法建立全局映射
 * - 函数间无法通过比较找到相似性
 * - 即使是相同源代码的函数，编码后也完全不同
 */

/* 函数上下文状态 */
typedef enum {
    VM_FUNC_CTX_UNINITIALIZED = 0,
    VM_FUNC_CTX_INITIALIZING = 1,
    VM_FUNC_CTX_READY = 2,
    VM_FUNC_CTX_EXECUTING = 3,
    VM_FUNC_CTX_SUSPENDED = 4,
    VM_FUNC_CTX_COMPLETED = 5,
    VM_FUNC_CTX_ERROR = 6
} vm_func_ctx_state_t;

/* 函数保护级别 */
typedef enum {
    VM_PROTECT_LEVEL_NONE = 0,      /* 无保护 */
    VM_PROTECT_LEVEL_BASIC = 1,     /* 基础保护 (V0编码) */
    VM_PROTECT_LEVEL_STANDARD = 2,  /* 标准保护 (V1-V2编码) */
    VM_PROTECT_LEVEL_HIGH = 3,      /* 高级保护 (V3编码) */
    VM_PROTECT_LEVEL_CRITICAL = 4   /* 关键保护 (V3 + 完整性校验) */
} vm_protect_level_t;

/* 函数元数据标志 */
#define VM_FUNC_META_HAS_LOOPS      0x01u  /* 包含循环 */
#define VM_FUNC_META_HAS_BRANCHES   0x02u  /* 包含分支 */
#define VM_FUNC_META_HAS_CALLS      0x04u  /* 包含函数调用 */
#define VM_FUNC_META_IS_RECURSIVE   0x08u  /* 递归函数 */
#define VM_FUNC_META_IS_ENTRY_POINT 0x10u  /* 入口函数 */
#define VM_FUNC_META_NEEDS_STACK_ENC 0x20u /* 需要栈加密 */
#define VM_FUNC_META_NEEDS_INTEGRITY 0x40u /* 需要完整性校验 */

/* 函数级VM上下文 */
typedef struct {
    /* 标识信息 */
    uint64_t func_id;               /* 函数唯一标识 */
    uint32_t func_hash;             /* 函数代码哈希 */

    /* 编码方案 (核心) */
    vm_encoding_ctx_t encoding;     /* 编码上下文 */
    uint32_t encoding_version;      /* 编码版本 V0-V3 */
    uint32_t opcode_xor_key;        /* 操作码异或密钥 */
    uint64_t operand_salt;          /* 操作数加密盐值 */
    uint64_t dispatch_seed;         /* 调度表随机化种子 */

    /* 执行状态 */
    vm_func_ctx_state_t state;      /* 当前状态 */
    uint64_t execution_count;       /* 执行次数统计 */
    uint32_t step_count;            /* 当前执行步数 */
    uint32_t max_steps;             /* 最大允许步数 */

    /* 保护配置 */
    vm_protect_level_t protect_level; /* 保护级别 */
    uint32_t meta_flags;            /* 元数据标志 */

    /* 栈加密参数 */
    uint64_t stack_xor_key;         /* 栈值异或密钥 */
    uint8_t  stack_rot;             /* 栈值旋转位数 */
    uint32_t stack_offset;          /* 栈偏移混淆值 */

    /* 完整性校验参数 */
    uint32_t version_seed;          /* 版本校验种子 */
    uint64_t checksum_chain;        /* 校验和链 */
    uint8_t  integrity_tag[16];     /* 完整性标签 */

    /* 运行时数据 */
    void *bytecode_cache;           /* 字节码缓存 */
    size_t bytecode_size;           /* 字节码大小 */
    uint32_t entry_point;           /* 入口点偏移 */

    /* 审计日志 */
    uint64_t last_execution_time;   /* 上次执行时间戳 */
    uint32_t anomaly_flags;         /* 异常标志 */
} vm_function_ctx_t;

/* 函数上下文池 */
#define VM_FUNC_CTX_POOL_SIZE 64
typedef struct {
    vm_function_ctx_t contexts[VM_FUNC_CTX_POOL_SIZE];
    uint32_t used_bitmap[VM_FUNC_CTX_POOL_SIZE / 32 + 1];
    uint32_t active_count;
} vm_function_ctx_pool_t;

/*
 * 初始化函数上下文
 * 为指定函数创建独立的VM上下文
 */
int vm_function_ctx_init(vm_function_ctx_t *ctx,
                         uint64_t func_id,
                         vm_protect_level_t level);

/*
 * 从函数ID派生所有密钥参数
 * 使用WhiteBox PRF确保密钥不可提取
 */
int vm_function_ctx_derive_keys(vm_function_ctx_t *ctx, uint64_t func_id);

/*
 * 根据保护级别选择编码版本
 */
vm_encoding_version_t vm_function_ctx_select_encoding(vm_protect_level_t level);

/*
 * 设置函数元数据
 */
void vm_function_ctx_set_metadata(vm_function_ctx_t *ctx,
                                   uint32_t flags,
                                   uint32_t max_steps);

/*
 * 初始化栈加密参数
 */
int vm_function_ctx_init_stack_crypto(vm_function_ctx_t *ctx);

/*
 * 初始化完整性校验参数
 */
int vm_function_ctx_init_integrity(vm_function_ctx_t *ctx);

/*
 * 进入函数执行状态
 */
int vm_function_ctx_enter(vm_function_ctx_t *ctx);

/*
 * 退出函数执行状态
 */
int vm_function_ctx_exit(vm_function_ctx_t *ctx);

/*
 * 挂起函数执行 (用于yield/中断)
 */
int vm_function_ctx_suspend(vm_function_ctx_t *ctx);

/*
 * 恢复函数执行
 */
int vm_function_ctx_resume(vm_function_ctx_t *ctx);

/*
 * 获取函数编码上下文
 */
const vm_encoding_ctx_t *vm_function_ctx_get_encoding(const vm_function_ctx_t *ctx);

/*
 * 编码函数的字节码
 * 使用函数专属的编码方案
 */
int vm_function_ctx_encode_bytecode(vm_function_ctx_t *ctx,
                                    const uint8_t *raw_bytecode,
                                    size_t raw_len,
                                    uint8_t **out_encoded,
                                    size_t *out_len);

/*
 * 解码函数的字节码
 */
int vm_function_ctx_decode_bytecode(vm_function_ctx_t *ctx,
                                    const uint8_t *encoded_bytecode,
                                    size_t encoded_len,
                                    uint32_t pc,
                                    uint32_t *opcode_out,
                                    uint64_t *operand_out);

/*
 * 更新执行计数器
 */
static inline void vm_function_ctx_inc_execution(vm_function_ctx_t *ctx) {
    if (ctx) {
        ctx->execution_count++;
        ctx->step_count++;
    }
}

/*
 * 检查执行步数限制
 */
static inline int vm_function_ctx_check_step_limit(const vm_function_ctx_t *ctx) {
    if (!ctx) return -1;
    if (ctx->step_count >= ctx->max_steps) {
        return -1; /* 超出限制 */
    }
    return 0;
}

/*
 * 记录异常
 */
static inline void vm_function_ctx_record_anomaly(vm_function_ctx_t *ctx,
                                                   uint32_t flag) {
    if (ctx) {
        ctx->anomaly_flags |= flag;
        ctx->state = VM_FUNC_CTX_ERROR;
    }
}

/*
 * 验证函数上下文完整性
 */
int vm_function_ctx_verify_integrity(const vm_function_ctx_t *ctx);

/*
 * 复制函数上下文
 */
int vm_function_ctx_copy(vm_function_ctx_t *dst, const vm_function_ctx_t *src);

/*
 * 安全清除函数上下文
 */
void vm_function_ctx_clear(vm_function_ctx_t *ctx);

/* ==================== 上下文池管理 ==================== */

/*
 * 初始化上下文池
 */
void vm_function_ctx_pool_init(vm_function_ctx_pool_t *pool);

/*
 * 从池中分配上下文
 */
vm_function_ctx_t *vm_function_ctx_pool_alloc(vm_function_ctx_pool_t *pool);

/*
 * 释放上下文回池
 */
void vm_function_ctx_pool_free(vm_function_ctx_pool_t *pool,
                               vm_function_ctx_t *ctx);

/*
 * 查找函数的上下文
 */
vm_function_ctx_t *vm_function_ctx_pool_find(vm_function_ctx_pool_t *pool,
                                              uint64_t func_id);

/*
 * 获取或创建函数上下文
 */
vm_function_ctx_t *vm_function_ctx_pool_get_or_create(vm_function_ctx_pool_t *pool,
                                                       uint64_t func_id,
                                                       vm_protect_level_t level);

/*
 * 清理池中的所有上下文
 */
void vm_function_ctx_pool_clear(vm_function_ctx_pool_t *pool);

#endif /* VM_FUNCTION_CTX_H */
