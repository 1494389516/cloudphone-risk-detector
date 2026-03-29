/*
 *  vm_path_explosion.h
 *  CRiskCore
 *
 *  路径爆炸对抗符号执行 - Path Explosion Countermeasure for Symbolic Execution
 *
 *  本头文件定义了路径爆炸防御的公开API和数据结构。
 *  路径爆炸是通过在VM执行路径中插入不透明谓词和假分支，
 *  使符号执行工具面临指数级路径爆炸的技术。
 */

#ifndef VM_PATH_EXPLOSION_H
#define VM_PATH_EXPLOSION_H

#include <stdint.h>
#include <stddef.h>

#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 路径爆炸配置参数 */
#define VM_PATH_EXPLOSION_LAYERS        4   /* MBA混淆层数 */
#define VM_PATH_EXPLOSION_FORK_COUNT    8   /* 每个分支点产生的路径数 */
#define VM_PATH_EXPLOSION_DECOY_DENSITY 16  /* 每16条指令插入一个诱饵 */

/*
 * 不透明谓词类型枚举
 * 每种类型基于不同的数学性质构造
 */
typedef enum {
    VM_OPAQUE_PREDICATE_ALWAYS_TRUE_1 = 0,   /* x*x >= 0 */
    VM_OPAQUE_PREDICATE_ALWAYS_TRUE_2,        /* x + x = 2x */
    VM_OPAQUE_PREDICATE_ALWAYS_FALSE_1,       /* x*x < 0 */
    VM_OPAQUE_PREDICATE_ALWAYS_FALSE_2,       /* x & (~x) != 0 */
    VM_OPAQUE_PREDICATE_FERMAT_STYLE,         /* 基于a^2 + b^2 = c^2无解(非零) */
    VM_OPAQUE_PREDICATE_WILSON_STYLE,         /* (p-1)! mod p = p-1 */
    VM_OPAQUE_PREDICATE_EULER_STYLE,          /* 欧拉准则 */
    VM_OPAQUE_PREDICATE_COLLATZ_STYLE,        /* 考拉兹猜想相关 */
} vm_opaque_predicate_type_t;

/*
 * 假分支结构体
 * 描述一个假分支的元数据
 */
typedef struct {
    uint32_t predicate_seed;        /* 谓词生成种子 */
    uint32_t branch_target_fake;    /* 假分支目标地址 */
    uint32_t branch_target_real;    /* 实际分支目标 */
    uint8_t  is_always_true;        /* 谓词是否永真 */
    uint8_t  mba_layers;            /* MBA混淆层数 */
    vm_opaque_predicate_type_t type; /* 谓词类型 */
} vm_fake_branch_t;

/*
 * MBA表达式状态
 * 用于MBA混淆的上下文
 */
typedef struct {
    uint32_t accumulator;
    uint32_t xor_mask;
    uint32_t add_mask;
    uint32_t rotate_count;
} vm_mba_state_t;

/*
 * 路径爆炸上下文
 * 管理整个路径爆炸防御的状态
 */
typedef struct {
    uint64_t func_id;
    uint32_t bytecode_hash;
    uint32_t fork_counter;
    uint32_t decoy_counter;
    vm_mba_state_t mba;
    uint8_t path_marker[32];
} vm_path_explosion_ctx_t;

/*
 * 公开API: 在指定PC位置插入不透明谓词检查点
 *
 * @param ctx 路径爆炸上下文
 * @param pc 当前程序计数器
 * @param acc VM累加器状态
 * @return 0表示应继续执行实际路径，1表示进入诱饵路径
 */
int vm_path_explosion_checkpoint(vm_path_explosion_ctx_t *ctx,
                                  uint32_t pc,
                                  uint8_t acc[32]);

/*
 * 公开API: 执行NOP装饰指令序列
 *
 * 这些指令在语义上是NOP(不改变最终计算结果)，
 * 但会执行一些中间计算，使符号执行器跟踪额外状态
 */
void vm_path_explosion_nop_decoy(vm_path_explosion_ctx_t *ctx, uint32_t pc);

/*
 * 公开API: 初始化路径爆炸上下文
 */
void vm_path_explosion_init(vm_path_explosion_ctx_t *ctx,
                             uint64_t func_id,
                             const uint8_t bytecode_hash[32]);

/*
 * 公开API: 获取当前路径指纹
 * 用于检测符号执行器的路径覆盖
 */
void vm_path_explosion_get_fingerprint(vm_path_explosion_ctx_t *ctx,
                                        uint8_t fingerprint[32]);

/*
 * 公开API: 在VM解释器循环中应用路径爆炸防护
 *
 * 此函数应在VM主循环的每个指令周期调用
 */
void vm_path_explosion_apply_to_interp(cprisk_vm_interp_frame_t *fr);

/*
 * 公开API: 触发符号爆炸
 * 当检测到可疑行为时主动增加符号执行负担
 */
void vm_path_explosion_trigger_symex_bomb(cprisk_vm_interp_frame_t *fr,
                                           uint32_t intensity);

/*
 * 快速内联不透明谓词检查 - 用于热路径
 */
static inline int vm_path_explosion_predicate_true_inline(uint32_t seed) {
    /* x*x >= 0 永真 */
    int64_t x = (int64_t)seed;
    return (x * x) >= 0;
}

/*
 * 快速内联永假谓词 - 用于热路径
 */
static inline int vm_path_explosion_predicate_false_inline(uint32_t seed) {
    /* x*x < 0 永假 */
    int64_t x = (int64_t)seed;
    return (x * x) < 0;
}

/*
 * MBA混淆内联函数 - 快速版本
 */
static inline uint32_t vm_mba_xor_inline(uint32_t a, uint32_t b) {
    /* MBA: (a|b) - (a&b) = a ^ b */
    return (a | b) - (a & b);
}

#ifdef __cplusplus
}
#endif

#endif /* VM_PATH_EXPLOSION_H */
