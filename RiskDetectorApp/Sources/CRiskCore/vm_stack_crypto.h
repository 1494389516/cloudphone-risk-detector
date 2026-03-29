/*
 * ============================================================================
 * VM堆栈加密保护头文件 (vm_stack_crypto.h)
 * ============================================================================
 *
 * 设计目标:
 * --------
 * 1. 透明性: VM解释器无需关心加解密细节
 * 2. 安全性: 多层混淆，抗已知明文攻击
 * 3. 性能: 轻量级操作，不影响VM执行速度
 * 4. 兼容性: 与现有VM栈设计兼容
 */

#ifndef VM_STACK_CRYPTO_H
#define VM_STACK_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 栈加密上下文结构体
 *
 * 每个受保护的VM函数拥有独立的上下文
 */
typedef struct {
    uint64_t stack_xor_key;     /* 栈异或密钥 */
    uint8_t  stack_rot;         /* 循环旋转量 (0-63) */
    uint64_t stack_offset;      /* 加法偏移量 */
    uint64_t secondary_key;     /* 次级混合密钥 */
    uint32_t access_count;      /* 访问计数 (侧信道防护) */
    uint32_t initialized;       /* 初始化标记 */
} vm_stack_crypto_ctx_t;

/* 错误码 */
typedef enum {
    VM_STACK_OK = 0,
    VM_STACK_ERROR_INVALID_PARAM = -1,
    VM_STACK_ERROR_NOT_INITIALIZED = -2,
    VM_STACK_ERROR_OVERFLOW = -3,
    VM_STACK_ERROR_UNDERFLOW = -4,
    VM_STACK_ERROR_CORRUPTED = -5
} vm_stack_error_t;

/* 初始化栈加密上下文
 *
 * 从主密钥派生所有栈加密参数
 */
int vm_stack_crypto_init(vm_stack_crypto_ctx_t *ctx,
                         uint64_t func_id,
                         const uint8_t master_key[32]);

/* 加密压栈值
 *
 * 流程: value -> XOR -> ROTL -> ADD -> XOR_SECONDARY
 */
uint64_t vm_stack_encrypt_push(const vm_stack_crypto_ctx_t *ctx, uint64_t value);

/* 解密出栈值
 *
 * 流程: encrypted -> XOR_SECONDARY -> SUB -> ROTR -> XOR
 */
uint64_t vm_stack_decrypt_pop(const vm_stack_crypto_ctx_t *ctx, uint64_t encrypted);

/* 安全压栈操作
 *
 * 自动加密并存储到栈
 */
int vm_stack_push_encrypted(vm_stack_crypto_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t *sp,
                            uint32_t stack_size,
                            uint64_t value);

/* 安全出栈操作
 *
 * 从栈读取并自动解密
 */
int vm_stack_pop_encrypted(vm_stack_crypto_ctx_t *ctx,
                           uint64_t *stack,
                           uint32_t *sp,
                           uint64_t *out_value);

/* 窥视栈顶值 (不解密) */
int vm_stack_peek_encrypted(const vm_stack_crypto_ctx_t *ctx,
                            const uint64_t *stack,
                            uint32_t sp,
                            uint64_t *out_encrypted);

/* 从中间位置读取并解密 (本地变量访问) */
int vm_stack_load_encrypted(const vm_stack_crypto_ctx_t *ctx,
                            const uint64_t *stack,
                            uint32_t index,
                            uint64_t *out_value);

/* 加密并存储到中间位置 (本地变量赋值) */
int vm_stack_store_encrypted(vm_stack_crypto_ctx_t *ctx,
                             uint64_t *stack,
                             uint32_t index,
                             uint64_t value);

/* 安全清除栈加密上下文 */
void vm_stack_crypto_clear(vm_stack_crypto_ctx_t *ctx);

/* 批量加密/解密栈区域 */
int vm_stack_encrypt_region(vm_stack_crypto_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t start,
                            uint32_t count);
int vm_stack_decrypt_region(vm_stack_crypto_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t start,
                            uint32_t count);

/* 验证栈完整性 */
int vm_stack_verify_integrity(const vm_stack_crypto_ctx_t *ctx,
                              const uint64_t *stack,
                              uint32_t sp);

/* 便捷宏 */
#define VM_STACK_PUSH(ctx, stack, sp, size, val) \
    vm_stack_push_encrypted(ctx, stack, sp, size, val)

#define VM_STACK_POP(ctx, stack, sp, out) \
    vm_stack_pop_encrypted(ctx, stack, sp, out)

#define VM_STACK_LOAD(ctx, stack, idx, out) \
    vm_stack_load_encrypted(ctx, stack, idx, out)

#define VM_STACK_STORE(ctx, stack, idx, val) \
    vm_stack_store_encrypted(ctx, stack, idx, val)

#ifdef __cplusplus
}
#endif

#endif /* VM_STACK_CRYPTO_H */
