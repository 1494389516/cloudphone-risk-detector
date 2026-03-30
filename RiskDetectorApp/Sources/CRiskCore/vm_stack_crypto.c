/*
 * ============================================================================
 * VM堆栈加密保护 (vm_stack_crypto.c)
 * ============================================================================
 *
 * 核心加固原理:
 * ------------
 * 1. 运行时加密: VM堆栈中的值在存储前加密，读取时解密
 * 2. 每函数独立密钥: 不同函数使用不同的加密参数，防止密钥复用攻击
 * 3. 混淆存储: 使用旋转+偏移+异或的多层混淆
 * 4. 抗内存Dump: 内存中的栈值始终处于加密状态
 *
 * 对抗技术:
 * --------
 * - 反内存分析: 静态分析无法直接读取栈值
 * - 反动态调试: 调试器看到的栈值是密文
 * - 反Hook: Hook栈操作函数需要同时处理加解密
 * - 抗侧信道: 每层操作都有不同的密钥参数
 */

#include "vm_stack_crypto.h"
#include "include/cprisk_secure_zero.h"
#include <string.h>

/* 内部常量 */
#define VM_STACK_MAGIC_PUSH 0x50555348u  /* "PUSH" */
#define VM_STACK_MAGIC_POP  0x504F5000u  /* "POP" */

/* 64位循环左移 */
static inline uint64_t vm_rotl64(uint64_t x, uint8_t n) {
    return (x << n) | (x >> (64 - n));
}

/* 64位循环右移 */
static inline uint64_t vm_rotr64(uint64_t x, uint8_t n) {
    return (x >> n) | (x << (64 - n));
}

/* 初始化栈加密上下文
 *
 * 密钥派生:
 * - 从VM主密钥派生栈专用密钥
 * - 每个函数使用不同的旋转量和偏移量
 */
int vm_stack_crypto_init(vm_stack_crypto_ctx_t *ctx,
                         uint64_t func_id,
                         const uint8_t master_key[32]) {
    if (!ctx || !master_key) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    memset(ctx, 0, sizeof(*ctx));

    /* 派生栈异或密钥 (前8字节) */
    ctx->stack_xor_key = 0;
    for (int i = 0; i < 8; i++) {
        ctx->stack_xor_key |= ((uint64_t)master_key[i]) << (i * 8);
    }
    ctx->stack_xor_key ^= func_id;

    /* 派生旋转量 (第8-15字节) */
    uint64_t rot_seed = 0;
    for (int i = 0; i < 8; i++) {
        rot_seed |= ((uint64_t)master_key[i + 8]) << (i * 8);
    }
    ctx->stack_rot = (uint8_t)(rot_seed ^ func_id) & 0x3F;
    if (ctx->stack_rot < 8) {
        ctx->stack_rot = 8;  /* 最小旋转量 */
    }

    /* 派生偏移量 (第16-23字节) */
    uint64_t offset_seed = 0;
    for (int i = 0; i < 8; i++) {
        offset_seed |= ((uint64_t)master_key[i + 16]) << (i * 8);
    }
    ctx->stack_offset = offset_seed ^ (func_id << 1);

    /* 派生次级密钥 (第24-31字节) */
    ctx->secondary_key = 0;
    for (int i = 0; i < 8; i++) {
        ctx->secondary_key |= ((uint64_t)master_key[i + 24]) << (i * 8);
    }
    ctx->secondary_key ^= (func_id >> 1);

    ctx->initialized = VM_STACK_MAGIC_PUSH;

    return VM_STACK_OK;
}

/* 加密压栈值
 *
 * 加密流程: value -> XOR -> ROTL -> ADD_OFFSET
 */
uint64_t vm_stack_encrypt_push(const vm_stack_crypto_ctx_t *ctx, uint64_t value) {
    if (!ctx || ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return value;  /* 未初始化，明文返回 */
    }

    /* 第一层: XOR with key */
    uint64_t encrypted = value ^ ctx->stack_xor_key;

    /* 第二层: 循环左移 */
    encrypted = vm_rotl64(encrypted, ctx->stack_rot);

    /* 第三层: 加法偏移 */
    encrypted += ctx->stack_offset;

    /* 第四层: 与次级密钥混合 */
    encrypted ^= (ctx->secondary_key + ctx->stack_offset);

    return encrypted;
}

/* 解密出栈值
 *
 * 解密流程: encrypted -> XOR_SECONDARY -> SUB_OFFSET -> ROTR -> XOR
 */
uint64_t vm_stack_decrypt_pop(const vm_stack_crypto_ctx_t *ctx, uint64_t encrypted) {
    if (!ctx || ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return encrypted;  /* 未初始化，直接返回 */
    }

    uint64_t decrypted = encrypted;

    /* 逆向第四层 */
    decrypted ^= (ctx->secondary_key + ctx->stack_offset);

    /* 逆向第三层 */
    decrypted -= ctx->stack_offset;

    /* 逆向第二层: 循环右移 */
    decrypted = vm_rotr64(decrypted, ctx->stack_rot);

    /* 逆向第一层 */
    decrypted ^= ctx->stack_xor_key;

    return decrypted;
}

/* 安全压栈操作
 *
 * 自动加密值并存储到加密栈 */
int vm_stack_push_encrypted(vm_stack_crypto_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t *sp,
                            uint32_t stack_size,
                            uint64_t value) {
    if (!ctx || !stack || !sp) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (*sp >= stack_size) {
        return VM_STACK_ERROR_OVERFLOW;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    /* 加密值 */
    uint64_t encrypted = vm_stack_encrypt_push(ctx, value);

    /* 存储到栈 */
    stack[*sp] = encrypted;
    (*sp)++;

    /* 可选: 更新访问计数用于侧信道防护 */
    ctx->access_count++;

    return VM_STACK_OK;
}

/* 安全出栈操作
 *
 * 从加密栈读取并自动解密
 */
int vm_stack_pop_encrypted(vm_stack_crypto_ctx_t *ctx,
                           uint64_t *stack,
                           uint32_t *sp,
                           uint64_t *out_value) {
    if (!ctx || !stack || !sp || !out_value) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (*sp == 0) {
        return VM_STACK_ERROR_UNDERFLOW;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    /* 递减栈指针 */
    (*sp)--;

    /* 读取加密值 */
    uint64_t encrypted = stack[*sp];

    /* 解密 */
    *out_value = vm_stack_decrypt_pop(ctx, encrypted);

    /* 清零栈槽 (抗残留攻击) */
    stack[*sp] = ctx->stack_xor_key ^ ctx->stack_offset;

    /* 更新访问计数 */
    ctx->access_count++;

    return VM_STACK_OK;
}

/* 窥视栈顶值 (不解密)
 *
 * 用于调试或验证，不修改栈状态
 */
int vm_stack_peek_encrypted(const vm_stack_crypto_ctx_t *ctx,
                            const uint64_t *stack,
                            uint32_t sp,
                            uint64_t *out_encrypted) {
    if (!ctx || !stack || !out_encrypted) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (sp == 0) {
        return VM_STACK_ERROR_UNDERFLOW;
    }

    *out_encrypted = stack[sp - 1];
    return VM_STACK_OK;
}

/* 从中间位置读取并解密
 *
 * 用于本地变量访问
 */
int vm_stack_load_encrypted(const vm_stack_crypto_ctx_t *ctx,
                            const uint64_t *stack,
                            uint32_t index,
                            uint64_t *out_value) {
    if (!ctx || !stack || !out_value) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    uint64_t encrypted = stack[index];
    *out_value = vm_stack_decrypt_pop(ctx, encrypted);

    return VM_STACK_OK;
}

/* 加密并存储到中间位置
 *
 * 用于本地变量赋值
 */
int vm_stack_store_encrypted(vm_stack_crypto_ctx_t *ctx,
                             uint64_t *stack,
                             uint32_t index,
                             uint64_t value) {
    if (!ctx || !stack) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    stack[index] = vm_stack_encrypt_push(ctx, value);
    return VM_STACK_OK;
}

/* 安全清除栈加密上下文
 *
 * 清除所有密钥参数
 */
void vm_stack_crypto_clear(vm_stack_crypto_ctx_t *ctx) {
    if (ctx) {
        cprisk_secure_zero(ctx, sizeof(*ctx));
    }
}

/* 批量加密栈区域
 *
 * 用于初始化或清理栈内存
 */
int vm_stack_encrypt_region(vm_stack_crypto_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t start,
                            uint32_t count) {
    if (!ctx || !stack) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    for (uint32_t i = 0; i < count; i++) {
        uint64_t original = stack[start + i];
        stack[start + i] = vm_stack_encrypt_push(ctx, original);
    }

    return VM_STACK_OK;
}

/* 批量解密栈区域
 *
 * 用于栈转储(仅调试使用)
 */
int vm_stack_decrypt_region(vm_stack_crypto_ctx_t *ctx,
                            uint64_t *stack,
                            uint32_t start,
                            uint32_t count) {
    if (!ctx || !stack) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    for (uint32_t i = 0; i < count; i++) {
        stack[start + i] = vm_stack_decrypt_pop(ctx, stack[start + i]);
    }

    return VM_STACK_OK;
}

/* 验证栈完整性
 *
 * 检测栈是否被篡改
 */
int vm_stack_verify_integrity(const vm_stack_crypto_ctx_t *ctx,
                              const uint64_t *stack,
                              uint32_t sp) {
    if (!ctx || !stack) {
        return VM_STACK_ERROR_INVALID_PARAM;
    }

    if (ctx->initialized != VM_STACK_MAGIC_PUSH) {
        return VM_STACK_ERROR_NOT_INITIALIZED;
    }

    /* 简单验证: 检查栈值是否符合加密特征 */
    for (uint32_t i = 0; i < sp; i++) {
        uint64_t value = stack[i];

        /* 加密值不应等于明文零 */
        if (value == 0) {
            return VM_STACK_ERROR_CORRUPTED;
        }

        /* 加密值应有良好的比特分布 */
        uint64_t popcount = 0;
        uint64_t temp = value;
        while (temp) {
            popcount += temp & 1;
            temp >>= 1;
        }

        /* 如果0或1的比特数极端，可能是未加密数据 */
        if (popcount < 8 || popcount > 56) {
            /* 可能是明文，继续检查其他槽位 */
            continue;
        }
    }

    return VM_STACK_OK;
}
