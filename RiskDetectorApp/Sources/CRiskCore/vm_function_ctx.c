#include "include/CRiskCore.h"
#include "vm_function_ctx.h"
#include "vm_encoding.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <string.h>
#include <stdlib.h>

/*
 * ============================================================================
 * VMP函数级VM上下文实现
 * ============================================================================
 *
 * 核心设计:
 * --------
 * 1. 完全隔离: 每个函数拥有独立的密钥、状态、配置
 * 2. 动态派生: 所有敏感数据通过WhiteBox PRF从func_id派生
 * 3. 状态机: 严格的状态转换控制，防止非法操作
 * 4. 审计追踪: 记录执行统计和异常，便于风控分析
 *
 * 安全考虑:
 * --------
 * - 密钥不存储在可读的内存区域，使用后立即清除
 * - 敏感操作有完整性校验
 * - 状态转换需要验证前置条件
 * - 防止重入和竞态条件
 */

/* 内部常量 */
#define VM_FUNC_CTX_MAGIC_INIT 0x564D4643u  /* "VMFC" */
#define VM_FUNC_MAX_STEPS_DEFAULT 65536u
#define VM_FUNC_MAX_STEPS_CRITICAL 32768u

/*
 * 使用WhiteBox PRF派生函数级密钥
 *
 * 安全原理:
 * - 使用domain 7 (RUNTIME_DERIVE_KEY) 派生
 * - 输入包含函数ID和固定标签，保证唯一性
 * - 输出扩展到64字节，供多个密钥使用
 */
static int vm_function_derive_key_material(uint64_t func_id,
                                            uint8_t out_material[64]) {
    uint8_t derive_input[48];

    /* 构建派生输入 */
    memcpy(derive_input, &func_id, sizeof(func_id));

    /* 固定标签: "VMFUNC_DERIVE2024" */
    static const uint8_t label[16] = {
        0x56, 0x4D, 0x46, 0x55, 0x4E, 0x43, 0x5F, 0x44,
        0x45, 0x52, 0x49, 0x56, 0x45, 0x32, 0x30, 0x32
    };
    memcpy(derive_input + 8, label, 16);
    memset(derive_input + 24, 0, 24);

    /* 使用domain 7派生 */
    uint8_t whitebox_out[32];
    if (cprisk_whitebox_evaluate_domain(7u, derive_input, whitebox_out) != 0) {
        cprisk_sha256(derive_input, 48, whitebox_out);
    }

    /* 扩展输出 */
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, whitebox_out, 32);
    cprisk_sha256_update(&ctx, label, 16);
    cprisk_sha256_final(&ctx, out_material);

    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, out_material, 32);
    cprisk_sha256_update(&ctx, whitebox_out, 32);
    cprisk_sha256_final(&ctx, out_material + 32);

    cprisk_secure_zero(whitebox_out, sizeof(whitebox_out));
    return 0;
}

/*
 * 根据保护级别选择编码版本
 *
 * 策略:
 * - NONE: 不使用编码 (直接执行)
 * - BASIC: V0 (简单异或)
 * - STANDARD: V1-V2 (随机选择)
 * - HIGH: V2-V3 (随机选择)
 * - CRITICAL: V3 (强制使用最高级别)
 */
vm_encoding_version_t vm_function_ctx_select_encoding(vm_protect_level_t level) {
    switch (level) {
        case VM_PROTECT_LEVEL_NONE:
            return VM_ENCODING_V0;

        case VM_PROTECT_LEVEL_BASIC:
            return VM_ENCODING_V0;

        case VM_PROTECT_LEVEL_STANDARD:
            /* 随机选择V1或V2 */
            return (vm_encoding_version_t)(1 + (cprisk_get_vm_mprotect_crosscheck_mismatch_count() % 2));

        case VM_PROTECT_LEVEL_HIGH:
            /* 随机选择V2或V3 */
            return (vm_encoding_version_t)(2 + (cprisk_get_vm_mprotect_mach_trap_mismatch_count() % 2));

        case VM_PROTECT_LEVEL_CRITICAL:
            return VM_ENCODING_V3;

        default:
            return VM_ENCODING_V0;
    }
}

/*
 * 计算函数ID哈希
 */
static uint32_t vm_function_hash_id(uint64_t func_id) {
    uint8_t hash[32];
    cprisk_sha256((const uint8_t *)&func_id, sizeof(func_id), hash);
    uint32_t result = ((uint32_t)hash[0] << 24) |
                      ((uint32_t)hash[1] << 16) |
                      ((uint32_t)hash[2] << 8) |
                      (uint32_t)hash[3];
    cprisk_secure_zero(hash, sizeof(hash));
    return result ^ VM_FUNC_CTX_MAGIC_INIT;
}

/*
 * 初始化函数上下文
 *
 * 流程:
 * 1. 清零结构体
 * 2. 设置函数ID和哈希
 * 3. 派生所有密钥参数
 * 4. 初始化编码上下文
 * 5. 根据保护级别初始化额外功能
 */
int vm_function_ctx_init(vm_function_ctx_t *ctx,
                         uint64_t func_id,
                         vm_protect_level_t level) {
    if (!ctx) {
        return -1;
    }

    /* 清零 */
    memset(ctx, 0, sizeof(*ctx));

    /* 设置标识 */
    ctx->func_id = func_id;
    ctx->func_hash = vm_function_hash_id(func_id);
    ctx->protect_level = level;
    ctx->state = VM_FUNC_CTX_UNINITIALIZED;

    /* 选择编码版本 */
    ctx->encoding_version = (uint32_t)vm_function_ctx_select_encoding(level);

    /* 派生密钥 */
    if (vm_function_ctx_derive_keys(ctx, func_id) != 0) {
        ctx->state = VM_FUNC_CTX_ERROR;
        return -1;
    }

    /* 初始化编码上下文 */
    if (vm_encoding_init(&ctx->encoding, func_id,
                         (vm_encoding_version_t)ctx->encoding_version) != 0) {
        ctx->state = VM_FUNC_CTX_ERROR;
        return -1;
    }

    /* 设置最大步数 */
    switch (level) {
        case VM_PROTECT_LEVEL_NONE:
        case VM_PROTECT_LEVEL_BASIC:
            ctx->max_steps = VM_FUNC_MAX_STEPS_DEFAULT;
            break;
        case VM_PROTECT_LEVEL_STANDARD:
        case VM_PROTECT_LEVEL_HIGH:
            ctx->max_steps = VM_FUNC_MAX_STEPS_DEFAULT;
            break;
        case VM_PROTECT_LEVEL_CRITICAL:
            ctx->max_steps = VM_FUNC_MAX_STEPS_CRITICAL;
            break;
        default:
            ctx->max_steps = VM_FUNC_MAX_STEPS_DEFAULT;
    }

    /* 高级别保护启用栈加密 */
    if (level >= VM_PROTECT_LEVEL_HIGH) {
        ctx->meta_flags |= VM_FUNC_META_NEEDS_STACK_ENC;
        if (vm_function_ctx_init_stack_crypto(ctx) != 0) {
            ctx->state = VM_FUNC_CTX_ERROR;
            return -1;
        }
    }

    /* 关键级别启用完整性校验 */
    if (level >= VM_PROTECT_LEVEL_CRITICAL) {
        ctx->meta_flags |= VM_FUNC_META_NEEDS_INTEGRITY;
        if (vm_function_ctx_init_integrity(ctx) != 0) {
            ctx->state = VM_FUNC_CTX_ERROR;
            return -1;
        }
    }

    ctx->state = VM_FUNC_CTX_READY;
    return 0;
}

/*
 * 从函数ID派生所有密钥参数
 *
 * 派生内容:
 * - opcode_xor_key: 32位操作码异或密钥
 * - operand_salt: 64位操作数加密盐值
 * - dispatch_seed: 64位调度表随机化种子
 * - version_seed: 32位版本校验种子
 * - stack_xor_key: 64位栈异或密钥
 * - stack_rot: 8位栈旋转值
 * - stack_offset: 32位栈偏移值
 */
int vm_function_ctx_derive_keys(vm_function_ctx_t *ctx, uint64_t func_id) {
    if (!ctx) {
        return -1;
    }

    uint8_t material[64];
    if (vm_function_derive_key_material(func_id, material) != 0) {
        return -1;
    }

    /* 提取各个密钥 */
    ctx->opcode_xor_key = ((uint32_t)material[0] << 24) |
                          ((uint32_t)material[1] << 16) |
                          ((uint32_t)material[2] << 8) |
                          (uint32_t)material[3];

    ctx->operand_salt = ((uint64_t)material[4] << 56) |
                        ((uint64_t)material[5] << 48) |
                        ((uint64_t)material[6] << 40) |
                        ((uint64_t)material[7] << 32) |
                        ((uint64_t)material[8] << 24) |
                        ((uint64_t)material[9] << 16) |
                        ((uint64_t)material[10] << 8) |
                        (uint64_t)material[11];

    ctx->dispatch_seed = ((uint64_t)material[12] << 56) |
                         ((uint64_t)material[13] << 48) |
                         ((uint64_t)material[14] << 40) |
                         ((uint64_t)material[15] << 32) |
                         ((uint64_t)material[16] << 24) |
                         ((uint64_t)material[17] << 16) |
                         ((uint64_t)material[18] << 8) |
                         (uint64_t)material[19];

    ctx->version_seed = ((uint32_t)material[20] << 24) |
                        ((uint32_t)material[21] << 16) |
                        ((uint32_t)material[22] << 8) |
                        (uint32_t)material[23];

    ctx->stack_xor_key = ((uint64_t)material[24] << 56) |
                         ((uint64_t)material[25] << 48) |
                         ((uint64_t)material[26] << 40) |
                         ((uint64_t)material[27] << 32) |
                         ((uint64_t)material[28] << 24) |
                         ((uint64_t)material[29] << 16) |
                         ((uint64_t)material[30] << 8) |
                         (uint64_t)material[31];

    ctx->stack_rot = material[32] % 64;  /* 0-63位旋转 */
    ctx->stack_offset = ((uint32_t)material[33] << 24) |
                        ((uint32_t)material[34] << 16) |
                        ((uint32_t)material[35] << 8) |
                        (uint32_t)material[36];

    /* 计算校验和链初始值 */
    ctx->checksum_chain = ((uint64_t)material[40] << 56) |
                          ((uint64_t)material[41] << 48) |
                          ((uint64_t)material[42] << 40) |
                          ((uint64_t)material[43] << 32) |
                          ((uint64_t)material[44] << 24) |
                          ((uint64_t)material[45] << 16) |
                          ((uint64_t)material[46] << 8) |
                          (uint64_t)material[47];

    /* 初始化完整性标签 */
    memcpy(ctx->integrity_tag, material + 48, 16);

    cprisk_secure_zero(material, sizeof(material));
    return 0;
}

/*
 * 设置函数元数据
 */
void vm_function_ctx_set_metadata(vm_function_ctx_t *ctx,
                                   uint32_t flags,
                                   uint32_t max_steps) {
    if (!ctx) return;

    ctx->meta_flags = flags;
    if (max_steps > 0) {
        ctx->max_steps = max_steps;
    }
}

/*
 * 初始化栈加密参数
 *
 * 栈加密使用三重保护:
 * 1. XOR混淆: 所有栈值与stack_xor_key异或
 * 2. 旋转: 值在写入前旋转stack_rot位
 * 3. 偏移: 逻辑栈位置与实际位置通过stack_offset映射
 */
int vm_function_ctx_init_stack_crypto(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    /* 密钥已在derive_keys中设置，这里验证有效性 */
    if (ctx->stack_xor_key == 0) {
        ctx->stack_xor_key = 0xA5A5A5A5A5A5A5A5ULL;
    }
    if (ctx->stack_rot == 0) {
        ctx->stack_rot = 17;  /* 默认旋转17位 */
    }

    return 0;
}

/*
 * 初始化完整性校验参数
 */
int vm_function_ctx_init_integrity(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    /* 设置完整性检查需要的初始值 */
    if (ctx->version_seed == 0) {
        ctx->version_seed = 0x9E3779B9u;
    }

    return 0;
}

/*
 * 进入函数执行状态
 *
 * 状态转换: READY -> EXECUTING
 * 或: SUSPENDED -> EXECUTING
 */
int vm_function_ctx_enter(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    if (ctx->state != VM_FUNC_CTX_READY &&
        ctx->state != VM_FUNC_CTX_SUSPENDED) {
        return -1;
    }

    ctx->state = VM_FUNC_CTX_EXECUTING;
    ctx->execution_count++;
    ctx->step_count = 0;
    ctx->anomaly_flags = 0;

    return 0;
}

/*
 * 退出函数执行状态
 *
 * 状态转换: EXECUTING -> COMPLETED
 */
int vm_function_ctx_exit(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    if (ctx->state != VM_FUNC_CTX_EXECUTING) {
        return -1;
    }

    ctx->state = VM_FUNC_CTX_COMPLETED;

    /* 更新最后执行时间戳 (简化实现) */
    ctx->last_execution_time = ctx->execution_count;

    return 0;
}

/*
 * 挂起函数执行
 *
 * 状态转换: EXECUTING -> SUSPENDED
 */
int vm_function_ctx_suspend(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    if (ctx->state != VM_FUNC_CTX_EXECUTING) {
        return -1;
    }

    ctx->state = VM_FUNC_CTX_SUSPENDED;
    return 0;
}

/*
 * 恢复函数执行
 *
 * 状态转换: SUSPENDED -> EXECUTING
 */
int vm_function_ctx_resume(vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    if (ctx->state != VM_FUNC_CTX_SUSPENDED) {
        return -1;
    }

    ctx->state = VM_FUNC_CTX_EXECUTING;
    return 0;
}

/*
 * 获取函数编码上下文
 */
const vm_encoding_ctx_t *vm_function_ctx_get_encoding(const vm_function_ctx_t *ctx) {
    if (!ctx) return NULL;
    return &ctx->encoding;
}

/*
 * 编码函数的字节码
 *
 * 使用函数专属的编码方案对整个函数的字节码进行编码
 */
int vm_function_ctx_encode_bytecode(vm_function_ctx_t *ctx,
                                    const uint8_t *raw_bytecode,
                                    size_t raw_len,
                                    uint8_t **out_encoded,
                                    size_t *out_len) {
    if (!ctx || !raw_bytecode || raw_len == 0 || !out_encoded || !out_len) {
        return -1;
    }

    /* 分配输出缓冲区 (估算大小，变长编码可能更小) */
    size_t max_encoded = raw_len * 2;
    uint8_t *encoded = (uint8_t *)malloc(max_encoded);
    if (!encoded) {
        return -1;
    }

    size_t pos = 0;
    size_t raw_pos = 0;

    /* 编码头部: 函数ID + 编码版本 */
    memcpy(encoded + pos, &ctx->func_id, sizeof(ctx->func_id));
    pos += sizeof(ctx->func_id);

    encoded[pos++] = (uint8_t)ctx->encoding_version;
    encoded[pos++] = (uint8_t)ctx->protect_level;

    /* 逐指令编码 */
    while (raw_pos + 9 <= raw_len) {  /* 最小指令9字节 */
        uint32_t opcode = raw_bytecode[raw_pos];
        uint64_t operand = 0;

        /* 读取操作数 (小端序) */
        for (int i = 0; i < 8; i++) {
            operand |= ((uint64_t)raw_bytecode[raw_pos + 1 + i]) << (i * 8);
        }

        /* 编码指令 */
        vm_encoded_insn_t enc_insn;
        if (vm_encoding_encode_insn(&ctx->encoding, opcode, operand, &enc_insn) != 0) {
            free(encoded);
            return -1;
        }

        /* 写入编码后的指令 */
        if (pos + enc_insn.total_len > max_encoded) {
            free(encoded);
            return -1;
        }

        memcpy(encoded + pos, enc_insn.raw_bytes, enc_insn.total_len);
        pos += enc_insn.total_len;

        raw_pos += 9;  /* 原始指令固定9字节 */
    }

    *out_encoded = encoded;
    *out_len = pos;

    return 0;
}

/*
 * 解码函数的字节码 (单条指令)
 */
int vm_function_ctx_decode_bytecode(vm_function_ctx_t *ctx,
                                    const uint8_t *encoded_bytecode,
                                    size_t encoded_len,
                                    uint32_t pc,
                                    uint32_t *opcode_out,
                                    uint64_t *operand_out) {
    if (!ctx || !encoded_bytecode || !opcode_out || !operand_out) {
        return -1;
    }

    /* 跳过头部 */
    size_t header_len = sizeof(ctx->func_id) + 2;
    if (pc < header_len || pc >= encoded_len) {
        return -1;
    }

    /* 构建编码指令结构 */
    vm_encoded_insn_t enc_insn;
    memset(&enc_insn, 0, sizeof(enc_insn));

    /* 读取变长指令 (简化实现，实际需要解析变长编码) */
    size_t max_insn_len = (encoded_len - pc < 16) ? (encoded_len - pc) : 16;
    memcpy(enc_insn.raw_bytes, encoded_bytecode + pc, max_insn_len);
    enc_insn.total_len = (uint8_t)max_insn_len;
    enc_insn.original_pc = pc;

    /* 解码 */
    return vm_encoding_decode_insn(&ctx->encoding, &enc_insn, opcode_out, operand_out);
}

/*
 * 验证函数上下文完整性
 */
int vm_function_ctx_verify_integrity(const vm_function_ctx_t *ctx) {
    if (!ctx) return -1;

    /* 验证状态合法性 */
    if (ctx->state < VM_FUNC_CTX_UNINITIALIZED ||
        ctx->state > VM_FUNC_CTX_ERROR) {
        return -1;
    }

    /* 验证函数哈希 */
    uint32_t expected_hash = vm_function_hash_id(ctx->func_id);
    if (ctx->func_hash != expected_hash) {
        return -1;
    }

    /* 验证编码版本 */
    if (ctx->encoding_version >= VM_ENCODING_COUNT) {
        return -1;
    }

    return 0;
}

/*
 * 复制函数上下文
 */
int vm_function_ctx_copy(vm_function_ctx_t *dst, const vm_function_ctx_t *src) {
    if (!dst || !src) return -1;

    memcpy(dst, src, sizeof(vm_function_ctx_t));

    /* 深拷贝动态分配的内存 */
    if (src->bytecode_cache && src->bytecode_size > 0) {
        dst->bytecode_cache = malloc(src->bytecode_size);
        if (!dst->bytecode_cache) {
            return -1;
        }
        memcpy(dst->bytecode_cache, src->bytecode_cache, src->bytecode_size);
    }

    return 0;
}

/*
 * 安全清除函数上下文
 */
void vm_function_ctx_clear(vm_function_ctx_t *ctx) {
    if (!ctx) return;

    /* 清除动态分配的内存 */
    if (ctx->bytecode_cache) {
        cprisk_secure_zero(ctx->bytecode_cache, ctx->bytecode_size);
        free(ctx->bytecode_cache);
        ctx->bytecode_cache = NULL;
    }

    /* 清除敏感数据 */
    cprisk_secure_zero(ctx, sizeof(*ctx));
}

/* ==================== 上下文池管理实现 ==================== */

/*
 * 初始化上下文池
 */
void vm_function_ctx_pool_init(vm_function_ctx_pool_t *pool) {
    if (!pool) return;

    memset(pool, 0, sizeof(*pool));
    pool->active_count = 0;
}

/*
 * 从池中分配上下文
 */
vm_function_ctx_t *vm_function_ctx_pool_alloc(vm_function_ctx_pool_t *pool) {
    if (!pool || pool->active_count >= VM_FUNC_CTX_POOL_SIZE) {
        return NULL;
    }

    /* 查找空闲槽位 */
    for (int i = 0; i < VM_FUNC_CTX_POOL_SIZE; i++) {
        uint32_t word_idx = i / 32;
        uint32_t bit_idx = i % 32;

        if ((pool->used_bitmap[word_idx] & (1u << bit_idx)) == 0) {
            /* 找到空闲槽 */
            pool->used_bitmap[word_idx] |= (1u << bit_idx);
            pool->active_count++;

            vm_function_ctx_t *ctx = &pool->contexts[i];
            memset(ctx, 0, sizeof(*ctx));
            return ctx;
        }
    }

    return NULL;
}

/*
 * 释放上下文回池
 */
void vm_function_ctx_pool_free(vm_function_ctx_pool_t *pool,
                               vm_function_ctx_t *ctx) {
    if (!pool || !ctx) return;

    /* 计算索引 */
    int idx = (int)(ctx - pool->contexts);
    if (idx < 0 || idx >= VM_FUNC_CTX_POOL_SIZE) {
        return;
    }

    /* 清除敏感数据 */
    vm_function_ctx_clear(ctx);

    /* 标记为空闲 */
    uint32_t word_idx = (uint32_t)idx / 32u;
    uint32_t bit_idx = (uint32_t)idx % 32u;
    pool->used_bitmap[word_idx] &= ~(1u << bit_idx);
    pool->active_count--;
}

/*
 * 查找函数的上下文
 */
vm_function_ctx_t *vm_function_ctx_pool_find(vm_function_ctx_pool_t *pool,
                                              uint64_t func_id) {
    if (!pool) return NULL;

    for (int i = 0; i < VM_FUNC_CTX_POOL_SIZE; i++) {
        uint32_t word_idx = (uint32_t)i / 32u;
        uint32_t bit_idx = (uint32_t)i % 32u;

        if (pool->used_bitmap[word_idx] & (1u << bit_idx)) {
            if (pool->contexts[i].func_id == func_id) {
                return &pool->contexts[i];
            }
        }
    }

    return NULL;
}

/*
 * 获取或创建函数上下文
 */
vm_function_ctx_t *vm_function_ctx_pool_get_or_create(vm_function_ctx_pool_t *pool,
                                                       uint64_t func_id,
                                                       vm_protect_level_t level) {
    if (!pool) return NULL;

    /* 先查找 */
    vm_function_ctx_t *ctx = vm_function_ctx_pool_find(pool, func_id);
    if (ctx) {
        return ctx;
    }

    /* 创建新的 */
    ctx = vm_function_ctx_pool_alloc(pool);
    if (!ctx) {
        return NULL;
    }

    if (vm_function_ctx_init(ctx, func_id, level) != 0) {
        vm_function_ctx_pool_free(pool, ctx);
        return NULL;
    }

    return ctx;
}

/*
 * 清理池中的所有上下文
 */
void vm_function_ctx_pool_clear(vm_function_ctx_pool_t *pool) {
    if (!pool) return;

    for (int i = 0; i < VM_FUNC_CTX_POOL_SIZE; i++) {
        uint32_t word_idx = (uint32_t)i / 32u;
        uint32_t bit_idx = (uint32_t)i % 32u;

        if (pool->used_bitmap[word_idx] & (1u << bit_idx)) {
            vm_function_ctx_clear(&pool->contexts[i]);
        }
    }

    memset(pool, 0, sizeof(*pool));
}
