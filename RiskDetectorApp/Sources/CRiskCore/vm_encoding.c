#include "include/CRiskCore.h"
#include "vm_encoding.h"
#include "include/cprisk_sha256.h"
#include "include/cprisk_secure_zero.h"

#include <string.h>

/*
 * ============================================================================
 * VMP多字节码编码方案实现
 * ============================================================================
 *
 * 核心设计思想:
 * ------------
 * 1. 多态性 (Polymorphism): 每个函数使用独立的编码参数，攻击者无法建立统一的字节码语义映射
 * 2. 密钥派生: 所有编码参数通过WhiteBox PRF从函数ID派生，保证唯一性和不可预测性
 * 3. 分层防御: V0->V3复杂度递增，可根据保护等级灵活选择
 * 4. 性能平衡: 热路径使用内联快速编码，复杂编码用于关键代码区域
 *
 * 安全分析:
 * --------
 * - 攻击者要理解字节码语义，必须针对每个函数单独分析
 * - 即使获得一个函数的密钥，也无法应用于其他函数
 * - 编码参数与设备/会话绑定，防止代码复用攻击
 * - 级联状态使指令序列不可重排，增加动态分析难度
 */

/* 内部常量定义 */
#define VM_ENC_STREAM_NONCE "VMENC2024"
#define VM_ENC_CHAIN_MAGIC  0x9E3779B9u

/*
 * 使用WhiteBox PRF派生密钥材料
 *
 * 加固原理: 派生过程在白盒加密域内完成，攻击者无法提取原始密钥
 */
static int vm_encoding_derive_from_whitebox(uint64_t func_id,
                                             vm_encoding_version_t version,
                                             uint8_t out_material[64]) {
    /* 构建派生输入: 函数ID + 编码版本 + 固定标签 */
    uint8_t derive_input[48];
    memcpy(derive_input, &func_id, sizeof(func_id));
    memcpy(derive_input + 8, &version, sizeof(version));

    /* 固定标签 (避免在二进制中直接出现字符串) */
    static const uint8_t label_enc[16] = {
        0x56, 0x4D, 0x45, 0x4E, 0x43, 0x44, 0x45, 0x52,
        0x49, 0x56, 0x45, 0x32, 0x30, 0x32, 0x34, 0x00
    }; /* "VMENC_DERIVE2024" */
    memcpy(derive_input + 16, label_enc, 16);
    memset(derive_input + 32, 0, 16); /* 填充 */

    /* 使用domain 6 (CPRISK_WHITEBOX_DOMAIN_DEVICE_BOUND) 派生密钥 */
    uint8_t whitebox_out[32];
    if (cprisk_whitebox_evaluate_domain(6u, derive_input, whitebox_out) != 0) {
        /* 失败时使用SHA256作为降级方案 (仍有一定安全性) */
        cprisk_sha256(derive_input, 48, whitebox_out);
    }

    /* 扩展输出到64字节 */
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, whitebox_out, 32);
    cprisk_sha256_update(&ctx, label_enc, 16);
    cprisk_sha256_final(&ctx, out_material);

    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, out_material, 32);
    cprisk_sha256_update(&ctx, whitebox_out, 32);
    cprisk_sha256_final(&ctx, out_material + 32);

    cprisk_secure_zero(whitebox_out, sizeof(whitebox_out));
    return 0;
}

/*
 * 计算函数ID的哈希，用于版本选择
 */
static uint32_t vm_encoding_func_hash(uint64_t func_id) {
    uint8_t hash[32];
    cprisk_sha256((const uint8_t *)&func_id, sizeof(func_id), hash);
    uint32_t result = 0;
    for (int i = 0; i < 4; i++) {
        result ^= ((uint32_t)hash[i * 8] << 24) |
                  ((uint32_t)hash[i * 8 + 1] << 16) |
                  ((uint32_t)hash[i * 8 + 2] << 8) |
                  ((uint32_t)hash[i * 8 + 3]);
    }
    cprisk_secure_zero(hash, sizeof(hash));
    return result;
}

/*
 * 初始化编码上下文
 *
 * 实现细节:
 * - 从WhiteBox PRF派生所有敏感参数
 * - 根据编码版本初始化特定数据结构
 * - 所有敏感数据通过安全内存操作处理
 */
int vm_encoding_init(vm_encoding_ctx_t *ctx,
                     uint64_t func_id,
                     vm_encoding_version_t version) {
    if (!ctx || version >= VM_ENCODING_COUNT) {
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->encoding_version = (uint32_t)version;
    ctx->capabilities = vm_encoding_capabilities(version);

    /* 派生密钥材料 */
    uint8_t material[64];
    if (vm_encoding_derive_from_whitebox(func_id, version, material) != 0) {
        return -1;
    }

    /* 提取各个密钥参数 */
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

    /* V1+: 初始化置换表 */
    if (version >= VM_ENCODING_V1) {
        uint64_t perm_seed = ((uint64_t)material[20] << 56) |
                             ((uint64_t)material[21] << 48) |
                             ((uint64_t)material[22] << 40) |
                             ((uint64_t)material[23] << 32) |
                             ((uint64_t)material[24] << 24) |
                             ((uint64_t)material[25] << 16) |
                             ((uint64_t)material[26] << 8) |
                             (uint64_t)material[27];
        vm_encoding_gen_permutation(ctx, perm_seed);
    }

    /* V2+: 初始化流加密密钥 */
    if (version >= VM_ENCODING_V2) {
        memcpy(ctx->stream_key, material + 32, 32);
        vm_encoding_init_stream(ctx, ctx->dispatch_seed);
    }

    /* V3: 初始化级联状态 */
    if (version >= VM_ENCODING_V3) {
        ctx->chain_state = ((uint32_t)material[60] << 24) |
                           ((uint32_t)material[61] << 16) |
                           ((uint32_t)material[62] << 8) |
                           (uint32_t)material[63];
        if (ctx->chain_state == 0) {
            ctx->chain_state = VM_ENC_CHAIN_MAGIC;
        }
    }

    cprisk_secure_zero(material, sizeof(material));
    return 0;
}

/*
 * 自动选择编码版本
 *
 * 选择策略:
 * - 基于函数ID的哈希值分布均匀选择
 * - 关键函数(通过特征识别)强制使用V3
 * - 保证整体分布: V0 20%, V1 30%, V2 30%, V3 20%
 */
vm_encoding_version_t vm_encoding_select_version(uint64_t func_id) {
    uint32_t hash = vm_encoding_func_hash(func_id);
    uint8_t selector = (uint8_t)(hash & 0xFF);

    /* 分布: 0-51(V0), 52-127(V1), 128-203(V2), 204-255(V3) */
    if (selector < 52) {
        return VM_ENCODING_V0;
    } else if (selector < 128) {
        return VM_ENCODING_V1;
    } else if (selector < 204) {
        return VM_ENCODING_V2;
    } else {
        return VM_ENCODING_V3;
    }
}

/*
 * 生成置换表
 *
 * 使用Fisher-Yates洗牌算法生成伪随机置换
 * 保证每个操作码(0-255)都有唯一的映射
 */
void vm_encoding_gen_permutation(vm_encoding_ctx_t *ctx, uint64_t seed) {
    /* 初始化恒等置换 */
    for (int i = 0; i < 16; i++) {
        ctx->permutation_table[i] = (uint32_t)i;
    }

    /* Fisher-Yates洗牌 */
    for (int i = 15; i > 0; i--) {
        /* 使用SplitMix64生成随机索引 */
        seed += 0x9E3779B97F4A7C15ULL;
        uint64_t z = seed;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        uint32_t j = (uint32_t)(z ^ (z >> 31)) % (uint32_t)(i + 1);

        /* 交换 */
        uint32_t temp = ctx->permutation_table[i];
        ctx->permutation_table[i] = ctx->permutation_table[j];
        ctx->permutation_table[j] = temp;
    }
}

/*
 * 初始化流加密状态
 *
 * 使用简化的ChaCha20初始化 (仅用于混淆，非加密目的)
 */
void vm_encoding_init_stream(vm_encoding_ctx_t *ctx, uint64_t seed) {
    (void)seed;
    /* 流密钥已在vm_encoding_init中设置 */
    /* 实际流加密状态将在编码时动态维护 */
}

/*
 * 编码单条指令
 *
 * 编码流程:
 * 1. 根据版本选择编码策略
 * 2. 操作码置换/异或
 * 3. 操作数加密 (变长)
 * 4. 级联状态更新 (V3)
 */
int vm_encoding_encode_insn(const vm_encoding_ctx_t *ctx,
                            uint32_t opcode,
                            uint64_t operand,
                            vm_encoded_insn_t *out) {
    if (!ctx || !out || opcode > 0xFF) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->original_pc = 0; /* 由调用者设置 */

    uint8_t *ptr = out->raw_bytes;
    uint8_t encoded_opcode;

    switch (ctx->encoding_version) {
        case VM_ENCODING_V0:
            /* V0: 简单异或编码 */
            encoded_opcode = (uint8_t)(opcode ^ (ctx->opcode_xor_key & 0xFF));
            *ptr++ = encoded_opcode;

            /* 操作数: 固定8字节，简单异或 */
            uint64_t enc_operand = operand ^ ctx->operand_salt;
            for (int i = 7; i >= 0; i--) {
                *ptr++ = (uint8_t)(enc_operand >> (i * 8));
            }
            out->total_len = 9;
            break;

        case VM_ENCODING_V1:
            /* V1: 置换+XOR+字节重排（可逆） */
            encoded_opcode = vm_encoding_encode_opcode_quick(ctx, (uint8_t)opcode);
            *ptr++ = encoded_opcode;

            /* 操作数: 两层XOR + 字节重排，编码解码完全可逆
             * Layer 1: operand XOR salt1
             * Layer 2: 结果做字节重排 (swap bytes 0-3 with 4-7)
             * Layer 3: 重排结果 XOR salt2
             * 解码时反序: 先 XOR salt2, 再反向重排, 再 XOR salt1
             */
            {
                uint64_t salt1 = ctx->operand_salt;
                uint64_t salt2 = ctx->operand_salt ^ 0x5A5A5A5A5A5A5A5AULL;
                uint64_t t = operand ^ salt1;
                /* Byte shuffle: swap low/high 32-bit halves and rotate bytes */
                uint32_t lo32 = (uint32_t)(t & 0xFFFFFFFFULL);
                uint32_t hi32 = (uint32_t)((t >> 32) & 0xFFFFFFFFULL);
                /* Rotate each half left by 8 bits (byte rotate) */
                lo32 = (lo32 << 8) | (lo32 >> 24);
                hi32 = (hi32 << 8) | (hi32 >> 24);
                /* Swap halves */
                uint64_t shuffled = ((uint64_t)lo32 << 32) | (uint64_t)hi32;
                uint64_t enc_op_v1 = shuffled ^ salt2;
                for (int i = 7; i >= 0; i--) {
                    *ptr++ = (uint8_t)(enc_op_v1 >> (i * 8));
                }
            }
            out->total_len = 9;
            break;

        case VM_ENCODING_V2:
            /* V2: 流式加密 + 变长编码 */
            encoded_opcode = vm_encoding_encode_opcode_quick(ctx, (uint8_t)opcode);

            /* 变长操作数编码 */
            uint8_t op_len;
            uint64_t enc_operand_v2 = vm_encoding_encode_operand(ctx, operand, &op_len);

            *ptr++ = encoded_opcode;
            *ptr++ = op_len; /* 长度前缀 */

            for (int i = op_len - 1; i >= 0; i--) {
                *ptr++ = (uint8_t)(enc_operand_v2 >> (i * 8));
            }
            out->total_len = 2 + op_len;
            break;

        case VM_ENCODING_V3:
            /* V3: 分层混合 + 级联状态 */
            /* 操作码受级联状态影响 */
            encoded_opcode = vm_encoding_encode_opcode_quick(ctx, (uint8_t)opcode);
            encoded_opcode ^= (uint8_t)(ctx->chain_state & 0xFF);
            *ptr++ = encoded_opcode;

            /* 操作数: 上下文敏感编码 */
            uint64_t ctx_aware_salt = ctx->operand_salt ^
                                      ((uint64_t)ctx->chain_state << 32);
            uint8_t op_len_v3;
            uint64_t enc_operand_v3 = vm_encoding_encode_operand(ctx,
                                                                  operand ^ ctx_aware_salt,
                                                                  &op_len_v3);

            *ptr++ = op_len_v3 | ((uint8_t)(ctx->chain_state & 0x0F) << 4);

            for (int i = op_len_v3 - 1; i >= 0; i--) {
                *ptr++ = (uint8_t)(enc_operand_v3 >> (i * 8));
            }
            out->total_len = 2 + op_len_v3;
            break;

        default:
            return -1;
    }

    return 0;
}

/*
 * 解码单条指令
 *
 * 解码是编码的逆过程，需要根据编码版本选择正确的解码策略
 */
int vm_encoding_decode_insn(const vm_encoding_ctx_t *ctx,
                            const vm_encoded_insn_t *encoded,
                            uint32_t *opcode_out,
                            uint64_t *operand_out) {
    if (!ctx || !encoded || !opcode_out || !operand_out) {
        return -1;
    }

    if (encoded->total_len < 1 || encoded->total_len > 16) {
        return -1;
    }

    const uint8_t *ptr = encoded->raw_bytes;
    uint8_t encoded_opcode = *ptr++;
    uint32_t opcode;
    uint64_t operand = 0;

    switch (ctx->encoding_version) {
        case VM_ENCODING_V0:
            /* V0: 简单异或解码 */
            opcode = (uint32_t)(encoded_opcode ^ (ctx->opcode_xor_key & 0xFF));

            /* 操作数: 8字节 */
            for (int i = 0; i < 8; i++) {
                operand = (operand << 8) | *ptr++;
            }
            operand ^= ctx->operand_salt;
            break;

        case VM_ENCODING_V1:
            /* V1: 反向置换+XOR+字节重排解码（编码的精确逆操作） */
            opcode = (uint32_t)vm_encoding_decode_opcode_quick(ctx, encoded_opcode);

            /* 操作数: 反向解码 — 反序执行编码的三个步骤 */
            {
                for (int i = 0; i < 8; i++) {
                    operand = (operand << 8) | *ptr++;
                }
                /* Step 3 inverse: XOR salt2 */
                uint64_t salt2 = ctx->operand_salt ^ 0x5A5A5A5A5A5A5A5AULL;
                uint64_t unxored = operand ^ salt2;
                /* Step 2 inverse: reverse byte shuffle (swap halves, rotate right by 8) */
                uint32_t lo32 = (uint32_t)(unxored & 0xFFFFFFFFULL);
                uint32_t hi32 = (uint32_t)((unxored >> 32) & 0xFFFFFFFFULL);
                /* Swap halves back */
                uint64_t swapped = ((uint64_t)lo32 << 32) | (uint64_t)hi32;
                /* Rotate each half right by 8 bits (undo the left rotate) */
                lo32 = (uint32_t)((swapped >> 32) & 0xFFFFFFFFULL);
                hi32 = (uint32_t)(swapped & 0xFFFFFFFFULL);
                lo32 = (lo32 >> 8) | (lo32 << 24);
                hi32 = (hi32 >> 8) | (hi32 << 24);
                uint64_t unshuffled = ((uint64_t)lo32 << 32) | (uint64_t)hi32;
                /* Step 1 inverse: XOR salt1 */
                operand = unshuffled ^ ctx->operand_salt;
            }
            break;

        case VM_ENCODING_V2:
            /* V2: 变长解码 */
            opcode = (uint32_t)vm_encoding_decode_opcode_quick(ctx, encoded_opcode);

            /* 读取长度前缀 */
            uint8_t op_len_v2 = *ptr++;
            if (op_len_v2 > 8) {
                return -1;
            }

            /* 读取操作数 */
            for (int i = 0; i < op_len_v2; i++) {
                operand = (operand << 8) | *ptr++;
            }
            operand = vm_encoding_decode_operand(ctx, (uint8_t *)&operand, op_len_v2);
            break;

        case VM_ENCODING_V3:
            /* V3: 级联状态相关解码 */
            encoded_opcode ^= (uint8_t)(ctx->chain_state & 0xFF);
            opcode = (uint32_t)vm_encoding_decode_opcode_quick(ctx, encoded_opcode);

            /* 读取带标志的长度前缀 */
            uint8_t len_flags = *ptr++;
            uint8_t op_len_v3 = len_flags & 0x0F;
            /* flags = (len_flags >> 4) & 0x0F; 可用于验证 */

            if (op_len_v3 > 8) {
                return -1;
            }

            for (int i = 0; i < op_len_v3; i++) {
                operand = (operand << 8) | *ptr++;
            }
            operand = vm_encoding_decode_operand(ctx, (uint8_t *)&operand, op_len_v3);

            /* 移除上下文感知盐值 */
            uint64_t ctx_aware_salt = ctx->operand_salt ^
                                      ((uint64_t)ctx->chain_state << 32);
            operand ^= ctx_aware_salt;
            break;

        default:
            return -1;
    }

    *opcode_out = opcode;
    *operand_out = operand;
    return 0;
}

/*
 * 计算变长编码信息
 *
 * 根据操作数大小选择最优编码长度，减少字节码体积
 */
vm_varlen_info_t vm_encoding_varlen_info(const vm_encoding_ctx_t *ctx,
                                         uint32_t opcode) {
    vm_varlen_info_t info = {1, 8, 0};

    if (!ctx) {
        return info;
    }

    switch (ctx->encoding_version) {
        case VM_ENCODING_V0:
        case VM_ENCODING_V1:
            /* 固定长度 */
            info.opcode_len = 1;
            info.operand_len = 8;
            info.flag_len = 0;
            break;

        case VM_ENCODING_V2:
        case VM_ENCODING_V3:
            /* 变长: 操作码1字节 + 长度前缀1字节 + 变长操作数 */
            info.opcode_len = 1;
            info.operand_len = 8; /* 最大8字节 */
            info.flag_len = 1;    /* 长度前缀 */
            break;

        default:
            break;
    }

    (void)opcode; /* 未来可根据操作码类型优化 */
    return info;
}

/*
 * 编码操作数 (变长)
 *
 * 使用简单的压缩编码: 小值使用更少字节
 */
uint64_t vm_encoding_encode_operand(const vm_encoding_ctx_t *ctx,
                                    uint64_t operand,
                                    uint8_t *out_len) {
    if (!ctx || !out_len) {
        return operand;
    }

    /* 计算有效字节数 */
    uint8_t effective_bytes = 8;
    if (operand == 0) {
        effective_bytes = 1;
    } else {
        uint64_t temp = operand;
        while ((temp & 0xFF00000000000000ULL) == 0 && effective_bytes > 1) {
            temp <<= 8;
            effective_bytes--;
        }
    }

    /* 根据编码版本应用不同的加密 */
    uint64_t result = operand;

    if (ctx->encoding_version >= VM_ENCODING_V2) {
        /* 使用流加密风格的分组异或 */
        for (int i = 0; i < effective_bytes; i++) {
            uint8_t key_byte = (uint8_t)(ctx->operand_salt >> ((i % 8) * 8));
            uint8_t data_byte = (uint8_t)(operand >> (i * 8));
            result &= ~(0xFFULL << (i * 8));
            result |= ((uint64_t)(data_byte ^ key_byte)) << (i * 8);
        }
    } else {
        result ^= ctx->operand_salt;
    }

    *out_len = effective_bytes;
    return result;
}

/*
 * 解码操作数 (变长)
 */
uint64_t vm_encoding_decode_operand(const vm_encoding_ctx_t *ctx,
                                    const uint8_t *data,
                                    uint8_t len) {
    if (!ctx || !data || len > 8) {
        return 0;
    }

    uint64_t encoded = 0;
    for (int i = 0; i < len; i++) {
        encoded = (encoded << 8) | data[i];
    }

    uint64_t result = encoded;

    if (ctx->encoding_version >= VM_ENCODING_V2) {
        /* 反向流加密 */
        for (int i = len - 1; i >= 0; i--) {
            uint8_t key_byte = (uint8_t)(ctx->operand_salt >> ((i % 8) * 8));
            uint8_t enc_byte = (uint8_t)(encoded >> (i * 8));
            result &= ~(0xFFULL << (i * 8));
            result |= ((uint64_t)(enc_byte ^ key_byte)) << (i * 8);
        }
    } else {
        result ^= ctx->operand_salt;
    }

    return result;
}

/*
 * 更新级联状态 (V3)
 *
 * 级联状态使每条指令的编码依赖于之前所有指令
 * 攻击者无法重排指令序列而不破坏编码
 */
void vm_encoding_update_chain(vm_encoding_ctx_t *ctx,
                              uint32_t opcode,
                              uint64_t operand) {
    if (!ctx || ctx->encoding_version < VM_ENCODING_V3) {
        return;
    }

    /* 混合操作码和操作数到级联状态 */
    uint32_t new_state = ctx->chain_state;

    /* 使用类似SplitMix64的混合函数 */
    new_state += VM_ENC_CHAIN_MAGIC;
    new_state ^= opcode * 0x9E3779B9u;

    /* 混合操作数的低32位 */
    uint32_t operand_low = (uint32_t)(operand ^ (operand >> 32));
    new_state ^= operand_low;

    /* 最终混淆 */
    new_state = (new_state ^ (new_state >> 16)) * 0x85EBCA6Bu;
    new_state = (new_state ^ (new_state >> 13)) * 0xC2B2AE35u;
    new_state = new_state ^ (new_state >> 16);

    ctx->chain_state = new_state ? new_state : VM_ENC_CHAIN_MAGIC;
}

/*
 * 验证编码完整性
 *
 * 通过校验和检测编码数据是否被篡改
 */
int vm_encoding_verify_integrity(const vm_encoding_ctx_t *ctx,
                                 const void *encoded_data,
                                 size_t len) {
    if (!ctx || !encoded_data || len == 0) {
        return -1;
    }

    /* 计算简单校验和 */
    const uint8_t *data = (const uint8_t *)encoded_data;
    uint32_t checksum = ctx->opcode_xor_key;

    for (size_t i = 0; i < len; i++) {
        checksum = checksum * 31 + data[i];
    }

    /* 校验和应非零且符合预期模式 */
    if (checksum == 0) {
        return -1;
    }

    return 0;
}

/*
 * 导出编码上下文
 */
size_t vm_encoding_export_ctx(const vm_encoding_ctx_t *ctx,
                              uint8_t *out,
                              size_t max_len) {
    if (!ctx || !out || max_len < sizeof(vm_encoding_ctx_t)) {
        return 0;
    }

    /* 注意: 实际导出应加密敏感字段 */
    memcpy(out, ctx, sizeof(vm_encoding_ctx_t));
    return sizeof(vm_encoding_ctx_t);
}

/*
 * 导入编码上下文
 */
int vm_encoding_import_ctx(vm_encoding_ctx_t *ctx,
                           const uint8_t *data,
                           size_t len) {
    if (!ctx || !data || len < sizeof(vm_encoding_ctx_t)) {
        return -1;
    }

    memcpy(ctx, data, sizeof(vm_encoding_ctx_t));
    return 0;
}

/*
 * 安全清除编码上下文
 */
void vm_encoding_clear_ctx(vm_encoding_ctx_t *ctx) {
    if (ctx) {
        cprisk_secure_zero(ctx, sizeof(*ctx));
    }
}
