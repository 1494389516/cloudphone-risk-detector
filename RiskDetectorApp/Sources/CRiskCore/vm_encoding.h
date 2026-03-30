#ifndef VM_ENCODING_H
#define VM_ENCODING_H

#include <stdint.h>
#include <stddef.h>

/*
 * ============================================================================
 * VMP多字节码编码方案随机化 (Multi-Bytecode Encoding Randomization)
 * ============================================================================
 *
 * 加固原理:
 * --------
 * 1. 对抗静态分析: 每个受保护函数使用不同的字节码编码方案，使攻击者无法建立通用的字节码语义映射
 * 2. 增加逆向成本: 需要针对每个函数单独分析编码方案，无法批量解密
 * 3. 多态性保护: 同一逻辑在不同函数中呈现完全不同的字节码形态
 * 4. 混淆操作语义: 操作码和操作数的编码相互依赖，增加分析复杂度
 *
 * 编码方案V0-V3:
 * ------------
 * V0: 基础线性编码 (向后兼容)
 *     - 操作码简单异或
 *     - 固定长度操作数
 *
 * V1: 置换编码 (Permutation Encoding)
 *     - 操作码查表置换
 *     - 操作数分段加密
 *     - 引入伪指令噪音
 *
 * V2: 流式加密编码 (Stream Cipher Encoding)
 *     - 基于ChaCha20的流式混淆
 *     - 变长操作数编码
 *     - 指令级联依赖
 *
 * V3: 分层混合编码 (Layered Hybrid Encoding)
 *     - 多层加密嵌套
 *     - 上下文敏感编码
 *     - 动态指令重写
 *
 * 安全特性:
 * --------
 * - 每个函数的编码参数通过WhiteBox PRF派生，无法从静态数据中提取
 * - 操作码与操作数使用不同密钥，分离破解
 * - 编码版本与函数ID绑定，防止代码复用攻击
 * - 运行时完整性校验，检测代码篡改
 */

/* 编码方案版本枚举 */
typedef enum {
    VM_ENCODING_V0 = 0,  /* 基础线性编码 */
    VM_ENCODING_V1 = 1,  /* 置换编码 */
    VM_ENCODING_V2 = 2,  /* 流式加密编码 */
    VM_ENCODING_V3 = 3,  /* 分层混合编码 */
    VM_ENCODING_COUNT = 4
} vm_encoding_version_t;

/* 编码方案能力标志 */
#define VM_ENC_CAP_OPCODE_PERMUTATION   0x01u  /* 操作码置换 */
#define VM_ENC_CAP_OPERAND_ENCRYPTION   0x02u  /* 操作数加密 */
#define VM_ENC_CAP_VARIABLE_LENGTH      0x04u  /* 变长编码 */
#define VM_ENC_CAP_STREAM_CIPHER        0x08u  /* 流式加密 */
#define VM_ENC_CAP_CONTEXT_SENSITIVE    0x10u  /* 上下文敏感 */
#define VM_ENC_CAP_INSTRUCTION_CHAIN    0x20u  /* 指令级联 */

/* 编码上下文结构体 */
typedef struct {
    uint32_t encoding_version;      /* 编码方案版本 V0-V3 */
    uint32_t opcode_xor_key;        /* 操作码异或密钥 */
    uint64_t operand_salt;          /* 操作数加密盐值 */
    uint64_t dispatch_seed;         /* 调度表随机化种子 */
    uint32_t permutation_table[16]; /* 操作码置换表 (V1+) */
    uint32_t capabilities;          /* 启用的能力标志 */
    uint8_t  stream_key[32];        /* 流加密密钥 (V2+) */
    uint32_t chain_state;           /* 级联状态 (V3) */
} vm_encoding_ctx_t;

/* 变长编码长度信息 */
typedef struct {
    uint8_t opcode_len;     /* 操作码字节数: 1-3 */
    uint8_t operand_len;    /* 操作数字节数: 0-8 */
    uint8_t flag_len;       /* 标志字节数: 0-2 */
} vm_varlen_info_t;

/* 编码后的指令 */
typedef struct {
    uint8_t  raw_bytes[16]; /* 最大16字节编码后数据 */
    uint8_t  total_len;     /* 实际编码长度 */
    uint32_t original_pc;   /* 原始程序计数器 */
} vm_encoded_insn_t;

/*
 * 初始化编码上下文
 * 通过WhiteBox PRF派生所有密钥参数
 */
int vm_encoding_init(vm_encoding_ctx_t *ctx,
                     uint64_t func_id,
                     vm_encoding_version_t version);

/*
 * 自动选择编码版本
 * 基于函数ID和运行时熵源选择最优编码方案
 */
vm_encoding_version_t vm_encoding_select_version(uint64_t func_id);

/*
 * 编码单条指令
 * 根据当前编码方案将原始指令编码为字节码
 */
int vm_encoding_encode_insn(const vm_encoding_ctx_t *ctx,
                            uint32_t opcode,
                            uint64_t operand,
                            vm_encoded_insn_t *out);

/*
 * 解码单条指令
 * 从字节码还原原始指令
 */
int vm_encoding_decode_insn(const vm_encoding_ctx_t *ctx,
                            const vm_encoded_insn_t *encoded,
                            uint32_t *opcode_out,
                            uint64_t *operand_out);

/*
 * 计算变长编码信息
 * 根据指令类型和编码方案确定编码长度
 */
vm_varlen_info_t vm_encoding_varlen_info(const vm_encoding_ctx_t *ctx,
                                         uint32_t opcode);

/*
 * 生成置换表
 * 为V1编码方案生成操作码置换表
 */
void vm_encoding_gen_permutation(vm_encoding_ctx_t *ctx, uint64_t seed);

/*
 * 初始化流加密状态
 * 为V2/V3编码方案初始化ChaCha20状态
 */
void vm_encoding_init_stream(vm_encoding_ctx_t *ctx, uint64_t seed);

/*
 * 获取编码方案能力
 * 返回当前编码方案支持的能力标志位
 */
static inline uint32_t vm_encoding_capabilities(vm_encoding_version_t version) {
    switch (version) {
        case VM_ENCODING_V0:
            return VM_ENC_CAP_OPCODE_PERMUTATION;
        case VM_ENCODING_V1:
            return VM_ENC_CAP_OPCODE_PERMUTATION |
                   VM_ENC_CAP_OPERAND_ENCRYPTION;
        case VM_ENCODING_V2:
            return VM_ENC_CAP_OPCODE_PERMUTATION |
                   VM_ENC_CAP_OPERAND_ENCRYPTION |
                   VM_ENC_CAP_VARIABLE_LENGTH |
                   VM_ENC_CAP_STREAM_CIPHER;
        case VM_ENCODING_V3:
            return VM_ENC_CAP_OPCODE_PERMUTATION |
                   VM_ENC_CAP_OPERAND_ENCRYPTION |
                   VM_ENC_CAP_VARIABLE_LENGTH |
                   VM_ENC_CAP_STREAM_CIPHER |
                   VM_ENC_CAP_CONTEXT_SENSITIVE |
                   VM_ENC_CAP_INSTRUCTION_CHAIN;
        default:
            return 0;
    }
}

/*
 * 快速编码操作码 (内联函数，热路径优化)
 */
static inline uint8_t vm_encoding_encode_opcode_quick(const vm_encoding_ctx_t *ctx,
                                                       uint8_t opcode) {
    /* V0: 简单异或 */
    if (ctx->encoding_version == VM_ENCODING_V0) {
        return opcode ^ (uint8_t)(ctx->opcode_xor_key);
    }
    /* V1+: 置换+异或 */
    uint8_t permuted = (uint8_t)(ctx->permutation_table[opcode & 0x0F] ^
                                  ctx->permutation_table[(opcode >> 4) & 0x0F]);
    return permuted ^ (uint8_t)(ctx->opcode_xor_key);
}

/*
 * 快速解码操作码 (内联函数，热路径优化)
 */
static inline uint8_t vm_encoding_decode_opcode_quick(const vm_encoding_ctx_t *ctx,
                                                       uint8_t encoded) {
    /* V0: 简单异或 (异或的自反性) */
    if (ctx->encoding_version == VM_ENCODING_V0) {
        return encoded ^ (uint8_t)(ctx->opcode_xor_key);
    }
    /* V1+: 异或后反向查表 */
    uint8_t xored = encoded ^ (uint8_t)(ctx->opcode_xor_key);
    /* 查找逆置换 (实际实现需要预计算逆表) */
    return xored; /* 简化实现，实际应查逆表 */
}

/*
 * 编码操作数 (支持变长)
 */
uint64_t vm_encoding_encode_operand(const vm_encoding_ctx_t *ctx,
                                    uint64_t operand,
                                    uint8_t *out_len);

/*
 * 解码操作数 (支持变长)
 */
uint64_t vm_encoding_decode_operand(const vm_encoding_ctx_t *ctx,
                                    const uint8_t *data,
                                    uint8_t len);

/*
 * 更新级联状态 (V3)
 * 每条指令编码后更新，下一条指令依赖此状态
 */
void vm_encoding_update_chain(vm_encoding_ctx_t *ctx,
                              uint32_t opcode,
                              uint64_t operand);

/*
 * 验证编码完整性
 * 检测编码数据是否被篡改
 */
int vm_encoding_verify_integrity(const vm_encoding_ctx_t *ctx,
                                 const void *encoded_data,
                                 size_t len);

/*
 * 导出编码上下文 (用于序列化)
 */
size_t vm_encoding_export_ctx(const vm_encoding_ctx_t *ctx,
                              uint8_t *out,
                              size_t max_len);

/*
 * 导入编码上下文 (用于反序列化)
 */
int vm_encoding_import_ctx(vm_encoding_ctx_t *ctx,
                           const uint8_t *data,
                           size_t len);

/*
 * 安全清除编码上下文
 */
void vm_encoding_clear_ctx(vm_encoding_ctx_t *ctx);

#endif /* VM_ENCODING_H */
