/*
 *  vm_whitebox_bind.c
 *  CRiskCore
 */

#include "vm_whitebox_bind.h"
#include "include/cprisk_secure_zero.h"
#include "include/cprisk_sha256.h"
#include <string.h>

static const uint8_t LABEL_ROOT[16] = {
    0x52, 0x4F, 0x4F, 0x54, 0x5F, 0x44, 0x45, 0x52,
    0x49, 0x56, 0x45, 0x5F, 0x56, 0x31, 0x00, 0x00
};

static const uint8_t LABEL_FUNC[16] = {
    0x46, 0x55, 0x4E, 0x43, 0x5F, 0x44, 0x45, 0x52,
    0x49, 0x56, 0x45, 0x5F, 0x56, 0x31, 0x00, 0x00
};

static const uint8_t LABEL_OP[16] = {
    0x4F, 0x50, 0x5F, 0x44, 0x45, 0x52, 0x49, 0x56,
    0x45, 0x5F, 0x56, 0x31, 0x00, 0x00, 0x00, 0x00
};

void vm_wb_hash_function_identity(void (*func_ptr)(void),
                                   const uint8_t compile_salt[16],
                                   uint8_t out_hash[32]) {
    uint8_t input[48];
    uint64_t addr = (uint64_t)(uintptr_t)func_ptr;

    memcpy(input, &addr, sizeof(addr));
    memcpy(input + 8, compile_salt, 16);
    memset(input + 24, 0, 24);

    for (int i = 0; i < 16; i++) {
        input[24 + i] = LABEL_FUNC[i];
    }

    cprisk_sha256(input, 48, out_hash);
    cprisk_secure_zero(input, sizeof(input));
}

int vm_wb_derive_root_key(const uint8_t device_binding[32],
                          const uint8_t whitebox_key[32],
                          uint8_t out_root_key[32]) {
    if (!device_binding || !whitebox_key || !out_root_key) {
        return VM_WB_ERROR_INVALID_PARAM;
    }

    uint8_t derive_input[80];
    memcpy(derive_input, device_binding, 32);
    memcpy(derive_input + 32, whitebox_key, 32);
    memcpy(derive_input + 64, LABEL_ROOT, 16);

    cprisk_sha256(derive_input, 80, out_root_key);

    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);
    cprisk_sha256_update(&ctx, out_root_key, 32);
    cprisk_sha256_update(&ctx, derive_input, 80);
    cprisk_sha256_final(&ctx, out_root_key);

    cprisk_secure_zero(derive_input, sizeof(derive_input));
    return VM_WB_OK;
}

/* 从根密钥派生函数专用密钥
 *
 * 每个受保护函数调用一次
 */
int vm_wb_derive_function_key(const uint8_t root_key[32],
                              uint64_t func_id,
                              uint8_t out_func_key[32]) {
    if (!root_key || !out_func_key) {
        return VM_WB_ERROR_INVALID_PARAM;
    }

    /* 构造派生输入 */
    uint8_t derive_input[56];
    memcpy(derive_input, root_key, 32);
    memcpy(derive_input + 32, &func_id, sizeof(func_id));
    memcpy(derive_input + 40, LABEL_FUNC, 16);

    cprisk_sha256(derive_input, 56, out_func_key);

    cprisk_secure_zero(derive_input, sizeof(derive_input));
    return VM_WB_OK;
}

/* 从函数密钥派生操作密钥
 *
 * 用于特定的VM操作(编码、加解密等)
 */
int vm_wb_derive_operation_key(const uint8_t func_key[32],
                               vm_wb_key_type_t key_type,
                               const uint8_t context[16],
                               uint8_t out_op_key[32]) {
    if (!func_key || !context || !out_op_key) {
        return VM_WB_ERROR_INVALID_PARAM;
    }

    /* 构造派生输入 */
    uint8_t derive_input[64];
    memcpy(derive_input, func_key, 32);
    derive_input[32] = (uint8_t)key_type;
    memcpy(derive_input + 33, context, 16);
    memcpy(derive_input + 49, LABEL_OP, 15);

    cprisk_sha256(derive_input, 64, out_op_key);

    cprisk_secure_zero(derive_input, sizeof(derive_input));
    return VM_WB_OK;
}

/* 初始化VM的完整密钥派生
 *
 * 一键派生所有VM参数
 */
int vm_wb_init_vm_keys(const vm_wb_binding_params_t *params,
                       vm_wb_derived_keys_t *out_keys) {
    if (!params || !out_keys) {
        return VM_WB_ERROR_INVALID_PARAM;
    }

    /* 派生根密钥 */
    uint8_t root_key[32];
    int ret = vm_wb_derive_root_key(params->device_binding,
                                     params->whitebox_key,
                                     root_key);
    if (ret != VM_WB_OK) {
        return ret;
    }

    /* 派生函数专用密钥 */
    ret = vm_wb_derive_function_key(root_key, params->func_id, out_keys->func_key);
    if (ret != VM_WB_OK) {
        cprisk_secure_zero(root_key, sizeof(root_key));
        return ret;
    }

    /* 派生各类操作密钥 */
    uint8_t context[16];
    memset(context, 0, sizeof(context));
    memcpy(context, &params->func_id, sizeof(params->func_id));

    /* 字节码编码密钥 */
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_BYTECODE,
                                context,
                                out_keys->bytecode_key);

    /* 栈加密密钥 */
    context[0] ^= 0x01;
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_STACK,
                                context,
                                out_keys->stack_key);

    /* 内存加密密钥 */
    context[0] ^= 0x02;
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_MEMORY,
                                context,
                                out_keys->memory_key);

    /* 完整性校验密钥 */
    context[0] ^= 0x03;
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_INTEGRITY,
                                context,
                                out_keys->integrity_key);

    /* 反调试密钥 */
    context[0] ^= 0x04;
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_ANTIDEBUG,
                                context,
                                out_keys->antidebug_key);

    /* 毒化密钥 */
    context[0] ^= 0x05;
    vm_wb_derive_operation_key(out_keys->func_key,
                                VM_WB_KEY_POISON,
                                context,
                                out_keys->poison_key);

    /* 导出func_id */
    out_keys->func_id = params->func_id;

    /* 清理中间密钥 */
    cprisk_secure_zero(root_key, sizeof(root_key));

    return VM_WB_OK;
}

/* 派生编码专用参数
 *
 * 从字节码密钥派生具体的编码参数
 */
void vm_wb_derive_encoding_params(const uint8_t bytecode_key[32],
                                  vm_wb_encoding_params_t *out_params) {
    if (!bytecode_key || !out_params) {
        return;
    }

    /* 操作码异或密钥: 前4字节 */
    out_params->opcode_xor_key = 0;
    for (int i = 0; i < 4; i++) {
        out_params->opcode_xor_key |= ((uint32_t)bytecode_key[i]) << (i * 8);
    }

    /* 操作数盐值: 第4-11字节 */
    out_params->operand_salt = 0;
    for (int i = 0; i < 8; i++) {
        out_params->operand_salt |= ((uint64_t)bytecode_key[i + 4]) << (i * 8);
    }

    /* 调度种子: 第12-19字节 */
    out_params->dispatch_seed = 0;
    for (int i = 0; i < 8; i++) {
        out_params->dispatch_seed |= ((uint64_t)bytecode_key[i + 12]) << (i * 8);
    }

    /* 置换表种子: 第20-27字节 */
    out_params->perm_seed = 0;
    for (int i = 0; i < 8; i++) {
        out_params->perm_seed |= ((uint64_t)bytecode_key[i + 20]) << (i * 8);
    }

    /* 流加密密钥: 第28-32字节复制扩展 */
    memcpy(out_params->stream_key, bytecode_key + 24, 8);
    /* 扩展填充 */
    for (int i = 8; i < 32; i++) {
        out_params->stream_key[i] = bytecode_key[i % 8] ^ (uint8_t)i;
    }
}

/* 派生栈加密参数
 *
 * 从栈密钥派生具体的栈加密参数
 */
void vm_wb_derive_stack_params(const uint8_t stack_key[32],
                               uint64_t func_id,
                               vm_wb_stack_params_t *out_params) {
    if (!stack_key || !out_params) {
        return;
    }

    /* 异或密钥: 前8字节与func_id混合 */
    out_params->stack_xor_key = 0;
    for (int i = 0; i < 8; i++) {
        out_params->stack_xor_key |= ((uint64_t)stack_key[i]) << (i * 8);
    }
    out_params->stack_xor_key ^= func_id;

    /* 旋转量: 第8字节取低6位 */
    out_params->stack_rot = stack_key[8] & 0x3F;
    if (out_params->stack_rot < 8) {
        out_params->stack_rot = 8 + (stack_key[8] & 0x07);
    }

    /* 偏移量: 第9-16字节 */
    out_params->stack_offset = 0;
    for (int i = 0; i < 8; i++) {
        out_params->stack_offset |= ((uint64_t)stack_key[i + 9]) << (i * 8);
    }
    out_params->stack_offset ^= (func_id << 1);

    /* 次级密钥: 第17-24字节 */
    out_params->secondary_key = 0;
    for (int i = 0; i < 8; i++) {
        out_params->secondary_key |= ((uint64_t)stack_key[i + 17]) << (i * 8);
    }
    out_params->secondary_key ^= (func_id >> 1);
}

/* 生成毒化值
 *
 * 从毒化密钥派生特定用途的毒化值
 */
uint64_t vm_wb_derive_poison_value(const uint8_t poison_key[32],
                                    vm_wb_poison_type_t poison_type) {
    if (!poison_key) {
        return 0xDEADBEEFCAFEBABEULL;
    }

    /* 简单派生: 密钥异或 + 类型偏移 */
    uint64_t poison = 0;
    for (int i = 0; i < 8; i++) {
        poison |= ((uint64_t)poison_key[i + (uint8_t)poison_type]) << (i * 8);
    }

    /* 混合类型标识 */
    poison ^= ((uint64_t)poison_type << 56);
    poison ^= 0xDEADBEEFCAFEBABEULL;

    return poison;
}

/* 安全清除派生密钥 */
void vm_wb_clear_derived_keys(vm_wb_derived_keys_t *keys) {
    if (keys) {
        cprisk_secure_zero(keys, sizeof(*keys));
    }
}
