/*
 * ============================================================================
 * VM与白盒PRF深度绑定头文件 (vm_whitebox_bind.h)
 * ============================================================================
 */

#ifndef VM_WHITEBOX_BIND_H
#define VM_WHITEBOX_BIND_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 密钥类型枚举 */
typedef enum {
    VM_WB_KEY_BYTECODE = 0,     /* 字节码编码密钥 */
    VM_WB_KEY_STACK = 1,        /* 栈加密密钥 */
    VM_WB_KEY_MEMORY = 2,       /* 内存加密密钥 */
    VM_WB_KEY_INTEGRITY = 3,    /* 完整性校验密钥 */
    VM_WB_KEY_ANTIDEBUG = 4,    /* 反调试密钥 */
    VM_WB_KEY_POISON = 5        /* 毒化值派生密钥 */
} vm_wb_key_type_t;

/* 毒化值类型 */
typedef enum {
    VM_WB_POISON_SCORE = 0,     /* 评分毒化 */
    VM_WB_POISON_DEVICE_ID = 1, /* 设备ID毒化 */
    VM_WB_POISON_REPORT = 2,    /* 报告毒化 */
    VM_WB_POISON_CONFIG = 3,    /* 配置毒化 */
    VM_WB_POISON_RANDOM = 4     /* 随机毒化 */
} vm_wb_poison_type_t;

/* 绑定参数结构体 */
typedef struct {
    uint64_t func_id;                    /* 函数标识符 */
    uint8_t device_binding[32];          /* 设备绑定值 */
    uint8_t whitebox_key[32];            /* 白盒根密钥 */
} vm_wb_binding_params_t;

/* 派生密钥集合 */
typedef struct {
    uint64_t func_id;                    /* 函数ID */
    uint8_t func_key[32];                /* 函数专用密钥 */
    uint8_t bytecode_key[32];            /* 字节码密钥 */
    uint8_t stack_key[32];               /* 栈加密密钥 */
    uint8_t memory_key[32];              /* 内存加密密钥 */
    uint8_t integrity_key[32];           /* 完整性密钥 */
    uint8_t antidebug_key[32];           /* 反调试密钥 */
    uint8_t poison_key[32];              /* 毒化密钥 */
} vm_wb_derived_keys_t;

/* 编码参数 */
typedef struct {
    uint32_t opcode_xor_key;             /* 操作码异或密钥 */
    uint64_t operand_salt;               /* 操作数盐值 */
    uint64_t dispatch_seed;              /* 调度种子 */
    uint64_t perm_seed;                  /* 置换表种子 */
    uint8_t  stream_key[32];             /* 流加密密钥 */
} vm_wb_encoding_params_t;

/* 栈加密参数 */
typedef struct {
    uint64_t stack_xor_key;              /* 栈异或密钥 */
    uint8_t  stack_rot;                  /* 旋转量 */
    uint64_t stack_offset;               /* 偏移量 */
    uint64_t secondary_key;              /* 次级密钥 */
} vm_wb_stack_params_t;

/* 错误码 */
typedef enum {
    VM_WB_OK = 0,
    VM_WB_ERROR_INVALID_PARAM = -1,
    VM_WB_ERROR_DERIVE_FAILED = -2,
    VM_WB_ERROR_NOT_INITIALIZED = -3
} vm_wb_error_t;

/* 计算函数身份哈希
 *
 * 生成函数的唯一标识
 */
void vm_wb_hash_function_identity(void (*func_ptr)(void),
                                   const uint8_t compile_salt[16],
                                   uint8_t out_hash[32]);

/* 派生根密钥 */
int vm_wb_derive_root_key(const uint8_t device_binding[32],
                          const uint8_t whitebox_key[32],
                          uint8_t out_root_key[32]);

/* 派生函数专用密钥 */
int vm_wb_derive_function_key(const uint8_t root_key[32],
                              uint64_t func_id,
                              uint8_t out_func_key[32]);

/* 派生操作密钥 */
int vm_wb_derive_operation_key(const uint8_t func_key[32],
                               vm_wb_key_type_t key_type,
                               const uint8_t context[16],
                               uint8_t out_op_key[32]);

/* 初始化完整VM密钥派生 */
int vm_wb_init_vm_keys(const vm_wb_binding_params_t *params,
                       vm_wb_derived_keys_t *out_keys);

/* 派生编码参数 */
void vm_wb_derive_encoding_params(const uint8_t bytecode_key[32],
                                  vm_wb_encoding_params_t *out_params);

/* 派生栈加密参数 */
void vm_wb_derive_stack_params(const uint8_t stack_key[32],
                               uint64_t func_id,
                               vm_wb_stack_params_t *out_params);

/* 生成毒化值 */
uint64_t vm_wb_derive_poison_value(const uint8_t poison_key[32],
                                    vm_wb_poison_type_t poison_type);

/* 安全清除派生密钥 */
void vm_wb_clear_derived_keys(vm_wb_derived_keys_t *keys);

#ifdef __cplusplus
}
#endif

#endif /* VM_WHITEBOX_BIND_H */
