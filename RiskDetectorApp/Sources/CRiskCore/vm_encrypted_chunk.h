/*
 * ============================================================================
 * VM运行时按需解码头文件 (vm_encrypted_chunk.h)
 * ============================================================================
 */

#ifndef VM_ENCRYPTED_CHUNK_H
#define VM_ENCRYPTED_CHUNK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 最大代码块大小 (256KB) */
#define VM_CHUNK_MAX_SIZE (256 * 1024)

/* 加密代码块结构体
 *
 * 存储AES-GCM加密的代码块
 */
typedef struct {
    uint32_t magic;              /* 状态魔数 */
    uint32_t chunk_id;           /* 块标识符 */
    uint32_t data_len;           /* 数据长度 */
    uint32_t hotness_counter;    /* 访问热度 */
    uint64_t last_access_time;   /* 最后访问时间 */
    uint8_t  nonce[12];          /* GCM nonce */
    uint8_t  auth_tag[16];       /* 认证标签 */
    uint8_t  encrypted_data[VM_CHUNK_MAX_SIZE]; /* 加密数据 */
} vm_encrypted_chunk_t;

/* 错误码 */
typedef enum {
    VM_CHUNK_OK = 0,
    VM_CHUNK_ERROR_INVALID_PARAM = -1,
    VM_CHUNK_ERROR_INVALID_MAGIC = -2,
    VM_CHUNK_ERROR_AUTH_FAILED = -3,
    VM_CHUNK_ERROR_ALLOC_FAILED = -4,
    VM_CHUNK_ERROR_TOO_LARGE = -5,
    VM_CHUNK_ERROR_NOT_DECRYPTED = -6,
    VM_CHUNK_ERROR_DECRYPT_FAILED = -7
} vm_chunk_error_t;

/* 分配execute-only内存
 *
 * 分配的内存可执行但不可读
 */
void* vm_chunk_alloc_execute_only(size_t size);

/* 释放execute-only内存 */
void vm_chunk_free_execute_only(void *mem, size_t size);

/* 将内存降级为execute-only */
int vm_chunk_make_execute_only(void *mem, size_t size);

/* 初始化加密代码块
 *
 * 编译期调用，准备加密数据
 */
int vm_chunk_init(vm_encrypted_chunk_t *chunk,
                  uint32_t chunk_id,
                  const uint8_t *plaintext,
                  size_t plaintext_len,
                  const uint8_t key[32]);

/* 解密并验证代码块
 *
 * 执行前调用，解密到execute-only内存
 */
int vm_chunk_decrypt_and_verify(vm_encrypted_chunk_t *chunk,
                                const uint8_t key[32],
                                void **out_exec_mem);

/* 重新加密代码块
 *
 * 执行完成后清理
 */
int vm_chunk_reencrypt(vm_encrypted_chunk_t *chunk,
                       void *exec_mem,
                       size_t exec_mem_size);

/* 更新热度计数器 */
void vm_chunk_update_hotness(vm_encrypted_chunk_t *chunk);

/* 检查是否应保持解密状态 */
int vm_chunk_should_keep_decrypted(const vm_encrypted_chunk_t *chunk);

/* 验证代码块完整性 */
int vm_chunk_verify_integrity(const vm_encrypted_chunk_t *chunk,
                              const uint8_t key[32]);

/* 安全清零 */
void vm_chunk_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* VM_ENCRYPTED_CHUNK_H */
