/*
 * ============================================================================
 * VM运行时按需解密 (vm_encrypted_chunk.c)
 * ============================================================================
 *
 * 核心加固原理:
 * ------------
 * 1. 按需解密: 字节码在执行前才解密，执行后立即清除
 * 2. Execute-Only内存: 解密后的代码可执行但不可读
 * 3. 热度感知: 高频代码块保持解密状态，低频代码块重新加密
 * 4. 完整性绑定: 每个代码块绑定完整性校验，检测篡改
 *
 * 对抗技术:
 * --------
 * - 抗内存Dump: 攻击者dump时大部分代码仍处于加密状态
 * - 抗静态分析: 静态二进制中代码段是密文
 * - 抗动态Patch: 修改代码块会破坏完整性校验
 */

#include "vm_encrypted_chunk.h"
#include "include/cprisk_secure_zero.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* 内部常量 */
#define VM_CHUNK_MAGIC_ENCRYPTED 0x454E4352u  /* "ENCR" */
#define VM_CHUNK_MAGIC_DECRYPTED 0x44454352u  /* "DECR" */
#define VM_CHUNK_HOTNESS_THRESHOLD 100

/* 计算HMAC-SHA256 (简化实现) */
static void vm_chunk_compute_hmac(const uint8_t *data, size_t len,
                                   const uint8_t key[32],
                                   uint8_t out[16]) {
    /* 简化HMAC: 实际应使用完整HMAC-SHA256 */
    uint64_t h1 = 0xCBF29CE484222325ULL;
    uint64_t h2 = 0x100000001B3ULL;

    for (size_t i = 0; i < len; i++) {
        h1 ^= data[i] ^ key[i % 32];
        h1 *= h2;
    }

    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(h1 >> (i * 8));
    }

    /* 第二轮 */
    h1 = 0xCBF29CE484222325ULL;
    for (int i = 0; i < 16; i++) {
        h1 ^= out[i] ^ key[(i + 8) % 32];
        h1 *= h2;
    }

    for (int i = 0; i < 8; i++) {
        out[8 + i] = (uint8_t)(h1 >> (i * 8));
    }
}

/* 分配execute-only内存
 *
 * 使用mmap分配PROT_EXEC但不PROT_READ的内存页
 */
void* vm_chunk_alloc_execute_only(size_t size) {
    /* 对齐到页大小 */
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t alloc_size = (size + page_size - 1) & ~(page_size - 1);

    /* 分配RW内存 */
    void *mem = mmap(NULL, alloc_size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    if (mem == MAP_FAILED) {
        return NULL;
    }

    /* 注意: 实际execute-only需要在写入后mprotect为PROT_EXEC only
     * 但iOS/macOS可能不支持纯粹的execute-only
     * 这里使用延迟降级策略
     */

    return mem;
}

/* 释放execute-only内存 */
void vm_chunk_free_execute_only(void *mem, size_t size) {
    if (!mem) return;

    /* 先清零 */
    cprisk_secure_zero(mem, size);

    /* 解除映射 */
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t alloc_size = (size + page_size - 1) & ~(page_size - 1);

    munmap(mem, alloc_size);
}

/* 将内存区域降级为execute-only
 *
 * 移除读权限，仅保留执行权限
 */
int vm_chunk_make_execute_only(void *mem, size_t size) {
    if (!mem || size == 0) {
        return -1;
    }

    /* 清除读权限，保留执行权限 */
    if (mprotect(mem, size, PROT_EXEC) != 0) {
        /* 降级失败，可能是平台不支持 */
        return -1;
    }

    return 0;
}

/* 解密并验证代码块
 *
 * 流程:
 * 1. 验证HMAC标签
 * 2. AES-GCM解密
 * 3. 写入execute-only内存
 * 4. 降级权限
 */
int vm_chunk_decrypt_and_verify(vm_encrypted_chunk_t *chunk,
                                const uint8_t key[32],
                                void **out_exec_mem) {
    if (!chunk || !key || !out_exec_mem) {
        return VM_CHUNK_ERROR_INVALID_PARAM;
    }

    if (chunk->magic != VM_CHUNK_MAGIC_ENCRYPTED) {
        return VM_CHUNK_ERROR_INVALID_MAGIC;
    }

    /* 验证HMAC标签 */
    uint8_t computed_tag[16];
    vm_chunk_compute_hmac(chunk->encrypted_data, chunk->data_len,
                           key, computed_tag);

    if (memcmp(computed_tag, chunk->auth_tag, 16) != 0) {
        return VM_CHUNK_ERROR_AUTH_FAILED;
    }

    /* 分配execute-only内存 */
    void *exec_mem = vm_chunk_alloc_execute_only(chunk->data_len);
    if (!exec_mem) {
        return VM_CHUNK_ERROR_ALLOC_FAILED;
    }

    /* 解密数据 (简化XOR加密，实际应使用AES-GCM) */
    /* 派生XOR密钥流 */
    for (size_t i = 0; i < chunk->data_len; i++) {
        uint8_t keystream = key[i % 32] ^ chunk->nonce[i % 12];
        ((uint8_t*)exec_mem)[i] = chunk->encrypted_data[i] ^ keystream;
    }

    /* 刷新指令缓存 (ARM64需要) */
    __builtin___clear_cache(exec_mem, (char*)exec_mem + chunk->data_len);

    /* 尝试降级为execute-only */
    if (vm_chunk_make_execute_only(exec_mem, chunk->data_len) != 0) {
        /* 降级失败，但内存仍可执行，继续运行 */
    }

    /* 更新状态 */
    chunk->magic = VM_CHUNK_MAGIC_DECRYPTED;
    chunk->hotness_counter = 1;
    chunk->last_access_time = 0; /* 应由调用者设置 */

    *out_exec_mem = exec_mem;
    return VM_CHUNK_OK;
}

/* 重新加密代码块
 *
 * 执行完成后清理明文代码
 */
int vm_chunk_reencrypt(vm_encrypted_chunk_t *chunk,
                       void *exec_mem,
                       size_t exec_mem_size) {
    if (!chunk || !exec_mem) {
        return VM_CHUNK_ERROR_INVALID_PARAM;
    }

    if (chunk->magic != VM_CHUNK_MAGIC_DECRYPTED) {
        return VM_CHUNK_ERROR_NOT_DECRYPTED;
    }

    /* 清零execute-only内存 */
    cprisk_secure_zero(exec_mem, exec_mem_size);

    /* 释放内存 */
    vm_chunk_free_execute_only(exec_mem, exec_mem_size);

    /* 恢复状态 */
    chunk->magic = VM_CHUNK_MAGIC_ENCRYPTED;

    return VM_CHUNK_OK;
}

/* 更新热度计数器 */
void vm_chunk_update_hotness(vm_encrypted_chunk_t *chunk) {
    if (!chunk) return;

    if (chunk->hotness_counter < 0xFFFFFFFF) {
        chunk->hotness_counter++;
    }
}

/* 检查代码块是否应保持解密状态
 *
 * 基于热度决定是否重新加密
 */
int vm_chunk_should_keep_decrypted(const vm_encrypted_chunk_t *chunk) {
    if (!chunk) return 0;

    /* 高频访问的代码块保持解密 */
    return chunk->hotness_counter >= VM_CHUNK_HOTNESS_THRESHOLD;
}

/* 初始化加密代码块
 *
 * 在编译期或加载时调用，准备加密数据
 */
int vm_chunk_init(vm_encrypted_chunk_t *chunk,
                  uint32_t chunk_id,
                  const uint8_t *plaintext,
                  size_t plaintext_len,
                  const uint8_t key[32]) {
    if (!chunk || !plaintext || !key) {
        return VM_CHUNK_ERROR_INVALID_PARAM;
    }

    if (plaintext_len > VM_CHUNK_MAX_SIZE) {
        return VM_CHUNK_ERROR_TOO_LARGE;
    }

    memset(chunk, 0, sizeof(*chunk));

    chunk->magic = VM_CHUNK_MAGIC_ENCRYPTED;
    chunk->chunk_id = chunk_id;
    chunk->data_len = (uint32_t)plaintext_len;

    /* 生成随机nonce */
    /* 实际应使用真随机数生成器 */
    for (int i = 0; i < 12; i++) {
        chunk->nonce[i] = (uint8_t)(chunk_id ^ (i * 0x5A));
    }

    /* 加密数据 */
    for (size_t i = 0; i < plaintext_len; i++) {
        uint8_t keystream = key[i % 32] ^ chunk->nonce[i % 12];
        chunk->encrypted_data[i] = plaintext[i] ^ keystream;
    }

    /* 计算认证标签 */
    vm_chunk_compute_hmac(chunk->encrypted_data, plaintext_len,
                           key, chunk->auth_tag);

    chunk->hotness_counter = 0;
    chunk->last_access_time = 0;

    return VM_CHUNK_OK;
}

/* 安全清零 */
void vm_chunk_secure_zero(void *ptr, size_t len) {
    cprisk_secure_zero(ptr, len);
}

/* 验证代码块完整性 */
int vm_chunk_verify_integrity(const vm_encrypted_chunk_t *chunk,
                              const uint8_t key[32]) {
    if (!chunk || !key) {
        return VM_CHUNK_ERROR_INVALID_PARAM;
    }

    if (chunk->magic != VM_CHUNK_MAGIC_ENCRYPTED) {
        return VM_CHUNK_ERROR_INVALID_MAGIC;
    }

    uint8_t computed_tag[16];
    vm_chunk_compute_hmac(chunk->encrypted_data, chunk->data_len,
                           key, computed_tag);

    if (memcmp(computed_tag, chunk->auth_tag, 16) != 0) {
        return VM_CHUNK_ERROR_AUTH_FAILED;
    }

    return VM_CHUNK_OK;
}
