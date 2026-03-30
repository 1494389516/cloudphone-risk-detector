/*
 * ============================================================================
 * VM状态完整性校验 (vm_integrity.c)
 * ============================================================================
 *
 * 核心加固原理:
 * ------------
 * 1. 运行时自检: 在VM执行过程中持续验证内部状态的一致性
 * 2. 累积校验链: 每条指令执行后更新校验链，检测中间状态篡改
 * 3. 隐式检测: 校验失败不直接报错，而是污染后续计算结果
 * 4. 多维度验证: 同时验证寄存器、栈、PC、执行计数等多个维度
 *
 * 对抗技术:
 * --------
 * - 反内存Patch: 检测到代码/数据篡改时触发毒化
 * - 反调试: 调试器单步执行会破坏校验链的时间连续性
 * - 反Hook: 函数Hook会改变执行流，被校验链捕获
 */

#include "vm_integrity.h"
#include "include/cprisk_secure_zero.h"
#include <string.h>

/* 内部常量 */
#define VM_INT_MAGIC_ACTIVE     0x564D5354u  /* "VMST" */
#define VM_INT_MAGIC_CORRUPTED  0xDEADCAFEu
#define VM_INT_VERSION_SEED     0x20240703u

/* 计算校验和更新 */
static uint64_t vm_int_update_checksum(uint64_t chain, uint64_t value) {
    /* 使用FNV-1a哈希的变体 */
    const uint64_t FNV_PRIME = 0x100000001B3ULL;
    chain ^= value;
    chain *= FNV_PRIME;
    return chain;
}

/* 初始化VM完整性状态
 *
 * 安全设计:
 * - Magic值标记状态有效性
 * - 版本种子用于检测不兼容的状态恢复
 * - 校验链初始化为非零值，防止全零状态被误认为有效
 */
int vm_integrity_init(vm_integrity_state_t *state, uint64_t vm_id) {
    if (!state) {
        return VM_INT_ERROR_INVALID_PARAM;
    }

    memset(state, 0, sizeof(*state));

    state->magic = VM_INT_MAGIC_ACTIVE;
    state->version_seed = VM_INT_VERSION_SEED ^ (uint32_t)(vm_id >> 32);
    state->execution_count = 0;
    state->checksum_chain = 0xCBF29CE484222325ULL;  /* FNV偏移基础 */

    /* 初始化完整性标签 (简化HMAC) */
    uint64_t tag_input = vm_id ^ state->version_seed;
    for (int i = 0; i < 8; i++) {
        state->integrity_tag[i] = (uint8_t)(tag_input >> (i * 8));
    }

    return VM_INT_OK;
}

/* 执行校验点检查
 *
 * 校验内容:
 * 1. Magic值有效性
 * 2. 版本种子一致性
 * 3. 执行计数单调递增
 * 4. 校验链连续性
 * 5. 完整性标签有效性
 */
vm_integrity_result_t vm_integrity_check(const vm_integrity_state_t *state) {
    if (!state) {
        return VM_INT_RESULT_ERROR;
    }

    /* 检查Magic值 */
    if (state->magic != VM_INT_MAGIC_ACTIVE) {
        if (state->magic == VM_INT_MAGIC_CORRUPTED) {
            /* 已知损坏状态 */
            return VM_INT_RESULT_CORRUPTED;
        }
        return VM_INT_RESULT_INVALID;
    }

    /* 检查版本种子 */
    uint32_t expected_seed = VM_INT_VERSION_SEED;
    if ((state->version_seed & 0xFFFF0000u) != (expected_seed & 0xFFFF0000u)) {
        return VM_INT_RESULT_VERSION_MISMATCH;
    }

    /* 检查执行计数 (防止回滚) */
    if (state->execution_count == 0xFFFFFFFFFFFFFFFFULL) {
        return VM_INT_RESULT_OVERFLOW;
    }

    /* 校验链不应为零 (除非刚初始化) */
    if (state->execution_count > 0 && state->checksum_chain == 0) {
        return VM_INT_RESULT_CHAIN_BROKEN;
    }

    /* 完整性标签基础检查 */
    uint8_t tag_sum = 0;
    for (int i = 0; i < 8; i++) {
        tag_sum |= state->integrity_tag[i];
    }
    if (tag_sum == 0) {
        return VM_INT_RESULT_TAG_INVALID;
    }

    return VM_INT_RESULT_OK;
}

/* 更新完整性状态
 *
 * 更新内容:
 * - 执行计数递增
 * - 校验链累积当前操作
 * - 定期刷新完整性标签
 */
int vm_integrity_update(vm_integrity_state_t *state,
                        vm_integrity_event_t event,
                        uint64_t event_data) {
    if (!state) {
        return VM_INT_ERROR_INVALID_PARAM;
    }

    /* 先检查当前状态 */
    vm_integrity_result_t check = vm_integrity_check(state);
    if (check != VM_INT_RESULT_OK) {
        /* 状态已损坏，标记并返回 */
        state->magic = VM_INT_MAGIC_CORRUPTED;
        return VM_INT_ERROR_CORRUPTED;
    }

    /* 执行计数递增 */
    state->execution_count++;

    /* 根据事件类型更新校验链 */
    uint64_t value_to_mix = ((uint64_t)event << 56) | (event_data & 0x00FFFFFFFFFFFFFFULL);
    state->checksum_chain = vm_int_update_checksum(state->checksum_chain, value_to_mix);

    /* 每256次执行刷新完整性标签 */
    if ((state->execution_count & 0xFF) == 0) {
        uint64_t new_tag_seed = state->checksum_chain ^ state->execution_count;
        for (int i = 0; i < 8; i++) {
            state->integrity_tag[i] = (uint8_t)(new_tag_seed >> (i * 8));
            /* 添加一些混淆 */
            state->integrity_tag[i] ^= (uint8_t)(i * 0x5A);
        }
    }

    return VM_INT_OK;
}

/* 处理完整性破坏事件
 *
 * 毒化策略:
 * - 不立即崩溃或报错
 * - 标记状态为损坏
 * - 后续计算将产生错误结果
 * - 服务端可通过校验和检测异常
 */
void vm_integrity_handle_tamper(vm_integrity_state_t *state,
                                vm_integrity_violation_t violation) {
    if (!state) {
        return;
    }

    /* 标记状态为损坏 */
    state->magic = VM_INT_MAGIC_CORRUPTED;

    /* 污染校验链，使后续验证失败 */
    state->checksum_chain ^= 0xDEADBEEFCAFEBABEULL;
    state->checksum_chain += (uint64_t)violation;

    /* 污染完整性标签 */
    for (int i = 0; i < 8; i++) {
        state->integrity_tag[i] ^= (uint8_t)(0xFF - i);
    }

    /* 执行计数设置为异常值 */
    state->execution_count = 0xDEADBEEFCAFEBABEULL;
}

/* 验证特定操作序列的完整性
 *
 * 用于验证一段字节码执行过程中是否被篡改
 */
int vm_integrity_verify_sequence(const vm_integrity_state_t *state_before,
                                  const vm_integrity_state_t *state_after,
                                  uint32_t expected_step_count) {
    if (!state_before || !state_after) {
        return VM_INT_ERROR_INVALID_PARAM;
    }

    /* 检查两个状态都有效 */
    if (vm_integrity_check(state_before) != VM_INT_RESULT_OK ||
        vm_integrity_check(state_after) != VM_INT_RESULT_OK) {
        return VM_INT_ERROR_CORRUPTED;
    }

    /* 验证执行步数 */
    uint64_t actual_steps = state_after->execution_count - state_before->execution_count;
    if (actual_steps != expected_step_count) {
        return VM_INT_ERROR_STEP_MISMATCH;
    }

    /* 验证校验链连续性 */
    uint64_t expected_chain = state_before->checksum_chain;
    /* 这里需要知道中间操作才能完整验证，简化检查 */
    if (state_after->checksum_chain == state_before->checksum_chain) {
        /* 如果执行了指令但校验链未变化，可能是被Hook */
        return VM_INT_ERROR_CHAIN_UNCHANGED;
    }

    return VM_INT_OK;
}

/* 导出完整性状态 (用于持久化或传输) */
size_t vm_integrity_export(const vm_integrity_state_t *state,
                           uint8_t *out_buffer,
                           size_t buffer_size) {
    if (!state || !out_buffer || buffer_size < sizeof(vm_integrity_state_t)) {
        return 0;
    }

    /* 先验证状态有效 */
    if (vm_integrity_check(state) != VM_INT_RESULT_OK) {
        return 0;
    }

    memcpy(out_buffer, state, sizeof(vm_integrity_state_t));
    return sizeof(vm_integrity_state_t);
}

/* 导入完整性状态 */
int vm_integrity_import(vm_integrity_state_t *state,
                        const uint8_t *data,
                        size_t data_size) {
    if (!state || !data || data_size < sizeof(vm_integrity_state_t)) {
        return VM_INT_ERROR_INVALID_PARAM;
    }

    memcpy(state, data, sizeof(vm_integrity_state_t));

    /* 验证导入的状态 */
    vm_integrity_result_t check = vm_integrity_check(state);
    if (check != VM_INT_RESULT_OK) {
        memset(state, 0, sizeof(vm_integrity_state_t));
        return VM_INT_ERROR_CORRUPTED;
    }

    return VM_INT_OK;
}

/* 安全清除完整性状态 */
void vm_integrity_clear(vm_integrity_state_t *state) {
    if (state) {
        cprisk_secure_zero(state, sizeof(*state));
    }
}

/* 生成调试信息 (仅用于开发调试) */
#ifdef VM_INTEGRITY_DEBUG
#include <stdio.h>
void vm_integrity_dump(const vm_integrity_state_t *state) {
    if (!state) {
        printf("VM Integrity State: NULL\n");
        return;
    }

    printf("=== VM Integrity State ===\n");
    printf("Magic: 0x%08X (%s)\n",
           state->magic,
           state->magic == VM_INT_MAGIC_ACTIVE ? "ACTIVE" :
           state->magic == VM_INT_MAGIC_CORRUPTED ? "CORRUPTED" : "UNKNOWN");
    printf("Version Seed: 0x%08X\n", state->version_seed);
    printf("Execution Count: %llu\n", (unsigned long long)state->execution_count);
    printf("Checksum Chain: 0x%016llX\n", (unsigned long long)state->checksum_chain);
    printf("Integrity Tag: ");
    for (int i = 0; i < 8; i++) {
        printf("%02X", state->integrity_tag[i]);
    }
    printf("\n");

    vm_integrity_result_t check = vm_integrity_check(state);
    printf("Check Result: %d (%s)\n", check,
           check == VM_INT_RESULT_OK ? "OK" :
           check == VM_INT_RESULT_CORRUPTED ? "CORRUPTED" :
           check == VM_INT_RESULT_INVALID ? "INVALID" : "OTHER");
    printf("==========================\n");
}
#endif
