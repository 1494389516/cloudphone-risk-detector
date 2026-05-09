// MARK: - GF(2) 128-bit Affine Transform
//
// 借鉴自小红书 x-mini-sig 的 transform_16 设计：在 GF(2)（二元域）上对 128-bit 输入做
// 128×128 矩阵乘法 + 平移向量 = 仿射变换。
//
// 数学上：output[i] = (Σⱼ matrix[i][j] · input[j]) ⊕ translation[i]   （所有运算在 GF(2)）
//
// 等价于 16×8 = 128 个独立的 popcount-parity 计算。
//
// 防御价值：
//  1. 算法本身在汇编层面只产生 AND / XOR / popcount，没有可识别的密码学常量
//     （没有 S-box、没有循环结构、没有魔数），混在花指令里几乎无法被静态识别。
//  2. 若用作完整性 hash 的后处理层（hash → transform_16），攻击者即使用常量替换了
//     SHA-256 的实现也得不到正确的 transform 输出 — 必须同时还原 128×128 矩阵。
//  3. 矩阵运行时由固定种子 + xorshift64 生成，编译产物的 .rodata 里没有矩阵字节，
//     攻击者必须在内存里 dump 出 BSS 段才能拿到矩阵。

#include "include/CRiskCore.h"

#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define CPRISK_GF2_MATRIX_BYTES         2048u   // 128 行 × 16 字节
#define CPRISK_GF2_TRANSLATION_BYTES    16u

// 矩阵和平移向量在 BSS — 由 init_once 用 xorshift64 从下面的种子生成。
static uint8_t kCpriskGf2Matrix[CPRISK_GF2_MATRIX_BYTES];
static uint8_t kCpriskGf2Translation[CPRISK_GF2_TRANSLATION_BYTES];
// 初始化后立即记录的 FNV-1a 校验值；self_check 时重新计算并比对。
static uint64_t kCpriskGf2InitChecksum = 0u;

static pthread_once_t kCpriskGf2InitOnce = PTHREAD_ONCE_INIT;

// 种子常量。该值唯一影响矩阵内容，不影响算法正确性。
static const uint64_t kCpriskGf2InitSeed = 0xCAFEBABEDEADBEEFULL;

static uint64_t cprisk_gf2_xorshift64(uint64_t s) {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
}

static uint64_t cprisk_gf2_fnv1a(const uint8_t *data, size_t len) {
    uint64_t h = 0xcbf29ce484222325ULL;  // FNV-1a 64-bit offset basis
    for (size_t i = 0u; i < len; ++i) {
        h ^= (uint64_t)data[i];
        h *= 0x100000001b3ULL;            // FNV-1a 64-bit prime
    }
    return h;
}

// Exposed via public CRiskCore.h + visibility("default") so the symbol survives
// `-fvisibility=hidden` and Release strip — armor CFF/VMP policies target this name.
// Removing `static` alone is NOT sufficient under -fvisibility=hidden (which makes
// non-static functions N_PEXT and dead-strippable); the explicit attribute promotes
// to N_EXT. v7.7 audit-fix F1+F4 (post-1st-pass: comment was wrong about the mechanism).
// FNV-1a basis/prime are materialized as immediates here — VMP partial covers them.
__attribute__((visibility("default")))
uint64_t cprisk_gf2_compute_full_checksum(void) {
    // 链式 FNV：先 matrix 再 translation，保证两者都被覆盖。
    uint64_t h = cprisk_gf2_fnv1a(kCpriskGf2Matrix, CPRISK_GF2_MATRIX_BYTES);
    // 用 matrix hash 当 translation 的 offset basis 续算
    for (size_t i = 0u; i < CPRISK_GF2_TRANSLATION_BYTES; ++i) {
        h ^= (uint64_t)kCpriskGf2Translation[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

// Exposed via public CRiskCore.h + visibility("default") so the symbol survives
// `-fvisibility=hidden` and Release strip — armor CFF/VMP policies target this name.
// Removing `static` alone is NOT sufficient under -fvisibility=hidden (which makes
// non-static functions N_PEXT and dead-strippable); the explicit attribute promotes
// to N_EXT. v7.7 audit-fix F1+F4 (post-1st-pass: comment was wrong about the mechanism).
// Seed kCpriskGf2InitSeed (0xCAFEBABEDEADBEEFULL) is materialized as immediate here —
// VMP partial walks it through VPC to defeat constant-search matrix recovery.
__attribute__((visibility("default")))
void cprisk_gf2_init_real(void) {
    uint64_t s = kCpriskGf2InitSeed;
    for (size_t i = 0u; i < CPRISK_GF2_MATRIX_BYTES; ++i) {
        s = cprisk_gf2_xorshift64(s);
        kCpriskGf2Matrix[i] = (uint8_t)(s & 0xFFu);
    }
    for (size_t i = 0u; i < CPRISK_GF2_TRANSLATION_BYTES; ++i) {
        s = cprisk_gf2_xorshift64(s);
        kCpriskGf2Translation[i] = (uint8_t)(s & 0xFFu);
    }
    kCpriskGf2InitChecksum = cprisk_gf2_compute_full_checksum();
}

static inline void cprisk_gf2_init_if_needed(void) {
    pthread_once(&kCpriskGf2InitOnce, cprisk_gf2_init_real);
}

// 计算 (a & b) 的 GF(2) 内积奇偶性（popcount mod 2）。
// 用 __builtin_parityll，编译器在 ARM64 上会发 popcount + AND 1，没有循环。
static inline uint8_t cprisk_gf2_inner_parity_128(
    const uint8_t row[16],
    const uint8_t input[16]
) {
    uint64_t row_lo, row_hi, in_lo, in_hi;
    memcpy(&row_lo, row, sizeof(row_lo));
    memcpy(&row_hi, row + 8, sizeof(row_hi));
    memcpy(&in_lo, input, sizeof(in_lo));
    memcpy(&in_hi, input + 8, sizeof(in_hi));
    uint64_t and_lo = row_lo & in_lo;
    uint64_t and_hi = row_hi & in_hi;
    return (uint8_t)((unsigned)__builtin_parityll(and_lo) ^ (unsigned)__builtin_parityll(and_hi));
}

// 公开 API：对 128-bit 输入做 GF(2) 仿射变换。
// 矩阵参数为可选：matrix==NULL 时使用 SDK 默认矩阵（运行时由种子生成）。
// translation==NULL 时使用 SDK 默认平移向量。
//
// 注意：input 与 output 可以是同一缓冲区（先全部读到栈上局部变量再写出）。
void cprisk_gf2_affine_transform_16(
    uint8_t output[16],
    const uint8_t input[16],
    const uint8_t *matrix,        // 2048 bytes (128×16); NULL = default
    const uint8_t *translation    // 16 bytes; NULL = default
) {
    if (output == NULL || input == NULL) {
        return;
    }

    cprisk_gf2_init_if_needed();

    const uint8_t *m = matrix != NULL ? matrix : kCpriskGf2Matrix;
    const uint8_t *t = translation != NULL ? translation : kCpriskGf2Translation;

    // 先把 input 拷贝到栈上的本地缓冲区，允许 input == output 的别名调用。
    uint8_t local_input[16];
    memcpy(local_input, input, sizeof(local_input));

    uint8_t result[16];
    memset(result, 0, sizeof(result));

    for (int row = 0; row < 128; ++row) {
        const uint8_t *row_ptr = m + (row * 16);
        uint8_t parity = cprisk_gf2_inner_parity_128(row_ptr, local_input);
        if (parity) {
            // 输出 bit 编号：row / 8 是字节索引；7 - (row % 8) 是该字节内的 bit（高位优先）。
            int byte_idx = row / 8;
            int bit_idx  = 7 - (row % 8);
            result[byte_idx] = (uint8_t)(result[byte_idx] | (uint8_t)(1u << bit_idx));
        }
    }

    for (int j = 0; j < 16; ++j) {
        result[j] ^= t[j];
    }

    memcpy(output, result, sizeof(result));
}

// 自校验：对运行时矩阵 + 平移向量做 FNV-1a，与 init 时记录的值比对。
// 攻击者修改 .bss 任意一字节都会导致 mismatch。
// 返回 0 = OK，非零 = 矩阵被篡改。
int cprisk_gf2_affine_self_check(void) {
    cprisk_gf2_init_if_needed();
    uint64_t now = cprisk_gf2_compute_full_checksum();
    return (now == kCpriskGf2InitChecksum) ? 0 : 1;
}
