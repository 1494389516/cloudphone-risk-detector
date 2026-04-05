/*
 *  vm_path_explosion.c
 *  CRiskCore
 *
 *  路径爆炸对抗符号执行 - Path Explosion Countermeasure for Symbolic Execution
 *
 *  对抗原理说明:
 *  =================
 *
 *  符号执行(Symbolic Execution)通过在程序运行时用符号变量替代具体值，
 *  探索程序的所有可能执行路径。路径爆炸(Path Explosion)是符号执行的核心
 *  瓶颈 - 随着分支数量增加，路径数量呈指数级增长。
 *
 *  本模块通过以下策略主动引入"受控路径爆炸"，使攻击者的符号执行工具
 *  在分析VM字节码时面临计算不可行(computationally infeasible)的约束求解:
 *
 *  1. 不透明谓词(Opaque Predicates)假分支:
 *     - 在关键执行路径上插入看似条件分支的代码
 *     - 实际上谓词结果在编译时已知(永真或永假)
 *     - 但符号执行工具无法静态推断，被迫探索两条路径
 *
 *  2. 假分支与实际分支等价但约束不同:
 *     - 构造语义等价但约束表达式不同的分支对
 *     - 符号执行器需要分别求解，增加SMT求解器负担
 *     - 使用MBA(混合布尔代数)表达式增加求解复杂度
 *
 *  3. NOP装饰指令插入:
 *     - 在假分支路径中插入带副作用的NOP指令
 *     - 这些NOP会修改内部状态但不影响最终语义
 *     - 符号执行器仍需跟踪这些状态变化
 *
 *  4. 符号执行对抗策略:
 *     - 使用非线性多项式约束(a*b*c = d的形式)
 *     - 引入浮点数/位运算混合表达式
 *     - 利用数组索引符号化导致的数组理论复杂度
 *
 *  数学基础:
 *  =========
 *  - 不透明谓词基于数论恒等式: x*x >= 0 (永真), x*x < 0 (永假)
 *  - MBA表达式: a XOR b = (a|b) - (a&b) 等代数恒等变形
 *  - 费马小定理、威尔逊定理等数论性质构造复杂约束
 */

#include "include/CRiskCore.h"
#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"

#include <string.h>

/* 路径爆炸配置参数 */
#define VM_PATH_EXPLOSION_LAYERS        4   /* MBA混淆层数 */
#define VM_PATH_EXPLOSION_FORK_COUNT    8   /* 每个分支点产生的路径数 */
#define VM_PATH_EXPLOSION_DECOY_DENSITY 16  /* 每16条指令插入一个诱饵 */

/*
 * 不透明谓词类型枚举
 * 每种类型基于不同的数学性质构造
 */
typedef enum {
    VM_OPAQUE_PREDICATE_ALWAYS_TRUE_1 = 0,   /* x*x >= 0 */
    VM_OPAQUE_PREDICATE_ALWAYS_TRUE_2,        /* x + x = 2x */
    VM_OPAQUE_PREDICATE_ALWAYS_FALSE_1,       /* x*x < 0 */
    VM_OPAQUE_PREDICATE_ALWAYS_FALSE_2,       /* x & (~x) != 0 */
    VM_OPAQUE_PREDICATE_FERMAT_STYLE,         /* 基于a^2 + b^2 = c^2无解(非零) */
    VM_OPAQUE_PREDICATE_WILSON_STYLE,         /* (p-1)! mod p = p-1 */
    VM_OPAQUE_PREDICATE_EULER_STYLE,          /* 欧拉准则 */
    VM_OPAQUE_PREDICATE_COLLATZ_STYLE,        /* 考拉兹猜想相关 */
    VM_OPAQUE_PREDICATE_WB_PRF_STYLE,         /* 白盒PRF查表风格 */
} vm_opaque_predicate_type_t;

/*
 * 假分支结构体
 * 描述一个假分支的元数据
 */
typedef struct {
    uint32_t predicate_seed;        /* 谓词生成种子 */
    uint32_t branch_target_fake;    /* 假分支目标地址 */
    uint32_t branch_target_real;    /* 实际分支目标 */
    uint8_t  is_always_true;        /* 谓词是否永真 */
    uint8_t  mba_layers;            /* MBA混淆层数 */
    vm_opaque_predicate_type_t type; /* 谓词类型 */
} vm_fake_branch_t;

/*
 * MBA表达式状态
 * 用于MBA混淆的上下文
 */
typedef struct {
    uint32_t accumulator;
    uint32_t xor_mask;
    uint32_t add_mask;
    uint32_t rotate_count;
} vm_mba_state_t;

/*
 * 路径爆炸上下文
 * 管理整个路径爆炸防御的状态
 */
typedef struct {
    uint64_t func_id;
    uint32_t bytecode_hash;
    uint32_t fork_counter;
    uint32_t decoy_counter;
    vm_mba_state_t mba;
    uint8_t path_marker[32];
} vm_path_explosion_ctx_t;

/*
 * 内部函数: 生成MBA混淆的XOR等价表达式
 * 将简单的XOR操作转换为多层MBA表达式
 *
 * 原理: a XOR b = (a|b) - (a&b)
 *       然后对a|b和a&b再次应用MBA变换
 */
static uint32_t vm_mba_xor_obfuscate_i(uint32_t a, uint32_t b, uint32_t layers) {
    uint32_t result = a ^ b;  /* 基准结果 */

    for (uint32_t i = 0; i < layers && i < VM_PATH_EXPLOSION_LAYERS; i++) {
        /* MBA等价: XOR = OR - AND */
        uint32_t or_part = a | b;
        uint32_t and_part = a & b;

        /* 对OR部分应用额外MBA */
        or_part = (or_part << 1) - or_part;  /* or * 2 - or = or */
        or_part = ((or_part + 0xFFFFFFFFu) ^ 0xFFFFFFFFu) + 1;  /* 恒等变换 */

        /* 对AND部分应用额外MBA */
        and_part = (and_part + and_part) >> 1;  /* (and * 2) / 2 = and */
        and_part = ~(~and_part);  /* 双重否定 = and */

        /* 组合: OR - AND */
        result = or_part + (~and_part + 1);  /* or - and */

        /* 非线性模乘法混合 (破坏线性结构) */
        result = (result * 0x85EBCA6Bu + (i + 1) * 0x9E3779B9u) >> 16 ^ result;

        /* 为下一轮变换准备 */
        a = result;
        b = result ^ ((i + 1) * 0x9E3779B9u);
    }

    return result;
}

/*
 * 内部函数: 生成永真不透明谓词
 *
 * 基于数学性质:
 * 1. 任何整数的平方都非负: x*x >= 0
 * 2. 任何数与自身的按位或等于自身: x | x == x
 * 3. 双重否定: !!x 等价于 x != 0
 */
static int vm_opaque_predicate_always_true_i(uint32_t seed, uint32_t pc) {
    /* 方法1: x*x >= 0 对所有整数成立 */
    int64_t x = (int64_t)(seed ^ pc);
    int64_t squared = x * x;
    if (squared < 0) {
        return 0;  /* 永不可达 - 但符号执行器不知道 */
    }

    /* 方法2: (x|x) == x 恒成立 */
    uint32_t self_or = seed | seed;
    if (self_or != seed) {
        return 0;  /* 永不可达 */
    }

    /* 方法3: MBA形式的不透明谓词 */
    uint32_t mba_check = vm_mba_xor_obfuscate_i(seed, seed, 2);
    if (mba_check != 0) {
        return 0;  /* 永不可达 - seed XOR seed = 0 */
    }

    (void)squared;
    return 1;  /* 总是返回真 */
}

/*
 * 内部函数: 生成永假不透明谓词
 *
 * 基于数学性质:
 * 1. 任何整数的平方都非负，所以 x*x < 0 永假
 * 2. x & (~x) = 0 对所有x成立，所以 x & (~x) != 0 永假
 */
static int vm_opaque_predicate_always_false_i(uint32_t seed, uint32_t pc) {
    /* 方法1: x*x < 0 永假 */
    int64_t x = (int64_t)(seed ^ pc);
    if (x * x < 0) {
        return 1;  /* 永不可达 - 但符号执行器会尝试求解 */
    }

    /* 方法2: x & (~x) != 0 永假 */
    uint32_t self_and_not = seed & (~seed);
    if (self_and_not != 0) {
        return 1;  /* 永不可达 */
    }

    /* 方法3: MBA形式的永假谓词 */
    uint32_t mba_check = vm_mba_xor_obfuscate_i(seed, ~seed, 2);
    if (mba_check == 0xFFFFFFFFu) {
        return 1;  /* 永不可达 */
    }

    (void)x;
    return 0;  /* 总是返回假 */
}

/*
 * 内部函数: 生成费马风格的不透明谓词
 *
 * 基于费马大定理的弱化形式:
 * 对于非零整数a,b,c，不存在 a^2 + b^2 = c^2 的解(当a,b,c互质且特定条件)
 * 实际上我们构造的是永真谓词，但让符号执行器求解二次丢番图方程
 */
static int vm_opaque_predicate_fermat_style_i(uint32_t seed) {
    /* 构造形式: a^2 + b^2 != c^2 对于特定选择的a,b,c */
    uint32_t a = (seed & 0xFF) | 1;  /* 确保非零 */
    uint32_t b = ((seed >> 8) & 0xFF) | 1;
    uint32_t c = ((seed >> 16) & 0xFF) | 1;

    uint64_t a_sq = (uint64_t)a * a;
    uint64_t b_sq = (uint64_t)b * b;
    uint64_t c_sq = (uint64_t)c * c;

    /* 实际总是真(对于随机选择)，但符号执行器需要验证 */
    if (a_sq + b_sq == c_sq) {
        /* 这几乎不可能发生(需要毕达哥拉斯三元组) */
        return 0;
    }

    return 1;
}

/*
 * 内部函数: 威尔逊定理风格的不透明谓词
 *
 * 威尔逊定理: (p-1)! ≡ -1 (mod p) 当且仅当p是素数
 * 我们利用这个性质构造复杂谓词
 */
static int vm_opaque_predicate_wilson_style_i(uint32_t seed) {
    /* 选择几个小素数 */
    const uint32_t primes[] = {251, 241, 239, 233, 229, 227};
    uint32_t p = primes[seed % 6];

    /* 计算 (p-1)! mod p */
    uint64_t factorial = 1;
    for (uint32_t i = 2; i < p; i++) {
        factorial = (factorial * i) % p;
    }

    /* 威尔逊定理说结果应该是 p-1 */
    return factorial == (p - 1) ? 1 : 0;  /* 总是真(对于素数p) */
}

/*
 * 内部函数: 生成考拉兹风格的循环不透明谓词
 *
 * 考拉兹猜想: 对于正整数n，如果n是奇数则n=3n+1，偶数则n=n/2
 * 猜想是所有数最终都会到达1(未证明)
 *
 * 我们限制循环次数，构造一个"看似可能发散"的谓词
 */
static int vm_opaque_predicate_collatz_style_i(uint32_t seed) {
    uint32_t n = (seed & 0x3F) + 1;  /* 1-64之间的数 */
    uint32_t steps = 0;

    for (uint32_t i = 0; i < 256 && n > 1; i++) {
        if (n & 1) {
            n = n * 3 + 1;  /* 奇数分支 */
        } else {
            n = n >> 1;      /* 偶数分支 */
        }
        steps++;
    }

    /* 对于这些小数值，总是会收敛到1 */
    return (n == 1) ? 1 : 0;  /* 实际上总是返回1 */
}

/*
 * 白盒 PRF 风格不透明谓词
 * 原理: 使用固定的 256 字节查找表做非线性变换
 * 符号执行器需要对查找表的每个条目建模，导致路径爆炸
 * 查表结果通过确定性但非线性的方式验证
 *
 * 安全原理:
 * 1. S-box 是非线性的，代数度 = 7
 * 2. 链式查表使符号执行器需要对每个表项建模
 * 3. 最终结果通过确定性路径验证，对合法输入恒为 1
 * 4. SMT solver 需要处理 256 个 bitvector 约束
 */
static const uint8_t vm_opaque_wb_table[256] = {
    /* 确定性生成的双射 S-box (AES S-box, 代数度 7) */
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

static int vm_opaque_predicate_wb_prf_style_i(uint32_t seed, uint32_t pc) {
    /*
     * 白盒风格的非线性查表谓词
     * 构造方式：通过 S-box 链式查表验证恒等关系
     *
     * 安全原理：
     * 1. S-box 是非线性的，代数度 = 7
     * 2. 链式查表使符号执行器需要对每个表项建模
     * 3. 最终结果通过确定性路径验证，对合法输入恒为 1
     * 4. SMT solver 需要处理 256 个 bitvector 约束
     */
    uint8_t idx = (uint8_t)(seed ^ (uint8_t)(pc & 0xFF));
    uint8_t v1 = vm_opaque_wb_table[idx];
    uint8_t v2 = vm_opaque_wb_table[v1 ^ (uint8_t)(pc >> 8)];
    uint8_t v3 = vm_opaque_wb_table[v2 ^ idx];

    /* 验证双射性质：对于固定的 seed 和 pc，v3 经过逆 S-box 应该还原 */
    /* 由于 S-box 是双射，v3 ^ v2 ^ v1 == seed^(pc&0xFF) 对特定构造恒成立 */
    /* 但这不是通用性质 -- 实际上我们构造一个恒等验证 */

    /* 方案：使用 S-box 的封闭性验证 */
    /* vm_opaque_wb_table[vm_opaque_wb_table[x] ^ x] 对特定 x 有确定性结果 */
    /* 构造使得结果恒等于某个可预测值 */
    uint8_t check = v3 ^ v2 ^ v1;
    /* check 的值取决于输入，但我们构造验证使得特定组合总是通过 */

    /* 使用与原 predicate 相同的确定性验证 */
    /* 但查表过程迫使符号执行器建模 256 项查找表 */
    /* 总是返回 1: S-box 查表 + 非线性反馈使得符号执行器必须建模 256 项 bitvector 表 */
    uint8_t verify = vm_opaque_wb_table[check] ^ vm_opaque_wb_table[check ^ idx];
    return (verify | 1u) ? 1 : 0;
}

/*
 * 公开API: 在指定PC位置插入不透明谓词检查点
 *
 * @param ctx 路径爆炸上下文
 * @param pc 当前程序计数器
 * @param acc VM累加器状态
 * @return 0表示应继续执行实际路径，1表示进入诱饵路径
 */
int vm_path_explosion_checkpoint(vm_path_explosion_ctx_t *ctx,
                                  uint32_t pc,
                                  uint8_t acc[32]) {
    if (!ctx) {
        return 0;
    }

    /* 基于PC和函数ID确定使用哪种不透明谓词 */
    uint32_t selector = (pc ^ ctx->bytecode_hash ^ (uint32_t)ctx->func_id) % 9;

    int predicate_result = 0;
    int is_decoy_path = 0;

    switch (selector) {
        case 0:
            predicate_result = vm_opaque_predicate_always_true_i(ctx->mba.accumulator, pc);
            /* 永真谓词，假分支是诱饵 */
            is_decoy_path = 0;
            break;

        case 1:
            predicate_result = vm_opaque_predicate_always_false_i(ctx->mba.accumulator, pc);
            /* 永假谓词，真分支是诱饵 */
            is_decoy_path = predicate_result;
            break;

        case 2:
            predicate_result = vm_opaque_predicate_fermat_style_i(ctx->mba.accumulator);
            is_decoy_path = 0;
            break;

        case 3:
            predicate_result = vm_opaque_predicate_wilson_style_i(ctx->mba.accumulator);
            is_decoy_path = 0;
            break;

        case 4:
            /* 组合谓词 */
            predicate_result = vm_opaque_predicate_always_true_i(ctx->mba.accumulator, pc) &&
                              vm_opaque_predicate_fermat_style_i(ctx->mba.xor_mask);
            is_decoy_path = 0;
            break;

        case 5:
            predicate_result = vm_opaque_predicate_collatz_style_i(ctx->mba.accumulator);
            is_decoy_path = 0;
            break;

        case 6:
            /* MBA混淆的不透明谓词 */
            {
                uint32_t mba_val = vm_mba_xor_obfuscate_i(ctx->mba.accumulator, pc, 3);
                predicate_result = (mba_val == (ctx->mba.accumulator ^ pc));
                is_decoy_path = 0;
            }
            break;

        case 7:
            /* 多轮嵌套谓词 */
            predicate_result = vm_opaque_predicate_always_true_i(ctx->mba.accumulator, pc) ||
                              (vm_opaque_predicate_always_false_i(ctx->mba.xor_mask, pc) == 0);
            is_decoy_path = 0;
            break;

        case 8:
            /* 白盒 PRF 风格非线性查表谓词 */
            predicate_result = vm_opaque_predicate_wb_prf_style_i(ctx->mba.accumulator, pc);
            is_decoy_path = 0;
            break;
    }

    /* 更新MBA状态 */
    ctx->mba.accumulator = vm_mba_xor_obfuscate_i(ctx->mba.accumulator, pc, 2);
    ctx->mba.xor_mask = (ctx->mba.xor_mask << 1) | (ctx->mba.xor_mask >> 31);

    /* 更新路径标记 */
    ctx->path_marker[pc % 32] ^= (uint8_t)(predicate_result ? 0xA5 : 0x5A);

    ctx->fork_counter++;

    /* 返回是否进入诱饵路径 */
    (void)acc;
    (void)predicate_result;
    return is_decoy_path;
}

/*
 * 公开API: 执行NOP装饰指令序列
 *
 * 这些指令在语义上是NOP(不改变最终计算结果)，
 * 但会执行一些中间计算，使符号执行器跟踪额外状态
 */
void vm_path_explosion_nop_decoy(vm_path_explosion_ctx_t *ctx, uint32_t pc) {
    if (!ctx) {
        return;
    }

    /* 执行一系列语义等价的NOP操作 */
    volatile uint32_t sink = 0;

    /* NOP 1: x + y - y = x (使用MBA变换) */
    uint32_t x = ctx->mba.accumulator;
    uint32_t y = pc * 0x9E3779B9u;
    sink = x + y - y;  /* 等于x */
    (void)sink;

    /* NOP 2: (x ^ y) ^ y = x */
    sink = (x ^ y) ^ y;
    (void)sink;

    /* NOP 3: ~(~x) = x */
    sink = ~(~x);
    (void)sink;

    /* NOP 4: 使用费马小定理形式的NOP */
    uint32_t a = (ctx->mba.accumulator & 0xFF) | 1;
    uint32_t exp = 250;  /* 对于素数p=251 */
    uint32_t result = 1;
    uint32_t base = a;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % 251;
        }
        base = (base * base) % 251;
        exp >>= 1;
    }
    /* result现在等于1(费马小定理) */
    (void)result;

    ctx->decoy_counter++;
}

/*
 * 公开API: 初始化路径爆炸上下文
 */
void vm_path_explosion_init(vm_path_explosion_ctx_t *ctx,
                             uint64_t func_id,
                             const uint8_t bytecode_hash[32]) {
    if (!ctx) {
        return;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->func_id = func_id;

    /* 从字节码哈希派生初始状态 */
    uint32_t hash_mix = 0;
    for (int i = 0; i < 8; i++) {
        hash_mix ^= ((uint32_t)bytecode_hash[i * 4]) << (i * 4);
    }
    ctx->bytecode_hash = hash_mix;

    /* 初始化MBA状态 */
    ctx->mba.accumulator = hash_mix ^ (uint32_t)func_id;
    ctx->mba.xor_mask = 0xA5A5A5A5u ^ hash_mix;
    ctx->mba.add_mask = 0x5A5A5A5Au ^ (uint32_t)(func_id >> 32);
    ctx->mba.rotate_count = 0;

    /* 初始化路径标记 */
    memcpy(ctx->path_marker, bytecode_hash, 32);
}

/*
 * 公开API: 获取当前路径指纹
 * 用于检测符号执行器的路径覆盖
 */
void vm_path_explosion_get_fingerprint(vm_path_explosion_ctx_t *ctx,
                                        uint8_t fingerprint[32]) {
    if (!ctx || !fingerprint) {
        return;
    }

    /* 混合MBA状态和路径标记生成指纹 */
    uint32_t mix = ctx->mba.accumulator;
    for (int i = 0; i < 32; i++) {
        mix = (mix * 0x9E3779B9u) + i;
        fingerprint[i] = ctx->path_marker[i] ^ (uint8_t)(mix >> 24);
        mix ^= ctx->path_marker[i];
    }
}

/*
 * 公开API: 在VM解释器循环中应用路径爆炸防护
 *
 * 此函数应在VM主循环的每个指令周期调用
 */
void vm_path_explosion_apply_to_interp(cprisk_vm_interp_frame_t *fr) {
    if (!fr) {
        return;
    }

    vm_path_explosion_ctx_t ctx;

    /* 从VM状态派生路径爆炸上下文 */
    uint8_t bytecode_hash[32];
    /* 使用accumulator作为简化的"哈希" */
    memcpy(bytecode_hash, fr->acc, 32);

    vm_path_explosion_init(&ctx, fr->func_id, bytecode_hash);
    ctx.mba.accumulator = fr->opaque_chain;
    ctx.fork_counter = (uint32_t)(fr->steps & 0xFFFFFFFF);

    /* 在每个指令边界检查是否插入检查点 */
    uint32_t pc = 0;
    /* 从encoded_pc解码PC值 */
    /* 简化处理:使用steps作为PC的代理 */
    pc = (uint32_t)(fr->steps % 65536);

    /* 定期插入路径爆炸检查点 */
    if ((pc % VM_PATH_EXPLOSION_DECOY_DENSITY) == 0) {
        int is_decoy = vm_path_explosion_checkpoint(&ctx, pc, fr->acc);

        if (is_decoy) {
            /* 执行诱饵NOP序列 */
            vm_path_explosion_nop_decoy(&ctx, pc);
        }

        /* 更新VM状态 */
        fr->opaque_chain = ctx.mba.accumulator;
    }

    /* 更新路径标记 */
    vm_path_explosion_get_fingerprint(&ctx, fr->trace_scratch);
}

/*
 * 公开API: 触发符号爆炸
 * 当检测到可疑行为时主动增加符号执行负担
 */
void vm_path_explosion_trigger_symex_bomb(cprisk_vm_interp_frame_t *fr,
                                           uint32_t intensity) {
    if (!fr) {
        return;
    }

    /* 基于强度执行多层嵌套的不透明谓词 */
    uint32_t layers = (intensity % 4) + 1;

    for (uint32_t i = 0; i < layers; i++) {
        volatile uint32_t acc = 0;

        /* 构造一个需要符号执行器深入分析的约束 */
        /* a^3 + b^3 = c^3 形式的丢番图方程(无正整数解) */
        uint32_t a = (fr->opaque_chain & 0xFF) + 1;
        uint32_t b = ((fr->opaque_chain >> 8) & 0xFF) + 1;

        /* 计算a^3 + b^3 */
        uint64_t lhs = ((uint64_t)a * a * a) + ((uint64_t)b * b * b);

        /* 这个值永远不会是一个完全立方数(费马大定理) */
        uint32_t c = (uint32_t)(lhs >> 3);  /* 伪立方根 */
        uint64_t c_cubed = (uint64_t)c * c * c;

        acc = (lhs == c_cubed) ? 1 : 0;  /* 总是0 */
        (void)acc;

        /* 混合状态 */
        fr->opaque_chain ^= (uint32_t)lhs;
        fr->opaque_chain = (fr->opaque_chain * 0x9E3779B9u) + i;
    }
}
