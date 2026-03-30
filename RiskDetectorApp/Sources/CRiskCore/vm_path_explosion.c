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
    uint32_t selector = (pc ^ ctx->bytecode_hash ^ (uint32_t)ctx->func_id) % 8;

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
                predicate_result = (mba_val == ctx->mba.accumulator ^ pc);
                is_decoy_path = 0;
            }
            break;

        case 7:
        default:
            /* 多轮嵌套谓词 */
            predicate_result = vm_opaque_predicate_always_true_i(ctx->mba.accumulator, pc) ||
                              (vm_opaque_predicate_always_false_i(ctx->mba.xor_mask, pc) == 0);
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
