/*
 *  vm_dynamic_const.c
 *  CRiskCore
 *
 *  常量动态化 - Dynamic Constant Derivation
 *
 *  对抗原理说明:
 *  ==============
 *
 *  传统逆向工程中，关键常量(如阈值、魔数、校验值)通常以立即数形式
 *  硬编码在指令中，攻击者可以通过静态分析轻松提取。
 *
 *  本模块实现"常量动态派生"技术:
 *  1. 关键常量在运行时通过PRF(伪随机函数)派生，不在代码中出现
 *  2. 每个函数的阈值是唯一的，基于函数ID和白盒PRF材料
 *  3. 引入VM_OP_LOAD_RND和VM_OP_DERIVE指令，在VM层面支持动态常量
 *
 *  核心概念:
 *  =========
 *
 *  1. VM_OP_LOAD_RND指令:
 *     - 从白盒PRF的随机流中加载一个32位值到累加器
 *     - 每次执行产生不同的"随机"常量(实际是确定性的PRF输出)
 *     - 攻击者无法静态提取，因为值在运行时计算
 *
 *  2. VM_OP_DERIVE指令:
 *     - 通过WhiteBoxPRF派生特定常量
 *     - 输入: domain(域ID) + seed(种子)
 *     - 输出: 派生值，用于比较、阈值检查等
 *
 *  3. 函数身份哈希:
 *     - 每个函数有唯一的身份指纹
 *     - 基于函数ID、字节码内容、白盒材料计算
 *     - 用于派生函数特定的阈值和常量
 *
 *  安全优势:
 *  =========
 *
 *  1. 抗静态分析: 常量值不出现在二进制中
 *  2. 抗动态分析: 每次执行产生不同序列(绑定到会话)
 *  3. 抗重放攻击: 派生值绑定到白盒PRF材料
 *  4. 抗符号执行: 约束求解需要完整的PRF模型
 *
 *  与现有系统集成:
 *  ==============
 *  - 复用cprisk_whitebox.c中的白盒PRF评估
 *  - 与CFF状态联动，派生值影响状态转换
 *  - 支持VM解释器内联执行
 */

#include "include/CRiskCore.h"
#include "include/cprisk_vm_interpreter.h"
#include "include/cprisk_vm_interpreter_internal.h"
#include "vm_dynamic_const.h"

#include <string.h>

/*
 * 白盒PRF域定义 - 常量派生专用域
 */
#define VM_CONST_DERIVE_DOMAIN_BASE     10  /* 常量派生域起始 */
#define VM_CONST_DERIVE_DOMAIN_RND      10  /* 随机常量域 */
#define VM_CONST_DERIVE_DOMAIN_THRESH   11  /* 阈值派生域 */
#define VM_CONST_DERIVE_DOMAIN_MAGIC    12  /* 魔数派生域 */
#define VM_CONST_DERIVE_DOMAIN_CHECK    13  /* 校验值派生域 */
#define VM_CONST_DERIVE_DOMAIN_MASK     14  /* 掩码派生域 */
#define VM_CONST_DERIVE_DOMAIN_KEY      15  /* 密钥派生域 */

/*
 * 内部状态 - PRF流状态
 */
typedef struct {
    uint64_t state;
    uint32_t buffer[8];      /* 预生成的随机值缓冲区 */
    uint8_t  buffer_pos;     /* 缓冲区当前位置 */
    uint8_t  initialized;    /* 是否已初始化 */
} vm_prng_stream_t;

/*
 * 线程本地存储的PRNG状态
 * 确保多线程安全性
 */
static _Thread_local vm_prng_stream_t s_tls_prng_stream = {0};

/*
 * 内部函数: SplitMix64 PRNG
 * 用于生成随机流
 */
static uint64_t vm_splitmix64_next(uint64_t *state) {
    *state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = *state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/*
 * 内部函数: 从白盒PRF派生种子
 * 使用白盒PRF的domain 5(运行时材料域)作为种子源
 */
static uint64_t vm_derive_seed_from_whitebox_i(uint64_t func_id, uint32_t pc) {
    uint8_t input[32];
    uint8_t output[32];

    /* 构造输入: func_id + pc */
    memset(input, 0, sizeof(input));
    memcpy(input, &func_id, sizeof(func_id));
    memcpy(input + 8, &pc, sizeof(pc));

    /* 评估白盒PRF domain 5 */
    if (cprisk_whitebox_evaluate_domain(5, input, output) != 0) {
        /* 失败时回退到确定性种子 */
        return func_id ^ pc ^ 0x9E3779B97F4A7C15ULL;
    }

    /* 从输出派生64位种子 */
    uint64_t seed = 0;
    for (int i = 0; i < 8; i++) {
        seed = (seed << 8) | output[i];
    }

    /* 清零敏感数据 */
    cprisk_secure_zero(input, sizeof(input));
    cprisk_secure_zero(output, sizeof(output));

    return seed;
}

/*
 * 内部函数: 初始化PRNG流
 */
static void vm_prng_stream_init(vm_prng_stream_t *stream,
                                uint64_t func_id,
                                uint32_t pc) {
    if (!stream) {
        return;
    }

    /* 从白盒PRF派生初始种子 */
    stream->state = vm_derive_seed_from_whitebox_i(func_id, pc);
    stream->buffer_pos = 0;
    stream->initialized = 1;

    /* 预填充缓冲区 */
    for (int i = 0; i < 8; i++) {
        stream->buffer[i] = (uint32_t)vm_splitmix64_next(&stream->state);
    }
}

/*
 * 内部函数: 从PRNG流获取下一个32位值
 */
static uint32_t vm_prng_stream_next(vm_prng_stream_t *stream) {
    if (!stream || !stream->initialized) {
        return 0;
    }

    /* 从缓冲区取值 */
    uint32_t value = stream->buffer[stream->buffer_pos];
    stream->buffer_pos++;

    /* 缓冲区耗尽时重新填充 */
    if (stream->buffer_pos >= 8) {
        stream->buffer_pos = 0;
        for (int i = 0; i < 8; i++) {
            stream->buffer[i] = (uint32_t)vm_splitmix64_next(&stream->state);
        }
    }

    return value;
}

/*
 * 公开API: 通过WhiteBoxPRF派生常量
 *
 * @param domain 派生域(用于区分不同类型的常量)
 * @param func_id 函数ID
 * @param seed 派生种子
 * @return 派生的32位常量值
 */
uint32_t vm_const_derive_via_whitebox(uint32_t domain,
                                       uint64_t func_id,
                                       uint32_t seed) {
    uint8_t input[32];
    uint8_t output[32];

    /* 构造输入: domain + func_id + seed */
    memset(input, 0, sizeof(input));
    memcpy(input, &domain, sizeof(domain));
    memcpy(input + 4, &func_id, sizeof(func_id));
    memcpy(input + 12, &seed, sizeof(seed));

    /* 计算输入的哈希作为白盒输入 */
    uint8_t hash[32];
    cprisk_sha256(input, 16, hash);

    /* 评估白盒PRF */
    uint32_t result = 0;
    if (cprisk_whitebox_evaluate_domain(VM_CONST_DERIVE_DOMAIN_BASE + (domain % 6),
                                         hash, output) == 0) {
        /* 从输出派生结果 */
        result = ((uint32_t)output[0] << 24) |
                 ((uint32_t)output[1] << 16) |
                 ((uint32_t)output[2] << 8) |
                 (uint32_t)output[3];
    } else {
        /* 失败时使用备用派生 */
        result = (uint32_t)(func_id >> 32) ^ seed ^ (domain * 0x9E3779B9u);
    }

    /* 清零敏感数据 */
    cprisk_secure_zero(input, sizeof(input));
    cprisk_secure_zero(output, sizeof(output));
    cprisk_secure_zero(hash, sizeof(hash));

    return result;
}

/*
 * 公开API: 派生函数特定的比较阈值
 *
 * 用于FUNC_ID_CMP_THRESH等场景
 *
 * @param func_id 函数ID
 * @param threshold_type 阈值类型(如CMP_THRESH_EQ, CMP_THRESH_GT等)
 * @return 派生的阈值
 */
uint32_t vm_const_derive_cmp_threshold(uint64_t func_id, uint32_t threshold_type) {
    /* 使用阈值派生域 */
    uint32_t seed = (uint32_t)(func_id ^ (func_id >> 32));
    return vm_const_derive_via_whitebox(VM_CONST_DERIVE_DOMAIN_THRESH,
                                         func_id,
                                         seed ^ threshold_type);
}

/*
 * 公开API: 派生函数特定的魔数
 *
 * @param func_id 函数ID
 * @param magic_type 魔数类型标识
 * @return 派生的魔数
 */
uint32_t vm_const_derive_magic(uint64_t func_id, uint32_t magic_type) {
    return vm_const_derive_via_whitebox(VM_CONST_DERIVE_DOMAIN_MAGIC,
                                         func_id,
                                         magic_type);
}

/*
 * 公开API: 派生校验常量
 *
 * 用于运行时完整性校验
 *
 * @param func_id 函数ID
 * @param check_type 校验类型
 * @return 派生的校验值
 */
uint32_t vm_const_derive_check_value(uint64_t func_id, uint32_t check_type) {
    return vm_const_derive_via_whitebox(VM_CONST_DERIVE_DOMAIN_CHECK,
                                         func_id,
                                         check_type);
}

/*
 * 公开API: 派生掩码常量
 *
 * @param func_id 函数ID
 * @param mask_type 掩码类型
 * @param bit_width 需要的位宽
 * @return 派生的掩码
 */
uint32_t vm_const_derive_mask(uint64_t func_id, uint32_t mask_type, uint8_t bit_width) {
    uint32_t raw = vm_const_derive_via_whitebox(VM_CONST_DERIVE_DOMAIN_MASK,
                                                func_id,
                                                mask_type);
    /* 根据位宽裁剪 */
    if (bit_width >= 32) {
        return raw;
    }
    return raw & ((1u << bit_width) - 1);
}

/*
 * 公开API: 派生密钥材料
 *
 * @param func_id 函数ID
 * @param key_index 密钥索引
 * @param key_out 输出缓冲区(32字节)
 * @return 0成功，非0失败
 */
int vm_const_derive_key_material(uint64_t func_id,
                                  uint32_t key_index,
                                  uint8_t key_out[32]) {
    uint8_t input[32];
    uint8_t output[32];

    /* 构造输入 */
    memset(input, 0, sizeof(input));
    memcpy(input, &func_id, sizeof(func_id));
    memcpy(input + 8, &key_index, sizeof(key_index));

    /* 评估白盒PRF */
    int rc = cprisk_whitebox_evaluate_domain(VM_CONST_DERIVE_DOMAIN_KEY,
                                              input, output);
    if (rc == 0) {
        memcpy(key_out, output, 32);
    }

    cprisk_secure_zero(input, sizeof(input));
    cprisk_secure_zero(output, sizeof(output));

    return rc;
}

/*
 * 公开API: 执行VM_OP_LOAD_RND指令
 *
 * 从PRNG流加载一个随机常量到累加器
 *
 * @param fr VM解释器帧
 * @param imm 立即数字段(包含派生参数)
 * @return VM_FLOW_CONTINUE
 */
cprisk_vm_flow_t vm_op_load_rnd_execute(cprisk_vm_interp_frame_t *fr,
                                         uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    /* 提取参数 */
    uint32_t target_slot = imm & 0x1F;           /* 目标累加器槽位 */
    uint32_t use_whitebox = (imm >> 5) & 1;      /* 是否使用白盒PRF */
    uint32_t pc = (uint32_t)(fr->steps & 0xFFFFFFFF);

    uint32_t value;

    if (use_whitebox) {
        /* 使用白盒PRF派生 */
        value = vm_const_derive_via_whitebox(VM_CONST_DERIVE_DOMAIN_RND,
                                             fr->func_id,
                                             pc);
    } else {
        /* 使用PRNG流 */
        vm_prng_stream_init(&s_tls_prng_stream, fr->func_id, pc);
        value = vm_prng_stream_next(&s_tls_prng_stream);
    }

    /* 存入累加器指定槽位 */
    if (target_slot < 32) {
        fr->acc[target_slot] = (uint8_t)(value & 0xFF);
    }

    /* 同时影响辅助累加器 */
    uint32_t aux_slot = (target_slot + 16) & 31;
    fr->acc_aux[aux_slot] = (uint8_t)((value >> 8) & 0xFF);

    /* 更新不透明链 */
    fr->opaque_chain ^= value;

    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * 公开API: 执行VM_OP_DERIVE指令
 *
 * 派生一个常量并执行操作
 *
 * @param fr VM解释器帧
 * @param imm 立即数字段
 *        - bits 0-7: 派生域
 *        - bits 8-15: 操作类型
 *        - bits 16-31: 派生种子
 * @return VM_FLOW_CONTINUE
 */
cprisk_vm_flow_t vm_op_derive_execute(cprisk_vm_interp_frame_t *fr,
                                       uint64_t imm) {
    if (!fr) {
        return CPRISK_VM_FLOW_LEAVE;
    }

    /* 解析立即数 */
    uint32_t domain = imm & 0xFF;
    uint32_t op_type = (imm >> 8) & 0xFF;
    uint32_t seed = (imm >> 16) & 0xFFFF;
    uint32_t pc = (uint32_t)(fr->steps & 0xFFFFFFFF);

    /* 派生常量 */
    uint32_t derived = vm_const_derive_via_whitebox(domain,
                                                     fr->func_id,
                                                     seed ^ pc);

    /* 根据操作类型应用派生值 */
    switch (op_type) {
        case VM_DERIVE_OP_LOAD_ACC: {
            /* 加载到累加器 */
            for (int i = 0; i < 4; i++) {
                fr->acc[i] = (uint8_t)((derived >> (i * 8)) & 0xFF);
            }
            break;
        }

        case VM_DERIVE_OP_XOR_ACC: {
            /* 与累加器XOR */
            for (int i = 0; i < 4; i++) {
                fr->acc[i] ^= (uint8_t)((derived >> (i * 8)) & 0xFF);
            }
            break;
        }

        case VM_DERIVE_OP_ADD_ACC: {
            /* 与累加器ADD(字节级) */
            uint32_t acc_val = 0;
            for (int i = 0; i < 4; i++) {
                acc_val |= ((uint32_t)fr->acc[i]) << (i * 8);
            }
            acc_val += derived;
            for (int i = 0; i < 4; i++) {
                fr->acc[i] = (uint8_t)((acc_val >> (i * 8)) & 0xFF);
            }
            break;
        }

        case VM_DERIVE_OP_CMP_THRESH: {
            /* 比较阈值检查 */
            /* 派生的阈值与累加器值比较，影响条件状态 */
            /* 实际比较逻辑由后续BRANCH_COND指令处理 */
            /* 这里只将派生值存入trace_scratch供后续使用 */
            memcpy(fr->trace_scratch, &derived, sizeof(derived));
            break;
        }

        case VM_DERIVE_OP_MASK_ACC: {
            /* 掩码操作 */
            for (int i = 0; i < 4; i++) {
                fr->acc[i] &= (uint8_t)((derived >> (i * 8)) & 0xFF);
            }
            break;
        }

        case VM_DERIVE_OP_MIX_STATE: {
            /* 混合VM状态 */
            fr->opaque_chain ^= derived;
            fr->session_mix ^= (derived >> 16);
            fr->opaque_session_mix = (fr->opaque_session_mix * 0x9E3779B9u) + derived;
            break;
        }

        default:
            /* 未知操作类型，使用默认值 */
            fr->opaque_chain ^= derived;
            break;
    }

    return CPRISK_VM_FLOW_CONTINUE;
}

/*
 * 公开API: 计算函数身份哈希
 *
 * 基于函数ID、字节码内容和白盒材料计算唯一的函数指纹
 *
 * @param func_id 函数ID
 * @param bytecode 字节码内容(可为NULL)
 * @param bytecode_len 字节码长度
 * @param hash_out 输出缓冲区(32字节)
 * @return 0成功，非0失败
 */
int vm_const_hash_function_identity(uint64_t func_id,
                                     const uint8_t *bytecode,
                                     size_t bytecode_len,
                                     uint8_t hash_out[32]) {
    cprisk_sha256_ctx ctx;
    cprisk_sha256_init(&ctx);

    /* 混入函数ID */
    cprisk_sha256_update(&ctx, (const uint8_t *)&func_id, sizeof(func_id));

    /* 混入字节码内容(如果有) */
    if (bytecode && bytecode_len > 0) {
        cprisk_sha256_update(&ctx, bytecode, bytecode_len);
    }

    /* 混入白盒材料(如果可用) */
    uint8_t wb_material[32];
    if (cprisk_get_runtime_material(wb_material) == 0) {
        cprisk_sha256_update(&ctx, wb_material, sizeof(wb_material));
        cprisk_secure_zero(wb_material, sizeof(wb_material));
    }

    /* 混入版本常量 */
    static const uint8_t version_tag[] = "VM_DYNAMIC_CONST_v1";
    cprisk_sha256_update(&ctx, version_tag, sizeof(version_tag) - 1);

    /* 输出哈希 */
    cprisk_sha256_final(&ctx, hash_out);

    return 0;
}

/*
 * 公开API: 从函数身份哈希派生常量
 *
 * @param func_id 函数ID
 * @param const_index 常量索引(用于派生多个常量)
 * @return 派生的常量值
 */
uint32_t vm_const_derive_from_identity(uint64_t func_id, uint32_t const_index) {
    uint8_t identity_hash[32];

    /* 计算函数身份哈希 */
    vm_const_hash_function_identity(func_id, NULL, 0, identity_hash);

    /* 从哈希派生指定索引的常量 */
    uint32_t offset = (const_index * 4) % 28;  /* 确保不越界 */
    uint32_t value = ((uint32_t)identity_hash[offset] << 24) |
                     ((uint32_t)identity_hash[offset + 1] << 16) |
                     ((uint32_t)identity_hash[offset + 2] << 8) |
                     (uint32_t)identity_hash[offset + 3];

    /* 混合索引防止碰撞 */
    value ^= const_index * 0x9E3779B9u;

    cprisk_secure_zero(identity_hash, sizeof(identity_hash));

    return value;
}

/*
 * 公开API: 在VM解释器中应用动态常量
 *
 * 此函数应在VM初始化时调用，设置函数的动态常量
 */
void vm_dynamic_const_apply_to_interp(cprisk_vm_interp_frame_t *fr) {
    if (!fr) {
        return;
    }

    /* 派生函数特定的初始常量 */
    uint32_t init_acc = vm_const_derive_from_identity(fr->func_id, 0);
    uint32_t init_aux = vm_const_derive_from_identity(fr->func_id, 1);
    uint32_t session_salt = vm_const_derive_from_identity(fr->func_id, 2);

    /* 应用派生值到VM状态 */
    for (int i = 0; i < 4; i++) {
        fr->acc[i] = (uint8_t)((init_acc >> (i * 8)) & 0xFF);
        fr->acc_aux[i + 16] = (uint8_t)((init_aux >> (i * 8)) & 0xFF);
    }

    /* 更新会话混合 */
    fr->session_mix ^= session_salt;
    fr->opaque_session_mix ^= (session_salt >> 16);
}

/*
 * 公开API: 重置动态常量上下文
 * 用于函数调用切换时
 */
void vm_dynamic_const_reset_for_func(uint64_t func_id) {
    /* 重置TLS PRNG状态 */
    memset(&s_tls_prng_stream, 0, sizeof(s_tls_prng_stream));

    /* 预初始化新函数的PRNG */
    vm_prng_stream_init(&s_tls_prng_stream, func_id, 0);
}

/*
 * 公开API: 获取函数特定的比较阈值
 * 用于FUNC_ID_CMP_THRESH场景
 */
uint32_t vm_const_get_func_cmp_threshold(uint64_t func_id,
                                          uint32_t cmp_type,
                                          uint32_t base_value) {
    /* 派生函数特定的阈值 */
    uint32_t derived = vm_const_derive_from_identity(func_id, cmp_type + 100);

    /* 将派生值与基础值混合 */
    uint32_t threshold = base_value ^ derived;

    /* 确保阈值在合理范围内(可选) */
    /* threshold = threshold % MAX_THRESHOLD; */

    (void)threshold;
    return threshold;
}
