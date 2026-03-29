#ifndef VM_REORDER_H
#define VM_REORDER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * ============================================================================
 * VM指令重排序与伪依赖引擎
 * ============================================================================
 *
 * 加固原理:
 * --------
 * 1. 控制流混淆: 通过指令重排序破坏原始控制流，增加静态分析难度
 * 2. 数据流混淆: 插入伪依赖关系，使数据流分析复杂化
 * 3. 反模式匹配: 打乱常见的指令序列，阻止模式识别
 * 4. 抗符号执行: 伪依赖增加约束条件，使符号执行路径爆炸
 *
 * 重排序策略:
 * -----------
 * 1. 调度表重排: 基于数据流分析的安全重排
 * 2. 寄存器重命名: 增加虚假寄存器依赖
 * 3. 指令调度: 利用空闲槽位插入无关指令
 * 4. 循环变换: 循环展开/压扁/重排
 *
 * 伪依赖技术:
 * -----------
 * 1. 虚假数据依赖: 插入看似相关实际无关的指令
 * 2. 控制依赖伪装: 创建复杂的控制流使其看起来像数据依赖
 * 3. 内存别名混淆: 使不同内存位置看起来可能别名
 * 4. 死代码插入: 插入永远不会执行的指令作为干扰
 */

/* 最大支持参数 */
#define VM_REORDER_MAX_INSNS      1024   /* 最大指令数 */
#define VM_REORDER_MAX_REGS       64     /* 最大寄存器数 */
#define VM_REORDER_MAX_DEP_BITS   16     /* 依赖位图大小 */

/* 指令类型 */
typedef enum {
    VM_INSN_TYPE_ALU = 0,       /* 算术逻辑运算 */
    VM_INSN_TYPE_LOAD = 1,      /* 加载 */
    VM_INSN_TYPE_STORE = 2,     /* 存储 */
    VM_INSN_TYPE_BRANCH = 3,    /* 分支 */
    VM_INSN_TYPE_CALL = 4,      /* 调用 */
    VM_INSN_TYPE_RET = 5,       /* 返回 */
    VM_INSN_TYPE_NOP = 6,       /* 空操作 */
    VM_INSN_TYPE_SPECIAL = 7    /* 特殊指令 */
} vm_insn_type_t;

/* 依赖类型 */
typedef enum {
    VM_DEP_NONE = 0,            /* 无依赖 */
    VM_DEP_RAW = 1,             /* 写后读 (Read After Write) */
    VM_DEP_WAR = 2,             /* 读后写 (Write After Read) */
    VM_DEP_WAW = 3,             /* 写后写 (Write After Write) */
    VM_DEP_CONTROL = 4,         /* 控制依赖 */
    VM_DEP_MEMORY = 5,          /* 内存依赖 */
    VM_DEP_FAKE = 6             /* 伪依赖 (人为插入) */
} vm_dependency_type_t;

/* 指令描述 */
typedef struct {
    uint32_t id;                    /* 指令ID */
    vm_insn_type_t type;            /* 指令类型 */
    uint32_t opcode;                /* 操作码 */
    uint64_t operand;               /* 操作数 */

    /* 寄存器信息 */
    uint32_t dst_reg;               /* 目标寄存器 (VM_REORDER_MAX_REGS表示无) */
    uint32_t src_regs[4];           /* 源寄存器列表 */
    uint32_t src_reg_count;         /* 源寄存器数量 */

    /* 内存访问 */
    bool is_load;                   /* 是否读内存 */
    bool is_store;                  /* 是否写内存 */
    uint64_t mem_addr;              /* 内存地址 (如已知) */
    uint32_t mem_size;              /* 访问大小 */

    /* 控制流 */
    bool is_branch;                 /* 是否分支 */
    bool is_conditional;            /* 是否条件分支 */
    uint32_t target_id;             /* 跳转目标ID */
    bool may_fall_through;          /* 是否可能继续执行 */

    /* 依赖信息 */
    uint16_t dep_bitmap;            /* 依赖位图 */
    uint32_t depends_on[VM_REORDER_MAX_DEP_BITS]; /* 依赖的指令ID */
    uint32_t dep_count;             /* 依赖数量 */

    /* 重排序信息 */
    int32_t original_order;         /* 原始顺序 */
    int32_t scheduled_order;        /* 调度后顺序 */
    int32_t priority;               /* 调度优先级 */

    /* 伪依赖标记 */
    bool has_fake_dep;              /* 是否包含伪依赖 */
    uint32_t fake_dep_source;       /* 伪依赖来源 */
} vm_insn_desc_t;

/* 基本块 */
typedef struct {
    uint32_t id;                    /* 块ID */
    uint32_t entry_insn;            /* 入口指令 */
    uint32_t exit_insn;             /* 出口指令 */
    uint32_t insn_count;            /* 指令数量 */
    uint32_t predecessors[8];       /* 前驱块 */
    uint32_t successor_count;       /* 前驱数量 */
    uint32_t successors[8];         /* 后继块 */
    uint32_t successor_count;       /* 后继数量 */
} vm_basic_block_t;

/* 数据流分析结果 */
typedef struct {
    uint64_t def_regs;              /* 定义的寄存器位图 */
    uint64_t use_regs;              /* 使用的寄存器位图 */
    uint64_t live_in;               /* 入口活跃寄存器 */
    uint64_t live_out;              /* 出口活跃寄存器 */
    uint64_t killed_regs;           /* 杀死的寄存器 */
} vm_dataflow_info_t;

/* 重排序引擎上下文 */
typedef struct {
    /* 指令列表 */
    vm_insn_desc_t insns[VM_REORDER_MAX_INSNS];
    uint32_t insn_count;

    /* 基本块 */
    vm_basic_block_t blocks[VM_REORDER_MAX_INSNS]; /* 最多与指令数相同 */
    uint32_t block_count;

    /* 数据流信息 */
    vm_dataflow_info_t dataflow[VM_REORDER_MAX_INSNS];

    /* 依赖矩阵 */
    uint8_t dep_matrix[VM_REORDER_MAX_INSNS][VM_REORDER_MAX_INSNS / 8 + 1];

    /* 虚拟寄存器映射 */
    uint32_t vreg_map[VM_REORDER_MAX_REGS];
    uint32_t vreg_count;

    /* 调度配置 */
    bool enable_fake_deps;          /* 启用伪依赖 */
    bool enable_register_rename;    /* 启用寄存器重命名 */
    uint32_t fake_dep_probability;  /* 伪依赖概率 (0-100) */
    uint32_t seed;                  /* 随机种子 */

    /* 统计 */
    uint32_t reorder_count;         /* 重排序次数 */
    uint32_t fake_dep_count;        /* 伪依赖数量 */
} vm_reorder_engine_t;

/* 重排序结果 */
typedef struct {
    uint32_t *new_order;            /* 新顺序的指令索引 */
    uint32_t count;                 /* 指令数量 */
    bool reordered;                 /* 是否发生重排 */
} vm_reorder_result_t;

/* ==================== API函数 ==================== */

/*
 * 初始化重排序引擎
 */
int vm_reorder_init(vm_reorder_engine_t *engine, uint32_t seed);

/*
 * 添加指令
 */
int vm_reorder_add_insn(vm_reorder_engine_t *engine,
                        const vm_insn_desc_t *insn);

/*
 * 构建控制流图
 */
int vm_reorder_build_cfg(vm_reorder_engine_t *engine);

/*
 * 执行数据流分析
 * 计算DEF-USE链和活跃变量
 */
int vm_reorder_dataflow_analysis(vm_reorder_engine_t *engine);

/*
 * 构建依赖图
 * 识别真实的指令间依赖关系
 */
int vm_reorder_build_dep_graph(vm_reorder_engine_t *engine);

/*
 * 验证依赖关系
 * 检查两个指令是否可以安全重排
 */
bool vm_reorder_can_reorder(const vm_reorder_engine_t *engine,
                            uint32_t insn_a,
                            uint32_t insn_b);

/*
 * 插入伪依赖
 * 人为创建看似真实的依赖关系
 */
int vm_reorder_insert_fake_deps(vm_reorder_engine_t *engine,
                                uint32_t probability);

/*
 * 执行指令重排序
 * 在保持程序语义的前提下重新排列指令
 */
int vm_reorder_schedule(vm_reorder_engine_t *engine,
                        vm_reorder_result_t *result);

/*
 * 寄存器重命名
 * 将物理寄存器映射到更大的虚拟寄存器空间
 */
int vm_reorder_rename_registers(vm_reorder_engine_t *engine);

/*
 * 应用重排序结果
 * 根据调度结果重新排列指令
 */
int vm_reorder_apply(vm_reorder_engine_t *engine,
                     const vm_reorder_result_t *result,
                     vm_insn_desc_t *out_insns,
                     uint32_t max_out);

/*
 * 生成依赖位图验证数据
 * 用于运行时验证依赖关系
 */
int vm_reorder_gen_dep_verification(const vm_reorder_engine_t *engine,
                                    uint32_t insn_id,
                                    uint8_t *out_bitmap,
                                    size_t max_len);

/*
 * 运行时验证依赖
 * 检查实际执行是否符合预期的依赖关系
 */
bool vm_reorder_verify_dep(const uint8_t *expected_bitmap,
                           const uint8_t *actual_bitmap,
                           size_t len);

/*
 * 计算指令的依赖闭包
 * 找出所有依赖该指令的指令集合
 */
int vm_reorder_dep_closure(const vm_reorder_engine_t *engine,
                           uint32_t insn_id,
                           uint32_t *out_deps,
                           uint32_t max_deps);

/*
 * 查找可重排的指令对
 * 用于测试和验证
 */
int vm_reorder_find_reorderable_pairs(const vm_reorder_engine_t *engine,
                                      uint32_t *out_pairs,
                                      uint32_t max_pairs);

/*
 * 虚拟寄存器分配
 * 将虚拟寄存器映射到物理寄存器
 */
int vm_reorder_allocate_vregs(vm_reorder_engine_t *engine,
                              uint32_t max_physical_regs);

/*
 * 获取虚拟寄存器映射
 */
const uint32_t *vm_reorder_get_vreg_map(const vm_reorder_engine_t *engine);

/*
 * 导出重排序配置
 * 将重排序决策导出为可序列化的格式
 */
size_t vm_reorder_export_config(const vm_reorder_engine_t *engine,
                                uint8_t *out,
                                size_t max_len);

/*
 * 导入重排序配置
 */
int vm_reorder_import_config(vm_reorder_engine_t *engine,
                             const uint8_t *data,
                             size_t len);

/*
 * 重置引擎状态
 */
void vm_reorder_reset(vm_reorder_engine_t *engine);

/*
 * 安全清除引擎
 */
void vm_reorder_clear(vm_reorder_engine_t *engine);

/* ==================== 辅助函数 ==================== */

/*
 * 检查是否有依赖关系
 */
static inline bool vm_reorder_has_dep(const vm_reorder_engine_t *engine,
                                       uint32_t from,
                                       uint32_t to) {
    if (!engine || from >= engine->insn_count || to >= engine->insn_count) {
        return false;
    }
    uint32_t byte_idx = to / 8;
    uint32_t bit_idx = to % 8;
    return (engine->dep_matrix[from][byte_idx] & (1u << bit_idx)) != 0;
}

/*
 * 设置依赖关系
 */
static inline void vm_reorder_set_dep(vm_reorder_engine_t *engine,
                                       uint32_t from,
                                       uint32_t to) {
    if (!engine || from >= engine->insn_count || to >= engine->insn_count) {
        return;
    }
    uint32_t byte_idx = to / 8;
    uint32_t bit_idx = to % 8;
    engine->dep_matrix[from][byte_idx] |= (1u << bit_idx);
}

/*
 * 清除依赖关系
 */
static inline void vm_reorder_clear_dep(vm_reorder_engine_t *engine,
                                         uint32_t from,
                                         uint32_t to) {
    if (!engine || from >= engine->insn_count || to >= engine->insn_count) {
        return;
    }
    uint32_t byte_idx = to / 8;
    uint32_t bit_idx = to % 8;
    engine->dep_matrix[from][byte_idx] &= ~(1u << bit_idx);
}

/*
 * 检查是否是内存操作
 */
static inline bool vm_reorder_is_memory_op(const vm_insn_desc_t *insn) {
    return insn && (insn->is_load || insn->is_store);
}

/*
 * 检查是否是控制流指令
 */
static inline bool vm_reorder_is_control_op(const vm_insn_desc_t *insn) {
    return insn && insn->is_branch;
}

#endif /* VM_REORDER_H */
