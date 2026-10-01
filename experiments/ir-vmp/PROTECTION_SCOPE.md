# IR-VMP 保护范围与候选审查

审查日期：2026-10-01。SDK 源码基准：`8787f600a5b85bcb792644c87e0ef83c83a4fe3e`。本次只审查真实调用链、修正策略说明；没有向生产函数添加 annotation，没有接入 SDK/App 默认构建，也没有解除 Mach-O Pass 13 的 `full` 阻断。

优先推进两个小型 C 计算内核：**反调试策略选择**和**白盒增强扩散**。它们分别参与风险处置和签名材料计算，输入、结果消费以及可绕过的边界可以定位。两者当前均为 `planned`，不是已经通过 xollvm 的候选。适合拆出做下一轮语义实验，不表示固定上游已支持其全部 IR。

## 状态定义与当前证据

状态按具体函数、源码哈希、工具链、插件哈希、annotation 与 seed 分别记录，不能从一个函数推到其调用者或整个模块。

| 状态 | 必须具备的证据 | 不足以推进状态的证据 |
| --- | --- | --- |
| `planned` | 已定位生产函数、调用者、参数/结果与语义门槛 | YAML 名单、源码 annotation、原生/原生 baseline |
| `converted` | 每目标 pass 实际转换；目标字节码、handler 与真实引擎调用关联通过；转换前后 IR verifier 通过 | pass 退出码为零、静默 skip、无关 VM 符号、未替换的 partial 元数据 |
| `host_verified` | `converted` 加真实主机 VM 差分/已知答案执行；记录实际用例和工具链范围 | 只编译或链接、原生差分、合成报告 |
| `device_verified` | 对同一配置在物理 iPhone 上运行 Release 差分，保存设备、签名、退出状态与运行报告 | 模拟器、iOS object/link 成功、安装成功、App 启动但未完成差分 |

下表分别引用 [未修改上游插件的 macOS arm64 / LLVM 22 记录](validation/macos-arm64-llvm22.json)、[历史 pointer-eq-ne-v1 补丁记录](validation/pointer-eq-ne-v1-macos-arm64.json)、[当前累积 pointer-gep-v2 补丁记录](validation/pointer-gep-v2-macos-arm64.json)、[历史独立 iOS Release App 记录](ios/validation.json) 与 [最终 iOS 入口复核](ios/review-validation.json)。每个插件的 provenance、哈希和结果独立；不得把旧插件结果归到新插件。最终 iOS 构建和共享 suite 的主机并发均使用 v2 插件产物，没有物理 iPhone 执行证据。

| 目标/范围 | 当前已入库状态 | 证据与限制 |
| --- | --- | --- |
| 实验提取的 `cprisk_gf2_xorshift64` / `cprisk_gf2_fnv1a` | `host_verified` | 未修改上游、v1 与 v2 分别通过 4,096 例；固定 seed=1，`hardened=0, antiDebug=0, encBytecode=0`；v2 unsigned iPhoneOS Release App 构建通过；共享 suite 链接 v2 macOS VM objects 通过 20,480 例/40 次已知答案，四线程启动门通过；尚无 `device_verified` |
| 实验 pointer eq/ne/null 四个探针 | `host_verified`，限定本地 v1/v2 | 两补丁分别获得 `HOST_POINTER_VMP_PASS`；`randISA=0/1` 各 400 例，共 800；仅 address space 0，非业务生产函数；有序谓词与非零 address space 继续拒绝 |
| 实验 `vm_stack_crypto_init` / `vm_stack_encrypt_push` / `vm_stack_push_encrypted` | `host_verified`，限定本地 v2 加 LLVM 预处理 | v2 `HOST_VMP_PASS`，4,155 例；逐目标转换、原始/O2 后 IR 与最终机器码通过，损坏返回值被拒绝；需 `lower-constant-intrinsics`。未修改上游 pointer/null 拒绝及 v1 GEP 差分失败均保留为历史；native helpers/external calls 不在 VM 内 |
| 下述两个业务内核 | `planned` | 本次调用链与源码审查；尚未生成候选 IR、运行插件或差分 |
| 生产 SDK 中相同名称的函数及其调用者 | 尚无生产 IR-VMP 转换证据 | 隔离实验只改变提取样本/实验符号，不改变生产调用路径 |
| `vmp_policy.yaml` 的 `full` 列表 | 策略请求，整体阻断 | `VMPolicyConfig.validateNativeReplacementSupport()` 在修改 Mach-O 前拒绝原生替换 |
| `vmp_policy.yaml` 的 `partial` 列表 | 策略请求，可发元数据 | 原生函数仍执行；不能视为 `converted` 或函数保护 |
| `never` 列表 | 明确排除 | 不是已验证的其他保护机制，也不是 IR-VMP 候选否决的永久结论 |

FNV-1a 与 xorshift 是公开算法，默认 GF(2) 种子也写在公开源码中。它们证明有限的整数/循环/读取语义可以被转换，**本身不是秘密资产**，也不证明矩阵、密钥或业务决策得到保护。所有状态均不附带性能、代码膨胀、抗 DCA 或抗反虚拟化强度结论。

本机设备清单为空、有效签名身份为 0。最终未签名独立 App 构建、188,408-byte binary 大小和主机并发通过均不能推进到 `device_verified`；缺设备/签名参数的 device 模式明确失败。签名/安装/启动/文件回传流程已有入口，端到端验证仍需匹配设备、身份和 provisioning profile；devicectl 退出字段仅有静态与合成验证。补丁改变 `OP_COUNT` 与 decoy base，不能混用补丁与未修改上游的插件/字节码。v2 GEP 支持限定 address space 0、64-bit pointer/index layout；动态步长最大 65,535，其他动态多索引、scalable type 等继续拒绝。[独立 GEP 探针](validation/gep-v2-probe-macos-arm64.json) 通过 408 例地址计算/指针返回差分，并拒绝 65,536 步长，不构成业务函数转换证据。

## 候选一：反调试策略选择

生产位置：[cprisk_integrity.c:667](../../RiskDetectorApp/Sources/CRiskCore/cprisk_integrity.c#L667)，`cprisk_antidebug_select_policy_bits_i`，约 60 行；运行态 plan/entry 结构定义在同文件 199–223 行。

- **输入**：`probe_bits`、`high_risk`；读取 `s_adbg_plan_i` 的 seed、probe immediate 与 union bits，以及 `s_adbg_entries_i[0..s_adbg_entry_count_i)` 的标识、策略、scatter slot、flags；两个输出指针允许为 null。
- **输出与副作用**：返回选中的策略位；按需写 selected count 和 identifier mix。无 syscall、锁、atomic、堆分配或外部函数调用；不修改 plan/entry。零条目直接回退 union bits，非零条目按风险级别筛选；runtime gate 条目总被选中；选中位为空再次回退 union bits。
- **调用及消费**：同文件 `cprisk_antidebug_apply_policies_i`（806 行；调用在 854 行）构造 `high_risk`，用返回位控制 runtime gate、delay、integrity escalation、tamper trap、debugger response。count/mix 目前被 `(void)` 丢弃，不能宣称它们构成上报证明。处置调用者还受计划有效性和运行模式影响。
- **业务价值**：保护的是探测结果到实际处置位的映射和按构建计划的选择逻辑；不是 seed 数值本身。比仅转换通用 PRNG 更接近风险处置链。
- **上游兼容性门槛**：主体为 i32/i64 位运算、结构体读取、循环和整数比较；null 输出指针带来 pointer `icmp`，本地补丁的 address space 0 eq/ne/null 已通过独立探针，但尚未验证这个业务内核。必须保留多个返回路径、global 地址、struct GEP、i32→i64 扩展与条件写入语义；v2 修复 stack 所遇 GEP 字段偏移并通过其差分，也不能替代此业务内核的独立验收。不能删除 null 路径或把 global 改成任意假数据来制造通过。提取时需要固定结构定义与宏值、精确保留函数体；未来若显式化全局状态参数，须另立版本，不能冒充逐字提取。
- **差分最低范围**：0/1/最大 entry 数；零 policy、runtime gate、不同 high-risk 值、union fallback；各 null 输出组合；校验返回值、count/mix、输入状态不变与输出哨兵。VM 转换和两次主机执行要分别验收；最终在 Release 产物确认 static 函数没有先被内联消失。
- **可绕过边界**：攻击者仍可 hook 探测结果、修改 plan/entries、修改调用者的 high-risk、把返回值替换为安全位，或拦截 poison/runtime-gate 的消费。单独虚拟化此函数不证明处置执行，也不能替代服务端校验。

## 候选二：白盒增强扩散小核

生产位置：[cprisk_whitebox.c:382](../../RiskDetectorApp/Sources/CRiskCore/cprisk_whitebox.c#L382)，`cprisk_whitebox_strong_mix_layer_i`，约 15 行；依赖小型 `cprisk_rotl8_i`（303 行）。

- **输入**：32 字节 `in`、32 字节 round constants；**输出**：写满 32 字节 `out`。它按固定索引取四个输入 lane，旋转 1/3/5 位并 XOR round constant。无全局写入、锁、系统调用或堆分配。
- **别名与有效域**：函数没有 null 检查；生产调用传入有效且互不重叠的 `next`、round constants、`scratch`。不能宣称函数支持 `in == out`：后续迭代会读到已改写的输入。实验需保留生产有效域，并单独记录重叠/无效指针不在该域；不能擅自赋予新语义。
- **调用及消费**：`cprisk_whitebox_eval_record_i`（924 行）仅在 header 的 `ENHANCED_DIFFUSION` 标志开启时，在每轮 first mix 后调用该函数（994 行），将 `scratch` 输入 second mix，再按 permutation 更新 state、XOR final mask 输出。`cprisk_whitebox_evaluate_domain`（1181 行）进行主计算/重算比较，其结果继续被 `cprisk_init_protection_whitebox_i`（`cprisk_integrity.c:1653`）用于 anchor tag、accumulator seed、loader key 和 runtime material。需把未开启 flag 的路径统计为**未执行这个内核**，不能把名录覆盖当作全部 domain 覆盖。
- **业务价值**：此内核参与配置对应的实际 PRF 状态变换，影响解密与签名材料；保护对象是受认证的构建配置和实际状态流。公开 XOR/rotate 公式自身不是密钥，内核也没有把白盒表从内存中隐藏。
- **上游兼容性门槛**：C 整数提升通常将 XOR/shift 写为 i32，但优化后可能出现 i8/vector 运算；固定上游对窄整数算术没有已验证支持。必须检查实际目标 IR，保留 trunc/zext、8-bit rotate、所有 byte load/store 和循环索引。`cprisk_rotl8_i` 必须原样提取并明确记录内联或直接调用的实际路径；不通过删去/重写 helper 保证转换。O0 和 O2 后 verifier/引擎结构与差分都要通过。
- **差分最低范围**：全零/全一、单 bit、32 个位置、round constants 单 bit/随机、边界字节、guard 哨兵与输入不变；再用合法 bundle 开/关 enhanced diffusion，比较完整 domain 输出和错误路径。小核差分不代替整条 PRF 链验证，首次实验不得默认启用字节码加密或把当前路径时序称为 constant-time。
- **可绕过边界**：可在输入/输出、header flag、first/second mix 或外层 domain 返回边界替换状态；主计算/重算复用相同实现时，同步篡改不会自动产生 mismatch。白盒表/运行态材料仍可读取，签名入口和服务端结果消费仍需单独审查。此候选不宣称抵抗 DCA。

## 暂不优先的范围

- **GF(2) 仿射 seal 整体**：`cprisk_gf2_affine_transform_16`（`cprisk_gf2_affine.c:119`）有真实消费链：`IntegritySealComputer.sealFromDigestPrefix` → `IntegrityChainSealProvider.computeSeal` → SE best-effort 签名、Keychain drift 比较、risk evidence。但函数涉及 `pthread_once`、`memcpy`/`memset`、`__builtin_parityll`/ctpop、null/default 参数和 input/output 别名；现有 FNV/xorshift 成功不能覆盖这些语义。Mach-O `never` 保留。seal 是固定仿射输出，不是密码学 MAC；上层 canonical、签名输入、Keychain 基线、缓存和 signal 消费都可成为绕过边界，当前代码也不能用“未来服务器验签”作为已落地保证。
- **stack 套件**：适合检验 pointer/null、结构体写入和错误路径；本次对 `Sources` 的静态搜索仅找到 `vm_stack_crypto.c` 内部调用与头文件宏，未找到生产 VM interpreter 的外部消费调用。因此保留为兼容性样本，不能宣称它已保护生产 VM 栈。动态/生成代码等隐藏调用须用最终链接与运行证据另证；source-level absence 不是通用无调用证明。
- **整段 Swift 风险引擎、SE/Keychain/attestation 入口**：跨 Swift/ARC、对象生命周期、async 或系统 ABI，超出现有 IR-VMP 样本范围。优先保证上述小核等价和真实结果消费，再讨论更大入口。

## 策略文件与生产门槛

本次 [vmp_policy.yaml](../../RiskDetectorApp/vmp_policy.yaml) 只更新注释，`version`、全部 hardening 参数及 full/partial/never 函数名单均不变。移除已删除 ABI 测试的当前覆盖说明，纠正 partial 隐藏常量/提高 hook 成本和“微秒变毫秒”等未经实际测量的表述。生产源码中的历史强度注释仍需另轮审查，不作为本文件结论。

`VMPolicyParser` 忽略注释；状态保存在这个独立文档，避免为 YAML 子集解析器增加未支持键。没有恢复单元测试。下一阶段只有同时满足“逐函数转换 → 主机差分 → iPhone Release 执行 → 真实 App/SDK 链接与消费核查”才能考虑生产接入；隔离实验成功不会消除 Pass 13 的原生参数、返回及指令语义缺口。
