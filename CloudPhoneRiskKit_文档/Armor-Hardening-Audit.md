# SDK 加固审计与修复记录

日期：2026-09-20。审计起点：`codex/fix-audit-findings`，提交 `7d8dc2a`。
范围：`cprisk-armor`、CRiskCore 对应运行时、Xcode 构建脚本与 SwiftPM Hikari 接入。

## 结论与当前行为

最优先问题是加固会破坏业务行为，或构建成功但保护并未实际生效。
当前代码不是可替换任意 ARM64/Swift 函数的语义保持型 VMP，也不能将自研 Pass 8/9 等同于已验证的 upstream OLLVM。

本次已修复确定的协议、顺序和错误处理问题，并阻止不安全的 VMP 原生替换产出。
**CLI 的 `--pass13`、`--all` 会在读写 Mach-O 前报错，Xcode 默认 `standard` profile 因包含 `--all` 同样失败。**
没有自动删掉 VMP 后继续报全量加固成功。非 VMP 流程需要显式选择 Pass，或选择已有 `appstore-safe` profile；该名称不代表审核通过或真机兼容性保证。

## 发现与处置

| 优先级 | 证据与影响 | 本次处置 |
| --- | --- | --- |
| P0 | `VMPatchRewriter` 三种跳板都以 BL 调用 VM 后 RET，没有保存 X30；VM 返回后可能停留在跳板 RET | 改为不覆盖 LR 的 B 尾跳转；补充三个模板的指令编码与目标地址检查。此接口仍只支持函数 ID ABI |
| P0 | `VMProtectorPass` 最多 lift 24 条指令；`ARM64Lifter` 将未知指令变成 rawRegion，可能提前 halt；`cprisk_vm_entry` 只收 func_id，并返回 `cprisk_vm_fold_result_i`，没有原函数参数／返回 ABI 桥 | CLI 阻断 Pass 13；库在 full policy 生效时、修改 Mach-O 前抛错。未来需重建语义保持路径后才能恢复 |
| P1 | partial tier 仅写 dispatch/bytecode，原函数入口不变；full 以前在跳板失败前就计入 program 数 | 只在跳板写入成功后计 full 指标；输出 full/partial/unresolved 指标；partial-only 不再通过 CLI 的有效变换后置条件 |
| P1 | 原顺序在锚点生成后修改 text，且 Pass 3 先于产生 split anchor 的 Pass 4；header 快照可能早于 load command 变更 | 用可测试拓扑约束排序；Pass 4 先于 3/12，8/9/13 先于 4，符号剥离后置，11 最后。Header 在快照前预留 section 并移除旧签名命令 |
| P1 | producer 的 loader key 未执行 runtime mini-VM 的 XOR A5 | Data/Text producer 同步 bootstrap，Swift/C 共享数值约束与回归检查 |
| P1 | String/Import/Header producer 使用额外静态输入，C 端用零输入；runtime 又将 Domain 8/9 绑定运行时环境 | Domain 2/8/9 使用零输入；仅保留 Domain 6/7 的运行时绑定。每次构建差异仍由 white-box 表携带 |
| P1 | VM self-check 构建期无法知道未来 session key，原 HMAC KDF 因此不可能稳定匹配 | 两端统一为 SHA256(runtime_material[32] + 18-byte label)，移除 session key；显式零材料必须有 fixture 开关 |
| P1 | self-expect 与 armor 分进程时可能使用不同 seed/material；注入失败被脚本降为 warning | 传递同一 seed；新增从 root key、anchor 和 white-box sections 校验并重建 material 的路径；失败传播到构建 |
| P1 | 配置了加固后仍可因工具/密钥缺失静默跳过；未知 CLI 参数和零命中混淆可能继续成功 | 明确请求时强制失败；未知/缺值参数拒绝；Pass 8/9 零变换拒绝；禁止自定义参数覆盖流水线输入、输出、key、seed |
| P2 | 只设置 Hikari wrapper 提示变量不能证明 SwiftPM 使用了 wrapper；required 单独开启可能无效 | required 本身触发检查，要求 SWIFT_EXEC 与 CC 配置，按路径或 PATH 检查可执行性。未验证 wrapper 身份、版本或混淆效果 |

## 已执行验证

环境为 Linux，没有 Swift、Clang、Xcode 和 Apple SDK。以下结果为本地实际执行：

- `python3 -m unittest discover -s contracts/tests -v`：22 个检查通过。
  其中 8 个为本轮加固契约检查：6 个源码/配置静态检查，2 个实际运行 Bash 的失败/可选跳过行为检查；其余 14 个为原有 wire contract 检查。
- `python3 contracts/generate.py --check`：通过，生成契约未漂移。
- 两个 Release 脚本及新增 CI Bash 块的 `bash -n`：通过。
- `project.yml` 和 workflow 的 YAML 解析：通过。
- `git diff --check`：通过。

已添加但**未在本机运行**的 macOS 检查：

- `swift test --package-path cprisk-armor`：拓扑、有效变换、跳板、KDF、header、seed、self-expect fixture 回归。
- 两个 CLI 的构建、未知/缺值参数拒绝、Pass 13/--all 拒绝且原文件不变、零材料拒绝。
- `xcodebuild -list` 检查工程可解析；它不等于实际 Release 构建或真机运行。

workflow 只是已修改的配置，尚未推送或取得 CI 成功结果。源码契约检查不能证明 Swift/C 算法等价、混淆质量或应用兼容性。

## 未闭合边界与下一步验收

1. **VMP 语义保持**：必须提供原函数参数／寄存器／栈和返回值桥，完整 CFG 与指令支持；拒绝未知指令、截断 lift 与不支持的 ABI。对真实函数做原生与 VM 差分执行，包含副作用、分支、调用、异常与 Swift 专有约定。在此之前不解除 Pass 13 阻断。
2. **Pass 12 启动闭环**：目前页面选择未证明会排除解密 bootstrap 本身；与 VM self-check 联用时，构建期密文窗口和运行时明文窗口还需对齐。CLI VMP 阻断避免了该组合产出，但单独 Pass 12 的真机可启动性仍待验证。
3. **CFF 与 full VMP 策略重叠**：后续恢复 full 前，必须拒绝同一函数被不兼容的变换重复处理。当前 full 阻断提供兜底；未宣称任意 Pass 组合有效。
4. **runtime material 重建假设**：当前按正常 white-box 初始化、string/data accumulator 为零、mini-VM bootstrap 开启重建。设备环境、调试开关、legacy 路径和异常初始化不在已验证范围；需在真机逐字节比对 producer/runtime 输出。seed 必须与生成 white-box sections 时一致。
5. **协议兼容**：静态 PRF 输入、mini-VM key、self-check KDF 和 seed 编码均有变化。需使用本轮工具重新加固并配套本轮 CRiskCore，不能将新版 runtime 与旧产物随意混搭。
6. **Xcode 真实构建**：检查已有的多个 phase 原地修改同一可执行文件是否触发依赖环／重复产物问题、placeholder 容量、签名时序、冷启动和增量构建。当前 YAML 解析不覆盖这些风险。
7. **OLLVM/Hikari 效果**：当前 Pass 8 是二进制指令替换，Pass 9 是自研 CFF；配置变量只能证明请求，不证明使用了特定编译器或有效混淆。验收需记录实际编译器身份/参数、目标命中数、前后反汇编和语义差分结果。

建议下一步先在 macOS 跑上述原生 gate，再以非 VMP 最小 Pass 组合验证签名、启动与密钥一致性；VMP 作为单独重建项，不能用增加混淆强度代替语义正确性。
