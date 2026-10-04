> 2026-10-04：按维护者要求移除仓库中的单元测试、差分/回归测试源码、测试运行脚本及对应测试 CI。下文测试命令和结果作为历史记录保留；需要复现时请使用删除前的提交 `16543b971eaeb247e8720f8aa927d45fe97e90c0`。代码生成、CPSV 布局生成和发布证据校验工具仍保留。

# IR-VMP 验证记录

## 2026-10-01：v2 GEP 边界与 iOS 验证入口复核

最终集成时重新执行 stack、GF2 和未签名 iPhoneOS Release App 构建，分别得到 4,155 例 `HOST_VMP_PASS`、4,096 例 `HOST_VMP_PASS` 和 `IOS_RELEASE_APP_BUILD_PASS`。当前源码哈希、产物哈希与原始报告摘要保存在 [final-integration-macos-arm64.json](validation/final-integration-macos-arm64.json)；源码提取、Python/JSON 语法、补丁哈希和 diff 检查均通过，策略文件的非注释配置与基准完全一致。

[GEP 独立探针](validation/gep-v2-probe-macos-arm64.json) 使用同一 `pointer-gep-v2` 插件，在 `randISA=0/1` 下各通过 204 例、12 个目标，共 408 例真实主机差分。覆盖带 padding / packed struct、嵌套常量偏移、i32/i64 动态索引和有效数组范围内的负索引；返回地址同时对照原生实现和独立 C 布局断言。动态步长 65,536 在两种配置下均明确 skipped，函数体不变且没有生成 VM 字节码/引擎。此探针验证地址计算和指针返回，不代替 stack 的内存写入验证。

[iOS 复核记录](ios/review-validation.json) 对应最终共享 C suite 和 v2 插件：串行加四个 worker 通过 20,480 例、40 次已知答案检查；所有 worker 到达 mutex/condition 启动门后统一释放。损坏输出和部分线程创建失败均被拒绝；启动门证明线程已就绪，不保证同时被 CPU 调度。

最终独立 iPhoneOS Release App 构建为 `IOS_RELEASE_APP_BUILD_PASS`，未签名 binary 为 188,408 bytes，两个 wrapper 的最终机器码均直接调用 VM 引擎。结果门禁检查本次 UUID、五组 seed/计数/返回值、四个 worker 就绪及有限正耗时；执行前以当前 `RUNNING` 报告覆盖旧 PASS，异常或中断不能保留旧成功状态。合成 payload/故障注入共拒绝 26 种设备报告和 8 种 devicectl 报告，并检查异常/中断处理。

`devicectl` 的退出字段来自本机 Xcode 框架静态检查，尚无真实设备 JSON 或签名/部署端到端证据；缺失退出证据会阻断。`iphone_release_verified=false`、`device_executed=false`，上述构建、主机执行及合成门禁均不能替代 iPhone Release 验收。旧 [ios/validation.json](ios/validation.json) 保留原插件及原 harness 的历史结果，不与这份 v2 记录混用。

## 2026-10-01：累积 pointer-gep-v2 主机验证（当前 stack 状态）

[pointer-gep-v2-macos-arm64.json](validation/pointer-gep-v2-macos-arm64.json) 保存独立插件 provenance、完整执行报告、最终机器码与反例。基于固定上游 `81808e195c9a40a01c36b1016ed7e6fbd96a4a3e` 的累积补丁插件 SHA-256 为 `a07f243b2a1fe20f0f8fcc2a1606f9d4357420611337032552cc02b4281dd3fe`；环境为 macOS arm64、LLVM 22.1.8，仓库基准 `8787f600a5b85bcb792644c87e0ef83c83a4fe3e`。v2 相对固定上游包含 v1 指针支持与新增 GEP 修复，不重写旧 v1 失败记录。

**当前 v2 的 stack、GF2 与 pointer 探针均通过真实主机 VM 差分。** 这些隔离样本为 `host_verified`，不证明生产函数或全部传递调用已保护；native helpers/external calls 仍在 VM 之外。

| 验证 | 实测结果 | 范围与证据边界 |
| --- | --- | --- |
| stack 真实 VM 差分 | `HOST_VMP_PASS`，4,155 例 | 显式 `--lower-constant-intrinsics`；三目标 pass、原始/O2 后 verifier、字节码/handler/引擎结构通过；返回值、结构体/栈写入、错误路径副作用一致 |
| GF2 回归 | `HOST_VMP_PASS`，4,096 例 | 两目标独立转换、IR 检查与主机执行通过 |
| pointer eq/ne/null 回归 | `HOST_POINTER_VMP_PASS`，800 例 | `randISA=0/1` 各 400；四探针每配置 pass、原始/O2 后 IR 与真实差分通过 |
| stack 最终机器码 | 三个 protected wrapper 均直接 `bl ___vm_engine` | 检查实际链接差分可执行文件；不证明调用到的 native helpers/external calls 也进入 VM |
| 故意损坏 stack 返回值 | 退出码 1，`FAIL line=27 case=0` | 将优化后 `protected_vm_stack_crypto_init` 最终 i32 返回 XOR 1；IR verifier 与编译通过，真实差分明确拒绝 |

v2 的 GEP emitter 用目标 DataLayout 的 `accumulateConstantOffset` 计算常量结构体和嵌套聚合的实际字节偏移，保留 padding；动态 GEP 按 allocation size 计算步长，超出 65,535 拒绝，避免旧实现截断/饱和。GEP 依据目标数据布局计算地址、不会自身读取内存，语义参考 [LLVM 官方 GEP 说明](https://llvm.org/docs/GetElementPtr.html)。支持范围限定 address space 0、64-bit pointer/index layout，动态形式为一个 i32/i64 index 或 array `[0,index]`。其他动态多索引、scalable type、非零 address space 与非 64-bit layout 继续拒绝。这些实现范围不等于每种 GEP 形式都有完整执行覆盖。

Darwin stack 的 `llvm.objectsize` 仍需显式 LLVM 预处理，此通过不代表 VM 新增了 objectsize handler。固定 obfuscation seed=1，`hardened=0, antiDebug=0, encBytecode=0`；pointer probe 另测 `randISA=1`。尚无 stack 真机运行、生产集成、其他 seed/加固配置、性能或抗逆向强度结论。构建复现使用 README 入口加 `--patch-set pointer-gep-v2`，stack runner 加 `--lower-constant-intrinsics`；完整命令和最终产物反例脚本在 v2 JSON 中。

## 2026-10-01：本地指针补丁与独立 iOS Release App

本节追加两份独立证据：[pointer-eq-ne-v1-macos-arm64.json](validation/pointer-eq-ne-v1-macos-arm64.json) 与 [ios/validation.json](ios/validation.json)。前者使用基于固定上游 `81808e195c9a40a01c36b1016ed7e6fbd96a4a3e` 的本地补丁插件；后者使用下节记录的未修改上游插件。两者不能合并为同一个插件或设备通过结论，也不覆盖生产 SDK/App。

**本节已完成：v1 pointer eq/ne/null 主机差分 800 例、v1 GF2 主机回归 4,096 例、独立未签名 iPhoneOS Release App 构建，以及新 iOS harness 的 macOS 串行/并发 20,480 例。未完成：物理 iPhone 执行、签名/部署端到端验证、生产集成与性能评估。** v1 的 stack `BLOCKED_OR_FAILED` 保留为历史证据；首节 v2 修复 GEP 后的独立通过结果更新当前状态。

| 验证 | 实测结果 | 范围与证据边界 |
| --- | --- | --- |
| 本地补丁构建 | schema v2 provenance；插件 SHA-256 `e58eaae381b3809913a6c064836445a613c78df2ca97d303f05a32e1fb9b0e40` | 干净上游 checkout 保持不变；补丁仅应用到 staging tree；LLVM 22.1.8、macOS arm64 |
| pointer 探针 | `HOST_POINTER_VMP_PASS`，800 例 | `randISA=0/1` 各 400；eq/ne、null、相同/不同对象、全局/局部对象与内部/one-past 指针；每配置四目标 pass、原始/O2 后 IR 与真实引擎结构均通过 |
| 补丁版 GF2 回归 | `HOST_VMP_PASS`，4,096 例 | 真实 VM 差分通过；固定 seed=1，`hardened=0, antiDebug=0, encBytecode=0` |
| 原上游 provenance 兼容 | schema v1 与 GF2 `HOST_VMP_PASS`，4,096 例 | 更新后的 runner 仍接受原上游独立 provenance；不是把原上游插件视为补丁版 |
| pointer 拒绝边界与 provenance 门禁 | 有序谓词、address space 1、非空构建目录、篡改补丁 provenance 均拒绝 | `opt` 返回 0 不等于目标转换；有序谓词四目标 pass 均 skipped |
| stack 未预处理 | `BLOCKED_OR_FAILED` | pointer/null 不再是首个阻断；init 因 `llvm.objectsize.i64.p0` skipped，其他两个目标转换，不满足整套验收 |
| stack 可选预处理 | `BLOCKED_OR_FAILED`，差分退出码 1 | LLVM `lower-constant-intrinsics` 后三个目标 pass/IR 结构通过，但 `case=0` 结构体 `memcmp` 失败；不是 VM objectsize 支持或主机等价通过 |
| 独立 iPhoneOS Release App | `IOS_RELEASE_APP_BUILD_PASS` | arm64 iOS 15.0 target、iPhoneOS SDK 26.0、`-O2 -DNDEBUG`；未签名 binary 187,672 bytes；两 GF2 wrapper 最终机器码直接调用 `___vm_engine` |
| 新 iOS harness 主机串行/并发 | 20,480 例、40 次已知答案检查，failed=0 | 1 次串行加 4 个 pthread workers；复用先前已验证的 macOS VM objects，没有重新调用插件，不是 iPhone 执行 |
| 新 harness 故意损坏结果 | 退出码 1，failed=1 | 证明新 harness 能拒绝损坏的 VM 结果；不代替设备部署验收 |
| 缺设备/签名的 device 模式 | `BLOCKED_OR_FAILED`，退出码 1 | 设备清单为空，有效签名身份 0；缺 `--device/--identity/--profile` 不会把 unsigned build 记作 device pass |

指针补丁使用原生 pointer registers 的独立 `OP_ICMP_PTR`，仅支持 address space 0 的 eq/ne/null。它改变 `OP_COUNT` 与 decoy base，补丁与未修改上游插件/字节码不能混用。probe 的 `randISA=1` 通过不扩展到其他 seed、加密或 hardened 配置。v1 stack 诊断观察到 `vm_stack_crypto_ctx_t` 的字段写入发生在错误字节偏移，作为结构体 GEP 缺陷线索保存；诊断程序正常退出只说明成功输出差异，不能改变该历史差分失败状态。v2 的独立通过不倒改这份 v1 记录。

独立 App 的签名、安装、启动与设备报告回传路径已实现，但没有端到端设备执行证据。`iphone_release_verified=false`、`device_executed=false`。冷启动、函数延迟分位数、生产体积变化、其他配置和抗逆向强度仍未评估。结构化文件保存命令、工具版本与哈希；原始 `/tmp` 路径为本机临时证据，可能失效。

构建本地补丁使用 README 的固定上游入口加 `--patch-set pointer-eq-ne-v1`；probe 命令及 stack 的 `--lower-constant-intrinsics` 命令见 pointer JSON。独立 App 与真机模式的准确命令见 [ios/README.md](ios/README.md)。本轮没有恢复已删除单元测试，没有改动生产源码或解除 Pass 13 `full` 阻断。

## 2026-10-01：未修改上游插件的 macOS arm64 实测（历史记录）

在分支基准 `cc18cbe` 上验证，并修复本轮发现的调用检查缺口与 CI 覆盖缺口。环境为 macOS 26.2 (25C56)、LLVM 22.1.8、Xcode 26.0 (17A324)、iPhoneOS SDK 26.0。使用干净的固定上游提交 `81808e195c9a40a01c36b1016ed7e6fbd96a4a3e` 构建真实插件，没有修改上游源码。

提交前按要求删除 `test_runner.py` 单元测试套件及其 CI 调用。下文的 7 项/6 项测试结果是删除前的历史记录，不能作为当前仓库仍提供该测试套件的说明；差分验证入口、实际产物验收检查及基线 CI 保留。

**GF2 在本机获得 `HOST_VMP_PASS`；stack 的三个候选被上游拒绝。GF2 的 iOS arm64 编译和链接通过，尚未进行真机执行或签名验证。**

| 验证 | 实测结果 | 范围 |
| --- | --- | --- |
| 验收逻辑测试 | 7 项通过 | 包含断开的引擎调用、错误表槽、注释伪证据、跳过目标及旧成功报告覆盖 |
| GF2 原生基线 | `BASELINE_ONLY_PASS`，4,096 例 | 已知答案、整数边界、0..256 字节长度、未对齐输入、输入不变 |
| stack 原生基线 | `BASELINE_ONLY_PASS`，4,155 例 | 返回值、结构体/栈写入、错误路径副作用 |
| ASan + UBSan | 两组原生基线均通过，无诊断 | 使用 Apple clang；不是对 VM 引擎的 sanitizer 验证 |
| 固定版插件构建 | `Obfuscator.dylib` 构建成功，写出 provenance | 构建有上游警告，不代表零警告 |
| GF2 真实 VM 差分 | `HOST_VMP_PASS`，4,096 例 | LLVM verifier、每目标 pass 报告、原始和 O2 后 IR 均通过；收紧验收逻辑后重新执行 |
| stack 真实 VM 验收 | `BLOCKED_OR_FAILED`，退出码 1 | 三个目标均因 `icmp ne ptr ..., null` 不被上游支持而跳过；没有执行 VM 差分 |
| 故意破坏 VM 结果 | 差分程序退出码 1，`FAIL line=15 case=0` | 在真实优化后 IR 中将返回值 XOR 1，证明测试能拒绝错误结果 |
| 最终机器码检查 | macOS / iOS 两个 wrapper 均调用 `___vm_engine` | 检查最终链接产物；未见这两个 wrapper 回退到原始 GF2 实现，不是通用等价证明 |
| iOS arm64 编译链接 | `IOS_ARM64_COMPILE_LINK_PASS` | LLVM 22 生成 iOS IR/object，Xcode clang 链接独立差分可执行文件；`LC_BUILD_VERSION` 为 iOS、minos 15.0、SDK 26.0 |

两个 GF2 目标分别生成 65 字节（xorshift64）和 105 字节（FNV-1a）字节码。配置仍为 `hardened=0, antiDebug=0, encBytecode=0`，固定混淆 seed 为 1；不作性能、保护强度或其他 seed 的结论。

### 本轮修复

1. 原 `inspect_ir()` 只要求函数体含有字节码、handler 表和某个 `call`，把引擎调用换成 `native_fallback` 后仍会通过。现在要求真实引擎调用同时使用该目标的字节码和 handler 表，间接调用还核查表槽实际指向 `__vm_engine`。检查仅接受固定版本已观察到的 wrapper 形态；新增回归反例，并用真实 macOS/iOS IR 重新验证。
2. 原 CI 只运行默认 GF2 套件。现在使用 OS × suite 矩阵覆盖 GF2 与 stack，分别上传报告，并把 `cprisk_secure_zero.h` 纳入触发路径。此处验证了等效本地命令，尚未验证修改后的远端 Actions 运行结果。

### 复现与证据

结构化结果、插件及产物哈希见 [macos-arm64-llvm22.json](validation/macos-arm64-llvm22.json)。插件 SHA-256：`fbe46e386b25172f20e3836d130d4f486f9d0af8dbc87091c2a4d2d7b5403231`。原始报告和大型 IR/二进制保留在本次机器的 `/tmp` 目录，JSON 中记录其路径；这些临时路径不保证跨机器可用。

真实主机验证使用以下命令（先按 README 构建插件；替换路径即可复现）：

```bash
python3 experiments/ir-vmp/build_plugin.py \
  --source /tmp/cprisk-xollvm-validation-src \
  --llvm-root /opt/homebrew/opt/llvm@22 \
  --build-dir /tmp/cprisk-xollvm-validation-build --jobs 2

python3 experiments/ir-vmp/run.py --mode xollvm --suite gf2 \
  --clang /opt/homebrew/opt/llvm@22/bin/clang \
  --opt /opt/homebrew/opt/llvm@22/bin/opt \
  --plugin /tmp/cprisk-xollvm-validation-build/Obfuscator.dylib \
  --plugin-provenance /tmp/cprisk-xollvm-validation-build/plugin-provenance.json \
  --output /tmp/ir-vmp-mac-verified-gf2
```

将 `--suite` 改成 `stack` 并使用独立输出目录可复现上游拒绝。iOS 交叉构建的准确命令保存在结构化结果中，使用 `arm64-apple-ios15.0` 和 iPhoneOS SDK；并未把 macOS IR 强行改标签作为 iOS 产物，也未向 Apple clang 加载 LLVM 22 插件。

在此历史记录形成时，实际 App/SDK 构建集成、iPhone Release 运行、签名、并发、启动时间、延迟和体积评估尚未完成。后续独立 App 构建、主机并发与 unsigned binary 大小证据见上文 iOS 记录；物理 iPhone 执行、生产集成及性能评估仍未完成。生产 SDK 文件与 `full` 替换阻断保持不变，本实验不修复 Pass 13 的原生参数/返回/指令语义缺口。

## 先前 Linux 基线记录（保留）

日期：2026-10-01。环境：Linux，GCC 13.3.0；无 clang/opt/Xcode/iPhone。

| 验证 | 结果 | 可得结论 |
| --- | --- | --- |
| `python3 -m unittest discover -s experiments/ir-vmp -p 'test_*.py' -v` | 6 项通过 | 版本、provenance、逐函数报告、IR 结构、旧成功报告覆盖的门禁行为通过合成用例 |
| `run.py --mode baseline-only --cc cc` | `BASELINE_ONLY_PASS`；4,096 例 | GF2 原生/原生差分与已知答案通过 |
| `run.py --mode baseline-only --suite stack --cc cc` | `BASELINE_ONLY_PASS`；4,155 例 | 栈操作原生/原生差分通过 |
| `run.py --mode xollvm` | `BLOCKED_OR_FAILED`；缺少 clang | 未执行上游插件，`vmp_verified=false` |
| `verify_sources.py` | 通过 | 实验提取函数与固定 SDK 源码一致 |

在此 Linux 基线记录形成时，没有对真实 xollvm 输出运行过结构门禁，也没有生成已通过的 `HOST_VMP_PASS`；后续主机验证见上文。合成测试不能代替真实产物验收。该 Linux 记录没有测定 VMP 性能、代码膨胀、抗逆向强度或 iOS 兼容性。默认 annotation 关闭字节码加密和额外加固，仅供正确性实验。

SDK 生产文件未修改。`full` 替换的既有阻断保持不变，当前改动不修复 Pass 13 的原生参数/返回/指令语义缺口。此历史阶段的 CI 运行未保护 baseline 和门禁测试，不构建或运行第三方插件；门禁单元测试及其 CI 调用后来已删除，当前只保留差分入口、实际产物验收和 baseline CI。
