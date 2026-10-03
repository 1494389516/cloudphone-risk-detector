# IR-VMP 隔离验证

2026-10-03 vNext 增量：新增严格配置、两个真实业务候选的原样套件与 LLVM API
preflight。Linux LLVM 22.1.8 / pointer-gep-v2 下两个候选的 5 seed 共 106,380
例主机 VM 差分通过；仍未接入生产 SDK。[实施范围与复现](VNEXT_IMPLEMENTATION.md)
明确区分已完成的软件、缺失的生产接入和发布门槛。

本目录验证 **SDK 中少量 C 函数是否能被 xollvm 等价虚拟化**。不接入 SDK 默认构建，不解除 `VMPolicyConfig.validateNativeReplacementSupport()` 的 `full` 阻断，不把 `partial` 元数据当作函数保护。

当前交付是候选函数、差分基线、固定版本构建入口和失败关闭的验收流程。**累积本地补丁 `pointer-gep-v2` 在 macOS arm64 / LLVM 22.1.8 上通过 stack 4,155 例、GF2 4,096 例，以及指针 eq/ne/null 探针 800 例真实 VM 差分。** stack 必须显式启用 LLVM `lower-constant-intrinsics`；v2 修复 v1 暴露的结构体字段偏移问题，v1 失败证据保留为历史记录。通过范围是这些隔离函数及配置，原生 helper/外部调用仍在 VM 之外。

GEP 独立探针另通过 408 例，覆盖结构体布局、嵌套偏移和动态正负索引，并验证过大步长被拒绝。GF2 还用同一 v2 插件完成未签名的独立 iPhoneOS Release App 构建；App 与主机共用的 harness 链接 v2 macOS VM objects，通过 20,480 例串行/并发验证。**尚无 iPhone Release 执行或签名通过证据**：本机设备清单为空，有效签名身份为 0。详见 [验证记录](VALIDATION.md) 与 [iOS 复核记录](ios/review-validation.json)。CI 的绿色 baseline 仍只证明未保护版本和测试设施可运行。

## 固定输入

- SDK 源码基准：`53a6b1c9c555ba35423b2557caee450b2f234181`。
- xollvm：[`81808e195c9a40a01c36b1016ed7e6fbd96a4a3e`](https://github.com/und3ath/xollvm/tree/81808e195c9a40a01c36b1016ed7e6fbd96a4a3e)。未修改的上游插件与本地补丁插件分别记录 provenance 和结果。仅支持本实验核查过的 LLVM 22/23；clang、opt 和插件构建版本必须一致。
- 上游源码及本地补丁适用 Apache-2.0 WITH LLVM-exception。本目录保存审查过的补丁与 provenance，不 vendoring 完整上游源码，也不引入 Hikari/AGPL 代码。
- `sources.json` 与 `verify_sources.py` 检查完整 SDK 源文件 SHA-256、提取函数体逐字一致性及提取文件 SHA-256。源码更新后必须重新审查、更新基线，不静默跳过。

## 两组候选

| 套件 | 真实 SDK 函数 | 验证范围 |
| --- | --- | --- |
| `gf2`（默认） | `cprisk_gf2_xorshift64`、`cprisk_gf2_fnv1a` | 64 位整数参数/返回、循环、字节读取、0..256 长度、未对齐输入、输入不变、已知答案 |
| `stack`（边界） | `vm_stack_crypto_init`、`vm_stack_encrypt_push`、`vm_stack_push_encrypted` | 结构体/缓冲区写入、返回值、栈指针变化、错误路径副作用 |

GF2 函数是从实际源码中精确提取的 static 函数体；实验编译只改变符号名/链接可见性并加 annotation，不改生产实现。它们是机械语义验证样本，不代表这两个函数本身具有足够的秘密资产价值。

未修改的上游插件拒绝 stack 的指针 null 比较；本地补丁支持 address space 0 的 eq/ne/null，但不支持有序指针比较或非零 address space。历史 `pointer-eq-ne-v1` 在预处理后仍因结构体写入偏移错误而差分失败；`pointer-gep-v2` 使用目标 DataLayout 计算常量结构体/嵌套 GEP 的字节偏移，动态 GEP 使用 allocation size 并拒绝大于 65,535 的步长，在显式 `lower-constant-intrinsics` 后获得 stack `HOST_VMP_PASS`。这项预处理不是 VM 原生支持 `llvm.objectsize`。保留历史边界和原始 null/错误路径语义；两组测试都不能证明任意外部调用 ABI、Swift、ARC、async、异常或浮点语义正确。

## 运行未保护基线

从仓库根目录运行，需要 Python 3 和 C 编译器：

```bash
python3 experiments/ir-vmp/run.py --mode baseline-only --cc cc --output /tmp/ir-vmp-gf2
python3 experiments/ir-vmp/run.py --mode baseline-only --suite stack --cc cc --output /tmp/ir-vmp-stack
```

基线状态为 `BASELINE_ONLY_PASS`，`vmp_verified` 永远是 `false`。测试用同一源分别编译 `plain_` / `protected_` 名称的两个原生版本；此时 `protected_` 只是符号前缀，没有经过虚拟化。

## 构建固定版本插件

在已有 LLVM 22/23 开发工具链的 macOS/Linux 主机准备源码：

```bash
git clone https://github.com/und3ath/xollvm /tmp/xollvm-src
git -C /tmp/xollvm-src checkout --detach 81808e195c9a40a01c36b1016ed7e6fbd96a4a3e
python3 experiments/ir-vmp/build_plugin.py \
  --source /tmp/xollvm-src \
  --llvm-root /path/to/llvm22 \
  --build-dir /tmp/xollvm-build \
  --jobs 2
```

需要 CMake、LLVM 开发文件及匹配的 clang/clang++/opt/llvm-config。脚本不下载工具，不接受脏源码或非空构建目录。构建完成写出 `plugin-provenance.json`，记录上游 commit、工具版本和插件哈希。它是本地可复核记录，不是签名供应链证明。

验证当前本地补丁时，在上述命令加 `--patch-set pointer-gep-v2` 并使用独立的空构建目录。v2 是相对固定上游的累积补丁，包含 pointer eq/ne/null 与 GEP 修复，无需先应用 v1。构建脚本只向 staging tree 应用已审查、固定哈希的补丁，保留上游 checkout 干净；schema v2 provenance 额外记录 patch manifest、各文件前后哈希与补丁源码树哈希。补丁改变 `OP_COUNT` 和 decoy base，**不能混用补丁版与未修改上游版插件/字节码**。当前结果见 [pointer-gep-v2 记录](validation/pointer-gep-v2-macos-arm64.json)；历史 v1 的通过与拒绝边界见 [pointer-eq-ne-v1 记录](validation/pointer-eq-ne-v1-macos-arm64.json)。

## 运行真实 VM 差分

`--plugin` 使用构建报告中的真实插件路径（平台可能是 `.so` 或 `.dylib`）：

```bash
python3 experiments/ir-vmp/run.py --mode xollvm --suite gf2 \
  --clang /path/to/llvm22/bin/clang \
  --opt /path/to/llvm22/bin/opt \
  --plugin /tmp/xollvm-build/Obfuscator.so \
  --plugin-provenance /tmp/xollvm-build/plugin-provenance.json \
  --output /tmp/ir-vmp-host
```

实验 annotation 为 `obf: vm(minBlocks=1,hardened=0,antiDebug=0,encBytecode=0)`：先隔离正确性；未打开字节码加密，不作抗逆向强度结论。README 中旧式 `useAES` 参数不能代替此版本实际读取的 `encBytecode`。

runner 使用新建构建目录，检查每个目标的上游报告、字节码、handler 表与执行器结构，并进行 IR verifier、优化后检查和差分执行。调用检查要求目标字节码和 handler 表传入真实 VM 引擎；间接调用还检查加载的表槽是否指向引擎，不接受无关函数调用。该检查仅支持固定上游版本已核查的 wrapper 形态，不是通用 LLVM 数据流证明。任一目标静默 skip、缺产物或结果不一致均失败。缺工具时写失败报告并返回非零，不复用旧的成功状态。

即使得到 `HOST_VMP_PASS`，也只表示该主机、该工具链、这些输入及结构检查通过。它不是形式化等价证明、完整反虚拟化评估或 iOS 发布认证。

stack 使用 v2 插件时，增加 `--suite stack --lower-constant-intrinsics` 并选择独立输出目录。GEP 支持限定 address space 0、64-bit pointer/index layout；动态形式限定单个 i32/i64 index 或 array `[0,index]`。其他动态多索引、scalable type、非零 address space 与非 64-bit layout 拒绝，不能从本次通过外推到任意 GEP。

## 接入 iOS 前的剩余门槛

1. 当前 GF2 与 v2 stack 固定配置已完成 macOS VM 差分、目标 IR 与最终机器码核查；其他候选、配置和工具链仍须分别验收。
2. GF2 已用 iOS target/sysroot 生成 IR 和 Mach-O object，并用 Xcode 工具链构建未签名的独立 Release App；[iOS 入口](ios/README.md) 提供显式设备/签名参数及失败关闭的部署验收。仍需实际 App/SDK 构建集成。不要向不匹配的 Apple clang 加载此 LLVM 插件。
3. 在有设备、有效签名身份和匹配 provisioning profile 的环境执行 iPhone Release 差分，验证链接/签名、调用约定、并发与异常退出。主机新 harness 已通过 20,480 例，但不代替设备执行；独立未签名 binary 大小已有记录，冷启动、函数延迟分位数和生产体积评估仍未完成。
4. 只有这些证据齐备后才单独讨论生产构建接入。当前 Mach-O Pass 13 的语义缺口不因本实验而消失。

源码审查参考：上游 `VMPass_Emitter.cpp`、`VMPass_Impl.cpp`、`VMPass_Wrapper.cpp`、`include/llvm/Transforms/Obfuscator/VMPass_Impl.h`、`ObfReport.cpp`、`utils/gates/vm.py`。当前重点审查 i8/i16 算术、多带值 return、结构体 GEP、浮点、volatile/atomic 和特殊外调 ABI。pointer `icmp` 的已验证范围仅为本地补丁的 address space 0 eq/ne/null；其他指针谓词继续拒绝。
