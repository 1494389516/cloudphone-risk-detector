# IR-VMP 验证记录

## 2026-10-01：macOS arm64 实测

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

实际 App/SDK 构建集成、iPhone Release 运行、签名、并发、启动时间、延迟和体积评估仍未完成。生产 SDK 文件与 `full` 替换阻断保持不变，本实验不修复 Pass 13 的原生参数/返回/指令语义缺口。

## 先前 Linux 基线记录（保留）

日期：2026-10-01。环境：Linux，GCC 13.3.0；无 clang/opt/Xcode/iPhone。

| 验证 | 结果 | 可得结论 |
| --- | --- | --- |
| `python3 -m unittest discover -s experiments/ir-vmp -p 'test_*.py' -v` | 6 项通过 | 版本、provenance、逐函数报告、IR 结构、旧成功报告覆盖的门禁行为通过合成用例 |
| `run.py --mode baseline-only --cc cc` | `BASELINE_ONLY_PASS`；4,096 例 | GF2 原生/原生差分与已知答案通过 |
| `run.py --mode baseline-only --suite stack --cc cc` | `BASELINE_ONLY_PASS`；4,155 例 | 栈操作原生/原生差分通过 |
| `run.py --mode xollvm` | `BLOCKED_OR_FAILED`；缺少 clang | 未执行上游插件，`vmp_verified=false` |
| `verify_sources.py` | 通过 | 实验提取函数与固定 SDK 源码一致 |

没有对真实 xollvm 输出运行过结构门禁；合成测试不能代替该验收。没有生成已通过的 `HOST_VMP_PASS`，没有测定 VMP 性能、代码膨胀、抗逆向强度或 iOS 兼容性。默认 annotation 关闭字节码加密和额外加固，仅供正确性实验。

SDK 生产文件未修改。`full` 替换的既有阻断保持不变，当前改动不修复 Pass 13 的原生参数/返回/指令语义缺口。CI 仅运行未保护 baseline 和门禁测试，不构建或运行第三方插件。
