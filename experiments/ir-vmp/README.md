# IR-VMP 隔离验证

本目录验证 **SDK 中少量 C 函数是否能被 xollvm 等价虚拟化**。不接入 SDK 默认构建，不解除 `VMProtectorPass.validateNativeReplacementSupport()` 的 `full` 阻断，不把 `partial` 元数据当作函数保护。

当前交付是候选函数、差分基线、固定版本构建入口和失败关闭的验收流程。**没有 iPhone Release 验证，也没有已通过的 LLVM VM 执行结果。** CI 的绿色 baseline 只证明未保护版本和测试设施可运行。

## 固定输入

- SDK 源码基准：`53a6b1c9c555ba35423b2557caee450b2f234181`。
- xollvm：[`81808e195c9a40a01c36b1016ed7e6fbd96a4a3e`](https://github.com/und3ath/xollvm/tree/81808e195c9a40a01c36b1016ed7e6fbd96a4a3e)。仅支持本实验核查过的 LLVM 22/23；clang、opt 和插件构建版本必须一致。
- 上游 LICENSE：Apache-2.0 WITH LLVM-exception。这里不复制上游实现，也不引入 Hikari/AGPL 代码。
- `sources.json` 与 `verify_sources.py` 检查完整 SDK 源文件 SHA-256、提取函数体逐字一致性及提取文件 SHA-256。源码更新后必须重新审查、更新基线，不静默跳过。

## 两组候选

| 套件 | 真实 SDK 函数 | 验证范围 |
| --- | --- | --- |
| `gf2`（默认） | `cprisk_gf2_xorshift64`、`cprisk_gf2_fnv1a` | 64 位整数参数/返回、循环、字节读取、0..256 长度、未对齐输入、输入不变、已知答案 |
| `stack`（边界） | `vm_stack_crypto_init`、`vm_stack_encrypt_push`、`vm_stack_push_encrypted` | 结构体/缓冲区写入、返回值、栈指针变化、错误路径副作用 |

GF2 函数是从实际源码中精确提取的 static 函数体；实验编译只改变符号名/链接可见性并加 annotation，不改生产实现。它们是机械语义验证样本，不代表这两个函数本身具有足够的秘密资产价值。

stack 套件包含上游暂不支持的指针比较，以及可能无法降低的内存操作，**预计会被 VMP 拒绝**。保留它来暴露兼容性边界，不能删除 null 检查、改参数语义来制造“通过”。两组测试都不能证明任意外部调用 ABI、Swift、ARC、async、异常或浮点语义正确。

## 运行未保护基线

从仓库根目录运行，需要 Python 3 和 C 编译器：

```bash
python3 -m unittest discover -s experiments/ir-vmp -p 'test_*.py' -v
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

runner 使用新建构建目录，检查每个目标的上游报告、字节码、handler 表与执行器结构，并进行 IR verifier、优化后检查和差分执行。任一目标静默 skip、缺产物或结果不一致均失败。缺工具时写失败报告并返回非零，不复用旧的成功状态。

即使得到 `HOST_VMP_PASS`，也只表示该主机、该工具链、这些输入及结构检查通过。它不是形式化等价证明、完整反虚拟化评估或 iOS 发布认证。

## 接入 iOS 前的剩余门槛

1. 在真实 macOS 工具链完成上述 VM 差分；审阅每目标产物与最终机器码，排除原始实现残留/原生回退。
2. 用相同 iOS target/sysroot 生成 IR 和 Mach-O object，交 Xcode 链接。不要向不匹配的 Apple clang 加载此 LLVM 插件。
3. 对 iPhone Release 执行相同已知答案与差分用例，验证链接/签名、调用约定、并发、异常退出、启动时间、延迟和体积。
4. 只有这些证据齐备后才单独讨论生产构建接入。当前 Mach-O Pass 13 的语义缺口不因本实验而消失。

源码审查参考：上游 `VMPass_Emitter.cpp`、`VMPass_Impl.cpp`、`VMPass_Wrapper.cpp`、`include/llvm/Transforms/Obfuscator/VMPass_Impl.h`、`ObfReport.cpp`、`utils/gates/vm.py`。当前重点排除 i8/i16 算术、pointer icmp、多带值 return、浮点、volatile/atomic 和特殊外调 ABI。
