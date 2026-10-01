# 隔离的 iPhone Release GF2 验证入口

此入口从真实 SDK 提取的两个 GF2 函数生成 iPhoneOS IR，通过匹配的 LLVM 22/23 与固定 xollvm 插件生成真实 VM object，再由 Xcode 的 Apple clang 将最小 UIKit App 以 `-O2 -DNDEBUG` 链接。没有修改主 App、生产 SDK、默认构建或 Pass 13 `full` 阻断。

每次调用创建新构建目录和 UUID，检查插件 provenance、源码提取一致性、逐函数 pass 报告、原始/优化后 IR 和最终链接机器码。机器码检查只接受当前固定版本两个 wrapper 直接 `bl ___vm_engine` 的形态；其他合法形态也可能被拒绝，需要审查后扩展。产物不剥离符号，以保留验收证据。

## 构建独立 App

从仓库根目录运行，要求本机已有 Xcode、iPhoneOS SDK、匹配 LLVM 和已构建插件：

```bash
python3 experiments/ir-vmp/ios/run.py --mode build-only \
  --llvm-root /opt/homebrew/opt/llvm@22 \
  --plugin /tmp/cprisk-xollvm-validation-build/Obfuscator.dylib \
  --plugin-provenance /tmp/cprisk-xollvm-validation-build/plugin-provenance.json \
  --output /tmp/ir-vmp-iphone-release-build
```

成功状态为 `IOS_RELEASE_APP_BUILD_PASS`。`iphone_release_verified=false`、`device_executed=false`：这只证明真实 VM object、最小 App 链接和结构验收成功。`report.json` 提供 App 路径、完整命令、工具版本、哈希、机器码证据和未签名 binary 字节数；大型 stdout 保存到单独文件。这里的 Release 指上述优化配置，不代表 App Store 归档、正式 App 集成或生产发布验收。

## 签名并在 iPhone 上执行

需要已配对、已启用开发者模式的 iPhone，以及现有有效签名身份和适用于该设备、该 bundle ID 的 provisioning profile。脚本不下载证书、不修改钥匙串、不注册新设备；使用显式提供的签名材料。先用以下命令核查条件：

```bash
xcrun devicectl list devices --timeout 15 --json-output /tmp/ir-vmp-device-inventory.json
security find-identity -v -p codesigning
```

提供实际设备 ID、身份和 profile 路径后运行：

```bash
python3 experiments/ir-vmp/ios/run.py --mode device \
  --plugin /tmp/cprisk-xollvm-validation-build/Obfuscator.dylib \
  --plugin-provenance /tmp/cprisk-xollvm-validation-build/plugin-provenance.json \
  --device IPHONE_DEVICE_ID \
  --identity 'Apple Development: Your Name (IDENTITY)' \
  --profile /path/to/matching.mobileprovision \
  --bundle-id com.cprisk.irvmp.release \
  --output /tmp/ir-vmp-iphone-release-device
```

脚本先构建、核查 profile 标识和过期时间，然后签名并执行 `codesign --verify --strict`、`devicectl install app` 和 `process launch --console`。专用 App 自动运行并把 JSON 原子写入 `Documents/report-<本次 UUID>.json` 后退出；脚本从本次安装的 App 数据容器取回该文件，检查 UUID、physical-device 标识、iPhone model、Release 配置、全部差分结果、启动门及已就绪 worker 数。每条设备命令均保存并检查 devicectl 官方 JSON 的 `info.outcome=success`。启动还要求 `result.terminationResult.exitCode=0`、无 terminatingSignal、`wasCoreDumpCreated=false`；字段缺失或形态改变会阻断。

该 terminationResult 路径来自本机 Xcode 26 / devicectl 477.30 的 CoreDeviceClientJSONSupport 导出符号及 Codable 字段静态检查。`--console` 的本机帮助说明明确要求等待 App 退出，但当前没有设备可验证实际 JSON；此门禁尚未端到端确认，不能将合成 payload 验收当作真实设备 schema 或退出验收通过。

只有这些检查全部通过才输出 `IPHONE_RELEASE_VMP_PASS`、`iphone_release_verified=true`。脚本在调用工具前先原子写入当前 UUID 的 `RUNNING`、`iphone_release_verified=false`，覆盖旧成功状态；任何构建、签名、安装、启动、异常退出、文件回传或结果门禁失败均返回非零并原子覆盖 `report.json` 为 `BLOCKED_OR_FAILED`。外部中断会留下本次 `RUNNING`，不会沿用旧成功状态。App 内存崩溃、pthread join 或其他同步操作失败、写文件失败不会产生可接受的结果。缺少设备/签名参数也会失败，即使构建已经通过。

## 执行范围与证据边界

`differential.c` 包含 xorshift64 的 0/1 已知答案、FNV-1a 的空输入/`hello` 已知答案；每次 invocation 共 8 次 plain/protected 已知答案检查和 4,096 个差分 case。覆盖整数边界、0..256 字节长度、偏移一字节的输入、输入未改变。App 和 host smoke 共用 `cprisk_ios_differential_suite`：一个串行 invocation 后创建 4 个 pthread workers，每个 worker 到达 mutex/condition 启动门后等待；全部就绪才统一释放。每线程独立 seed、输入数组和结果，避免全局 seed 数据竞争。合计 20,480 cases、40 次已知答案检查。启动门证明四个 worker 均已就绪，不保证操作系统将四条线程同时调度到 CPU。

设备 JSON 给出全套 harness 的执行耗时，主报告给出 binary 体积。这不是冷启动、单函数延迟分位数、性能基准或抗逆向强度评估。仍使用固定 obfuscation seed=1、`hardened=0, antiDebug=0, encBytecode=0`；不能外推到其他配置、函数或完整 SDK。

2026-10-01 实测：[validation.json](validation.json)。本机设备清单为空、有效签名身份为 0，因而只通过未签名 iPhoneOS Release App 构建。host 并发验证的 20,480 cases 通过，以及损坏 VM 结果被拒绝，仅验证新 harness 与 macOS VM objects；**尚无 iPhone 实际执行、签名或设备文件回传通过结果**。device 签名/部署流程已经实现，端到端正确性仍须设备实测。

后续审阅与 v2 插件验收单独记录在 [review-validation.json](review-validation.json)，保留上述历史证据。共享启动门 suite 链接新 v2 插件生成的 macOS GF2 objects 通过；损坏输出及创建线程失败均被拒绝；畸形 JSON、异常和中断不会留下旧 PASS。新的未签名 iPhoneOS Release App 构建通过，**仍无设备执行通过结果**。
