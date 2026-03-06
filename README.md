<p align="center">
  <img src="https://img.shields.io/badge/Platform-iOS%2014%2B-0A84FF?style=for-the-badge&logo=apple&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Swift-5.9-F05138?style=for-the-badge&logo=swift&logoColor=white" alt="Swift">
  <img src="https://img.shields.io/badge/SDK-3.5.0-FF3B30?style=for-the-badge" alt="SDK">
  <img src="https://img.shields.io/badge/SPM-Compatible-34C759?style=for-the-badge&logo=swift&logoColor=white" alt="SPM">
  <img src="https://img.shields.io/badge/License-Proprietary-8E8E93?style=for-the-badge" alt="License">
</p>

<h1 align="center">CloudPhoneRiskKit</h1>

<p align="center">
  <strong>iOS 端环境风险检测 SDK — 识别越狱、云手机、Hook 注入与机房设备</strong>
</p>

<p align="center">
  面向业务风控场景的本地信号采集与决策引擎，提供硬件指纹、行为熵分析、<br>
  反篡改对抗与场景化策略，帮助 App 在端侧完成高质量的环境风险判定。
</p>

---

## 版本演进

| 版本 | 定位 | 关键能力 |
|------|------|----------|
| 3.0 | 架构重建 | 四层检测体系、场景化决策树、信号状态模型 |
| 3.1 | 检测补强 | 关键符号扩展、trampoline 识别、路径判定强化 |
| 3.5 | **安全加固 + 检测能力补强** | DRM 等级检测、电池物理熵、RWX 内存扫描、字符串混淆、SVC 直调、PLT 完整性校验、HMAC 签名 |

## 架构概览

```
┌──────────────────────────────────────────────────────┐
│                   业务应用层                           │
│            evaluate(scenario: .payment)               │
├──────────────────────────────────────────────────────┤
│               RiskDetectionEngine                     │
│   场景策略 ─ 决策树 ─ 组合规则 ─ 盲挑战 ─ HMAC 签名   │
├──────────┬───────────┬───────────┬───────────────────┤
│ Layer 1  │  Layer 2  │  Layer 3  │     Layer 4       │
│ 硬件指纹  │  一致性    │  行为熵    │   服务端聚合       │
├──────────┼───────────┼───────────┼───────────────────┤
│ GPU 名称  │ PLT/GOT   │ 触摸熵    │  公网 IP / ASN    │
│ DRM 等级  │ RWX 内存   │ 传感器熵   │  机房属性         │
│ 设备型号  │ Hook 检测  │ 电压方差   │  IP 聚合度        │
│ 电池计数器 │ 挂载点     │ 时序模式   │  风险标签         │
│ Board ID │ SVC 双路   │ 耦合分析   │  黑名单           │
└──────────┴───────────┴───────────┴───────────────────┘
```

### 信号三分类

| 类型 | 判定方式 | 典型信号 | 权重 |
|------|----------|----------|------|
| **硬信号** | 本地独立判定，单点即可触发 | 越狱、DRM 降级、ChargeCounter 异常、PLT 篡改 | 80-100 |
| **软信号** | 需结合场景综合评分 | VPN、行为异常、电压方差低、挂载点异常 | 30-75 |
| **服务端信号** | 依赖外部聚合 | 机房 IP、ASN 黑名单、IP 设备聚合度 | 55-100 |

## 3.5 新增能力

### 检测维度扩展

| 能力 | 优先级 | 层级 | 原理 |
|------|--------|------|------|
| **DRM 等级检测** | P0 | Layer 1 | FairPlay/AVContentKeySession 探测硬件安全解码能力，L3 或失败即高风险 |
| **电池 ChargeCounter** | P0 | Layer 1 | 硬件寄存器值 -1 或 0 = 未实现 = 云机特征，误杀率极低 |
| **电压时序方差** | P0 | Layer 3 | 100ms 间隔 5 次采样，方差接近 0 = 返回固定模拟值 |
| **匿名 RWX 内存扫描** | P0 | Layer 2 | `vm_region_64` 检测 Frida trampoline 页（匿名 + rwx） |
| **挂载点异常检测** | P1 | Layer 2 | `getmntinfo()` 双向校验：虚拟化 FS 黑名单 + 必需挂载白名单 |

### 安全加固

| 能力 | 优先级 | 说明 |
|------|--------|------|
| **字符串多段混淆** | P0 | 每个敏感字符串独立混淆（XOR / ROT13 / Caesar / Base64 / 逆序），不存在统一解密入口 |
| **SVC 直调加固** | P0 | `sysctlbyname` / `stat` 通过 RTLD_NEXT 绕过 PLT hook，双路验证检测篡改 |
| **PLT/GOT 完整性** | P0 | 10 个关键函数的地址基线校验，`dladdr` + Mach-O `.text` 段范围验证 |
| **内存安全清零** | P0 | `SecureBuffer` / `SecureString` 使用 `memset_s` 防编译器优化，用完即销毁 |
| **上报语义混淆** | P1 | 字段名运行时映射 + 10-15 个诱饵字段注入，攻击者无法区分真伪 |
| **HMAC 结论签名** | P1 | HKDF-SHA256 派生设备密钥 + HMAC-SHA256 签名，服务端验签防篡改 |
| **Release 日志禁用** | P0 | 生产构建自动禁用所有日志输出，避免 panic 路径泄露信息 |

## 快速开始

### 环境要求

- macOS 14.0+ / Xcode 15.0+
- iOS 14.0+ 部署目标
- Swift 5.9+

### 集成方式

**Swift Package Manager**

```swift
// Package.swift
dependencies: [
    .package(path: "../cloudphone-risk-detector/RiskDetectorApp")
]
```

```swift
// target
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "CloudPhoneRiskKit", package: "CloudPhoneRiskKit"),
    ]
)
```

**XcodeGen**

```bash
cd RiskDetectorApp
brew install xcodegen
xcodegen generate
open RiskDetectorApp.xcodeproj
```

### 基础用法

```swift
import CloudPhoneRiskKit

// 1. 启动采集（建议 didFinishLaunching 调用）
CPRiskKit.shared.start()

// 2. 同步评估
let report = CPRiskKit.shared.evaluate(config: .default, scenario: .payment)
print(report.score, report.isHighRisk, report.summary)

// 3. async/await
let report = await CPRiskKit.shared.evaluateAsync(config: .default, scenario: .login)

// 4. 停止采集
CPRiskKit.shared.stop()
```

### 场景化决策

```swift
let cfg = CPRiskConfig.default
cfg.defaultScenario = .payment
cfg.enableTemporalAnalysis = true
cfg.enableAntiTamper = true

let report = CPRiskKit.shared.evaluate(config: cfg, scenario: .payment)

// report.score     → 0-100 风险分
// report.isHighRisk → 是否触发高风险
// report.tampered   → 是否检测到篡改
// report.signals    → 所有触发的信号列表
```

支持场景：`login` / `payment` / `register` / `accountChange` / `sensitiveAction` / `apiAccess`

### 服务端信号注入

```swift
CPRiskKit.setExternalServerSignals(
    publicIP: "203.0.113.10",
    asn: "AS64500",
    asOrg: "Cloud-DC",
    isDatacenter: true,
    ipDeviceAgg: 260,
    ipAccountAgg: 800,
    geoCountry: "CN",
    geoRegion: "BJ",
    riskTags: ["cloud_phone", "dc_ip"]
)
```

### HMAC 签名验证（3.5 新增）

```swift
import CloudPhoneRiskKit

let report = CPRiskKit.shared.evaluate()

// 从设备特征派生密钥（不存储在 SDK 中）
let deviceKey = DeviceKeyDeriver.deriveKey(
    deviceID: report.deviceID,
    hardwareMachine: "iPhone15,3",
    kernelVersion: "Darwin 23.0.0"
)

// 签名结论
let signed = SignedRiskConclusion.sign(report: report, deviceKey: deviceKey)

// 服务端验签
let valid = signed.verify(deviceKey: deviceKey)  // false → 结论被篡改
```

### 安全上报信封

```swift
let envelope = try CPRiskKit.shared.buildSecureReportEnvelope(
    report: report,
    sessionToken: "server-issued-token",
    signingKey: "hmac-signing-key",
    keyId: "k1"
)

let json = try envelope.toJSONString(prettyPrinted: false)
// 包含 nonce、签名、字段混淆、诱饵字段
```

## 项目结构

```
RiskDetectorApp/
├── Package.swift
├── project.yml
├── App/                                    # SwiftUI Demo 应用
│   ├── Views/                              # Dashboard / Results / History / Settings
│   └── ViewModels/                         # Detection / History / Settings ViewModel
└── Sources/
    ├── CloudPhoneRiskKit/                  # SDK 核心
    │   ├── CloudPhoneRiskKit.swift         # 主入口 CPRiskKit
    │   ├── Jailbreak/                      # 越狱检测引擎 (11 个检测器)
    │   ├── Detection/
    │   │   ├── AntiTampering/              # 调试器 / Frida / 代码签名 / 内存完整性 / RWX 扫描
    │   │   ├── AntiBypass/                 # SDK 完整性 / PLT 校验 / 随机化 / 指纹反混淆
    │   │   └── Adapter/                    # 信号适配器
    │   ├── Decision/                       # 决策引擎 / 决策树 / 场景策略
    │   ├── Providers/                      # 信号提供者
    │   │   ├── DRMCapabilityProvider       # DRM 等级检测 (3.5)
    │   │   ├── BatteryEntropyProvider      # 电池物理熵 (3.5)
    │   │   ├── MountPointProvider          # 挂载点异常 (3.5)
    │   │   ├── VPhoneHardwareProvider      # 云手机硬件特征
    │   │   ├── DeviceHardwareProvider      # 设备硬件信息
    │   │   ├── LayeredConsistencyProvider  # 跨层一致性
    │   │   └── ...
    │   ├── Risk/                           # 报告 / 评分 / 信封 / 混淆 / HMAC
    │   │   ├── RiskConclusionSigner        # HMAC 签名 (3.5)
    │   │   ├── DecoyFieldInjector          # 诱饵字段 (3.5)
    │   │   └── ...
    │   ├── Util/                           # 工具
    │   │   ├── ObfuscatedStrings           # 字符串多段混淆 (3.5)
    │   │   ├── SVCDirectCall               # SVC 直调加固 (3.5)
    │   │   ├── SecureBuffer                # 内存安全清零 (3.5)
    │   │   └── ...
    │   ├── Behavior/                       # 触摸 / 运动传感器 / 耦合分析
    │   ├── Analysis/                       # 时序分析 / 异常检测 / 行为基线
    │   ├── CloudPhone/                     # 云手机本地信号
    │   ├── Network/                        # VPN / 代理检测
    │   ├── Device/                         # 设备指纹 / Keychain ID
    │   ├── Config/                         # 远程配置
    │   └── Storage/                        # AES-GCM 加密存储
    └── CloudPhoneRiskAppCore/              # App 封装层
```

## 检测器矩阵

### 越狱检测 (11 个)

| 检测器 | 检测维度 |
|--------|----------|
| `FileDetector` | 越狱文件路径探测 |
| `DyldDetector` | 越狱动态库加载 |
| `EnvDetector` | `DYLD_INSERT_LIBRARIES` 等环境变量 |
| `SysctlDetector` | 调试状态与进程信息 |
| `SchemeDetector` | Cydia / Sileo 等 URL Scheme |
| `HookDetector` | 函数 prologue 完整性 |
| `HookFrameworkSymbolDetector` | Hook 框架符号存在性 |
| `ObjCIMPDetector` | ObjC 方法实现地址验证 |
| `PrologueBranchDetector` | ARM64 函数入口跳转指令 |
| `PointerValidationDetector` | 指针有效性验证 |
| `IndirectSymbolPointerDetector` | 间接符号指针完整性 |

### 反篡改 & 抗绕过

| 检测器 | 检测维度 |
|--------|----------|
| `AntiTamperingDetector` | P_TRACED / 可疑父进程 / 调试环境变量 / 时序异常 |
| `DebuggerDetector` | 调试器附加检测 |
| `FridaDetector` | dylib 镜像 / 环境变量 / 端口 / 文件 |
| `RWXMemoryScanner` | 匿名 RWX 内存段（Frida trampoline）**(3.5)** |
| `CodeSignatureValidator` | LC_CODE_SIGNATURE 验证 |
| `MemoryIntegrityChecker` | 内存完整性校验 |
| `SDKIntegrityChecker` | DYLD 注入 / 可疑镜像 / Bundle 路径 / 代码签名 |
| `PLTIntegrityGuard` | 10 个关键函数的 PLT 地址基线校验 **(3.5)** |

### 设备 & 环境信号

| Provider | 检测维度 |
|----------|----------|
| `DRMCapabilityProvider` | FairPlay DRM 等级 + 设备交叉验证 **(3.5)** |
| `BatteryEntropyProvider` | ChargeCounter / EnergyCounter / 电压时序方差 **(3.5)** |
| `MountPointProvider` | 虚拟化 FS 黑名单 + 必需挂载白名单 **(3.5)** |
| `VPhoneHardwareProvider` | GPU 名称 / 设备型号 / Board ID / 内核版本 |
| `LayeredConsistencyProvider` | Prologue 完整性 / Timing / 传感器熵 / 触摸熵 |

## 配置参考

### CPRiskConfig

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `enableBehaviorDetect` | `true` | 行为采集（触摸 + 运动） |
| `enableNetworkSignals` | `true` | VPN / 代理检测 |
| `threshold` | `60` | 高风险判定阈值 |
| `enableRemoteConfig` | `true` | 远程配置拉取 |
| `defaultScenario` | `.default` | 默认业务场景 |
| `enableTemporalAnalysis` | `true` | 时序分析 |
| `enableAntiTamper` | `true` | 反篡改检测（含 RWX / PLT） |

### 场景策略阈值

| 场景 | 中风险 | 高风险 | 严重 | 越狱处置 |
|------|--------|--------|------|----------|
| `default` | 30 | 55 | 80 | challenge |
| `login` | 35 | 60 | 85 | challenge |
| `register` | 25 | 50 | 75 | block |
| `payment` | 20 | 45 | 70 | block |
| `sensitiveAction` | 15 | 40 | 65 | block |

## 安全设计

### 字符串保护

```
明文 "Apple Paravirtual device"
  → 分 3 段，每段不同变换：
    XOR(key=0x42) + ROT13 + reverseBytes
  → IDA 搜索不到任何明文特征
  → 用完通过 SecureString 清零
```

### 双路验证

```
标准调用 sysctlbyname("hw.machine") → "iPhone15,3"
加固调用 RTLD_NEXT → sysctlbyname → "iPhone15,3"
结果一致 → 正常
结果不一致 → tampered 信号触发
```

### HMAC 防篡改

```
客户端：score|isHighRisk|timestamp|nonce|tampered → HMAC-SHA256(deviceKey)
攻击者：修改 score → 无法重算 HMAC（不知道 deviceKey 派生输入）
服务端：验签失败 → 反而暴露攻击行为
```

## 文档索引

| 文档 | 路径 |
|------|------|
| SDK 接入说明 | `CloudPhoneRiskKit_使用说明.md` |
| 项目技术文档 | `RiskDetectorApp/RiskDetectorApp项目文档.md` |
| 架构设计 | `RiskDetectorApp/docs/architecture-design.md` |
| API 设计 | `RiskDetectorApp/docs/api-design.md` |
| 模块依赖 | `RiskDetectorApp/docs/module-dependencies.md` |

## 构建

```bash
cd RiskDetectorApp
swift build
```

> 推荐真机调试。模拟器环境下 DRM 检测、电池采样、部分越狱检测器返回 `unavailable`。

## 免责声明

本项目仅供安全研究与学习用途。使用者应遵守当地法律法规，不得用于任何非法目的。

---

<p align="center"><sub>CloudPhoneRiskKit 3.5.0 — Security Hardening + Detection Enhancement</sub></p>
