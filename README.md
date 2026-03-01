<p align="center">
  <img src="https://img.shields.io/badge/Platform-iOS%2014%2B-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Swift-5.9-orange?style=flat-square" alt="Swift">
  <img src="https://img.shields.io/badge/SDK-3.0.0--beta.1-red?style=flat-square" alt="SDK">
  <img src="https://img.shields.io/badge/SwiftUI-✓-green?style=flat-square" alt="SwiftUI">
</p>

# RiskDetectorApp（基于 CloudPhoneRiskKit SDK 3.0）

面向 iOS 设备环境风险检测的研究型项目，聚焦以下三类信号：

- 设备完整性与越狱（硬信号）
- 网络与行为异常（软信号）
- 云手机/机房环境（本地推断 + 服务端聚合）

当前代码基线已包含 **SDK 3.0 增量能力**，版本常量为 `3.0.0-beta.1`。

## SDK 3.0 版本说明

### 核心升级

- **场景化风控决策**：支持 `login/payment/register/accountChange/sensitiveAction/apiAccess` 等场景。
- **策略动态化**：支持远程配置与服务端策略注入（JSON），可动态调整阈值、权重与动作。
- **抗绕过增强**：引入跨层一致性检查、信号变形（mutation jitter）、盲挑战（blind challenge）、服务端黑名单强制动作。
- **信号状态升级**：`RiskSignalState` 支持 `hard/soft/serverRequired/unavailable/tampered`，便于表达“需要服务端/不可用/疑似篡改”。
- **报告字段增强**：`RiskReportDTO` 与 JSON payload 增加 3.0 字段（如 `tamperedCount`、`gpuName`、`kernelBuild`、`deviceModel` 等）。

### 向后兼容

- 保留 `evaluate()` / `evaluate(config:)` 等旧入口。
- 新增 `evaluate(config:scenario:)` 与 async/await API，便于平滑迁移。

## 功能特性

### 设备与安全信号

- **越狱检测**：文件、dyld、环境变量、sysctl、URL Scheme、Hook、ObjC IMP、函数入口跳转等多检测器组合。
- **反篡改检测**：调试器、Frida、代码签名与内存完整性等对抗检测（可按配置开关）。
- **抗绕过策略**：信号变形、跨层一致性校验、黑名单命中硬阻断。

### 网络与云手机信号

- **网络信号**：VPN/代理检测。
- **本地云手机线索**：硬件、行为、时序特征联合推断。
- **服务端聚合信号注入**：公网 IP、ASN、机房属性、IP 聚合度、风险标签等。

### 决策与输出

- **场景化决策树**：按业务场景切分阈值、权重、动作映射。
- **统一 DTO 输出**：`RiskReportDTO` 同时提供 `hardSignals` / `softSignals` 供 UI 直接渲染。
- **安全存储**：AES-GCM 加密保存报告，密钥存放 Keychain。

## 页面预览

| Dashboard | Results | History | Settings |
|:---------:|:-------:|:-------:|:--------:|
| 风险仪表盘 | 检测结果 | 历史记录 | 配置管理 |
| 一键检测 | 信号详情 | 加密存储 | 调试开关 |

## 信号分类与状态

### 硬信号（Hard Signals）

本地可独立判定，检测到即可触发高风险路径：

- 越狱
- 篡改/干预（`tampered`）
- 黑名单命中（由策略决定是否强制阻断）

### 软信号（Soft Signals）

用于风险加权，需要结合场景与策略综合判断：

- VPN / 代理
- 行为异常与时序模式
- 云手机本地线索与服务端聚合信号

### UI 状态（四态）

| 状态 | 颜色 | 说明 |
|------|------|------|
| 检测到 | 红色 | 发现风险信号 |
| 未检测到 | 绿色 | 正常状态 |
| 不可用 | 灰色 | 运行环境限制（如模拟器） |
| 需服务端 | 紫色 | 需外部聚合信号参与 |

## 快速开始

### 环境要求

- macOS 13.0+
- Xcode 15.0+
- iOS 14.0+
- Swift 5.9+

### 方式 1：使用 XcodeGen（推荐）

```bash
# 进入项目
cd /path/to/cloudphone-risk-detector/RiskDetectorApp

# 安装 XcodeGen
brew install xcodegen

# 生成 Xcode 工程
xcodegen generate

# 打开工程
open RiskDetectorApp.xcodeproj
```

### 方式 2：直接打开已有工程

```bash
cd /path/to/cloudphone-risk-detector/RiskDetectorApp
open RiskDetectorApp.xcodeproj
```

### 运行

1. 选择目标设备（推荐真机；模拟器下部分信号会显示不可用）。
2. `Cmd + R` 运行。

## 项目结构

```text
cloudphone-risk-detector/
├── README.md
├── CloudPhoneRiskKit_使用说明.md
└── RiskDetectorApp/
    ├── App/                               # SwiftUI 应用层
    │   ├── Views/
    │   └── ViewModels/
    ├── Sources/
    │   ├── CloudPhoneRiskKit/             # SDK 核心
    │   │   ├── Jailbreak/                 # 越狱检测引擎与检测器
    │   │   ├── Detection/                 # 反篡改/抗绕过适配
    │   │   ├── Decision/                  # 场景策略、决策树、3.0 风险引擎
    │   │   ├── Providers/                 # 设备/云手机/服务端信号 Provider
    │   │   ├── Config/                    # 远程配置模型与拉取
    │   │   ├── Risk/                      # 报告模型与评分
    │   │   └── Storage/                   # 本地安全存储
    │   └── CloudPhoneRiskAppCore/         # App Core 封装层
    │       ├── RiskDetectionService.swift
    │       ├── RiskReportDTO.swift
    │       └── RiskAppConfig.swift
    ├── Tests/CloudPhoneRiskKitTests/      # 单元测试（含 V3UpgradeTests）
    ├── Package.swift
    └── project.yml
```

## 核心 API（SDK 3.0）

### 1) AppCore 一体化检测

```swift
import CloudPhoneRiskAppCore

let config = RiskAppConfig(
    enableBehaviorDetect: true,
    enableNetworkSignals: true,
    threshold: 60,
    storeEncryptionEnabled: true
)

RiskDetectionService.shared.start()

RiskDetectionService.shared.runAsync(config: config, save: true) { result in
    print("score:", result.dto.score)
    print("highRisk:", result.dto.isHighRisk)
    print("sdkVersion:", result.dto.sdkVersion ?? "nil")
    print("savedPath:", result.savedPath ?? "not saved")
}
```

### 2) 场景化评估（SDK 原生入口）

```swift
import CloudPhoneRiskKit

let cfg = CPRiskConfig.default
cfg.defaultScenario = .payment
cfg.enableTemporalAnalysis = true
cfg.enableAntiTamper = true

let report = CPRiskKit.shared.evaluate(config: cfg, scenario: .payment)
print(report.score, report.summary)
```

### 3) async/await（避免阻塞主线程）

```swift
import CloudPhoneRiskKit

let cfg = CPRiskConfig.default
let report = await CPRiskKit.shared.evaluateAsync(config: cfg, scenario: .login)
print(report.jsonString(prettyPrinted: true))
```

### 4) 服务端聚合信号注入

```swift
import CloudPhoneRiskKit

CPRiskKit.setExternalServerSignals(
    publicIP: "203.0.113.10",
    asn: "AS64500",
    asOrg: "Cloud-DC",
    isDatacenter: NSNumber(value: true),
    ipDeviceAgg: NSNumber(value: 260),
    ipAccountAgg: NSNumber(value: 800),
    geoCountry: "CN",
    geoRegion: "BJ",
    riskTags: ["cloud_phone", "dc_ip"]
)
```

### 5) 3.0 服务端策略注入（JSON）

```swift
import CloudPhoneRiskKit

let policyJSON = """
{
  "version": 3,
  "signalWeights": {
    "jailbreak": 1.4,
    "vpn_active": 1.1,
    "proxy_enabled": 1.1
  },
  "thresholds": {
    "block": 85,
    "challenge": 60,
    "monitor": 40
  },
  "newVPhonePatterns": ["kernel:virtual", "gpu:swiftshader"],
  "blocklist": ["AS9009", "cloud_phone_sim"],
  "mutation": {
    "seed": "sdk3.0-2026Q1",
    "shuffleChecks": true,
    "thresholdJitterBps": 500,
    "scoreJitterBps": 300
  },
  "blindChallenge": {
    "enabled": true,
    "challengeSalt": "server-secret-salt",
    "windowSeconds": 300,
    "rules": [
      {
        "id": "tamper_combo",
        "allOfSignalIDs": ["cross_layer_inconsistency"],
        "anyOfSignalIDs": ["vpn_active", "proxy_enabled"],
        "minTamperedCount": 1,
        "minDistinctRiskLayers": 2,
        "requireCrossLayerInconsistency": true,
        "weight": 80
      }
    ]
  }
}
"""

let ok = CPRiskKit.shared.setServerRiskPolicyJSON(policyJSON)
print("policy loaded:", ok)
```

### 6) 远程配置更新

```swift
import CloudPhoneRiskKit

_ = CPRiskKit.shared.setRemoteConfigEndpoint("https://example.com/risk-config.json")
CPRiskKit.shared.updateRemoteConfig { success in
    print("remote config updated:", success)
}
```

## 数据模型（节选）

```swift
public struct RiskReportDTO: Codable, Sendable {
    public var sdkVersion: String?
    public var reportId: String?
    public var generatedAt: String
    public var deviceID: String

    public var score: Double
    public var isHighRisk: Bool
    public var summary: String
    public var tamperedCount: Int?

    public var hardSignals: [SignalItemDTO]
    public var softSignals: [SignalItemDTO]

    // SDK 3.0 增量字段
    public var gpuName: String?
    public var kernelBuild: String?
    public var deviceModel: String?
}
```

## 配置选项

### AppCore (`RiskAppConfig`)

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `enableBehaviorDetect` | `true` | 行为采集开关 |
| `enableNetworkSignals` | `true` | 网络信号开关 |
| `threshold` | `60` | 总风险阈值 |
| `jailbreakThreshold` | `50` | 越狱判定阈值 |
| `storeEncryptionEnabled` | `true` | 报告加密存储 |
| `storeMaxFiles` | `50` | 本地报告文件上限 |

### SDK (`CPRiskConfig`)

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `enableRemoteConfig` | `true` | 启用远程配置 |
| `defaultScenario` | `.default` | 默认业务场景 |
| `enableTemporalAnalysis` | `true` | 启用时序分析 |
| `enableAntiTamper` | `true` | 启用反篡改检测 |
| `remoteConfigURLString` | `""` | 远程配置地址 |

## 主要检测器

| 类别 | 组件 | 说明 |
|------|------|------|
| 越狱检测 | `FileDetector` | 越狱文件路径探测 |
| 越狱检测 | `DyldDetector` | 越狱动态库加载检测 |
| 越狱检测 | `EnvDetector` | 环境变量异常检测 |
| 越狱检测 | `SysctlDetector` | 调试状态与进程信息检测 |
| 越狱检测 | `SchemeDetector` | 越狱 App URL Scheme 探测 |
| 越狱检测 | `HookDetector` / `ObjCIMPDetector` / `PrologueBranchDetector` | Hook 与函数入口完整性检测 |
| 反篡改 | `AntiTamperingDetector` / `DebuggerDetector` / `FridaDetector` / `MemoryIntegrityChecker` | 对抗动态调试与注入 |
| 抗绕过 | `SDKIntegrityChecker` / `RandomizedDetection` / `FingerprintDeobfuscation` | SDK 完整性与反脚本化 |

## 测试

已在本仓库执行通过：

```bash
cd /path/to/cloudphone-risk-detector/RiskDetectorApp
swift test
```

当前测试集包含 `V3UpgradeTests`、`EvaluateAsyncTests`、`RiskReportDTOTests` 等，覆盖 3.0 关键链路。

## 文档索引

- `CloudPhoneRiskKit_使用说明.md`：SDK 接入与调用说明
- `RiskDetectorApp/RiskDetectorApp项目文档.md`：项目技术文档
- `RiskDetectorApp/docs/architecture-design.md`：架构设计
- `RiskDetectorApp/docs/api-design.md`：API 设计

## 贡献

欢迎提交 Issue 和 Pull Request。

1. Fork 本项目
2. 创建特性分支（`git checkout -b feature/AmazingFeature`）
3. 提交更改（`git commit -m 'Add some AmazingFeature'`）
4. 推送分支（`git push origin feature/AmazingFeature`）
5. 发起 Pull Request

## 许可证

未指定（内部项目）。

## 免责声明

本项目仅供学习与安全研究。请遵守当地法律法规，不得用于任何非法用途。

---

<p align="center">
  Made with ❤️ for iOS Security Research
</p>
