# RiskDetectorApp 项目技术文档

> **iOS 设备风险检测应用**
> 基于 CloudPhoneRiskKit 框架，实现越狱检测、云手机识别与网络信号分析的一体化解决方案

---

## 目录

- [项目概述](#项目概述)
- [核心架构](#核心架构)
- [模块设计](#模块设计)
- [数据模型](#数据模型)
- [信号三态系统](#信号三态系统)
- [UI 组件库](#ui-组件库)
- [检测引擎](#检测引擎)
- [配置管理](#配置管理)
- [存储与加密](#存储与加密)
- [目录结构](#目录结构)
- [技术栈](#技术栈)

---

## 项目概述

### 背景

在移动安全领域，设备环境的可信度评估是风控系统的第一道防线。越狱设备、云手机、代理/VPN 等非常规运行环境，往往与欺诈行为高度相关。

**RiskDetectorApp** 是一款面向 iOS 平台的设备风险检测工具，它将复杂的安全检测能力封装为直观的用户界面。

### 核心能力矩阵

| 检测类型 | 信号类型 | 检测方法 | 可信度 |
|---------|---------|----------|--------|
| 越狱检测 | 硬信号 | 文件探测、dyld分析、环境变量、系统调用、Hook检测 | 高 |
| VPN检测 | 软信号 | 网络接口前缀检测 (utun/ipsec) | 中 |
| 代理检测 | 软信号 | 系统代理配置读取 | 中 |
| 云手机检测 | 软信号 | 服务端信号：机房IP、IP聚合度、风险标签 | 需服务端 |
| 行为采集 | 辅助数据 | 触摸轨迹 + 陀螺仪数据 | - |

### 信号分类说明

- **硬信号**：本地可独立判定，检测到即可定性（如越狱）
- **软信号**：仅作为风险参考，需结合服务端数据或多维度综合判断

---

## 核心架构

### 三层架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                         UI Layer (SwiftUI)                       │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐ │
│  │ Dashboard  │  │  Results   │  │  History   │  │  Settings  │ │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘ │
│        │               │               │               │        │
│  ┌─────▼───────────────▼───────────────▼───────────────▼─────┐  │
│  │                    ViewModels (MVVM)                       │  │
│  │   DetectionVM    │    HistoryVM    │    SettingsVM        │  │
│  └───────────────────────────┬───────────────────────────────┘  │
└──────────────────────────────┼──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                    CloudPhoneRiskAppCore                         │
│  ┌─────────────────────┐    ┌─────────────────────┐             │
│  │ RiskDetectionService │    │  RiskAppConfigStore │             │
│  └──────────┬──────────┘    └─────────────────────┘             │
│             │                                                    │
│  ┌──────────▼──────────┐                                        │
│  │    RiskReportDTO    │  ← 统一数据输出格式                     │
│  │  (hardSignals/softSignals)                                   │
│  └─────────────────────┘                                        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                      CloudPhoneRiskKit                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │JailbreakEngine│  │NetworkSignals│  │BehaviorSignals│          │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │   Providers  │  │ PayloadCrypto│  │  RiskScoring │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

### 数据流向

```
用户点击检测
      │
      ▼
DetectionViewModel.detect(config:)
      │
      ▼
RiskDetectionService.evaluate()
      │
      ├── JailbreakEngine.evaluate()      → JailbreakDTO
      ├── NetworkSignals.collect()        → NetworkSignals
      ├── BehaviorSignals.collect()       → BehaviorSignals
      └── ExternalServerProvider.get()    → ServerSignals?
      │
      ▼
RiskScoring.calculate() → score (0-100)
      │
      ▼
RiskReportDTO.build() → hardSignals + softSignals
      │
      ▼
UI 展示（三态渲染）
```

---

## 模块设计

### CloudPhoneRiskKit（核心检测库）

| 模块 | 路径 | 职责 |
|------|------|------|
| **Jailbreak** | `Jailbreak/` | 越狱检测引擎，包含 10+ 检测器 |
| **Network** | `Network/` | VPN/代理/网络类型检测 |
| **Behavior** | `Behavior/` | 触摸轨迹和陀螺仪数据采集 |
| **Providers** | `Providers/` | 设备信息、服务端信号等数据提供者 |
| **Risk** | `Risk/` | 风险评分算法 |
| **Util** | `Util/` | 加密、日志、时间格式化等工具 |

### CloudPhoneRiskAppCore（应用核心层）

| 文件 | 职责 |
|------|------|
| `RiskDetectionService.swift` | 检测服务入口，协调各模块 |
| `RiskReportDTO.swift` | 统一输出格式，构建 hardSignals/softSignals |
| `RiskAppConfigStore.swift` | 配置持久化（UserDefaults） |
| `RiskAppConfig.swift` | 配置数据结构 |

### App（UI 层）

| 目录/文件 | 职责 |
|----------|------|
| `ViewModels/` | MVVM 架构的 ViewModel 层 |
| `Views/` | SwiftUI 视图 |
| `Views/Components/` | 可复用 UI 组件 |

---

## 数据模型

### RiskReportDTO（核心输出）

```swift
public struct RiskReportDTO: Codable, Sendable {
    // 基础信息
    public var sdkVersion: String?
    public var generatedAt: String          // ISO8601 时间戳
    public var deviceID: String             // 设备唯一标识

    // 风险评估
    public var score: Double                // 风险分数 0-100
    public var isHighRisk: Bool
    public var summary: String

    // 检测详情
    public var jailbreak: JailbreakDTO
    public var network: NetworkSignals
    public var behavior: BehaviorSignals
    public var server: ServerSignals?       // 可选：服务端聚合信号
    public var local: LocalSignals?

    // 信号列表（UI 直接使用）
    public var hardSignals: [SignalItemDTO]
    public var softSignals: [SignalItemDTO]
}
```

### SignalItemDTO（单个信号）

```swift
public struct SignalItemDTO: Codable, Sendable {
    public enum Kind: String, Codable { case hard, soft }

    public var id: String                   // 唯一标识：vpn, proxy, cloud_datacenter 等
    public var title: String                // 显示标题
    public var kind: Kind                   // 硬/软信号
    public var detected: Bool               // 是否检测到
    public var confidence: SignalConfidence? // 置信度：weak/medium/strong
    public var method: String?              // 检测方法
    public var evidenceSummary: String?     // 证据摘要
}
```

### ServerSignals（服务端信号）

```swift
public struct ServerSignals: Codable, Sendable {
    public var publicIP: String?            // 公网 IP
    public var asn: String?                 // 自治系统号
    public var asOrg: String?               // ASN 组织名
    public var isDatacenter: Bool?          // 是否机房/数据中心 IP
    public var ipDeviceAgg: Int?            // IP 关联设备数
    public var ipAccountAgg: Int?           // IP 关联账号数
    public var geoCountry: String?          // 国家
    public var geoRegion: String?           // 地区
    public var riskTags: [String]?          // 风险标签
}
```

---

## 信号三态系统

### 设计理念

传统的布尔值（检测到/未检测到）无法表达所有状态，例如：
- 模拟器环境下，某些检测方法不可用
- 云手机信号需要服务端数据支持

因此设计了**四态系统**：

### SignalDisplayState

```swift
enum SignalDisplayState {
    case detected           // 检测到风险
    case notDetected        // 未检测到风险
    case unavailable        // 检测方法不可用（如模拟器）
    case needBackend        // 需要服务端数据

    var statusText: String {
        switch self {
        case .detected: return "检测到"
        case .notDetected: return "未检测到"
        case .unavailable: return "不可用"
        case .needBackend: return "需服务端"
        }
    }

    var statusColor: Color {
        switch self {
        case .detected: return .red
        case .notDetected: return .green
        case .unavailable: return .gray
        case .needBackend: return .purple
        }
    }
}
```

### 状态判定逻辑

```swift
var displayState: SignalDisplayState {
    if let method = method {
        if method == "unavailable_simulator" { return .unavailable }
        if method == "need_backend" { return .needBackend }
    }
    return detected ? .detected : .notDetected
}
```

### UI 展示效果

| 状态 | 图标 | 颜色 | 场景 |
|------|------|------|------|
| detected | ⚠️ | 红色 | 检测到 VPN/越狱等 |
| notDetected | ✓ | 绿色 | 正常状态 |
| unavailable | ⊘ | 灰色 | 模拟器环境 |
| needBackend | 🖥 | 紫色 | 云手机信号待服务端 |

---

## UI 组件库

### 页面组件

| 页面 | 文件 | 功能 |
|------|------|------|
| Dashboard | `DashboardView.swift` | 主仪表盘、快速状态、检测按钮 |
| Results | `ResultsView.swift` | 检测结果详情、信号分组、JSON 展示 |
| History | `HistoryView.swift` | 历史记录列表、详情查看 |
| Settings | `SettingsView.swift` | 配置管理、调试开关 |

### 核心组件

#### RiskGaugeView（风险仪表盘）

```swift
RiskGaugeView(score: 75, riskLevel: .high, size: 220)
```

特性：
- 渐变色进度环
- 动画分数计数器
- 发光效果
- 刻度线装饰

#### SignalGroupView（信号分组）

```swift
SignalGroupView(
    title: "越狱检测（硬结论）",
    icon: "lock.shield.fill",
    iconColor: .red,
    signals: hardSignals,
    showDetails: debugMode  // 调试模式显示详情
)
```

特性：
- 折叠/展开动画
- 状态徽章（异常数 + 待定数）
- 支持调试模式显示 method/evidence

#### SignalRowView（信号行）

```swift
SignalRowView(item: signalItem, showDetails: true)
```

特性：
- 三态状态指示器
- 点击展开详情（method/evidence/confidence）
- 硬信号/软信号不同样式

#### StatusBadge（状态徽章）

```swift
StatusBadge(title: "VPN", state: .detected, isHardSignal: false)
```

特性：
- 支持四态展示
- 动画效果（检测到时脉冲）
- 状态文字提示

---

## 检测引擎

### 越狱检测器列表

| 检测器 | 方法 | 检测目标 |
|--------|------|----------|
| FileDetector | 文件存在性检测 | Cydia.app、MobileSubstrate 等 |
| DyldDetector | 动态库枚举 | 加载的越狱框架 |
| EnvDetector | 环境变量检测 | DYLD_INSERT_LIBRARIES 等 |
| SysctlDetector | 系统调用 | 进程信息、调试状态 |
| SchemeDetector | URL Scheme | cydia://、sileo:// 等 |
| HookDetector | 函数 Hook 检测 | 关键函数被替换 |
| ObjCIMPDetector | ObjC 方法实现 | 方法地址验证 |
| PrologueBranchDetector | 函数序言检测 | 入口点跳转指令 |
| IndirectSymbolPointerDetector | 间接符号指针 | GOT/PLT 篡改 |
| PointerValidationDetector | 指针验证 | PAC 相关检测 |

### 检测文件路径

```swift
// 越狱应用
"/Applications/Cydia.app"
"/Applications/Sileo.app"
"/Applications/Zebra.app"

// 越狱框架
"/Library/MobileSubstrate/MobileSubstrate.dylib"
"/usr/lib/substitute.dylib"

// 系统工具
"/usr/bin/ssh"
"/usr/sbin/sshd"
"/bin/bash"

// 包管理
"/private/var/lib/apt/"
"/var/cache/apt/"
"/etc/apt/"
```

---

## 配置管理

### RiskAppConfig

```swift
public struct RiskAppConfig {
    // 检测开关
    public var enableBehaviorDetect: Bool = true
    public var enableNetworkSignals: Bool = true

    // 越狱检测开关
    public var jailbreakEnableFileDetect: Bool = true
    public var jailbreakEnableDyldDetect: Bool = true
    public var jailbreakEnableEnvDetect: Bool = true
    public var jailbreakEnableSysctlDetect: Bool = true
    public var jailbreakEnableSchemeDetect: Bool = true
    public var jailbreakEnableHookDetect: Bool = true

    // 阈值（20-80）
    public var threshold: Double = 60
    public var jailbreakThreshold: Double = 50

    // 存储
    public var storeEncryptionEnabled: Bool = true
    public var storeMaxFiles: Int = 50
}
```

### 调试开关

| 开关 | 功能 |
|------|------|
| `logEnabled` | 输出调试日志到控制台 |
| `debugShowDetailedSignals` | 结果页显示 method/evidence 详情 |
| `debugSimulateCloudPhoneSignals` | 注入模拟的服务端信号 |

---

## 存储与加密

### 报告存储

- **路径**: `Documents/RiskReports/`
- **文件名**: `risk_<ISO8601>.json` 或 `risk_<ISO8601>.enc`
- **加密**: AES-GCM 256-bit
- **密钥**: 存储于 Keychain

### 加密实现

```swift
// PayloadCrypto.swift
public struct PayloadCrypto {
    public static func encrypt(_ data: Data, key: SymmetricKey) throws -> Data
    public static func decrypt(_ data: Data, key: SymmetricKey) throws -> Data
}
```

### HistoryItem

```swift
public struct HistoryItem: Identifiable {
    public let id: UUID
    public let filename: String
    public let url: URL
    public let date: Date
    public let size: Int64
    public let isEncrypted: Bool
    public var summary: ReportSummary?  // 缓存的摘要信息
}
```

---

## 目录结构

```
RiskDetectorApp/
├── App/
│   ├── RiskDetectorAppApp.swift        # App 入口
│   ├── ContentView.swift               # TabView 容器
│   ├── ViewModels/
│   │   ├── DetectionViewModel.swift    # 检测状态管理
│   │   ├── HistoryViewModel.swift      # 历史记录管理
│   │   └── SettingsViewModel.swift     # 配置管理
│   └── Views/
│       ├── DashboardView.swift         # 主仪表盘
│       ├── ResultsView.swift           # 检测结果
│       ├── HistoryView.swift           # 历史记录
│       ├── SettingsView.swift          # 设置页面
│       └── Components/
│           ├── RiskGaugeView.swift     # 风险仪表盘
│           ├── SignalRowView.swift     # 信号行/分组组件
│           └── JSONTextView.swift      # JSON 展示
├── Sources/
│   ├── CloudPhoneRiskKit/
│   │   ├── Jailbreak/                  # 越狱检测
│   │   │   ├── JailbreakEngine.swift
│   │   │   ├── JailbreakConfig.swift
│   │   │   └── Detectors/              # 10+ 检测器
│   │   ├── Network/                    # 网络信号
│   │   │   └── NetworkSignals.swift
│   │   ├── Behavior/                   # 行为采集
│   │   │   ├── TouchCapture.swift
│   │   │   ├── MotionSampler.swift
│   │   │   └── BehaviorSignals.swift
│   │   ├── Providers/                  # 数据提供者
│   │   ├── Risk/                       # 风险评分
│   │   └── Util/                       # 工具类
│   └── CloudPhoneRiskAppCore/
│       ├── RiskDetectionService.swift
│       ├── RiskReportDTO.swift
│       └── RiskAppConfigStore.swift
├── Tests/
│   └── CloudPhoneRiskKitTests/         # 单元测试
├── Package.swift
├── project.yml                         # XcodeGen 配置
└── RiskDetectorApp.xcodeproj
```

---

## 技术栈

| 类别 | 技术 |
|------|------|
| 语言 | Swift 5.9+ |
| UI 框架 | SwiftUI |
| 最低版本 | iOS 14.0 |
| 架构模式 | MVVM |
| 加密 | CryptoKit (AES-GCM) |
| 密钥存储 | Keychain |
| 包管理 | Swift Package Manager |
| 项目生成 | XcodeGen |

---

## 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| 1.0.0 | 2025-01 | 初始版本：完整检测功能、四页面 UI、信号三态系统 |

---

## 许可证

未指定（内部项目）。
