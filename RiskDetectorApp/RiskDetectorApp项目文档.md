# RiskDetectorApp 项目文档

> **iOS 设备风险检测应用**
> 基于 CloudPhoneRiskKit 框架，实现越狱检测、云手机识别与行为分析的一体化解决方案

---

## 目录

- [项目概述](#项目概述)
- [设计理念](#设计理念)
- [架构设计](#架构设计)
- [模块分层](#模块分层)
- [核心数据模型](#核心数据模型)
- [页面功能详解](#页面功能详解)
- [运行时数据流](#运行时数据流)
- [信号分级体系](#信号分级体系)
- [接入指南](#接入指南)
- [API 参考](#api-参考)
- [最佳实践](#最佳实践)
- [技术栈](#技术栈)

---

## 项目概述

### 背景

在移动安全领域，设备环境的可信度评估是风控系统的第一道防线。越狱设备、云手机、模拟器等非常规运行环境，往往与欺诈行为、作弊行为高度相关。

**RiskDetectorApp** 是一款面向 iOS 平台的设备风险检测工具，它将复杂的安全检测能力封装为直观的用户界面，让开发者和安全工程师能够：

- **一键检测** 设备的越狱状态与环境风险
- **可视化展示** 多维度的风险信号与置信度
- **本地加密存储** 检测报告，支持历史回溯
- **灵活配置** 检测策略与阈值参数

### 核心能力

| 能力 | 描述 |
|-----|------|
| 越狱检测 | 文件探测、动态库分析、环境变量检测、系统调用验证、URL Scheme 探测、Hook 检测 |
| 网络信号 | VPN 隧道探测、系统代理检测、网络接口类型识别 |
| 行为采集 | 触摸轨迹分析、传感器数据采集、人机行为相关性计算 |
| 安全存储 | AES-GCM 加密、Keychain 密钥管理、摘要缓存机制 |

---

## 设计理念

### 三层分离原则

本项目严格遵循 **UI - 逻辑 - 底层** 三层分离的架构原则：

```
┌─────────────────────────────────────────────────────────┐
│                      表现层 (UI)                         │
│           只负责展示与交互，不处理业务逻辑               │
├─────────────────────────────────────────────────────────┤
│                    逻辑层 (AppCore)                      │
│          服务封装、数据转换、配置管理、存储管理          │
├─────────────────────────────────────────────────────────┤
│                     能力层 (SDK)                         │
│            采集、检测、评分、加密、序列化                │
└─────────────────────────────────────────────────────────┘
```

### 数据驱动设计

UI 层仅通过 **DTO (Data Transfer Object)** 获取数据，不直接接触底层 SDK 类型。这种设计带来的好处：

- **解耦**：UI 变更不影响底层逻辑
- **可测试**：DTO 可轻松 Mock
- **类型安全**：编译期保证数据结构正确
- **可维护**：业务逻辑集中在 AppCore 层

### 信号语义明确

检测结果分为 **硬信号** 与 **软信号** 两类，UI 展示时严格区分：

- **硬信号**（如越狱）：本地可做强结论，用 ✓/✗ 明确标识
- **软信号**（如 VPN）：仅作参考，用圆点 + "有/无信号" 标识

这种设计避免了将"系统限制导致看不到"误判为"低风险"的问题。

---

## 架构设计

### 整体架构图

```
┌─────────────────────────────────────────────────────────────┐
│                    RiskDetectorApp (SwiftUI)                 │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                    ContentView                          ││
│  │              TabView (3 tabs)                           ││
│  │    ┌──────────┐ ┌──────────┐ ┌──────────┐              ││
│  │    │Dashboard │ │ History  │ │ Settings │              ││
│  │    └──────────┘ └──────────┘ └──────────┘              ││
│  └─────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────┤
│                      ViewModel 层                            │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐     │
│  │DetectionVM    │ │HistoryVM      │ │SettingsVM     │     │
│  │- lastDTO      │ │- items[]      │ │- config       │     │
│  │- detect()     │ │- loadDetail() │ │- save()       │     │
│  └───────────────┘ └───────────────┘ └───────────────┘     │
├─────────────────────────────────────────────────────────────┤
│                 CloudPhoneRiskAppCore                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                RiskDetectionService                    │  │
│  │    start() | evaluateAsync() | save() | inject()      │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │RiskAppConfig│ │ReportMapper │ │ RiskReportStorage   │   │
│  │ + Store     │ │DTO ↔ JSON   │ │ list/load/delete    │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                   CloudPhoneRiskKit                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │Jailbreak │ │ Network  │ │ Behavior │ │ Storage  │       │
│  │ Engine   │ │ Signals  │ │ Capture  │ │ Crypto   │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────────────────────────────────────────────────┘
```

### 文件结构

```
RiskDetectorApp/
├── Package.swift                         # SwiftPM 配置
├── project.yml                           # XcodeGen 配置
├── README.md                             # 快速入门指南
├── RiskDetectorApp项目文档.md            # 本文档
│
└── RiskDetectorApp/
    ├── RiskDetectorAppApp.swift          # App 入口
    ├── ContentView.swift                 # TabView 容器
    ├── Info.plist                        # 应用配置
    │
    ├── ViewModels/
    │   ├── DetectionViewModel.swift      # 检测逻辑
    │   ├── HistoryViewModel.swift        # 历史管理
    │   └── SettingsViewModel.swift       # 配置管理
    │
    ├── Views/
    │   ├── DashboardView.swift           # 首页
    │   ├── ResultsView.swift             # 结果页
    │   ├── HistoryView.swift             # 历史页
    │   ├── SettingsView.swift            # 设置页
    │   │
    │   └── Components/
    │       ├── RiskGaugeView.swift       # 风险仪表盘
    │       ├── SignalRowView.swift       # 信号行组件
    │       └── JSONTextView.swift        # JSON 展示组件
    │
    └── Resources/
        ├── Assets.xcassets               # 图标资源
        └── Info.plist                    # 权限配置
```

---

## 模块分层

### 1. 表现层 (RiskDetectorApp)

**职责**：页面渲染、用户交互、状态展示

| 组件 | 功能 |
|-----|------|
| `DashboardView` | 风险仪表盘、一键检测、状态概览 |
| `ResultsView` | 详细结果展示、信号分组、JSON 原文 |
| `HistoryView` | 历史记录列表、解密查看、批量管理 |
| `SettingsView` | 检测配置、阈值调节、存储设置 |

**设计约束**：
- 只读取 `RiskReportDTO` 和 `RiskReportSummary`
- 不直接调用 SDK 方法
- 不处理加密/解密逻辑

### 2. 逻辑层 (CloudPhoneRiskAppCore)

**职责**：业务编排、数据转换、状态管理

| 组件 | 功能 |
|-----|------|
| `RiskDetectionService` | 统一服务入口：start/evaluate/save/inject |
| `RiskAppConfig` | 配置模型，可映射到 SDK 配置 |
| `RiskAppConfigStore` | 配置持久化 (UserDefaults) |
| `RiskReportMapper` | CPRiskReport → RiskReportDTO 转换 |
| `RiskReportStorage` | 报告文件管理：list/load/delete |
| `RiskReportSummary` | 历史列表摘要，支持 meta.json 缓存 |

### 3. 能力层 (CloudPhoneRiskKit)

**职责**：底层采集、检测、评分、加密

| 模块 | 功能 |
|-----|------|
| `JailbreakEngine` | 越狱检测引擎，支持多种探测器 |
| `NetworkSignals` | 网络环境信号采集 |
| `BehaviorCapture` | 触摸/传感器行为采集 |
| `CPRiskStore` | AES-GCM 加密存储 |
| `RiskScorer` | 风险评分算法 |

---

## 核心数据模型

### RiskReportDTO

检测结果的传输对象，UI 层通过此结构获取所有展示数据。

```swift
public struct RiskReportDTO: Codable, Sendable {
    // 基础信息
    public var sdkVersion: String?
    public var generatedAt: String
    public var deviceID: String

    // 风险评估
    public var score: Double
    public var isHighRisk: Bool
    public var summary: String

    // 详细信号
    public var jailbreak: JailbreakDTO
    public var network: NetworkSignals
    public var behavior: BehaviorSignals

    // 扩展信号
    public var server: ServerSignals?
    public var local: LocalSignals?
    public var signals: [RiskSignal]

    // UI 分组（重要！）
    public var hardSignals: [SignalItemDTO]   // 硬信号列表
    public var softSignals: [SignalItemDTO]   // 软信号列表
}
```

### SignalItemDTO

单个信号的展示结构，包含置信度和检测方法。

```swift
public struct SignalItemDTO: Codable, Sendable {
    public enum Kind { case hard, soft }

    public var id: String
    public var title: String
    public var kind: Kind
    public var detected: Bool
    public var confidence: SignalConfidence?  // weak/medium/strong
    public var method: String?                // 检测方法
    public var evidenceSummary: String?       // 证据摘要
}
```

### RiskReportSummary

历史列表的轻量摘要，来自 `<report>.meta.json`，无需解密即可读取。

```swift
public struct RiskReportSummary: Codable, Sendable {
    public var generatedAt: String?
    public var score: Double?
    public var isHighRisk: Bool?
    public var summary: String?

    public var jailbreakIsJailbroken: Bool?
    public var jailbreakConfidence: Double?

    public var vpnDetected: Bool?
    public var proxyDetected: Bool?
    public var interfaceType: String?
}
```

---

## 页面功能详解

### Dashboard（首页）

**核心功能**：设备风险一览与一键检测

```
┌────────────────────────────────────┐
│                                    │
│         ╭───────────────╮          │
│         │      85       │          │
│         │    高风险     │          │
│         ╰───────────────╯          │
│                                    │
│    越狱        VPN        代理     │
│     ✗          🔵          ⚪       │
│                                    │
│  ┌──────────────────────────────┐  │
│  │         开始检测             │  │
│  └──────────────────────────────┘  │
│                                    │
│  最近检测: 2026-01-11 10:30:00    │
│  状态: 高风险                      │
└────────────────────────────────────┘
```

**交互逻辑**：
1. 页面加载时调用 `startIfNeeded()` 启动采集
2. 点击"开始检测"触发 `detect(config:)`
3. 检测完成后自动弹出 `ResultsView`
4. 状态徽章区分硬/软信号

### Results（结果页）

**核心功能**：详细检测结果与数据导出

```
┌────────────────────────────────────┐
│  风险分数: 85          🔴 高风险  │
├────────────────────────────────────┤
│ ▸ 越狱检测（硬结论）              │
│   ├─ Jailbreak    ✗  强          │
│   ├─ Cydia.app                    │
│   └─ MobileSubstrate              │
├────────────────────────────────────┤
│ ▸ 网络信号（仅供参考）            │
│   ├─ VPN Signal   🔵  弱          │
│   │  方法: ifaddrs_prefix         │
│   └─ Proxy Signal ⚪  无信号      │
│                                    │
│ ⚠️ 网络信号仅供参考，强结论需     │
│    结合服务端数据                  │
├────────────────────────────────────┤
│ ▸ 原始 JSON                       │
│   { "score": 85, ... }            │
├────────────────────────────────────┤
│  [保存]    [分享]    [复制]       │
└────────────────────────────────────┘
```

**数据来源**：
- 分数/风险等级：`dto.score`, `dto.isHighRisk`
- 硬信号列表：`dto.hardSignals`
- 软信号列表：`dto.softSignals`
- JSON 原文：DTO 编码后的字符串

### History（历史页）

**核心功能**：检测记录管理与回溯

```
┌────────────────────────────────────┐
│  检测历史                    🗑️   │
├────────────────────────────────────┤
│ ┌──────────────────────────────┐  │
│ │ 🔴 risk-2026-01-11.enc   85  │  │
│ │    10:30  2KB  越狱 VPN     │  │
│ └──────────────────────────────┘  │
│ ┌──────────────────────────────┐  │
│ │ 🟢 risk-2026-01-10.enc   12  │  │
│ │    15:22  1.8KB              │  │
│ └──────────────────────────────┘  │
│                                    │
│  ← 左滑可删除                     │
└────────────────────────────────────┘
```

**性能优化**：
- 列表展示使用 `RiskReportSummary`（读取 meta.json，无需解密）
- 点击详情时才调用 `loadDTO()`（触发解密）
- 支持批量删除

### Settings（设置页）

**核心功能**：检测策略与存储配置

```
┌────────────────────────────────────┐
│  设置                              │
├────────────────────────────────────┤
│  检测配置                          │
│    行为采集              [ON]      │
│    网络信号              [ON]      │
├────────────────────────────────────┤
│  越狱检测                          │
│    文件检测              [ON]      │
│    dyld 检测             [ON]      │
│    环境变量检测          [ON]      │
│    系统调用检测          [ON]      │
│    URL Scheme 检测       [ON]      │
│    Hook 检测             [ON]      │
├────────────────────────────────────┤
│  阈值设置                          │
│    风险阈值         60  ────●────  │
│    越狱阈值         50  ────●────  │
├────────────────────────────────────┤
│  存储设置                          │
│    加密存储              [ON]      │
│    最大文件数            50        │
├────────────────────────────────────┤
│  调试                              │
│    日志输出              [OFF]     │
├────────────────────────────────────┤
│         [ 恢复默认配置 ]           │
└────────────────────────────────────┘
```

**配置持久化**：
- 页面离开时自动保存
- 使用 `RiskAppConfigStore` 存储到 UserDefaults
- 检测时通过 `settingsVM.currentConfig()` 获取最新配置

---

## 运行时数据流

### 完整生命周期

```
                    ┌─────────────────┐
                    │   App 启动     │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │SettingsVM.load()│           │DetectionVM      │
    │  加载配置        │           │.startIfNeeded() │
    └────────┬────────┘           └────────┬────────┘
             │                             │
             ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │ RiskAppConfig   │           │RiskDetection    │
    │  配置就绪        │           │Service.start()  │
    └─────────────────┘           │  启动采集        │
                                  └─────────────────┘
                                           │
                    ┌──────────────────────┘
                    ▼
          ┌─────────────────┐
          │  用户点击检测   │
          └────────┬────────┘
                   │
                   ▼
    ┌──────────────────────────────┐
    │ DetectionVM.detect(config:)  │
    │   ↓                          │
    │ RiskDetectionService         │
    │   .evaluateAsync(config:)    │
    │   ↓                          │
    │ CPRiskKit.evaluateAsync()    │
    │   ↓                          │
    │ CPRiskReport                 │
    │   ↓                          │
    │ RiskReportMapper.dto(from:)  │
    │   ↓                          │
    │ RiskReportDTO                │
    └──────────────┬───────────────┘
                   │
                   ▼
          ┌─────────────────┐
          │   UI 更新       │
          │ ResultsView显示 │
          └────────┬────────┘
                   │
                   ▼
          ┌─────────────────┐
          │  用户点击保存   │
          └────────┬────────┘
                   │
                   ▼
    ┌──────────────────────────────┐
    │ DetectionVM.save(config:)    │
    │   ↓                          │
    │ RiskDetectionService.save()  │
    │   ↓                          │
    │ CPRiskStore.save()           │
    │   (AES-GCM 加密)             │
    │   ↓                          │
    │ RiskReportSummaryIO          │
    │   .writeMeta()               │
    │   (写入 meta.json)           │
    └──────────────────────────────┘
                   │
                   ▼
          ┌─────────────────┐
          │ History 可见    │
          │ (无需解密)      │
          └─────────────────┘
```

### 关键节点说明

| 节点 | 说明 |
|-----|------|
| `start()` | 仅在 App 启动时调用一次，启动触摸/传感器采集 |
| `evaluateAsync()` | 可多次调用，每次生成独立报告 |
| `RiskReportMapper` | 将 SDK 类型转换为 DTO，同时生成 hardSignals/softSignals |
| `meta.json` | 摘要缓存，让 History 列表无需解密即可展示关键信息 |

---

## 信号分级体系

### 设计原则

本项目将检测信号分为 **硬信号** 和 **软信号** 两类，这一设计源于对移动安全检测边界的深刻理解：

**硬信号（Hard Signals）**
- 本地具备充分的检测能力
- 可以做出强结论
- 典型代表：越狱检测

**软信号（Soft Signals）**
- 受系统沙箱限制，检测能力有限
- 仅作为参考信号，不做强结论
- 典型代表：VPN/代理检测

### VPN 检测的现实边界

| 能做到 | 做不到 |
|-------|-------|
| `getifaddrs()` 探测 utun/ppp/ipsec 接口 | 判断用户是否真的开了 VPN |
| `CFNetworkCopySystemProxySettings` 读取代理配置 | 获取 VPN 品牌/节点信息 |
| `NWPathMonitor` 获取网络接口类型 | 判断是否企业专线/代理链路 |

**结论**：VPN/Proxy 适合做"网络环境异常"的加分项，真正的强判定需要服务端结合 IP/ASN/机房/共享度做聚合分析。

### UI 展示规范

| 信号类型 | 图标 | 文案 | 颜色 |
|---------|------|------|------|
| 越狱（检测到） | ✗ | - | 红色 |
| 越狱（未检测到） | ✓ | - | 绿色 |
| VPN（有信号） | 🔵 | 有信号 + 方法 | 蓝色 |
| VPN（无信号） | ⚪ | 无信号 | 灰色 |

---

## 接入指南

### 方式一：XcodeGen（推荐）

```bash
# 1. 安装 XcodeGen
brew install xcodegen

# 2. 进入项目目录
cd /Users/mac/Desktop/RiskDetectorApp

# 3. 生成 Xcode 项目
xcodegen generate

# 4. 打开项目
open RiskDetectorApp.xcodeproj
```

### 方式二：手动创建 Xcode 项目

1. **新建 iOS App 项目**
   - Product Name: `RiskDetectorApp`
   - Interface: SwiftUI
   - Language: Swift
   - Minimum Deployments: iOS 14.0

2. **导入源码**
   - 将 `RiskDetectorApp/` 目录下的所有文件拖入项目

3. **添加本地依赖**
   - File → Add Package Dependencies → Add Local...
   - 选择 `云手机检测和越野插件的开发` 目录
   - 添加 `CloudPhoneRiskKit` 和 `CloudPhoneRiskAppCore` 两个产品

4. **配置 Info.plist**
   - 添加 `LSApplicationQueriesSchemes`（cydia/sileo/filza/activator/undecimus）
   - 添加 `NSMotionUsageDescription`

### 真机测试注意事项

- 越狱检测在模拟器上不具备真实意义，建议使用真机验证
- 首次运行需要授权传感器访问权限
- VPN/代理检测需要在有相应网络配置的环境下测试

---

## API 参考

### DetectionViewModel

```swift
@MainActor
class DetectionViewModel: ObservableObject {
    // 状态
    @Published var state: DetectionState
    @Published var lastDTO: RiskReportDTO?
    @Published var showResults: Bool

    // 派生属性
    var riskLevel: RiskLevel?
    var isDetecting: Bool

    // 方法
    func startIfNeeded()                          // 启动采集
    func detect(config: RiskAppConfig? = nil)     // 执行检测
    func save(config: RiskAppConfig? = nil) -> String?  // 保存报告
    func reset()                                  // 重置状态
}
```

### HistoryViewModel

```swift
@MainActor
class HistoryViewModel: ObservableObject {
    // 状态
    @Published var items: [HistoryItem]
    @Published var isLoading: Bool
    @Published var selectedDTO: RiskReportDTO?
    @Published var showDetail: Bool

    // 方法
    func reload()                                 // 加载列表
    func loadDetail(for item: HistoryItem)        // 加载详情
    func delete(_ item: HistoryItem)              // 删除单条
    func deleteAll()                              // 删除全部
}
```

### SettingsViewModel

```swift
@MainActor
class SettingsViewModel: ObservableObject {
    // 检测开关
    @Published var enableBehaviorDetect: Bool
    @Published var enableNetworkSignals: Bool

    // 越狱检测开关
    @Published var jailbreakEnableFileDetect: Bool
    @Published var jailbreakEnableDyldDetect: Bool
    // ... 其他开关

    // 阈值
    @Published var threshold: Double
    @Published var jailbreakThreshold: Double

    // 方法
    func load()
    func save()
    func resetToDefault()
    func setLogEnabled(_ enabled: Bool)
    func currentConfig() -> RiskAppConfig
}
```

---

## 最佳实践

### 1. 启动时机

```swift
// 在 App 入口尽早调用
@main
struct RiskDetectorAppApp: App {
    init() {
        RiskDetectionService.shared.start()  // 启动采集
    }
}
```

### 2. 配置传递

```swift
// 检测时使用最新配置
detectionVM.detect(config: settingsVM.currentConfig())

// 保存时也传入配置（影响加密开关等）
detectionVM.save(config: settingsVM.currentConfig())
```

### 3. 错误处理

```swift
// ViewModel 层已封装错误处理
// UI 层只需观察 state 变化
switch detectionVM.state {
case .idle: showIdleUI()
case .detecting: showLoadingUI()
case .completed: showResultsUI()
case .error(let msg): showErrorUI(msg)
}
```

### 4. 性能优化

```swift
// History 列表使用 Summary（无需解密）
let items = RiskReportStorage.listSummaries()

// 详情页才加载完整 DTO
let dto = RiskReportStorage.loadDTO(atPath: path)
```

---

## 技术栈

| 类别 | 技术 |
|-----|------|
| UI 框架 | SwiftUI |
| 架构模式 | MVVM + 依赖注入 |
| 最低版本 | iOS 14.0 |
| 语言版本 | Swift 5.9 |
| 包管理 | Swift Package Manager |
| 项目生成 | XcodeGen (可选) |
| 加密算法 | AES-GCM |
| 密钥存储 | Keychain (ThisDeviceOnly) |

---

## 版本历史

| 版本 | 日期 | 更新内容 |
|-----|------|---------|
| 1.0.0 | 2026-01 | 初始版本，完成 4 页 + DTO 架构 |

---

## 许可证

MIT License

---

> **文档版本**: 1.0.0
> **最后更新**: 2026-01-11
> **维护者**: Claude + GPT 协作开发
