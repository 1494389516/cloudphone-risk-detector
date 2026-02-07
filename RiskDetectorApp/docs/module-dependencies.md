# CloudPhoneRiskKit SDK 2.0 模块依赖关系文档

## 文档概述

| 项目 | 说明 |
|------|------|
| 版本 | 2.0.0 |
| 作者 | CloudPhone Risk Team |
| 更新日期 | 2026-02-06 |
| 状态 | 设计中 |

---

## 一、模块依赖图

### 1.1 全局依赖关系

```
                        ┌─────────────────────────────────────┐
                        │         Core (核心层)                 │
                        │  ┌─────────────────────────────────┐ │
                        │  │  CPRiskKit (主入口)               │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  CPRiskConfig (配置)              │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  CPRiskReport (报告)              │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  RiskSignal (信号)                │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  RiskSnapshot (快照)              │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  RiskVerdict (裁决)               │ │
                        │  └─────────────────────────────────┘ │
                        └──────────────────┬──────────────────┘
                                           │
            ┌──────────────────────────────┼──────────────────────────────┐
            │                              │                              │
            ↓                              ↓                              ↓
┌───────────────────────┐    ┌───────────────────────┐    ┌───────────────────────┐
│   Detection (检测层)   │    │   Decision (决策层)     │    │   Config (配置层)      │
│                       │    │                       │    │                       │
│ ┌───────────────────┐ │    │ ┌───────────────────┐ │    │ ┌───────────────────┐ │
│ │ JailbreakEngine   │ │    │ │RiskDecisionEngine │ │    │ │RemoteConfigProvider│ │
│ ├───────────────────┤ │    │ ├───────────────────┤ │    │ ├───────────────────┤ │
│ │AntiTamperEngine   │ │    │ │ScenarioBasedPolicy│ │    │ │ LocalConfigProvider│ │
│ ├───────────────────┤ │    │ ├───────────────────┤ │    │ ├───────────────────┤ │
│ │ BehaviorEngine    │ │    │ │TemporalAnalyzer   │ │    │ │   ConfigManager    │ │
│ ├───────────────────┤ │    │ ├───────────────────┤ │    │ └───────────────────┘ │
│ │  NetworkEngine    │ │    │ │  EnsembleDecider  │ │    │                       │
│ ├───────────────────┤ │    │ ├───────────────────┤ │    │                       │
│ │  DeviceEngine     │ │    │ │   RuleDecider     │ │    │                       │
│ ├───────────────────┤ │    │ └───────────────────┘ │    │                       │
│ │EnvironmentEngine  │ │    │                       │    │                       │
│ └───────────────────┘ │    │                       │    │                       │
└───────────┬───────────┘    └───────────┬───────────┘    └───────────┬───────────┘
            │                           │                           │
            └───────────────────────────┼───────────────────────────┘
                                        │
                                        ↓
                        ┌─────────────────────────────────────┐
                        │      Analysis (分析模块)              │
                        │  ┌─────────────────────────────────┐ │
                        │  │  TemporalAnalyzer               │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  AnomalyDetector                │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  PatternMatcher                 │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  FeatureExtractor               │ │
                        │  └─────────────────────────────────┘ │
                        └──────────────────┬──────────────────┘
                                           │
                                           ↓
                        ┌─────────────────────────────────────┐
                        │      Storage (存储层)                │
                        │  ┌─────────────────────────────────┐ │
                        │  │  RiskHistoryStore               │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  SecureStorage                  │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  CacheStore                     │ │
                        │  └─────────────────────────────────┘ │
                        └─────────────────────────────────────┘

                        ┌─────────────────────────────────────┐
                        │      Util (工具层)                  │
                        │  ┌─────────────────────────────────┐ │
                        │  │  Logger                         │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  JSON                           │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  Crypto                         │ │
                        │  ├─────────────────────────────────┤ │
                        │  │  Sysctl                         │ │
                        │  └─────────────────────────────────┘ │
                        └─────────────────��───────────────────┘
```

### 1.2 层级依赖规则

```
┌─────────────────────────────────────────────────────────────────────┐
│                        依赖方向规则                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Application Layer (应用层)                                         │
│       ↓ 依赖                                                        │
│  Decision Layer (决策层)                                            │
│       ↓ 依赖                                                        │
│  Detection Layer (检测层)                                           │
│       ↓ 依赖                                                        │
│  Config Layer (配置层)                                              │
│       ↓ 依赖                                                        │
│  Storage Layer (存储层)                                             │
│       ↓ 依赖                                                        │
│  Util Layer (工具层)                                                │
│                                                                     │
│  禁止反向依赖！                                                      │
│  禁止跨层依赖！                                                      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 二、详细模块依赖

### 2.1 Core 模块依赖

**模块职责：** 定义公开 API 和核心数据模型

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Storage | 编译依赖 | RiskHistoryStore, KeychainDeviceID |
| Util | 编译依赖 | Logger, JSON, ISO8601 |

**被依赖方：**
- Detection (通过 RiskSnapshot)
- Decision (通过 RiskSnapshot, RiskVerdict)
- Config (通过配置模型)

**核心文件：**
```
Core/
├── Public/
│   ├── CPRiskKit.swift         # 依赖: Storage, Detection, Decision
│   ├── CPRiskConfig.swift      # 依赖: -
│   └── CPRiskReport.swift      # 依赖: Core/Models, Util/JSON
├── Models/
│   ├── RiskSignal.swift        # 依赖: -
│   ├── RiskSnapshot.swift      # 依赖: Detection, Device
│   ├── RiskVerdict.swift       # 依赖: -
│   └── DetectionResult.swift   # 依赖: -
└── Protocols/
    ├── Detector.swift          # 依赖: Core/Models
    ├── SignalProvider.swift    # 依赖: Core/Models
    ├── DecisionEngine.swift    # 依赖: Core/Models
    └── ConfigProvider.swift    # 依赖: Config/Models
```

### 2.2 Detection 模块依赖

**模块职责：** 采集各类风险信号

#### 2.2.1 Jailbreak 子模块

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Core/Protocols | 编译依赖 | Detector 协议 |
| Core/Models | 编译依赖 | DetectionResult |
| Util | 编译依赖 | Logger, Sysctl |
| Storage | 运行依赖 | 读取缓存 |

**文件依赖图：**
```
Jailbreak/
├── JailbreakEngine.swift       # 依赖: JailbreakConfig, 所有 Detector
├── JailbreakConfig.swift       # 依赖: -
└── Detectors/
    ├── FileDetector.swift       # 依赖: Detector, Util/Sysctl
    ├── DyldDetector.swift       # 依赖: Detector, Util/Sysctl
    ├── EnvDetector.swift        # 依赖: Detector, Util/Sysctl
    ├── SysctlDetector.swift     # 依赖: Detector, Util/Sysctl
    ├── SchemeDetector.swift     # 依赖: Detector
    └── HookDetector.swift       # 依赖: Detector
```

#### 2.2.2 AntiTampering 子模块（新增）

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Core/Protocols | 编译依赖 | Detector 协议 |
| Core/Models | 编译依赖 | DetectionResult, AntiTamperResult |
| Util | 编译依赖 | Logger, Sysctl, Crypto |

**文件依赖图：**
```
AntiTampering/
├── AntiTamperEngine.swift       # 依赖: AntiTamperConfig, 所有 Detector
├── AntiTamperConfig.swift       # 依赖: -
└── Detectors/
    ├── CodeIntegrityDetector.swift   # 依赖: Detector, Util/Crypto
    ├── DylibInjectionDetector.swift  # 依赖: Detector, Util/Sysctl
    ├── DebuggerDetector.swift        # 依赖: Detector, Util/Sysctl
    └── FridaDetector.swift           # 依赖: Detector, Util/Sysctl
```

#### 2.2.3 Behavior 子模块

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Core/Models | 编译依赖 | BehaviorSignals |
| Util | 编译依赖 | Logger |

**文件依赖图：**
```
Behavior/
├── BehaviorEngine.swift        # 依赖: TouchCapture, MotionSampler
├── TouchCapture.swift          # 依赖: BehaviorSignals
├── MotionSampler.swift         # 依赖: BehaviorSignals
└── BehaviorCoupling.swift      # 依赖: BehaviorSignals
```

#### 2.2.4 Network 子模块

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Core/Models | 编译依赖 | NetworkSignals |
| Util | 编译依赖 | Logger |

**文件依赖图：**
```
Network/
├── NetworkEngine.swift         # 依赖: NetworkSignals
└── NetworkSignals.swift        # 依赖: -
```

#### 2.2.5 Device 子模块

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Core/Models | 编译依赖 | DeviceFingerprint |
| Storage | 编译依赖 | KeychainDeviceID |
| Util | 编译依赖 | Logger |

**文件依赖图：**
```
Device/
├── DeviceEngine.swift          # 依赖: DeviceFingerprint
├── DeviceFingerprint.swift     # 依赖: -
└── KeychainDeviceID.swift      # 依赖: Storage/SecureStorage
```

#### 2.2.6 Environment 子模块（新增）

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Core/Protocols | 编译依赖 | Detector 协议 |
| Core/Models | 编译依赖 | EnvironmentSignals |
| Util | 编译依赖 | Logger, Sysctl |

**文件依赖图：**
```
Environment/
├── EnvironmentEngine.swift     # 依赖: SimulatorDetector, ProxyDetector
├── SimulatorDetector.swift     # 依赖: Detector
└── ProxyDetector.swift         # 依赖: Detector
```

### 2.3 Decision 模块依赖

**模块职责：** 基于检测信号进行决策

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Core/Protocols | 编译依赖 | DecisionEngine 协议 |
| Core/Models | 编译依赖 | RiskSnapshot, RiskVerdict, RiskSignal |
| Detection | 编译依赖 | 使用 DetectionResult |
| Analysis | 编译依赖 | TemporalAnalyzer |
| Config | 编译依赖 | DecisionConfig, PolicyConfig |
| Util | 编译依赖 | Logger |

**文件依赖图：**
```
Decision/
├── RiskDecisionEngine.swift    # 依赖: Models/*, Verdicts/*
├── ScenarioBasedPolicy.swift   # 依赖: Config/PolicyConfig
├── Models/
│   ├── RuleBasedModel.swift    # 依赖: DecisionModel
│   ├── ScoringModel.swift      # 依赖: DecisionModel
│   └── EnsembleModel.swift     # 依赖: DecisionModel
└── Verdicts/
    ├── ThresholdDecider.swift  # 依赖: -
    └── CompositeDecider.swift  # 依赖: ThresholdDecider
```

### 2.4 Analysis 模块依赖

**模块职责：** 时序分析、异常检测、模式匹配

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Core/Models | 编译依赖 | RiskHistoryEvent, RiskSignal |
| Storage | 编译依赖 | RiskHistoryStore |
| Util | 编译依赖 | Logger |

**文件依赖图：**
```
Analysis/
├── TemporalAnalyzer.swift       # 依赖: RiskHistoryStore, FeatureExtractor
├── AnomalyDetector.swift        # 依赖: TemporalAnalyzer
├── PatternMatcher.swift         # 依赖: TemporalAnalyzer
└── FeatureExtractor.swift       # 依赖: -
```

### 2.5 Config 模块依赖

**模块职责：** 配置管理、远程配置获取

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Core/Protocols | 编译依赖 | ConfigProvider 协议 |
| Storage | 编译依赖 | ConfigCache |
| Util | 编译依赖 | Logger, JSON, Crypto |

**文件依赖图：**
```
Config/
├── ConfigManager.swift          # 依赖: RemoteConfigProvider, LocalConfigProvider
├── RemoteConfigProvider.swift   # 依赖: Models/RemoteConfig
├── LocalConfigProvider.swift    # 依赖: Models/LocalConfig
├── Models/
│   ├── RemoteConfig.swift       # 依赖: DetectorConfigs, PolicyConfigs
│   ├── DetectorConfig.swift     # 依赖: JailbreakDetectorConfig, ...
│   ├── PolicyConfig.swift       # 依赖: ThresholdConfig, WeightConfig
│   └── ScenarioConfig.swift     # 依赖: -
└── Cache/
    └── ConfigCache.swift        # 依赖: Storage/CacheStore
```

### 2.6 Storage 模块依赖

**模块职责：** 数据持久化、缓存管理

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Core/Models | 编译依赖 | RiskHistoryEvent |
| Util | 编译依赖 | Logger, JSON, Crypto |

**文件依赖图：**
```
Storage/
├── RiskHistoryStore.swift       # 依赖: -
├── SecureStorage.swift          # 依赖: Util/Crypto
└── CacheStore.swift             # 依赖: -
```

### 2.7 Util 模块依赖

**模块职责：** 基础工具类

| 依赖模块 | 依赖类型 | 说明 |
|---------|---------|------|
| Foundation | 系统框架 | 基础 |
| Security | 系统框架 | Crypto 需要 |
| Darwin | 系统框架 | Sysctl 需要 |

**文件依赖图：**
```
Util/
├── Logger.swift                 # 依赖: -
├── Sysctl.swift                 # 依赖: -
├── JSON.swift                   # 依赖: -
├── ISO8601.swift                # 依赖: -
└── Crypto.swift                 # 依赖: Security
```

---

## 三、循环依赖分析

### 3.1 潜在循环依赖及解决方案

#### 场景 1: CPRiskKit ↔ Detection ↔ Decision

**问题：**
```
CPRiskKit → Detection (创建 DetectionEngine)
Detection → Decision (需要 DecisionConfig)
Decision → Detection (需要 DetectionResult)
```

**解决方案：** 使用协议注入
```swift
// Decision 模块不直接依赖 Detection
// 而是通过 RiskSnapshot 抽象

protocol DecisionEngine {
    func decide(snapshot: RiskSnapshot) -> RiskVerdict
    // RiskSnapshot 在 Core 模块，不依赖 Detection
}
```

#### 场景 2: Config → Decision → Config

**问题：**
```
Config → Decision (DecisionConfig 包含 PolicyConfig)
Decision → Config (需要获取 PolicyConfig)
```

**解决方案：** 配置接口隔离
```swift
// Config 模块提供配置读取接口
protocol ConfigReading {
    func getPolicy(for: RiskScenario) async -> PolicyConfig
}

// Decision 模块依赖抽象接口
class RiskDecisionEngine {
    private let configReader: ConfigReading
    // ...
}
```

### 3.2 模块依赖矩阵

|  | Core | Detection | Decision | Analysis | Config | Storage | Util |
|--|------|-----------|----------|----------|--------|---------|------|
| **Core** | - | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Detection** | ✓ | - | - | - | - | ✓ | ✓ |
| **Decision** | ✓ | ✓ | - | ✓ | ✓ | ✓ | ✓ |
| **Analysis** | ✓ | - | - | - | - | ✓ | ✓ |
| **Config** | ✓ | - | - | - | - | ✓ | ✓ |
| **Storage** | ✓ | - | - | - | - | - | ✓ |
| **Util** | - | - | - | - | - | - | - |

**注：** 
- ✓ 表示存在依赖
- 检测层模块之间相互独立
- 工具层不依赖任何业务模块

---

## 四、接口依赖关系

### 4.1 协议依赖图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           协议依赖关系                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────────┐                                                  │
│  │   Detector       │ ◄────────────────────┐                           │
│  │   (检测器协议)     │                       │                           │
│  └────────┬─────────┘                       │                           │
│           │                                 │                           │
│           │ implements                      │                           │
│           ▼                                 │                           │
│  ┌──────────────────┐                       │                           │
│  │ FileDetector     │                       │                           │
│  │ DyldDetector     │                       │                           │
│  │ ...              │                       │                           │
│  └──────────────────┘                       │                           │
│                                             │                           │
│  ┌──────────────────┐                       │                           │
│  │ DecisionEngine   │ ◄────────────────────┼───────────┐               │
│  │ (决策引擎协议)     │                       │           │               │
│  └────────┬─────────┘                       │           │               │
│           │                                 │           │               │
│           │ implements                      │           │               │
│           ▼                                 │           │               │
│  ┌──────────────────┐                       │           │               │
│  │RiskDecisionEngine│                       │           │               │
│  └──────────────────┘                       │           │               │
│                                             │           │               │
│  ┌──────────────────┐                       │           │               │
│  │ ConfigProvider   │ ◄────────────────────┼───────────┼───────────┐   │
│  │ (配置提供者协议)  │                       │           │           │   │
│  └──────────────────┘                       │           │           │   │
│                                             │           │           │   │
│  ┌──────────────────┐                       │           │           │   │
│  │SignalProvider    │ ◄────────────────────┼───────────┼───────────┼───┤
│  │ (信号提供者协议)  │                       │           │           │   │
│  └──────────────────┘                       │           │           │   │
│                                                         │           │   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Core/Protocols                                │   │
│  │                  (核心协议定义层)                                 │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.2 数据流依赖

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           数据流依赖                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  DetectionResult ──────┐                                               │
│  (检测结果)             │                                               │
│                         │                                               │
│                         ▼                                               │
│                    RiskSnapshot ──────────────┐                         │
│                    (风险快照)                  │                         │
│                                                │                         │
│                                                ▼                         │
│                                         FeatureVector                    │
│                                         (特征向量)                        │
│                                                │                         │
│                                                ▼                         │
│                                          ModelResult                      │
│                                          (模型结果)                        │
│                                                │                         │
│                                                ▼                         │
│                                          RiskVerdict                      │
│                                          (风险裁决)                        │
│                                                │                         │
│                                                ▼                         │
│                                          CPRiskReport                     │
│                                          (风险报告)                        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 五、编译依赖说明

### 5.1 模块编译顺序

```
1. Util (最底层，无依赖)
   └─ Logger, Sysctl, JSON, ISO8601, Crypto

2. Storage (依赖 Util)
   └─ RiskHistoryStore, SecureStorage, CacheStore

3. Core/Models, Core/Protocols (依赖 Storage, Util)
   └─ RiskSignal, RiskSnapshot, Detector, SignalProvider

4. Detection (依赖 Core, Storage, Util)
   ├─ Jailbreak
   ├─ AntiTampering
   ├─ Behavior
   ├─ Network
   ├─ Device
   └─ Environment

5. Analysis (依赖 Core, Storage, Util)
   └─ TemporalAnalyzer, AnomalyDetector, PatternMatcher, FeatureExtractor

6. Config (依赖 Core, Storage, Util)
   └─ ConfigManager, RemoteConfigProvider, LocalConfigProvider

7. Decision (依赖 Core, Detection, Analysis, Config, Storage, Util)
   └─ RiskDecisionEngine, ScenarioBasedPolicy, Models, Verdicts

8. Core/Public (依赖所有其他模块)
   └─ CPRiskKit, CPRiskConfig, CPRiskReport
```

### 5.2 Swift Package Manager 模块划分

```swift
// Package.swift 结构
let package = Package(
    name: "CloudPhoneRiskKit",
    targets: [
        // 工具层
        .target(name: "CPRUtil"),
        
        // 存储层
        .target(name: "CPRStorage", dependencies: ["CPRUtil"]),
        
        // 核心层
        .target(name: "CPRCore", dependencies: ["CPRStorage", "CPRUtil"]),
        
        // 检测层
        .target(name: "CPRDetection", dependencies: ["CPRCore", "CPRStorage", "CPRUtil"]),
        
        // 分析层
        .target(name: "CPRAnalysis", dependencies: ["CPRCore", "CPRStorage", "CPRUtil"]),
        
        // 配置层
        .target(name: "CPRConfig", dependencies: ["CPRCore", "CPRStorage", "CPRUtil"]),
        
        // 决策层
        .target(name: "CPRDecision", dependencies: [
            "CPRCore", "CPRDetection", "CPRAnalysis", 
            "CPRConfig", "CPRStorage", "CPRUtil"
        ]),
        
        // 公开 API
        .target(name: "CloudPhoneRiskKit", dependencies: [
            "CPRCore", "CPRDetection", "CPRDecision", 
            "CPRAnalysis", "CPRConfig", "CPRStorage", "CPRUtil"
        ]),
    ]
)
```

---

## 六、运行时依赖

### 6.1 单例依赖关系

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           单例依赖关系                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  CPRiskKit.shared                                                       │
│       │                                                                 │
│       ├──> RiskDecisionEngine.shared                                    │
│       │         │                                                       │
│       │         ├──> ConfigManager.shared                               │
│       │         │         │                                             │
│       │         │         ├──> RemoteConfigProvider.shared              │
│       │         │         └──> LocalConfigProvider.shared               │
│       │         │                                                       │
│       │         ├──> ScenarioBasedPolicy.shared                         │
│       │         │                                                       │
│       │         └──> TemporalAnalyzer.shared                            │
│       │                 │                                               │
│       │                 └──> RiskHistoryStore.shared                     │
│       │                                                                 │
│       ├──> JailbreakEngine (非单例，每次创建)                           │
│       │                                                                 │
│       ├──> AntiTamperEngine (非单例，每次创建)                          │
│       │                                                                 │
│       ├──> BehaviorEngine (内部使用单例 TouchCapture, MotionSampler)   │
│       │         │                                                       │
│       │         ├──> TouchCapture.shared                                │
│       │         └──> MotionSampler.shared                               │
│       │                                                                 │
│       ├──> NetworkEngine (非单例)                                      │
│       │                                                                 │
│       ├──> DeviceEngine (非单例)                                       │
│       │         │                                                       │
│       │         └──> KeychainDeviceID.shared                           │
│       │                                                                 │
│       └──> EnvironmentEngine (非单例)                                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 初始化顺序

```
启动顺序：
1. CPRiskKit.shared.start()
   │
2. Logger 初始化
   │
3. ConfigManager 初始化
   │
   ├──> 加载本地配置
   │
4. 注册默认信号提供者
   │
   ├──> ExternalServerAggregateProvider
   ├──> DeviceHardwareProvider
   ├──> DeviceAgeProvider
   └──> TimePatternProvider
   │
5. 启动行为采集
   │
   ├──> TouchCapture.shared.start()
   └──> MotionSampler.shared.start()
   │
6. 尝试获取远程配置 (异步)
   │
   └──> RemoteConfigProvider.fetchConfig()
        │
        └──> 成功后更新所有检测器和决策引擎配置
```

---

## 七、测试依赖

### 7.1 单元测试依赖

```
Tests/
├── UtilTests/
│   ├── JSONTests.swift              # 依赖: CPRUtil
│   └── CryptoTests.swift            # 依赖: CPRUtil
│
├── StorageTests/
│   ├── RiskHistoryStoreTests.swift  # 依赖: CPRStorage
│   └── CacheStoreTests.swift        # 依赖: CPRStorage
│
├── DetectionTests/
│   ├── JailbreakEngineTests.swift   # 依赖: CPRDetection, Mocks
│   ├── BehaviorEngineTests.swift    # 依赖: CPRDetection, Mocks
│   └── NetworkEngineTests.swift     # 依赖: CPRDetection, Mocks
│
├── DecisionTests/
│   ├── RiskDecisionEngineTests.swift # 依赖: CPRDecision, Mocks
│   └── ScenarioBasedPolicyTests.swift # 依赖: CPRDecision, Mocks
│
├── AnalysisTests/
│   └── TemporalAnalyzerTests.swift  # 依赖: CPRAnalysis
│
├── ConfigTests/
│   ├── ConfigManagerTests.swift     # 依赖: CPRConfig
│   └── RemoteConfigProviderTests.swift # 依赖: CPRConfig, NetworkMock
│
└── IntegrationTests/
    └── EndToEndTests.swift          # 依赖: 全部模块
```

### 7.2 Mock 依赖

```
TestMocks/
├── MockDetector.swift               # 实现 Detector 协议
├── MockDecisionEngine.swift         # 实现 DecisionEngine 协议
├── MockConfigProvider.swift         # 实现 ConfigProvider 协议
├── MockSignalProvider.swift         # 实现 SignalProvider 协议
└── MockNetworkClient.swift          # 模拟网络请求
```

---

## 八、依赖最佳实践

### 8.1 依赖倒置原则

**❌ 错误示例：**
```swift
class RiskDecisionEngine {
    // 直接依赖具体实现
    private let configManager = ConfigManager.shared
    private let jailbreakEngine = JailbreakEngine()
}
```

**✅ 正确示例：**
```swift
class RiskDecisionEngine {
    // 依赖抽象接口
    private let configReader: ConfigReading
    private let detectorRegistry: DetectorRegistry
    
    init(
        configReader: ConfigReading,
        detectorRegistry: DetectorRegistry
    ) {
        self.configReader = configReader
        self.detectorRegistry = detectorRegistry
    }
}
```

### 8.2 依赖注入模式

```swift
// 1. 构造器注入 (推荐)
class JailbreakEngine {
    private let detectors: [Detector]
    
    init(detectors: [Detector]) {
        self.detectors = detectors
    }
}

// 2. 属性注入 (可选)
class RiskDecisionEngine {
    var configProvider: ConfigProvider?
}

// 3. 方法注入 (临时依赖)
func evaluate(
    snapshot: RiskSnapshot,
    policy: PolicyConfig  // 临时传入
) -> RiskVerdict {
    // ...
}
```

### 8.3 接口隔离原则

**❌ 肥接口：**
```swift
protocol ConfigProvider {
    func getRemoteConfig() -> RemoteConfig
    func getLocalConfig() -> LocalConfig
    func updateRemoteConfig(_ config: RemoteConfig)
    func clearCache()
    // ... 太多方法
}
```

**✅ 拆分接口：**
```swift
protocol ConfigReading {
    func getConfig() -> Config
}

protocol ConfigUpdating {
    func updateConfig(_ config: Config)
}

protocol ConfigCaching {
    func clearCache()
}
```

---

## 附录

### A. 依赖检查清单

在添加新依赖时，请检查：

- [ ] 是否违反依赖方向（上层依赖下层）
- [ ] 是否创建循环依赖
- [ ] 是否可以使用协议解耦
- [ ] 是否可以通过依赖注入解决
- [ ] 是否影响测试（能否方便地 Mock）

### B. 依赖更新流程

1. **添加新模块依赖**
   - 更新本文档
   - 更新 Package.swift
   - 添加相关测试

2. **移除模块依赖**
   - 检查影响范围
   - 更新本文档
   - 更新 Package.swift
   - 更新相关测试

3. **修改模块接口**
   - 检查依赖方影响
   - 保持向后兼容
   - 更新文档和测试

---

*文档版本：1.0*
*最后更新：2026-02-06*
