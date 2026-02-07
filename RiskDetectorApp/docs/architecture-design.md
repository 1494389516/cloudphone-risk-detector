# CloudPhoneRiskKit SDK 2.0 架构设计文档

## 文档概述

| 项目 | 说明 |
|------|------|
| 版本 | 2.0.0 |
| 作者 | CloudPhone Risk Team |
| 更新日期 | 2026-02-06 |
| 状态 | 设计中 |

---

## 一、背景分析

### 1.1 当前版本 (1.0) 架构分析

经过对现有代码的深入分析，当前 1.0 版本具有以下特点：

**优点：**
- 代码结构清晰，模块划分合理
- 采用了协议导向设计（如 `Detector`、`RiskSignalProvider`）
- 支持插件化扩展（`RiskSignalProviderRegistry`）
- 具备基础的检测能力（越狱、行为、网络信号）

**存在的问题：**

#### 问题 1：评分算法固化
```swift
// RiskScorer.swift - 硬编码的评分逻辑
let jbContribution = jbScore * 0.6  // 越狱权重固定 60%
total += jbContribution
```
- 所有评分权重、阈值都硬编码在 `RiskScorer` 中
- 无法动态调整策略
- 无法实现 A/B 测试

#### 问题 2：缺乏远程配置能力
- 配置仅支持本地静态配置（`RiskConfig`）
- 无法下发动态策略
- 无法紧急关闭特定检测器
- 无法动态调整阈值

#### 问题 3：缺乏时序分析
- 虽��� `RiskHistoryStore` 记录历史，但分析能力有限
- 无法检测异常时间模式（如凌晨高频操作）
- 无法识别批量攻击行为

#### 问题 4：检测能力有限
- 缺少反篡改检测
- 缺少反调试检测
- 缺少 Hook 深度检测
- 缺少模拟器深度识别

#### 问题 5：决策逻辑简单
- 仅基于简单阈值判断
- 无场景化策略
- 无灰度决策能力
- 无置信度量化

---

## 二、架构设计原则

### 2.1 设计目标

1. **向后兼容**：保持与 1.0 API 的兼容性
2. **动态可配**：支持远程配置下发
3. **智能决策**：基于多维度信号进行综合决策
4. **高可扩展**：易于添加新的检测器和策略
5. **高性能**：异步检测，不阻塞主线程
6. **安全可靠**：防篡改、防逆向

### 2.2 架构原则

| 原则 | 说明 |
|------|------|
| 关注点分离 | 检测、决策、配置三层解耦 |
| 依赖倒置 | 上层依赖抽象，不依赖具体实现 |
| 开闭原则 | 对扩展开放，对修改关闭 |
| 单一职责 | 每个模块职责明确 |
| 接口隔离 | 接口设计精简，避免冗余 |

---

## 三、三层架构设计

### 3.1 架构全景图

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CloudPhoneRiskKit 2.0                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌───────────────────────────────────────────────────────���─────┐   │
│  │                    应用层 (Application Layer)                │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌─────────────────┐  │   │
│  │  │  CPRiskKit    │  │  CPRiskConfig │  │  CPRiskReport   │  │   │
│  │  │  (主入口)      │  │  (公开配置)    │  │  (结果报告)      │  │   │
│  │  └───────────────┘  └───────────────┘  └─────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                     决策层 (Decision Layer)                  │   │
│  │  ┌───────────────────┐  ┌─────────────────────────────────┐  │   │
│  │  │ RiskDecisionEngine│  │   ScenarioBasedPolicy            │  │   │
│  │  │ (智能决策引擎)     │  │   (场景化策略)                    │  │   │
│  │  └───────────────────┘  └─────────────────────────────────┘  │   │
│  │  ┌───────────────────┐  ┌─────────────────────────────────┐  │   │
│  │  │  TemporalAnalyzer │  │   EnsembleDecider               │  │   │
│  │  │  (时序分析引擎)    │  │   (集成决策器)                    │  │   │
│  │  └───────────────────┘  └─────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                     检测层 (Detection Layer)                 │   │
│  │  ┌────────────────┐  ┌─────────────────┐  ┌──────────────┐  │   │
│  │  │  JailbreakEngine│ │ AntiTamperEngine│ │ BehaviorEngine│  │   │
│  │  │  (越狱检测)      │ │ (反篡改检测)      │ │ (行为检测)     │  │   │
│  │  └────────────────┘  └─────────────────┘  └──────────────┘  │   │
│  │  ┌────────────────┐  ┌─────────────────┐  ┌──────────────┐  │   │
│  │  │ NetworkEngine  │ │  DeviceEngine   │ │ Environment   │  │   │
│  │  │ (网络检测)      │ │  (设备指纹)       │ │ (环境检测)     │  │   │
│  │  └────────────────┘  └─────────────────┘  └──────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                     配置层 (Config Layer)                     │   │
│  │  ┌─────────────────────┐  ┌───────────────────────────────┐  │   │
│  │  │ RemoteConfigProvider│  │   LocalConfigProvider          │  │   │
│  │  │ (远程配置提供者)      │ │   (本地配置提供者)              │  │   │
│  │  └─────────────────────┘  └───────────────────────────────┘  │   │
│  │  ┌─────────────────────────────────────────────────────────┐ │   │
│  │  │           ConfigManager (配置管理器)                      │ │   │
│  │  └─────────────────────────────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              ↓                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                     存储层 (Storage Layer)                    │   │
│  │  ┌────────────────┐  ┌─────────────────┐  ┌──────────────┐  │   │
│  │  │ RiskHistoryStore│ │  SecureStorage  │ │ CacheStore   │  │   │
│  │  │ (历史记录)      │ │  (安全存储)       │ │ (缓存存储)    │  │   │
│  │  └────────────────┘  └─────────────────┘  └──────────────┘  │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 层次职责说明

#### 检测层 (Detection Layer)

**职责：** 负责采集各种风险信号，不参与决策逻辑

| 模块 | 功能 | 输出 |
|------|------|------|
| JailbreakEngine | 越狱检测 | DetectionResult |
| AntiTamperEngine | 反篡改检测 | TamperingResult |
| BehaviorEngine | 行为分析 | BehaviorSignals |
| NetworkEngine | 网络环境检测 | NetworkSignals |
| DeviceEngine | 设备指纹采集 | DeviceFingerprint |
| EnvironmentEngine | 运行环境检测 | EnvironmentSignals |

**设计原则：**
- 检测器之间相互独立
- 每个检测器输出标准化信号
- 支持异步检测
- 支持配置开关

#### 决策层 (Decision Layer)

**职责：** 基于检测层输出的信号进行综合决策

| 模块 | 功能 | 说明 |
|------|------|------|
| RiskDecisionEngine | 智能决策引擎 | 多模型融合决策 |
| ScenarioBasedPolicy | 场景化策略 | 不同场景不同策略 |
| TemporalAnalyzer | 时序分析引擎 | 分析时间模式异常 |
| EnsembleDecider | 集成决策器 | 多算法投票/加权 |

**决策流程：**
```
原始信号 → 特征提取 → 模型评估 → 策略应用 → 最终决策
    ↓         ↓          ↓          ↓          ↓
 Detection  Features  Scoring   Policy    Verdict
```

#### 配置层 (Config Layer)

**职责：** 管理检测和决策所需的配置

| 模块 | 功能 | 说明 |
|------|------|------|
| RemoteConfigProvider | 远程配置提供者 | 从服务端获取配置 |
| LocalConfigProvider | 本地配置提供者 | 本地默认配置 |
| ConfigManager | 配置管理器 | 配置合并、缓存、更新 |

**配置优先级：**
```
远程配置 > 本地配置 > 代码默认值
```

---

## 四、核心模块设计

### 4.1 RiskDecisionEngine (智能决策引擎)

**设计目标：**
- 支持多模型融合决策
- 支持动态权重调整
- 支持置信度量化
- 支持特征重要性分析

**决策模型：**
```
                    ┌─────────────────┐
                    │  Raw Signals    │
                    │  (原始信号)      │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ↓              ↓              ↓
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │  Rule    │   │  ML      │   │ Graph    │
        │  Model   │   │  Model   │   │  Model   │
        │(规则模型) │   │(ML模型)  │   │(图模型)  │
        └────┬─────┘   └────┬─────┘   └────┬─────┘
             │              │              │
             └──────────────┼──────────────┘
                            ↓
                   ┌─────────────────┐
                   │  Ensemble       │
                   │  (集成决策)      │
                   └────────┬────────┘
                            │
                   ┌─────────────────┐
                   │  Final Verdict  │
                   │  (最终裁决)      │
                   └─────────────────┘
```

### 4.2 TemporalAnalyzer (时序分析引擎)

**功能：**
- 检测异常时间模式
- 识别机器人行为特征
- 检测批量操作

**分析维度：**
| 维度 | 说明 | 风险特征 |
|------|------|----------|
| 时间分布 | 24小时内事件分布 | 凌晨高频、全时段活跃 |
| 频率分析 | 事件间隔统计 | 过于规律、过于频繁 |
| 序列模式 | 事件序列分析 | 固定序列、循环模式 |
| 异常检测 | 偏离正常模式 | 突然活跃、突然沉寂 |

### 4.3 ScenarioBasedPolicy (场景化策略)

**支持场景：**
- 登录场景
- 支付场景
- 注册场景
- 数据查询场景

**每个场景独立配置：**
- 不同的阈值
- 不同的检测器组合
- 不同的权重策略

### 4.4 AntiTamperEngine (反篡改引擎)

**新增模块，检测能力：**
- 代码完整性校验
- 动态库注入检测
- Hook 检测（Cydia Substitute、Frida）
- 调试器检测
- 模拟器深度识别

---

## 五、数据流设计

### 5.1 检测流程

```
┌─────────────┐
│ CPRiskKit.  │
│ evaluate()  │
└──────┬──────┘
       │
       ↓
┌─────────────────────────────────────┐
│ 1. 并行采集信号 (异步)               │
│    - JailbreakEngine.detect()       │
│    - AntiTamperEngine.detect()      │
│    - BehaviorEngine.collect()       │
│    - NetworkEngine.collect()        │
│    - DeviceEngine.collect()         │
└──────────┬──────────────────────────┘
           │
           ↓
┌─────────────────────────────────────┐
│ 2. 构建 RiskSnapshot                │
│    (信号快照)                        │
└──────────┬──────────────────────────┘
           │
           ↓
┌─────────────────────────────────────┐
│ 3. 获取配置                          │
│    - RemoteConfig (优先)            │
│    - LocalConfig (兜底)              │
└──────────┬──────────────────────────┘
           │
           ↓
┌─────────────────────────────────────┐
│ 4. 时序分析                          │
│    TemporalAnalyzer.analyze()       │
└──────────┬──────────────────────────┘
           │
           ↓
┌─────────────────────────────────────┐
│ 5. 场景匹配                          │
│    ScenarioBasedPolicy.match()      │
└──────────┬──────────────────────────┘
           │
           ↓
┌─────────────────────────────────────┐
│ 6. 决策评估                          │
│    RiskDecisionEngine.decide()      │
└──────────┬──────────────────────────┘
           │
           ↓
┌─────────────────────────────────────┐
│ 7. 生成报告                          │
│    CPRiskReport                     │
└─────────────────────────────────────┘
```

### 5.2 配置更新流程

```
┌───────────────┐
│  Server API   │
│  (配置服务)     │
└───────┬───────┘
        │
        ↓ 定期拉取/WebSocket 推送
┌───────────────────────────────┐
│ RemoteConfigProvider          │
│ - 配置下载                     │
│ - 签名验证                     │
│ - 版本检查                     │
└───────────┬───────────────────┘
            │
            ↓
┌───────────────────────────────┐
│ ConfigManager                 │
│ - 配置合并 (远程+本地)          │
│ - 配置缓存                     │
│ - 配置分发                     │
└───────────┬───────────────────┘
            │
            ↓
┌───────────────────────────────┐
│ 各引擎/检测器                  │
│ - 应用新配置                   │
│ - 动态调整策略                 │
└───────────────────────────────┘
```

---

## 六、目录结构设计

### 6.1 完整目录结构

```
Sources/CloudPhoneRiskKit/
├── Core/                           # 核心接口和模型
│   ├── Public/                     # 公开 API
│   │   ├── CPRiskKit.swift         # 主入口
│   │   ├── CPRiskConfig.swift      # 公开配置
│   │   └── CPRiskReport.swift      # 公开报告
│   ├── Models/                     # 数据模型
│   │   ├── RiskSignal.swift        # 风险信号
│   │   ├── RiskSnapshot.swift      # 信号快照
│   │   ├── RiskVerdict.swift       # 决策结果
│   │   └── DetectionResult.swift   # 检测结果
│   └── Protocols/                  # 核心协议
│       ├── Detector.swift          # 检测器协议
│       ├── SignalProvider.swift    # 信号提供者协议
│       ├── DecisionEngine.swift    # 决策引擎协议
│       └── ConfigProvider.swift    # 配置提供者协议
│
├── Detection/                      # 检测引擎
│   ├── Jailbreak/                  # 越狱检测
│   │   ├── JailbreakEngine.swift
│   │   ├── JailbreakConfig.swift
│   │   └── Detectors/
│   │       ├── FileDetector.swift
│   │       ├── DyldDetector.swift
│   │       ├── EnvDetector.swift
│   │       ├── SysctlDetector.swift
│   │       ├── SchemeDetector.swift
│   │       └── HookDetector.swift
│   │
│   ├── AntiTampering/              # 反篡改检测 (新增)
│   │   ├── AntiTamperEngine.swift
│   │   ├── AntiTamperConfig.swift
│   │   └── Detectors/
│   │       ├── CodeIntegrityDetector.swift
│   │       ├── DylibInjectionDetector.swift
│   │       ├── DebuggerDetector.swift
│   │       └── FridaDetector.swift
│   │
│   ├── Behavior/                   # 行为检测
│   │   ├── BehaviorEngine.swift
│   │   ├── TouchCapture.swift
│   │   ├── MotionSampler.swift
│   │   └── BehaviorCoupling.swift
│   │
│   ├── Network/                    # 网络检测
│   │   ├── NetworkEngine.swift
│   │   └── NetworkSignals.swift
│   │
│   ├── Device/                     # 设备指纹
│   │   ├── DeviceEngine.swift
│   │   ├── DeviceFingerprint.swift
│   │   └── KeychainDeviceID.swift
│   │
│   └── Environment/                # 环境检测 (新增)
│       ├── EnvironmentEngine.swift
│       ├── SimulatorDetector.swift
│       └── ProxyDetector.swift
│
├── Decision/                       # 决策引擎 (新增)
│   ├── RiskDecisionEngine.swift    # 智能决策引擎
│   ├── ScenarioBasedPolicy.swift   # 场景化策略
│   ├── Models/                     # 决策模型
│   │   ├── RuleBasedModel.swift    # 规则模型
│   │   ├── ScoringModel.swift      # 评分模型
│   │   └── EnsembleModel.swift     # 集成模型
│   └── Verdicts/                   # 裁决器
│       ├── ThresholdDecider.swift  # 阈值裁决
│       └── CompositeDecider.swift  # 组合裁决
│
├── Analysis/                       # 分析模块 (新增)
│   ├── TemporalAnalyzer.swift      # 时序分析
│   ├── AnomalyDetector.swift       # 异常检测
│   ├── PatternMatcher.swift        # 模式匹配
│   └── FeatureExtractor.swift      # 特征提取
│
├── Config/                         # 配置模块 (新增)
│   ├── ConfigManager.swift         # 配置管理器
│   ├── RemoteConfigProvider.swift  # 远程配置提供者
│   ├── LocalConfigProvider.swift   # 本地配置提供者
│   ├── Models/                     # 配置模型
│   │   ├── RemoteConfig.swift      # 远程配置
│   │   ├── DetectorConfig.swift    # 检测器配置
│   │   ├── PolicyConfig.swift      # 策略配置
│   │   └── ScenarioConfig.swift    # 场景配置
│   └── Cache/                      # 配置缓存
│       └── ConfigCache.swift
│
├── Providers/                      # 扩展信号提供者
│   ├── ExternalServerAggregateProvider.swift
│   ├── DeviceHardwareProvider.swift
│   ├── DeviceAgeProvider.swift
│   └── TimePatternProvider.swift
│
├── Storage/                        # 存储模块
│   ├── RiskHistoryStore.swift      # 历史记录
│   ├── SecureStorage.swift         # 安全存储
│   └── CacheStore.swift            # 缓存存储
│
└── Util/                           # 工具类
    ├── Logger.swift
    ├── Sysctl.swift
    ├── JSON.swift
    ├── ISO8601.swift
    └── Crypto.swift
```

---

## 七、向后兼容性设计

### 7.1 API 兼容策略

**保持 1.0 API 不变：**
```swift
// 1.0 API - 保持不变
@objc public class CPRiskKit: NSObject {
    @objc public static let shared = CPRiskKit()
    @objc public func start()
    @objc public func stop()
    @objc public func evaluate() -> CPRiskReport
    @objc public func evaluateAsync(completion: @escaping (CPRiskReport) -> Void)
}
```

**新增 2.0 API：**
```swift
// 2.0 新增 API
extension CPRiskKit {
    @objc public func evaluate(scenario: RiskScenario) -> CPRiskReport
    @objc public func evaluate(config: RiskConfig, scenario: RiskScenario) -> CPRiskReport
    @objc public func updateRemoteConfig(completion: @escaping (Bool) -> Void)
}
```

### 7.2 配置兼容策略

**1.0 配置继续支持：**
```swift
// 1.0 配置方式
let config = CPRiskConfig()
config.threshold = 60
config.enableBehaviorDetect = true
```

**2.0 增强配置：**
```swift
// 2.0 增强配置
let config = RiskConfig()
config.scenario = .payment  // 场景配置
config.enableRemoteConfig = true  // 启用远程配置
```

---

## 八、安全设计

### 8.1 通信安全

| 措施 | 说明 |
|------|------|
| HTTPS | 所有网络通信使用 HTTPS |
| 证书校验 | 严格校验服务端证书 |
| 签名验证 | 远程配置必须带签名 |
| 加密存储 | 敏感数据本地加密存储 |

### 8.2 防篡改设计

| 措施 | 说明 |
|------|------|
| 代码校验 | 启动时校验关键代码段 |
| 完整性检查 | 检测动态库注入 |
| 反调试 | 运行时检测调试器 |
| 反 Hook | 检测 Frida、Cydia 等 |

### 8.3 隐私保护

| 措施 | 说明 |
|------|------|
| 最小采集 | 只采集必要信息 |
| 本地处理 | 敏感分析本地完成 |
| 可控上报 | 用户可控上报行为 |
| 数据脱敏 | 上报数据脱敏处理 |

---

## 九、性能设计

### 9.1 性能目标

| 指标 | 目标值 |
|------|--------|
| 冷启动耗时 | < 50ms |
| 检测耗时 | < 100ms (P99) |
| 内存占用 | < 10MB |
| CPU 占用 | < 5% (平均) |
| 电量影响 | < 1%/天 |

### 9.2 性能优化策略

1. **异步检测**：耗时检测异步执行
2. **并行采集**：信号采集并行化
3. **结果缓存**：缓存稳定信号
4. **按需检测**：根据配置动态开关
5. **懒加载**：非核心模块懒加载

---

## 十、测试策略

### 10.1 测试金字塔

```
        ┌─────┐
       ┌───────┐      E2E Tests (10%)
      ┌─────────┐     集成测试
     ┌───────────┐    Integration Tests (30%)
    ┌─────────────┘   模块间测试
   ┌───────────────┘  Unit Tests (60%)
  └─────────────────┘ 单元测试
```

### 10.2 测试覆盖

| 模块 | 单元测试 | 集成测试 | E2E测试 |
|------|---------|---------|---------|
| Detection | ✓ | ✓ | ✓ |
| Decision | ✓ | ✓ | ✓ |
| Config | ✓ | ✓ | - |
| Storage | ✓ | - | - |

---

## 十一、版本规划

### 11.1 里程碑

| 版本 | 时间 | 主要功能 |
|------|------|----------|
| 2.0.0-alpha | 2026-02 | 架构重构、核心接口 |
| 2.0.0-beta | 2026-03 | 完整功能、内部测试 |
| 2.0.0-rc | 2026-04 | 稳定版本、外部测试 |
| 2.0.0 | 2026-05 | 正式发布 |

### 11.2 功能优先级

**P0 (必须有)：**
- 三层架构实现
- 远程配置支持
- 时序分析引擎
- 场景化策略

**P1 (应该有)：**
- 反篡改检测
- 反调试检测
- 决策引擎优化

**P2 (可以有)：**
- ML 模型集成
- 图分析
- 高级异常检测

---

## 十二、风险评估与应对

| 风险 | 等级 | 应对措施 |
|------|------|----------|
| 架构重构引入 bug | 高 | 充分测试、保持 1.0 API 兼容 |
| 远程配置服务不可用 | 中 | 本地配置兜底 |
| 性能回归 | 中 | 性能测试、优化关键路径 |
| 检测能力不足 | 低 | 持续迭代、增强检测器 |

---

## 附录

### A. 术语表

| 术语 | 说明 |
|------|------|
| Detection Result | 检测结果，检测器输出 |
| Risk Signal | 风险信号，标准化风险指标 |
| Risk Snapshot | 风险快照，某时刻的所有信号 |
| Verdict | 裁决，最终决策结果 |
| Scenario | 场景，业务使用场景 |
| Policy | 策略，决策规则集合 |

### B. 参考文档

1. Apple Swift API Design Guidelines
2. iOS Security Best Practices
3. Mobile Fraud Detection Patterns
4. Machine Learning for Fraud Detection

---

*文档版本：1.0*
*最后更新：2026-02-06*
