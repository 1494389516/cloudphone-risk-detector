# CloudPhoneRiskKit SDK 2.0 - 架构差距分析与实现计划

## 文档概述

| 项目 | 说明 |
|------|------|
| 版本 | 2.0.0 |
| 作者 | CloudPhone Risk Team |
| 更新日期 | 2026-02-06 |
| 状态 | 规划中 |

---

## 一、架构差距分析

### 1.1 目录结构对比

#### 目标架构（设计文档）
```
Sources/CloudPhoneRiskKit/
├── Core/
│   ├── Public/           # 公开 API
│   ├── Models/           # 数据模型
│   └── Protocols/        # 核心协议
├── Detection/            # 检测引擎
│   ├── Jailbreak/        # 越狱检测
│   ├── AntiTampering/    # 反篡改检测
│   ├── Behavior/         # 行为检测
│   ├── Network/          # 网络检测
│   ├── Device/           # 设备指纹
│   └── Environment/      # 环境检测
├── Decision/             # 决策引擎
├── Analysis/             # 分析模块
├── Config/               # 配置模块
├── Providers/            # 扩展信号提供者
├── Storage/              # 存储模块
└── Util/                 # 工具类
```

#### 当前结构（已实现）
```
Sources/CloudPhoneRiskKit/
├── Analysis/             ✅ 已实现
│   ├── AnomalyDetector.swift
│   ├── BehaviorBaseline.swift
│   ├── DeviceHistory.swift
│   ├── TemporalAnalyzer.swift
│   └── TemporalFeatures.swift
├── Behavior/             ✅ 已实现（1.0 遗留）
├── CloudPhone/           ✅ 已实现（1.0 遗留）
├── Config/               ✅ 已实现
│   ├── ConfigCache.swift
│   ├── RemoteConfig.swift
│   └── RemoteConfigProvider.swift
├── Core/                 ✅ 部分实现
│   ├── Models/
│   │   ├── DeviceHistory.swift
│   │   └── EnhancedDeviceFingerprint.swift
│   └── Protocols/
│       ├── ConfigProvider.swift
│       └── DecisionEngine.swift
├── Decision/             ✅ 已实现
│   ├── DecisionEngineAdapter.swift
│   ├── RiskDetectionEngine.swift
│   └── ScenarioPolicy.swift
├── Detection/            ✅ 部分实现
│   ├── AntiBypass/       ✅ 已实��
│   │   ├── FingerprintDeobfuscation.swift
│   │   ├── MultiPathFileDetector.swift
│   │   ├── RandomizedDetection.swift
│   │   └── SDKIntegrityChecker.swift
│   └── AntiTampering/    ✅ 已实现
├── Device/               ✅ 已实现（1.0 遗留）
├── Jailbreak/            ✅ 已实现（1.0 遗留）
├── Network/              ✅ 已实现（1.0 遗留）
├── Providers/            ✅ 已实现（1.0 遗留）
├── Storage/              ✅ 已实现（1.0 遗留）
└── Util/                 ✅ 已实现（1.0 遗留）
```

### 1.2 功能模块差距

| 模块 | 设计要求 | 当前状态 | 差距 |
|------|---------|---------|------|
| **Core/Public** | CPRiskKit.swift, CPRiskConfig.swift, CPRiskReport.swift | 使用 1.0 版本 | 需要更新为 2.0 API |
| **Core/Models** | RiskSignal, RiskSnapshot, RiskVerdict, DetectionResult | 部分实现 | 缺少 RiskSignal, RiskSnapshot |
| **Detection/Jailbreak** | JailbreakEngine + Detectors | ✅ 已有（1.0） | 需要重构为 2.0 架构 |
| **Detection/AntiTampering** | AntiTamperEngine + Detectors | ✅ 已实现 | 需要整合到 Detection 层 |
| **Detection/AntiBypass** | 对抗技术模块 | ✅ 已实现 | 需要整合到 Detection 层 |
| **Detection/Behavior** | BehaviorEngine | 部分实现（1.0） | 需要重构 |
| **Detection/Network** | NetworkEngine | 部分实现（1.0） | 需要重构 |
| **Detection/Device** | DeviceEngine | 部分实现（1.0） | 需要重构 |
| **Detection/Environment** | EnvironmentEngine | ❌ 未实现 | **需要新建** |
| **Decision** | RiskDecisionEngine, ScenarioPolicy | ✅ 已实现 | 需要整合 |
| **Analysis** | TemporalAnalyzer, AnomalyDetector | ✅ 已实现 | 需要整合 |
| **Config** | ConfigManager, Remote/Local Provider | 部分实现 | 缺少 LocalConfigProvider |
| **Storage** | RiskHistoryStore, SecureStorage, CacheStore | 部分实现 | 缺少 SecureStorage, CacheStore |

---

## 二、优先级分级

### 2.1 P0 - 核心功能（必须完成）

| 任务 | 描述 | 预估工作量 |
|------|------|-----------|
| 核心模型实现 | RiskSignal, RiskSnapshot, RiskVerdict | 2h |
| Detection 层整合 | 统一各检测引擎接口 | 4h |
| Decision 层集成 | 连接 Detection 和 Decision | 3h |
| Config 补全 | LocalConfigProvider, ConfigManager | 2h |
| 主入口重构 | CPRiskKit 2.0 API | 3h |

**小计**: 14 小时

### 2.2 P1 - 重要功能（应该完成）

| 任务 | 描述 | 预估工作量 |
|------|------|-----------|
| Environment 检测引擎 | SimulatorDetector, ProxyDetector | 3h |
| Storage 补全 | SecureStorage, CacheStore | 2h |
| 1.0 检测器重构 | 适配新架构 | 4h |
| 异步检测支持 | async/await 接口 | 2h |

**小计**: 11 小时

### 2.3 P2 - 增强功能（可以延后）

| 任务 | 描述 | 预估工作量 |
|------|------|-----------|
| 高级异常检测 | ML 模型集成 | 8h |
| 性能优化 | 并行检测、缓存 | 4h |
| 文档完善 | API 文档、使用指南 | 4h |

**小计**: 16 小时

---

## 三、实现计划

### 3.1 第一阶段：核心整合（P0）

**目标**: 完成核心架构整合，确保基本功能可用

#### Step 1: 核心模型实现
```swift
// Core/Models/RiskSignal.swift
public struct RiskSignal: Sendable {
    public let id: String
    public let category: String
    public let score: Double
    public let evidence: [String: Any]
    public let timestamp: Date
}

// Core/Models/RiskSnapshot.swift
public struct RiskSnapshot: Sendable {
    public let signals: [RiskSignal]
    public let fingerprint: DeviceFingerprint
    public let timestamp: Date
    public let scenario: RiskScenario
}

// Core/Models/RiskVerdict.swift
public struct RiskVerdict: Sendable {
    public let level: RiskLevel
    public let confidence: Double
    public let action: RiskAction
    public let reasons: [String]
}
```

#### Step 2: Detection 层统一接口
```swift
// Detection/DetectionEngine.swift (新建)
public protocol DetectionEngine {
    func detect() async -> DetectionResult
}

// 将现有检测器整合到统一架构
// - JailbreakEngine
// - AntiTamperEngine (整合 AntiTampering + AntiBypass)
// - BehaviorEngine
// - NetworkEngine
// - DeviceEngine
```

#### Step 3: Decision 层集成
```swift
// 使用现有的 DecisionEngineAdapter 连接 Detection 和 Decision
// 确保数据流正确
```

#### Step 4: Config 补全
```swift
// Config/LocalConfigProvider.swift (新建)
public struct LocalConfigProvider: ConfigProvider {
    // 本地默认配置
}

// Config/ConfigManager.swift (新建)
public final class ConfigManager {
    // 配置合并、缓存、更新逻辑
}
```

#### Step 5: 主入口重构
```swift
// Core/Public/CPRiskKit.swift (更新)
// 保持 1.0 API 兼容
// 新增 2.0 API
```

### 3.2 第二阶段：功能补全（P1）

**目标**: 完善检测能力和存储能力

#### Step 6: Environment 检测引擎
```swift
// Detection/Environment/EnvironmentEngine.swift
// Detection/Environment/SimulatorDetector.swift
// Detection/Environment/ProxyDetector.swift
```

#### Step 7: Storage 补全
```swift
// Storage/SecureStorage.swift
// Storage/CacheStore.swift
```

#### Step 8: 1.0 检测器重构
```swift
// 将现有 1.0 检测器适配新架构
// 确保向后兼容
```

#### Step 9: 异步检测支持
```swift
// 为所有 DetectionEngine 添加 async 接口
// 支持并行检测
```

### 3.3 第三阶段：增强优化（P2）

**目标**: 性能优化和高级功能

#### Step 10: 高级异常检测
```swift
// 集成 ML 模型
// 图分析
```

#### Step 11: 性能优化
```swift
// 并行检测优化
// 结果缓存
// 懒加载
```

#### Step 12: 文档完善
```swift
// API 文档
// 使用指南
// 迁移指南
```

---

## 四、迁移策略

### 4.1 兼容性保证

1. **保留 1.0 API**: 所有 1.0 公开接口保持不变
2. **新增 2.0 API**: 通过 extension 添加新功能
3. **渐进式迁移**: 用户可以逐步迁移到 2.0 API

### 4.2 数据迁移

1. **存储格式兼容**: 保持现有存储格式
2. **配置迁移**: 自动迁移 1.0 配置到 2.0
3. **历史数据**: 保留现有历史记录

### 4.3 测试策略

1. **单元测试**: 为每个新模块编写测试
2. **集成测试**: 确保模块间协作正常
3. **回归测试**: 确保 1.0 功能不受影响
4. **性能测试**: 确保性能不下降

---

## 五、风险与应对

| 风险 | 影响 | 应对措施 |
|------|------|---------|
| 架构重构引入 bug | 高 | 充分测试、逐步迁移 |
| 性能回归 | 中 | 性能基准测试、优化关键路径 |
| 兼容性问题 | 中 | 保留 1.0 API、自动化兼容性测试 |
| 开发周期延长 | 低 | 按优先级分阶段交付 |

---

## 六、时间规划

| 阶段 | 任务 | 预估时间 | 里程碑 |
|------|------|---------|--------|
| 第一阶段 | P0 核心整合 | 14h | 基本功能可用 |
| 第二阶段 | P1 功能补全 | 11h | 功能完整 |
| 第三阶段 | P2 增强优化 | 16h | 性能优化 |
| **总计** | | **41h** | |

---

## 七、验收标准

### 7.1 功能验收

- [ ] 所有 P0 功能实现
- [ ] 1.0 API 完全兼容
- [ ] 2.0 API 可用
- [ ] 单元测试覆盖率 > 80%

### 7.2 性能验收

- [ ] 冷启动耗时 < 50ms
- [ ] 检测耗时 < 100ms (P99)
- [ ] 内存占用 < 10MB

### 7.3 质量验收

- [ ] 无编译警告
- [ ] 无静态分析问题
- [ ] 代码审查通过

---

*文档版本：1.0*
*最后更新：2026-02-06*
