# CloudPhoneRiskKit SDK 2.0 API 设计文档

## 文档概述

| 项目 | 说明 |
|------|------|
| 版本 | 2.0.0 |
| 作者 | CloudPhone Risk Team |
| 更新日期 | 2026-02-06 |
| 状态 | 设计中 |

---

## 一、API 设计原则

### 1.1 设计理念

1. **渐进式增强**：从简单到复杂，满足不同层次需求
2. **类型安全**：充分利用 Swift 类型系统
3. **异步优先**：主 API 使用 async/await
4. **向后兼容**：保持 1.0 Objective-C API 可用

### 1.2 命名规范

| 类型 | 规范 | 示例 |
|------|------|------|
| Protocol | 名词/形容词 + Protocol/able | `DecisionEngine`, `Detectable` |
| Class | 名词 | `RiskDecisionEngine` |
| Struct | 名词 | `RiskSignal` |
| Enum | 名词 | `RiskScenario` |
| Function | 动词开头 | `evaluate()`, `detect()` |
| Property | 名词 | `score`, `isHighRisk` |

---

## 二、核心接口定义

### 2.1 RiskDecisionEngine (智能决策引擎)

```swift
/// 决策引擎协议
public protocol DecisionEngine: Sendable {
    
    /// 基于信号快照进行决策
    /// - Parameters:
    ///   - snapshot: 风险信号快照
    ///   - config: 决策配置
    /// - Returns: 决策结果
    func decide(
        snapshot: RiskSnapshot,
        config: DecisionConfig
    ) async -> RiskVerdict
    
    /// 获取引擎支持的特征
    var supportedFeatures: [String] { get }
    
    /// 重置引擎状态
    func reset() async
}

/// 智能决策引擎
public final class RiskDecisionEngine: DecisionEngine {
    
    // MARK: - Properties
    
    /// 配置管理器
    private let configManager: ConfigManaging
    
    /// 模型集合
    private var models: [DecisionModel]
    
    /// 支持的特征
    public let supportedFeatures: [String]
    
    // MARK: - Initialization
    
    public init(
        configManager: ConfigManaging,
        models: [DecisionModel] = []
    ) {
        self.configManager = configManager
        self.models = models.isEmpty ? Self.defaultModels() : models
        self.supportedFeatures = Self.extractFeatures(from: self.models)
    }
    
    // MARK: - DecisionEngine
    
    public func decide(
        snapshot: RiskSnapshot,
        config: DecisionConfig
    ) async -> RiskVerdict {
        
        // 1. 特征提取
        let features = await extractFeatures(from: snapshot)
        
        // 2. 获取场景策略
        let policy = await configManager.getPolicy(for: config.scenario)
        
        // 3. 多模型评估
        let modelScores = await evaluateModels(
            features: features,
            models: models,
            policy: policy
        )
        
        // 4. 集成决策
        let verdict = await ensembleDecision(
            modelScores: modelScores,
            policy: policy
        )
        
        // 5. 应用规则覆盖
        let finalVerdict = applyRuleOverrides(
            verdict: verdict,
            snapshot: snapshot,
            policy: policy
        )
        
        return finalVerdict
    }
    
    public func reset() async {
        for model in models {
            await model.reset()
        }
    }
    
    // MARK: - Private Methods
    
    private func extractFeatures(from snapshot: RiskSnapshot) async -> FeatureVector {
        // TODO: 实现特征提取逻辑
        return FeatureVector()
    }
    
    private func evaluateModels(
        features: FeatureVector,
        models: [DecisionModel],
        policy: PolicyConfig
    ) async -> [String: Double] {
        // TODO: 实现多模型评估
        return [:]
    }
    
    private func ensembleDecision(
        modelScores: [String: Double],
        policy: PolicyConfig
    ) async -> RiskVerdict {
        // TODO: 实现集成决策逻辑
        return RiskVerdict(
            score: 0,
            level: .low,
            confidence: 0,
            reason: "",
            signals: []
        )
    }
    
    private func applyRuleOverrides(
        verdict: RiskVerdict,
        snapshot: RiskSnapshot,
        policy: PolicyConfig
    ) -> RiskVerdict {
        // TODO: 实现规则覆盖逻辑
        return verdict
    }
    
    // MARK: - Factory Methods
    
    private static func defaultModels() -> [DecisionModel] {
        [
            RuleBasedModel(),
            ScoringModel(),
            // 未来可添加 ML 模型
        ]
    }
    
    private static func extractFeatures(from models: [DecisionModel]) -> [String] {
        models.flatMap { $0.supportedFeatures }
    }
}

// MARK: - Supporting Types

/// 决策配置
public struct DecisionConfig: Sendable {
    
    /// 决策场景
    public var scenario: RiskScenario
    
    /// 是否使用远程配置
    public var useRemoteConfig: Bool
    
    /// 自定义阈值（覆盖远程配置）
    public var customThreshold: Double?
    
    /// 启用的检测器
    public var enabledDetectors: Set<String>
    
    public init(
        scenario: RiskScenario = .default,
        useRemoteConfig: Bool = true,
        customThreshold: Double? = nil,
        enabledDetectors: Set<String> = []
    ) {
        self.scenario = scenario
        self.useRemoteConfig = useRemoteConfig
        self.customThreshold = customThreshold
        self.enabledDetectors = enabledDetectors.isEmpty ? Self.allDetectors : enabledDetectors
    }
    
    private static let allDetectors: Set<String> = [
        "jailbreak",
        "anti_tamper",
        "behavior",
        "network",
        "device",
        "environment"
    ]
}

/// 决策模型协议
public protocol DecisionModel: Sendable {
    var id: String { get }
    var supportedFeatures: [String] { get }
    func evaluate(features: FeatureVector, policy: PolicyConfig) async -> ModelResult
    func reset() async
}

/// 模型评估结果
public struct ModelResult: Sendable {
    public var score: Double
    public var confidence: Double
    public var explanation: [String: Any]
}

/// 特征向量
public struct FeatureVector: Sendable {
    public var values: [String: Double]
    public var metadata: [String: String]
    
    public init(values: [String: Double] = [:], metadata: [String: String] = [:]) {
        self.values = values
        self.metadata = metadata
    }
}
```

### 2.2 RemoteConfigProvider (远程配置提供者)

```swift
/// 远程配置提供者协议
public protocol RemoteConfigProvider: Sendable {
    
    /// 获取远程配置
    /// - Parameter completion: 完成回调
    func fetchConfig(completion: @escaping (Result<RemoteConfig, ConfigError>) -> Void)
    
    /// 使用 async/await 的配置获取
    func fetchConfig() async throws -> RemoteConfig
    
    /// 获取缓存的配置
    func getCachedConfig() -> RemoteConfig?
    
    /// 清除缓存
    func clearCache()
    
    /// 配置更新监听
    func addConfigUpdateListener(_ listener: @escaping (RemoteConfig) -> Void)
}

/// 远程配置提供者实现
public final class DefaultRemoteConfigProvider: RemoteConfigProvider {
    
    // MARK: - Properties
    
    /// API 端点
    private let endpoint: URL
    
    /// 会话配置
    private let session: URLSession
    
    /// 配置缓存
    private var cachedConfig: RemoteConfig?
    
    /// 更新监听器
    private var listeners: [(RemoteConfig) -> Void]
    
    /// 队列
    private let queue: DispatchQueue
    
    // MARK: - Initialization
    
    public init(
        endpoint: URL,
        session: URLSession = .shared
    ) {
        self.endpoint = endpoint
        self.session = session
        self.listeners = []
        self.queue = DispatchQueue(label: "com.cloudphone.risk.config")
    }
    
    // MARK: - RemoteConfigProvider
    
    public func fetchConfig(completion: @escaping (Result<RemoteConfig, ConfigError>) -> Void) {
        Task {
            do {
                let config = try await fetchConfig()
                completion(.success(config))
            } catch {
                completion(.failure(error as? ConfigError ?? .networkError(error)))
            }
        }
    }
    
    public func fetchConfig() async throws -> RemoteConfig {
        var request = URLRequest(url: endpoint)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(getSDKVersion(), forHTTPHeaderField: "X-SDK-Version")
        request.setValue(getDeviceID(), forHTTPHeaderField: "X-Device-ID")
        
        let (data, response) = try await session.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw ConfigError.invalidResponse
        }
        
        guard httpResponse.statusCode == 200 else {
            throw ConfigError.httpError(httpResponse.statusCode)
        }
        
        let config = try JSONDecoder().decode(RemoteConfig.self, from: data)
        
        // 验证签名
        try validateSignature(config)
        
        // 缓存配置
        await cacheConfig(config)
        
        // 通知监听器
        notifyListeners(config)
        
        return config
    }
    
    public func getCachedConfig() -> RemoteConfig? {
        return cachedConfig
    }
    
    public func clearCache() {
        queue.sync {
            cachedConfig = nil
        }
    }
    
    public func addConfigUpdateListener(_ listener: @escaping (RemoteConfig) -> Void) {
        queue.sync {
            listeners.append(listener)
        }
    }
    
    // MARK: - Private Methods
    
    private func validateSignature(_ config: RemoteConfig) throws {
        // TODO: 实现签名验证逻辑
    }
    
    private func cacheConfig(_ config: RemoteConfig) async {
        queue.sync {
            cachedConfig = config
        }
    }
    
    private func notifyListeners(_ config: RemoteConfig) {
        queue.sync {
            listeners.forEach { $0(config) }
        }
    }
    
    private func getSDKVersion() -> String {
        return CloudPhoneRiskKit.version
    }
    
    private func getDeviceID() -> String {
        return KeychainDeviceID.shared.getOrCreate()
    }
}

// MARK: - RemoteConfig Model

/// 远程配置
public struct RemoteConfig: Codable, Sendable {
    
    /// 配置版本
    public var version: String
    
    /// 配置生效时间
    public var effectiveTime: Date
    
    /// 配置过期时间
    public var expireTime: Date
    
    /// 检测器配置
    public var detectors: DetectorConfigs
    
    /// 策略配置
    public var policies: PolicyConfigs
    
    /// 场景配置
    public var scenarios: ScenarioConfigs
    
    /// 签名
    public var signature: String
    
    public init(
        version: String,
        effectiveTime: Date,
        expireTime: Date,
        detectors: DetectorConfigs,
        policies: PolicyConfigs,
        scenarios: ScenarioConfigs,
        signature: String
    ) {
        self.version = version
        self.effectiveTime = effectiveTime
        self.expireTime = expireTime
        self.detectors = detectors
        self.policies = policies
        self.scenarios = scenarios
        self.signature = signature
    }
}

/// 检测器配置集合
public struct DetectorConfigs: Codable, Sendable {
    public var jailbreak: JailbreakDetectorConfig
    public var antiTamper: AntiTamperDetectorConfig
    public var behavior: BehaviorDetectorConfig
    public var network: NetworkDetectorConfig
    
    public init(
        jailbreak: JailbreakDetectorConfig,
        antiTamper: AntiTamperDetectorConfig,
        behavior: BehaviorDetectorConfig,
        network: NetworkDetectorConfig
    ) {
        self.jailbreak = jailbreak
        self.antiTamper = antiTamper
        self.behavior = behavior
        self.network = network
    }
}

/// 策略配置集合
public struct PolicyConfigs: Codable, Sendable {
    public var thresholds: ThresholdConfig
    public var weights: WeightConfig
    public var rules: [RuleConfig]
    
    public init(
        thresholds: ThresholdConfig,
        weights: WeightConfig,
        rules: [RuleConfig]
    ) {
        self.thresholds = thresholds
        self.weights = weights
        self.rules = rules
    }
}

/// 阈值配置
public struct ThresholdConfig: Codable, Sendable {
    public var lowRisk: Double
    public var mediumRisk: Double
    public var highRisk: Double
    
    public init(lowRisk: Double, mediumRisk: Double, highRisk: Double) {
        self.lowRisk = lowRisk
        self.mediumRisk = mediumRisk
        self.highRisk = highRisk
    }
}

/// 权重配置
public struct WeightConfig: Codable, Sendable {
    public var jailbreak: Double
    public var antiTamper: Double
    public var behavior: Double
    public var network: Double
    public var device: Double
    
    public init(
        jailbreak: Double,
        antiTamper: Double,
        behavior: Double,
        network: Double,
        device: Double
    ) {
        self.jailbreak = jailbreak
        self.antiTamper = antiTamper
        self.behavior = behavior
        self.network = network
        self.device = device
    }
}

/// 规则配置
public struct RuleConfig: Codable, Sendable {
    public var id: String
    public var name: String
    public var condition: RuleCondition
    public var action: RuleAction
    
    public init(id: String, name: String, condition: RuleCondition, action: RuleAction) {
        self.id = id
        self.name = name
        self.condition = condition
        self.action = action
    }
}

/// 规则条件
public enum RuleCondition: Codable, Sendable {
    case always
    case never
    case signalEquals(signal: String, value: String)
    case signalGreaterThan(signal: String, value: Double)
    case signalLessThan(signal: String, value: Double)
    case and([RuleCondition])
    case or([RuleCondition])
    case not(RuleCondition)
}

/// 规则动作
public enum RuleAction: Codable, Sendable {
    case setScore(score: Double)
    case setRiskLevel(level: RiskLevel)
    case block
    case allow
}

/// 场景配置集合
public struct ScenarioConfigs: Codable, Sendable {
    public var login: ScenarioConfig
    public var payment: ScenarioConfig
    public var register: ScenarioConfig
    public var query: ScenarioConfig
    public var `default`: ScenarioConfig
    
    public init(
        login: ScenarioConfig,
        payment: ScenarioConfig,
        register: ScenarioConfig,
        query: ScenarioConfig,
        default: ScenarioConfig
    ) {
        self.login = login
        self.payment = payment
        self.register = register
        self.query = query
        self.`default` = `default`
    }
}

/// 单个场���配置
public struct ScenarioConfig: Codable, Sendable {
    public var enabled: Bool
    public var threshold: Double
    public var enabledDetectors: [String]
    public var customWeights: WeightConfig?
    
    public init(
        enabled: Bool,
        threshold: Double,
        enabledDetectors: [String],
        customWeights: WeightConfig? = nil
    ) {
        self.enabled = enabled
        self.threshold = threshold
        self.enabledDetectors = enabledDetectors
        self.customWeights = customWeights
    }
}

// MARK: - Config Errors

public enum ConfigError: Error, Sendable {
    case networkError(Error)
    case invalidResponse
    case httpError(Int)
    case invalidSignature
    case expiredConfig
    case decodeError(Error)
}
```

### 2.3 TemporalAnalyzer (时序分析引擎)

```swift
/// 时序分析引擎
public protocol TemporalAnalyzer: Sendable {
    
    /// 分析时间模式
    /// - Parameters:
    ///   - history: 历史事件
    ///   - window: 分析窗口
    /// - Returns: 分析结果
    func analyze(
        history: [RiskHistoryEvent],
        window: TimeWindow
    ) async -> TemporalAnalysisResult
    
    /// 检测异常模式
    /// - Parameters:
    ///   - history: 历史事件
    ///   - current: 当前事件
    /// - Returns: 异常检测结果
    func detectAnomaly(
        history: [RiskHistoryEvent],
        current: RiskHistoryEvent
    ) async -> AnomalyDetectionResult
}

/// 默认时序分析引擎实现
public final class DefaultTemporalAnalyzer: TemporalAnalyzer {
    
    // MARK: - Properties
    
    private let historyStore: RiskHistoryStore
    private let config: TemporalAnalysisConfig
    
    // MARK: - Initialization
    
    public init(
        historyStore: RiskHistoryStore = .shared,
        config: TemporalAnalysisConfig = .default
    ) {
        self.historyStore = historyStore
        self.config = config
    }
    
    // MARK: - TemporalAnalyzer
    
    public func analyze(
        history: [RiskHistoryEvent],
        window: TimeWindow
    ) async -> TemporalAnalysisResult {
        
        let filtered = filterEvents(history, window: window)
        
        return TemporalAnalysisResult(
            window: window,
            eventCount: filtered.count,
            timeDistribution: analyzeTimeDistribution(filtered),
            frequencyMetrics: analyzeFrequency(filtered),
            sequencePatterns: analyzeSequences(filtered),
            anomalyScore: calculateAnomalyScore(filtered),
            riskSignals: extractRiskSignals(filtered)
        )
    }
    
    public func detectAnomaly(
        history: [RiskHistoryEvent],
        current: RiskHistoryEvent
    ) async -> AnomalyDetectionResult {
        
        let baseline = await calculateBaseline(history)
        let currentScore = calculateAnomalyScore([current])
        let deviation = abs(currentScore - baseline)
        
        let isAnomalous = deviation > config.anomalyThreshold
        
        return AnomalyDetectionResult(
            isAnomalous: isAnomalous,
            deviation: deviation,
            confidence: calculateConfidence(deviation),
            reasons: identifyAnomalyReasons(current, baseline: baseline)
        )
    }
    
    // MARK: - Private Methods
    
    private func filterEvents(_ events: [RiskHistoryEvent], window: TimeWindow) -> [RiskHistoryEvent] {
        let now = Date().timeIntervalSince1970
        let startTime = now - window.duration
        return events.filter { $0.t >= startTime && $0.t <= now }
    }
    
    private func analyzeTimeDistribution(_ events: [RiskHistoryEvent]) -> TimeDistribution {
        let calendar = Calendar.current
        var hourlyCount = [Int: Int]()
        var weekdayCount = [Int: Int]()
        
        for event in events {
            let date = Date(timeIntervalSince1970: event.t)
            let hour = calendar.component(.hour, from: date)
            let weekday = calendar.component(.weekday, from: date)
            
            hourlyCount[hour, default: 0] += 1
            weekdayCount[weekday, default: 0] += 1
        }
        
        return TimeDistribution(
            hourlyCount: hourlyCount,
            weekdayCount: weekdayCount
        )
    }
    
    private func analyzeFrequency(_ events: [RiskHistoryEvent]) -> FrequencyMetrics {
        guard events.count > 1 else {
            return FrequencyMetrics(
                averageInterval: nil,
                minInterval: nil,
                maxInterval: nil,
                intervalVariance: nil
            )
        }
        
        let sorted = events.sorted { $0.t < $1.t }
        var intervals: [Double] = []
        
        for i in 1..<sorted.count {
            intervals.append(sorted[i].t - sorted[i-1].t)
        }
        
        let avg = intervals.reduce(0, +) / Double(intervals.count)
        let min = intervals.min()
        let max = intervals.max()
        
        let variance = intervals.map { pow($0 - avg, 2) }.reduce(0, +) / Double(intervals.count)
        
        return FrequencyMetrics(
            averageInterval: avg,
            minInterval: min,
            maxInterval: max,
            intervalVariance: variance
        )
    }
    
    private func analyzeSequences(_ events: [RiskHistoryEvent]) -> [SequencePattern] {
        // TODO: 实现序列模式分析
        return []
    }
    
    private func calculateAnomalyScore(_ events: [RiskHistoryEvent]) -> Double {
        // TODO: 实现异常评分逻辑
        return 0
    }
    
    private func calculateBaseline(_ history: [RiskHistoryEvent]) async -> Double {
        let recent = Array(history.suffix(100))
        return calculateAnomalyScore(recent)
    }
    
    private func calculateConfidence(_ deviation: Double) -> Double {
        min(deviation / config.anomalyThreshold, 1.0)
    }
    
    private func identifyAnomalyReasons(
        _ current: RiskHistoryEvent,
        baseline: Double
    ) -> [String] {
        var reasons: [String] = []
        
        if current.score > baseline * 1.5 {
            reasons.append("unusually_high_score")
        }
        
        // TODO: 添加更多异常原因识别
        
        return reasons
    }
    
    private func extractRiskSignals(_ events: [RiskHistoryEvent]) -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        // 夜间活跃信号
        let nightEvents = events.filter {
            let hour = Calendar.current.component(.hour, from: Date(timeIntervalSince1970: $0.t))
            return hour >= 0 && hour <= 5
        }
        if nightEvents.count > 10 {
            signals.append(RiskSignal(
                id: "night_activity_high",
                category: "temporal",
                score: Double(nightEvents.count),
                evidence: ["count": "\(nightEvents.count)"]
            ))
        }
        
        return signals
    }
}

// MARK: - Supporting Types

/// 时间窗口
public struct TimeWindow: Sendable {
    public var duration: TimeInterval
    public var startTime: TimeInterval?
    public var endTime: TimeInterval?
    
    public init(duration: TimeInterval, startTime: TimeInterval? = nil, endTime: TimeInterval? = nil) {
        self.duration = duration
        self.startTime = startTime
        self.endTime = endTime
    }
    
    public static let last1Hour = TimeWindow(duration: 3600)
    public static let last24Hours = TimeWindow(duration: 86400)
    public static let last7Days = TimeWindow(duration: 604800)
}

/// 时序分析结果
public struct TemporalAnalysisResult: Sendable {
    public var window: TimeWindow
    public var eventCount: Int
    public var timeDistribution: TimeDistribution
    public var frequencyMetrics: FrequencyMetrics
    public var sequencePatterns: [SequencePattern]
    public var anomalyScore: Double
    public var riskSignals: [RiskSignal]
}

/// 时间分布
public struct TimeDistribution: Sendable {
    public var hourlyCount: [Int: Int]
    public var weekdayCount: [Int: Int]
}

/// 频率指标
public struct FrequencyMetrics: Sendable {
    public var averageInterval: Double?
    public var minInterval: Double?
    public var maxInterval: Double?
    public var intervalVariance: Double?
}

/// 序列模式
public struct SequencePattern: Sendable {
    public var pattern: [String]
    public var frequency: Int
    public var confidence: Double
}

/// 异常检测结果
public struct AnomalyDetectionResult: Sendable {
    public var isAnomalous: Bool
    public var deviation: Double
    public var confidence: Double
    public var reasons: [String]
}

/// 时序分析配置
public struct TemporalAnalysisConfig: Sendable {
    public var anomalyThreshold: Double
    public var minEventsForAnalysis: Int
    
    public init(anomalyThreshold: Double, minEventsForAnalysis: Int) {
        self.anomalyThreshold = anomalyThreshold
        self.minEventsForAnalysis = minEventsForAnalysis
    }
    
    public static let `default` = TemporalAnalysisConfig(
        anomalyThreshold: 2.0,
        minEventsForAnalysis: 10
    )
}
```

### 2.4 ScenarioBasedPolicy (场景化策略)

```swift
/// 风险场景枚举
@objc public enum RiskScenario: Int, Sendable, Codable {
    case login = 0
    case payment = 1
    case register = 2
    case query = 3
    case `default` = 4
    
    public var displayName: String {
        switch self {
        case .login: return "登录"
        case .payment: return "支付"
        case .register: return "注册"
        case .query: return "查询"
        case .default: return "默认"
        }
    }
}

/// 场景化策略管理器
public protocol ScenarioBasedPolicy: Sendable {
    
    /// 获取场景配置
    /// - Parameter scenario: 风险场景
    /// - Returns: 场景策略配置
    func getPolicy(for scenario: RiskScenario) async -> PolicyConfig
    
    /// 应用场景策略
    /// - Parameters:
    ///   - verdict: 原始裁决
    ///   - scenario: 风险场景
    /// - Returns: 应用策略后的裁决
    func applyPolicy(
        verdict: RiskVerdict,
        scenario: RiskScenario
    ) async -> RiskVerdict
    
    /// 更新场景策略
    /// - Parameters:
    ///   - scenario: 风险场景
    ///   - policy: 新策略配置
    func updatePolicy(for scenario: RiskScenario, policy: PolicyConfig) async
}

/// 默认场景化策略实现
public final class DefaultScenarioBasedPolicy: ScenarioBasedPolicy {
    
    // MARK: - Properties
    
    private var policies: [RiskScenario: PolicyConfig]
    private let configManager: ConfigManaging
    private let queue: DispatchQueue
    
    // MARK: - Initialization
    
    public init(
        configManager: ConfigManaging,
        policies: [RiskScenario: PolicyConfig] = [:]
    ) {
        self.configManager = configManager
        self.policies = policies.isEmpty ? Self.defaultPolicies() : policies
        self.queue = DispatchQueue(label: "com.cloudphone.risk.policy")
    }
    
    // MARK: - ScenarioBasedPolicy
    
    public func getPolicy(for scenario: RiskScenario) async -> PolicyConfig {
        // 优先使用远程配置
        if let remotePolicy = await configManager.getPolicy(for: scenario) {
            return remotePolicy
        }
        
        // 使用本地配置
        return queue.sync {
            policies[scenario] ?? policies[.default]!
        }
    }
    
    public func applyPolicy(
        verdict: RiskVerdict,
        scenario: RiskScenario
    ) async -> RiskVerdict {
        
        let policy = await getPolicy(for: scenario)
        
        // 应用场景特定的阈值调整
        var adjustedVerdict = verdict
        if verdict.score >= policy.threshold {
            adjustedVerdict = RiskVerdict(
                score: verdict.score,
                level: adjustLevel(verdict.level, with: policy),
                confidence: verdict.confidence,
                reason: verdict.reason,
                signals: verdict.signals,
                scenario: scenario,
                action: determineAction(for: adjustedVerdict, policy: policy)
            )
        }
        
        return adjustedVerdict
    }
    
    public func updatePolicy(for scenario: RiskScenario, policy: PolicyConfig) async {
        queue.sync {
            policies[scenario] = policy
        }
    }
    
    // MARK: - Private Methods
    
    private func adjustLevel(_ level: RiskLevel, with policy: PolicyConfig) -> RiskLevel {
        // TODO: 实现级别调整逻辑
        return level
    }
    
    private func determineAction(for verdict: RiskVerdict, policy: PolicyConfig) -> RiskAction {
        switch verdict.level {
        case .low:
            return .allow
        case .medium:
            return policy.mediumRiskAction
        case .high:
            return policy.highRiskAction
        }
    }
    
    private static func defaultPolicies() -> [RiskScenario: PolicyConfig] {
        [
            .login: PolicyConfig(
                threshold: 60,
                mediumRiskAction: .challenge,
                highRiskAction: .block
            ),
            .payment: PolicyConfig(
                threshold: 50,
                mediumRiskAction: .challenge,
                highRiskAction: .block
            ),
            .register: PolicyConfig(
                threshold: 70,
                mediumRiskAction: .allow,
                highRiskAction: .challenge
            ),
            .query: PolicyConfig(
                threshold: 80,
                mediumRiskAction: .allow,
                highRiskAction: .allow
            ),
            .default: PolicyConfig(
                threshold: 60,
                mediumRiskAction: .allow,
                highRiskAction: .block
            )
        ]
    }
}

// MARK: - Supporting Types

/// 策略配置
public struct PolicyConfig: Codable, Sendable {
    public var threshold: Double
    public var mediumRiskAction: RiskAction
    public var highRiskAction: RiskAction
    public var enabledDetectors: Set<String>
    public var customWeights: [String: Double]?
    
    public init(
        threshold: Double,
        mediumRiskAction: RiskAction,
        highRiskAction: RiskAction,
        enabledDetectors: Set<String> = [],
        customWeights: [String: Double]? = nil
    ) {
        self.threshold = threshold
        self.mediumRiskAction = mediumRiskAction
        self.highRiskAction = highRiskAction
        self.enabledDetectors = enabledDetectors.isEmpty ? Self.defaultDetectors : enabledDetectors
        self.customWeights = customWeights
    }
    
    private static let defaultDetectors: Set<String> = [
        "jailbreak", "anti_tamper", "behavior", "network", "device"
    ]
}

/// 风险级别
@objc public enum RiskLevel: Int, Sendable, Codable {
    case low = 0
    case medium = 1
    case high = 2
    
    public var displayName: String {
        switch self {
        case .low: return "低风险"
        case .medium: return "中风险"
        case .high: return "高风险"
        }
    }
}

/// 风险动作
@objc public enum RiskAction: Int, Sendable, Codable {
    case allow = 0
    case challenge = 1
    case block = 2
    
    public var displayName: String {
        switch self {
        case .allow: return "允许"
        case .challenge: return "挑战"
        case .block: return "拒绝"
        }
    }
}

/// 风险裁决结果
public struct RiskVerdict: Sendable, Codable {
    public var score: Double
    public var level: RiskLevel
    public var confidence: Double
    public var reason: String
    public var signals: [RiskSignal]
    public var scenario: RiskScenario
    public var action: RiskAction
    
    public init(
        score: Double,
        level: RiskLevel,
        confidence: Double,
        reason: String,
        signals: [RiskSignal],
        scenario: RiskScenario = .default,
        action: RiskAction = .allow
    ) {
        self.score = score
        self.level = level
        self.confidence = confidence
        self.reason = reason
        self.signals = signals
        self.scenario = scenario
        self.action = action
    }
}
```

---

## 三、公开 API 设计

### 3.1 主入口 API (保持向后兼容)

```swift
/// CloudPhoneRiskKit 主入口
@objc(CPRiskKit)
public final class CPRiskKit: NSObject {
    
    /// 单例
    @objc public static let shared = CPRiskKit()
    
    // MARK: - Lifecycle
    
    /// 启动 SDK
    @objc public func start()
    
    /// 停止 SDK
    @objc public func stop()
    
    // MARK: - Configuration
    
    /// 设置日志开关
    @objc public static func setLogEnabled(_ enabled: Bool)
    
    /// 设置外部服务端信号
    @objc public static func setExternalServerSignals(
        publicIP: String?,
        asn: String?,
        asOrg: String?,
        isDatacenter: NSNumber?,
        ipDeviceAgg: NSNumber?,
        ipAccountAgg: NSNumber?,
        geoCountry: String?,
        geoRegion: String?,
        riskTags: [String]?
    )
    
    /// 清除外部服务端信号
    @objc public static func clearExternalServerSignals()
    
    /// 注册自定义信号提供者
    public static func register(provider: RiskSignalProvider)
    
    /// 注销信号提供者
    public static func unregisterProvider(id: String)
    
    /// 获取已注册的提供者 ID 列表
    public static func registeredProviderIDs() -> [String]
    
    // MARK: - Evaluation
    
    /// 同步评估风险（使用默认配置）
    @objc public func evaluate() -> CPRiskReport
    
    /// 同步评估风险（使用指定配置）
    @objc(evaluateWithConfig:)
    public func evaluate(config: CPRiskConfig) -> CPRiskReport
    
    /// 异步评估风险（使用默认配置）
    @objc(evaluateAsyncWithCompletion:)
    public func evaluateAsync(completion: @escaping (CPRiskReport) -> Void)
    
    /// 异步评估风险（使用指定配置）
    @objc(evaluateAsyncWithConfig:completion:)
    public func evaluateAsync(
        config: CPRiskConfig,
        completion: @escaping (CPRiskReport) -> Void
    )
    
    // MARK: - 2.0 新增 API
    
    /// 使用场景评估风险
    @objc(evaluateWithScenario:completion:)
    public func evaluate(
        scenario: RiskScenario,
        completion: @escaping (CPRiskReport) -> Void
    )
    
    /// 更新远程配置
    @objc(updateRemoteConfigWithCompletion:)
    public func updateRemoteConfig(completion: @escaping (Bool) -> Void)
}
```

### 3.2 async/await 版本 API

```swift
extension CPRiskKit {
    
    /// 使用 async/await 评估风险
    @available(iOS 13.0, *)
    public func evaluateAsync() async -> CPRiskReport {
        await withCheckedContinuation { continuation in
            evaluateAsync { report in
                continuation.resume(returning: report)
            }
        }
    }
    
    /// 使用 async/await 和指定配置评估风险
    @available(iOS 13.0, *)
    public func evaluateAsync(config: CPRiskConfig) async -> CPRiskReport {
        await withCheckedContinuation { continuation in
            evaluateAsync(config: config) { report in
                continuation.resume(returning: report)
            }
        }
    }
    
    /// 使用 async/await 和场景评估风险
    @available(iOS 13.0, *)
    public func evaluateAsync(
        config: CPRiskConfig = .default,
        scenario: RiskScenario = .default
    ) async -> CPRiskReport {
        await withCheckedContinuation { continuation in
            evaluateAsync { report in
                continuation.resume(returning: report)
            }
        }
    }
    
    /// 使用 async/await 更新远程配置
    @available(iOS 13.0, *)
    public func updateRemoteConfigAsync() async throws {
        try await withCheckedThrowingContinuation { continuation in
            updateRemoteConfig { success in
                if success {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: ConfigError.networkError(NSError()))
                }
            }
        }
    }
}
```

### 3.3 配置 API

```swift
/// 风险配置类 (Objective-C 兼容)
@objc(CPRiskConfig)
public final class CPRiskConfig: NSObject {
    
    /// 是否启用行为检测
    @objc public var enableBehaviorDetect: Bool = true
    
    /// 是否启用网络信号
    @objc public var enableNetworkSignals: Bool = true
    
    /// 风险阈值
    @objc public var threshold: Double = 60
    
    /// 越狱检测配置
    @objc public var jailbreakConfig: CPJailbreakConfig
    
    /// 默认配置
    @objc public static let `default` = CPRiskConfig()
    
    /// 轻量级配置
    @objc public static let light = CPRiskConfig(threshold: 70)
    
    /// 完整配置
    @objc public static let full = CPRiskConfig(threshold: 55)
    
    // MARK: - 2.0 新增属性
    
    /// 是否启用远程配置
    @objc public var enableRemoteConfig: Bool = true
    
    /// 默认场景
    @objc public var defaultScenario: RiskScenario = .default
    
    /// 是否启用时序分析
    @objc public var enableTemporalAnalysis: Bool = true
    
    /// 是否启用反篡改检测
    @objc public var enableAntiTamper: Bool = true
}
```

---

## 四、数据模型定义

### 4.1 核心数据模型

```swift
/// 风险信号
public struct RiskSignal: Sendable, Codable {
    public var id: String
    public var category: String
    public var score: Double
    public var evidence: [String: String]
    public var timestamp: Date
    
    public init(
        id: String,
        category: String,
        score: Double,
        evidence: [String: String] = [:],
        timestamp: Date = Date()
    ) {
        self.id = id
        self.category = category
        self.score = score
        self.evidence = evidence
        self.timestamp = timestamp
    }
}

/// 风险快照
public struct RiskSnapshot: Sendable, Codable {
    public var deviceID: String
    public var device: DeviceFingerprint
    public var network: NetworkSignals
    public var behavior: BehaviorSignals
    public var jailbreak: DetectionResult
    public var antiTamper: AntiTamperResult?
    public var timestamp: Date
    
    public init(
        deviceID: String,
        device: DeviceFingerprint,
        network: NetworkSignals,
        behavior: BehaviorSignals,
        jailbreak: DetectionResult,
        antiTamper: AntiTamperResult? = nil,
        timestamp: Date = Date()
    ) {
        self.deviceID = deviceID
        self.device = device
        self.network = network
        self.behavior = behavior
        self.jailbreak = jailbreak
        self.antiTamper = antiTamper
        self.timestamp = timestamp
    }
}

/// 历史事件
public struct RiskHistoryEvent: Sendable, Codable {
    public var timestamp: TimeInterval
    public var score: Double
    public var isHighRisk: Bool
    public var summary: String
    public var scenario: RiskScenario?
    public var action: RiskAction?
    
    public init(
        timestamp: TimeInterval,
        score: Double,
        isHighRisk: Bool,
        summary: String,
        scenario: RiskScenario? = nil,
        action: RiskAction? = nil
    ) {
        self.timestamp = timestamp
        self.score = score
        self.isHighRisk = isHighRisk
        self.summary = summary
        self.scenario = scenario
        self.action = action
    }
}
```

### 4.2 检测结果模型

```swift
/// 检测结果基类
public struct DetectionResult: Sendable, Codable {
    public var isDetected: Bool
    public var confidence: Double
    public var detectedMethods: [String]
    public var details: String
    public var timestamp: Date
    
    public init(
        isDetected: Bool,
        confidence: Double,
        detectedMethods: [String] = [],
        details: String = "",
        timestamp: Date = Date()
    ) {
        self.isDetected = isDetected
        self.confidence = confidence
        self.detectedMethods = detectedMethods
        self.details = details
        self.timestamp = timestamp
    }
}

/// 越狱检测结果（向后兼容别名）
public typealias JailbreakDetectionResult = DetectionResult

/// 反篡改检测结果
public struct AntiTamperResult: Sendable, Codable {
    public var isTampered: Bool
    public var confidence: Double
    public var detectedThreats: [ThreatType]
    public var details: String
    
    public init(
        isTampered: Bool,
        confidence: Double,
        detectedThreats: [ThreatType] = [],
        details: String = ""
    ) {
        self.isTampered = isTampered
        self.confidence = confidence
        self.detectedThreats = detectedThreats
        self.details = details
    }
}

/// 威胁类型
public enum ThreatType: String, Sendable, Codable {
    case codeIntegrity = "code_integrity"
    case dylibInjection = "dylib_injection"
    case debuggerAttached = "debugger_attached"
    case fridaDetected = "frida_detected"
    case emulatorDetected = "emulator_detected"
    case hookDetected = "hook_detected"
}
```

---

## 五、错误处理

### 5.1 错误类型定义

```swift
/// SDK 错误类型
@objc public enum CPRiskError: Int, Error, Sendable {
    case unknown = 0
    case notInitialized = 1
    case invalidConfiguration = 2
    case detectionFailed = 3
    case networkError = 4
    case configFetchFailed = 5
    case storageError = 6
    
    public var localizedDescription: String {
        switch self {
        case .unknown:
            return "未知错误"
        case .notInitialized:
            return "SDK 未初始化"
        case .invalidConfiguration:
            return "配置无效"
        case .detectionFailed:
            return "检测失败"
        case .networkError:
            return "网络错误"
        case .configFetchFailed:
            return "配置获取失败"
        case .storageError:
            return "存储错误"
        }
    }
}
```

### 5.2 结果类型

```swift
/// 检测结果类型
public enum DetectionResult<T: Sendable>: Sendable {
    case success(T)
    case failure(CPRiskError)
    
    public var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }
    
    public var isFailure: Bool {
        return !isSuccess
    }
}
```

---

## 六、扩展协议

### 6.1 自定义检测器协议

```swift
/// 自定义检测器协议
public protocol CustomDetector: Sendable {
    
    /// 检测器唯一标识
    var id: String { get }
    
    /// 检测器名称
    var name: String { get }
    
    /// 执行检测
    func detect() async -> DetectionResult
    
    /// 是否启用
    var isEnabled: Bool { get set }
}
```

### 6.2 自定义决策模型协议

```swift
/// 自定义决策模型协议
public protocol CustomDecisionModel: Sendable {
    
    /// 模型唯一标识
    var id: String { get }
    
    /// 模型版本
    var version: String { get }
    
    /// 评估
    func evaluate(features: FeatureVector) async -> ModelResult
    
    /// 重置模型状态
    func reset() async
}
```

---

## 七、使用示例

### 7.1 基础使用

```swift
// 启动 SDK
CPRiskKit.shared.start()

// 设置日志
CPRiskKit.setLogEnabled(true)

// 同步评估
let report = CPRiskKit.shared.evaluate()
print("风险评分: \(report.score)")

// 异步评估
CPRiskKit.shared.evaluateAsync { report in
    print("风险评分: \(report.score), 是否高风险: \(report.isHighRisk)")
}
```

### 7.2 使用场景策略

```swift
// 登录场景评估
CPRiskKit.shared.evaluate(scenario: .login) { report in
    switch report.verdict.level {
    case .low:
        // 直接登录
        completeLogin()
    case .medium:
        // 需要额外验证
        showChallenge()
    case .high:
        // 拒绝登录
        denyLogin()
    }
}
```

### 7.3 使用 async/await

```swift
// 使用 async/await
Task {
    let report = await CPRiskKit.shared.evaluateAsync(
        scenario: .payment
    )
    handlePayment(report.verdict)
}
```

### 7.4 自定义配置

```swift
let config = CPRiskConfig()
config.threshold = 70
config.enableBehaviorDetect = true
config.enableRemoteConfig = true
config.defaultScenario = .payment

let report = CPRiskKit.shared.evaluate(config: config)
```

---

## 八、API 变更日志

### 2.0.0 新增

| API | 说明 |
|-----|------|
| `evaluate(scenario:completion:)` | 场景化评估 |
| `updateRemoteConfig(completion:)` | 更新远程配置 |
| `RiskScenario` | 场景枚举 |
| `RiskVerdict` | 风险裁决结果 |
| `RiskDecisionEngine` | 决策引擎协议 |
| `RemoteConfigProvider` | 远程配置提供者 |
| `TemporalAnalyzer` | 时序分析引擎 |
| `ScenarioBasedPolicy` | 场景化策略 |

### 1.0 保留 API (向后兼容)

| API | 说明 |
|-----|------|
| `CPRiskKit.shared.start()` | 启动 SDK |
| `CPRiskKit.shared.stop()` | 停止 SDK |
| `CPRiskKit.shared.evaluate()` | 同步评估 |
| `CPRiskKit.shared.evaluateAsync(completion:)` | 异步评估 |
| `CPRiskConfig` | 配置类 |
| `CPRiskReport` | 报告类 |

---

## 附录

### A. 类型映射表

| 1.0 类型 | 2.0 类型 | 说明 |
|---------|---------|------|
| `DetectionResult.isJailbroken` | `DetectionResult.isDetected` | 通用化 |
| - | `RiskVerdict` | 新增 |
| - | `RiskScenario` | 新增 |
| - | `RiskAction` | 新增 |

### B. 配置参数对照

| 1.0 参数 | 2.0 参数 | 说明 |
|---------|---------|------|
| `threshold` | `threshold` | 保持 |
| - | `scenario` | 新增 |
| - | `enableRemoteConfig` | 新增 |
| - | `enableAntiTamper` | 新增 |
| - | `enableTemporalAnalysis` | 新增 |

---

*文档版本：1.0*
*最后更新：2026-02-06*
