import Foundation

// MARK: - Decision Engine Adapter
///
/// 适配器层，将 RiskDetectionEngine 实现适配到 DecisionEngine 协议
/// 由于已统一命名，适配层主要处理协议实现和远程配置

/// 决策引擎适配器
///
/// 实现 DecisionEngine 协议，内部委托给 RiskDetectionEngine
public final class DecisionEngineAdapter: DecisionEngine {

    // MARK: - 属性

    /// 内部委托的决策引擎
    private let engine: RiskDetectionEngine

    /// 配置管理器（用于获取远程配置）
    private let configManager: AdapterConfigManager?

    // MARK: - 初始化

    public init(
        engine: RiskDetectionEngine = RiskDetectionEngine(),
        configManager: AdapterConfigManager? = nil
    ) {
        self.engine = engine
        self.configManager = configManager
    }

    // MARK: - DecisionEngine 协议实现

    /// 基于信号快照进行决策
    public func decide(
        snapshot: RiskSnapshot,
        config: DecisionConfig
    ) async -> ProtocolRiskVerdict {
        // 转换 RiskSnapshot 到 RiskContext
        let context = convertSnapshotToContext(snapshot)

        // 场景已统一，直接使用
        let scenario = config.scenario

        // 应用远程配置（如果启用）
        let policy = await applyRemoteConfigIfNeeded(config)

        // 使用指定策略创建引擎
        let engineWithPolicy = RiskDetectionEngine(
            policy: policy,
            enableLogging: true,
            customProviders: [:]
        )

        // 执行评估
        let internalVerdict = engineWithPolicy.evaluate(
            context: context,
            scenario: scenario,
            extraSignals: []
        )

        // 内部 RiskVerdict 已实现协议兼容的属性
        return internalVerdict
    }

    /// 获取支持的特征列表
    public var supportedFeatures: [String] {
        [
            "jailbreak_score",
            "vpn_active",
            "proxy_enabled",
            "device_age_days",
            "touch_spread",
            "touch_interval_cv",
            "swipe_linearity",
            "motion_stillness",
            "touch_motion_correlation"
        ]
    }

    /// 重置引擎状态
    public func reset() async {
        // 当前实现无状态，但为未来扩展预留
        Logger.log("[DecisionEngineAdapter] Engine reset")
    }

    // MARK: - 私有辅助方法

    /// 应用远程配置
    private func applyRemoteConfigIfNeeded(_ config: DecisionConfig) async -> EnginePolicy {
        guard config.useRemoteConfig,
              let manager = configManager else {
            return engine.policy
        }

        // 尝试从远程获取策略配置
        do {
            let remoteConfig = try await manager.getCurrentConfig()
            // 转换远程配置为 EnginePolicy
            return convertRemoteConfig(remoteConfig)
        } catch {
            Logger.log("[DecisionEngineAdapter] Failed to fetch remote config: \(error)")
            return engine.policy
        }
    }

    /// 转换 RiskSnapshot 到 RiskContext
    private func convertSnapshotToContext(_ snapshot: RiskSnapshot) -> RiskContext {
        RiskContext(
            device: snapshot.device,
            deviceID: snapshot.deviceID,
            network: snapshot.network,
            behavior: snapshot.behavior,
            jailbreak: snapshot.jailbreak
        )
    }

    /// 转换远程配置到 EnginePolicy
    private func convertRemoteConfig(_ config: AdapterConfig) -> EnginePolicy {
        // 从远程配置构建策略
        var scenarioPolicies: [RiskScenario: ScenarioPolicy] = [:]

        // 转换各场景策略
        for (scenarioKey, policyData) in config.policy.scenarios {
            // 根据场景键查找对应的枚举值
            let scenario = findRiskScenario(for: scenarioKey)
            let policy = ScenarioPolicy(
                mediumThreshold: policyData.thresholds.medium,
                highThreshold: policyData.thresholds.high,
                criticalThreshold: policyData.thresholds.critical
            )
            scenarioPolicies[scenario] = policy
        }

        return EnginePolicy(
            name: "remote_\(config.version)",
            version: config.version,
            enableNetworkSignals: config.detectors.network?.enabled ?? true,
            enableBehaviorDetection: config.detectors.behavior?.enabled ?? true,
            enableDeviceFingerprint: config.detectors.device?.enabled ?? true,
            scenarioPolicies: scenarioPolicies
        )
    }

    /// 根据字符串查找 RiskScenario
    private func findRiskScenario(for key: String) -> ProtocolRiskScenario {
        switch key.lowercased() {
        case "login": return .login
        case "payment": return .payment
        case "register": return .register
        case "query": return .query
        case "account_change", "accountchange": return .accountChange
        case "sensitive_action", "sensitiveaction": return .sensitiveAction
        case "api_access", "apiaccess": return .apiAccess
        default: return .default
        }
    }
}

// MARK: - Config Manager 协议（简化版）
/// 配置管理器协议，用于适配器获取远程配置
public protocol AdapterConfigManager: Sendable {
    func getCurrentConfig() async throws -> AdapterConfig
}

// MARK: - 远程配置模型（简化）
/// 远程配置结构
public struct AdapterConfig: Sendable {
    public let version: String
    public let policy: PolicyConfigData
    public let detectors: AdapterDetectorsConfigData

    public init(version: String, policy: PolicyConfigData, detectors: AdapterDetectorsConfigData) {
        self.version = version
        self.policy = policy
        self.detectors = detectors
    }
}

/// 策略配置数据
public struct PolicyConfigData: Sendable, Codable {
    public let scenarios: [String: ScenarioPolicyData]
    public let comboRules: [ComboRuleData]

    public init(scenarios: [String: ScenarioPolicyData], comboRules: [ComboRuleData] = []) {
        self.scenarios = scenarios
        self.comboRules = comboRules
    }
}

/// 场景策略数据
public struct ScenarioPolicyData: Sendable, Codable {
    public let thresholds: ThresholdsData

    public init(thresholds: ThresholdsData) {
        self.thresholds = thresholds
    }
}

/// 阈值数据
public struct ThresholdsData: Sendable, Codable {
    public let medium: Double
    public let high: Double
    public let critical: Double

    public init(medium: Double, high: Double, critical: Double) {
        self.medium = medium
        self.high = high
        self.critical = critical
    }
}

/// 组合规则数据
public struct ComboRuleData: Sendable, Codable {
    public let name: String
    public let requiredSignals: [String]
    public let bonusScore: Double
    public let forceAction: String?

    public init(name: String, requiredSignals: [String], bonusScore: Double, forceAction: String? = nil) {
        self.name = name
        self.requiredSignals = requiredSignals
        self.bonusScore = bonusScore
        self.forceAction = forceAction
    }
}

/// 检测器配置数据
public struct AdapterDetectorsConfigData: Sendable, Codable {
    public let jailbreak: AdapterDetectorConfig?
    public let network: AdapterDetectorConfig?
    public let behavior: AdapterDetectorConfig?
    public let device: AdapterDetectorConfig?

    public init(
        jailbreak: AdapterDetectorConfig? = nil,
        network: AdapterDetectorConfig? = nil,
        behavior: AdapterDetectorConfig? = nil,
        device: AdapterDetectorConfig? = nil
    ) {
        self.jailbreak = jailbreak
        self.network = network
        self.behavior = behavior
        self.device = device
    }
}

/// 单个检测器配置
public struct AdapterDetectorConfig: Sendable, Codable {
    public let enabled: Bool
    public let threshold: Double?

    public init(enabled: Bool, threshold: Double? = nil) {
        self.enabled = enabled
        self.threshold = threshold
    }
}

// MARK: - 工厂方法
extension DecisionEngineAdapter {
    /// 创建默认适配器
    public static func `default`() -> DecisionEngineAdapter {
        DecisionEngineAdapter(
            engine: RiskDetectionEngine(policy: .default),
            configManager: nil
        )
    }

    /// 创建严格策略适配器
    public static func strict() -> DecisionEngineAdapter {
        DecisionEngineAdapter(
            engine: RiskDetectionEngine(policy: .strict),
            configManager: nil
        )
    }

    /// 创建金融级适配器
    public static func financial() -> DecisionEngineAdapter {
        DecisionEngineAdapter(
            engine: RiskDetectionEngine(policy: .financial),
            configManager: nil
        )
    }
}

// MARK: - 同步版本（兼容旧 API）
extension DecisionEngineAdapter {
    /// 同步版本的决策方法（不使用 async/await）
    public func decideSync(
        snapshot: RiskSnapshot,
        config: DecisionConfig = DecisionConfig()
    ) -> ProtocolRiskVerdict {
        // 创建简单的 RiskContext
        let context = RiskContext(
            device: snapshot.device,
            deviceID: snapshot.deviceID,
            network: snapshot.network,
            behavior: snapshot.behavior,
            jailbreak: snapshot.jailbreak
        )

        let verdict = engine.evaluate(context: context, scenario: config.scenario)
        return verdict
    }
}
