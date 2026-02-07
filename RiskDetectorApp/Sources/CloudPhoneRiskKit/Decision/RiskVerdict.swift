import Foundation

// MARK: - Risk Verdict
/// 风险判决结果
/// 风控决策引擎的最终输出，包含综合评估结果和建议动作
public struct RiskVerdict: Codable, Sendable {

    // MARK: - 核心评估结果

    /// 综合风险分数 (0-100)
    /// 0 = 无风险, 100 = 最高风险
    public let score: Double

    /// 内部风险等级（4级，更精细控制）
    public let internalLevel: InternalRiskLevel

    /// 公开风险等级（3级，符合协议定义）
    public var level: PublicRiskLevel {
        internalLevel.toPublicRiskLevel()
    }

    /// 内部风险动作（4种，更精细控制）
    public let internalAction: RiskAction

    /// 公开风险动作（3种，符合协议定义）
    public var action: PublicRiskAction {
        internalAction.toPublicRiskAction()
    }

    /// 置信度 (0-1)
    /// 表示决策的可信程度，基于信号数量和质量
    public let confidence: Double

    // MARK: - 决策依据

    /// 主要风险原因（按重要性排序）
    /// 如: ["jailbreak_detected", "vpn_active", "behavior_anomaly"]
    public let primaryReasons: [String]

    /// 决策原因（单行，兼容协议）
    public var reason: String {
        primaryReasons.joined(separator: ", ")
    }

    /// 命中的所有风险信号
    public let signals: [RiskSignal]

    /// 使用的场景类型
    public let scenario: RiskScenario

    // MARK: - 元数据

    /// 判决生成时间
    public let timestamp: Date

    /// 用于追踪的请求ID
    public let requestId: String

    /// 额外信息（兼容协议）
    public var extras: [String: String] {
        [
            "requestId": requestId,
            "timestamp": ISO8601DateFormatter().string(from: timestamp)
        ]
    }

    // MARK: - 初始化

    public init(
        score: Double,
        internalLevel: InternalRiskLevel,
        internalAction: RiskAction,
        confidence: Double,
        primaryReasons: [String],
        signals: [RiskSignal],
        scenario: RiskScenario
    ) {
        self.score = score
        self.internalLevel = internalLevel
        self.internalAction = internalAction
        self.confidence = confidence
        self.primaryReasons = primaryReasons
        self.signals = signals
        self.scenario = scenario
        self.timestamp = Date()
        self.requestId = UUID().uuidString
    }

    /// 便捷初始化：从分数自动推算等级和动作
    public init(
        score: Double,
        confidence: Double,
        signals: [RiskSignal],
        scenario: RiskScenario,
        policy: ScenarioPolicy
    ) {
        self.score = score
        self.internalLevel = InternalRiskLevel.from(score: score)
        self.internalAction = policy.action(for: self.internalLevel)
        self.confidence = confidence
        self.primaryReasons = Self.extractPrimaryReasons(signals: signals, score: score)
        self.signals = signals
        self.scenario = scenario
        self.timestamp = Date()
        self.requestId = UUID().uuidString
    }

    // MARK: - 辅助方法

    /// 提取主要原因
    private static func extractPrimaryReasons(signals: [RiskSignal], score: Double) -> [String] {
        // 按分数降序排序，取前3个主要原因
        signals
            .sorted { $0.score > $1.score }
            .prefix(3)
            .map { "\($0.category)_\($0.id)" }
    }

    /// 是否为高风险及以上（内部4级）
    public var isHighRisk: Bool {
        internalLevel.numericValue >= InternalRiskLevel.high.numericValue
    }

    /// 是否为高风险（公开3级）
    public var isHighRiskPublic: Bool {
        level == .high
    }

    /// 是否应该阻止操作
    public var shouldBlock: Bool {
        internalAction == .block
    }

    /// 是否需要用户交互（挑战或升级认证）
    public var requiresUserInteraction: Bool {
        internalAction == .challenge || internalAction == .stepUpAuth
    }

    /// 是否需要挑战（公开API）
    public var requiresChallenge: Bool {
        action == .challenge
    }

    /// 调试信息
    public var debugDescription: String {
        """
        RiskVerdict {
          score: \(score)
          internalLevel: \(internalLevel.rawValue)
          level: \(level.displayName)
          internalAction: \(internalAction.rawValue)
          action: \(action.displayName)
          confidence: \(confidence)
          reasons: \(reason)
          signalCount: \(signals.count)
          scenario: \(scenario.displayName)
          timestamp: \(ISO8601DateFormatter().string(from: timestamp))
        }
        """
    }
}

// MARK: - 兼容性扩展
/// 与现有 RiskScorer 的兼容桥接
extension RiskVerdict {
    /// 从 RiskScoreReport 创建 RiskVerdict（向后兼容）
    public static func from(
        report: RiskScoreReport,
        context: RiskContext,
        scenario: RiskScenario = .default
    ) -> RiskVerdict {
        let level = InternalRiskLevel.from(score: report.score)
        let action: RiskAction
        switch level {
        case .low, .medium:
            action = .allow
        case .high:
            action = .challenge
        case .critical:
            action = .block
        }

        return RiskVerdict(
            score: report.score,
            internalLevel: level,
            internalAction: action,
            confidence: calculateConfidence(context: context),
            primaryReasons: report.signals.map { "\($0.category)_\($0.id)" },
            signals: report.signals,
            scenario: scenario
        )
    }

    /// 计算置信度
    private static func calculateConfidence(context: RiskContext) -> Double {
        var confidence = 0.5 // 基础置信度

        // 越狱检测命中显著提高置信度
        if context.jailbreak.isJailbroken {
            confidence += 0.3
        }

        // 行为信号充足提高置信度
        let actionCount = context.behavior.actionCount
        if actionCount >= 10 {
            confidence += 0.1
        }

        // 网络信号存在提高置信度
        if context.network.isVPNActive || context.network.proxyEnabled {
            confidence += 0.1
        }

        return min(confidence, 1.0)
    }

    /// 生成摘要文本（兼容旧版）
    public var summary: String {
        if action == .block {
            return "blocked(\(internalLevel.rawValue))"
        } else if action == .challenge {
            return "challenged(\(internalLevel.rawValue))"
        } else if internalAction == .stepUpAuth {
            return "stepup_auth(\(internalLevel.rawValue))"
        } else {
            return "allowed(\(internalLevel.rawValue))"
        }
    }
}

// MARK: - Protocol-Compatible Factory
extension RiskVerdict {
    /// 创建符合协议定义的 RiskVerdict
    public static func protocolCompatible(
        score: Double,
        level: PublicRiskLevel,
        confidence: Double,
        reason: String,
        signals: [RiskSignal],
        scenario: RiskScenario = .default,
        action: PublicRiskAction = .allow,
        extras: [String: String] = [:]
    ) -> RiskVerdict {
        // 映射到内部等级
        let internalLevel: InternalRiskLevel
        switch level {
        case .low: internalLevel = .low
        case .medium: internalLevel = .medium
        case .high: internalLevel = .high  // 默认为 high，critical 需要显式创建
        }

        // 映射到内部动作
        let internalAction: RiskAction
        switch action {
        case .allow: internalAction = .allow
        case .challenge: internalAction = .challenge
        case .block: internalAction = .block
        }

        return RiskVerdict(
            score: score,
            internalLevel: internalLevel,
            internalAction: internalAction,
            confidence: confidence,
            primaryReasons: reason.components(separatedBy: ", "),
            signals: signals,
            scenario: scenario
        )
    }
}
