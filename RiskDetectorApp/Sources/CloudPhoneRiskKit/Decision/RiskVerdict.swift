import Foundation

// MARK: - Risk Verdict
/// 风险判决结果
/// 风控决策引擎的最终输出，包含综合评估结果和建议动作
public struct RiskVerdict: Codable, Sendable {

    public let score: Double
    public let internalLevel: InternalRiskLevel

    public var level: PublicRiskLevel {
        internalLevel.toPublicRiskLevel()
    }

    public let internalAction: RiskAction

    public var action: PublicRiskAction {
        internalAction.toPublicRiskAction()
    }

    public let confidence: Double
    public let primaryReasons: [String]

    public var reason: String {
        primaryReasons.joined(separator: ", ")
    }

    public let signals: [RiskSignal]
    public let scenario: RiskScenario
    public let compressedDigest: Data?
    public let mappingVersion: String?
    /// 引擎聚合/底线决策的可观测元数据（供上报与服务端联动；不参与分数计算）。
    public let decisionMetadata: [String: String]?
    public let timestamp: Date
    public let requestId: String

    public var extras: [String: String] {
        var base = [
            "requestId": requestId,
            "timestamp": ISO8601DateFormatter().string(from: timestamp)
        ]
        if let decisionMetadata {
            for (k, v) in decisionMetadata {
                base["dm.\(k)"] = v
            }
        }
        return base
    }

    private enum CodingKeys: String, CodingKey {
        case score = "s"
        case internalLevel = "il"
        case internalAction = "ia"
        case confidence = "c"
        case primaryReasons = "pr"
        case signals = "sg"
        case scenario = "sc"
        case compressedDigest = "cd"
        case mappingVersion = "mv"
        case decisionMetadata = "dm"
        case timestamp = "ts"
        case requestId = "ri"
    }

    // MARK: - 初始化

    public init(
        score: Double,
        internalLevel: InternalRiskLevel,
        internalAction: RiskAction,
        confidence: Double,
        primaryReasons: [String],
        signals: [RiskSignal],
        scenario: RiskScenario,
        compressedDigest: Data? = nil,
        mappingVersion: String? = nil,
        decisionMetadata: [String: String]? = nil
    ) {
        self.score = score
        self.internalLevel = internalLevel
        self.internalAction = internalAction
        self.confidence = confidence
        self.primaryReasons = primaryReasons
        self.signals = signals
        self.scenario = scenario
        self.compressedDigest = compressedDigest
        self.mappingVersion = mappingVersion
        self.decisionMetadata = decisionMetadata
        self.timestamp = Date()
        self.requestId = UUID().uuidString
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let rawScore = try container.decode(Double.self, forKey: .score)
        score = rawScore.isFinite ? min(max(rawScore, 0), 100) : 0
        internalLevel = try container.decode(InternalRiskLevel.self, forKey: .internalLevel)
        internalAction = try container.decode(RiskAction.self, forKey: .internalAction)
        let rawConfidence = try container.decode(Double.self, forKey: .confidence)
        confidence = rawConfidence.isFinite ? min(max(rawConfidence, 0), 1) : 0.5
        primaryReasons = try container.decodeIfPresent([String].self, forKey: .primaryReasons) ?? []
        signals = try container.decodeIfPresent([RiskSignal].self, forKey: .signals) ?? []
        scenario = try container.decode(RiskScenario.self, forKey: .scenario)
        compressedDigest = try container.decodeIfPresent(Data.self, forKey: .compressedDigest)
        mappingVersion = try container.decodeIfPresent(String.self, forKey: .mappingVersion)
        decisionMetadata = try container.decodeIfPresent([String: String].self, forKey: .decisionMetadata)
        timestamp = try container.decodeIfPresent(Date.self, forKey: .timestamp) ?? Date()
        requestId = try container.decodeIfPresent(String.self, forKey: .requestId) ?? UUID().uuidString
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(score, forKey: .score)
        try container.encode(internalLevel, forKey: .internalLevel)
        try container.encode(internalAction, forKey: .internalAction)
        try container.encode(confidence, forKey: .confidence)
        try container.encode(primaryReasons, forKey: .primaryReasons)
        try container.encode(signals, forKey: .signals)
        try container.encode(scenario, forKey: .scenario)
        try container.encodeIfPresent(compressedDigest, forKey: .compressedDigest)
        try container.encodeIfPresent(mappingVersion, forKey: .mappingVersion)
        try container.encodeIfPresent(decisionMetadata, forKey: .decisionMetadata)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(requestId, forKey: .requestId)
    }

    /// 便捷初始化：从分数自动推算等级和动作
    public init(
        score: Double,
        confidence: Double,
        signals: [RiskSignal],
        scenario: RiskScenario,
        policy: ScenarioPolicy,
        compressedDigest: Data? = nil,
        mappingVersion: String? = nil
    ) {
        self.score = score
        self.internalLevel = policy.level(for: score)
        self.internalAction = policy.action(for: self.internalLevel)
        self.confidence = confidence
        self.primaryReasons = Self.extractPrimaryReasons(signals: signals, score: score)
        self.signals = signals
        self.scenario = scenario
        self.compressedDigest = compressedDigest
        self.mappingVersion = mappingVersion
        self.decisionMetadata = nil
        self.timestamp = Date()
        self.requestId = UUID().uuidString
    }

    // MARK: - 辅助方法

    /// 提取主要原因
    ///
    /// Sort key 使用 `max(score, weightHint)`，而非单纯的 `.score`。
    /// 状态驱动信号（.tampered/.hard）score=0 而 weightHint 承载实际权重，
    /// 若仅按 score 排序会将这些高危信号排到末尾，导致审计记录与真实原因脱节。
    private static func extractPrimaryReasons(signals: [RiskSignal], score: Double) -> [String] {
        signals
            .sorted { max($0.score, $0.weightHint) > max($1.score, $1.weightHint) }
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
        let policy = ScenarioPolicy.policy(for: scenario)
        let level = policy.level(for: report.score)
        let action = policy.action(for: level)

        return RiskVerdict(
            score: report.score,
            internalLevel: level,
            internalAction: action,
            confidence: calculateConfidence(context: context),
            primaryReasons: Array(report.signals.sorted { $0.score > $1.score }.prefix(5).map { "\($0.category)_\($0.id)" }),
            signals: report.signals,
            scenario: scenario,
            compressedDigest: report.compressedDigest,
            mappingVersion: report.mappingVersion
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
