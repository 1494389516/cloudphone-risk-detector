import Foundation

// MARK: - Challenge Trigger

/// Challenge 触发器
/// 用于检查是否需要触发 blindChallenge
public struct ChallengeTrigger: Sendable {

    // MARK: - 触发结果

    /// 触发结果
    public struct TriggerResult: Sendable {
        /// 是否触发 blindChallenge
        public let triggered: Bool
        /// 匹配的规则
        public let matchedRule: ServerRiskPolicy.BlindRule?
        /// 触发原因描述
        public let reason: String

        public init(triggered: Bool, matchedRule: ServerRiskPolicy.BlindRule?, reason: String) {
            self.triggered = triggered
            self.matchedRule = matchedRule
            self.reason = reason
        }

        public static let noTrigger = TriggerResult(triggered: false, matchedRule: nil, reason: "")
    }

    // MARK: - 默认阈值

    /// 触发 blindChallenge 的默认能力探针异常数阈值
    public static let defaultCapabilityAnomalyThreshold = 2

    // MARK: - 触发检查

    /// 检查是否触发 blindChallenge
    ///
    /// - Parameters:
    ///   - capabilityAnomalyCount: 能力探针异常数（来自 CapabilityScore.basicAnomalyCount）
    ///   - tamperedCount: 被篡改的信号数量
    ///   - existingRules: 服务端配置的 blindChallenge 规则
    /// - Returns: 触发结果
    public static func shouldTriggerBlindChallenge(
        capabilityAnomalyCount: Int,
        tamperedCount: Int,
        existingRules: [ServerRiskPolicy.BlindRule]
    ) -> TriggerResult {
        // 如果没有配置规则，不触发
        guard !existingRules.isEmpty else {
            return .noTrigger
        }

        // 遍历所有规则，检查是否有匹配的
        for rule in existingRules {
            // 检查能力探针异常数是否满足规则要求
            let capabilityMatches = capabilityAnomalyCount >= rule.minCapabilityAnomalyCount

            // 检查篡改计数是否满足规则要求
            let tamperedMatches = tamperedCount >= rule.minTamperedCount

            // 如果满足规则要求，触发 blindChallenge
            if capabilityMatches && tamperedMatches {
                let reason = buildReason(
                    capabilityAnomalyCount: capabilityAnomalyCount,
                    tamperedCount: tamperedCount,
                    rule: rule
                )
                return TriggerResult(
                    triggered: true,
                    matchedRule: rule,
                    reason: reason
                )
            }
        }

        // 没有匹配到任何规则，检查是否满足默认触发条件
        // 当 capabilityAnomalyCount >= 2 时自动触发（不依赖具体规则）
        if capabilityAnomalyCount >= defaultCapabilityAnomalyThreshold && tamperedCount > 0 {
            let defaultRule = ServerRiskPolicy.BlindRule(
                id: "auto_capability_trigger",
                minTamperedCount: 1,
                minCapabilityAnomalyCount: defaultCapabilityAnomalyThreshold,
                weight: 75
            )
            return TriggerResult(
                triggered: true,
                matchedRule: defaultRule,
                reason: "Auto-trigger: capabilityAnomalyCount(\(capabilityAnomalyCount)) >= \(defaultCapabilityAnomalyThreshold) && tamperedCount(\(tamperedCount)) > 0"
            )
        }

        return .noTrigger
    }

    /// 检查是否触发 blindChallenge（基于 CapabilityScore）
    ///
    /// - Parameters:
    ///   - capabilityScore: 能力探针得分
    ///   - tamperedCount: 被篡改的信号数量
    ///   - existingRules: 服务端配置的 blindChallenge 规则
    /// - Returns: 触发结果
    public static func shouldTriggerBlindChallenge(
        capabilityScore: CapabilityScore,
        tamperedCount: Int,
        existingRules: [ServerRiskPolicy.BlindRule]
    ) -> TriggerResult {
        return shouldTriggerBlindChallenge(
            capabilityAnomalyCount: capabilityScore.basicAnomalyCount,
            tamperedCount: tamperedCount,
            existingRules: existingRules
        )
    }

    // MARK: - 私有方法

    private static func buildReason(
        capabilityAnomalyCount: Int,
        tamperedCount: Int,
        rule: ServerRiskPolicy.BlindRule
    ) -> String {
        var reasons: [String] = []

        if rule.minCapabilityAnomalyCount > 0 {
            reasons.append("capabilityAnomalyCount(\(capabilityAnomalyCount)) >= \(rule.minCapabilityAnomalyCount)")
        }

        if rule.minTamperedCount > 0 {
            reasons.append("tamperedCount(\(tamperedCount)) >= \(rule.minTamperedCount)")
        }

        if rule.requireCrossLayerInconsistency {
            reasons.append("crossLayerInconsistency")
        }

        if !rule.allOfSignalIDs.isEmpty {
            reasons.append("allOfSignals:\(rule.allOfSignalIDs.joined(separator: ","))")
        }

        if !rule.anyOfSignalIDs.isEmpty {
            reasons.append("anyOfSignals:\(rule.anyOfSignalIDs.joined(separator: ","))")
        }

        return "Rule[\(rule.id)]: \(reasons.joined(separator: " && "))"
    }
}

// MARK: - 服务端验证辅助

extension ChallengeTrigger {

    /// 生成 blindChallenge 验证请求的数据
    ///
    /// - Parameters:
    ///   - capabilityScore: 能力探针得分
    ///   - tamperedCount: 被篡改的信号数量
    ///   - salt: 服务端下发的 challengeSalt
    ///   - timestamp: 当前时间戳
    /// - Returns: 验证数据字典（供服务端验证）
    public static func buildChallengePayload(
        capabilityScore: CapabilityScore,
        tamperedCount: Int,
        salt: String,
        timestamp: Int64 = Int64(Date().timeIntervalSince1970)
    ) -> [String: Any] {
        return [
            "capabilityAnomalyCount": capabilityScore.basicAnomalyCount,
            "qualitySuspicion": capabilityScore.qualitySuspicion,
            "totalProbes": capabilityScore.totalProbes,
            "tamperedCount": tamperedCount,
            "salt": salt,
            "timestamp": timestamp,
            // 探针原始数据（供服务端重新验证）
            "probeRiskContribution": capabilityScore.riskContribution
        ]
    }

    /// 验证客户端上报的数据是否与服务端规则匹配
    ///
    /// - Parameters:
    ///   - capabilityAnomalyCount: 客户端上报的能力探针异常数
    ///   - tamperedCount: 客户端上报的篡改信号数
    ///   - rule: 服务端规则
    /// - Returns: 是否匹配
    public static func validateWithRule(
        capabilityAnomalyCount: Int,
        tamperedCount: Int,
        rule: ServerRiskPolicy.BlindRule
    ) -> Bool {
        // 检查能力探针异常数
        if capabilityAnomalyCount < rule.minCapabilityAnomalyCount {
            return false
        }

        // 检查篡改计数
        if tamperedCount < rule.minTamperedCount {
            return false
        }

        return true
    }
}
