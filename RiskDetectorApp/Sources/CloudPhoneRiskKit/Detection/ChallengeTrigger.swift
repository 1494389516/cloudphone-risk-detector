import CryptoKit
import Foundation

private enum ChallengeTriggerCFF {
    static let shouldTriggerConfig = CFFConfig.adaptive(
        functionSeed: 0xB5E2_71CA_4D3F_8096,
        protectionTier: .light,
        dispatcherStyle: .dualRail,
        codecStyle: .xorRotate
    )

    static func salt(
        capabilityAnomalyCount: Int,
        tamperedCount: Int,
        rules: [ServerRiskPolicy.BlindRule]
    ) -> UInt32 {
        let preview = rules.prefix(2).map(\.id).joined(separator: "|")
        return CFFRuntimeSalt.derive(
            functionSeed: shouldTriggerConfig.functionSeed,
            inputs: CFFRuntimeSaltInputs(
                extraWords: [
                    UInt64(capabilityAnomalyCount),
                    UInt64(tamperedCount),
                    UInt64(rules.count),
                    stableHash64(preview),
                ],
                strings: ["ChallengeTrigger.shouldTriggerBlindChallenge", preview],
                flags: [rules.isEmpty, capabilityAnomalyCount > 0, tamperedCount > 0]
            )
        )
    }

    private static func stableHash64(_ value: String) -> UInt64 {
        var hash: UInt64 = 0xCBF29CE484222325
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x100000001B3
        }
        return hash
    }
}

// MARK: - Challenge Trigger

/// Challenge 触发器
/// 用于检查是否需要触发 blindChallenge。
/// 注意：SDK 内的“本地合成 challenge”仅用于联调与回归，不代表服务端下发的一次性生产挑战。
public struct ChallengeTrigger: Sendable {

    /// 服务端下发的一次性 challenge
    public struct BlindChallenge: Codable, Sendable {
        public let challengeId: String
        public let probeIds: [String]
        public let seed: String
        public let expiresAt: Int64

        private enum CodingKeys: String, CodingKey {
            case challengeId = "ci"
            case probeIds = "pi"
            case seed = "s"
            case expiresAt = "ea"
        }

        public init(
            challengeId: String,
            probeIds: [String],
            seed: String,
            expiresAt: Int64
        ) {
            self.challengeId = challengeId
            self.probeIds = probeIds
            self.seed = seed
            self.expiresAt = expiresAt
        }
    }

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
        let cffConfig = ChallengeTriggerCFF.shouldTriggerConfig
        let salt = ChallengeTriggerCFF.salt(
            capabilityAnomalyCount: capabilityAnomalyCount,
            tamperedCount: tamperedCount,
            rules: existingRules
        )
        let entryState: UInt32 = 0x51
        let emptyRulesState: UInt32 = 0x52
        let iterateState: UInt32 = 0x53
        let evaluateState: UInt32 = 0x54
        let triggerState: UInt32 = 0x55
        let connectorState: UInt32 = 0x56
        let settleState: UInt32 = 0x57
        let noTriggerState: UInt32 = 0x58

        let cffKey = CFFStateCodec.deriveSeed(function: "ChallengeTrigger.shouldTriggerBlindChallenge", config: cffConfig)
        let effectiveSalt = cffConfig.enableRuntimeSalt ? salt : salt ^ 0x13579BDF

        func encodeState(_ rawState: UInt32) -> UInt32 {
            CFFStateCodec.encode(state: rawState, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        func decodeState(_ encoded: UInt32) -> UInt32 {
            CFFStateCodec.decode(state: encoded, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        var sink = CFFReturnSink<TriggerResult>()
        var encodedState = encodeState(entryState)
        var loopBudget = max(24, existingRules.count * 5 + 10)
        var ruleIndex = 0
        var currentRule: ServerRiskPolicy.BlindRule?

        while !sink.isResolved {
            guard loopBudget > 0 else {
                sink.store(.noTrigger)
                break
            }
            loopBudget -= 1

            let decodedState = decodeState(encodedState)
            let dispatchPlan = CFFDispatcher.plan(encodedState: encodedState, salt: salt, config: cffConfig)
            let useIfElseRail = dispatchPlan.style == .ifElseChain
                || (dispatchPlan.usesSecondaryDispatcher && CFFOpaquePredicates.connectorGate(encodedState: encodedState, salt: salt))

            if useIfElseRail {
                if decodedState == entryState {
                    let nextState = existingRules.isEmpty ? emptyRulesState : iterateState
                    encodedState = encodeState(nextState)
                } else if decodedState == emptyRulesState {
                    #if DEBUG
                    if capabilityAnomalyCount >= defaultCapabilityAnomalyThreshold && tamperedCount > 0 {
                        let defaultRule = ServerRiskPolicy.BlindRule(
                            id: "debug_local_auto_trigger",
                            minTamperedCount: 1,
                            minCapabilityAnomalyCount: defaultCapabilityAnomalyThreshold,
                            weight: 75
                        )
                        sink.store(TriggerResult(
                            triggered: true,
                            matchedRule: defaultRule,
                            reason: "DEBUG local-only trigger: capabilityAnomalyCount(\(capabilityAnomalyCount)) >= \(defaultCapabilityAnomalyThreshold) && tamperedCount(\(tamperedCount)) > 0"
                        ))
                    } else {
                        sink.store(.noTrigger)
                    }
                    #else
                    sink.store(.noTrigger)
                    #endif
                } else if decodedState == iterateState {
                    guard ruleIndex < existingRules.count else {
                        encodedState = encodeState(noTriggerState)
                        continue
                    }
                    currentRule = existingRules[ruleIndex]
                    encodedState = encodeState(evaluateState)
                } else if decodedState == evaluateState {
                    guard let rule = currentRule else {
                        sink.store(.noTrigger)
                        continue
                    }

                    // NOTE: rule.allOfSignalIDs, anyOfSignalIDs, requireCrossLayerInconsistency, and
                    // minDistinctRiskLayers are NOT evaluated here because this overload only receives
                    // aggregated counts, not the full signal list. Rules that rely solely on count-based
                    // conditions (the common case) are fully evaluated. Rules that also include signal-ID
                    // or cross-layer conditions will over-trigger (match on counts alone). Use the signals-
                    // based overload when those conditions need to be enforced.
                    let capabilityMatches = capabilityAnomalyCount >= rule.minCapabilityAnomalyCount
                    let tamperedMatches = tamperedCount >= rule.minTamperedCount
                    if capabilityMatches && tamperedMatches {
                        encodedState = encodeState(triggerState)
                    } else {
                        encodedState = encodeState(connectorState)
                    }
                } else if decodedState == triggerState {
                    guard let rule = currentRule else {
                        sink.store(.noTrigger)
                        continue
                    }
                    sink.store(
                        TriggerResult(
                            triggered: true,
                            matchedRule: rule,
                            reason: buildReason(
                                capabilityAnomalyCount: capabilityAnomalyCount,
                                tamperedCount: tamperedCount,
                                rule: rule
                            )
                        )
                    )
                } else if decodedState == connectorState {
                    ruleIndex += 1
                    currentRule = nil
                    let nextState = CFFOpaquePredicates.parityFence(UInt32(ruleIndex) &+ decodedState, salt: salt) ? iterateState : settleState
                    encodedState = encodeState(nextState)
                } else if decodedState == settleState {
                    encodedState = encodeState(iterateState)
                } else if decodedState == noTriggerState {
                    sink.store(.noTrigger)
                } else {
                    sink.store(.noTrigger)
                }
            } else {
                switch decodedState {
                case entryState:
                    encodedState = encodeState(existingRules.isEmpty ? emptyRulesState : iterateState)
                case emptyRulesState:
                    #if DEBUG
                    if capabilityAnomalyCount >= defaultCapabilityAnomalyThreshold && tamperedCount > 0 {
                        let defaultRule = ServerRiskPolicy.BlindRule(
                            id: "debug_local_auto_trigger",
                            minTamperedCount: 1,
                            minCapabilityAnomalyCount: defaultCapabilityAnomalyThreshold,
                            weight: 75
                        )
                        sink.store(TriggerResult(
                            triggered: true,
                            matchedRule: defaultRule,
                            reason: "DEBUG local-only trigger: capabilityAnomalyCount(\(capabilityAnomalyCount)) >= \(defaultCapabilityAnomalyThreshold) && tamperedCount(\(tamperedCount)) > 0"
                        ))
                    } else {
                        sink.store(.noTrigger)
                    }
                    #else
                    sink.store(.noTrigger)
                    #endif
                case iterateState:
                    guard ruleIndex < existingRules.count else {
                        encodedState = encodeState(noTriggerState)
                        continue
                    }
                    currentRule = existingRules[ruleIndex]
                    encodedState = encodeState(evaluateState)
                case connectorState:
                    ruleIndex += 1
                    currentRule = nil
                    let nextState = CFFDispatcher.branchKey(encodedState, salt: salt) & 1 == 0 ? iterateState : settleState
                    encodedState = encodeState(nextState)
                case settleState:
                    encodedState = encodeState(iterateState)
                case evaluateState:
                    guard let rule = currentRule else {
                        sink.store(.noTrigger)
                        continue
                    }
                    let capabilityMatches = capabilityAnomalyCount >= rule.minCapabilityAnomalyCount
                    let tamperedMatches = tamperedCount >= rule.minTamperedCount
                    if capabilityMatches && tamperedMatches {
                        encodedState = encodeState(triggerState)
                    } else {
                        encodedState = encodeState(connectorState)
                    }
                case triggerState:
                    guard let rule = currentRule else {
                        sink.store(.noTrigger)
                        continue
                    }
                    sink.store(
                        TriggerResult(
                            triggered: true,
                            matchedRule: rule,
                            reason: buildReason(
                                capabilityAnomalyCount: capabilityAnomalyCount,
                                tamperedCount: tamperedCount,
                                rule: rule
                            )
                        )
                    )
                case noTriggerState:
                    sink.store(.noTrigger)
                default:
                    sink.store(.noTrigger)
                }
            }
        }

        return sink.resolve(or: .noTrigger)
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

        // NOTE: rule.requireCrossLayerInconsistency, allOfSignalIDs, anyOfSignalIDs, and
        // minDistinctRiskLayers are BlindRule fields that require the full signal list to
        // evaluate. shouldTriggerBlindChallenge only receives count parameters and cannot
        // check these conditions. Do NOT include them in the reason string to avoid sending
        // the server false attribution (e.g. claiming "crossLayerInconsistency" was detected
        // when it was never verified).

        return "Rule[\(rule.id)]: \(reasons.joined(separator: " && "))"
    }
}

// MARK: - 服务端验证辅助

extension ChallengeTrigger {

    public static func nowMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }

    private static func canonicalJSONString(_ object: [String: Any]) -> String? {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

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
        timestamp: Int64 = nowMillis()
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

    /// 生成带 challenge 绑定的 payload（beta.4）
    /// 返回值中包含 challengeId/probeIds/seed/expiresAt，可用于服务端防重放核验。
    public static func buildChallengePayload(
        challenge: BlindChallenge,
        capabilityScore: CapabilityScore,
        tamperedCount: Int,
        executedProbeIDs: [String],
        timestamp: Int64 = nowMillis()
    ) -> [String: Any] {
        [
            "challengeId": challenge.challengeId,
            "seed": challenge.seed,
            "probeIds": challenge.probeIds,
            "executedProbeIds": executedProbeIDs,
            "expiresAt": challenge.expiresAt,
            "timestamp": timestamp,
            "capabilityAnomalyCount": capabilityScore.basicAnomalyCount,
            "qualitySuspicion": capabilityScore.qualitySuspicion,
            "totalProbes": capabilityScore.totalProbes,
            "tamperedCount": tamperedCount,
            "probeRiskContribution": capabilityScore.riskContribution,
        ]
    }

    /// 生成强类型 challenge 绑定载荷，可直接写入 CPRiskReport payload。
    /// - Parameter executionStatus: 探针执行状态（超时/不支持时传入 .timeout / .unsupported）
    /// - Parameter expectedHash: seed 与设备指纹绑定占位，expectedHash = SHA256(seed + deviceFingerprint)
    public static func buildChallengeBindingPayload(
        challenge: BlindChallenge,
        capabilityScore: CapabilityScore,
        tamperedCount: Int,
        executedProbeIDs: [String],
        triggerReason: String?,
        timestamp: Int64 = nowMillis(),
        executionStatus: ChallengeExecutionStatus = .completed,
        expectedHash: String? = nil
    ) -> ChallengeBindingPayload {
        ChallengeBindingPayload(
            challengeId: challenge.challengeId,
            seed: challenge.seed,
            probeIds: challenge.probeIds,
            executedProbeIds: executedProbeIDs,
            expiresAt: challenge.expiresAt,
            timestamp: timestamp,
            capabilityAnomalyCount: capabilityScore.basicAnomalyCount,
            qualitySuspicion: capabilityScore.qualitySuspicion,
            totalProbes: capabilityScore.totalProbes,
            tamperedCount: tamperedCount,
            probeRiskContribution: capabilityScore.riskContribution,
            triggerReason: triggerReason,
            executionStatus: executionStatus,
            expectedHash: expectedHash
        )
    }

    /// 计算 seed 与设备指纹绑定的 expectedHash 占位
    /// expectedHash = SHA256(seed + deviceFingerprint)，用于服务端防重放验证
    public static func computeExpectedHash(seed: String, deviceFingerprint: String) -> String? {
        let input = seed + deviceFingerprint
        guard let data = input.data(using: .utf8) else { return nil }
        let hash = SHA256.hash(data: data)
        return hash.compactMap { String(format: "%02x", $0) }.joined()
    }

    /// challenge 是否在有效期内
    public static func isChallengeValid(_ challenge: BlindChallenge, timestamp: Int64 = nowMillis()) -> Bool {
        timestamp <= challenge.expiresAt
    }

    /// 客户端生成 challenge 绑定签名
    public static func signChallengePayload(payload: [String: Any], signingKey: String) -> String? {
        guard let canonical = canonicalJSONString(payload),
              let messageData = canonical.data(using: .utf8) else {
            return nil
        }
        guard var keyData = signingKey.data(using: .utf8) else {
            return nil
        }
        defer { secureZeroData(&keyData) }
        let key = SymmetricKey(data: keyData)
        let digest = HMAC<SHA256>.authenticationCode(for: messageData, using: key)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// challenge 绑定签名校验
    public static func verifyChallengePayloadSignature(
        payload: [String: Any],
        signature: String,
        signingKey: String
    ) -> Bool {
        guard let expected = signChallengePayload(payload: payload, signingKey: signingKey) else {
            return false
        }
        return timingSafeCompare(expected, signature.lowercased())
    }

    private static func timingSafeCompare(_ lhs: String, _ rhs: String) -> Bool {
        guard lhs.count == rhs.count else { return false }
        let lhsBytes = Array(lhs.utf8)
        let rhsBytes = Array(rhs.utf8)
        var result: UInt8 = 0
        for i in 0..<lhsBytes.count {
            result |= lhsBytes[i] ^ rhsBytes[i]
        }
        return result == 0
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
