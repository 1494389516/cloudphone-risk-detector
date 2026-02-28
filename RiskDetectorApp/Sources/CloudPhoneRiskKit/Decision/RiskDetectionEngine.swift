import Foundation

// MARK: - 风险检测引擎
/// 智能风控决策引擎，支持场景化检测、动态权重和组合规则
///
/// ## 核心设计原则
/// 1. **场景化**: 不同业务场景使用不同的风险阈值和权重
/// 2. **可配置**: 所有阈值、权重、规则都可通过 Policy 配置
/// 3. **可扩展**: 支持自定义信号提供者和决策树
/// 4. **向后兼容**: 与现有 RiskScorer API 保持兼容
///
/// ## 使用示例
/// ```swift
/// let engine = RiskDetectionEngine(policy: .payment)
/// let verdict = engine.evaluate(context: riskContext, scenario: .payment)
///
/// switch verdict.action {
/// case .allow: print("允许交易")
/// case .challenge: print("需要验证码")
/// case .stepUpAuth: print("需要短信验证")
/// case .block: print("拒绝交易")
/// }
/// ```
public struct RiskDetectionEngine: Sendable {

    // MARK: - 属性

    /// 引擎策略配置
    public let policy: EnginePolicy

    /// 是否启用日志
    public let enableLogging: Bool

    /// 自定义信号提供者
    private let customProviders: [String: @Sendable (RiskContext) -> [RiskSignal]]

    // MARK: - 初始化

    public init(
        policy: EnginePolicy = .default,
        enableLogging: Bool = true,
        customProviders: [String: @Sendable (RiskContext) -> [RiskSignal]] = [:]
    ) {
        self.policy = policy
        self.enableLogging = enableLogging
        self.customProviders = customProviders
    }

    // MARK: - 核心评估方法

    /// 评估风险并返回判决结果
    /// - Parameters:
    ///   - context: 风险上下文，包含所有检测信号
    ///   - scenario: 检测场景
    ///   - extraSignals: 额外的风险信号（可选）
    /// - Returns: 风险判决结果
    public func evaluate(
        context: RiskContext,
        scenario: RiskScenario = .default,
        extraSignals: [RiskSignal] = []
    ) -> RiskVerdict {
        log("=== RiskDetectionEngine evaluation started ===")
        log("Scenario: \(scenario.rawValue)")
        log("Policy: \(policy.name)")

        // 1. 获取场景策略（带版本变形）
        let planner = MutationPlanner(
            strategy: policy.mutationStrategy,
            scope: scenario.identifier,
            deviceID: context.deviceID
        )
        let scenarioPolicy = mutatedScenarioPolicy(
            base: policy.scenarioPolicy(for: scenario),
            planner: planner
        )
        log("Scenario policy - medium: \(scenarioPolicy.mediumThreshold), high: \(scenarioPolicy.highThreshold), critical: \(scenarioPolicy.criticalThreshold)")

        // 2. 收集所有风险信号
        var allSignals = collectSignals(
            context: context,
            scenarioPolicy: scenarioPolicy,
            extraSignals: extraSignals,
            planner: planner
        )

        // 2.1 跨层一致性约束（Layer1/2/3）
        let crossLayerSignals = deriveCrossLayerSignals(from: allSignals)
        if !crossLayerSignals.isEmpty {
            allSignals.append(contentsOf: crossLayerSignals)
            log("Cross-layer inconsistency hit: +\(crossLayerSignals.count) signals")
        }

        // 2.2 服务端黑名单命中（Layer4）
        let blocklistSignals = deriveBlocklistSignals(from: allSignals)
        if !blocklistSignals.isEmpty {
            allSignals.append(contentsOf: blocklistSignals)
            log("Server blocklist hit: +\(blocklistSignals.count) signals")
        }

        // 2.3 每版本变形：打乱信号顺序，提升脚本复用成本
        allSignals = planner.maybeShuffle(allSignals, salt: "signal_order")
        log("Collected \(allSignals.count) signals")

        // 3. 应用组合规则
        let comboRules = planner.maybeShuffle(scenarioPolicy.comboRules, salt: "combo_rules")
        let comboBonus = applyComboRules(
            signals: allSignals,
            comboRules: comboRules
        )
        if comboBonus > 0 {
            log("Combo rules bonus: +\(comboBonus)")
        }

        // 4. 计算基础分数
        let scoreComponents = calculateBaseScore(
            signals: allSignals,
            weights: scenarioPolicy.signalWeights,
            weightOverrides: policy.signalWeightOverrides,
            planner: planner
        )
        let baseScore = scoreComponents.total
        log(
            "Base score: \(baseScore) " +
            "(legacy=\(scoreComponents.legacyComponent), hard=\(scoreComponents.hardComponent), " +
            "soft=\(scoreComponents.softComponent), tampered=\(scoreComponents.tamperedCount))"
        )

        // 5. 服务端盲挑战（不暴露规则细节）
        let blindBonus = evaluateBlindChallengeBonus(
            signals: allSignals,
            scenario: scenario,
            deviceID: context.deviceID
        )
        if blindBonus > 0 {
            log("Blind challenge bonus applied")
        }

        // 6. 应用组合规则加成
        let finalScore = min(baseScore + comboBonus + blindBonus, 100)
        log("Final score: \(finalScore)")

        // 7. 应用强制规则
        let (adjustedScore, forcedAction) = applyForceRules(
            score: finalScore,
            context: context,
            signals: allSignals,
            scenarioPolicy: scenarioPolicy
        )
        if forcedAction != nil {
            log("Force rule applied, action: \(forcedAction!.rawValue)")
        }

        // 8. 使用决策树确定最终动作
        let evaluationContext = EvaluationContext(
            score: adjustedScore,
            signals: allSignals,
            scenario: scenario,
            riskContext: context,
            policy: scenarioPolicy
        )

        let decisionTree = DecisionTree.tree(for: scenario)
        let treeAction = decisionTree.decide(context: evaluationContext)
        log("Decision tree action: \(treeAction.rawValue)")

        // 9. 强制动作优先级高于决策树
        let finalAction = forcedAction ?? treeAction

        // 10. 创建判决结果
        let verdict = RiskVerdict(
            score: adjustedScore,
            internalLevel: InternalRiskLevel.from(score: adjustedScore),
            internalAction: finalAction,
            confidence: calculateConfidence(
                context: context,
                signals: allSignals,
                score: adjustedScore
            ),
            primaryReasons: extractPrimaryReasons(signals: allSignals),
            signals: allSignals,
            scenario: scenario
        )

        log("=== Evaluation complete ===")
        log("Verdict - level: \(verdict.level.rawValue), action: \(verdict.action.rawValue), confidence: \(verdict.confidence)")

        return verdict
    }

    // MARK: - 信号收集

    /// 收集所有风险信号
    private func collectSignals(
        context: RiskContext,
        scenarioPolicy: ScenarioPolicy,
        extraSignals: [RiskSignal],
        planner: MutationPlanner
    ) -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // 1. 越狱信号
        if context.jailbreak.confidence > 0 {
            let jbScore = context.jailbreak.confidence
            signals.append(
                RiskSignal(
                    id: "jailbreak",
                    category: "jailbreak",
                    score: jbScore,
                    evidence: [
                        "is_jailbroken": "\(context.jailbreak.isJailbroken)",
                        "confidence": "\(jbScore)",
                        "methods": context.jailbreak.detectedMethods.joined(separator: ",")
                    ]
                )
            )
        }

        // 2. 网络信号
        if policy.enableNetworkSignals {
            if context.network.isVPNActive {
                signals.append(
                    RiskSignal(
                        id: "vpn_active",
                        category: "network",
                        score: 10,
                        evidence: ["type": "VPN"]
                    )
                )
            }
            if context.network.proxyEnabled {
                signals.append(
                    RiskSignal(
                        id: "proxy_enabled",
                        category: "network",
                        score: 8,
                        evidence: ["type": "Proxy"]
                    )
                )
            }
        }

        // 3. 行为信号
        if policy.enableBehaviorDetection {
            let behaviorSignals = extractBehaviorSignals(behavior: context.behavior)
            signals.append(contentsOf: behaviorSignals)
        }

        // 4. 设备信号
        let deviceSignals = extractDeviceSignals(
            device: context.device,
            jailbreak: context.jailbreak
        )
        signals.append(contentsOf: deviceSignals)

        // 5. 自定义提供者信号
        let providerKeys = planner.maybeShuffle(customProviders.keys.sorted(), salt: "custom_provider_order")
        for key in providerKeys {
            guard let provider = customProviders[key] else { continue }
            signals.append(contentsOf: provider(context))
        }

        // 6. 额外信号
        signals.append(contentsOf: planner.maybeShuffle(extraSignals, salt: "extra_signal_order"))

        return planner.maybeShuffle(signals, salt: "collect_signal_order")
    }

    /// 提取行为信号
    private func extractBehaviorSignals(behavior: BehaviorSignals) -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // 触摸坐标分散度异常
        if let spread = behavior.touch.coordinateSpread, behavior.touch.tapCount >= 6 {
            if spread < 2.0 {
                signals.append(
                    RiskSignal(
                        id: "touch_spread_low",
                        category: "behavior",
                        score: 12,
                        evidence: ["spread": "\(spread)"]
                    )
                )
            } else if spread > 10.0 {
                signals.append(
                    RiskSignal(
                        id: "touch_spread_high",
                        category: "behavior",
                        score: 4,
                        evidence: ["spread": "\(spread)"]
                    )
                )
            }
        }

        // 触摸间隔规律性异常
        if let cv = behavior.touch.intervalCV, behavior.touch.tapCount >= 6 {
            if cv < 0.2 {
                signals.append(
                    RiskSignal(
                        id: "touch_interval_too_regular",
                        category: "behavior",
                        score: 10,
                        evidence: ["cv": "\(cv)"]
                    )
                )
            } else if cv > 0.6 {
                signals.append(
                    RiskSignal(
                        id: "touch_interval_too_chaotic",
                        category: "behavior",
                        score: 4,
                        evidence: ["cv": "\(cv)"]
                    )
                )
            }
        }

        // 滑动线性度异常
        if let lin = behavior.touch.averageLinearity, behavior.touch.swipeCount >= 3 {
            if lin > 0.98 {
                signals.append(
                    RiskSignal(
                        id: "swipe_too_linear",
                        category: "behavior",
                        score: 8,
                        evidence: ["linearity": "\(lin)"]
                    )
                )
            } else if lin < 0.90 {
                signals.append(
                    RiskSignal(
                        id: "swipe_too_curvy",
                        category: "behavior",
                        score: 4,
                        evidence: ["linearity": "\(lin)"]
                    )
                )
            }
        }

        // 设备静止度过高
        if let still = behavior.motion.stillnessRatio,
           still > 0.98,
           (behavior.touch.tapCount + behavior.touch.swipeCount) >= 10 {
            signals.append(
                RiskSignal(
                    id: "motion_too_still",
                    category: "behavior",
                    score: 10,
                    evidence: ["stillness": "\(still)"]
                )
            )
        }

        // 触摸与运动弱耦合
        if let corr = behavior.touchMotionCorrelation,
           corr < 0.10,
           behavior.actionCount >= 10,
           (behavior.motion.stillnessRatio ?? 0) > 0.95 {
            signals.append(
                RiskSignal(
                    id: "touch_motion_weak_coupling",
                    category: "behavior",
                    score: 8,
                    evidence: ["correlation": "\(corr)"]
                )
            )
        }

        return signals
    }

    /// 提取设备信号
    private func extractDeviceSignals(
        device: DeviceFingerprint,
        jailbreak: DetectionResult
    ) -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // 设备年龄过短（可能是新设备或虚拟机）
        // 当前 DeviceFingerprint 不包含 deviceAgeDays 字段，跳过该项。

        // 设备名称可疑（如包含模拟器关键词）
        let suspiciousNames = ["simulator", "emulator", "x86", "arm64"]
        let deviceName = device.model.lowercased()
        if suspiciousNames.contains(where: { deviceName.contains($0) }) {
            signals.append(
                RiskSignal(
                    id: "suspicious_device_name",
                    category: "device",
                    score: 15,
                    evidence: ["name": device.model]
                )
            )
        }

        // 越狱设备加分
        if jailbreak.isJailbroken {
            signals.append(
                RiskSignal(
                    id: "jailbreak_device",
                    category: "device",
                    score: 20,
                    evidence: ["methods": jailbreak.detectedMethods.joined(separator: ",")]
                )
            )
        }

        return signals
    }

    // MARK: - 分数计算

    /// 计算基础风险分数（应用权重）
    private func calculateBaseScore(
        signals: [RiskSignal],
        weights: SignalWeights,
        weightOverrides: [String: Double],
        planner: MutationPlanner
    ) -> ScoreComponents {
        var legacyScore: Double = 0
        var hardScore: Double = 0
        var softScore: Double = 0
        var tamperedCount = 0
        let softGate = planner.softConfidenceGate(default: 0.3)
        let tamperedBase = planner.tamperedBase(default: 60)

        for signal in signals {
            if let state = signal.state {
                let weight = signalWeight(for: signal, overrides: weightOverrides, planner: planner)
                switch state {
                case .hard(let detected):
                    if detected {
                        hardScore = max(hardScore, weight)
                    }
                case .soft(let confidence):
                    let normalized = min(max(confidence, 0), 1)
                    if normalized > softGate {
                        softScore += weight * normalized * 0.3
                    }
                case .tampered:
                    tamperedCount += 1
                    softScore += tamperedBase
                case .serverRequired, .unavailable:
                    break
                }
                continue
            }

            let categoryWeight = planner.jitter(
                base: weights.weight(for: signal.category),
                maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0
            )
            legacyScore += signal.score * categoryWeight
        }

        let tamperedMultiplier = 1.0 + Double(tamperedCount) * 0.5
        let v3Component = (hardScore + softScore) * tamperedMultiplier
        let total = min(100, legacyScore + v3Component)

        return ScoreComponents(
            total: total,
            legacyComponent: legacyScore,
            hardComponent: hardScore,
            softComponent: softScore,
            tamperedCount: tamperedCount
        )
    }

    private func signalWeight(
        for signal: RiskSignal,
        overrides: [String: Double],
        planner: MutationPlanner
    ) -> Double {
        let baseWeight: Double
        if signal.weightHint > 0 {
            baseWeight = signal.weightHint
            return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
        }
        if let override = overrides[signal.id], override > 0 {
            baseWeight = override
            return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
        }
        if let fallback = Self.defaultV3SignalWeights[signal.id], fallback > 0 {
            baseWeight = fallback
            return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
        }
        baseWeight = max(signal.score, 0)
        return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
    }

    /// 应用组合规则
    private func applyComboRules(
        signals: [RiskSignal],
        comboRules: [ComboRule]
    ) -> Double {
        var bonus: Double = 0

        for rule in comboRules {
            if rule.matches(signals: signals) {
                log("Combo rule matched: \(rule.name), bonus: +\(rule.bonusScore)")
                bonus += rule.bonusScore
            }
        }

        return bonus
    }

    /// 应用强制规则
    private func applyForceRules(
        score: Double,
        context: RiskContext,
        signals: [RiskSignal],
        scenarioPolicy: ScenarioPolicy
    ) -> (Double, RiskAction?) {
        var adjustedScore = score
        var forcedAction: RiskAction? = nil

        guard scenarioPolicy.enableForceRules else {
            return (adjustedScore, forcedAction)
        }

        // 服务端黑名单强制规则
        let blocklistHit = signals.contains(where: { $0.id == "blocklist_hit" })
        if blocklistHit, let blocklistAction = policy.blocklistAction {
            forcedAction = strictestAction(forcedAction, blocklistAction)
            adjustedScore = max(adjustedScore, minScore(for: blocklistAction, scenarioPolicy: scenarioPolicy))
        }

        // 越狱设备强制规则
        if context.jailbreak.isJailbroken {
            if let jailbreakAction = policy.forceActionOnJailbreak {
                forcedAction = strictestAction(forcedAction, jailbreakAction)
                adjustedScore = max(adjustedScore, minScore(for: jailbreakAction, scenarioPolicy: scenarioPolicy))
            } else {
                // 保持向后兼容：即使没有强制动作，越狱分数也不低于高风险阈值。
                adjustedScore = max(adjustedScore, scenarioPolicy.highThreshold)
            }
        }

        return (adjustedScore, forcedAction)
    }

    private func strictestAction(_ lhs: RiskAction?, _ rhs: RiskAction) -> RiskAction {
        guard let lhs else { return rhs }
        return lhs.severity >= rhs.severity ? lhs : rhs
    }

    private func minScore(for action: RiskAction, scenarioPolicy: ScenarioPolicy) -> Double {
        switch action {
        case .allow:
            return scenarioPolicy.mediumThreshold
        case .challenge:
            return scenarioPolicy.highThreshold
        case .stepUpAuth, .block:
            return scenarioPolicy.criticalThreshold
        }
    }

    // MARK: - 置信度计算

    /// 计算决策置信度
    private func calculateConfidence(
        context: RiskContext,
        signals: [RiskSignal],
        score: Double
    ) -> Double {
        var confidence = 0.3 // 基础置信度

        // 信号数量越多，置信度越高
        let signalCount = signals.count
        confidence += min(Double(signalCount) * 0.05, 0.3)

        // 高分信号增加置信度
        let highScoreSignals = signals.filter { $0.score >= 10 }.count
        confidence += min(Double(highScoreSignals) * 0.1, 0.2)

        // 越狱检测命中显著提高置信度
        if context.jailbreak.isJailbroken {
            confidence += 0.2
        }

        // 行为数据充足提高置信度
        if context.behavior.actionCount >= 10 {
            confidence += 0.1
        }

        return min(confidence, 1.0)
    }

    /// 提取主要原因
    private func extractPrimaryReasons(signals: [RiskSignal]) -> [String] {
        signals
            .sorted { $0.score > $1.score }
            .prefix(5)
            .map { signal in
                var reason = signal.category
                if !signal.id.isEmpty && signal.id != signal.category {
                    reason += "_" + signal.id
                }
                return reason
            }
    }

    private func mutatedScenarioPolicy(base: ScenarioPolicy, planner: MutationPlanner) -> ScenarioPolicy {
        let jitterBps = policy.mutationStrategy?.thresholdJitterBps ?? 0
        guard jitterBps > 0 else { return base }

        var medium = planner.jitter(base: base.mediumThreshold, maxBps: jitterBps)
        var high = planner.jitter(base: base.highThreshold, maxBps: jitterBps)
        var critical = planner.jitter(base: base.criticalThreshold, maxBps: jitterBps)

        medium = min(max(0, medium), 98)
        high = min(max(medium + 1, high), 99)
        critical = min(max(high + 1, critical), 100)

        return ScenarioPolicy(
            mediumThreshold: medium,
            highThreshold: high,
            criticalThreshold: critical,
            actionMapping: base.actionMapping,
            signalWeights: base.signalWeights,
            comboRules: base.comboRules,
            enableForceRules: base.enableForceRules
        )
    }

    private func deriveBlocklistSignals(from signals: [RiskSignal]) -> [RiskSignal] {
        guard let configured = policy.serverBlocklist, !configured.isEmpty else { return [] }
        let normalizedBlocklist = Set(configured.flatMap { blocklistTokens(from: $0) })
        guard !normalizedBlocklist.isEmpty else { return [] }

        var matchedTokens = Set<String>()
        var matchedSources = Set<String>()

        for signal in signals {
            let isServerSignal = signal.category == "server" || signal.id.hasPrefix("server_")
            guard isServerSignal else { continue }

            for (token, source) in blocklistCandidates(for: signal) where normalizedBlocklist.contains(token) {
                matchedTokens.insert(token)
                matchedSources.insert(source)
            }
        }

        guard !matchedTokens.isEmpty else { return [] }
        return [
            RiskSignal(
                id: "blocklist_hit",
                category: "server",
                score: 0,
                evidence: [
                    "matched": matchedTokens.sorted().joined(separator: ","),
                    "sources": matchedSources.sorted().joined(separator: ","),
                ],
                state: .hard(detected: true),
                layer: 4,
                weightHint: 100
            ),
        ]
    }

    private func blocklistCandidates(for signal: RiskSignal) -> [(token: String, source: String)] {
        var out: [(token: String, source: String)] = []
        for token in blocklistTokens(from: signal.id) {
            out.append((token: token, source: "id:\(signal.id)"))
        }
        for (key, value) in signal.evidence {
            for token in blocklistTokens(from: value) {
                out.append((token: token, source: "\(signal.id).\(key)"))
            }
        }
        return out
    }

    private func blocklistTokens(from raw: String) -> [String] {
        let normalized = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else { return [] }

        var set = Set<String>()
        set.insert(normalized)
        normalized
            .split(whereSeparator: { $0 == "," || $0 == ";" || $0 == "|" || $0.isWhitespace })
            .map(String.init)
            .filter { !$0.isEmpty }
            .forEach { set.insert($0) }

        for item in Array(set) {
            if let host = stripPort(from: item) {
                set.insert(host)
            }
        }
        return Array(set)
    }

    private func stripPort(from value: String) -> String? {
        if value.hasPrefix("["),
           let endBracket = value.firstIndex(of: "]"),
           value.index(after: endBracket) < value.endIndex,
           value[value.index(after: endBracket)] == ":" {
            let host = value[value.index(after: value.startIndex)..<endBracket]
            return host.isEmpty ? nil : String(host)
        }

        let colonCount = value.reduce(into: 0) { count, char in
            if char == ":" { count += 1 }
        }
        guard colonCount == 1, let idx = value.lastIndex(of: ":") else { return nil }

        let suffix = value[value.index(after: idx)...]
        guard !suffix.isEmpty, suffix.allSatisfy(\.isNumber) else { return nil }
        let host = value[..<idx]
        return host.isEmpty ? nil : String(host)
    }

    private func deriveCrossLayerSignals(from signals: [RiskSignal]) -> [RiskSignal] {
        let hasLayer2Tampered = signals.contains(where: { $0.layer == 2 && $0.state == .tampered }) ||
            signals.contains(where: { $0.id == "hook_detected" && $0.state == .hard(detected: true) })

        let l1GPUReal = signals.contains(where: { $0.id == "gpu_virtual" && $0.state == .hard(detected: false) })
        let l1HardwareReal = signals.contains(where: { $0.id == "vphone_hardware" && $0.state == .hard(detected: false) })

        let l1Suspicious = signals.contains(where: { $0.id == "vphone_hardware" && $0.state == .hard(detected: true) }) ||
            signals.contains(where: { $0.id == "gpu_virtual" && $0.state == .hard(detected: true) }) ||
            signals.contains(where: { $0.id == "hardware_inconsistency" && confidence(of: $0.state) >= 0.8 })

        let l3Virtual = signals.contains(where: { ($0.id == "sensor_entropy" || $0.id == "touch_entropy") && confidence(of: $0.state) >= 0.65 })
        let l3UnavailableCount = signals.filter {
            ($0.id == "sensor_entropy" || $0.id == "touch_entropy") && $0.state == .unavailable
        }.count

        var reasons: [String] = []
        if l1GPUReal && l1HardwareReal && hasLayer2Tampered {
            reasons.append("l1_clean_vs_l2_tampered")
        }
        if l1Suspicious && hasLayer2Tampered && l3UnavailableCount >= 2 {
            reasons.append("l1_risky_l2_tampered_l3_absent")
        }
        if l1GPUReal && l1HardwareReal && l3Virtual {
            reasons.append("l1_clean_vs_l3_virtual")
        }

        guard !reasons.isEmpty else { return [] }
        return [
            RiskSignal(
                id: "cross_layer_inconsistency",
                category: "anti_tamper",
                score: 0,
                evidence: [
                    "reasons": reasons.joined(separator: ","),
                    "layer2_tampered": "\(hasLayer2Tampered)",
                    "layer3_virtual": "\(l3Virtual)",
                ],
                state: .tampered,
                layer: 2,
                weightHint: 92
            ),
        ]
    }

    private func evaluateBlindChallengeBonus(
        signals: [RiskSignal],
        scenario: RiskScenario,
        deviceID: String
    ) -> Double {
        guard let policy = policy.blindChallengePolicy, policy.enabled else { return 0 }
        guard !policy.rules.isEmpty else { return 0 }

        let activeRule = activeBlindRule(policy: policy, scenario: scenario, deviceID: deviceID)
        guard blindRuleMatches(activeRule, signals: signals) else { return 0 }
        return max(0, activeRule.weight)
    }

    private func activeBlindRule(
        policy: BlindChallengePolicy,
        scenario: RiskScenario,
        deviceID: String
    ) -> BlindChallengeRule {
        if policy.rules.count == 1 {
            return policy.rules[0]
        }
        let bucket = Int(Date().timeIntervalSince1970) / max(1, policy.windowSeconds)
        let seedText = "\(policy.challengeSalt)|\(scenario.identifier)|\(deviceID)|\(bucket)"
        let hash = fnv1a64(seedText)
        let idx = Int(hash % UInt64(policy.rules.count))
        return policy.rules[idx]
    }

    private func blindRuleMatches(_ rule: BlindChallengeRule, signals: [RiskSignal]) -> Bool {
        let ids = Set(signals.map(\.id))
        let allOfOK = rule.allOfSignalIDs.allSatisfy { ids.contains($0) }
        guard allOfOK else { return false }

        if !rule.anyOfSignalIDs.isEmpty {
            let anyOfOK = rule.anyOfSignalIDs.contains(where: { ids.contains($0) })
            guard anyOfOK else { return false }
        }

        let tamperedCount = signals.filter { $0.state == .tampered }.count
        guard tamperedCount >= rule.minTamperedCount else { return false }

        let distinctLayers = Set(signals.compactMap { signal -> Int? in
            guard signal.layer != nil else { return nil }
            guard signal.state != .unavailable else { return nil }
            if signal.state == .serverRequired { return nil }
            return signal.layer
        }).count
        guard distinctLayers >= rule.minDistinctRiskLayers else { return false }

        if rule.requireCrossLayerInconsistency {
            guard ids.contains("cross_layer_inconsistency") else { return false }
        }

        return true
    }

    private func confidence(of state: RiskSignalState?) -> Double {
        guard let state else { return 0 }
        switch state {
        case .soft(let confidence):
            return confidence
        case .hard(let detected):
            return detected ? 1 : 0
        case .tampered:
            return 1
        case .serverRequired, .unavailable:
            return 0
        }
    }

    private func fnv1a64(_ text: String) -> UInt64 {
        var hash: UInt64 = 0xcbf29ce484222325
        for b in text.utf8 {
            hash ^= UInt64(b)
            hash &*= 0x100000001b3
        }
        return hash
    }

    // MARK: - 日志辅助

    private func log(_ message: String) {
        if enableLogging {
            Logger.log("[RiskDetectionEngine] \(message)")
        }
    }
}

private struct ScoreComponents: Sendable {
    let total: Double
    let legacyComponent: Double
    let hardComponent: Double
    let softComponent: Double
    let tamperedCount: Int
}

private extension RiskDetectionEngine {
    static let defaultV3SignalWeights: [String: Double] = [
        "vphone_hardware": 100,
        "board_id_virtual": 88,
        "gpu_virtual": 95,
        "hardware_inconsistency": 90,
        "cross_layer_inconsistency": 92,
        "blocklist_hit": 100,
        "hook_detected": 80,
        "tampering_detected": 85,
        "jailbreak_file": 70,
        "dyld_injection": 65,
        "jailbreak_scheme": 40,
        "sensor_entropy": 60,
        "touch_entropy": 50,
        "timing_anomaly": 45,
        "vpn_active": 30,
        "proxy_enabled": 25,
        "datacenter_ip": 55,
        "ip_device_agg": 70,
        "cloud_phone_tag": 90,
    ]
}

// MARK: - 引擎策略配置
/// 决策引擎的全局策略配置
public struct EnginePolicy: Codable, Sendable {

    // MARK: - 全局开关

    /// 是否启用网络信号检测
    public let enableNetworkSignals: Bool

    /// 是否启用行为检测
    public let enableBehaviorDetection: Bool

    /// 是否启用设备指纹检测
    public let enableDeviceFingerprint: Bool

    // MARK: - 强制规则

    /// 越狱设备的强制动作（nil表示不强制）
    public let forceActionOnJailbreak: RiskAction?

    // MARK: - 场景策略

    /// 各场景的默认策略映射
    public let scenarioPolicies: [RiskScenario: ScenarioPolicy]

    /// 单信号权重覆盖（3.0）
    /// key = signal.id, value = weight
    public let signalWeightOverrides: [String: Double]

    /// 每版本变形策略（3.0）
    public let mutationStrategy: MutationStrategy?

    /// 服务端盲挑战策略（3.0）
    public let blindChallengePolicy: BlindChallengePolicy?

    /// 服务端黑名单条目（3.0）
    /// 支持 IP / ASN / AS-ORG / 风险标签等匹配。
    public let serverBlocklist: [String]?

    /// 命中服务端黑名单时的强制动作（3.0）
    public let blocklistAction: RiskAction?

    // MARK: - 元数据

    /// 策略名称
    public let name: String

    /// 策略版本
    public let version: String

    // MARK: - 初始化

    public init(
        name: String = "default",
        version: String = "1.0.0",
        enableNetworkSignals: Bool = true,
        enableBehaviorDetection: Bool = true,
        enableDeviceFingerprint: Bool = true,
        forceActionOnJailbreak: RiskAction? = nil,
        signalWeightOverrides: [String: Double] = [:],
        mutationStrategy: MutationStrategy? = nil,
        blindChallengePolicy: BlindChallengePolicy? = nil,
        serverBlocklist: [String]? = nil,
        blocklistAction: RiskAction? = nil,
        scenarioPolicies: [RiskScenario: ScenarioPolicy] = [:]
    ) {
        self.name = name
        self.version = version
        self.enableNetworkSignals = enableNetworkSignals
        self.enableBehaviorDetection = enableBehaviorDetection
        self.enableDeviceFingerprint = enableDeviceFingerprint
        self.forceActionOnJailbreak = forceActionOnJailbreak
        self.signalWeightOverrides = signalWeightOverrides
        self.mutationStrategy = mutationStrategy
        self.blindChallengePolicy = blindChallengePolicy
        self.serverBlocklist = serverBlocklist
        self.blocklistAction = blocklistAction
        self.scenarioPolicies = scenarioPolicies
    }

    /// 获取指定场景的策略
    public func scenarioPolicy(for scenario: RiskScenario) -> ScenarioPolicy {
        scenarioPolicies[scenario] ?? .policy(for: scenario)
    }

    // MARK: - 预设策略

    /// 默认策略
    public static let `default` = EnginePolicy(
        name: "default",
        version: "1.0.0"
    )

    /// 严格策略
    public static let strict = EnginePolicy(
        name: "strict",
        version: "1.0.0",
        enableNetworkSignals: true,
        enableBehaviorDetection: true,
        enableDeviceFingerprint: true,
        forceActionOnJailbreak: .block
    )

    /// 宽松策略
    public static let lenient = EnginePolicy(
        name: "lenient",
        version: "1.0.0",
        enableNetworkSignals: true,
        enableBehaviorDetection: false,
        enableDeviceFingerprint: false,
        forceActionOnJailbreak: nil
    )

    /// 金融级策略（最高安全）
    public static let financial = EnginePolicy(
        name: "financial",
        version: "1.0.0",
        enableNetworkSignals: true,
        enableBehaviorDetection: true,
        enableDeviceFingerprint: true,
        forceActionOnJailbreak: .block,
        scenarioPolicies: [
            .payment: .payment,
            .login: .login,
            .register: .register,
            .accountChange: .accountChange,
            .sensitiveAction: .sensitiveAction
        ]
    )
}

public struct MutationStrategy: Codable, Sendable {
    public let seed: String
    public let shuffleChecks: Bool
    public let thresholdJitterBps: Int
    public let scoreJitterBps: Int

    public init(
        seed: String,
        shuffleChecks: Bool = true,
        thresholdJitterBps: Int = 0,
        scoreJitterBps: Int = 0
    ) {
        self.seed = seed
        self.shuffleChecks = shuffleChecks
        self.thresholdJitterBps = thresholdJitterBps
        self.scoreJitterBps = scoreJitterBps
    }
}

public struct BlindChallengePolicy: Codable, Sendable {
    public let enabled: Bool
    public let challengeSalt: String
    public let windowSeconds: Int
    public let rules: [BlindChallengeRule]

    public init(
        enabled: Bool = true,
        challengeSalt: String,
        windowSeconds: Int = 300,
        rules: [BlindChallengeRule]
    ) {
        self.enabled = enabled
        self.challengeSalt = challengeSalt
        self.windowSeconds = windowSeconds
        self.rules = rules
    }
}

public struct BlindChallengeRule: Codable, Sendable {
    public let id: String
    public let allOfSignalIDs: [String]
    public let anyOfSignalIDs: [String]
    public let minTamperedCount: Int
    public let minDistinctRiskLayers: Int
    public let requireCrossLayerInconsistency: Bool
    public let weight: Double

    public init(
        id: String,
        allOfSignalIDs: [String] = [],
        anyOfSignalIDs: [String] = [],
        minTamperedCount: Int = 0,
        minDistinctRiskLayers: Int = 0,
        requireCrossLayerInconsistency: Bool = false,
        weight: Double = 75
    ) {
        self.id = id
        self.allOfSignalIDs = allOfSignalIDs
        self.anyOfSignalIDs = anyOfSignalIDs
        self.minTamperedCount = minTamperedCount
        self.minDistinctRiskLayers = minDistinctRiskLayers
        self.requireCrossLayerInconsistency = requireCrossLayerInconsistency
        self.weight = weight
    }
}

// MARK: - 向后兼容扩展
extension RiskDetectionEngine {

    /// 兼容旧版 RiskScorer 接口
    /// 使用默认场景和策略评估风险
    func score(
        context: RiskContext,
        config: RiskConfig,
        extraSignals: [RiskSignal] = []
    ) -> RiskScoreReport {
        // 将 RiskConfig 转换为 EnginePolicy
        let policy = EnginePolicy(
            enableNetworkSignals: config.enableNetworkSignals,
            enableBehaviorDetection: config.enableBehaviorDetect,
            enableDeviceFingerprint: true,
            forceActionOnJailbreak: context.jailbreak.isJailbroken ? .block : nil
        )

        let engine = RiskDetectionEngine(policy: policy)
        let verdict = engine.evaluate(
            context: context,
            scenario: .default,
            extraSignals: extraSignals
        )

        return RiskScoreReport(
            score: verdict.score,
            isHighRisk: verdict.isHighRisk,
            signals: verdict.signals,
            summary: verdict.summary
        )
    }
}

extension RiskVerdict {
    /// 旧版兼容字段
    public var legacySummary: String {
        if action == .block {
            return "blocked(\(level.rawValue))"
        } else if action == .challenge {
            return "challenged(\(level.rawValue))"
        } else {
            return "allowed(\(level.rawValue))"
        }
    }
}
