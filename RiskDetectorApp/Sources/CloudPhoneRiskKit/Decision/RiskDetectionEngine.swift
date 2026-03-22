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

        if policy.killSwitchEnabled {
            log("⚠️ killSwitch enabled — forcing allow verdict, all risk interception bypassed")
            return RiskVerdict(
                score: 0,
                internalLevel: .low,
                internalAction: .allow,
                confidence: 1.0,
                primaryReasons: ["kill_switch_active"],
                signals: [],
                scenario: scenario
            )
        }

        let collected = collectAndAugmentSignals(
            context: context,
            scenario: scenario,
            extraSignals: extraSignals
        )
        if let preflightVerdict = collected.preflightVerdict {
            log("=== Evaluation complete ===")
            log("Verdict - level: \(preflightVerdict.level.rawValue), action: \(preflightVerdict.action.rawValue), confidence: \(preflightVerdict.confidence)")
            return preflightVerdict
        }

        if let fastDecision = fastDigestShortCircuit(
            context: context,
            collected: collected,
            scenario: scenario
        ) {
            let verdict = fastDecision.verdict
            log("=== Evaluation complete ===")
            log("Verdict - level: \(verdict.level.rawValue), action: \(verdict.action.rawValue), confidence: \(verdict.confidence)")
            return verdict
        }

        let intermediate = scoreAndForceDecision(
            context: context,
            scenario: scenario,
            collected: collected
        )
        let verdict = treeCommitVerdict(
            context: context,
            scenario: scenario,
            collected: collected,
            intermediate: intermediate
        )

        log("=== Evaluation complete ===")
        log("Verdict - level: \(verdict.level.rawValue), action: \(verdict.action.rawValue), confidence: \(verdict.confidence)")

        return verdict
    }

    private func collectAndAugmentSignals(
        context: RiskContext,
        scenario: RiskScenario,
        extraSignals: [RiskSignal]
    ) -> CollectedSignalContext {
        let planner = MutationPlanner(
            strategy: policy.mutationStrategy,
            scope: scenario.identifier,
            deviceID: context.deviceID
        )
        let challengeOffsetHint = ChallengeResultStore.shared.currentScoreOffset() ?? 0
        let regionKey = regionStateKey(label: "collectAndAugmentSignals", scenario: scenario)
        let regionSalt = runtimeSalt(
            phase: "collect",
            scenario: scenario,
            context: context,
            signals: extraSignals,
            challengeOffsetHint: challengeOffsetHint,
            antiTamperingDigest: 0
        )

        var scenarioPolicy = policy.scenarioPolicy(for: scenario)
        var allSignals: [RiskSignal] = []
        var callStackExtraSignals: [RiskSignal] = []
        var compressResult = SignalCompressor.compress(signals: [])
        var preflightVerdict: RiskVerdict?
        var sink: CollectedSignalContext?
        var state = encodeRegionState(0x11, key: regionKey, salt: regionSalt)
        var budget = 0
        var poison = regionSalt ^ challengeOffsetHint.bitPattern

        while sink == nil && budget < 12 {
            switch decodeRegionState(state, key: regionKey, salt: regionSalt) {
            case 0x11:
                let (isCallStackMalicious, callStackSignalId) = CallStackUnwinder.validateCallStack()
                if isCallStackMalicious, let signalId = callStackSignalId {
                    if signalId == CallStackUnwinder.dladdrHookSignalId {
                        let hookSignal = makeCallStackSignal(id: signalId)
                        preflightVerdict = RiskVerdict(
                            score: 100,
                            internalLevel: .critical,
                            internalAction: .block,
                            confidence: 1.0,
                            primaryReasons: [hookSignal.id],
                            signals: [hookSignal],
                            scenario: scenario
                        )
                        state = encodeRegionState(0x17, key: regionKey, salt: regionSalt)
                    } else {
                        callStackExtraSignals.append(makeCallStackSignal(id: signalId))
                        log("CallStackUnwinder: \(signalId) injected as signal (not hard-exit)")
                        state = encodeRegionState(0x12, key: regionKey, salt: regionSalt)
                    }
                } else {
                    state = encodeRegionState(0x12, key: regionKey, salt: regionSalt)
                }
            case 0x12:
                scenarioPolicy = mutatedScenarioPolicy(
                    base: policy.scenarioPolicy(for: scenario),
                    planner: planner
                )
                log("Scenario policy - medium: \(scenarioPolicy.mediumThreshold), high: \(scenarioPolicy.highThreshold), critical: \(scenarioPolicy.criticalThreshold)")
                state = encodeRegionState(0x13, key: regionKey, salt: regionSalt)
            case 0x13:
                allSignals = collectSignals(
                    context: context,
                    scenarioPolicy: scenarioPolicy,
                    extraSignals: extraSignals + callStackExtraSignals,
                    planner: planner
                )
                state = encodeRegionState(0x14, key: regionKey, salt: regionSalt)
            case 0x14:
                let crossLayerSignals = deriveCrossLayerSignals(from: allSignals)
                if !crossLayerSignals.isEmpty {
                    allSignals.append(contentsOf: crossLayerSignals)
                    log("Cross-layer inconsistency hit: +\(crossLayerSignals.count) signals")
                }
                state = encodeRegionState(0x15, key: regionKey, salt: regionSalt)
            case 0x15:
                let blocklistSignals = deriveBlocklistSignals(from: allSignals)
                if !blocklistSignals.isEmpty {
                    allSignals.append(contentsOf: blocklistSignals)
                    log("Server blocklist hit: +\(blocklistSignals.count) signals")
                }
                state = encodeRegionState(0x16, key: regionKey, salt: regionSalt)
            case 0x16:
                allSignals = planner.maybeShuffle(allSignals, salt: "signal_order")
                log("Collected \(allSignals.count) signals")
                compressResult = SignalCompressor.compress(signals: allSignals)
                state = encodeRegionState(0x17, key: regionKey, salt: regionSalt)
            case 0x17:
                sink = CollectedSignalContext(
                    planner: planner,
                    scenarioPolicy: scenarioPolicy,
                    allSignals: allSignals,
                    compressResult: compressResult,
                    preflightVerdict: preflightVerdict,
                    challengeOffsetHint: challengeOffsetHint,
                    antiTamperingDigest: antiTamperingDigest(from: allSignals)
                )
            default:
                poison = poison &* 0x100000001b3 &+ 0x9e3779b97f4a7c15
                preflightVerdict = preflightVerdict ?? failClosedVerdict(
                    scenario: scenario,
                    phase: "collectAndAugmentSignals",
                    poison: poison
                )
                compressResult = SignalCompressor.compress(signals: allSignals)
                state = encodeRegionState(0x17, key: regionKey, salt: regionSalt)
            }
            budget += 1
        }

        return sink ?? CollectedSignalContext(
            planner: planner,
            scenarioPolicy: scenarioPolicy,
            allSignals: allSignals,
            compressResult: compressResult,
            preflightVerdict: preflightVerdict ?? failClosedVerdict(
                scenario: scenario,
                phase: "collectAndAugmentSignals_budget",
                poison: poison
            ),
            challengeOffsetHint: challengeOffsetHint,
            antiTamperingDigest: antiTamperingDigest(from: allSignals)
        )
    }

    private func fastDigestShortCircuit(
        context: RiskContext,
        collected: CollectedSignalContext,
        scenario: RiskScenario
    ) -> FastDigestDecision? {
        let regionKey = regionStateKey(label: "fastDigestShortCircuit", scenario: scenario)
        let regionSalt = runtimeSalt(
            phase: "fast_digest",
            scenario: scenario,
            context: context,
            signals: collected.allSignals,
            challengeOffsetHint: collected.challengeOffsetHint,
            antiTamperingDigest: collected.antiTamperingDigest
        )
        var sink: FastDigestDecision?
        var done = false
        var state = encodeRegionState(0x21, key: regionKey, salt: regionSalt)
        var candidateVerdict: RiskVerdict?
        var budget = 0
        var poison = collected.antiTamperingDigest ^ regionSalt

        while !done && budget < 8 {
            let decoded = decodeRegionState(state, key: regionKey, salt: regionSalt)
            if decoded == 0x21 {
                candidateVerdict = evaluateCompressedVerdictRules(
                    digest: collected.compressResult.digest,
                    scenarioPolicy: collected.scenarioPolicy,
                    signals: collected.allSignals,
                    scenario: scenario
                )
                state = encodeRegionState(candidateVerdict == nil ? 0x22 : 0x23, key: regionKey, salt: regionSalt)
            } else if decoded == 0x22 {
                done = true
            } else if decoded == 0x23 {
                if let verdict = candidateVerdict {
                    log("Compressed verdict rule hit, short-circuit: \(verdict.internalAction.rawValue)")
                    sink = FastDigestDecision(verdict: verdict)
                    done = true
                } else {
                    state = encodeRegionState(0x24, key: regionKey, salt: regionSalt)
                }
            } else {
                poison = poison &* 0x9e3779b97f4a7c15 &+ 0x517cc1b727220a95
                sink = FastDigestDecision(
                    verdict: failClosedVerdict(
                        scenario: scenario,
                        phase: "fastDigestShortCircuit",
                        poison: poison
                    )
                )
                done = true
            }
            budget += 1
        }

        if !done && sink == nil {
            return FastDigestDecision(
                verdict: failClosedVerdict(
                    scenario: scenario,
                    phase: "fastDigestShortCircuit_budget",
                    poison: poison
                )
            )
        }
        return sink
    }

    private func scoreAndForceDecision(
        context: RiskContext,
        scenario: RiskScenario,
        collected: CollectedSignalContext
    ) -> IntermediateDecision {
        let regionKey = regionStateKey(label: "scoreAndForceDecision", scenario: scenario)
        let regionSalt = runtimeSalt(
            phase: "score_force",
            scenario: scenario,
            context: context,
            signals: collected.allSignals,
            challengeOffsetHint: collected.challengeOffsetHint,
            antiTamperingDigest: collected.antiTamperingDigest
        )

        var comboBonus = 0.0
        var blindBonus = 0.0
        var challengeOffset = 0.0
        var finalScore = 0.0
        var adjustedScore = collected.scenarioPolicy.criticalThreshold
        var forcedAction: RiskAction? = .block
        var scoreComponents = ScoreComponents(
            total: 0,
            legacyComponent: 0,
            hardComponent: 0,
            softComponent: 0,
            tamperedCount: 0
        )
        var sink: IntermediateDecision?
        var state = encodeRegionState(0x31, key: regionKey, salt: regionSalt)
        var budget = 0
        var poison = regionSalt ^ collected.antiTamperingDigest

        while sink == nil && budget < 14 {
            let decoded = decodeRegionState(state, key: regionKey, salt: regionSalt)
            if decoded == 0x31 {
                let comboRules = collected.planner.maybeShuffle(collected.scenarioPolicy.comboRules, salt: "combo_rules")
                comboBonus = applyComboRules(
                    signals: collected.allSignals,
                    comboRules: comboRules
                )
                if comboBonus > 0 {
                    log("Combo rules bonus: +\(comboBonus)")
                }
                state = encodeRegionState(0x32, key: regionKey, salt: regionSalt)
            } else if decoded == 0x32 {
                scoreComponents = calculateBaseScore(
                    signals: collected.allSignals,
                    weights: collected.scenarioPolicy.signalWeights,
                    weightOverrides: policy.signalWeightOverrides,
                    planner: collected.planner
                )
                let baseScore = scoreComponents.total
                log(
                    "Base score: \(baseScore) " +
                    "(legacy=\(scoreComponents.legacyComponent), hard=\(scoreComponents.hardComponent), " +
                    "soft=\(scoreComponents.softComponent), tampered=\(scoreComponents.tamperedCount))"
                )
                let connectorState: UInt32 = ((poison ^ UInt64(scoreComponents.tamperedCount)) & 1) == 0 ? 0x33 : 0x34
                poison ^= UInt64(scoreComponents.tamperedCount) &+ 0xA511E9B3
                finalScore = baseScore
                state = encodeRegionState(connectorState, key: regionKey, salt: regionSalt)
            } else if decoded == 0x33 || decoded == 0x34 {
                blindBonus = evaluateBlindChallengeBonus(
                    signals: collected.allSignals,
                    scenario: scenario,
                    deviceID: context.deviceID
                )
                if blindBonus > 0 {
                    log("Blind challenge bonus applied")
                }
                state = encodeRegionState(0x35, key: regionKey, salt: regionSalt)
            } else if decoded == 0x35 {
                challengeOffset = ChallengeResultStore.shared.consumeScoreOffset() ?? 0
                if challengeOffset != 0 {
                    log("Challenge result offset applied: +\(challengeOffset)")
                }
                finalScore = min(max(finalScore + comboBonus + blindBonus + challengeOffset, 0), 100)
                log("Final score: \(finalScore)")
                state = encodeRegionState(0x36, key: regionKey, salt: regionSalt)
            } else if decoded == 0x36 {
                (adjustedScore, forcedAction) = applyForceRules(
                    score: finalScore,
                    context: context,
                    signals: collected.allSignals,
                    scenarioPolicy: collected.scenarioPolicy
                )
                if let action = forcedAction {
                    log("Force rule applied, action: \(action.rawValue)")
                }
                sink = IntermediateDecision(
                    adjustedScore: adjustedScore,
                    forcedAction: forcedAction
                )
            } else {
                poison = poison &* 0x100000001b3 &+ 0xC6A4A7935BD1E995
                sink = IntermediateDecision(
                    adjustedScore: collected.scenarioPolicy.criticalThreshold,
                    forcedAction: .block
                )
            }
            budget += 1
        }

        return sink ?? IntermediateDecision(
            adjustedScore: collected.scenarioPolicy.criticalThreshold,
            forcedAction: .block
        )
    }

    private func treeCommitVerdict(
        context: RiskContext,
        scenario: RiskScenario,
        collected: CollectedSignalContext,
        intermediate: IntermediateDecision
    ) -> RiskConclusion {
        let regionKey = regionStateKey(label: "treeCommitVerdict", scenario: scenario)
        let regionSalt = runtimeSalt(
            phase: "tree_commit",
            scenario: scenario,
            context: context,
            signals: collected.allSignals,
            challengeOffsetHint: collected.challengeOffsetHint,
            antiTamperingDigest: collected.antiTamperingDigest,
            scoreHint: intermediate.adjustedScore
        )

        var evaluationContext = EvaluationContext(
            score: intermediate.adjustedScore,
            signals: collected.allSignals,
            scenario: scenario,
            riskContext: context,
            policy: collected.scenarioPolicy
        )
        var treeAction: RiskAction = collected.scenarioPolicy.action(for: collected.scenarioPolicy.level(for: intermediate.adjustedScore))
        var finalAction: RiskAction = intermediate.forcedAction ?? treeAction
        var sink: RiskConclusion?
        var state = encodeRegionState(0x41, key: regionKey, salt: regionSalt)
        var budget = 0
        var poison = regionSalt ^ intermediate.adjustedScore.bitPattern

        while sink == nil && budget < 10 {
            switch decodeRegionState(state, key: regionKey, salt: regionSalt) {
            case 0x41:
                evaluationContext = EvaluationContext(
                    score: intermediate.adjustedScore,
                    signals: collected.allSignals,
                    scenario: scenario,
                    riskContext: context,
                    policy: collected.scenarioPolicy,
                    metadata: [
                        "digestVersion": collected.compressResult.mappingVersion,
                        "antiTamper": String(collected.antiTamperingDigest, radix: 16)
                    ]
                )
                state = encodeRegionState(0x42, key: regionKey, salt: regionSalt)
            case 0x42:
                let decisionTree = DecisionTree.tree(for: scenario)
                treeAction = decisionTree.decide(context: evaluationContext)
                log("Decision tree action: \(treeAction.rawValue)")
                state = encodeRegionState(intermediate.forcedAction == nil ? 0x44 : 0x43, key: regionKey, salt: regionSalt)
            case 0x43:
                finalAction = intermediate.forcedAction ?? treeAction
                state = encodeRegionState(0x45, key: regionKey, salt: regionSalt)
            case 0x44:
                finalAction = treeAction
                state = encodeRegionState(0x45, key: regionKey, salt: regionSalt)
            case 0x45:
                sink = RiskVerdict(
                    score: intermediate.adjustedScore,
                    internalLevel: collected.scenarioPolicy.level(for: intermediate.adjustedScore),
                    internalAction: finalAction,
                    confidence: calculateConfidence(
                        context: context,
                        signals: collected.allSignals,
                        score: intermediate.adjustedScore
                    ),
                    primaryReasons: extractPrimaryReasons(signals: collected.allSignals),
                    signals: collected.allSignals,
                    scenario: scenario,
                    compressedDigest: collected.compressResult.digest,
                    mappingVersion: collected.compressResult.mappingVersion
                )
            default:
                poison = poison &* 0x9e3779b97f4a7c15 &+ 0xD6E8FEB86659FD93
                sink = failClosedVerdict(
                    scenario: scenario,
                    phase: "treeCommitVerdict",
                    poison: poison
                )
            }
            budget += 1
        }

        return sink ?? failClosedVerdict(
            scenario: scenario,
            phase: "treeCommitVerdict_budget",
            poison: poison
        )
    }

    private func makeCallStackSignal(id: String) -> RiskSignal {
        RiskSignal(
            id: id,
            category: "anti_tamper",
            score: 0,
            evidence: [
                "detail": "call_stack_return_address_outside_trusted_regions",
                "mechanism": "dladdr_dual_path_vm_region_validation",
            ],
            state: .tampered,
            layer: 2,
            weightHint: 90
        )
    }

    private func regionStateKey(label: String, scenario: RiskScenario) -> UInt64 {
        fnv1a64("cff|\(label)|\(scenario.identifier)|\(policy.name)|\(policy.version)") | 1
    }

    private func runtimeSalt(
        phase: String,
        scenario: RiskScenario,
        context: RiskContext,
        signals: [RiskSignal],
        challengeOffsetHint: Double,
        antiTamperingDigest: UInt64,
        scoreHint: Double? = nil
    ) -> UInt64 {
        let antiTamperIDs = signals
            .filter { $0.category == "anti_tamper" || $0.state == .tampered }
            .map(\.id)
            .sorted()
            .prefix(4)
            .joined(separator: ",")
        let material = [
            phase,
            scenario.identifier,
            policy.name,
            policy.version,
            policy.mutationStrategy?.seed ?? "no_mutation_seed",
            context.deviceID,
            context.device.model,
            context.jailbreak.isJailbroken ? "jb1" : "jb0",
            context.network.isVPNActive ? "vpn1" : "vpn0",
            context.network.proxyEnabled ? "px1" : "px0",
            String(format: "%.2f", challengeOffsetHint),
            String(antiTamperingDigest, radix: 16),
            scoreHint.map { String(format: "%.2f", $0) } ?? "no_score",
            antiTamperIDs
        ].joined(separator: "|")
        return fnv1a64(material)
    }

    private func antiTamperingDigest(from signals: [RiskSignal]) -> UInt64 {
        let summary = signals
            .filter { $0.category == "anti_tamper" || $0.state == .tampered }
            .sorted { lhs, rhs in
                if lhs.id == rhs.id {
                    return (lhs.layer ?? -1) < (rhs.layer ?? -1)
                }
                return lhs.id < rhs.id
            }
            .map { signal in
                "\(signal.id)#\(signal.layer ?? -1)#\(signal.weightHint)#\(stableSignalStateTag(signal.state))"
            }
            .joined(separator: "|")
        guard !summary.isEmpty else { return 0 }
        return fnv1a64(summary)
    }

    private func stableSignalStateTag(_ state: RiskSignalState?) -> String {
        guard let state else { return "none" }
        switch state {
        case .hard(let detected):
            return detected ? "hard1" : "hard0"
        case .soft(let confidence):
            return "soft:\(String(format: "%.3f", confidence))"
        case .serverRequired:
            return "serverRequired"
        case .unavailable:
            return "unavailable"
        case .tampered:
            return "tampered"
        }
    }

    private func encodeRegionState(_ raw: UInt32, key: UInt64, salt: UInt64) -> UInt64 {
        let shift = Int(((key ^ salt) & 0x7) + 5)
        let mixed = UInt64(raw) ^ key ^ salt ^ 0xD6E8FEB86659FD93
        return rotateLeft(mixed, by: shift) ^ 0xA5A5A5A5A5A5A5A5
    }

    private func decodeRegionState(_ encoded: UInt64, key: UInt64, salt: UInt64) -> UInt32 {
        let shift = Int(((key ^ salt) & 0x7) + 5)
        let mixed = rotateRight(encoded ^ 0xA5A5A5A5A5A5A5A5, by: shift)
        return UInt32(truncatingIfNeeded: mixed ^ key ^ salt ^ 0xD6E8FEB86659FD93)
    }

    private func rotateLeft(_ value: UInt64, by shift: Int) -> UInt64 {
        let normalized = shift & 63
        guard normalized != 0 else { return value }
        return (value << normalized) | (value >> (64 - normalized))
    }

    private func rotateRight(_ value: UInt64, by shift: Int) -> UInt64 {
        let normalized = shift & 63
        guard normalized != 0 else { return value }
        return (value >> normalized) | (value << (64 - normalized))
    }

    private func failClosedVerdict(
        scenario: RiskScenario,
        phase: String,
        poison: UInt64
    ) -> RiskVerdict {
        let poisonSignal = RiskSignal(
            id: "engine_region_poison",
            category: "anti_tamper",
            score: 0,
            evidence: [
                "phase": phase,
                "poison": String(poison, radix: 16)
            ],
            state: .tampered,
            layer: 2,
            weightHint: 100
        )
        return RiskVerdict(
            score: 100,
            internalLevel: .critical,
            internalAction: .block,
            confidence: 1.0,
            primaryReasons: [poisonSignal.id],
            signals: [poisonSignal],
            scenario: scenario
        )
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
            let jbScore = context.jailbreak.confidence * 100
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

        let totalActions = behavior.touch.tapCount + behavior.touch.swipeCount
        if totalActions < 3, behavior.touch.sampleCount < 5 {
            signals.append(
                RiskSignal(
                    id: "insufficient_behavior_data",
                    category: "behavior",
                    score: 5,
                    evidence: [
                        "tapCount": "\(behavior.touch.tapCount)",
                        "swipeCount": "\(behavior.touch.swipeCount)",
                        "sampleCount": "\(behavior.touch.sampleCount)"
                    ],
                    state: .soft(confidence: 0.4),
                    layer: 3,
                    weightHint: 15
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
                    softScore += max(tamperedBase, weight)
                case .serverRequired, .unavailable:
                    break
                }
                continue
            }

            let w = weights.weight(for: signal.category)
            let categoryWeight = planner.jitter(
                base: w.isFinite ? w : 1.0,
                maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0
            )
            let safeScore = signal.score.isFinite ? signal.score : 0
            legacyScore += safeScore * categoryWeight
        }

        let tamperedMultiplier = 1.0 + Double(tamperedCount) * 0.5
        let v3Component = (hardScore + softScore) * tamperedMultiplier
        let total = min(100, max(0, legacyScore + v3Component))

        return ScoreComponents(
            total: total,
            legacyComponent: legacyScore,
            hardComponent: hardScore,
            softComponent: softScore,
            tamperedCount: tamperedCount
        )
    }

    private static let criticalSignalMinWeights: [String: Double] = [
        "vphone_hardware": 50,
        "gpu_virtual": 50,
        "hook_detected": 40,
        "jailbreak": 30,
        "blocklist_hit": 50,
        "cross_layer_inconsistency": 40,
        "sdk_binary_replaced": 50,
        "plt_integrity_tampered": 40,
        "frida_thread_anomaly": 30,
        "frida_js_engine_heap": 30,
        "dyld_interpose_detected": 40,
        "rop_chain_detected": 90,
    ]

    private func signalWeight(
        for signal: RiskSignal,
        overrides: [String: Double],
        planner: MutationPlanner
    ) -> Double {
        let minWeight = Self.criticalSignalMinWeights[signal.id] ?? 0
        let baseWeight: Double
        if signal.weightHint > 0 {
            // minWeight must be enforced even when weightHint is explicitly set.
            // Without max(), a critical signal whose weightHint is set to a low value
            // (e.g. by a compromised/forged provider signal) would silently bypass
            // its guaranteed floor, letting it contribute near-zero to the score.
            baseWeight = max(signal.weightHint, minWeight)
            return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
        }
        if let override = overrides[signal.id], override > 0 {
            baseWeight = max(override, minWeight)
            return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
        }
        if let fallback = Self.defaultV3SignalWeights[signal.id], fallback > 0 {
            baseWeight = max(fallback, minWeight)
            return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
        }
        baseWeight = max(max(signal.score, 0), minWeight)
        return planner.jitter(base: baseWeight, maxBps: policy.mutationStrategy?.scoreJitterBps ?? 0)
    }

    /// 压缩摘要快速判决：若位向量规则命中，返回短路判决；否则返回 nil
    private func evaluateCompressedVerdictRules(
        digest: Data,
        scenarioPolicy: ScenarioPolicy,
        signals: [RiskSignal],
        scenario: RiskScenario
    ) -> RiskVerdict? {
        let rules = scenarioPolicy.compressedVerdictRules
        guard !rules.isEmpty else { return nil }

        var matchedRules: [CompressedVerdictRule] = []
        for rule in rules {
            if rule.matches(digest: digest) {
                matchedRules.append(rule)
            }
        }
        guard !matchedRules.isEmpty else { return nil }

        // 取最严格动作
        guard let strictestRule = matchedRules.max(by: { $0.action.severity < $1.action.severity }) else {
            return nil
        }
        let score = minScore(for: strictestRule.action, scenarioPolicy: scenarioPolicy)

        return RiskVerdict(
            score: score,
            internalLevel: scenarioPolicy.level(for: score),
            internalAction: strictestRule.action,
            confidence: 1.0,
            primaryReasons: ["compressed_rule:\(strictestRule.id)"],
            signals: signals,
            scenario: scenario,
            compressedDigest: digest,
            mappingVersion: SignalCompressor.mappingVersion
        )
    }

    /// 应用组合规则
    private func applyComboRules(
        signals: [RiskSignal],
        comboRules: [ComboRule]
    ) -> Double {
        var bonus: Double = 0

        for rule in comboRules {
            if rule.matches(signals: signals) {
                let safeBonus = max(0, rule.bonusScore.isFinite ? rule.bonusScore : 0)
                log("Combo rule matched: \(rule.name), bonus: +\(safeBonus)")
                bonus += safeBonus
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
        let blocklistHit = signals.contains(where: { $0.id == SignalID.blocklistHit })
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

        // ComboRule 命中且带 forceAction 时强制应用（如 Impossible States）
        for rule in scenarioPolicy.comboRules {
            guard let action = rule.forceAction else { continue }
            if rule.matches(signals: signals) {
                forcedAction = strictestAction(forcedAction, action)
                adjustedScore = max(adjustedScore, minScore(for: action, scenarioPolicy: scenarioPolicy))
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
            // Forcing .allow should NOT elevate the score. Returning mediumThreshold would
            // produce a contradiction: action=allow but internalLevel=.medium, and would
            // silently inflate the score when a blocklist/comboRule uses .allow as its action.
            return 0
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

        let result = min(confidence, 1.0)
        return result.isFinite && result >= 0 ? result : 0.5
    }

    /// 提取主要原因
    ///
    /// Sort key 使用 `max(score, weightHint)`，而非单纯的 `.score`。
    /// 原因：状态驱动信号（.tampered/.hard）统一将 score 设为 0，
    /// 实际权重由 weightHint 表达。若仅按 score 排序，这些高危信号会被
    /// 行为信号（score=10/8/5）压到末尾，导致主要原因与实际评分依据脱节。
    private func extractPrimaryReasons(signals: [RiskSignal]) -> [String] {
        signals
            .sorted { max($0.score, $0.weightHint) > max($1.score, $1.weightHint) }
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
            enableForceRules: base.enableForceRules,
            compressedVerdictRules: base.compressedVerdictRules
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
            signals.contains(where: { $0.id == SignalID.hookDetected && $0.state == .hard(detected: true) })

        let l1GPUReal = signals.contains(where: { $0.id == SignalID.gpuVirtual && $0.state == .hard(detected: false) })
        let l1HardwareReal = signals.contains(where: { $0.id == SignalID.vphoneHardware && $0.state == .hard(detected: false) })

        let l1Suspicious = signals.contains(where: { $0.id == SignalID.vphoneHardware && $0.state == .hard(detected: true) }) ||
            signals.contains(where: { $0.id == SignalID.gpuVirtual && $0.state == .hard(detected: true) }) ||
            signals.contains(where: { $0.id == SignalID.hardwareInconsistency && confidence(of: $0.state) >= 0.8 })

        let l3Virtual = signals.contains(where: { ($0.id == SignalID.sensorEntropy || $0.id == SignalID.touchEntropy) && confidence(of: $0.state) >= 0.65 })
        let l3UnavailableCount = signals.filter {
            ($0.id == SignalID.sensorEntropy || $0.id == SignalID.touchEntropy) && $0.state == .unavailable
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
        guard !policy.rules.isEmpty else {
            return BlindChallengeRule(id: "_noop")
        }
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

private typealias RiskConclusion = RiskVerdict

private struct CollectedSignalContext: Sendable {
    let planner: MutationPlanner
    let scenarioPolicy: ScenarioPolicy
    let allSignals: [RiskSignal]
    let compressResult: SignalCompressor.CompressResult
    let preflightVerdict: RiskVerdict?
    let challengeOffsetHint: Double
    let antiTamperingDigest: UInt64
}

private struct FastDigestDecision: Sendable {
    let verdict: RiskVerdict
}

private struct IntermediateDecision: Sendable {
    let adjustedScore: Double
    let forcedAction: RiskAction?
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
        // 3.5 新增信号权重
        "drm_capability": 85,
        "drm_device_mismatch": 100,
        "battery_charge_counter": 95,
        "battery_voltage_entropy": 55,
        "battery_energy_counter": 85,
        "mount_virtual_fs": 75,
        "mount_missing_required": 60,
        "mount_count_anomaly": 45,
        "rwx_anonymous": 90,
        "rwx_multiple": 60,
        "plt_integrity_tampered": 92,
        // 3.5 图算法反哺信号权重
        "graph_community_risk": 65,
        "graph_hw_profile_cluster": 70,
        "graph_dense_subgraph": 60,
        "local_device_cluster": 55,
        "text_segment_tampered": 88,
        "text_segment_baseline_rejected_suspicious_env": 88,
        "text_segment_baseline_cleared_suspicious_env": 88,
        // 3.5.1 Frida 深度检测信号权重
        "frida_thread_anomaly": 75,
        "frida_exception_port": 85,
        "frida_js_engine_heap": 80,
        "frida_stalker_jit": 78,
        "objc_method_swizzled": 80,
        "frida_dispatch_queue": 70,
        "frida_unix_socket": 75,
        "frida_timing_anomaly": 65,
        "kernel_hook_timing_anomaly": 68,
        "kernel_hook_stalker_amplified": 72,
        "system_library_wx_mapping": 94,
        "system_library_anonymous_exec_region": 92,
        "system_library_segment_count_drift": 68,
        "app_image_segment_layout_anomaly": 85,
        // 3.6 加固信号权重
        "multipath_hook_detected": 82,
        "multipath_jailbreak_file": 70,
        "randomized_env_anomaly": 60,
        "fingerprint_simulator": 90,
        "fingerprint_virtualization": 85,
        "fingerprint_mutation": 55,
        "fingerprint_suspicious_hw": 80,
        "dyld_interpose_detected": 88,
        "dyld_env_abuse": 78,
        "dyld_image_overload": 45,
        "sdk_code_signature_missing": 90,
        "sdk_binary_replaced": 95,
        "sdk_segment_tampered": 85,
        "sdk_binary_size_anomaly": 70,
        // 3.7 深度加固信号权重
        "sensor_replay_detected": 72,
        "gpu_render_anomaly": 75,
        "isa_swizzle_detected": 82,
        "msg_forward_hijack": 85,
        "method_count_anomaly": 50,
        // 4.4 执行流栈回溯
        "rop_chain_detected": 90,
        // 环境一致性、硬件能力、网络接口
        "physical_sensor_anomaly": 70,
        "thermal_state_static": 40,
        "battery_state_static": 50,
        "screen_brightness_static": 35,
        "haptic_capability_mismatch": 80,
        "refresh_rate_mismatch": 75,
        "proximity_sensor_absent": 30,
        "network_interface_anomaly": 55,
        // barometer_anomaly：PhysicalSensorProbe 当前未单独输出，预留权重供后续扩展
        "barometer_anomaly": 65,
        // SDK 5.2 新信号权重
        "screen_captured": 50,
        "external_display_attached": 45,
        "usb_audio_routed": 55,
        "no_cellular_provider": 60,
        "biometric_not_enrolled": 40,
    ]
}

// MARK: - 引擎策略配置
/// 决策引擎的全局策略配置
public struct EnginePolicy: Codable, Sendable {

    // MARK: - 紧急开关

    public let killSwitchEnabled: Bool

    // MARK: - 全局开关

    public let enableNetworkSignals: Bool
    public let enableBehaviorDetection: Bool
    public let enableDeviceFingerprint: Bool

    // MARK: - 强制规则

    public let forceActionOnJailbreak: RiskAction?

    // MARK: - 场景策略

    public let scenarioPolicies: [RiskScenario: ScenarioPolicy]
    public let signalWeightOverrides: [String: Double]
    public let mutationStrategy: MutationStrategy?
    public let blindChallengePolicy: BlindChallengePolicy?
    public let serverBlocklist: [String]?
    public let blocklistAction: RiskAction?

    // MARK: - 元数据

    public let name: String
    public let version: String

    private enum CodingKeys: String, CodingKey {
        case killSwitchEnabled = "ks"
        case enableNetworkSignals = "en"
        case enableBehaviorDetection = "eb"
        case enableDeviceFingerprint = "ef"
        case forceActionOnJailbreak = "fj"
        case scenarioPolicies = "sp"
        case signalWeightOverrides = "wo"
        case mutationStrategy = "ms"
        case blindChallengePolicy = "bp"
        case serverBlocklist = "sb"
        case blocklistAction = "ba"
        case name = "n"
        case version = "v"
    }

    // MARK: - 初始化

    public init(
        name: String = "default",
        version: String = "1.0.0",
        killSwitchEnabled: Bool = false,
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
        self.killSwitchEnabled = killSwitchEnabled
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

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        version = try container.decode(String.self, forKey: .version)
        killSwitchEnabled = try container.decodeIfPresent(Bool.self, forKey: .killSwitchEnabled) ?? false
        enableNetworkSignals = try container.decodeIfPresent(Bool.self, forKey: .enableNetworkSignals) ?? true
        enableBehaviorDetection = try container.decodeIfPresent(Bool.self, forKey: .enableBehaviorDetection) ?? true
        enableDeviceFingerprint = try container.decodeIfPresent(Bool.self, forKey: .enableDeviceFingerprint) ?? true
        forceActionOnJailbreak = try container.decodeIfPresent(RiskAction.self, forKey: .forceActionOnJailbreak)
        signalWeightOverrides = try container.decodeIfPresent([String: Double].self, forKey: .signalWeightOverrides) ?? [:]
        mutationStrategy = try container.decodeIfPresent(MutationStrategy.self, forKey: .mutationStrategy)
        blindChallengePolicy = try container.decodeIfPresent(BlindChallengePolicy.self, forKey: .blindChallengePolicy)
        serverBlocklist = try container.decodeIfPresent([String].self, forKey: .serverBlocklist)
        blocklistAction = try container.decodeIfPresent(RiskAction.self, forKey: .blocklistAction)
        scenarioPolicies = try container.decodeIfPresent([RiskScenario: ScenarioPolicy].self, forKey: .scenarioPolicies) ?? [:]
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

    private enum CodingKeys: String, CodingKey {
        case seed = "s"
        case shuffleChecks = "sc"
        case thresholdJitterBps = "tj"
        case scoreJitterBps = "sj"
    }

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

    private enum CodingKeys: String, CodingKey {
        case enabled = "e"
        case challengeSalt = "cs"
        case windowSeconds = "ws"
        case rules = "r"
    }

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

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case allOfSignalIDs = "ao"
        case anyOfSignalIDs = "ay"
        case minTamperedCount = "mt"
        case minDistinctRiskLayers = "ml"
        case requireCrossLayerInconsistency = "rc"
        case weight = "w"
    }

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
            summary: verdict.summary,
            compressedDigest: verdict.compressedDigest,
            mappingVersion: verdict.mappingVersion
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
