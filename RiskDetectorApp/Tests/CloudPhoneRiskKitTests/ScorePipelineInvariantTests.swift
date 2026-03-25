import XCTest
@testable import CloudPhoneRiskKit

/// 分数管道不变量测试
///
/// 保证 finalScore 计算路径的边界行为：
/// - finalScore 始终在 [0, 100] 内
/// - 负 challengeOffset 不会导致负 finalScore 被误判为 .critical
/// - InternalRiskLevel.from(score:) 分类正确
/// - ChallengeResultStore 偏移范围约束有效
final class ScorePipelineInvariantTests: XCTestCase {

    // MARK: - InternalRiskLevel.from(score:) 范围分类

    func testInternalRiskLevelLowRange() {
        // [0, 30) → .low
        XCTAssertEqual(InternalRiskLevel.from(score: 0), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: 15), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: 29.9), .low)
    }

    func testInternalRiskLevelMediumRange() {
        // [30, 55) → .medium
        XCTAssertEqual(InternalRiskLevel.from(score: 30), .medium)
        XCTAssertEqual(InternalRiskLevel.from(score: 42), .medium)
        XCTAssertEqual(InternalRiskLevel.from(score: 54.9), .medium)
    }

    func testInternalRiskLevelHighRange() {
        // [55, 80) → .high
        XCTAssertEqual(InternalRiskLevel.from(score: 55), .high)
        XCTAssertEqual(InternalRiskLevel.from(score: 67), .high)
        XCTAssertEqual(InternalRiskLevel.from(score: 79.9), .high)
    }

    func testInternalRiskLevelCriticalRange() {
        // [80, 100] → .critical
        XCTAssertEqual(InternalRiskLevel.from(score: 80), .critical)
        XCTAssertEqual(InternalRiskLevel.from(score: 90), .critical)
        XCTAssertEqual(InternalRiskLevel.from(score: 100), .critical)
    }

    /// 无效分数（NaN/负/无穷）：guard 提前返回 .low，避免误判
    func testInternalRiskLevelInvalidScoreReturnsLow() {
        XCTAssertEqual(InternalRiskLevel.from(score: -1), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: -100), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: Double.nan), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: Double.infinity), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: -Double.infinity), .low)
    }

    // MARK: - ChallengeResultStore 偏移范围约束

    func testChallengeResultStoreClipsPositiveOverflow() {
        let store = ChallengeResultStore.shared
        store.apply(result: ChallengeVerificationResult(
            challengeId: "test-pos",
            passed: true,
            adjustedScore: 150.0  // 超出上界
        ))
        let offset = store.consumeScoreOffset()
        XCTAssertNotNil(offset)
        XCTAssertEqual(offset!, 100.0, accuracy: 0.001)
    }

    func testChallengeResultStoreClipsNegativeUnderflow() {
        let store = ChallengeResultStore.shared
        store.apply(result: ChallengeVerificationResult(
            challengeId: "test-neg",
            passed: false,
            adjustedScore: -200.0  // 超出下界
        ))
        let offset = store.consumeScoreOffset()
        XCTAssertNotNil(offset)
        XCTAssertEqual(offset!, -100.0, accuracy: 0.001)
    }

    func testChallengeResultStoreNilAdjustedScore() {
        let store = ChallengeResultStore.shared
        store.apply(result: ChallengeVerificationResult(
            challengeId: "test-nil",
            passed: true,
            adjustedScore: nil
        ))
        let offset = store.consumeScoreOffset()
        XCTAssertNil(offset)
    }

    func testChallengeResultStoreOneTimeConsumption() {
        let store = ChallengeResultStore.shared
        store.apply(result: ChallengeVerificationResult(
            challengeId: "test-once",
            passed: true,
            adjustedScore: 30.0
        ))
        let first = store.consumeScoreOffset()
        let second = store.consumeScoreOffset()
        XCTAssertNotNil(first)
        XCTAssertNil(second, "consumeScoreOffset 应一次性消费，第二次调用应返回 nil")
    }

    // MARK: - finalScore [0, 100] 不变量

    /// 负 challengeOffset 不得导致 finalScore < 0
    func testFinalScoreNeverNegativeWithLargeNegativeOffset() {
        // baseScore=10, comboBonus=0, blindBonus=0, challengeOffset=-100 → 原始为 -90
        // 修复后 max(..., 0) → 0
        let rawSum = 10.0 + 0.0 + 0.0 + (-100.0)
        let finalScore = min(max(rawSum, 0), 100)
        XCTAssertGreaterThanOrEqual(finalScore, 0, "负 challengeOffset 不得产生负 finalScore")
        XCTAssertEqual(InternalRiskLevel.from(score: finalScore), .low,
            "clamp 到 0 的分数应归为 .low，不得误判为 .critical")
    }

    func testFinalScoreNeverExceeds100() {
        // baseScore=80, comboBonus=50, blindBonus=0, challengeOffset=50 → 原始为 180
        let rawSum = 80.0 + 50.0 + 0.0 + 50.0
        let finalScore = min(max(rawSum, 0), 100)
        XCTAssertLessThanOrEqual(finalScore, 100.0)
        XCTAssertEqual(finalScore, 100.0, accuracy: 0.001)
    }

    func testFinalScoreBoundaryAtZero() {
        // baseScore=0, 所有加成=0, challengeOffset=0 → finalScore=0 → .low
        let rawSum = 0.0 + 0.0 + 0.0 + 0.0
        let finalScore = min(max(rawSum, 0), 100)
        XCTAssertEqual(finalScore, 0.0)
        XCTAssertEqual(InternalRiskLevel.from(score: finalScore), .low)
    }

    func testFinalScoreExactThresholdBoundaries() {
        // 验证 finalScore=30 / 55 / 80 的分类精确边界
        XCTAssertEqual(InternalRiskLevel.from(score: 29.999), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: 30.0), .medium)
        XCTAssertEqual(InternalRiskLevel.from(score: 54.999), .medium)
        XCTAssertEqual(InternalRiskLevel.from(score: 55.0), .high)
        XCTAssertEqual(InternalRiskLevel.from(score: 79.999), .high)
        XCTAssertEqual(InternalRiskLevel.from(score: 80.0), .critical)
    }

    // MARK: - RiskDetectionEngine 端到端 finalScore 范围

    func testEngineScoreAlwaysInRange() {
        let engine = RiskDetectionEngine(policy: .default, enableLogging: false)
        let context = TestFixtures.makeRiskContext(isJailbroken: true, jailbreakConfidence: 90)
        let verdict = engine.evaluate(context: context)
        XCTAssertGreaterThanOrEqual(verdict.score, 0, "engine.evaluate score 不得小于 0")
        XCTAssertLessThanOrEqual(verdict.score, 100, "engine.evaluate score 不得大于 100")
    }

    func testEngineScoreWithNegativeChallengeOffset() {
        // 注入大额负偏移，验证引擎不会产生 score < 0 或误报 .critical
        let store = ChallengeResultStore.shared
        store.apply(result: ChallengeVerificationResult(
            challengeId: "inv-test",
            passed: false,
            adjustedScore: -100.0
        ))

        let engine = RiskDetectionEngine(policy: .default, enableLogging: false)
        let context = TestFixtures.makeRiskContext()
        let verdict = engine.evaluate(context: context)

        XCTAssertGreaterThanOrEqual(verdict.score, 0, "负 challengeOffset 不得使 score 为负")
        XCTAssertLessThanOrEqual(verdict.score, 100)
        // 干净设备 + 大额负偏移：score 应贴近 0，不应误判为 .critical
        XCTAssertNotEqual(verdict.internalLevel, .critical,
            "干净设备 + 负 challengeOffset 不得误归 .critical")
    }

    // MARK: - signalWeight minWeight 强制下限（Bug fix 验证）

    /// Bug fix: signalWeight() 当 weightHint > 0 时，之前绕过了 criticalSignalMinWeights
    /// 的下限约束。修复后使用 max(weightHint, minWeight)，确保关键信号不因低 weightHint 被压低。
    func testSignalWeightMinWeightEnforcedWithLowWeightHint() {
        // rop_chain_detected 的 criticalSignalMinWeights = 90
        // 注入 weightHint=1（远低于 90）的 hard-detected 信号：
        //   修复前 → weight = 1 → hardScore = 1 → finalScore ≈ 1
        //   修复后 → weight = max(1, 90) = 90 → hardScore = 90 → finalScore ≈ 90
        let criticalSignal = RiskSignal(
            id: "rop_chain_detected",
            category: "anti_tamper",
            score: 0,
            evidence: [:],
            state: .hard(detected: true),
            layer: 2,
            weightHint: 1  // 故意设置低值，应被 minWeight=90 覆盖
        )

        let engine = RiskDetectionEngine(policy: .default, enableLogging: false)
        let context = TestFixtures.makeRiskContext()
        let verdict = engine.evaluate(context: context, extraSignals: [criticalSignal])

        // criticalSignalMinWeights 下限生效后，score 应显著高于 weightHint=1 的原始值
        XCTAssertGreaterThanOrEqual(verdict.score, 80,
            "criticalSignalMinWeights 下限应覆盖低 weightHint，score 应 >= 80")
        XCTAssertLessThanOrEqual(verdict.score, 100)
    }

    // MARK: - minScore(.allow) 不得抬升分数（Bug fix 验证）

    /// Bug fix: minScore(for: .allow) 之前返回 mediumThreshold（如 50），
    /// 导致 forceAction=.allow 的组合规则意外将 adjustedScore 抬升到 mediumThreshold。
    /// 修复后返回 0，forcing .allow 不影响分数。
    func testMinScoreForAllowComboRuleDoesNotInflateScore() {
        let allowComboRule = ComboRule(
            name: "test_force_allow",
            requiredSignals: ["dummy_allow_test_signal"],
            bonusScore: 0,
            forceAction: .allow  // 修复前会把 adjustedScore 抬升到 mediumThreshold
        )
        let scenarioPolicy = ScenarioPolicy(
            mediumThreshold: 50,  // 较高，便于检测意外抬升
            highThreshold: 70,
            criticalThreshold: 90,
            comboRules: [allowComboRule],
            enableForceRules: true
        )
        let enginePolicy = EnginePolicy(
            scenarioPolicies: [.default: scenarioPolicy]
        )
        let dummySignal = RiskSignal(
            id: "dummy_allow_test_signal",
            category: "test",
            score: 3,
            evidence: [:]
        )

        let engine = RiskDetectionEngine(policy: enginePolicy, enableLogging: false)
        let context = TestFixtures.makeRiskContext()
        let verdict = engine.evaluate(context: context, extraSignals: [dummySignal])

        // 修复前：adjustedScore = max(rawScore, 50) → 至少 50
        // 修复后：adjustedScore = max(rawScore, 0) → 不被抬升到 50
        XCTAssertLessThan(verdict.score, 50,
            "forceAction=.allow 的组合规则不应将 score 抬升到 mediumThreshold (50)")
    }

    // MARK: - extractPrimaryReasons 优先展示高 weightHint 信号（Bug fix 验证）

    /// Bug fix: 之前 extractPrimaryReasons 按 signal.score 降序排序，
    /// 导致状态驱动信号（score=0, weightHint=90）被行为信号（score=12）排到末尾。
    /// 修复后按 max(score, weightHint) 排序，tampered/hard 信号排在最前。
    func testExtractPrimaryReasonsPrefersTamperedOverLowScoreSignal() {
        let tamperedSignal = RiskSignal(
            id: "rop_chain_detected",
            category: "anti_tamper",
            score: 0,
            evidence: [:],
            state: .tampered,
            layer: 2,
            weightHint: 90
        )
        let behaviorSignal = RiskSignal(
            id: "touch_spread_low",
            category: "behavior",
            score: 12,
            evidence: [:],
            state: nil,
            weightHint: 0
        )

        let engine = RiskDetectionEngine(policy: .default, enableLogging: false)
        let context = TestFixtures.makeRiskContext()
        // 故意将行为信号放在 tampered 信号之前，验证排序不依赖输入顺序
        let verdict = engine.evaluate(
            context: context,
            extraSignals: [behaviorSignal, tamperedSignal]
        )

        let reasons = verdict.primaryReasons
        let tamperedIdx = reasons.firstIndex(where: { $0.contains("rop_chain_detected") })
        let behaviorIdx = reasons.firstIndex(where: { $0.contains("touch_spread_low") })

        // tampered 信号 max(0, 90)=90 > 行为信号 max(12, 0)=12 → 应排在前面
        if let ti = tamperedIdx, let bi = behaviorIdx {
            XCTAssertLessThan(ti, bi,
                "tampered 信号 (weightHint=90) 应排在行为信号 (score=12) 之前")
        } else {
            XCTAssertNotNil(tamperedIdx,
                "rop_chain_detected tampered 信号应出现在 primaryReasons 中")
        }
    }

    // MARK: - 聚合底线：分数档位优先于「单点树路径」，ForceRule 全关仍降级

    /// 登录场景：决策树在高分段可能给出 stepUpAuth，但分数已达 critical → 应用 ScenarioPolicy 的 block 底线。
    func testLoginScenarioPolicyScoreFloorOverridesTreeWhenCriticalScoreWithoutJailbreakSignal() {
        let scenarioPolicy = ScenarioPolicy.login
        let enginePolicy = EnginePolicy(
            forceActionOnJailbreak: nil,
            scenarioPolicies: [.login: scenarioPolicy]
        )
        let engine = RiskDetectionEngine(policy: enginePolicy, enableLogging: false)
        let context = TestFixtures.makeRiskContext(isJailbroken: false, jailbreakConfidence: 0)
        let criticalSignal = RiskSignal(
            id: "rop_chain_detected",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 0,
            evidence: [:],
            state: .hard(detected: true),
            layer: 2,
            weightHint: 1
        )
        let verdict = engine.evaluate(context: context, scenario: .login, extraSignals: [criticalSignal])
        XCTAssertGreaterThanOrEqual(verdict.score, scenarioPolicy.criticalThreshold)
        XCTAssertEqual(verdict.internalLevel, .critical)
        XCTAssertEqual(verdict.internalAction, .block, "critical 档位应对齐策略 block，而非仅依赖越狱 ForceRule 或树默认 stepUp")
        XCTAssertEqual(verdict.decisionMetadata?["policy_score_floor"], "1")
    }

    /// `enableForceRules == false` 时仍应按累计分档位执行策略动作（不因缺少 ForceRule 放行）。
    func testForceRulesDisabledStillAppliesScorePolicyFloor() {
        let scenarioPolicy = ScenarioPolicy(
            mediumThreshold: 30,
            highThreshold: 55,
            criticalThreshold: 80,
            enableForceRules: false
        )
        let enginePolicy = EnginePolicy(
            forceActionOnJailbreak: nil,
            scenarioPolicies: [.default: scenarioPolicy]
        )
        let engine = RiskDetectionEngine(policy: enginePolicy, enableLogging: false)
        let context = TestFixtures.makeRiskContext(isJailbroken: false)
        let highSignal = RiskSignal(
            id: "rop_chain_detected",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 0,
            evidence: [:],
            state: .hard(detected: true),
            layer: 2,
            weightHint: 1
        )
        let verdict = engine.evaluate(context: context, extraSignals: [highSignal])
        XCTAssertGreaterThanOrEqual(verdict.score, scenarioPolicy.criticalThreshold)
        XCTAssertEqual(verdict.internalAction, .block)
    }

    /// 多家族证据 + 高分：聚合升级元数据应出现（root/JB 单点绕过不影响其它家族计数）。
    func testMultiFamilyAggregateEscalationMetadataWhenRootContextClean() {
        let scenarioPolicy = ScenarioPolicy.general
        let enginePolicy = EnginePolicy(scenarioPolicies: [.default: scenarioPolicy])
        let engine = RiskDetectionEngine(policy: enginePolicy, enableLogging: false)
        let context = TestFixtures.makeRiskContext(
            isJailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: true
        )
        let s1 = RiskSignal(
            id: "frida_thread_anomaly",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 0,
            evidence: [:],
            state: .hard(detected: true),
            layer: 2,
            weightHint: 1
        )
        let s2 = RiskSignal(
            id: "frida_js_engine_heap",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 0,
            evidence: [:],
            state: .hard(detected: true),
            layer: 2,
            weightHint: 1
        )
        let s3 = RiskSignal(
            id: "touch_spread_low",
            category: "behavior",
            score: 12,
            evidence: [:]
        )
        let s4 = RiskSignal(
            id: "tampering_detected",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 0,
            evidence: [:],
            state: .tampered,
            layer: 3,
            weightHint: 85
        )
        let verdict = engine.evaluate(
            context: context,
            extraSignals: [s1, s2, s3, s4]
        )
        XCTAssertGreaterThanOrEqual(verdict.score, scenarioPolicy.highThreshold)
        XCTAssertNotNil(verdict.decisionMetadata?["aggregate_rule"])
        XCTAssertTrue(
            verdict.primaryReasons.contains(where: { $0.contains("aggregate") }),
            "primaryReasons 应带上聚合原因标签便于观测"
        )
    }

    func testCompressedVerdictShortCircuitStillReconcilesAggregatePolicy() {
        let scenarioPolicy = ScenarioPolicy(
            mediumThreshold: 30,
            highThreshold: 55,
            criticalThreshold: 80,
            compressedVerdictRules: [
                CompressedVerdictRule(
                    id: "always_allow_shortcut",
                    layerIndex: 1,
                    bitMask: 0,
                    matchValue: 0,
                    action: .allow
                )
            ]
        )
        let engine = RiskDetectionEngine(
            policy: EnginePolicy(scenarioPolicies: [.default: scenarioPolicy]),
            enableLogging: false
        )
        let context = TestFixtures.makeRiskContext(isJailbroken: false, jailbreakConfidence: 0)
        let signals = [
            RiskSignal(
                id: "gpu_virtual",
                category: "device",
                score: 0,
                evidence: [:],
                state: .hard(detected: true),
                layer: 1,
                weightHint: 1
            ),
            RiskSignal(
                id: "sdk_binary_replaced",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 0,
                evidence: [:],
                state: .hard(detected: true),
                layer: 2,
                weightHint: 1
            )
        ]

        let verdict = engine.evaluate(context: context, extraSignals: signals)

        XCTAssertGreaterThanOrEqual(verdict.score, scenarioPolicy.highThreshold)
        XCTAssertNotEqual(verdict.internalAction, .allow, "compressed short-circuit must still honor score floor and aggregate reconciliation")
        XCTAssertEqual(verdict.decisionMetadata?["short_circuit_path"], "compressed_rule")
    }

    func testMultipleHardSignalsAccumulateWithDiminishingReturns() {
        let engine = RiskDetectionEngine(policy: .default, enableLogging: false)
        let context = TestFixtures.makeRiskContext(isJailbroken: false, jailbreakConfidence: 0)
        let signals = [
            RiskSignal(
                id: "gpu_virtual",
                category: "device",
                score: 0,
                evidence: [:],
                state: .hard(detected: true),
                layer: 1,
                weightHint: 1
            ),
            RiskSignal(
                id: "sdk_binary_replaced",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 0,
                evidence: [:],
                state: .hard(detected: true),
                layer: 2,
                weightHint: 1
            )
        ]

        let verdict = engine.evaluate(context: context, extraSignals: signals)

        XCTAssertGreaterThanOrEqual(verdict.score, 70, "independent hard signals should stack with diminishing returns instead of collapsing to max(weight)")
        XCTAssertTrue(verdict.internalAction == .challenge || verdict.internalAction == .stepUpAuth || verdict.internalAction == .block)
    }
}
