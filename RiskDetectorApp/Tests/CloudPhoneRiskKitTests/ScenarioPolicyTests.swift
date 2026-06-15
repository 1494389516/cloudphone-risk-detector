import XCTest
@testable import CloudPhoneRiskKit

final class ScenarioPolicyTests: XCTestCase {

    // MARK: - Default Thresholds

    func testGeneralPolicyThresholds() {
        let policy = ScenarioPolicy.general
        XCTAssertEqual(policy.mediumThreshold, 30)
        XCTAssertEqual(policy.highThreshold, 55)
        XCTAssertEqual(policy.criticalThreshold, 80)
    }

    func testPaymentPolicyIsStricter() {
        let payment = ScenarioPolicy.payment
        let general = ScenarioPolicy.general
        XCTAssertLessThan(payment.mediumThreshold, general.mediumThreshold)
        XCTAssertLessThan(payment.highThreshold, general.highThreshold)
        XCTAssertLessThan(payment.criticalThreshold, general.criticalThreshold)
    }

    func testSensitiveActionPolicyIsStrictest() {
        let sensitive = ScenarioPolicy.sensitiveAction
        for scenario in RiskScenario.allCases {
            let policy = ScenarioPolicy.policy(for: scenario)
            if scenario != .sensitiveAction {
                XCTAssertLessThanOrEqual(
                    sensitive.mediumThreshold, policy.mediumThreshold,
                    "sensitiveAction should have lowest or equal mediumThreshold vs \(scenario)"
                )
            }
        }
    }

    // MARK: - Action Mapping

    func testGeneralPolicyDefaultActions() {
        let policy = ScenarioPolicy.general
        XCTAssertEqual(policy.action(for: .low), .allow)
        XCTAssertEqual(policy.action(for: .medium), .allow)
        XCTAssertEqual(policy.action(for: .high), .challenge)
        XCTAssertEqual(policy.action(for: .critical), .block)
    }

    func testPaymentPolicyBlocksHighRisk() {
        let policy = ScenarioPolicy.payment
        XCTAssertEqual(policy.action(for: .high), .block)
        XCTAssertEqual(policy.action(for: .critical), .block)
    }

    func testSensitiveActionChallengesEvenLowRisk() {
        let policy = ScenarioPolicy.sensitiveAction
        XCTAssertEqual(policy.action(for: .low), .challenge)
    }

    // MARK: - Signal Weights

    func testDefaultSignalWeightsAreOne() {
        let weights = SignalWeights.default
        XCTAssertEqual(weights.jailbreak, 1.0)
        XCTAssertEqual(weights.network, 1.0)
        XCTAssertEqual(weights.behavior, 1.0)
        XCTAssertEqual(weights.device, 1.0)
        XCTAssertEqual(weights.time, 1.0)
    }

    func testSignalWeightForCategory() {
        let weights = SignalWeights(jailbreak: 0.8, network: 1.2, behavior: 1.0, device: 1.5, time: 0.7)
        XCTAssertEqual(weights.weight(for: "jailbreak"), 0.8)
        XCTAssertEqual(weights.weight(for: "network"), 1.2)
        XCTAssertEqual(weights.weight(for: "JAILBREAK"), 0.8)
        XCTAssertEqual(weights.weight(for: "unknown_category"), 1.0)
    }

    func testLoginPolicyWeightsBehaviorHigher() {
        let login = ScenarioPolicy.login
        XCTAssertGreaterThan(login.signalWeights.behavior, 1.0)
    }

    // MARK: - Combo Rules

    func testComboRuleMatching() {
        let rule = ComboRule(
            name: "jb_vpn",
            requiredSignals: ["jailbreak", "vpn_active"],
            bonusScore: 40,
            forceAction: .block
        )
        let matchSignals = [
            RiskSignal(id: "jailbreak", category: "jailbreak", score: 50, evidence: [:]),
            RiskSignal(id: "vpn_active", category: "network", score: 10, evidence: [:]),
        ]
        XCTAssertTrue(rule.matches(signals: matchSignals))
    }

    func testComboRuleNotMatching() {
        let rule = ComboRule(
            name: "jb_vpn",
            requiredSignals: ["jailbreak", "vpn_active"],
            bonusScore: 40
        )
        let partialSignals = [
            RiskSignal(id: "jailbreak", category: "jailbreak", score: 50, evidence: [:]),
        ]
        XCTAssertFalse(rule.matches(signals: partialSignals))
    }

    /// N-of-M 带权：抑制单个低权重信号仍命中（鲁棒性），仅抑制最高权重信号才逃逸，
    /// 且合法设备凑不出高权重组合（低误报）。镜像 impossible_states 的权重设计。
    func testComboRuleWeightedNofMMatching() {
        let rule = ComboRule(
            name: "impossible_weighted",
            requiredSignals: [
                "screen_captured", "battery_state_static", "usb_audio_routed",
                "no_cellular_provider", "biometric_not_enrolled",
            ],
            bonusScore: 100,
            forceAction: .block,
            weightThreshold: 70,
            signalWeights: [
                "usb_audio_routed": 34, "battery_state_static": 26, "screen_captured": 18,
                "no_cellular_provider": 11, "biometric_not_enrolled": 11,
            ],
            minimumMatchedCount: 4,
            mandatorySignals: ["usb_audio_routed"]
        )
        func sig(_ id: String) -> RiskSignal { RiskSignal(id: id, category: "device", score: 1, evidence: [:]) }
        let all = ["screen_captured", "battery_state_static", "usb_audio_routed",
                   "no_cellular_provider", "biometric_not_enrolled"]

        // 全 5 信号 -> 100 >= 70，命中。
        XCTAssertTrue(rule.matches(signals: all.map(sig)))
        // 抑制低权重信号（no_cellular，11）-> 89 >= 70，仍命中（硬 AND 下会逃逸）。
        XCTAssertTrue(rule.matches(signals: all.filter { $0 != "no_cellular_provider" }.map(sig)))
        // 抑制次高权重（battery，26）-> 74 >= 70，仍命中。
        XCTAssertTrue(rule.matches(signals: all.filter { $0 != "battery_state_static" }.map(sig)))
        // 抑制最高权重（usb_audio，34）-> 66 < 70，逃逸（最难伪造信号是唯一杀手锏）。
        XCTAssertFalse(rule.matches(signals: all.filter { $0 != "usb_audio_routed" }.map(sig)))
        // 合法 WiFi-iPad 易误报组合（无 usb_audio）-> 66 < 70，不误报。
        XCTAssertFalse(rule.matches(signals: ["screen_captured", "battery_state_static",
                                              "no_cellular_provider", "biometric_not_enrolled"].map(sig)))
        // 仅 3 个信号即使权重过阈值（34+26+11=71），也不能直接 force block。
        XCTAssertFalse(rule.matches(signals: ["usb_audio_routed", "battery_state_static",
                                              "no_cellular_provider"].map(sig)))
        // 仅两个低权重信号 -> 22 < 70，不命中。
        XCTAssertFalse(rule.matches(signals: ["no_cellular_provider", "biometric_not_enrolled"].map(sig)))
    }

    func testComboRuleInvalidWeightedConfigFallsBackToHardAnd() {
        let rule = ComboRule(
            name: "invalid_weighted",
            requiredSignals: ["a", "b"],
            bonusScore: 10,
            weightThreshold: 0,
            signalWeights: ["a": 10, "b": 10]
        )
        func sig(_ id: String) -> RiskSignal { RiskSignal(id: id, category: "device", score: 1, evidence: [:]) }

        XCTAssertFalse(rule.matches(signals: []), "非法阈值不能让加权规则空信号命中")
        XCTAssertFalse(rule.matches(signals: ["a"].map(sig)), "非法阈值应回退硬 AND，而不是部分命中")
        XCTAssertTrue(rule.matches(signals: ["a", "b"].map(sig)), "回退硬 AND 后完整 required 信号仍应命中")
    }

    func testPaymentPolicyHasComboRules() {
        let payment = ScenarioPolicy.payment
        XCTAssertFalse(payment.comboRules.isEmpty)
        let jbVpnRule = payment.comboRules.first { $0.name == "jailbreak_vpn_payment" }
        XCTAssertNotNil(jbVpnRule)
        XCTAssertEqual(jbVpnRule?.forceAction, .block)
    }

    func testGeneralPolicyIncludesBatteryAndTimeFusionRules() {
        let policy = ScenarioPolicy.general
        let batteryRule = policy.comboRules.first { $0.name == "CR-004_impossible_no_cellular_power" }
        let timeRule = policy.comboRules.first { $0.name == "CR-006_time_anomaly_combo" }

        XCTAssertNotNil(batteryRule)
        XCTAssertEqual(
            Set(batteryRule?.requiredSignals ?? []),
            Set(["no_cellular_provider", SignalID.batteryLevelStatic, SignalID.noChargeStateChange])
        )
        XCTAssertNotNil(timeRule)
        XCTAssertEqual(
            Set(timeRule?.requiredSignals ?? []),
            Set([SignalID.bootTimeRollback, SignalID.systemTimeJump, SignalID.installDateUnusual])
        )
    }

    // MARK: - Policy for Scenario

    func testPolicyForScenarioMapping() {
        XCTAssertEqual(ScenarioPolicy.policy(for: .default).mediumThreshold, ScenarioPolicy.general.mediumThreshold)
        XCTAssertEqual(ScenarioPolicy.policy(for: .login).mediumThreshold, ScenarioPolicy.login.mediumThreshold)
        XCTAssertEqual(ScenarioPolicy.policy(for: .payment).mediumThreshold, ScenarioPolicy.payment.mediumThreshold)
        XCTAssertEqual(ScenarioPolicy.policy(for: .register).mediumThreshold, ScenarioPolicy.register.mediumThreshold)
        XCTAssertEqual(ScenarioPolicy.policy(for: .query).mediumThreshold, ScenarioPolicy.general.mediumThreshold)
    }

    // MARK: - ScenarioPolicyBuilder

    func testPolicyBuilder() {
        let policy = ScenarioPolicyBuilder()
            .setThresholds(medium: 20, high: 40, critical: 70)
            .setAction(.block, for: .high)
            .setAction(.block, for: .critical)
            .setSignalWeights(SignalWeights(jailbreak: 1.5))
            .addComboRule(ComboRule(name: "test_combo", requiredSignals: ["a", "b"], bonusScore: 10))
            .build()

        XCTAssertEqual(policy.mediumThreshold, 20)
        XCTAssertEqual(policy.highThreshold, 40)
        XCTAssertEqual(policy.criticalThreshold, 70)
        XCTAssertEqual(policy.action(for: .high), .block)
        XCTAssertEqual(policy.signalWeights.jailbreak, 1.5)
        XCTAssertEqual(policy.comboRules.count, 1)
    }

    // MARK: - Codable

    func testScenarioPolicyCodable() throws {
        let policy = ScenarioPolicy.payment
        let data = try JSONEncoder().encode(policy)
        let decoded = try JSONDecoder().decode(ScenarioPolicy.self, from: data)
        XCTAssertEqual(decoded.mediumThreshold, policy.mediumThreshold)
        XCTAssertEqual(decoded.highThreshold, policy.highThreshold)
        XCTAssertEqual(decoded.criticalThreshold, policy.criticalThreshold)
        XCTAssertEqual(decoded.comboRules.count, policy.comboRules.count)
    }
}
