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

    func testPaymentPolicyHasComboRules() {
        let payment = ScenarioPolicy.payment
        XCTAssertFalse(payment.comboRules.isEmpty)
        let jbVpnRule = payment.comboRules.first { $0.name == "jailbreak_vpn_payment" }
        XCTAssertNotNil(jbVpnRule)
        XCTAssertEqual(jbVpnRule?.forceAction, .block)
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
