import XCTest
@testable import CloudPhoneRiskKit

/// 敏感场景下 `certificate_pinning_anomaly` 的决策底线（与纯网络权重聚合解耦）。
final class CertificatePinningScenarioFloorTests: XCTestCase {

    private func engine() -> RiskDetectionEngine {
        RiskDetectionEngine(
            policy: EnginePolicy(
                forceActionOnJailbreak: nil,
                scenarioPolicies: [
                    .payment: .payment,
                    .register: .register,
                    .login: .login,
                    .default: .general,
                ]
            ),
            enableLogging: false
        )
    }

    private func cleanContext() -> RiskContext {
        TestFixtures.makeRiskContext(isJailbroken: false, jailbreakConfidence: 0)
    }

    func testPaymentSoftPinningRaisesToMediumFloorStepUpAuth() {
        let pin = RiskSignal(
            id: SignalID.certificatePinningAnomaly,
            category: "network",
            score: 38,
            evidence: ["kind": "trustEvalSuspiciouslyFast"],
            state: .soft(confidence: 0.55)
        )
        let verdict = engine().evaluate(context: cleanContext(), scenario: .payment, extraSignals: [pin])
        XCTAssertGreaterThanOrEqual(verdict.score, ScenarioPolicy.payment.mediumThreshold)
        XCTAssertEqual(verdict.internalAction, .stepUpAuth)
        XCTAssertEqual(verdict.decisionMetadata?["pinning_floor_tier"], "soft_timing")
        XCTAssertEqual(verdict.decisionMetadata?["pinning_floor_applied"], "1")
    }

    func testPaymentHardPinningRaisesToHighFloorBlock() {
        let pin = RiskSignal(
            id: SignalID.certificatePinningAnomaly,
            category: "network",
            score: 65,
            evidence: ["kind": "pinMismatch"],
            state: .hard(detected: true)
        )
        let verdict = engine().evaluate(context: cleanContext(), scenario: .payment, extraSignals: [pin])
        XCTAssertGreaterThanOrEqual(verdict.score, ScenarioPolicy.payment.highThreshold)
        XCTAssertEqual(verdict.internalAction, .block)
    }

    func testPaymentTamperedPinningForcesBlockAtCriticalFloor() {
        let pin = RiskSignal(
            id: SignalID.certificatePinningAnomaly,
            category: "network",
            score: 78,
            evidence: ["kind": "integrityRecheckTamper"],
            state: .tampered
        )
        let verdict = engine().evaluate(context: cleanContext(), scenario: .payment, extraSignals: [pin])
        XCTAssertGreaterThanOrEqual(verdict.score, ScenarioPolicy.payment.criticalThreshold)
        XCTAssertEqual(verdict.internalAction, .block)
        XCTAssertEqual(verdict.decisionMetadata?["pinning_floor_tier"], "tampered_path")
    }

    func testDefaultScenarioDoesNotApplySensitivePinningFloor() {
        let pin = RiskSignal(
            id: SignalID.certificatePinningAnomaly,
            category: "network",
            score: 38,
            evidence: [:],
            state: .soft(confidence: 0.55)
        )
        let verdict = engine().evaluate(context: cleanContext(), scenario: .default, extraSignals: [pin])
        XCTAssertNil(verdict.decisionMetadata?["pinning_floor_applied"])
        XCTAssertLessThan(verdict.score, ScenarioPolicy.general.mediumThreshold)
    }

    func testRegisterSoftPinningRaisesToChallengeTier() {
        let pin = RiskSignal(
            id: SignalID.certificatePinningAnomaly,
            category: "network",
            score: 38,
            evidence: [:],
            state: .soft(confidence: 0.55)
        )
        let verdict = engine().evaluate(context: cleanContext(), scenario: .register, extraSignals: [pin])
        XCTAssertGreaterThanOrEqual(verdict.score, ScenarioPolicy.register.mediumThreshold)
        XCTAssertEqual(verdict.internalAction, .challenge)
    }

    func testStrongestTierWinsWhenMultiplePinningSignalsPresent() {
        let soft = RiskSignal(
            id: SignalID.certificatePinningAnomaly,
            category: "network",
            score: 38,
            evidence: ["seq": "1"],
            state: .soft(confidence: 0.55)
        )
        let hard = RiskSignal(
            id: SignalID.certificatePinningAnomaly,
            category: "network",
            score: 65,
            evidence: ["seq": "2"],
            state: .hard(detected: true)
        )
        let verdict = engine().evaluate(context: cleanContext(), scenario: .payment, extraSignals: [soft, hard])
        XCTAssertGreaterThanOrEqual(verdict.score, ScenarioPolicy.payment.highThreshold)
        XCTAssertEqual(verdict.decisionMetadata?["pinning_floor_tier"], "hard_integrity")
    }
}
