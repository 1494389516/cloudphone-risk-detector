import XCTest
@testable import CloudPhoneRiskKit

final class RiskVerdictTests: XCTestCase {

    // MARK: - Convenience Init

    func testVerdictFromScoreAndPolicy() {
        let signals = [
            RiskSignal(id: "vpn_active", category: "network", score: 10, evidence: [:]),
        ]
        let verdict = RiskVerdict(
            score: 40,
            confidence: 0.7,
            signals: signals,
            scenario: .login,
            policy: .general
        )
        XCTAssertEqual(verdict.score, 40)
        XCTAssertEqual(verdict.internalLevel, .medium)
        XCTAssertEqual(verdict.level, .medium)
        XCTAssertEqual(verdict.internalAction, .allow)
        XCTAssertEqual(verdict.action, .allow)
        XCTAssertEqual(verdict.scenario, .login)
        XCTAssertFalse(verdict.isHighRisk)
        XCTAssertFalse(verdict.shouldBlock)
    }

    func testVerdictHighRiskScore() {
        let verdict = RiskVerdict(
            score: 70,
            confidence: 0.9,
            signals: [],
            scenario: .payment,
            policy: .general
        )
        XCTAssertEqual(verdict.internalLevel, .high)
        XCTAssertTrue(verdict.isHighRisk)
        XCTAssertTrue(verdict.requiresUserInteraction)
        XCTAssertEqual(verdict.internalAction, .challenge)
    }

    func testVerdictCriticalScore() {
        let verdict = RiskVerdict(
            score: 90,
            confidence: 0.95,
            signals: [],
            scenario: .payment,
            policy: .general
        )
        XCTAssertEqual(verdict.internalLevel, .critical)
        XCTAssertTrue(verdict.isHighRisk)
        XCTAssertTrue(verdict.shouldBlock)
        XCTAssertEqual(verdict.internalAction, .block)
    }

    // MARK: - Payment Policy Verdict

    func testPaymentPolicyBlocksHighRisk() {
        let verdict = RiskVerdict(
            score: 55,
            confidence: 0.8,
            signals: [],
            scenario: .payment,
            policy: .payment
        )
        XCTAssertEqual(verdict.internalAction, .block)
        XCTAssertTrue(verdict.shouldBlock)
    }

    // MARK: - From RiskScoreReport

    func testVerdictFromReport() {
        let context = TestFixtures.makeRiskContext(isJailbroken: true, jailbreakConfidence: 80)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)
        let verdict = RiskVerdict.from(report: report, context: context, scenario: .login)

        XCTAssertEqual(verdict.score, report.score)
        XCTAssertTrue(verdict.isHighRisk)
        XCTAssertEqual(verdict.scenario, .login)
    }

    // MARK: - Summary

    func testVerdictSummary() {
        let blocked = RiskVerdict(
            score: 90,
            internalLevel: .critical,
            internalAction: .block,
            confidence: 1.0,
            primaryReasons: ["jailbreak"],
            signals: [],
            scenario: .payment
        )
        XCTAssertEqual(blocked.summary, "blocked(critical)")

        let allowed = RiskVerdict(
            score: 10,
            internalLevel: .low,
            internalAction: .allow,
            confidence: 0.5,
            primaryReasons: [],
            signals: [],
            scenario: .default
        )
        XCTAssertEqual(allowed.summary, "allowed(low)")

        let challenged = RiskVerdict(
            score: 50,
            internalLevel: .medium,
            internalAction: .challenge,
            confidence: 0.7,
            primaryReasons: ["vpn"],
            signals: [],
            scenario: .login
        )
        XCTAssertEqual(challenged.summary, "challenged(medium)")
    }

    // MARK: - Codable

    func testVerdictCodable() throws {
        let verdict = RiskVerdict(
            score: 50,
            internalLevel: .medium,
            internalAction: .challenge,
            confidence: 0.7,
            primaryReasons: ["vpn_active"],
            signals: [RiskSignal(id: "vpn_active", category: "network", score: 10, evidence: [:])],
            scenario: .login
        )
        let data = try JSONEncoder().encode(verdict)
        let decoded = try JSONDecoder().decode(RiskVerdict.self, from: data)
        XCTAssertEqual(decoded.score, verdict.score)
        XCTAssertEqual(decoded.internalLevel, verdict.internalLevel)
        XCTAssertEqual(decoded.internalAction, verdict.internalAction)
        XCTAssertEqual(decoded.scenario, verdict.scenario)
    }

    func testVerdictCodableRoundTripWithDecisionMetadata() throws {
        let verdict = RiskVerdict(
            score: 88,
            internalLevel: .critical,
            internalAction: .block,
            confidence: 0.9,
            primaryReasons: ["anti_tamper_x"],
            signals: [],
            scenario: .default,
            decisionMetadata: ["policy_score_floor": "1", "aggregate_rule": "frida_cluster"]
        )
        let data = try JSONEncoder().encode(verdict)
        let decoded = try JSONDecoder().decode(RiskVerdict.self, from: data)
        XCTAssertEqual(decoded.decisionMetadata?["policy_score_floor"], "1")
        XCTAssertEqual(decoded.decisionMetadata?["aggregate_rule"], "frida_cluster")
    }
}
