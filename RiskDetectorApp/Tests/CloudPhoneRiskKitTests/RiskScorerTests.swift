import XCTest
@testable import CloudPhoneRiskKit

final class RiskScorerTests: XCTestCase {

    // MARK: - Clean Device (No Risk)

    func testCleanDeviceScoresLow() {
        let context = TestFixtures.makeRiskContext()
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        XCTAssertLessThan(report.score, 60)
        XCTAssertFalse(report.isHighRisk)
        XCTAssertEqual(report.summary, "low_risk")
    }

    // MARK: - Jailbreak Scoring

    func testJailbrokenDeviceIsHighRisk() {
        let context = TestFixtures.makeRiskContext(isJailbroken: true, jailbreakConfidence: 80)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        XCTAssertTrue(report.isHighRisk)
        XCTAssertGreaterThanOrEqual(report.score, 60)
        XCTAssertEqual(report.summary, "high_risk(jailbreak)")
    }

    func testJailbreakScoreContribution() {
        let context = TestFixtures.makeRiskContext(isJailbroken: true, jailbreakConfidence: 100)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        let jailbreakSignal = report.signals.first { $0.id == "jailbreak" }
        XCTAssertNotNil(jailbreakSignal)
        XCTAssertEqual(jailbreakSignal?.score, 100)
        XCTAssertEqual(jailbreakSignal?.category, "jailbreak")
    }

    func testJailbrokenBumpsScoreToThreshold() {
        let context = TestFixtures.makeRiskContext(isJailbroken: true, jailbreakConfidence: 10)
        let config = RiskConfig(threshold: 60)
        let report = RiskScorer.score(context: context, config: config)

        XCTAssertTrue(report.isHighRisk)
        XCTAssertGreaterThanOrEqual(report.score, 60)
    }

    func testConfidenceCappedAt100() {
        let context = TestFixtures.makeRiskContext(isJailbroken: true, jailbreakConfidence: 200)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        XCTAssertLessThanOrEqual(report.score, 100)
    }

    // MARK: - Network Signals

    func testVPNAddsScore() {
        let context = TestFixtures.makeRiskContext(vpnActive: true)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        let vpnSignal = report.signals.first { $0.id == "vpn_active" }
        XCTAssertNotNil(vpnSignal)
        XCTAssertEqual(vpnSignal?.score, 10)
    }

    func testProxyAddsScore() {
        let context = TestFixtures.makeRiskContext(proxyEnabled: true)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        let proxySignal = report.signals.first { $0.id == "proxy_enabled" }
        XCTAssertNotNil(proxySignal)
        XCTAssertEqual(proxySignal?.score, 8)
    }

    func testNetworkSignalsDisabled() {
        let context = TestFixtures.makeRiskContext(vpnActive: true, proxyEnabled: true)
        let config = RiskConfig(enableNetworkSignals: false)
        let report = RiskScorer.score(context: context, config: config)

        XCTAssertNil(report.signals.first { $0.id == "vpn_active" })
        XCTAssertNil(report.signals.first { $0.id == "proxy_enabled" })
    }

    // MARK: - Behavior Scoring

    func testLowCoordinateSpreadAddsScore() {
        let touch = TestFixtures.makeTouchMetrics(coordinateSpread: 1.0)
        let context = TestFixtures.makeRiskContext(touch: touch)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        let signal = report.signals.first { $0.id == "touch_spread_low" }
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.score, 12)
    }

    func testTooRegularIntervalAddsScore() {
        let touch = TestFixtures.makeTouchMetrics(intervalCV: 0.1)
        let context = TestFixtures.makeRiskContext(touch: touch)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        let signal = report.signals.first { $0.id == "touch_interval_too_regular" }
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.score, 10)
    }

    func testBehaviorDisabledSkipsBehaviorSignals() {
        let touch = TestFixtures.makeTouchMetrics(coordinateSpread: 1.0, intervalCV: 0.1)
        let context = TestFixtures.makeRiskContext(touch: touch)
        let config = RiskConfig(enableBehaviorDetect: false)
        let report = RiskScorer.score(context: context, config: config)

        let behaviorSignals = report.signals.filter { $0.category == "behavior" }
        XCTAssertTrue(behaviorSignals.isEmpty)
    }

    func testBehaviorScoreCappedAt30() {
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 2,
            tapCount: 1,
            swipeCount: 0,
            coordinateSpread: 0.5,
            intervalCV: 0.05,
            averageLinearity: 0.99
        )
        let context = TestFixtures.makeRiskContext(touch: touch, stillnessRatio: 0.99)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        let behaviorTotal = report.signals.filter { $0.category == "behavior" }.reduce(0.0) { $0 + $1.score }
        XCTAssertLessThanOrEqual(behaviorTotal, 30)
    }

    func testMotionTooStillAddsScore() {
        let touch = TestFixtures.makeTouchMetrics(tapCount: 8, swipeCount: 5)
        let context = TestFixtures.makeRiskContext(touch: touch, stillnessRatio: 0.99)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        let signal = report.signals.first { $0.id == "motion_too_still" }
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.score, 10)
    }

    func testInsufficientBehaviorDataAddsSignal() {
        let touch = TestFixtures.makeTouchMetrics(sampleCount: 2, tapCount: 1, swipeCount: 0)
        let context = TestFixtures.makeRiskContext(touch: touch)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        let signal = report.signals.first { $0.id == "insufficient_behavior_data" }
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.score, 5)
    }

    // MARK: - Extra Signals

    func testExtraSignalsCappedAt20() {
        let context = TestFixtures.makeRiskContext()
        let extras = [
            RiskSignal(id: "custom1", category: "custom", score: 15, evidence: [:]),
            RiskSignal(id: "custom2", category: "custom", score: 15, evidence: [:]),
        ]
        let baseReport = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig, extraSignals: extras)

        // Raw sum of extra signal scores = 30, but the cap limits contribution to 20.
        // Verify the actual score delta equals the cap (20), not the raw sum (30).
        XCTAssertEqual(report.score, baseReport.score + 20, accuracy: 0.001,
            "Extra signals (raw sum=30) should contribute capped 20, not 30, to final score")

        XCTAssertLessThanOrEqual(report.score, 100)
    }

    func testDuplicateExtraSignalsDeduped() {
        let context = TestFixtures.makeRiskContext()
        let extras = [
            RiskSignal(id: "dup", category: "test", score: 10, evidence: [:]),
            RiskSignal(id: "dup", category: "test", score: 10, evidence: [:]),
        ]
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig, extraSignals: extras)

        let duped = report.signals.filter { $0.id == "dup" }
        XCTAssertEqual(duped.count, 1)
    }

    // MARK: - Total Score Cap

    func testTotalScoreCappedAt100() {
        let context = TestFixtures.makeRiskContext(
            isJailbroken: true,
            jailbreakConfidence: 100,
            vpnActive: true,
            proxyEnabled: true
        )
        let extras = [
            RiskSignal(id: "extra", category: "extra", score: 20, evidence: [:]),
        ]
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig, extraSignals: extras)

        XCTAssertLessThanOrEqual(report.score, 100)
    }

    // MARK: - Threshold

    func testCustomThreshold() {
        let context = TestFixtures.makeRiskContext(vpnActive: true, proxyEnabled: true)
        let lowThreshold = RiskConfig(threshold: 10)
        let highThreshold = RiskConfig(threshold: 90)

        let lowReport = RiskScorer.score(context: context, config: lowThreshold)
        let highReport = RiskScorer.score(context: context, config: highThreshold)

        XCTAssertTrue(lowReport.isHighRisk)
        XCTAssertFalse(highReport.isHighRisk)
    }
}
