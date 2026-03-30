import XCTest
@testable import CloudPhoneRiskKit

final class RealtimeTelemetryAdaptiveTests: XCTestCase {

    private func makeRemoteConfig(
        adaptive: RealtimeTelemetryAdaptiveConfig?
    ) -> RemoteConfig {
        RemoteConfig(
            version: 100,
            policy: .default,
            detector: .default,
            whitelist: .default,
            experiments: .default,
            advanced: .default,
            realtimeTelemetryAdaptive: adaptive,
            probeConfig: nil,
            payloadFieldMapping: nil,
            securityHardening: .default,
            textSegmentHashReference: nil
        )
    }

    func testRemoteConfigDefaultAdaptiveDisabled() {
        XCTAssertNil(RemoteConfig.default.realtimeTelemetryAdaptive)
    }

    func testRemoteConfigValidationRejectsInvalidAdaptiveRange() {
        let adaptive = RealtimeTelemetryAdaptiveConfig(
            enabled: true,
            baseMinEvaluationIntervalMillis: -1,
            highPressureMinEvaluationIntervalMillis: 0,
            defaultWeightScaleBps: 10_000,
            minWeightScaleBps: 15_000,
            maxWeightScaleBps: 12_000,
            feedbackTTLSeconds: 60
        )
        let result = makeRemoteConfig(adaptive: adaptive).validate()
        XCTAssertFalse(result.isValid)
        XCTAssertTrue(result.errors.contains { $0.contains("baseMinEvaluationIntervalMillis") })
        XCTAssertTrue(result.errors.contains { $0.contains("minWeightScaleBps") })
    }

    func testProviderParsesAdaptiveHintsFromRiskTags() {
        let provider = ExternalServerAggregateProvider.shared
        provider.clear()
        provider.setDebugBypassingVerification(
            ServerSignals(
                riskTags: [
                    "rt_pressure:0.75",
                    "rt_eval_ms:1200",
                    "rt_weight_bps:11200",
                    "rt_weight_behavior_bps:12500",
                ]
            )
        )
        defer { provider.clear() }

        let snapshot = provider.realtimeAdaptiveFeedbackSnapshot()
        XCTAssertNotNil(snapshot)
        XCTAssertEqual(snapshot?.riskPressure ?? -1, 0.75, accuracy: 0.0001)
        XCTAssertEqual(snapshot?.minEvaluationIntervalMillis, 1200)
        XCTAssertEqual(snapshot?.defaultWeightScaleBps, 11_200)
        XCTAssertEqual(snapshot?.categoryWeightScaleBps["behavior"], 12_500)
    }

    func testProviderExpiredExplicitFeedbackFallsBackToRiskTags() {
        let provider = ExternalServerAggregateProvider.shared
        provider.clear()
        let now = Date().timeIntervalSince1970
        provider.setRealtimeTelemetryFeedback(
            .init(
                riskPressure: 0.95,
                minEvaluationIntervalMillis: 300,
                defaultWeightScaleBps: 13_000,
                expiresAtEpochSeconds: now - 1
            )
        )
        provider.setDebugBypassingVerification(
            ServerSignals(riskTags: ["rt_pressure:0.30"])
        )
        defer { provider.clear() }

        let snapshot = provider.realtimeAdaptiveFeedbackSnapshot(nowEpochSeconds: now)
        XCTAssertEqual(snapshot?.riskPressure ?? -1, 0.30, accuracy: 0.0001)
    }

    func testCPRiskKitAdaptiveFrequencyReusesCachedReportWithinInterval() {
        CPRiskKit.clearRealtimeTelemetryFeedback()

        let baseline = CPRiskKit.shared.evaluate()
        XCTAssertNotNil(baseline.reportID)

        CPRiskKit.setRealtimeTelemetryFeedback(
            riskPressure: nil,
            minEvaluationIntervalMillis: NSNumber(value: 30_000),
            defaultWeightScaleBps: nil,
            jailbreakWeightScaleBps: nil,
            networkWeightScaleBps: nil,
            behaviorWeightScaleBps: nil,
            deviceWeightScaleBps: nil,
            timeWeightScaleBps: nil,
            ttlSeconds: NSNumber(value: 60)
        )
        let first = CPRiskKit.shared.evaluate()
        let second = CPRiskKit.shared.evaluate()
        XCTAssertTrue(first === second, "在最小评估间隔内应复用缓存报告")

        CPRiskKit.clearRealtimeTelemetryFeedback()
        let third = CPRiskKit.shared.evaluate()
        XCTAssertFalse(second === third, "关闭自适应反馈后应恢复常规评估")
    }
}
