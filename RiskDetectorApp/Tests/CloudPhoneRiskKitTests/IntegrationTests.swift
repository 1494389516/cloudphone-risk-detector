import CRiskCore
import XCTest
@testable import CloudPhoneRiskKit

final class IntegrationTests: XCTestCase {

    // MARK: - End-to-End Scoring Pipeline Tests

    func testCleanDeviceFullPipeline() {
        let context = TestFixtures.makeRiskContext()
        let config = TestFixtures.defaultRiskConfig
        let report = RiskScorer.score(context: context, config: config)

        XCTAssertFalse(report.isHighRisk)
        XCTAssertLessThan(report.score, config.threshold)
        XCTAssertEqual(report.summary, "low_risk")
    }

    func testJailbrokenDeviceFullPipeline() {
        let context = TestFixtures.makeRiskContext(
            isJailbroken: true,
            jailbreakConfidence: 90,
            vpnActive: true
        )
        let config = TestFixtures.defaultRiskConfig
        let report = RiskScorer.score(context: context, config: config)

        XCTAssertTrue(report.isHighRisk)
        XCTAssertGreaterThanOrEqual(report.score, config.threshold)
    }

    func testScoringWithBehaviorAnomalies() {
        let roboticTouch = TestFixtures.makeTouchMetrics(
            coordinateSpread: 1.0,  // Too small → suspicious
            intervalCV: 0.1         // Too regular → suspicious
        )
        let context = TestFixtures.makeRiskContext(touch: roboticTouch)
        let config = TestFixtures.defaultRiskConfig
        let report = RiskScorer.score(context: context, config: config)

        // Should have behavior-related signals
        let behaviorSignals = report.signals.filter { $0.category == "behavior" }
        XCTAssertFalse(behaviorSignals.isEmpty, "Robotic touch should trigger behavior signals")
    }

    func testScoringWithNetworkSignals() {
        let context = TestFixtures.makeRiskContext(vpnActive: true, proxyEnabled: true)
        let config = TestFixtures.defaultRiskConfig
        let report = RiskScorer.score(context: context, config: config)

        let networkSignals = report.signals.filter { $0.category == "network" }
        XCTAssertFalse(networkSignals.isEmpty, "VPN + proxy should trigger network signals")
    }

    func testRiskDetectionEngineHonorsScorePolicyFloorWithoutJailbreakSignal() {
        let engine = RiskDetectionEngine(
            policy: EnginePolicy(
                forceActionOnJailbreak: nil,
                scenarioPolicies: [.login: .login]
            ),
            enableLogging: false
        )
        let context = TestFixtures.makeRiskContext(isJailbroken: false)
        let signal = RiskSignal(
            id: "rop_chain_detected",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 0,
            evidence: [:],
            state: .hard(detected: true),
            layer: 2,
            weightHint: 1
        )
        let verdict = engine.evaluate(context: context, scenario: .login, extraSignals: [signal])
        XCTAssertGreaterThanOrEqual(verdict.score, ScenarioPolicy.login.criticalThreshold)
        XCTAssertEqual(verdict.internalAction, .block)
        XCTAssertNotNil(verdict.decisionMetadata?["policy_score_floor"])
    }

    func testScoringWithAllRiskFactors() {
        let roboticTouch = TestFixtures.makeTouchMetrics(
            coordinateSpread: 0.5,
            intervalCV: 0.05
        )
        let context = TestFixtures.makeRiskContext(
            isJailbroken: true,
            jailbreakConfidence: 95,
            vpnActive: true,
            proxyEnabled: true,
            touch: roboticTouch,
            stillnessRatio: 0.99  // Almost no motion → suspicious
        )
        let config = TestFixtures.defaultRiskConfig
        let report = RiskScorer.score(context: context, config: config)

        XCTAssertTrue(report.isHighRisk)
        // With all risk factors, score should be very high
        XCTAssertGreaterThanOrEqual(report.score, 80)
    }

    // MARK: - Sign and Verify Full Flow

    func testSignedReportFullFlow() {
        let context = TestFixtures.makeRiskContext(isJailbroken: true, jailbreakConfidence: 70)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)
        let cprReport = CPRiskReport(context: context, report: report)

        let key = DeviceKeyDeriver.deriveKey(
            deviceID: "test-device-integration",
            hardwareMachine: "iPhone15,3",
            kernelVersion: "23.0.0",
            salt: Data("integration-salt".utf8)
        )

        let signed = SignedRiskConclusion.sign(report: cprReport, deviceKey: key)
        XCTAssertTrue(signed.verify(deviceKey: key, maxAgeSeconds: 60))
        XCTAssertEqual(signed.score, report.score)
        XCTAssertEqual(signed.isHighRisk, report.isHighRisk)
    }

    // MARK: - Report Envelope Full Flow

    func testReportEnvelopeFullFlow() throws {
        let context = TestFixtures.makeRiskContext()
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        let payloadData = try JSONSerialization.data(withJSONObject: [
            "score": report.score,
            "isHighRisk": report.isHighRisk,
        ])
        let signingKey = "integration-test-key-32-bytes!!"

        let envelope = try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: "integration-test",
            sessionToken: "session-integration",
            signingKey: signingKey,
            keyId: "key-int",
            fieldMapping: nil,
            config: .init()
        )

        // Verify signature
        XCTAssertTrue(envelope.verifySignature(signingKey))

        // Validate full chain
        let store = InMemoryNonceReplayStore()
        let result = envelope.validate(
            signingKey: signingKey,
            nonceStore: store,
            config: .init()
        )

        switch result {
        case .success:
            break // Expected
        case .failure(let error):
            XCTFail("Envelope validation failed: \(error)")
        }

        // Replay should fail
        let replayResult = envelope.validate(
            signingKey: signingKey,
            nonceStore: store,
            config: .init()
        )
        switch replayResult {
        case .success:
            XCTFail("Replay should have been rejected")
        case .failure:
            break // Expected - nonce already consumed
        }
    }

    func testRiskReportPayloadPromotesLibcFallbackTelemetryFields() throws {
        let context = TestFixtures.makeRiskContext()
        let mask = UInt32(CPRISK_LIBC_FALLBACK_USED_UNSUPPORTED_PLATFORM)
            | UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCTL)
        let signal = RiskSignal(
            id: SignalID.libcDirectSyscallFallback,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 18,
            evidence: [
                "mask_hex": String(mask, radix: 16),
                "libc_fallback_event_total": "2",
                "watchdog_snapshot_supported": "0",
            ],
            state: .soft(confidence: 0.7),
            layer: 1,
            weightHint: 18
        )
        let report = RiskScoreReport(
            score: 18,
            isHighRisk: false,
            signals: [signal],
            summary: "libc_fallback_observed",
            compressedDigest: nil,
            mappingVersion: nil
        )
        let cprReport = CPRiskReport(context: context, report: report)
        let payloadData = cprReport.unencryptedPayloadData()
        let payload = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: payloadData) as? [String: Any]
        )

        XCTAssertEqual(payload["lfm"] as? String, String(mask, radix: 16))
        XCTAssertEqual(payload["lfe"] as? Int, 2)
        XCTAssertEqual(payload["lfs"] as? Bool, false)
    }

    // MARK: - Negative Path Tests

    func testScoringWithNilTouchMetrics() {
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 0,
            tapCount: 0,
            swipeCount: 0,
            coordinateSpread: nil,
            intervalCV: nil,
            averageLinearity: nil
        )
        let context = TestFixtures.makeRiskContext(touch: touch)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)

        // Should not crash, should handle nil gracefully
        XCTAssertGreaterThanOrEqual(report.score, 0)
    }

    func testScoringWithZeroThreshold() {
        let context = TestFixtures.makeRiskContext()
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: true,
            threshold: 0
        )
        let report = RiskScorer.score(context: context, config: config)

        // With threshold 0, everything should be high risk
        XCTAssertTrue(report.isHighRisk)
    }

    func testScoringWithMaxThreshold() {
        let context = TestFixtures.makeRiskContext(isJailbroken: true, jailbreakConfidence: 100)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: true,
            threshold: 100
        )
        let report = RiskScorer.score(context: context, config: config)

        // Even with high jailbreak, might not reach threshold 100
        // This tests the threshold boundary
        XCTAssertGreaterThanOrEqual(report.score, 0)
    }

    func testScoringWithAllDetectionDisabled() {
        let context = TestFixtures.makeRiskContext(isJailbroken: true, jailbreakConfidence: 90)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: false,
            enableNetworkSignals: false,
            threshold: 60
        )
        let report = RiskScorer.score(context: context, config: config)

        // Jailbreak signals should still be present
        let jailbreakSignals = report.signals.filter { $0.category == "jailbreak" }
        XCTAssertFalse(jailbreakSignals.isEmpty)

        // But no behavior/network signals
        let behaviorSignals = report.signals.filter { $0.category == "behavior" }
        XCTAssertTrue(behaviorSignals.isEmpty)
    }

    func testJailbreakEngineAllDisabled() {
        let engine = JailbreakEngine()
        var config = JailbreakConfig()
        config.enableFileDetect = false
        config.enableDyldDetect = false
        config.enableEnvDetect = false
        config.enableSysctlDetect = false
        config.enableSchemeDetect = false
        config.enableHookDetect = false

        let result = engine.detect(config: config)
        XCTAssertFalse(result.isJailbroken)
        XCTAssertEqual(result.confidence, 0)
    }

    // MARK: - Config Roundtrip Tests

    func testRemoteConfigToRiskConfigRoundtrip() {
        let remote = RemoteConfig.default
        let riskConfig = remote.toRiskConfig()

        // Should produce a valid RiskConfig
        XCTAssertGreaterThan(riskConfig.threshold, 0)
        XCTAssertLessThanOrEqual(riskConfig.threshold, 100)

        // Scoring with converted config should work
        let context = TestFixtures.makeRiskContext()
        let report = RiskScorer.score(context: context, config: riskConfig)
        XCTAssertGreaterThanOrEqual(report.score, 0)
    }

    // MARK: - Storage Integrity Full Flow

    func testStorageIntegrityFullFlow() {
        let testData = Data("integration test data with special chars: 中文 日本語".utf8)
        let purpose = "integration_test"

        let signature = StorageIntegrityGuard.sign(testData, purpose: purpose)
        XCTAssertTrue(StorageIntegrityGuard.verify(testData, signature: signature, purpose: purpose))

        // Tamper
        var tampered = testData
        tampered.append(0x00)
        XCTAssertFalse(StorageIntegrityGuard.verify(tampered, signature: signature, purpose: purpose))
    }
}
