import XCTest
@testable import CloudPhoneRiskKit

final class SecureUploadWiringTests: XCTestCase {

    override func setUp() {
        super.setUp()
        let kit = CPRiskKit.shared
        kit.clearRemoteConfigEndpoint()
        kit.clearServerRiskPolicy()
    }

    override func tearDown() {
        let kit = CPRiskKit.shared
        kit.clearRemoteConfigEndpoint()
        kit.clearServerRiskPolicy()
        super.tearDown()
    }

    func testSecureEnvelopeUsesRemoteFieldMapping() throws {
        let mapping = PayloadFieldMapping(
            version: "m-2026-03-04",
            mappings: [
                "score": "f_a7x2k",
                "tamperedCount": "q_9m3p",
            ]
        )
        let remoteConfig = makeRemoteConfig(
            payloadFieldMapping: mapping,
            securityHardening: SecurityHardeningConfig(
                enableEnvelopeSignatureV2: true,
                enforcePayloadFieldMapping: true,
                enableChallengeBinding: true,
                killSwitchEnabled: false
            )
        )

        let kit = CPRiskKit.shared
        XCTAssertTrue(kit.setRemoteConfigJSON(try jsonString(remoteConfig)))

        let report = kit.evaluate(config: .default, scenario: .default)
        let envelope = try kit.buildSecureReportEnvelope(
            report: report,
            sessionToken: "session-1",
            signingKey: "secret-1"
        )

        XCTAssertEqual(envelope.fieldMappingVersion, "m-2026-03-04")
        let payloadObject = try XCTUnwrap(try JSONSerialization.jsonObject(with: envelope.payload, options: []) as? [String: Any])
        XCTAssertNotNil(payloadObject["f_a7x2k"])
        XCTAssertNotNil(payloadObject["q_9m3p"])
        XCTAssertNil(payloadObject["score"])
        XCTAssertTrue(envelope.verifySignature("secret-1"))
    }

    func testSecureEnvelopeThrowsWhenMappingRequiredButMissing() throws {
        let remoteConfig = makeRemoteConfig(
            payloadFieldMapping: nil,
            securityHardening: SecurityHardeningConfig(
                enableEnvelopeSignatureV2: true,
                enforcePayloadFieldMapping: true,
                enableChallengeBinding: true,
                killSwitchEnabled: false
            )
        )

        let kit = CPRiskKit.shared
        XCTAssertTrue(kit.setRemoteConfigJSON(try jsonString(remoteConfig)))
        let report = kit.evaluate(config: .default, scenario: .default)

        XCTAssertThrowsError(
            try kit.buildSecureReportEnvelope(
                report: report,
                sessionToken: "session-2",
                signingKey: "secret-2"
            )
        ) { error in
            guard case CPRiskKit.SecureUploadError.payloadFieldMappingRequired = error else {
                return XCTFail("期望 payloadFieldMappingRequired，实际: \(error)")
            }
        }
    }

    func testEvaluateWiresChallengeBindingWhenRuleHit() throws {
        let remoteConfig = makeRemoteConfig(
            probeConfig: ProbeConfig(
                version: "probe-v-test",
                probes: [
                    ProbeConfigItem(
                        id: "unknown_probe",
                        expectedOutcome: "pass",
                        maxElapsedUs: 80,
                        weight: 1
                    ),
                ]
            ),
            securityHardening: SecurityHardeningConfig(
                enableEnvelopeSignatureV2: true,
                enforcePayloadFieldMapping: false,
                enableChallengeBinding: true,
                killSwitchEnabled: false
            )
        )

        let blindChallenge = ServerRiskPolicy.BlindChallengeConfig(
            enabled: true,
            challengeSalt: "salt-test",
            windowSeconds: 300,
            probePool: ["unknown_probe", "stat_bash", "sock_27042"],
            challengeTTLMillis: 120_000,
            rules: [
                ServerRiskPolicy.BlindRule(
                    id: "capability_rule",
                    minTamperedCount: 0,
                    minCapabilityAnomalyCount: 1,
                    weight: 85
                ),
            ]
        )
        let serverPolicy = ServerRiskPolicy(
            version: 1,
            signalWeights: [:],
            thresholds: .init(block: 90, challenge: 70, monitor: 40),
            blindChallenge: blindChallenge
        )

        let kit = CPRiskKit.shared
        XCTAssertTrue(kit.setRemoteConfigJSON(try jsonString(remoteConfig)))
        XCTAssertTrue(kit.setServerRiskPolicyJSON(try jsonString(serverPolicy)))

        let report = kit.evaluate(config: .default, scenario: .payment)
        let binding = try XCTUnwrap(report.challengeBinding())

        XCTAssertFalse(binding.challengeId.isEmpty)
        XCTAssertGreaterThanOrEqual(binding.capabilityAnomalyCount, 1)
        XCTAssertFalse(binding.executedProbeIds.isEmpty)
        XCTAssertFalse(binding.probeIds.isEmpty)
        XCTAssertGreaterThanOrEqual(binding.tamperedCount, 0)
        XCTAssertFalse((binding.triggerReason ?? "").isEmpty)
    }

    private func makeRemoteConfig(
        probeConfig: ProbeConfig? = nil,
        payloadFieldMapping: PayloadFieldMapping? = nil,
        securityHardening: SecurityHardeningConfig = .default
    ) -> RemoteConfig {
        RemoteConfig(
            version: 20260304,
            policy: .default,
            detector: .default,
            whitelist: .default,
            experiments: .default,
            advanced: .default,
            probeConfig: probeConfig,
            payloadFieldMapping: payloadFieldMapping,
            securityHardening: securityHardening
        )
    }

    private func jsonString<T: Encodable>(_ value: T) throws -> String {
        let data = try JSONEncoder().encode(value)
        guard let string = String(data: data, encoding: .utf8) else {
            throw NSError(domain: "SecureUploadWiringTests", code: -1)
        }
        return string
    }
}
