import XCTest
@testable import CloudPhoneRiskKit

final class CryptoTests: XCTestCase {

    // MARK: - PayloadFieldObfuscator Tests

    func testObfuscateAndDeobfuscateRoundtrip() throws {
        let original: [String: Any] = [
            "score": 75.5,
            "isHighRisk": true,
            "device_model": "iPhone15,3",
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: original)
        let mapping = PayloadFieldMapping(
            version: "v1",
            mappings: ["score": "s", "isHighRisk": "hr", "device_model": "dm"],
            expiresAtMillis: nil
        )

        let obfuscated = try PayloadFieldObfuscator.obfuscate(jsonData: jsonData, mapping: mapping)
        let deobfuscated = try PayloadFieldObfuscator.deobfuscate(jsonData: obfuscated, mapping: mapping)

        let restored = try JSONSerialization.jsonObject(with: deobfuscated) as! [String: Any]
        XCTAssertEqual(restored["score"] as? Double, 75.5)
        XCTAssertEqual(restored["isHighRisk"] as? Bool, true)
        XCTAssertEqual(restored["device_model"] as? String, "iPhone15,3")
    }

    func testObfuscateRenamesKeys() throws {
        let original: [String: Any] = ["score": 42]
        let jsonData = try JSONSerialization.data(withJSONObject: original)
        let mapping = PayloadFieldMapping(
            version: "v1",
            mappings: ["score": "s"],
            expiresAtMillis: nil
        )

        let obfuscated = try PayloadFieldObfuscator.obfuscate(jsonData: jsonData, mapping: mapping)
        let result = try JSONSerialization.jsonObject(with: obfuscated) as! [String: Any]

        XCTAssertNil(result["score"])
        XCTAssertEqual(result["s"] as? Int, 42)
    }

    func testObfuscatePreservesUnmappedKeys() throws {
        let original: [String: Any] = ["unmapped_key": "value"]
        let jsonData = try JSONSerialization.data(withJSONObject: original)
        let mapping = PayloadFieldMapping(
            version: "v1",
            mappings: ["score": "s"],
            expiresAtMillis: nil
        )

        let obfuscated = try PayloadFieldObfuscator.obfuscate(jsonData: jsonData, mapping: mapping)
        let result = try JSONSerialization.jsonObject(with: obfuscated) as! [String: Any]

        XCTAssertEqual(result["unmapped_key"] as? String, "value")
    }

    // MARK: - ReportEnvelope Tests

    func testReportEnvelopeCreateAndVerify() throws {
        let payloadData = try JSONSerialization.data(withJSONObject: ["score": 75])
        let signingKey = "test-signing-key-32-bytes-long!!"

        let envelope = try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: "report-123",
            sessionToken: "session-456",
            signingKey: signingKey,
            keyId: "key-1",
            fieldMapping: nil,
            config: .init()
        )

        XCTAssertFalse(envelope.nonce.isEmpty)
        XCTAssertGreaterThan(envelope.ts, 0)
        XCTAssertEqual(envelope.sessionToken, "session-456")
        XCTAssertEqual(envelope.reportId, "report-123")
        XCTAssertFalse(envelope.signature.isEmpty)

        // Verify signature
        XCTAssertTrue(envelope.verifySignature(signingKey))
    }

    func testReportEnvelopeRejectsBadSignature() throws {
        let payloadData = try JSONSerialization.data(withJSONObject: ["test": true])
        let signingKey = "test-signing-key-32-bytes-long!!"

        let envelope = try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: "report-1",
            sessionToken: "session-1",
            signingKey: signingKey,
            keyId: "key-1",
            fieldMapping: nil,
            config: .init()
        )

        // Verify with wrong key should fail
        XCTAssertFalse(envelope.verifySignature("wrong-key-that-is-also-32-bytes"))
    }

    func testReportEnvelopeJSONRoundtrip() throws {
        let payloadData = try JSONSerialization.data(withJSONObject: ["value": 42])
        let signingKey = "test-signing-key-32-bytes-long!!"

        let envelope = try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: "report-json",
            sessionToken: "session-json",
            signingKey: signingKey,
            keyId: "key-1",
            fieldMapping: nil,
            config: .init()
        )

        let jsonData = try envelope.toJSONData()
        let restored = try ReportEnvelope.fromJSON(jsonData)

        XCTAssertEqual(restored.nonce, envelope.nonce)
        XCTAssertEqual(restored.ts, envelope.ts)
        XCTAssertEqual(restored.reportId, envelope.reportId)
        XCTAssertEqual(restored.signature, envelope.signature)
        XCTAssertTrue(restored.verifySignature(signingKey))
    }

    func testReportEnvelopeTimestampValidity() throws {
        let payloadData = try JSONSerialization.data(withJSONObject: ["test": 1])
        let signingKey = "test-signing-key-32-bytes-long!!"

        let envelope = try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: "report-ts",
            sessionToken: "session-ts",
            signingKey: signingKey,
            keyId: "key-1",
            fieldMapping: nil,
            config: .init()
        )

        let config = ReportEnvelope.Config()
        XCTAssertTrue(envelope.isTimestampValid(config))
        XCTAssertFalse(envelope.isExpired(config))
    }

    func testGrpcPayloadContainsOutputPathIntegritySignal() throws {
        let payloadData = try JSONSerialization.data(withJSONObject: ["score": 60, "isHighRisk": false])
        let signingKey = "test-signing-key-32-bytes-long!!"
        let envelope = try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: "report-grpc-integrity",
            sessionToken: "session-grpc-integrity",
            signingKey: signingKey,
            keyId: "key-1",
            fieldMapping: nil,
            config: .init()
        )

        let grpcPayload = envelope.toGrpcCompatiblePayload()
        let jsonDict = grpcPayload.toJSONDictionary()
        let integrity = jsonDict["output_path_integrity"] as? [String: String]

        XCTAssertNotNil(integrity, "gRPC payload 应包含 output_path_integrity 信号")
        XCTAssertEqual(integrity?["status"], "ok")
        XCTAssertEqual(integrity?["payload_sha256_match"], "1")
        XCTAssertEqual(integrity?["route"], "report_envelope->grpc_payload")
        XCTAssertFalse((integrity?["signature_input_sha256"] ?? "").isEmpty)
        XCTAssertEqual(integrity?["binding_mode"], "base_key_request_bound")
        XCTAssertEqual(
            integrity?["binding_fields"],
            "sigVer,nonce,ts,sessionToken,reportId,keyId,fieldMappingVersion,attestationKeyId,payloadCanonical"
        )
        XCTAssertEqual(integrity?["attestation_pair_state"], "none")
        XCTAssertEqual(integrity?["trust_level"], "unspecified")
        XCTAssertFalse((integrity?["request_binding_fp"] ?? "").isEmpty)
        XCTAssertFalse((integrity?["signing_identity_status"] ?? "").isEmpty)
        XCTAssertFalse((integrity?["signing_identity_fp"] ?? "").isEmpty)
        XCTAssertEqual(integrity?["signals_digest_present"], "0")
    }

    func testReportEnvelopeBindingDiagnosticsExposeSignalDigestAndBindingState() throws {
        let payloadData = try JSONSerialization.data(withJSONObject: [
            "score": 75,
            "sd": "deadbeef",
            "dv2": "v2a",
        ])
        let signingKey = "test-signing-key-32-bytes-long!!"
        let envelope = try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: "report-bind-diag",
            sessionToken: "session-bind-diag",
            signingKey: signingKey,
            keyId: "key-1",
            attestationKeyId: "att-key",
            trustLevel: .derived,
            config: .init()
        )

        let diagnostics = envelope.bindingDiagnostics()
        XCTAssertEqual(diagnostics["binding_mode"], "plain_hmac_v1")
        XCTAssertEqual(diagnostics["binding_digest_present"], "1")
        XCTAssertEqual(diagnostics["binding_digest_consistent"], "1")
        XCTAssertEqual(diagnostics["signals_digest_present"], "1")
        XCTAssertEqual(diagnostics["signals_digest_version"], "v2a")
        XCTAssertEqual(diagnostics["signals_digest"], "deadbeef")
        XCTAssertEqual(diagnostics["attestation_pair_state"], "key_only")
        XCTAssertEqual(diagnostics["trust_level"], "derived")
    }

    func testGrpcPayloadFailClosedOnPayloadSha256Mismatch() throws {
        let badPayload = GrpcReportPayload(
            appId: "app",
            sdkVersion: "6.5",
            reportId: "rid-1",
            ts: 123456,
            nonce: "nonce-1",
            sessionToken: "st",
            sigVer: "v2",
            keyId: "k1",
            fieldMappingVersion: nil,
            deviceId: "dev-1",
            scene: "login",
            payloadJson: Data("{\"score\":80}".utf8),
            signature: "deadbeef",
            payloadSha256: Data(repeating: 0x00, count: 32)
        )

        XCTAssertThrowsError(try badPayload.validatedJSONDictionary(), "payload_sha256 不一致时必须 fail-closed") { error in
            guard let envelopeError = error as? ReportEnvelope.ReportEnvelopeError else {
                XCTFail("unexpected error type: \(error)")
                return
            }
            XCTAssertEqual(envelopeError, .encodingFailed)
        }
    }

    // MARK: - InMemoryNonceReplayStore Tests

    func testNonceReplayStoreRejectsReplay() {
        let store = InMemoryNonceReplayStore()
        let nonce = UUID().uuidString
        let expiry = Int64(Date().timeIntervalSince1970 * 1000) + 300_000

        // First consume should succeed
        XCTAssertTrue(store.consumeIfNew(sessionToken: "s1", nonce: nonce, expiresAtMillis: expiry))
        // Second consume (replay) should fail
        XCTAssertFalse(store.consumeIfNew(sessionToken: "s1", nonce: nonce, expiresAtMillis: expiry))
    }

    func testNonceReplayStoreDifferentNonces() {
        let store = InMemoryNonceReplayStore()
        let expiry = Int64(Date().timeIntervalSince1970 * 1000) + 300_000

        XCTAssertTrue(store.consumeIfNew(sessionToken: "s1", nonce: "nonce-1", expiresAtMillis: expiry))
        XCTAssertTrue(store.consumeIfNew(sessionToken: "s1", nonce: "nonce-2", expiresAtMillis: expiry))
    }

    // MARK: - RiskConclusionSigner Tests

    func testSignAndVerifyConclusion() {
        let context = TestFixtures.makeRiskContext(isJailbroken: true, jailbreakConfidence: 80)
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)
        let cprReport = CPRiskReport(context: context, report: report)
        let key = DeviceKeyDeriver.deriveKey(
            deviceID: "test-device",
            hardwareMachine: "iPhone15,3",
            kernelVersion: "23.0.0",
            salt: Data("test-salt".utf8)
        )

        let signed = SignedRiskConclusion.sign(report: cprReport, deviceKey: key)
        XCTAssertFalse(signed.signature.isEmpty)
        XCTAssertFalse(signed.nonce.isEmpty)
        XCTAssertGreaterThan(signed.timestamp, 0)

        // Verify should pass
        XCTAssertTrue(signed.verify(deviceKey: key, maxAgeSeconds: 300))
    }

    func testConclusionVerifyRejectsWrongKey() {
        let context = TestFixtures.makeRiskContext()
        let report = RiskScorer.score(context: context, config: TestFixtures.defaultRiskConfig)
        let cprReport = CPRiskReport(context: context, report: report)
        let key1 = DeviceKeyDeriver.deriveKey(
            deviceID: "device-1",
            hardwareMachine: "iPhone15,3",
            kernelVersion: "23.0.0",
            salt: Data("salt-1".utf8)
        )
        let key2 = DeviceKeyDeriver.deriveKey(
            deviceID: "device-2",
            hardwareMachine: "iPhone15,3",
            kernelVersion: "23.0.0",
            salt: Data("salt-2".utf8)
        )

        let signed = SignedRiskConclusion.sign(report: cprReport, deviceKey: key1)
        XCTAssertFalse(signed.verify(deviceKey: key2, maxAgeSeconds: 300))
    }

    func testDeviceKeyDeriverDeterministic() {
        let salt = Data("test-salt".utf8)
        let key1 = DeviceKeyDeriver.deriveKey(
            deviceID: "device-1",
            hardwareMachine: "iPhone15,3",
            kernelVersion: "23.0.0",
            salt: salt
        )
        let key2 = DeviceKeyDeriver.deriveKey(
            deviceID: "device-1",
            hardwareMachine: "iPhone15,3",
            kernelVersion: "23.0.0",
            salt: salt
        )

        // Same inputs should produce same key
        let data1 = key1.withUnsafeBytes { Data($0) }
        let data2 = key2.withUnsafeBytes { Data($0) }
        XCTAssertEqual(data1, data2)
    }

    func testDeviceKeyDeriverDifferentInputsDifferentKeys() {
        let salt = Data("test-salt".utf8)
        let key1 = DeviceKeyDeriver.deriveKey(
            deviceID: "device-1",
            hardwareMachine: "iPhone15,3",
            kernelVersion: "23.0.0",
            salt: salt
        )
        let key2 = DeviceKeyDeriver.deriveKey(
            deviceID: "device-2",
            hardwareMachine: "iPhone15,3",
            kernelVersion: "23.0.0",
            salt: salt
        )

        let data1 = key1.withUnsafeBytes { Data($0) }
        let data2 = key2.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(data1, data2)
    }

    func testDeviceKeyDeriverInfoVersionProducesDifferentKeys() {
        let salt = Data("test-salt".utf8)
        let keyV1 = DeviceKeyDeriver.deriveKey(
            deviceID: "device-1",
            hardwareMachine: "iPhone15,3",
            kernelVersion: "23.0.0",
            salt: salt,
            infoVersion: "v1"
        )
        let keyV2 = DeviceKeyDeriver.deriveKey(
            deviceID: "device-1",
            hardwareMachine: "iPhone15,3",
            kernelVersion: "23.0.0",
            salt: salt,
            infoVersion: "v2"
        )
        let dataV1 = keyV1.withUnsafeBytes { Data($0) }
        let dataV2 = keyV2.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(dataV1, dataV2, "不同 infoVersion 应产生不同密钥")
    }

    // MARK: - DecoyFieldInjector Tests

    func testDecoyInjectionAddsFields() throws {
        var payload: [String: Any] = ["score": 75, "isHighRisk": true]
        DecoyFieldInjector.inject(into: &payload, seed: 12345)

        // Should have more fields than original
        XCTAssertGreaterThan(payload.count, 2)
        // Original fields should be preserved
        XCTAssertEqual(payload["score"] as? Int, 75)
        XCTAssertEqual(payload["isHighRisk"] as? Bool, true)
    }

    func testDecoyInjectionDeterministic() {
        var payload1: [String: Any] = ["score": 50]
        var payload2: [String: Any] = ["score": 50]

        DecoyFieldInjector.inject(into: &payload1, seed: 42)
        DecoyFieldInjector.inject(into: &payload2, seed: 42)

        // Same seed should produce same decoy keys
        let keys1 = Set(payload1.keys)
        let keys2 = Set(payload2.keys)
        XCTAssertEqual(keys1, keys2)
    }

    func testDecoyInjectionDifferentSeeds() {
        var payload1: [String: Any] = ["score": 50]
        var payload2: [String: Any] = ["score": 50]

        DecoyFieldInjector.inject(into: &payload1, seed: 1)
        DecoyFieldInjector.inject(into: &payload2, seed: 999)

        // Different seeds should (very likely) produce different decoy keys
        let extra1 = Set(payload1.keys).subtracting(["score"])
        let extra2 = Set(payload2.keys).subtracting(["score"])
        XCTAssertNotEqual(extra1, extra2)
    }

    // MARK: - RuntimeFieldMapping Tests

    func testRuntimeFieldMappingGeneration() {
        let mapping = RuntimeFieldMapping.generate(seed: 12345, version: "v1")
        XCTAssertEqual(mapping.version, "v1")
        XCTAssertFalse(mapping.mappings.isEmpty)
    }

    func testRuntimeFieldMappingDeterministic() {
        let mapping1 = RuntimeFieldMapping.generate(seed: 42, version: "v1")
        let mapping2 = RuntimeFieldMapping.generate(seed: 42, version: "v1")
        XCTAssertEqual(mapping1.mappings, mapping2.mappings)
    }
}

// MARK: - SecureEnvelopeValidator Attestation Consistency Tests

final class SecureEnvelopeValidatorAttestationTests: XCTestCase {

    private let signingKey = "test-signing-key-32-bytes-long!!"

    private func makeEnvelope(
        attestationKeyId: String?,
        attestationAssertion: Data?
    ) throws -> ReportEnvelope {
        let payloadData = try JSONSerialization.data(withJSONObject: ["score": 50])
        let base = try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: "report-attest",
            sessionToken: "session-attest",
            signingKey: signingKey,
            keyId: "key-1",
            fieldMapping: nil,
            config: .init()
        )
        return ReportEnvelope(
            nonce: base.nonce,
            ts: base.ts,
            sessionToken: base.sessionToken,
            payload: base.payload,
            reportId: base.reportId,
            sigVer: base.sigVer,
            keyId: base.keyId,
            fieldMappingVersion: base.fieldMappingVersion,
            signature: base.signature,
            attestationKeyId: attestationKeyId,
            attestationAssertion: attestationAssertion,
            trustLevel: nil,
            reAttestationAssertion: nil
        )
    }

    func testAttestationConsistency_bothAbsent_passes() throws {
        let envelope = try makeEnvelope(attestationKeyId: nil, attestationAssertion: nil)
        let result = CPRiskKit.shared.validateSecureReportEnvelope(
            envelope,
            signingKey: signingKey,
            enableReplayProtection: false,
            validateAttestationConsistency: true
        )
        // Should not fail with attestationIncomplete
        if case .failure(.reportEnvelope(.attestationIncomplete)) = result {
            XCTFail("Both absent should pass attestation consistency check")
        }
    }

    func testAttestationConsistency_bothPresent_passes() throws {
        let envelope = try makeEnvelope(
            attestationKeyId: "key-abc",
            attestationAssertion: Data("assertion-data".utf8)
        )
        let result = CPRiskKit.shared.validateSecureReportEnvelope(
            envelope,
            signingKey: signingKey,
            enableReplayProtection: false,
            validateAttestationConsistency: true
        )
        // Should not fail with attestationIncomplete
        if case .failure(.reportEnvelope(.attestationIncomplete)) = result {
            XCTFail("Both present should pass attestation consistency check")
        }
    }

    func testAttestationConsistency_keyIdWithoutAssertion_fails() throws {
        let envelope = try makeEnvelope(attestationKeyId: "key-abc", attestationAssertion: nil)
        let result = CPRiskKit.shared.validateSecureReportEnvelope(
            envelope,
            signingKey: signingKey,
            enableReplayProtection: false,
            validateAttestationConsistency: true
        )
        guard case .failure(.reportEnvelope(.attestationIncomplete)) = result else {
            XCTFail("keyId present but assertion absent should return attestationIncomplete")
            return
        }
    }

    func testAttestationConsistency_assertionWithoutKeyId_fails() throws {
        // This is the new direction fixed by the XOR check
        let envelope = try makeEnvelope(
            attestationKeyId: nil,
            attestationAssertion: Data("assertion-data".utf8)
        )
        let result = CPRiskKit.shared.validateSecureReportEnvelope(
            envelope,
            signingKey: signingKey,
            enableReplayProtection: false,
            validateAttestationConsistency: true
        )
        guard case .failure(.reportEnvelope(.attestationIncomplete)) = result else {
            XCTFail("assertion present but keyId absent should return attestationIncomplete (XOR fix)")
            return
        }
    }

    func testAttestationConsistency_disabled_allowsInconsistentState() throws {
        let envelope = try makeEnvelope(attestationKeyId: "key-abc", attestationAssertion: nil)
        let result = CPRiskKit.shared.validateSecureReportEnvelope(
            envelope,
            signingKey: signingKey,
            enableReplayProtection: false,
            validateAttestationConsistency: false
        )
        // With consistency check disabled, should not return attestationIncomplete
        if case .failure(.reportEnvelope(.attestationIncomplete)) = result {
            XCTFail("Disabled consistency check should not return attestationIncomplete")
        }
    }
}

// MARK: - ChallengeSession configureChallengeKey Tests

final class ChallengeSessionKeyConfigTests: XCTestCase {

    func testConfigureChallengeKeyDoesNotDeadlock() {
        let session = ChallengeSession()
        let key = Data(repeating: 0xAB, count: 32)

        // Configure the key — must not deadlock even under concurrent access
        let expectation = self.expectation(description: "concurrent configure completes")
        expectation.expectedFulfillmentCount = 10

        let queue = DispatchQueue(label: "test.concurrent", attributes: .concurrent)
        for _ in 0..<10 {
            queue.async {
                session.configureChallengeKey(key)
                expectation.fulfill()
            }
        }
        wait(for: [expectation], timeout: 5.0)
    }

    func testConfigureChallengeKeyEnablesHMACVerification() {
        let session = ChallengeSession()
        let key = Data(repeating: 0x01, count: 32)
        session.configureChallengeKey(key)

        // A result with no HMAC should now return a mismatch signal (key is configured)
        let result = ChallengeVerificationResult(
            challengeId: "cid-001",
            passed: true,
            failedProbes: [],
            adjustedScore: nil,
            hmac: nil
        )
        let signal = session.verifyResult(result)
        XCTAssertNotNil(signal, "Configured key with missing HMAC should produce mismatch signal")
        XCTAssertEqual(signal?.id, "challenge_hmac_mismatch")
    }

    func testVerifyResultNilWhenNoKeyConfigured() {
        let session = ChallengeSession()
        // Do NOT configure a key — verifyResult should return nil (no-op)
        let result = ChallengeVerificationResult(
            challengeId: "cid-002",
            passed: true
        )
        XCTAssertNil(session.verifyResult(result), "Without a configured key, verifyResult should return nil")
    }
}
