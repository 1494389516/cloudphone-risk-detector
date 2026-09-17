import XCTest
import CryptoKit
@testable import CloudPhoneRiskKit

final class FusionTransportTests: XCTestCase {
    func testTransportPreservesProofAndBindingFields() throws {
        let envelope = try ReportEnvelope.create(payloadData: Data("{}".utf8), reportId: "r", sessionToken: "s", signingKey: "k", attestationKeyId: "ak", attestationAssertion: Data([1, 2]), reAttestationAssertion: Data([3]), trustLevel: .hardware, config: .init(signatureVersion: "v3"))
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: envelope.toGrpcRequestBytes()) as? [String: Any])
        XCTAssertEqual(object["attestation_key_id"] as? String, "ak")
        XCTAssertEqual(object["attestation_assertion"] as? String, "AQI=")
        XCTAssertEqual(object["re_attestation_assertion"] as? String, "Aw==")
        XCTAssertEqual(object["trust_level"] as? String, "hardware")
        XCTAssertEqual(object["binding_mode"] as? String, envelope.bindingMode)
        XCTAssertEqual(object["binding_digest"] as? String, envelope.bindingDigest)
    }

    func testRequiredProofCannotDisappearAcrossCodableOrCopy() throws {
        let envelope = try ReportEnvelope.create(payloadData: Data("{}".utf8), reportId: "r", sessionToken: "s", signingKey: "k", attestationKeyId: "ak", config: .init(signatureVersion: "v2", requireHardwareAttestation: true))
        let decoded = try JSONDecoder().decode(ReportEnvelope.self, from: JSONEncoder().encode(envelope))
        for value in [envelope, decoded, envelope.withTrustLevel(.derived), envelope.withReAttestationAssertion(Data([3]))] {
            XCTAssertThrowsError(try value.toGrpcRequestBytes()) { error in
                guard case ReportEnvelope.ReportEnvelopeError.attestationIncomplete = error else { return XCTFail("wrong error: \(error)") }
            }
        }
        XCTAssertNoThrow(try envelope.withAttestation(attestationKeyId: "ak", assertion: Data([1])).toGrpcRequestBytes())
    }
}

final class FusionGraphTests: XCTestCase {
    func testChurnIsLocalAndEvidenceContainsNoIPAddress() throws {
        let detector = LocalDeviceClusterDetector.shared
        detector.clear()
        defer { detector.clear() }
        var last: RiskSignal?
        for index in 0..<LocalDeviceClusterDetector.clusterThreshold {
            last = detector.recordAndDetect(hwProfileHash: "fingerprint-\(index)", key: "2001:db8::1")
        }
        let signal = try XCTUnwrap(last)
        XCTAssertEqual(signal.id, "local_identity_churn")
        XCTAssertEqual(signal.evidence["scope"], "local_installation")
        XCTAssertNil(signal.evidence["key"])
        XCTAssertNil(signal.evidence["distinct_devices"])
    }
}

extension FusionTransportTests {
    /// Same fixture bytes are consumed by Python's reference verifier.
    func testCrossLanguageWireGoldenVectors() throws {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { root.deleteLastPathComponent() }
        let vectors = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("contracts/fixtures/report_vectors.json"))) as? [[String: Any]])
        for vector in vectors {
            let wire = try XCTUnwrap(vector["upload"] as? [String: Any])
            let version = try XCTUnwrap(wire["sig_ver"] as? String)
            let payload = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(wire["payload_json"] as? String)))
            let signatureInput = try XCTUnwrap(vector["canonical_signature_input"] as? String)
            let key = Data((0..<32).map { UInt8($0) })
            XCTAssertEqual(CPRiskMessageAuth.authenticationCodeHex(for: Data(signatureInput.utf8), keyData: key), wire["signature"] as? String)
            let envelope = ReportEnvelope(nonce: "nonce", ts: 1790000000000, sessionToken: "session", payload: payload, reportId: "report", sigVer: version, keyId: "key", fieldMappingVersion: wire["field_mapping_version"] as? String, signature: try XCTUnwrap(wire["signature"] as? String), attestationKeyId: wire["attestation_key_id"] as? String, attestationAssertion: (wire["attestation_assertion"] as? String).flatMap { Data(base64Encoded: $0) }, trustLevel: (wire["trust_level"] as? String).flatMap { TrustLevel(rawValue: $0) }, reAttestationAssertion: (wire["re_attestation_assertion"] as? String).flatMap { Data(base64Encoded: $0) })
            let actual = try XCTUnwrap(JSONSerialization.jsonObject(with: envelope.toGrpcRequestBytes(context: .init(appId: "app", deviceId: "device", scene: "login"))) as? [String: Any])
            for field in ["payload_json", "payload_sha256", "signature", "attestation_key_id", "attestation_assertion", "trust_level", "re_attestation_assertion", "field_mapping_version"] {
                XCTAssertEqual(actual[field] as? String, wire[field] as? String, "\(vector["name"] ?? ""): \(field)")
            }
            XCTAssertEqual(envelope.bindingDiagnostics()["signature_input_sha256"], SHA256.hash(data: Data(signatureInput.utf8)).map { String(format: "%02x", $0) }.joined())
        }
    }
}
