import Foundation
import XCTest
@testable import CloudPhoneRiskKit

final class ReportEnvelopeSecurityTests: XCTestCase {

    func testSignatureBindsSessionToken() throws {
        let payload = try JSONSerialization.data(withJSONObject: ["riskScore": 88, "tamperedCount": 2], options: [])

        let envelopeA = try ReportEnvelope.create(
            payloadData: payload,
            reportId: "r-1",
            sessionToken: "session-A",
            signingKey: "secret"
        )

        let envelopeB = ReportEnvelope(
            nonce: envelopeA.nonce,
            ts: envelopeA.ts,
            sessionToken: "session-B",
            payload: envelopeA.payload,
            reportId: envelopeA.reportId,
            sigVer: envelopeA.sigVer,
            keyId: envelopeA.keyId,
            signature: envelopeA.signature
        )

        XCTAssertTrue(envelopeA.verifySignature("secret"))
        XCTAssertFalse(envelopeB.verifySignature("secret"), "sessionToken 改变后签名应失效")
    }

    func testSignatureUsesCanonicalPayload() throws {
        let payloadA = try JSONSerialization.data(withJSONObject: ["a": 1, "b": 2], options: [])
        let payloadB = try JSONSerialization.data(withJSONObject: ["b": 2, "a": 1], options: [])

        let original = try ReportEnvelope.create(
            payloadData: payloadA,
            reportId: "report-ordered",
            sessionToken: "session",
            signingKey: "secret"
        )

        let reordered = ReportEnvelope(
            nonce: original.nonce,
            ts: original.ts,
            sessionToken: original.sessionToken,
            payload: payloadB,
            reportId: original.reportId,
            sigVer: original.sigVer,
            keyId: original.keyId,
            signature: original.signature
        )

        XCTAssertTrue(reordered.verifySignature("secret"), "同语义 JSON 键序变化不应导致验签失败")
    }

    func testReplayProtectionRejectsSecondConsume() throws {
        let payload = try JSONSerialization.data(withJSONObject: ["riskScore": 77], options: [])
        let envelope = try ReportEnvelope.create(
            payloadData: payload,
            reportId: "report-replay",
            sessionToken: "session-replay",
            signingKey: "secret"
        )

        let store = InMemoryNonceReplayStore()

        let first = envelope.validate(signingKey: "secret", nonceStore: store)
        if case .failure(let error) = first {
            XCTFail("首次请求不应失败: \(error)")
        }

        let second = envelope.validate(signingKey: "secret", nonceStore: store)
        guard case .failure(let error) = second else {
            XCTFail("重放请求应失败")
            return
        }

        if case .replayDetected = error {
            // expected
        } else {
            XCTFail("应返回 replayDetected，实际: \(error)")
        }
    }

    func testFieldObfuscationMappingApplied() throws {
        let payload = try JSONSerialization.data(
            withJSONObject: [
                "riskScore": 63,
                "tamperedCount": 1,
                "hwEntropy": 2.5,
            ],
            options: []
        )

        let mapping = PayloadFieldMapping(
            version: "2026-03-04-a",
            mappings: [
                "riskScore": "f_a7x2k",
                "tamperedCount": "q_9m3p",
                "hwEntropy": "v_k2r8",
            ]
        )

        let envelope = try ReportEnvelope.create(
            payloadData: payload,
            reportId: "report-obf",
            sessionToken: "session-obf",
            signingKey: "secret",
            fieldMapping: mapping
        )

        XCTAssertEqual(envelope.fieldMappingVersion, "2026-03-04-a")

        let object = try JSONSerialization.jsonObject(with: envelope.payload, options: []) as? [String: Any]
        XCTAssertNotNil(object?["f_a7x2k"])
        XCTAssertNotNil(object?["q_9m3p"])
        XCTAssertNotNil(object?["v_k2r8"])
        XCTAssertNil(object?["riskScore"])
    }

    func testKeyResolverSupportsRotation() throws {
        let payload = try JSONSerialization.data(withJSONObject: ["riskScore": 42], options: [])
        let envelope = try ReportEnvelope.create(
            payloadData: payload,
            reportId: "report-kid",
            sessionToken: "session-kid",
            signingKey: "secret-k1",
            keyId: "k1"
        )

        let ok = envelope.verifySignature { keyId in
            switch keyId {
            case "k1":
                return "secret-k1"
            default:
                return nil
            }
        }

        XCTAssertTrue(ok)
    }
}
