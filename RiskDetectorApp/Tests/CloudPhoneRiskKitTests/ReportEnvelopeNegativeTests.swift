import XCTest
@testable import CloudPhoneRiskKit

/// ReportEnvelope 签名验证负面测试 — 确保篡改后验签失败
final class ReportEnvelopeNegativeTests: XCTestCase {

    private let signingKey = "test-signing-key-32-bytes-long!!"
    private let altSigningKey = "alt--signing-key-32-bytes-long!!"

    private func makeEnvelope(
        payloadDict: [String: Any] = ["score": 75],
        reportId: String = "report-neg",
        sessionToken: String = "session-neg"
    ) throws -> ReportEnvelope {
        let payloadData = try JSONSerialization.data(withJSONObject: payloadDict)
        return try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: reportId,
            sessionToken: sessionToken,
            signingKey: signingKey,
            keyId: "key-1",
            config: .init()
        )
    }

    // MARK: - 篡改 Payload

    func testTamperedPayloadFailsVerification() throws {
        let envelope = try makeEnvelope()

        // 篡改 payload
        let tamperedPayload = try JSONSerialization.data(withJSONObject: ["score": 0])
        let tampered = ReportEnvelope(
            nonce: envelope.nonce,
            ts: envelope.ts,
            sessionToken: envelope.sessionToken,
            payload: tamperedPayload,
            reportId: envelope.reportId,
            sigVer: envelope.sigVer,
            keyId: envelope.keyId,
            fieldMappingVersion: envelope.fieldMappingVersion,
            signature: envelope.signature
        )

        XCTAssertFalse(tampered.verifySignature(signingKey),
            "篡改 payload 后签名验证应失败")
    }

    // MARK: - 篡改 Nonce

    func testTamperedNonceFailsVerification() throws {
        let envelope = try makeEnvelope()

        let tampered = ReportEnvelope(
            nonce: "tampered-nonce-value",
            ts: envelope.ts,
            sessionToken: envelope.sessionToken,
            payload: envelope.payload,
            reportId: envelope.reportId,
            sigVer: envelope.sigVer,
            keyId: envelope.keyId,
            signature: envelope.signature
        )

        XCTAssertFalse(tampered.verifySignature(signingKey),
            "篡改 nonce 后签名验证应失败")
    }

    // MARK: - 篡改时间戳

    func testTamperedTimestampFailsVerification() throws {
        let envelope = try makeEnvelope()

        let tampered = ReportEnvelope(
            nonce: envelope.nonce,
            ts: envelope.ts + 1000, // 偏移 1 秒
            sessionToken: envelope.sessionToken,
            payload: envelope.payload,
            reportId: envelope.reportId,
            sigVer: envelope.sigVer,
            keyId: envelope.keyId,
            signature: envelope.signature
        )

        XCTAssertFalse(tampered.verifySignature(signingKey),
            "篡改时间戳后签名验证应失败")
    }

    // MARK: - 篡改 SessionToken

    func testTamperedSessionTokenFailsVerification() throws {
        let envelope = try makeEnvelope()

        let tampered = ReportEnvelope(
            nonce: envelope.nonce,
            ts: envelope.ts,
            sessionToken: "hijacked-session",
            payload: envelope.payload,
            reportId: envelope.reportId,
            sigVer: envelope.sigVer,
            keyId: envelope.keyId,
            signature: envelope.signature
        )

        XCTAssertFalse(tampered.verifySignature(signingKey),
            "篡改 sessionToken 后签名验证应失败")
    }

    // MARK: - 篡改 ReportId

    func testTamperedReportIdFailsVerification() throws {
        let envelope = try makeEnvelope()

        let tampered = ReportEnvelope(
            nonce: envelope.nonce,
            ts: envelope.ts,
            sessionToken: envelope.sessionToken,
            payload: envelope.payload,
            reportId: "tampered-report-id",
            sigVer: envelope.sigVer,
            keyId: envelope.keyId,
            signature: envelope.signature
        )

        XCTAssertFalse(tampered.verifySignature(signingKey),
            "篡改 reportId 后签名验证应失败")
    }

    // MARK: - 错误密钥

    func testWrongKeyFailsVerification() throws {
        let envelope = try makeEnvelope()
        XCTAssertFalse(envelope.verifySignature(altSigningKey),
            "使用错误密钥验签应失败")
    }

    func testEmptyKeyFailsVerification() throws {
        let envelope = try makeEnvelope()
        XCTAssertFalse(envelope.verifySignature(""),
            "空密钥验签应失败")
    }

    // MARK: - Key Resolver

    func testKeyResolverReturnsNilFailsVerification() throws {
        let envelope = try makeEnvelope()
        let result = envelope.verifySignature(using: { _ in nil })
        XCTAssertFalse(result, "keyResolver 返回 nil 时验签应失败")
    }

    func testKeyResolverReturnsWrongKeyFailsVerification() throws {
        let envelope = try makeEnvelope()
        let result = envelope.verifySignature(using: { _ in self.altSigningKey })
        XCTAssertFalse(result, "keyResolver 返回错误密钥时验签应失败")
    }

    func testKeyResolverReturnsCorrectKeyPassesVerification() throws {
        let envelope = try makeEnvelope()
        let result = envelope.verifySignature(using: { _ in self.signingKey })
        XCTAssertTrue(result, "keyResolver 返回正确密钥时验签应通过")
    }

    // MARK: - Validate 完整验证

    func testValidateRejectsExpiredEnvelope() throws {
        let payloadData = try JSONSerialization.data(withJSONObject: ["test": 1])
        // 创建一个过期的信封（手动构造过期时间戳）
        let oldTs = Int64(Date().timeIntervalSince1970 * 1000) - 600_000 // 10 分钟前
        let nonce = UUID().uuidString

        let signatureInput = "v2|\(nonce)|\(oldTs)|session-exp|report-exp|key-1|||{\"test\":1}"
        let signatureData = signatureInput.data(using: .utf8)!
        let key = CryptoKit.SymmetricKey(data: Data(signingKey.utf8))
        let digest = CryptoKit.HMAC<CryptoKit.SHA256>.authenticationCode(for: signatureData, using: key)
        let signatureHex = digest.map { String(format: "%02x", $0) }.joined()

        let expired = ReportEnvelope(
            nonce: nonce,
            ts: oldTs,
            sessionToken: "session-exp",
            payload: payloadData,
            reportId: "report-exp",
            sigVer: "v2",
            keyId: "key-1",
            signature: signatureHex
        )

        let result = expired.validate(
            signingKey: signingKey,
            config: .init(nonceExpirationMillis: 300_000, timeDriftToleranceMillis: 300_000)
        )

        switch result {
        case .failure(let error):
            // 应该是 timestampOutOfRange 或 nonceExpired
            XCTAssertTrue(
                error == .timestampOutOfRange || error == .nonceExpired,
                "Expected timestamp/nonce error, got \(error)"
            )
        case .success:
            XCTFail("过期信封不应通过验证")
        }
    }

    func testValidateWithReplayStore() throws {
        let envelope = try makeEnvelope()
        let store = InMemoryNonceReplayStore()
        let config = ReportEnvelope.Config()

        // 第一次验证应通过
        let result1 = envelope.validate(signingKey: signingKey, nonceStore: store, config: config)
        if case .failure = result1 {
            XCTFail("首次验证不应失败")
        }

        // 第二次验证应检测到重放
        let result2 = envelope.validate(signingKey: signingKey, nonceStore: store, config: config)
        if case .failure(.replayDetected) = result2 {
            // 预期
        } else {
            XCTFail("第二次验证应返回 replayDetected，实际返回 \(result2)")
        }
    }

    // MARK: - Hex 编码密钥

    func testHexEncodedKeyVerification() throws {
        let envelope = try makeEnvelope()
        // UTF-8 密钥的 hex 编码
        let hexKey = Data(signingKey.utf8).map { String(format: "%02x", $0) }.joined()
        XCTAssertTrue(envelope.verifySignature(hexKey, keyEncoding: .hex),
            "Hex 编码密钥应能正确验签")
    }

    func testWrongHexEncodedKeyFailsVerification() throws {
        let envelope = try makeEnvelope()
        let wrongHexKey = Data(altSigningKey.utf8).map { String(format: "%02x", $0) }.joined()
        XCTAssertFalse(envelope.verifySignature(wrongHexKey, keyEncoding: .hex),
            "错误的 hex 编码密钥验签应失败")
    }

    // MARK: - TrustLevel

    func testWithTrustLevel() throws {
        let envelope = try makeEnvelope()
        let hardware = envelope.withTrustLevel(.hardware)
        XCTAssertEqual(hardware.trustLevel, .hardware)
        XCTAssertTrue(hardware.verifySignature(signingKey),
            "设置 trustLevel 不应影响签名")
    }

    // MARK: - hasHardwareAttestation

    func testHasHardwareAttestationRequiresBoth() throws {
        let envelope = try makeEnvelope()
        XCTAssertFalse(envelope.hasHardwareAttestation,
            "无 attestation 时应为 false")

        let withKey = ReportEnvelope(
            nonce: envelope.nonce, ts: envelope.ts, sessionToken: envelope.sessionToken,
            payload: envelope.payload, reportId: envelope.reportId, sigVer: envelope.sigVer,
            keyId: envelope.keyId, signature: envelope.signature,
            attestationKeyId: "key-abc", attestationAssertion: nil
        )
        XCTAssertFalse(withKey.hasHardwareAttestation,
            "仅有 keyId 无 assertion 应为 false")

        let withBoth = withKey.withAttestation(
            attestationKeyId: "key-abc",
            assertion: Data("assertion".utf8)
        )
        XCTAssertTrue(withBoth.hasHardwareAttestation)
    }
}

import CryptoKit
