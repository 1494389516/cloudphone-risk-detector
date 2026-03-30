import CryptoKit
import XCTest
@testable import CloudPhoneRiskKit

final class ConfigSignatureVerifierTests: XCTestCase {

    // MARK: - HMAC Configuration

    func testConfigureWithStringKey() {
        let result = ConfigSignatureVerifier.configure(serverSigningKey: "test-key-12345")
        XCTAssertTrue(result)
        XCTAssertTrue(ConfigSignatureVerifier.isConfigured)
    }

    func testConfigureWithDataKey() {
        let keyData = Data("test-key-data-12345".utf8)
        let result = ConfigSignatureVerifier.configure(serverSigningKeyData: keyData)
        XCTAssertTrue(result)
    }

    // MARK: - HMAC Verification

    func testVerifyWithValidSignature() {
        ConfigSignatureVerifier.configure(serverSigningKey: "test-signing-key")

        let payload = Data("test payload".utf8)
        let keyData = Data(SHA256.hash(data: Data("test-signing-key".utf8)))
        let sigHex = CPRiskMessageAuth.authenticationCodeHex(for: payload, keyData: keyData)

        let result = ConfigSignatureVerifier.verify(payload: payload, signatureHex: sigHex)
        XCTAssertTrue(result.isValid)
        XCTAssertNil(result.reason)
    }

    func testVerifyWithInvalidSignature() {
        ConfigSignatureVerifier.configure(serverSigningKey: "test-signing-key-2")

        let payload = Data("test payload".utf8)
        let result = ConfigSignatureVerifier.verify(payload: payload, signatureHex: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        XCTAssertFalse(result.isValid)
    }

    func testVerifyWithInvalidHexFormat() {
        ConfigSignatureVerifier.configure(serverSigningKey: "test-signing-key-3")

        let payload = Data("test payload".utf8)
        let result = ConfigSignatureVerifier.verify(payload: payload, signatureHex: "xyz")
        XCTAssertFalse(result.isValid)
        XCTAssertEqual(result.reason, "invalid_signature_format")
    }

    // MARK: - Thread Safety

    func testConcurrentVerification() {
        ConfigSignatureVerifier.configure(serverSigningKey: "concurrent-key")

        let iterations = 50
        let group = DispatchGroup()
        let payload = Data("concurrent payload".utf8)

        for _ in 0..<iterations {
            group.enter()
            DispatchQueue.global().async {
                _ = ConfigSignatureVerifier.verify(payload: payload, signatureHex: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                group.leave()
            }
        }

        let result = group.wait(timeout: .now() + 10)
        XCTAssertEqual(result, .success)
    }
}
