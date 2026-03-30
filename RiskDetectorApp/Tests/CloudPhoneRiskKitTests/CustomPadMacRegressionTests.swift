import CryptoKit
import CRiskCore
import XCTest
@testable import CloudPhoneRiskKit

final class CustomPadMacRegressionTests: XCTestCase {

    func testSwiftCustomMacMatchesPinnedVectorAndNotStandardHMAC() {
        let key = Data("custom-pad-key".utf8)
        let message = Data("edge-auth-message".utf8)
        let expectedHex = "1846b893bfbac75593b325429dd6a8997012ce73768864d3a0a640011118098f"

        let customHex = CPRiskMessageAuth.authenticationCodeHex(for: message, keyData: key)
        let standardHex = standardHmacHex(key: key, message: message)

        XCTAssertEqual(customHex, expectedHex, "custom pad MAC should stay pinned to the coordinated regression vector")
        XCTAssertNotEqual(customHex, standardHex, "custom pad MAC must not silently fall back to standard HMAC-SHA256 pads")
    }

    func testCHmacHelperMatchesSwiftCustomMacKnownVector() throws {
        let key = Data("custom-pad-key".utf8)
        let message = Data("edge-auth-message".utf8)
        let expectedHex = "1846b893bfbac75593b325429dd6a8997012ce73768864d3a0a640011118098f"

        let swiftHex = CPRiskMessageAuth.authenticationCodeHex(for: message, keyData: key)
        let cHex = try cHmacHex(key: key, message: message)

        XCTAssertEqual(swiftHex, expectedHex)
        XCTAssertEqual(cHex, expectedHex, "C helper should preserve the same custom-pad vector as Swift")
    }

    func testCHmacHelperLongKeyNormalizationMatchesPinnedVector() throws {
        let key = Data(repeating: 0x41, count: 80)
        let message = Data("long-key-regression".utf8)
        let expectedHex = "da1207f242aa80b1afdb60c09e551ddcf0200ddeff34b6ca25fe8563c36acd25"

        let swiftHex = CPRiskMessageAuth.authenticationCodeHex(for: message, keyData: key)
        let cHex = try cHmacHex(key: key, message: message)
        let standardHex = standardHmacHex(key: key, message: message)

        XCTAssertEqual(swiftHex, expectedHex, "Swift custom MAC should remain stable on the >64-byte key normalization path")
        XCTAssertEqual(cHex, expectedHex, "C helper should match the pinned long-key custom MAC vector")
        XCTAssertNotEqual(cHex, standardHex, "long-key path must continue using the custom pad constants")
    }

    private func cHmacHex(key: Data, message: Data) throws -> String {
        var outHex = [CChar](repeating: 0, count: Int(CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE) + 1)
        let rc = key.withUnsafeBytes { keyRaw in
            message.withUnsafeBytes { messageRaw in
                cprisk_hmac_sha256_hex(
                    keyRaw.bindMemory(to: UInt8.self).baseAddress,
                    key.count,
                    messageRaw.bindMemory(to: UInt8.self).baseAddress,
                    message.count,
                    &outHex
                )
            }
        }
        XCTAssertEqual(rc, 0, "cprisk_hmac_sha256_hex should succeed for non-empty regression vectors")
        guard rc == 0 else {
            throw NSError(domain: "CustomPadMacRegressionTests", code: Int(rc))
        }
        return String(cString: outHex)
    }

    private func standardHmacHex(key: Data, message: Data) -> String {
        let digest = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(digest).map { String(format: "%02x", $0) }.joined()
    }
}
