import CryptoKit
import CRiskCore
import Foundation
import XCTest

final class SHA256MaskedRoundConstantsTests: XCTestCase {
    private func hexString<T: Sequence>(_ bytes: T) -> String where T.Element == UInt8 {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private func referenceCustomPadHMAC(key: [UInt8], message: [UInt8]) -> String {
        var normalizedKey = [UInt8](repeating: 0, count: Int(CPRISK_HMAC_BLOCK_SIZE))
        if key.count > Int(CPRISK_HMAC_BLOCK_SIZE) {
            let digest = Array(SHA256.hash(data: Data(key)))
            normalizedKey.replaceSubrange(0..<digest.count, with: digest)
        } else {
            normalizedKey.replaceSubrange(0..<key.count, with: key)
        }

        let ipadXor = UInt8(CPRISK_HMAC_IPAD_XOR_A ^ CPRISK_HMAC_IPAD_XOR_B)
        let opadXor = UInt8(CPRISK_HMAC_OPAD_XOR_A ^ CPRISK_HMAC_OPAD_XOR_B)
        let ipad = normalizedKey.map { $0 ^ ipadXor }
        let opad = normalizedKey.map { $0 ^ opadXor }

        let inner = Array(SHA256.hash(data: Data(ipad + message)))
        let outer = Array(SHA256.hash(data: Data(opad + inner)))
        return hexString(outer)
    }

    func testInlineSHA256MatchesKnownVector() {
        let message = Array("abc".utf8)
        var digest = [UInt8](repeating: 0, count: Int(CPRISK_SHA256_DIGEST_LENGTH))

        message.withUnsafeBufferPointer { msgPtr in
            digest.withUnsafeMutableBufferPointer { digestPtr in
                cprisk_sha256(msgPtr.baseAddress, message.count, digestPtr.baseAddress)
            }
        }

        XCTAssertEqual(
            hexString(digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }

    func testCustomPadHMACBridgeDoesNotRegress() {
        let key = Array("masked-k-regression-key".utf8)
        let message = Array("round-constant hardening should not alter HMAC output".utf8)
        let expected = referenceCustomPadHMAC(key: key, message: message)
        var outHex = [CChar](repeating: 0, count: Int(CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE) + 1)

        let rc = key.withUnsafeBufferPointer { keyPtr in
            message.withUnsafeBufferPointer { msgPtr in
                cprisk_hmac_sha256_hex(
                    keyPtr.baseAddress,
                    key.count,
                    msgPtr.baseAddress,
                    message.count,
                    &outHex
                )
            }
        }

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(String(cString: outHex), expected)
    }

    func testRoundConstantRemaskingPreservesValueWithoutCanonicalShareReuse() {
        let cases: [(UInt32, UInt32)] = [
            (0, 0x428a2f98),
            (1, 0x71374491),
            (63, 0xc67178f2),
        ]
        let seedA: UInt32 = 0x13579bdf
        let seedB: UInt32 = 0x2468ace1

        for (index, expectedK) in cases {
            let maskedA = cprisk_sha256_K_masked_at(index, seedA)
            let maskedB = cprisk_sha256_K_masked_at(index, seedB)

            XCTAssertEqual(maskedA.share0 &+ maskedA.share1, expectedK)
            XCTAssertEqual(maskedB.share0 &+ maskedB.share1, expectedK)
            XCTAssertNotEqual(maskedA.share0, expectedK)
            XCTAssertNotEqual(maskedA.share1, expectedK)
            XCTAssertNotEqual(maskedA.share0, maskedB.share0)
            XCTAssertNotEqual(maskedA.share1, maskedB.share1)
        }
    }

    /// Crypto-trace 微负载确定性摘要与入口探针：回归 Stalker/DBI 正交通路（非纯 Mach 慢速）。
    func testCryptoTracePrimitiveGoldenWorkloadDoesNotSetInvariantFail() {
        _ = cprisk_crypto_trace_consume_flags_i()
        cprisk_crypto_trace_primitive_enter_i()
        let flags = cprisk_crypto_trace_peek_flags_i()
        XCTAssertEqual(
            flags & UInt32(CPRISK_CRYPTO_TRACE_FLAG_INVARIANT_FAIL),
            0,
            "deterministic LCG digest must match golden uint64 on native execution"
        )
    }
}
