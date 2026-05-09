import CryptoKit
import XCTest
@testable import CloudPhoneRiskKit

/// v7.7 audit-fix N1: cover IntegritySealComputer cache semantics + seal API surface.
///
/// Coverage:
///   - 5s TTL cache hits (audit-fix F5: must not re-enter cprisk_gf2_affine_self_check)
///   - reset clears the cache (audit-fix F5 helper exists and is wired)
///   - seal(_:) on Data == sealFromDigestPrefix(SHA256(data).prefix(16)) (audit-fix F6
///     — the 2-overload coalesce is semantics-preserving)
///   - seal hex format invariants
final class IntegritySealComputerTests: XCTestCase {

    override func setUp() {
        super.setUp()
        IntegritySealComputer.resetMatrixIntactCacheForTesting()
    }

    override func tearDown() {
        IntegritySealComputer.resetMatrixIntactCacheForTesting()
        super.tearDown()
    }

    // MARK: - F5 cache

    func testIsMatrixIntactReturnsTrueOnFreshState() {
        XCTAssertTrue(IntegritySealComputer.isMatrixIntact)
    }

    func testIsMatrixIntactCachesWithinTTL() {
        let first = IntegritySealComputer.isMatrixIntact
        // 100 repeated calls within TTL window must remain stable. We can't
        // observe cache hit vs miss directly without hooking the C self-check,
        // so the contract verified here is "no flapping, no crash".
        for _ in 0..<100 {
            XCTAssertEqual(IntegritySealComputer.isMatrixIntact, first)
        }
    }

    func testResetMatrixIntactCacheForTestingClearsState() {
        _ = IntegritySealComputer.isMatrixIntact
        IntegritySealComputer.resetMatrixIntactCacheForTesting()
        // Post-reset call should still return true on a healthy build.
        XCTAssertTrue(IntegritySealComputer.isMatrixIntact)
    }

    // MARK: - F6 seal API

    func testSealOnDataIsDeterministic() {
        let data = Data("vendor=Apple,model=iPhone".utf8)
        let s1 = IntegritySealComputer.seal(data)
        let s2 = IntegritySealComputer.seal(data)
        XCTAssertEqual(s1, s2)
        XCTAssertEqual(s1.bytes.count, 16)
    }

    func testSealHexStringIs32CharsLowercase() {
        let seal = IntegritySealComputer.seal(Data("test".utf8))
        XCTAssertEqual(seal.hexString.count, 32)
        XCTAssertEqual(seal.hexString, seal.hexString.lowercased())
    }

    func testDifferentInputsProduceDifferentSeals() {
        let a = IntegritySealComputer.seal(Data("input-a".utf8))
        let b = IntegritySealComputer.seal(Data("input-b".utf8))
        XCTAssertNotEqual(a, b)
    }

    func testSealFromDigestPrefixIsCallableWith16Bytes() {
        let prefix = [UInt8](repeating: 0xAA, count: 16)
        let seal = IntegritySealComputer.sealFromDigestPrefix(prefix)
        XCTAssertEqual(seal.bytes.count, 16)
    }

    func testSealOnDataMatchesSealFromDigestPrefix() {
        // F6 invariant: seal(_:Data) is exactly SHA256(data).prefix(16) → sealFromDigestPrefix.
        // If the decomposition diverges from the one-shot, any caller that switched
        // overloads in commit 3de8892 would silently change behavior.
        let data = Data("invariant-canonical".utf8)
        let oneShot = IntegritySealComputer.seal(data)
        let digest = Array(SHA256.hash(data: data).prefix(16))
        let twoStep = IntegritySealComputer.sealFromDigestPrefix(digest)
        XCTAssertEqual(oneShot, twoStep,
            "F6 regression: seal(_:Data) must equal sealFromDigestPrefix(SHA256(data).prefix(16))")
    }
}
