import CryptoKit
import Foundation
import XCTest
@testable import CloudPhoneRiskKit

final class TrustChainManagerCFFTests: XCTestCase {

    private func keyData(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    func testDeriveSessionKeyIsDeterministicForSameInputs() {
        let deviceKey = SymmetricKey(data: Data(repeating: 0xAB, count: 32))

        let first = TrustChainManager.deriveSessionKey(
            deviceKey: deviceKey,
            sessionId: "session-1",
            timestamp: 1_700_000_001
        )
        let second = TrustChainManager.deriveSessionKey(
            deviceKey: deviceKey,
            sessionId: "session-1",
            timestamp: 1_700_000_001
        )

        XCTAssertEqual(keyData(first), keyData(second))
    }

    func testDeriveSessionKeyChangesWhenContextChanges() {
        let deviceKey = SymmetricKey(data: Data(repeating: 0xCD, count: 32))

        let baseline = keyData(
            TrustChainManager.deriveSessionKey(
                deviceKey: deviceKey,
                sessionId: "session-A",
                timestamp: 1_700_000_010
            )
        )
        let changedSession = keyData(
            TrustChainManager.deriveSessionKey(
                deviceKey: deviceKey,
                sessionId: "session-B",
                timestamp: 1_700_000_010
            )
        )
        let changedTimestamp = keyData(
            TrustChainManager.deriveSessionKey(
                deviceKey: deviceKey,
                sessionId: "session-A",
                timestamp: 1_700_000_011
            )
        )

        XCTAssertNotEqual(baseline, changedSession)
        XCTAssertNotEqual(baseline, changedTimestamp)
    }

    func testSessionKeyToHexProducesStableHexEncoding() {
        let key = SymmetricKey(data: Data(repeating: 0x01, count: 32))
        let hex = TrustChainManager.sessionKeyToHex(key)

        let hexScalars = CharacterSet(charactersIn: "0123456789abcdef")

        XCTAssertEqual(hex.count, 64)
        XCTAssertTrue(hex.unicodeScalars.allSatisfy { hexScalars.contains($0) })
    }
}
