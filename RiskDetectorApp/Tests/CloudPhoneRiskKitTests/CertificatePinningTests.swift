import XCTest
@testable import CloudPhoneRiskKit

final class CertificatePinningTests: XCTestCase {

    // MARK: - Initialization

    func testInitWithPinnedHashes() {
        let hashes: Set<String> = ["sha256/AAAA", "sha256/BBBB"]
        let delegate = CertificatePinningSessionDelegate(pinnedHashes: hashes)
        XCTAssertNotNil(delegate)
    }

    func testInitWithEmptyHashes() {
        let delegate = CertificatePinningSessionDelegate(pinnedHashes: [])
        XCTAssertNotNil(delegate)
    }

    func testInitWithAllowsSystemCA() {
        let delegate = CertificatePinningSessionDelegate(pinnedHashes: ["sha256/TEST"], allowsSystemCA: true)
        XCTAssertNotNil(delegate)
    }

    // MARK: - pinnedSession factory

    func testPinnedSessionCreatesValidSession() {
        let session = CertificatePinningSessionDelegate.pinnedSession(
            hashes: ["sha256/TEST_HASH"],
            allowsSystemCA: false
        )
        XCTAssertNotNil(session)
        XCTAssertNotNil(session.delegate)
        session.invalidateAndCancel()
    }

    func testPinnedSessionWithCustomConfiguration() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 10
        let session = CertificatePinningSessionDelegate.pinnedSession(
            hashes: ["sha256/ABC"],
            configuration: config,
            allowsSystemCA: true
        )
        XCTAssertNotNil(session)
        XCTAssertEqual(session.configuration.timeoutIntervalForRequest, 10)
        session.invalidateAndCancel()
    }

    func testPinnedSessionDelegateIsCertificatePinning() {
        let session = CertificatePinningSessionDelegate.pinnedSession(
            hashes: ["sha256/TEST"],
            allowsSystemCA: false
        )
        XCTAssertTrue(session.delegate is CertificatePinningSessionDelegate)
        session.invalidateAndCancel()
    }

    // MARK: - URLSession delegate conformance

    func testConformsToURLSessionDelegate() {
        let delegate = CertificatePinningSessionDelegate(pinnedHashes: ["sha256/X"])
        XCTAssertTrue(delegate is URLSessionDelegate)
    }

    func testIsNSObject() {
        let delegate = CertificatePinningSessionDelegate(pinnedHashes: ["sha256/X"])
        XCTAssertTrue(delegate is NSObject)
    }
}
