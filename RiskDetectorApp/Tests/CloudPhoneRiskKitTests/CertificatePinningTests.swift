import XCTest
@testable import CloudPhoneRiskKit

final class CertificatePinningTests: XCTestCase {

    /// Valid SPKI SHA-256 placeholder pins (32 zero / 32 0xFF bytes, base64).
    private var pinAllZero: String {
        "sha256/" + Data(repeating: 0, count: 32).base64EncodedString()
    }

    private var pinAllFF: String {
        "sha256/" + Data(repeating: 0xFF, count: 32).base64EncodedString()
    }

    // MARK: - PinnedCertificatePinMaterial

    func testPinMaterialParsesSha256PrefixAndRawBase64() {
        let b64 = Data(repeating: 0xAB, count: 32).base64EncodedString()
        XCTAssertNotNil(PinnedCertificatePinMaterial.digestFromPinString("sha256/\(b64)"))
        XCTAssertNotNil(PinnedCertificatePinMaterial.digestFromPinString(b64))
    }

    func testCanonicalPinStringsStable() {
        let b64 = Data(repeating: 1, count: 32).base64EncodedString()
        let messy = "  sha256/\(b64)  "
        let canon = PinnedCertificatePinMaterial.canonicalPinStrings(from: Set([messy]))
        XCTAssertEqual(canon, Set(["sha256/\(b64)"]))
    }

    func testPinMaterialContainsRawDigest() {
        let digest = Data(repeating: 7, count: 32)
        let pin = "sha256/" + digest.base64EncodedString()
        let m = PinnedCertificatePinMaterial(pinStrings: Set([pin]))
        XCTAssertTrue(m.containsRawDigest(digest))
        XCTAssertTrue(m.containsSPKISHA256Base64(digest.base64EncodedString()))
    }

    func testPinMaterialCorePathMatchesSwiftPath() {
        let digest = Data(repeating: 0x3C, count: 32)
        let pin = "sha256/" + digest.base64EncodedString()
        let material = PinnedCertificatePinMaterial(pinStrings: Set([pin]))
        XCTAssertTrue(material.containsRawDigest(digest))
        XCTAssertTrue(material.containsRawDigestViaCore(digest))
    }

    func testPinMaterialCorePathRejectsNonMatch() {
        let digest = Data(repeating: 0x11, count: 32)
        let other = Data(repeating: 0x22, count: 32)
        let pin = "sha256/" + digest.base64EncodedString()
        let material = PinnedCertificatePinMaterial(pinStrings: Set([pin]))
        XCTAssertFalse(material.containsRawDigest(other))
        XCTAssertFalse(material.containsRawDigestViaCore(other))
    }

    func testLayeredLeafPinOnlyMatchesChainIndexZero() {
        let digest = Data(repeating: 0x55, count: 32)
        let pin = "leaf/sha256/" + digest.base64EncodedString()
        let m = PinnedCertificatePinMaterial(pinStrings: Set([pin]))
        XCTAssertTrue(m.matchesLayeredDigest(digest, chainIndex: 0))
        XCTAssertFalse(m.matchesLayeredDigest(digest, chainIndex: 1))
        XCTAssertTrue(m.matchesLayeredDigestViaCore(digest, chainIndex: 0))
        XCTAssertFalse(m.matchesLayeredDigestViaCore(digest, chainIndex: 1))
    }

    func testLayeredIntermediatePinOnlyMatchesNonLeaf() {
        let digest = Data(repeating: 0x66, count: 32)
        let pin = "intermediate/sha256/" + digest.base64EncodedString()
        let m = PinnedCertificatePinMaterial(pinStrings: Set([pin]))
        XCTAssertFalse(m.matchesLayeredDigest(digest, chainIndex: 0))
        XCTAssertTrue(m.matchesLayeredDigest(digest, chainIndex: 1))
        XCTAssertTrue(m.matchesLayeredDigest(digest, chainIndex: 2))
        XCTAssertFalse(m.matchesLayeredDigestViaCore(digest, chainIndex: 0))
        XCTAssertTrue(m.matchesLayeredDigestViaCore(digest, chainIndex: 1))
    }

    func testExplicitAnyPrefixMatchesAllChainIndices() {
        let digest = Data(repeating: 0x77, count: 32)
        let pin = "any/sha256/" + digest.base64EncodedString()
        let m = PinnedCertificatePinMaterial(pinStrings: Set([pin]))
        XCTAssertTrue(m.matchesLayeredDigest(digest, chainIndex: 0))
        XCTAssertTrue(m.matchesLayeredDigest(digest, chainIndex: 3))
        XCTAssertTrue(m.matchesLayeredDigestViaCore(digest, chainIndex: 0))
        XCTAssertTrue(m.matchesLayeredDigestViaCore(digest, chainIndex: 3))
    }

    func testCanonicalPinStringsIncludesLayerPrefixes() {
        let b64 = Data(repeating: 0x88, count: 32).base64EncodedString()
        let leaf = "leaf/sha256/\(b64)"
        let intmd = "intermediate/sha256/\(b64)"
        let any = "sha256/\(b64)"
        let canon = PinnedCertificatePinMaterial.canonicalPinStrings(from: Set([leaf, intmd, any]))
        XCTAssertEqual(Set([leaf, intmd, any]), canon)
    }

    func testInvalidPinsProduceEmptyMaterial() {
        let m = PinnedCertificatePinMaterial(pinStrings: ["sha256/not-valid", "nope"])
        XCTAssertTrue(m.isEmpty)
    }

    // MARK: - Initialization

    func testInitWithPinnedHashes() {
        let hashes: Set<String> = [pinAllZero, pinAllFF]
        let delegate = CertificatePinningSessionDelegate(pinnedHashes: hashes)
        XCTAssertNotNil(delegate)
    }

    func testInitWithEmptyHashes() {
        let delegate = CertificatePinningSessionDelegate(pinnedHashes: [])
        XCTAssertNotNil(delegate)
    }

    func testInitWithAllowsSystemCA() {
        let delegate = CertificatePinningSessionDelegate(pinnedHashes: [pinAllZero], allowsSystemCA: true)
        XCTAssertNotNil(delegate)
    }

    // MARK: - pinnedSession factory

    func testPinnedSessionCreatesValidSession() {
        let session = CertificatePinningSessionDelegate.pinnedSession(
            hashes: [pinAllZero],
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
            hashes: [pinAllFF],
            configuration: config,
            allowsSystemCA: true
        )
        XCTAssertNotNil(session)
        XCTAssertEqual(session.configuration.timeoutIntervalForRequest, 10)
        session.invalidateAndCancel()
    }

    func testPinnedSessionDelegateIsCertificatePinning() {
        let session = CertificatePinningSessionDelegate.pinnedSession(
            hashes: [pinAllZero],
            allowsSystemCA: false
        )
        XCTAssertTrue(session.delegate is CertificatePinningSessionDelegate)
        session.invalidateAndCancel()
    }

    /// 进程内未打补丁时，trust hook 表面前缀校验应通过（与 pinning 预检同源 C 路径）。
    func testTrustHookSurfaceIntegritySucceedsInNormalProcess() {
        var mask: UInt32 = 0
        let ok = cprisk_verify_trust_hook_surface_integrity(&mask)
        XCTAssertEqual(ok, 1)
        XCTAssertEqual(mask, 0)
    }

    // MARK: - Pinning telemetry side-channel

    func testPinningTelemetryRecordsAndDrains() {
        CertificatePinningTelemetry.shared.resetForTesting()
        CertificatePinningTelemetry.shared.record(
            host: "example.com",
            kind: .pinMismatch,
            detail: ["unit": "1"]
        )
        let drained = CertificatePinningTelemetry.shared.drainEvents()
        XCTAssertEqual(drained.count, 1)
        XCTAssertEqual(drained.first?.host, "example.com")
        XCTAssertEqual(drained.first?.kind, .pinMismatch)
        XCTAssertEqual(CertificatePinningTelemetry.shared.peekEventsForTesting().count, 0)
    }

    func testPinningTelemetryProviderEmitsRiskSignals() {
        CertificatePinningTelemetry.shared.resetForTesting()
        CertificatePinningTelemetry.shared.record(host: "tls.test", kind: .trustEvalFailed, detail: [:])
        let snapshot = RiskSnapshot(
            deviceID: "pin-test",
            device: TestFixtures.makeDeviceFingerprint(),
            network: TestFixtures.makeNetworkSignals(),
            behavior: TestFixtures.makeBehaviorSignals(),
            jailbreak: TestFixtures.makeDetectionResult()
        )
        let signals = CertificatePinningTelemetryProvider.shared.signals(snapshot: snapshot)
        XCTAssertEqual(signals.count, 1)
        XCTAssertEqual(signals.first?.id, SignalID.certificatePinningAnomaly)
        XCTAssertEqual(signals.first?.category, SignalCategory.network)
    }
}
