import XCTest
@testable import CloudPhoneRiskKit

final class GraphModuleTests: XCTestCase {

    // MARK: - GraphNodeDescriptor

    func testGraphNodeDescriptorCodableRoundTrip() throws {
        let node = GraphNodeDescriptor(
            hwProfileHash: "abc123",
            ipHash: "ip_hash",
            asnHash: "asn_hash",
            accountIdHash: "acct_hash",
            bssidHash: nil,
            appListHash: nil
        )
        let data = try JSONEncoder().encode(node)
        let decoded = try JSONDecoder().decode(GraphNodeDescriptor.self, from: data)

        XCTAssertEqual(decoded.hwProfileHash, "abc123")
        XCTAssertEqual(decoded.ipHash, "ip_hash")
        XCTAssertEqual(decoded.asnHash, "asn_hash")
        XCTAssertEqual(decoded.accountIdHash, "acct_hash")
        XCTAssertNil(decoded.bssidHash)
        XCTAssertNil(decoded.appListHash)
    }

    func testGraphNodeDescriptorUsesShortCodingKeys() throws {
        let node = GraphNodeDescriptor(hwProfileHash: "test")
        let data = try JSONEncoder().encode(node)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        // Verify short coding keys are used
        XCTAssertNotNil(json["hp"])
        XCTAssertNil(json["hwProfileHash"])
    }

    func testGraphNodeDescriptorAllNilOptionals() throws {
        let node = GraphNodeDescriptor(hwProfileHash: "only_required")
        let data = try JSONEncoder().encode(node)
        let decoded = try JSONDecoder().decode(GraphNodeDescriptor.self, from: data)

        XCTAssertEqual(decoded.hwProfileHash, "only_required")
        XCTAssertNil(decoded.ipHash)
        XCTAssertNil(decoded.asnHash)
        XCTAssertNil(decoded.accountIdHash)
    }

    // MARK: - GraphFeatureCollector

    func testCollectProducesNonEmptyHwProfileHash() {
        let snapshot = makeTestSnapshot()
        let descriptor = GraphFeatureCollector.collect(
            snapshot: snapshot,
            serverSignals: nil,
            accountId: nil
        )

        XCTAssertFalse(descriptor.hwProfileHash.isEmpty)
        XCTAssertNil(descriptor.ipHash)
        XCTAssertNil(descriptor.asnHash)
        XCTAssertNil(descriptor.accountIdHash)
    }

    func testCollectWithServerSignals() {
        let snapshot = makeTestSnapshot()
        var signals = ServerSignals()
        signals.publicIP = "1.2.3.4"
        signals.asn = "AS12345"

        let descriptor = GraphFeatureCollector.collect(
            snapshot: snapshot,
            serverSignals: signals,
            accountId: "user_123"
        )

        XCTAssertFalse(descriptor.hwProfileHash.isEmpty)
        XCTAssertNotNil(descriptor.ipHash)
        XCTAssertNotNil(descriptor.asnHash)
        XCTAssertNotNil(descriptor.accountIdHash)
        // SHA256 hex is 64 chars
        XCTAssertEqual(descriptor.ipHash?.count, 64)
        XCTAssertEqual(descriptor.asnHash?.count, 64)
        XCTAssertEqual(descriptor.accountIdHash?.count, 64)
    }

    func testCollectWithEmptyServerSignals() {
        let snapshot = makeTestSnapshot()
        var signals = ServerSignals()
        signals.publicIP = ""
        signals.asn = ""

        let descriptor = GraphFeatureCollector.collect(
            snapshot: snapshot,
            serverSignals: signals,
            accountId: ""
        )

        XCTAssertNil(descriptor.ipHash, "Empty IP should result in nil hash")
        XCTAssertNil(descriptor.asnHash, "Empty ASN should result in nil hash")
        XCTAssertNil(descriptor.accountIdHash, "Empty account ID should result in nil hash")
    }

    func testCollectDeterministic() {
        let snapshot = makeTestSnapshot()
        let d1 = GraphFeatureCollector.collect(snapshot: snapshot, serverSignals: nil, accountId: "acct")
        let d2 = GraphFeatureCollector.collect(snapshot: snapshot, serverSignals: nil, accountId: "acct")

        XCTAssertEqual(d1.hwProfileHash, d2.hwProfileHash)
        XCTAssertEqual(d1.accountIdHash, d2.accountIdHash)
    }

    func testCollectDifferentInputsProduceDifferentHashes() {
        let snapshot1 = makeTestSnapshot(deviceID: "device_A")
        let snapshot2 = makeTestSnapshot(deviceID: "device_B")

        let d1 = GraphFeatureCollector.collect(snapshot: snapshot1, serverSignals: nil, accountId: nil)
        let d2 = GraphFeatureCollector.collect(snapshot: snapshot2, serverSignals: nil, accountId: nil)

        XCTAssertNotEqual(d1.hwProfileHash, d2.hwProfileHash)
    }

    // MARK: - DefaultGraphRiskFeedback

    func testDefaultGraphRiskFeedbackAllNil() {
        let feedback = DefaultGraphRiskFeedback()
        XCTAssertNil(feedback.communityId)
        XCTAssertNil(feedback.communityRiskDensity)
        XCTAssertNil(feedback.hwProfileDegree)
        XCTAssertNil(feedback.devicePageRank)
        XCTAssertNil(feedback.isInDenseSubgraph)
        XCTAssertNil(feedback.riskTags)
    }

    func testDefaultGraphRiskFeedbackWithValues() {
        let feedback = DefaultGraphRiskFeedback(
            communityId: "c1",
            communityRiskDensity: 0.8,
            hwProfileDegree: 5,
            devicePageRank: 0.02,
            isInDenseSubgraph: true,
            riskTags: ["bot_farm", "datacenter"]
        )
        XCTAssertEqual(feedback.communityId, "c1")
        XCTAssertEqual(feedback.communityRiskDensity, 0.8)
        XCTAssertEqual(feedback.hwProfileDegree, 5)
        XCTAssertEqual(feedback.devicePageRank, 0.02)
        XCTAssertEqual(feedback.isInDenseSubgraph, true)
        XCTAssertEqual(feedback.riskTags, ["bot_farm", "datacenter"])
    }

    // MARK: - LocalDeviceClusterDetector

    func testClusterDetectorNoTriggerBelowThreshold() {
        let detector = LocalDeviceClusterDetector.shared
        detector.clear()

        // Add fewer than threshold distinct devices
        for i in 0..<(LocalDeviceClusterDetector.clusterThreshold - 1) {
            let result = detector.recordAndDetect(hwProfileHash: "device_\(i)", key: "ip_1")
            XCTAssertNil(result, "Should not trigger below threshold (i=\(i))")
        }
    }

    func testClusterDetectorTriggersAtThreshold() {
        let detector = LocalDeviceClusterDetector.shared
        detector.clear()

        var triggered = false
        for i in 0..<LocalDeviceClusterDetector.clusterThreshold {
            if let signal = detector.recordAndDetect(hwProfileHash: "device_\(i)", key: "ip_test") {
                triggered = true
                XCTAssertEqual(signal.id, "local_device_cluster")
                XCTAssertEqual(signal.category, "server")
                XCTAssertGreaterThan(signal.score, 0)
            }
        }
        XCTAssertTrue(triggered, "Should trigger at threshold")
    }

    func testClusterDetectorSameDeviceDoesNotCount() {
        let detector = LocalDeviceClusterDetector.shared
        detector.clear()

        for _ in 0..<20 {
            let result = detector.recordAndDetect(hwProfileHash: "same_device", key: "ip_2")
            XCTAssertNil(result, "Same device hash should not increase distinct count")
        }
    }

    func testClusterDetectorNilKeyReturnsNil() {
        let detector = LocalDeviceClusterDetector.shared
        detector.clear()

        let result = detector.recordAndDetect(hwProfileHash: "device", key: nil)
        XCTAssertNil(result)
    }

    func testClusterDetectorEmptyKeyReturnsNil() {
        let detector = LocalDeviceClusterDetector.shared
        detector.clear()

        let result = detector.recordAndDetect(hwProfileHash: "device", key: "")
        XCTAssertNil(result)
    }

    func testClusterDetectorEmptyHashReturnsNil() {
        let detector = LocalDeviceClusterDetector.shared
        detector.clear()

        let result = detector.recordAndDetect(hwProfileHash: "", key: "ip_3")
        XCTAssertNil(result)
    }

    func testClusterDetectorClear() {
        let detector = LocalDeviceClusterDetector.shared
        detector.clear()

        // Add some entries
        for i in 0..<(LocalDeviceClusterDetector.clusterThreshold - 1) {
            _ = detector.recordAndDetect(hwProfileHash: "device_\(i)", key: "ip_clear")
        }

        // Clear and verify no trigger
        detector.clear()
        let result = detector.recordAndDetect(hwProfileHash: "device_new", key: "ip_clear")
        XCTAssertNil(result, "After clear, should not trigger")
    }

    func testClusterDetectorDifferentKeysAreIsolated() {
        let detector = LocalDeviceClusterDetector.shared
        detector.clear()

        // Add devices under different keys — neither should trigger
        for i in 0..<(LocalDeviceClusterDetector.clusterThreshold - 1) {
            _ = detector.recordAndDetect(hwProfileHash: "device_\(i)", key: "ip_A")
            _ = detector.recordAndDetect(hwProfileHash: "device_\(i + 100)", key: "ip_B")
        }

        // Verify ip_B 的设备不会污染 ip_A 的 distinct 集合；重复记录 ip_A 既有设备不应触发
        let resultA = detector.recordAndDetect(hwProfileHash: "device_1", key: "ip_A")
        XCTAssertNil(resultA, "replaying an existing hash on ip_A should stay below threshold when keys remain isolated")
    }

    // MARK: - Helpers

    private func makeTestSnapshot(deviceID: String = "test-device-id") -> RiskSnapshot {
        RiskSnapshot(
            deviceID: deviceID,
            device: TestFixtures.makeDeviceFingerprint(),
            network: TestFixtures.makeNetworkSignals(),
            behavior: TestFixtures.makeBehaviorSignals(),
            jailbreak: TestFixtures.makeDetectionResult()
        )
    }
}
