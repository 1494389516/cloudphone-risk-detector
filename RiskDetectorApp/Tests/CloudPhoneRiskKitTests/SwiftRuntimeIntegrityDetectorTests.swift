import XCTest
@testable import CloudPhoneRiskKit

final class SwiftRuntimeIntegrityDetectorTests: XCTestCase {
    private func makeSnapshot() -> RiskSnapshot {
        RiskSnapshot(
            deviceID: "swift-runtime-test-device",
            device: TestFixtures.makeDeviceFingerprint(),
            network: TestFixtures.makeNetworkSignals(),
            behavior: TestFixtures.makeBehaviorSignals(),
            jailbreak: TestFixtures.makeDetectionResult()
        )
    }

    private func makeDeterministicRuntimeSnapshot() -> SwiftRuntimeIntegrityDetector.Snapshot {
        let metadata = SwiftRuntimeIntegrityDetector.MetadataSnapshot(
            inspectedTypeCount: 3,
            reflectionMismatchCount: 1,
            suspiciousPointerCount: 1,
            pointerLocalityBuckets: [
                "image_exec": 2,
                "unknown": 1,
            ]
        )
        let witness = SwiftRuntimeIntegrityDetector.WitnessSnapshot(
            sampleCount: 2,
            dispatchMismatchCount: 1,
            suspiciousPointerCount: 1,
            nonImageExecutablePointerCount: 1,
            pointerLocalityBuckets: [
                "anon_exec": 1,
                "image_exec": 1,
            ]
        )
        let closure = SwiftRuntimeIntegrityDetector.ClosureSnapshot(
            sampleCount: 4,
            canaryMismatchCount: 1,
            layoutAnomalyCount: 0,
            unstableAddressCount: 0,
            functionPointerLocality: "image_exec",
            contextPointerLocality: "image_data"
        )
        let existential = SwiftRuntimeIntegrityDetector.ExistentialSnapshot(
            sampleCount: 4,
            dynamicTypeMismatchCount: 1,
            pointerAnomalyCount: 1,
            pointerLocalityBuckets: [
                "unknown": 1,
                "image_data": 1,
            ]
        )
        return SwiftRuntimeIntegrityDetector.Snapshot(
            metadata: metadata,
            witness: witness,
            closure: closure,
            existential: existential
        )
    }

    func testSwiftRuntimeDetectorReturnsStructuredSignalsOrEmptyWithoutCrash() throws {
        let detector = SwiftRuntimeIntegrityDetector()

        let result = try detector.detect()
        XCTAssertGreaterThanOrEqual(result.score, 0)

        let signals = detector.asSignals()
        let expectedIDs: Set<String> = [
            SwiftRuntimeIntegrityDetector.metadataSignalID,
            SwiftRuntimeIntegrityDetector.witnessSignalID,
            SwiftRuntimeIntegrityDetector.closureSignalID,
            SwiftRuntimeIntegrityDetector.existentialSignalID,
        ]
        for signal in signals {
            XCTAssertTrue(expectedIDs.contains(signal.id))
            XCTAssertEqual(signal.category, ObfuscatedConstants.categoryAntiTamper)
            XCTAssertNotNil(signal.evidence["mechanism"])
            XCTAssertNotNil(signal.evidence["anomaly_count"])
            XCTAssertNotNil(signal.evidence["pointer_locality"])
        }
    }

    func testDeterministicSnapshotProducesExpectedSignals() {
        let snapshot = makeDeterministicRuntimeSnapshot()
        let detector = SwiftRuntimeIntegrityDetector(snapshotOverride: snapshot)
        let signals = detector.asSignals()
        XCTAssertEqual(Set(signals.map { $0.id }), [
            SwiftRuntimeIntegrityDetector.metadataSignalID,
            SwiftRuntimeIntegrityDetector.witnessSignalID,
            SwiftRuntimeIntegrityDetector.closureSignalID,
            SwiftRuntimeIntegrityDetector.existentialSignalID,
        ])
        XCTAssertEqual(signals.count, 4)

        let metadataSignal = signals.first { $0.id == SwiftRuntimeIntegrityDetector.metadataSignalID }
        XCTAssertNotNil(metadataSignal)
        XCTAssertEqual(metadataSignal?.evidence["mechanism"], "swift_metadata_consistency")
        XCTAssertEqual(metadataSignal?.evidence["anomaly_count"], "2")
        XCTAssertTrue(metadataSignal?.evidence["pointer_locality"]?.contains("image_exec=2") ?? false)

        let witnessSignal = signals.first { $0.id == SwiftRuntimeIntegrityDetector.witnessSignalID }
        XCTAssertNotNil(witnessSignal)
        XCTAssertEqual(witnessSignal?.evidence["mechanism"], "swift_protocol_witness_consistency")
        XCTAssertEqual(witnessSignal?.evidence["sample_count"], "2")
        XCTAssertTrue(witnessSignal?.evidence["pointer_locality"]?.contains("anon_exec=1") ?? false)
        XCTAssertEqual(witnessSignal?.evidence["non_image_executable_pointer_count"], "1")
        XCTAssertEqual(witnessSignal?.state, .tampered)

        let closureSignal = signals.first { $0.id == SwiftRuntimeIntegrityDetector.closureSignalID }
        XCTAssertNotNil(closureSignal)
        XCTAssertEqual(closureSignal?.evidence["mechanism"], "swift_closure_context_integrity")
        XCTAssertEqual(closureSignal?.evidence["pointer_locality"], "function=image_exec,context=image_data")
        XCTAssertEqual(closureSignal?.evidence["anomaly_count"], "1")
        XCTAssertEqual(closureSignal?.state, .soft(confidence: 0.64))

        let existentialSignal = signals.first { $0.id == SwiftRuntimeIntegrityDetector.existentialSignalID }
        XCTAssertNotNil(existentialSignal)
        XCTAssertEqual(existentialSignal?.evidence["mechanism"], "swift_existential_container_sanity")
        XCTAssertEqual(existentialSignal?.evidence["dynamic_type_mismatch_count"], "1")
        XCTAssertEqual(existentialSignal?.evidence["pointer_anomaly_count"], "1")
        XCTAssertEqual(existentialSignal?.state, .tampered)
    }

    func testProviderSwitchOffDoesNotScheduleOrEmitSwiftRuntimeSignals() {
        var configuration = AntiTamperingSignalProvider.Configuration.default
        configuration.enableSwiftRuntimeIntegrity = false
        let provider = AntiTamperingSignalProvider(configuration: configuration)
        let snapshot = makeSnapshot()

        let configuredCheckIDs = provider.configuredCheckIDs(snapshot: snapshot)
        XCTAssertFalse(configuredCheckIDs.contains(SwiftRuntimeIntegrityDetector.detectorID))

        let signals = provider.signals(snapshot: snapshot)
        XCTAssertFalse(signals.contains { signal in
            signal.id == SwiftRuntimeIntegrityDetector.metadataSignalID
                || signal.id == SwiftRuntimeIntegrityDetector.witnessSignalID
                || signal.id == SwiftRuntimeIntegrityDetector.closureSignalID
                || signal.id == SwiftRuntimeIntegrityDetector.existentialSignalID
        })
    }

    func testProviderSwitchOnSchedulesSwiftRuntimeDetector() {
        var configuration = AntiTamperingSignalProvider.Configuration.default
        configuration.enableSwiftRuntimeIntegrity = true
        let provider = AntiTamperingSignalProvider(configuration: configuration)

        let configuredCheckIDs = provider.configuredCheckIDs(snapshot: makeSnapshot())
        XCTAssertTrue(configuredCheckIDs.contains(SwiftRuntimeIntegrityDetector.detectorID))
    }
}
