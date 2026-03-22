import XCTest
@testable import CloudPhoneRiskKit

/// Tests verifying that DetectorRegistering protocol enables proper dependency injection.
final class DetectorRegistryMockTests: XCTestCase {

    private var mock: MockDetectorRegistry!
    
    private struct NoopDetector: Detector {
        func detect() throws -> DetectorResult { .empty }
    }

    override func setUp() {
        super.setUp()
        mock = MockDetectorRegistry()
    }

    override func tearDown() {
        mock = nil
        super.tearDown()
    }

    // MARK: - Protocol Conformance

    func testMockConformsToProtocol() {
        let registry: DetectorRegistering = mock
        XCTAssertNotNil(registry)
    }

    // MARK: - Stubbed Detection

    func testDetectReturnsStubbedResult() {
        mock.stubbedResults[.frida] = DetectorResult(score: 85, methods: ["frida_port:27042"])
        let result = mock.detect(type: .frida)
        XCTAssertEqual(result.score, 85)
        XCTAssertEqual(result.methods, ["frida_port:27042"])
    }

    func testDetectReturnsDefaultForUnstubbed() {
        let result = mock.detect(type: .file)
        XCTAssertEqual(result.score, 0)
        XCTAssertEqual(result.methods, ["mock:no_result"])
    }

    func testDetectAllAggregatesEnabledTypes() {
        mock.stubbedResults[.frida] = DetectorResult(score: 40, methods: ["frida"])
        mock.stubbedResults[.debugger] = DetectorResult(score: 30, methods: ["debugger"])
        mock.stubbedResults[.file] = DetectorResult(score: 20, methods: ["jailbreak"])

        let result = mock.detectAll(enabledTypes: [.frida, .debugger])
        XCTAssertEqual(result.totalScore, 70)
        XCTAssertTrue(result.allMethods.contains("frida"))
        XCTAssertTrue(result.allMethods.contains("debugger"))
        XCTAssertFalse(result.allMethods.contains("jailbreak"))
        XCTAssertEqual(mock.detectAllCalledCount, 1)
    }

    func testDetectAllCapsScoreAt100() {
        mock.stubbedResults[.frida] = DetectorResult(score: 80, methods: ["frida"])
        mock.stubbedResults[.debugger] = DetectorResult(score: 80, methods: ["debugger"])

        let result = mock.detectAll(enabledTypes: [.frida, .debugger])
        XCTAssertEqual(result.totalScore, 100, "Total score should cap at 100")
    }

    // MARK: - Call Tracking

    func testDetectTracksCalledTypes() {
        _ = mock.detect(type: .frida)
        _ = mock.detect(type: .debugger)
        _ = mock.detect(type: .frida)

        XCTAssertEqual(mock.detectCalledTypes.count, 3)
        XCTAssertEqual(mock.detectCalledTypes[0], .frida)
        XCTAssertEqual(mock.detectCalledTypes[1], .debugger)
        XCTAssertEqual(mock.detectCalledTypes[2], .frida)
    }

    // MARK: - Seal Behavior

    func testSealPreventsRegistration() {
        mock.register(type: .frida, factory: { NoopDetector() })
        XCTAssertTrue(mock.registeredTypes.contains(.frida))

        mock.seal()
        XCTAssertTrue(mock.isSealed)
        XCTAssertEqual(mock.sealCallCount, 1)

        mock.register(type: .debugger, factory: { NoopDetector() })
        XCTAssertFalse(mock.registeredTypes.contains(.debugger), "Registration after seal should be no-op")
    }

    func testSealPreventsUnregistration() {
        mock.register(type: .frida, factory: { NoopDetector() })
        mock.seal()

        mock.unregister(type: .frida)
        XCTAssertTrue(mock.registeredTypes.contains(.frida), "Unregistration after seal should be no-op")
    }

    // MARK: - Availability

    func testIsAvailableRespectsMinOS() {
        mock.stubbedManifest[.frida] = DetectorRegistry.DetectorManifest(minOS: 15.0)

        XCTAssertTrue(mock.isAvailable(.frida, osVersion: 15.0))
        XCTAssertTrue(mock.isAvailable(.frida, osVersion: 17.0))
        XCTAssertFalse(mock.isAvailable(.frida, osVersion: 14.0))
    }

    func testIsAvailableRespectsMaxOS() {
        mock.stubbedManifest[.debugger] = DetectorRegistry.DetectorManifest(minOS: 14.0, maxOS: 16.0)

        XCTAssertTrue(mock.isAvailable(.debugger, osVersion: 14.0))
        XCTAssertTrue(mock.isAvailable(.debugger, osVersion: 16.0))
        XCTAssertFalse(mock.isAvailable(.debugger, osVersion: 17.0))
    }

    // MARK: - Reset

    func testResetClearsAllState() {
        mock.stubbedResults[.frida] = DetectorResult(score: 50, methods: [])
        _ = mock.detect(type: .frida)
        mock.seal()

        mock.reset()

        XCTAssertTrue(mock.stubbedResults.isEmpty)
        XCTAssertTrue(mock.detectCalledTypes.isEmpty)
        XCTAssertFalse(mock.isSealed)
        XCTAssertEqual(mock.sealCallCount, 0)
    }

    // MARK: - Integration: Mock as Dependency

    func testMockCanBeUsedAsDependency() {
        // Simulate a component that takes DetectorRegistering as dependency
        func evaluateRisk(registry: DetectorRegistering, types: Set<DetectorRegistry.DetectorType>) -> Double {
            let result = registry.detectAll(enabledTypes: types)
            return result.totalScore
        }

        mock.stubbedResults[.frida] = DetectorResult(score: 45, methods: ["frida_detected"])
        mock.stubbedResults[.file] = DetectorResult(score: 30, methods: ["jailbreak_detected"])

        let score = evaluateRisk(registry: mock, types: [.frida, .file])
        XCTAssertEqual(score, 75)
    }
}
