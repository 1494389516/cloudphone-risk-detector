import XCTest
@testable import CloudPhoneRiskKit

final class RiskSignalTests: XCTestCase {

    // MARK: - RiskSignal

    func testRiskSignalInit() {
        let signal = RiskSignal(
            id: "vpn_active",
            category: "network",
            score: 10,
            evidence: ["iface": "utun0"],
            state: .hard(detected: true),
            layer: 2,
            weightHint: 0.8
        )
        XCTAssertEqual(signal.id, "vpn_active")
        XCTAssertEqual(signal.category, "network")
        XCTAssertEqual(signal.score, 10)
        XCTAssertEqual(signal.evidence["iface"], "utun0")
        XCTAssertEqual(signal.layer, 2)
        XCTAssertEqual(signal.weightHint, 0.8)
    }

    func testRiskSignalDefaultValues() {
        let signal = RiskSignal(id: "test", category: "test", score: 5, evidence: [:])
        XCTAssertNil(signal.state)
        XCTAssertNil(signal.layer)
        XCTAssertEqual(signal.weightHint, 0)
    }

    // MARK: - RiskSignalState

    func testRiskSignalStateCodable() throws {
        let states: [RiskSignalState] = [
            .hard(detected: true),
            .hard(detected: false),
            .soft(confidence: 0.75),
            .serverRequired,
            .unavailable,
            .tampered,
        ]
        for state in states {
            let data = try JSONEncoder().encode(state)
            let decoded = try JSONDecoder().decode(RiskSignalState.self, from: data)
            XCTAssertEqual(decoded, state, "Failed round-trip for \(state)")
        }
    }

    func testRiskSignalStateEquality() {
        XCTAssertEqual(RiskSignalState.hard(detected: true), RiskSignalState.hard(detected: true))
        XCTAssertNotEqual(RiskSignalState.hard(detected: true), RiskSignalState.hard(detected: false))
        XCTAssertEqual(RiskSignalState.tampered, RiskSignalState.tampered)
        XCTAssertNotEqual(RiskSignalState.tampered, RiskSignalState.unavailable)
    }

    // MARK: - RiskSignal Codable

    func testRiskSignalCodable() throws {
        let signal = RiskSignal(
            id: "test_signal",
            category: "test",
            score: 42.5,
            evidence: ["key": "value"],
            state: .soft(confidence: 0.8),
            layer: 3,
            weightHint: 0.9
        )
        let data = try JSONEncoder().encode(signal)
        let decoded = try JSONDecoder().decode(RiskSignal.self, from: data)
        XCTAssertEqual(decoded.id, signal.id)
        XCTAssertEqual(decoded.category, signal.category)
        XCTAssertEqual(decoded.score, signal.score)
        XCTAssertEqual(decoded.evidence, signal.evidence)
        XCTAssertEqual(decoded.state, signal.state)
        XCTAssertEqual(decoded.layer, signal.layer)
        XCTAssertEqual(decoded.weightHint, signal.weightHint)
    }

    // MARK: - DetectionResult

    func testDetectionResultClean() {
        let result = DetectionResult(
            isJailbroken: false,
            confidence: 0,
            detectedMethods: [],
            details: "clean"
        )
        XCTAssertFalse(result.isJailbroken)
        XCTAssertEqual(result.confidence, 0)
        XCTAssertTrue(result.detectedMethods.isEmpty)
    }

    func testDetectionResultJailbroken() {
        let result = DetectionResult(
            isJailbroken: true,
            confidence: 85,
            detectedMethods: ["file:/Applications/Cydia.app", "dylib:FridaGadget"],
            details: "multiple_hits"
        )
        XCTAssertTrue(result.isJailbroken)
        XCTAssertEqual(result.confidence, 85)
        XCTAssertEqual(result.detectedMethods.count, 2)
    }

    // MARK: - DetectorResult

    func testDetectorResultEmpty() {
        let result = DetectorResult.empty
        XCTAssertEqual(result.score, 0)
        XCTAssertTrue(result.methods.isEmpty)
    }

    // MARK: - BehaviorSignals

    func testMotionMetricsEmpty() {
        let empty = MotionMetrics.empty
        XCTAssertEqual(empty.sampleCount, 0)
        XCTAssertNil(empty.stillnessRatio)
        XCTAssertNil(empty.motionEnergy)
    }

    func testBehaviorSignalsActionCount() {
        let signals = BehaviorSignals(
            touch: TouchMetrics(
                sampleCount: 10, tapCount: 5, swipeCount: 3,
                coordinateSpread: nil, intervalCV: nil, averageLinearity: nil,
                forceVariance: nil, majorRadiusVariance: nil
            ),
            motion: .empty
        )
        XCTAssertEqual(signals.actionCount, 8)
    }
}
