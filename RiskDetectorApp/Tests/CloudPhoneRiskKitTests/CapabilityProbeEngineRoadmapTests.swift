import Darwin
import XCTest
@testable import CloudPhoneRiskKit

final class CapabilityProbeEngineRoadmapTests: XCTestCase {

    func testCustomProbesAreUsed() {
        let custom = [
            CapabilityProbeEngine.ProbeDefinition(
                id: "unknown_probe",
                expectedOutcome: .fail,
                maxElapsedMicros: 25,
                weight: 1
            ),
        ]

        let engine = CapabilityProbeEngine(
            config: .init(maxElapsedMicros: 80, enableQualityProbes: true, customProbes: custom)
        )

        let results = engine.runBasicProbes()
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results.first?.id, "unknown_probe")
    }

    func testExpectedOutcomeAffectsAnomalyCount() {
        let custom = [
            CapabilityProbeEngine.ProbeDefinition(
                id: "unknown_probe",
                expectedOutcome: .pass,
                maxElapsedMicros: 25,
                weight: 1
            ),
        ]

        let engine = CapabilityProbeEngine(
            config: .init(maxElapsedMicros: 80, enableQualityProbes: false, customProbes: custom)
        )

        let score = engine.evaluate()
        XCTAssertEqual(score.totalProbes, 1)
        XCTAssertEqual(score.basicAnomalyCount, 1, "期望 pass 但实际失败，应计为异常")
    }

    func testErrnoMatrixDetectsSuspiciousFailure() {
        let engine = CapabilityProbeEngine()

        let suspicious = ProbeResult(
            id: "fork_ability",
            succeeded: false,
            elapsedMicros: 10,
            errnoValue: EINVAL,
            expectedOutcome: .fail,
            maxElapsedMicros: 80
        )

        let normal = ProbeResult(
            id: "fork_ability",
            succeeded: false,
            elapsedMicros: 10,
            errnoValue: EPERM,
            expectedOutcome: .fail,
            maxElapsedMicros: 80
        )

        let suspiciousScore = engine.runQualityProbes([suspicious])
        let normalScore = engine.runQualityProbes([normal])

        XCTAssertGreaterThanOrEqual(suspiciousScore, 3)
        XCTAssertEqual(normalScore, 0)
    }

    func testProbeSpecificLatencyThreshold() {
        let engine = CapabilityProbeEngine()

        let slowFailure = ProbeResult(
            id: "sock_27042",
            succeeded: false,
            elapsedMicros: 120,
            errnoValue: ECONNREFUSED,
            expectedOutcome: .fail,
            maxElapsedMicros: 80
        )

        let suspicion = engine.runQualityProbes([slowFailure])
        XCTAssertGreaterThanOrEqual(suspicion, 2)
    }
}
