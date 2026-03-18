import XCTest
@testable import CloudPhoneRiskKit

final class CapabilityProbeEngineTests: XCTestCase {

    // MARK: - CapabilityScore

    func testCapabilityScoreRiskContributionFormula() {
        let score = CapabilityScore(basicAnomalyCount: 3, qualitySuspicion: 5, totalProbes: 8)
        // riskContribution = basicAnomalyCount * 3 + qualitySuspicion
        XCTAssertEqual(score.riskContribution, 3 * 3 + 5)
    }

    func testCapabilityScoreZeroValues() {
        let score = CapabilityScore(basicAnomalyCount: 0, qualitySuspicion: 0, totalProbes: 8)
        XCTAssertEqual(score.riskContribution, 0)
    }

    func testCapabilityScoreToSignal() {
        let score = CapabilityScore(basicAnomalyCount: 2, qualitySuspicion: 4, totalProbes: 8)
        let signal = score.toSignal()

        XCTAssertEqual(signal.id, "capability_probe")
        XCTAssertEqual(signal.category, "capability")
        XCTAssertEqual(signal.score, Double(score.riskContribution))
        XCTAssertEqual(signal.layer, 3)
        XCTAssertEqual(signal.evidence["basicAnomalyCount"], "2")
        XCTAssertEqual(signal.evidence["qualitySuspicion"], "4")
        XCTAssertEqual(signal.evidence["totalProbes"], "8")
    }

    func testCapabilityScoreToSignalConfidenceCapped() {
        let score = CapabilityScore(basicAnomalyCount: 50, qualitySuspicion: 50, totalProbes: 8)
        let signal = score.toSignal()

        // confidence = min(riskContribution / 100.0, 1.0)
        if case .soft(let confidence) = signal.state {
            XCTAssertLessThanOrEqual(confidence, 1.0)
        } else {
            XCTFail("Expected .soft state")
        }
    }

    func testCapabilityScoreCodable() throws {
        let score = CapabilityScore(basicAnomalyCount: 1, qualitySuspicion: 2, totalProbes: 8)
        let data = try JSONEncoder().encode(score)
        let decoded = try JSONDecoder().decode(CapabilityScore.self, from: data)

        XCTAssertEqual(decoded.basicAnomalyCount, 1)
        XCTAssertEqual(decoded.qualitySuspicion, 2)
        XCTAssertEqual(decoded.totalProbes, 8)
        XCTAssertEqual(decoded.riskContribution, score.riskContribution)
    }

    // MARK: - ProbeResult

    func testProbeResultCodable() throws {
        let result = ProbeResult(
            id: "stat_bash",
            succeeded: false,
            elapsedMicros: 42,
            errnoValue: 2,
            expectedOutcome: .fail,
            maxElapsedMicros: 80,
            callerFrame: nil
        )
        let data = try JSONEncoder().encode(result)
        let decoded = try JSONDecoder().decode(ProbeResult.self, from: data)

        XCTAssertEqual(decoded.id, "stat_bash")
        XCTAssertFalse(decoded.succeeded)
        XCTAssertEqual(decoded.elapsedMicros, 42)
        XCTAssertEqual(decoded.errnoValue, 2)
        XCTAssertEqual(decoded.expectedOutcome, .fail)
    }

    // MARK: - CapabilityProbeEngine

    func testDefaultConfigValues() {
        let config = CapabilityProbeEngine.Config.default
        XCTAssertEqual(config.maxElapsedMicros, 80)
        XCTAssertTrue(config.enableQualityProbes)
        XCTAssertNil(config.customProbes)
    }

    func testEvaluateReturnsNonZeroTotalProbes() {
        let engine = CapabilityProbeEngine()
        let score = engine.evaluate()

        XCTAssertGreaterThan(score.totalProbes, 0, "Default probes should produce at least one result")
    }

    func testEvaluateDetailedMatchesEvaluate() {
        let engine = CapabilityProbeEngine()
        let (score, probes) = engine.evaluateDetailed()

        XCTAssertEqual(score.totalProbes, probes.count)
    }

    func testRunBasicProbesDefaultCount() {
        let engine = CapabilityProbeEngine()
        let probes = engine.runBasicProbes()

        // Default has 8 probes
        XCTAssertEqual(probes.count, 8)
    }

    func testCustomProbesOverrideDefaults() {
        let custom = [
            CapabilityProbeEngine.ProbeDefinition(id: "custom_1", expectedOutcome: .fail),
            CapabilityProbeEngine.ProbeDefinition(id: "custom_2", expectedOutcome: .pass),
        ]
        let config = CapabilityProbeEngine.Config(customProbes: custom)
        let engine = CapabilityProbeEngine(config: config)
        let probes = engine.runBasicProbes()

        XCTAssertEqual(probes.count, 2)
        XCTAssertEqual(probes[0].id, "custom_1")
        XCTAssertEqual(probes[1].id, "custom_2")
    }

    func testQualityProbesDisabled() {
        let config = CapabilityProbeEngine.Config(enableQualityProbes: false)
        let engine = CapabilityProbeEngine(config: config)
        let score = engine.evaluate()

        XCTAssertEqual(score.qualitySuspicion, 0, "Quality probes disabled should yield 0 suspicion")
    }

    func testRunQualityProbesTimingAnomaly() {
        let engine = CapabilityProbeEngine()
        // Simulate a failed probe with suspiciously high elapsed time
        let slowFail = ProbeResult(
            id: "stat_bash",
            succeeded: false,
            elapsedMicros: 200, // well above default 80
            errnoValue: 2, // ENOENT — expected
            maxElapsedMicros: 80
        )
        let suspicion = engine.runQualityProbes([slowFail])
        XCTAssertGreaterThanOrEqual(suspicion, 2, "Slow failure should add timing anomaly suspicion")
    }

    func testRunQualityProbesErrnoAnomaly() {
        let engine = CapabilityProbeEngine()
        // stat_bash failure with wrong errno (0 is not ENOENT/EACCES/EPERM)
        let wrongErrno = ProbeResult(
            id: "stat_bash",
            succeeded: false,
            elapsedMicros: 10,
            errnoValue: 0,
            maxElapsedMicros: 80
        )
        let suspicion = engine.runQualityProbes([wrongErrno])
        XCTAssertGreaterThanOrEqual(suspicion, 3, "Wrong errno should add suspicion")
    }

    func testRunQualityProbesHookFrameDetection() {
        let engine = CapabilityProbeEngine()
        let hookFrame = ProbeResult(
            id: "stat_bash",
            succeeded: false,
            elapsedMicros: 10,
            errnoValue: 2,
            callerFrame: "/usr/lib/frida-agent.dylib"
        )
        let suspicion = engine.runQualityProbes([hookFrame])
        XCTAssertGreaterThanOrEqual(suspicion, 5, "Frida frame should add high suspicion")
    }

    func testRunQualityProbesSucceededProbesSkipped() {
        let engine = CapabilityProbeEngine()
        let succeeded = ProbeResult(
            id: "stat_bash",
            succeeded: true,
            elapsedMicros: 200,
            errnoValue: 0,
            callerFrame: "/usr/lib/frida-agent.dylib"
        )
        let suspicion = engine.runQualityProbes([succeeded])
        XCTAssertEqual(suspicion, 0, "Succeeded probes should not generate suspicion")
    }

    func testFromRemoteConfig() {
        let probeConfig = ProbeConfig(version: "17.0", probes: [
            ProbeConfigItem(id: "stat_bash", expectedOutcome: "fail", maxElapsedUs: 100, weight: 2),
            ProbeConfigItem(id: "fork_ability", expectedOutcome: "fail", maxElapsedUs: 50, weight: 1),
        ])
        let engine = CapabilityProbeEngine.fromRemoteConfig(probeConfig)
        let probes = engine.runBasicProbes()

        XCTAssertEqual(probes.count, 2)
        XCTAssertEqual(probes[0].id, "stat_bash")
    }
}
