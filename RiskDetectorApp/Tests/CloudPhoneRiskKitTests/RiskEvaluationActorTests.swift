import XCTest
@testable import CloudPhoneRiskKit

@available(iOS 13.0, macOS 10.15, *)
final class RiskEvaluationActorTests: XCTestCase {

    // MARK: - Basic Functionality

    func testEvaluateReturnsReport() async {
        let actor = RiskEvaluationActor.shared
        await actor.reset()

        let report = await actor.evaluate()
        // On test host (macOS), score may vary; just verify we get a valid report
        XCTAssertGreaterThanOrEqual(report.score, 0)
        XCTAssertLessThanOrEqual(report.score, 100)
    }

    func testLastResultIsNilAfterReset() async {
        let actor = RiskEvaluationActor.shared
        await actor.reset()

        let last = await actor.lastResult()
        XCTAssertNil(last, "lastResult should be nil after reset")
    }

    func testLastResultAvailableAfterEvaluate() async {
        let actor = RiskEvaluationActor.shared
        await actor.reset()

        let report = await actor.evaluate()
        let last = await actor.lastResult()
        XCTAssertNotNil(last)
        XCTAssertEqual(last?.score, report.score)
    }

    func testResetClearsState() async {
        let actor = RiskEvaluationActor.shared

        _ = await actor.evaluate()
        await actor.reset()

        let last = await actor.lastResult()
        XCTAssertNil(last)
    }

    // MARK: - Concurrency Safety

    func testConcurrentEvaluationsAreActorIsolated() async {
        let actor = RiskEvaluationActor.shared
        await actor.reset()

        // Launch multiple concurrent evaluations
        await withTaskGroup(of: CPRiskReport.self) { group in
            for _ in 0..<5 {
                group.addTask {
                    await actor.evaluate()
                }
            }

            var reports: [CPRiskReport] = []
            for await report in group {
                reports.append(report)
            }

            // All evaluations should complete without crashes (actor isolation)
            XCTAssertEqual(reports.count, 5)
        }
    }
}
