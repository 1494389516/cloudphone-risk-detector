import XCTest
@testable import CloudPhoneRiskKit

// MARK: - Actor Facades for Key Components

/// Tests for actor-based facades that provide async/await access to SDK components.
/// These facades coexist with the sync Mutex-based implementations.

@available(iOS 13.0, macOS 10.15, *)
final class ActorFacadeTests: XCTestCase {

    // MARK: - ChallengeResultStore Actor Facade

    func testChallengeResultStoreConcurrentAsyncAccess() async {
        let store = ChallengeResultStore.shared

        // Simulate concurrent async access
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<20 {
                group.addTask {
                    store.apply(result: ChallengeVerificationResult(
                        challengeId: "async-\(i)",
                        passed: true,
                        adjustedScore: Double(i)
                    ))
                    _ = store.consumeScoreOffset()
                }
            }
        }

        // Should not crash or deadlock
    }

    // MARK: - DynamicFeatureList Thread Safety

    func testDynamicFeatureListConcurrentAccess() {
        let list = DynamicFeatureList.shared
        let iterations = 50
        let group = DispatchGroup()

        // Concurrent reads
        for _ in 0..<iterations {
            group.enter()
            DispatchQueue.global().async {
                _ = list.suspiciousLibraries
                _ = list.suspiciousPaths
                _ = list.suspiciousPorts
                group.leave()
            }
        }

        // Concurrent config apply
        for i in 0..<10 {
            group.enter()
            DispatchQueue.global().async {
                list.applyRemoteConfig(
                    additionalSuspiciousLibraries: ["lib_\(i)"],
                    additionalSuspiciousPaths: ["/tmp/test_\(i)"],
                    additionalSuspiciousPorts: [50000 + i]
                )
                group.leave()
            }
        }

        let result = group.wait(timeout: .now() + 10)
        XCTAssertEqual(result, .success)

        // Reset for other tests
        list.resetDynamic()
    }

    // MARK: - RiskEvaluationActor Rapid Evaluation

    func testRapidEvaluationRateLimiting() async {
        let actor = RiskEvaluationActor.shared
        await actor.reset()

        // Rapid-fire evaluations should not crash
        for _ in 0..<15 {
            _ = await actor.evaluate()
        }

        // Should still have a valid last result
        let last = await actor.lastResult()
        XCTAssertNotNil(last)
    }

    // MARK: - StorageIntegrityGuard Thread Safety

    func testStorageIntegrityGuardConcurrent() {
        let iterations = 50
        let group = DispatchGroup()
        let testData = Data("concurrent_test".utf8)

        for _ in 0..<iterations {
            group.enter()
            DispatchQueue.global().async {
                let sig = StorageIntegrityGuard.sign(testData, purpose: "concurrent")
                _ = StorageIntegrityGuard.verify(testData, signature: sig, purpose: "concurrent")
                group.leave()
            }
        }

        let result = group.wait(timeout: .now() + 10)
        XCTAssertEqual(result, .success)
    }

    // MARK: - ChallengeSession Thread Safety

    func testChallengeSessionConcurrentStateAccess() {
        let session = ChallengeSession()
        let iterations = 50
        let group = DispatchGroup()

        for _ in 0..<iterations {
            group.enter()
            DispatchQueue.global().async {
                _ = session.state
                _ = session.currentChallengeId
                _ = session.submittedChallengeIds
                _ = session.executionStatus
                group.leave()
            }
        }

        let result = group.wait(timeout: .now() + 10)
        XCTAssertEqual(result, .success)
    }
}
