import XCTest
@testable import CloudPhoneRiskKit

final class ChallengeResultStoreTests: XCTestCase {

    // MARK: - Score Offset

    func testApplyStoresAdjustedScore() {
        let store = ChallengeResultStore.shared

        let result = ChallengeVerificationResult(
            challengeId: "ch-1",
            passed: true,
            adjustedScore: 15.0
        )
        store.apply(result: result)

        XCTAssertTrue(store.hasPendingOffset)
        XCTAssertEqual(store.currentScoreOffset(), 15.0)
    }

    func testConsumeScoreOffsetClearsState() {
        let store = ChallengeResultStore.shared

        store.apply(result: ChallengeVerificationResult(
            challengeId: "ch-2",
            passed: true,
            adjustedScore: -10.0
        ))

        let offset = store.consumeScoreOffset()
        XCTAssertEqual(offset, -10.0)

        // After consumption, should be nil
        XCTAssertNil(store.consumeScoreOffset())
        XCTAssertFalse(store.hasPendingOffset)
    }

    func testApplyWithNilAdjustedScore() {
        let store = ChallengeResultStore.shared

        store.apply(result: ChallengeVerificationResult(
            challengeId: "ch-3",
            passed: false,
            adjustedScore: nil
        ))

        XCTAssertFalse(store.hasPendingOffset)
        XCTAssertNil(store.consumeScoreOffset())
    }

    func testApplyClampsOutOfRangeScore() {
        let store = ChallengeResultStore.shared

        // Score > 100 should be clamped
        store.apply(result: ChallengeVerificationResult(
            challengeId: "ch-4",
            passed: false,
            adjustedScore: 200.0
        ))
        XCTAssertEqual(store.currentScoreOffset(), 100.0)
        _ = store.consumeScoreOffset()

        // Score < -100 should be clamped
        store.apply(result: ChallengeVerificationResult(
            challengeId: "ch-5",
            passed: true,
            adjustedScore: -500.0
        ))
        XCTAssertEqual(store.currentScoreOffset(), -100.0)
        _ = store.consumeScoreOffset()
    }

    // MARK: - Pending Mismatch Signals

    func testStorePendingMismatchSignal() {
        let store = ChallengeResultStore.shared

        let signal = RiskSignal(
            id: "challenge_hmac_mismatch",
            category: "integrity",
            score: 35,
            evidence: ["reason": "hmac_mismatch"],
            state: .tampered,
            layer: 3,
            weightHint: 80
        )

        store.storePendingMismatchSignal(signal)
        let consumed = store.consumePendingMismatchSignals()
        XCTAssertEqual(consumed.count, 1)
        XCTAssertEqual(consumed[0].id, "challenge_hmac_mismatch")
    }

    func testConsumePendingMismatchSignalsClearsQueue() {
        let store = ChallengeResultStore.shared

        let signal = RiskSignal(
            id: "test_signal",
            category: "integrity",
            score: 20,
            evidence: [:],
            state: .tampered,
            layer: 3,
            weightHint: 50
        )

        store.storePendingMismatchSignal(signal)
        store.storePendingMismatchSignal(signal)
        _ = store.consumePendingMismatchSignals()

        // Second consumption should be empty
        let second = store.consumePendingMismatchSignals()
        XCTAssertTrue(second.isEmpty)
    }

    // MARK: - Thread Safety

    func testConcurrentApplyAndConsume() {
        let store = ChallengeResultStore.shared
        let iterations = 100
        let group = DispatchGroup()

        for i in 0..<iterations {
            group.enter()
            DispatchQueue.global().async {
                store.apply(result: ChallengeVerificationResult(
                    challengeId: "concurrent-\(i)",
                    passed: i % 2 == 0,
                    adjustedScore: Double(i)
                ))
                _ = store.consumeScoreOffset()
                group.leave()
            }
        }

        let result = group.wait(timeout: .now() + 10)
        XCTAssertEqual(result, .success, "Concurrent access should not deadlock or crash")
    }
}
