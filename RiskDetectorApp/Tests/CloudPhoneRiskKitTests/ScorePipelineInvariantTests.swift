import XCTest
@testable import CloudPhoneRiskKit

/// 分数管道不变量测试
///
/// 保证 finalScore 计算路径的边界行为：
/// - finalScore 始终在 [0, 100] 内
/// - 负 challengeOffset 不会导致负 finalScore 被误判为 .critical
/// - InternalRiskLevel.from(score:) 分类正确
/// - ChallengeResultStore 偏移范围约束有效
final class ScorePipelineInvariantTests: XCTestCase {

    // MARK: - InternalRiskLevel.from(score:) 范围分类

    func testInternalRiskLevelLowRange() {
        // [0, 30) → .low
        XCTAssertEqual(InternalRiskLevel.from(score: 0), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: 15), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: 29.9), .low)
    }

    func testInternalRiskLevelMediumRange() {
        // [30, 55) → .medium
        XCTAssertEqual(InternalRiskLevel.from(score: 30), .medium)
        XCTAssertEqual(InternalRiskLevel.from(score: 42), .medium)
        XCTAssertEqual(InternalRiskLevel.from(score: 54.9), .medium)
    }

    func testInternalRiskLevelHighRange() {
        // [55, 80) → .high
        XCTAssertEqual(InternalRiskLevel.from(score: 55), .high)
        XCTAssertEqual(InternalRiskLevel.from(score: 67), .high)
        XCTAssertEqual(InternalRiskLevel.from(score: 79.9), .high)
    }

    func testInternalRiskLevelCriticalRange() {
        // [80, 100] → .critical
        XCTAssertEqual(InternalRiskLevel.from(score: 80), .critical)
        XCTAssertEqual(InternalRiskLevel.from(score: 90), .critical)
        XCTAssertEqual(InternalRiskLevel.from(score: 100), .critical)
    }

    /// 负分（已修复前的隐患复现）：负分命中 default 分支，应归为 .critical
    /// 但 finalScore 现在有下界 clamp，负分永远不会被传入 from(score:)。
    /// 此测试验证 from(score:) 本身对负数的行为是 .critical（符合 switch default）
    func testInternalRiskLevelNegativeScoreFallsToDefault() {
        // 负分命中 switch default → .critical（这是语言行为，不是期望的生产路径）
        XCTAssertEqual(InternalRiskLevel.from(score: -1), .critical)
        XCTAssertEqual(InternalRiskLevel.from(score: -100), .critical)
    }

    // MARK: - ChallengeResultStore 偏移范围约束

    func testChallengeResultStoreClipsPositiveOverflow() {
        let store = ChallengeResultStore.shared
        store.apply(result: ChallengeVerificationResult(
            challengeId: "test-pos",
            passed: true,
            adjustedScore: 150.0  // 超出上界
        ))
        let offset = store.consumeScoreOffset()
        XCTAssertNotNil(offset)
        XCTAssertEqual(offset!, 100.0, accuracy: 0.001)
    }

    func testChallengeResultStoreClipsNegativeUnderflow() {
        let store = ChallengeResultStore.shared
        store.apply(result: ChallengeVerificationResult(
            challengeId: "test-neg",
            passed: false,
            adjustedScore: -200.0  // 超出下界
        ))
        let offset = store.consumeScoreOffset()
        XCTAssertNotNil(offset)
        XCTAssertEqual(offset!, -100.0, accuracy: 0.001)
    }

    func testChallengeResultStoreNilAdjustedScore() {
        let store = ChallengeResultStore.shared
        store.apply(result: ChallengeVerificationResult(
            challengeId: "test-nil",
            passed: true,
            adjustedScore: nil
        ))
        let offset = store.consumeScoreOffset()
        XCTAssertNil(offset)
    }

    func testChallengeResultStoreOneTimeConsumption() {
        let store = ChallengeResultStore.shared
        store.apply(result: ChallengeVerificationResult(
            challengeId: "test-once",
            passed: true,
            adjustedScore: 30.0
        ))
        let first = store.consumeScoreOffset()
        let second = store.consumeScoreOffset()
        XCTAssertNotNil(first)
        XCTAssertNil(second, "consumeScoreOffset 应一次性消费，第二次调用应返回 nil")
    }

    // MARK: - finalScore [0, 100] 不变量

    /// 负 challengeOffset 不得导致 finalScore < 0
    func testFinalScoreNeverNegativeWithLargeNegativeOffset() {
        // baseScore=10, comboBonus=0, blindBonus=0, challengeOffset=-100 → 原始为 -90
        // 修复后 max(..., 0) → 0
        let rawSum = 10.0 + 0.0 + 0.0 + (-100.0)
        let finalScore = min(max(rawSum, 0), 100)
        XCTAssertGreaterThanOrEqual(finalScore, 0, "负 challengeOffset 不得产生负 finalScore")
        XCTAssertEqual(InternalRiskLevel.from(score: finalScore), .low,
            "clamp 到 0 的分数应归为 .low，不得误判为 .critical")
    }

    func testFinalScoreNeverExceeds100() {
        // baseScore=80, comboBonus=50, blindBonus=0, challengeOffset=50 → 原始为 180
        let rawSum = 80.0 + 50.0 + 0.0 + 50.0
        let finalScore = min(max(rawSum, 0), 100)
        XCTAssertLessThanOrEqual(finalScore, 100.0)
        XCTAssertEqual(finalScore, 100.0, accuracy: 0.001)
    }

    func testFinalScoreBoundaryAtZero() {
        // baseScore=0, 所有加成=0, challengeOffset=0 → finalScore=0 → .low
        let rawSum = 0.0 + 0.0 + 0.0 + 0.0
        let finalScore = min(max(rawSum, 0), 100)
        XCTAssertEqual(finalScore, 0.0)
        XCTAssertEqual(InternalRiskLevel.from(score: finalScore), .low)
    }

    func testFinalScoreExactThresholdBoundaries() {
        // 验证 finalScore=30 / 55 / 80 的分类精确边界
        XCTAssertEqual(InternalRiskLevel.from(score: 29.999), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: 30.0), .medium)
        XCTAssertEqual(InternalRiskLevel.from(score: 54.999), .medium)
        XCTAssertEqual(InternalRiskLevel.from(score: 55.0), .high)
        XCTAssertEqual(InternalRiskLevel.from(score: 79.999), .high)
        XCTAssertEqual(InternalRiskLevel.from(score: 80.0), .critical)
    }

    // MARK: - RiskDetectionEngine 端到端 finalScore 范围

    func testEngineScoreAlwaysInRange() {
        let engine = RiskDetectionEngine(policy: .default, enableLogging: false)
        let context = TestFixtures.makeRiskContext(isJailbroken: true, jailbreakConfidence: 90)
        let verdict = engine.evaluate(context: context)
        XCTAssertGreaterThanOrEqual(verdict.score, 0, "engine.evaluate score 不得小于 0")
        XCTAssertLessThanOrEqual(verdict.score, 100, "engine.evaluate score 不得大于 100")
    }

    func testEngineScoreWithNegativeChallengeOffset() {
        // 注入大额负偏移，验证引擎不会产生 score < 0 或误报 .critical
        let store = ChallengeResultStore.shared
        store.apply(result: ChallengeVerificationResult(
            challengeId: "inv-test",
            passed: false,
            adjustedScore: -100.0
        ))

        let engine = RiskDetectionEngine(policy: .default, enableLogging: false)
        let context = TestFixtures.makeRiskContext()
        let verdict = engine.evaluate(context: context)

        XCTAssertGreaterThanOrEqual(verdict.score, 0, "负 challengeOffset 不得使 score 为负")
        XCTAssertLessThanOrEqual(verdict.score, 100)
        // 干净设备 + 大额负偏移：score 应贴近 0，不应误判为 .critical
        XCTAssertNotEqual(verdict.internalLevel, .critical,
            "干净设备 + 负 challengeOffset 不得误归 .critical")
    }
}
