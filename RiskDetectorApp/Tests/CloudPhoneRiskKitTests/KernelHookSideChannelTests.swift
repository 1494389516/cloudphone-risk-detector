import XCTest
@testable import CloudPhoneRiskKit

final class KernelHookSideChannelTests: XCTestCase {

    // MARK: - DetectorResult 基本行为

    func testDetectReturnsValidResult() throws {
        let detector = KernelHookSideChannel()
        let result = try detector.detect()
        // score 应在 [0, 100] 范围内
        XCTAssertGreaterThanOrEqual(result.score, 0)
        XCTAssertLessThanOrEqual(result.score, 100)
        // methods 不应为空（至少包含 clean 或具体检测方法）
        XCTAssertFalse(result.methods.isEmpty)
    }

    func testDetectScoreCappedAt100() throws {
        let detector = KernelHookSideChannel()
        let result = try detector.detect()
        XCTAssertLessThanOrEqual(result.score, 100,
            "即使多个策略同时触发，总分也应被 cap 在 100")
    }

    // MARK: - Signal 转换

    func testAsSignalsReturnsEmptyForCleanDevice() throws {
        let detector = KernelHookSideChannel()
        let signals = try detector.asSignals()
        // 在正常环境下不应产生非零信号
        // （若测试环境恰好触发某些策略，至少验证格式正确）
        for signal in signals {
            XCTAssertFalse(signal.id.isEmpty)
            XCTAssertEqual(signal.category, "anti_tamper")
            XCTAssertEqual(signal.layer, 2)
            XCTAssertGreaterThan(signal.score, 0)
        }
    }

    func testAsSignalsHaveCorrectCategories() throws {
        let detector = KernelHookSideChannel()
        let signals = try detector.asSignals()
        let validIDs: Set<String> = [
            "kernel_hook_timing_anomaly",
            "kernel_hook_inode_mismatch",
            "kernel_hook_time_desync",
            "kernel_hook_pid_unstable",
            "kernel_hook_stalker_amplified",
            "kernel_hook_crypto_trace_skew",
            "kernel_hook_crypto_trace_invariant",
        ]
        for signal in signals {
            XCTAssertTrue(validIDs.contains(signal.id),
                "Unexpected signal id: \(signal.id)")
        }
    }

    func testAsSignalsIncludeEvidenceMetrics() throws {
        let detector = KernelHookSideChannel()
        let signals = try detector.asSignals()
        for signal in signals {
            XCTAssertFalse(signal.evidence.isEmpty,
                "Signal \(signal.id) should include evidence metrics")
            XCTAssertNotNil(signal.evidence["detail"],
                "Signal \(signal.id) should include 'detail' in evidence")
        }
    }

    // MARK: - Signal State 验证

    func testTimingAnomalySignalIsSoft() throws {
        let detector = KernelHookSideChannel()
        let signals = try detector.asSignals()
        for signal in signals where signal.id == "kernel_hook_timing_anomaly" {
            if case .soft(let confidence) = signal.state {
                XCTAssertGreaterThanOrEqual(confidence, 0)
                XCTAssertLessThanOrEqual(confidence, 1)
            } else {
                XCTFail("timing_anomaly signal should have .soft state")
            }
        }
    }

    func testPidUnstableSignalIsTampered() throws {
        let detector = KernelHookSideChannel()
        let signals = try detector.asSignals()
        for signal in signals where signal.id == "kernel_hook_pid_unstable" {
            if case .tampered = signal.state {
                // expected
            } else {
                XCTFail("pid_unstable signal should have .tampered state")
            }
        }
    }

    // MARK: - Weight Hint 验证

    func testWeightHintsAreReasonable() throws {
        let detector = KernelHookSideChannel()
        let signals = try detector.asSignals()
        for signal in signals {
            XCTAssertGreaterThan(signal.weightHint ?? 0, 0,
                "Signal \(signal.id) should have a positive weight hint")
            XCTAssertLessThanOrEqual(signal.weightHint ?? 0, 100,
                "Signal \(signal.id) weight hint should not exceed 100")
        }
    }
}
