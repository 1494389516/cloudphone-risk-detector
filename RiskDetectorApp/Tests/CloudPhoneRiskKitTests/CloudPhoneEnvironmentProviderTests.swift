import XCTest
@testable import CloudPhoneRiskKit

/// Tests for the three CVD-hardening changes to CloudPhoneEnvironmentProvider:
///   1. Process name signal weight reduction (90 → 35)
///   2. Thermal state cross-call history (eliminating single-sample false positives)
///   3. RTT kurtosis analysis (detecting artificial jitter injection)
final class CloudPhoneEnvironmentProviderTests: XCTestCase {

    private let provider = CloudPhoneEnvironmentProvider.shared

    private var dummySnapshot: RiskSnapshot {
        RiskSnapshot(
            deviceID: "test-cpenv",
            device: TestFixtures.makeDeviceFingerprint(),
            network: TestFixtures.makeNetworkSignals(),
            behavior: TestFixtures.makeBehaviorSignals(),
            jailbreak: TestFixtures.makeDetectionResult()
        )
    }

    override func setUp() {
        super.setUp()
        // Clean up thermal history between tests.
        UserDefaults.standard.removeObject(forKey: CloudPhoneEnvironmentProvider.thermalSnapshotKey)
    }

    override func tearDown() {
        UserDefaults.standard.removeObject(forKey: CloudPhoneEnvironmentProvider.thermalSnapshotKey)
        super.tearDown()
    }

    // MARK: - 1. Process name weight reduction

    func testProcessNameSignalWeight() {
        let signals = provider.signals(snapshot: dummySnapshot)
        let processSignal = signals.first { $0.id == "cloud_process_detected" }

        XCTAssertNotNil(processSignal, "应包含 cloud_process_detected 信号")
        XCTAssertEqual(processSignal?.weightHint, 35,
            "进程名匹配是弱信号，权重应降到 35（CVD 内核级定制可轻易重命名进程）")
    }

    // MARK: - 2. Thermal state history

    func testThermalHistoryPersistence() {
        // Write a history, read it back.
        let history = [0, 0, 1, 0, 2]
        provider.saveThermalHistory(history)
        let loaded = provider.loadThermalHistory()
        XCTAssertEqual(loaded, history)
    }

    func testThermalHistoryEmptyReturnsEmpty() {
        let loaded = provider.loadThermalHistory()
        XCTAssertTrue(loaded.isEmpty)
    }

    func testThermalSignalUnavailableWhenHistoryInsufficient() {
        // Pre-populate with fewer than thermalHistoryMinCount (3) readings.
        provider.saveThermalHistory([0, 0])

        let signals = provider.signals(snapshot: dummySnapshot)
        let thermal = signals.first { $0.id == "thermal_state_anomaly" }

        XCTAssertNotNil(thermal)
        // In simulator the signal is always .unavailable via the #if guard, which is fine.
        // On non-simulator with < 3 readings, it should also be .unavailable.
        #if targetEnvironment(simulator)
        XCTAssertEqual(thermal?.evidence["detail"], "simulator")
        #else
        XCTAssertEqual(thermal?.evidence["detail"], "insufficient_history")
        #endif
    }

    // MARK: - 3. Kurtosis computation

    func testKurtosisNormalDistribution() {
        // Approximate normal: symmetric bell curve.
        // The values below are drawn from N(0,1); kurtosis should be ≈ 3.0.
        let samples: [Double] = [
            -1.5, -1.0, -0.8, -0.5, -0.3, -0.1,
             0.0,  0.1,  0.3,  0.5,  0.8,  1.0, 1.5,
        ]
        let mean = samples.reduce(0, +) / Double(samples.count)
        let variance = provider.computeVariance(samples)
        let kurt = provider.computeKurtosis(samples, mean: mean, variance: variance)

        XCTAssertNotNil(kurt)
        // Pearson kurtosis for normal ≈ 3.0; this hand-picked sample is close.
        XCTAssertGreaterThan(kurt!, 2.0, "正态型分布峰度应 > 2.0")
        XCTAssertLessThan(kurt!, 4.5, "正态型分布峰度应 < 4.5")
    }

    func testKurtosisUniformDistribution() {
        // Uniform distribution: kurtosis ≈ 1.8 (platykurtic).
        // Evenly spaced values simulate artificial jitter injection.
        let samples: [Double] = Array(stride(from: 1.0, through: 10.0, by: 1.0))
        let mean = samples.reduce(0, +) / Double(samples.count)
        let variance = provider.computeVariance(samples)
        let kurt = provider.computeKurtosis(samples, mean: mean, variance: variance)

        XCTAssertNotNil(kurt)
        XCTAssertLessThan(kurt!, 2.2,
            "均匀分布峰度应 < 2.2，表明是人工注入的抖动而非真实网络噪声")
    }

    func testKurtosisReturnsNilForTooFewSamples() {
        let samples: [Double] = [1.0, 2.0, 3.0]
        let mean = samples.reduce(0, +) / Double(samples.count)
        let variance = provider.computeVariance(samples)
        let kurt = provider.computeKurtosis(samples, mean: mean, variance: variance)

        XCTAssertNil(kurt, "< 4 个样本时应返回 nil")
    }

    func testKurtosisReturnsNilForZeroVariance() {
        let samples: [Double] = [5.0, 5.0, 5.0, 5.0, 5.0]
        let mean = 5.0
        let kurt = provider.computeKurtosis(samples, mean: mean, variance: 0.0)

        XCTAssertNil(kurt, "方差为零时应返回 nil（退化分布）")
    }

    // MARK: - Variance helper

    func testComputeVarianceSingleElement() {
        XCTAssertEqual(provider.computeVariance([42.0]), 0)
    }

    func testComputeVarianceKnownValues() {
        // [2, 4, 4, 4, 5, 5, 7, 9] → sample variance = 4.571…
        let v = provider.computeVariance([2, 4, 4, 4, 5, 5, 7, 9])
        XCTAssertEqual(v, 32.0 / 7.0, accuracy: 1e-10)
    }

    // MARK: - Provider ID

    func testProviderID() {
        XCTAssertEqual(provider.id, "cloudphone_environment")
    }

    // MARK: - Signal structure

    func testSignalsContainExpectedIDs() {
        let signals = provider.signals(snapshot: dummySnapshot)
        let ids = Set(signals.map(\.id))
        let expectedIDs: Set<String> = [
            "network_latency_pattern",
            "screen_resolution_anomaly",
            "thermal_state_anomaly",
            "cloud_process_detected",
            "locale_timezone_mismatch",
        ]
        for expected in expectedIDs {
            XCTAssertTrue(ids.contains(expected), "缺少预期信号 ID: \(expected)")
        }
    }
}
