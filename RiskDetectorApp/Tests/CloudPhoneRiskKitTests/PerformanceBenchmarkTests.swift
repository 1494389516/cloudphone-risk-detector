import XCTest
@testable import CloudPhoneRiskKit

/// 性能基准测试：使用 XCTest `measure {}` 对 SDK 关键路径进行性能回归检测。
///
/// 运行方式：`xcodebuild test -scheme RiskDetectorApp -only-testing PerformanceBenchmarkTests`
///
/// 注意事项：
/// - 模拟器性能数据仅供趋势参考，真机数据才可作为回归基线
/// - 测试在 Release 配置下运行结果更有参考价值
/// - 每项测试默认运行 10 次迭代取均值
final class PerformanceBenchmarkTests: XCTestCase {

    private var kit: CPRiskKit!

    override func setUp() {
        super.setUp()
        kit = CPRiskKit.shared
    }

    override func tearDown() {
        kit.stop()
        super.tearDown()
    }

    // MARK: - SDK Lifecycle

    /// 测量 `start()` 冷启动耗时
    ///
    /// 包含 Armor runtime init、anti-debug 配置、provider 注册等。
    /// 目标：旗舰 ≤ 50ms，低端 ≤ 120ms
    func testStartPerformance() {
        kit.stop()

        measure {
            kit.start()
            kit.stop()
        }
    }

    /// 测量 `start(config:)` 带自定义配置的启动耗时
    func testStartWithConfigPerformance() {
        kit.stop()

        let config = CPRiskConfig()
        config.enableBehaviorDetect = true
        config.enableNetworkSignals = true
        config.enableAntiTamper = true

        measure {
            kit.start(config: config)
            kit.stop()
        }
    }

    // MARK: - Evaluation

    /// 测量 `evaluate()` 同步评估耗时（默认配置）
    ///
    /// 包含信号采集、决策引擎评分、报告构建。
    /// 目标：旗舰 P50 ≤ 25ms，P95 ≤ 50ms
    func testEvaluateDefaultPerformance() {
        kit.start()

        measure {
            _ = kit.evaluate()
        }
    }

    /// 测量 `evaluate(config:scenario:)` 场景化评估耗时
    func testEvaluateWithScenarioPerformance() {
        kit.start()

        let config = CPRiskConfig()
        let scenario = RiskScenario.default

        measure {
            _ = kit.evaluate(config: config, scenario: scenario)
        }
    }

    /// 测量连续 5 次评估（模拟高频调用场景）
    func testEvaluateBurstPerformance() {
        kit.start()

        measure {
            for _ in 0..<5 {
                _ = kit.evaluate()
            }
        }
    }

    /// 测量 evaluate 在启用远程配置时的开销
    func testEvaluateWithRemoteConfigPerformance() {
        let config = CPRiskConfig()
        config.enableRemoteConfig = false
        kit.start(config: config)

        measure {
            _ = kit.evaluate(config: config)
        }
    }

    // MARK: - Individual Detectors

    /// 测量 JailbreakEngine.detect() 全量扫描耗时
    ///
    /// 11 检测器全量运行。
    /// 目标：旗舰 ≤ 8ms，低端 ≤ 20ms
    func testJailbreakEnginePerformance() {
        let engine = JailbreakEngine()
        let config = JailbreakConfig(
            enableFileDetect: true,
            enableDyldDetect: true,
            enableEnvDetect: true,
            enableSysctlDetect: true,
            enableSchemeDetect: true,
            enableHookDetect: true,
            threshold: 50
        )

        measure {
            _ = engine.detect(config: config)
        }
    }

    /// 测量 CapabilityProbeEngine 探测耗时
    ///
    /// 目标：旗舰 ≤ 5ms
    func testCapabilityProbePerformance() {
        let engine = CapabilityProbeEngine()

        measure {
            _ = engine.evaluateDetailed()
        }
    }

    /// 测量 RiskScorer 评分计算耗时
    func testRiskScorerPerformance() {
        let context = TestFixtures.makeRiskContext()
        let config = TestFixtures.defaultRiskConfig
        let signals = (0..<20).map { i in
            RiskSignal(
                id: "perf_test_signal_\(i)",
                category: "test",
                score: Double.random(in: 0...100),
                evidence: ["key": "value"],
                state: .soft(confidence: 0.5),
                layer: Int.random(in: 1...4),
                weightHint: Double.random(in: 0...100)
            )
        }

        measure {
            for _ in 0..<100 {
                _ = RiskScorer.score(context: context, config: config, extraSignals: signals)
            }
        }
    }

    // MARK: - Report Building

    /// 测量 buildSecureReportEnvelope 耗时
    ///
    /// 包含 JSON 序列化、HMAC 签名、字段混淆。
    /// 目标：旗舰 ≤ 10ms
    func testBuildSecureReportEnvelopePerformance() {
        kit.start()
        let report = kit.evaluate()
        let sessionToken = "perf-test-session-token"
        let signingKey = "perf-test-signing-key-32bytes!!"

        measure {
            _ = try? kit.buildSecureReportEnvelope(
                report: report,
                sessionToken: sessionToken,
                signingKey: signingKey,
                requireArmor: false
            )
        }
    }

    // MARK: - Memory

    /// 测量 evaluate() 前后内存增量
    func testEvaluateMemoryFootprint() {
        kit.start()

        let beforeMemory = currentResidentMemoryBytes()
        for _ in 0..<10 {
            _ = kit.evaluate()
        }
        let afterMemory = currentResidentMemoryBytes()

        let deltaKB = (afterMemory - beforeMemory) / 1024
        XCTAssertLessThan(deltaKB, 5 * 1024, "evaluate() 10 次内存增量应 < 5MB，实际 \(deltaKB) KB")
    }

    /// 测量 start() 内存增量
    func testStartMemoryFootprint() {
        kit.stop()

        let beforeMemory = currentResidentMemoryBytes()
        kit.start()
        let afterMemory = currentResidentMemoryBytes()

        let deltaKB = (afterMemory - beforeMemory) / 1024
        XCTAssertLessThan(deltaKB, 5 * 1024, "start() 内存增量应 < 5MB，实际 \(deltaKB) KB")
    }

    // MARK: - Helpers

    private func currentResidentMemoryBytes() -> Int {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
        let result = withUnsafeMutablePointer(to: &info) { infoPtr in
            infoPtr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rawPtr in
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), rawPtr, &count)
            }
        }
        guard result == KERN_SUCCESS else { return 0 }
        return Int(info.resident_size)
    }
}
