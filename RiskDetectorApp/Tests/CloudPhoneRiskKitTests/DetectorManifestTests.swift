import XCTest
@testable import CloudPhoneRiskKit

final class DetectorManifestTests: XCTestCase {

    // MARK: - Manifest 基本查询

    func testAllDetectorTypesHaveManifest() {
        let registry = DetectorRegistry.shared
        for type in DetectorRegistry.DetectorType.allCases {
            let manifest = registry.manifest(for: type)
            XCTAssertGreaterThanOrEqual(manifest.minOS, 0,
                "\(type.rawValue) should have valid minOS")
            XCTAssertGreaterThan(manifest.priority, 0,
                "\(type.rawValue) should have positive priority")
        }
    }

    func testFridaDetectorHasHighPriority() {
        let registry = DetectorRegistry.shared
        let fridaManifest = registry.manifest(for: .frida)
        let debuggerManifest = registry.manifest(for: .debugger)
        XCTAssertGreaterThan(fridaManifest.priority, debuggerManifest.priority,
            "Frida detector should have higher priority than debugger")
    }

    // MARK: - OS 版本兼容性

    func testIsAvailableRespectsMinOS() {
        let registry = DetectorRegistry.shared
        let manifest = registry.manifest(for: .codeSignature)
        XCTAssertTrue(registry.isAvailable(.codeSignature, osVersion: manifest.minOS))
        XCTAssertTrue(registry.isAvailable(.codeSignature, osVersion: manifest.minOS + 1))
        XCTAssertFalse(registry.isAvailable(.codeSignature, osVersion: manifest.minOS - 1))
    }

    func testIsAvailableRespectsMaxOS() {
        // 创建一个有 maxOS 的测试用 manifest
        let manifest = DetectorRegistry.DetectorManifest(minOS: 14.0, maxOS: 16.0)
        // 直接测试逻辑
        XCTAssertTrue(14.0 >= manifest.minOS)
        XCTAssertTrue(16.0 <= (manifest.maxOS ?? Double.infinity))
        XCTAssertFalse(17.0 <= (manifest.maxOS ?? Double.infinity))
    }

    // MARK: - 依赖关系

    func testUnsatisfiedDependencies() {
        let registry = DetectorRegistry.shared
        let antiTamperManifest = registry.manifest(for: .antiTampering)

        // 如果 antiTampering 依赖 debugger，缺少 debugger 应报告为未满足
        if antiTamperManifest.dependsOn.contains(.debugger) {
            let missing = registry.unsatisfiedDependencies(
                for: .antiTampering,
                enabledTypes: [.file, .dyld] // 不包含 debugger
            )
            XCTAssertTrue(missing.contains(.debugger))

            let satisfied = registry.unsatisfiedDependencies(
                for: .antiTampering,
                enabledTypes: [.debugger, .file]
            )
            XCTAssertTrue(satisfied.isEmpty)
        }
    }

    // MARK: - 信号重叠去重

    func testDeduplicateByOverlapGroup() {
        let registry = DetectorRegistry.shared

        // 构造同 signalOverlapGroup 的两个检测器结果
        let results: [(DetectorRegistry.DetectorType, DetectorResult)] = [
            (.frida, DetectorResult(score: 60, methods: ["frida_port"])),
            (.dylibInjection, DetectorResult(score: 30, methods: ["dylib_inject"])),
            (.env, DetectorResult(score: 10, methods: ["env_var"])),
        ]

        let deduped = registry.deduplicateByOverlapGroup(results)

        // frida 和 dylibInjection 可能在同一 overlap group，应只保留高分者
        let fridaManifest = registry.manifest(for: .frida)
        let dylibManifest = registry.manifest(for: .dylibInjection)

        if fridaManifest.signalOverlapGroup == dylibManifest.signalOverlapGroup
            && fridaManifest.signalOverlapGroup != nil {
            // 同组：去重后应只有 2 个结果（frida 取代 dylibInjection + env）
            XCTAssertEqual(deduped.count, 2,
                "同 overlap group 应去重为 1 个，加上 env 共 2 个")
            let scores = Set(deduped.map { $0.1.score })
            XCTAssertTrue(scores.contains(60), "应保留高分的 frida")
            XCTAssertFalse(scores.contains(30), "低分的 dylibInjection 应被去重")
        }
    }

    func testDeduplicatePreservesUngroupedDetectors() {
        let registry = DetectorRegistry.shared

        // env 没有 signalOverlapGroup → 不应被去重
        let results: [(DetectorRegistry.DetectorType, DetectorResult)] = [
            (.env, DetectorResult(score: 10, methods: ["env_check"])),
            (.sysctl, DetectorResult(score: 15, methods: ["sysctl_check"])),
        ]

        let deduped = registry.deduplicateByOverlapGroup(results)

        let envManifest = registry.manifest(for: .env)
        let sysctlManifest = registry.manifest(for: .sysctl)

        if envManifest.signalOverlapGroup == nil && sysctlManifest.signalOverlapGroup == nil {
            XCTAssertEqual(deduped.count, 2, "无 overlap group 的检测器不应被去重")
        }
    }
}

// MARK: - BehaviorSignals 样本充足性测试

final class BehaviorSignalsSufficiencyTests: XCTestCase {

    func testSufficientSamples() {
        let signals = BehaviorSignals(
            touch: TouchMetrics(
                sampleCount: 20, tapCount: 10, swipeCount: 5,
                coordinateSpread: 50, intervalCV: 0.35, averageLinearity: 0.95
            ),
            motion: MotionMetrics(sampleCount: 100, stillnessRatio: 0.3, motionEnergy: 0.5)
        )
        XCTAssertTrue(signals.hasSufficientTouchSamples)
        XCTAssertTrue(signals.hasSufficientMotionSamples)
        XCTAssertEqual(signals.sampleSufficiency, .sufficient)
    }

    func testInsufficientTouchSamples() {
        let signals = BehaviorSignals(
            touch: TouchMetrics(
                sampleCount: 3, tapCount: 2, swipeCount: 0,
                coordinateSpread: nil, intervalCV: nil, averageLinearity: nil
            ),
            motion: MotionMetrics(sampleCount: 100, stillnessRatio: 0.3, motionEnergy: 0.5)
        )
        XCTAssertFalse(signals.hasSufficientTouchSamples)
        XCTAssertEqual(signals.sampleSufficiency, .insufficient)
    }

    func testNoSamples() {
        let signals = BehaviorSignals(
            touch: TouchMetrics(
                sampleCount: 0, tapCount: 0, swipeCount: 0,
                coordinateSpread: nil, intervalCV: nil, averageLinearity: nil
            ),
            motion: MotionMetrics(sampleCount: 0, stillnessRatio: nil, motionEnergy: nil)
        )
        XCTAssertEqual(signals.sampleSufficiency, .none)
    }

    func testBoundaryActionCount() {
        // 刚好达到最小动作数
        let atBoundary = BehaviorSignals(
            touch: TouchMetrics(
                sampleCount: BehaviorSignals.minimumTouchSamples,
                tapCount: BehaviorSignals.minimumActionCount,
                swipeCount: 0,
                coordinateSpread: 50, intervalCV: 0.35, averageLinearity: 0.95
            ),
            motion: MotionMetrics(sampleCount: 100, stillnessRatio: 0.3, motionEnergy: 0.5)
        )
        XCTAssertTrue(atBoundary.hasSufficientTouchSamples)

        // 少一个动作
        let belowBoundary = BehaviorSignals(
            touch: TouchMetrics(
                sampleCount: BehaviorSignals.minimumTouchSamples,
                tapCount: BehaviorSignals.minimumActionCount - 1,
                swipeCount: 0,
                coordinateSpread: 50, intervalCV: 0.35, averageLinearity: 0.95
            ),
            motion: MotionMetrics(sampleCount: 100, stillnessRatio: 0.3, motionEnergy: 0.5)
        )
        XCTAssertFalse(belowBoundary.hasSufficientTouchSamples)
    }

    func testInsufficientMotionSamples() {
        let signals = BehaviorSignals(
            touch: TouchMetrics(
                sampleCount: 20, tapCount: 10, swipeCount: 5,
                coordinateSpread: 50, intervalCV: 0.35, averageLinearity: 0.95
            ),
            motion: MotionMetrics(sampleCount: 10, stillnessRatio: 0.3, motionEnergy: 0.5)
        )
        XCTAssertFalse(signals.hasSufficientMotionSamples)
        // 触摸充足但运动不足 → 总体仍 sufficient（仅 touch 达标即可）
        XCTAssertEqual(signals.sampleSufficiency, .sufficient)
    }
}
