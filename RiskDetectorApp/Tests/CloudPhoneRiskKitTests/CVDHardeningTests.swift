import XCTest
@testable import CloudPhoneRiskKit

/// CVD (Cuttlefish Virtual Device) 加固检测单元测试
///
/// 覆盖四个新增检测能力：
///   1. LayeredConsistencyProvider — 触摸-运动解耦检测
///   2. NetworkInterfaceProvider — hypervisor 接口名匹配
///   3. EnvironmentConsistencyProvider — 三维环境冻结联合检测
///   4. ScenarioPolicy — CR-007 CVD 组合规则
final class CVDHardeningTests: XCTestCase {

    // MARK: - Fixtures

    /// 模拟 CVD 云手机行为特征：大量触摸、运动静默、弱耦合
    private func makeCVDSnapshot(
        actionCount: Int = 30,
        motionEnergy: Double = 0,
        touchMotionCorrelation: Double = 0.05
    ) -> RiskSnapshot {
        let tapCount = actionCount * 2 / 3
        let swipeCount = actionCount - tapCount
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: actionCount * 2,
            tapCount: tapCount,
            swipeCount: swipeCount
        )
        let behavior = BehaviorSignals(
            touch: touch,
            motion: MotionMetrics(
                sampleCount: 100,
                stillnessRatio: 0.999,
                motionEnergy: motionEnergy
            ),
            touchMotionCorrelation: touchMotionCorrelation
        )
        return RiskSnapshot(
            deviceID: "test-cvd",
            device: TestFixtures.makeDeviceFingerprint(),
            network: TestFixtures.makeNetworkSignals(),
            behavior: behavior,
            jailbreak: TestFixtures.makeDetectionResult()
        )
    }

    /// 正常用户行为快照
    private func makeNormalSnapshot() -> RiskSnapshot {
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 40,
            tapCount: 20,
            swipeCount: 10
        )
        let behavior = BehaviorSignals(
            touch: touch,
            motion: MotionMetrics(
                sampleCount: 100,
                stillnessRatio: 0.3,
                motionEnergy: 0.5
            ),
            touchMotionCorrelation: 0.6
        )
        return RiskSnapshot(
            deviceID: "test-normal",
            device: TestFixtures.makeDeviceFingerprint(),
            network: TestFixtures.makeNetworkSignals(),
            behavior: behavior,
            jailbreak: TestFixtures.makeDetectionResult()
        )
    }

    // MARK: - 1. 触摸-运动解耦检测 (LayeredConsistencyProvider)

    func testTouchMotionDecouplingDetectedForCVD() {
        let provider = LayeredConsistencyProvider.shared
        let snapshot = makeCVDSnapshot(
            actionCount: 30,
            motionEnergy: 0,
            touchMotionCorrelation: 0.05
        )
        let signals = provider.signals(snapshot: snapshot)
        let decoupling = signals.first { $0.id == SignalID.touchMotionDecoupling }

        XCTAssertNotNil(decoupling, "CVD 特征快照应触发 touch_motion_decoupling 信号")
        XCTAssertEqual(decoupling?.category, SignalCategory.cloudphone)
        XCTAssertEqual(decoupling?.weightHint, 65)

        // 30 次操作 → confidence ≈ 0.6 + (15/35)*0.25 ≈ 0.71
        if case .soft(let conf) = decoupling?.state {
            XCTAssertGreaterThan(conf, 0.6)
            XCTAssertLessThanOrEqual(conf, 0.85)
        } else {
            XCTFail("应为 .soft 状态")
        }
    }

    func testTouchMotionDecouplingNotTriggeredForNormalUser() {
        let provider = LayeredConsistencyProvider.shared
        let snapshot = makeNormalSnapshot()
        let signals = provider.signals(snapshot: snapshot)
        let decoupling = signals.first { $0.id == SignalID.touchMotionDecoupling }

        XCTAssertNil(decoupling,
            "正常用户（有运动能量+强触摸-运动相关性）不应触发解耦信号")
    }

    func testTouchMotionDecouplingRequiresMinActions() {
        let provider = LayeredConsistencyProvider.shared
        // 仅 10 次操作 (tap=7, swipe=3) → 不满足 ≥15 阈值
        let snapshot = makeCVDSnapshot(actionCount: 10)
        let signals = provider.signals(snapshot: snapshot)
        let decoupling = signals.first { $0.id == SignalID.touchMotionDecoupling }

        XCTAssertNil(decoupling, "操作次数不足时不应触发")
    }

    func testTouchMotionDecouplingConfidenceScalesWithActions() {
        let provider = LayeredConsistencyProvider.shared

        let snapshot20 = makeCVDSnapshot(actionCount: 20)
        let snapshot50 = makeCVDSnapshot(actionCount: 50)

        let sig20 = provider.signals(snapshot: snapshot20).first { $0.id == SignalID.touchMotionDecoupling }
        let sig50 = provider.signals(snapshot: snapshot50).first { $0.id == SignalID.touchMotionDecoupling }

        XCTAssertNotNil(sig20)
        XCTAssertNotNil(sig50)

        if case .soft(let conf20) = sig20?.state,
           case .soft(let conf50) = sig50?.state {
            XCTAssertGreaterThan(conf50, conf20,
                "更多操作次数应产生更高的置信度")
        }
    }

    // MARK: - 2. Hypervisor 接口检测 (NetworkInterfaceProvider)

    func testNetworkInterfaceProviderID() {
        XCTAssertEqual(NetworkInterfaceProvider.shared.id, "network_interface")
    }

    func testNetworkInterfaceProviderSignalStructure() {
        let signals = NetworkInterfaceProvider.shared.signals(
            snapshot: makeNormalSnapshot()
        )
        let knownIDs: Set<String> = [
            SignalID.networkInterfaceAnomaly,
        ]
        for signal in signals {
            XCTAssertTrue(
                knownIDs.contains(signal.id),
                "未预期的 NetworkInterfaceProvider 信号 ID: \(signal.id)"
            )
        }
    }

    // MARK: - 3. 环境冻结联合检测 (EnvironmentConsistencyProvider)

    func testEnvironmentConsistencyProviderID() {
        XCTAssertEqual(EnvironmentConsistencyProvider.shared.id, "environment_consistency")
    }

    func testEnvironmentConsistencyProviderSignalStructure() {
        let signals = EnvironmentConsistencyProvider.shared.signals(
            snapshot: makeNormalSnapshot()
        )
        let knownIDs: Set<String> = [
            "thermal_state_static",
            "battery_state_static",
            SignalID.batteryLevelStatic,
            SignalID.noChargeStateChange,
            "screen_brightness_static",
            SignalID.environmentFreezeLock,
        ]
        for signal in signals {
            XCTAssertTrue(
                knownIDs.contains(signal.id),
                "未预期的 EnvironmentConsistencyProvider 信号 ID: \(signal.id)"
            )
        }
    }

    // MARK: - 4. CR-007 组合规则 (ScenarioPolicy)

    func testCR007FullRuleMatches() {
        let signals = [
            RiskSignal(id: SignalID.networkInterfaceAnomaly, category: "network", score: 10, evidence: [:], state: .hard(detected: true), layer: 1, weightHint: 55),
            RiskSignal(id: SignalID.environmentFreezeLock, category: "cloudphone", score: 10, evidence: [:], state: .soft(confidence: 0.85), layer: 2, weightHint: 75),
            RiskSignal(id: SignalID.touchMotionDecoupling, category: "cloudphone", score: 10, evidence: [:], state: .soft(confidence: 0.7), layer: 2, weightHint: 65),
        ]

        let policy = ScenarioPolicy.sensitiveAction
        let matchedRules = policy.comboRules.filter { $0.matches(signals: signals) }
        let cr007 = matchedRules.first { $0.name == "CR-007_cvd_multilayer_detection" }

        XCTAssertNotNil(cr007, "三信号全命中应匹配 CR-007")
        XCTAssertEqual(cr007?.bonusScore, 40.0)
        XCTAssertEqual(cr007?.forceAction, .block)
    }

    func testCR007bLightComboMatches() {
        let signals = [
            RiskSignal(id: SignalID.environmentFreezeLock, category: "cloudphone", score: 10, evidence: [:], state: .soft(confidence: 0.85), layer: 2, weightHint: 75),
            RiskSignal(id: SignalID.touchMotionDecoupling, category: "cloudphone", score: 10, evidence: [:], state: .soft(confidence: 0.7), layer: 2, weightHint: 65),
        ]

        // CR-007b 应在 coreComboRules 中（所有策略共享）
        let policy = ScenarioPolicy.general
        let matchedRules = policy.comboRules.filter { $0.matches(signals: signals) }
        let cr007b = matchedRules.first { $0.name == "CR-007b_cvd_light_combo" }

        XCTAssertNotNil(cr007b, "双信号命中应匹配 CR-007b")
        XCTAssertEqual(cr007b?.bonusScore, 25.0)
        XCTAssertEqual(cr007b?.forceAction, .challenge)
    }

    func testCR007DoesNotMatchPartialSignals() {
        let signals = [
            RiskSignal(id: SignalID.networkInterfaceAnomaly, category: "network", score: 10, evidence: [:], state: .hard(detected: true), layer: 1, weightHint: 55),
        ]

        let policy = ScenarioPolicy.sensitiveAction
        let matchedRules = policy.comboRules.filter { $0.matches(signals: signals) }
        let cr007 = matchedRules.first { $0.name.hasPrefix("CR-007") }

        XCTAssertNil(cr007, "单信号不应触发 CR-007 系列规则")
    }

    func testCR007bInAllScenarios() {
        // CR-007b 在 coreComboRules 中，所有场景策略都应包含
        let scenarios: [ScenarioPolicy] = [
            .general, .login, .register, .payment,
            .accountChange, .sensitiveAction, .apiAccess,
        ]
        for policy in scenarios {
            let hasCR007b = policy.comboRules.contains { $0.name == "CR-007b_cvd_light_combo" }
            XCTAssertTrue(hasCR007b,
                "所有场景策略都应包含 CR-007b 轻量 CVD 组合规则")
        }
    }

    // MARK: - Signal ID 注册

    func testNewSignalIDsExist() {
        XCTAssertEqual(SignalID.touchMotionDecoupling, "touch_motion_decoupling")
        XCTAssertEqual(SignalID.environmentFreezeLock, "environment_freeze_lock")
    }
}
