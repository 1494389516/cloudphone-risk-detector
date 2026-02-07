import XCTest
@testable import CloudPhoneRiskKit

/// 决策引擎单元测试
/// 
/// 测试策略：
/// 1. 测试不同场景的评分逻辑
/// 2. 测试组合规则
/// 3. 测试边界条件
/// 4. 测试配置影响
final class DecisionEngineTests: XCTestCase {
    
    // MARK: - 基础评分测试
    
    func testCleanDeviceScore() {
        // 测试干净设备的评分
        let device = makeTestDevice()
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: false,
            proxyEnabled: false
        )
        
        let report = RiskScorer.score(context: context, config: .default)
        
        XCTAssertLessThan(report.score, 30, "干净设备得分应 < 30（低风险）")
        XCTAssertFalse(report.isHighRisk, "干净设备不应被判定为高风险")
        XCTAssertEqual(report.summary, "low_risk")
    }
    
    func testJailbreakDeviceScore() {
        // 测试越狱设备的评分
        let context = makeTestContext(
            jailbroken: true,
            jailbreakConfidence: 80,
            vpnActive: false,
            proxyEnabled: false
        )
        
        let report = RiskScorer.score(context: context, config: .default)
        
        XCTAssertEqual(report.score, 60, "越狱设备得分应至少等于阈值")
        XCTAssertTrue(report.isHighRisk, "越狱设备应被判定为高风险")
        XCTAssertTrue(report.summary.contains("jailbreak"), "摘要应包含 jailbreak")
    }
    
    func testVPNOnlyDeviceScore() {
        // 测试仅使用 VPN 的设备
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: true,
            proxyEnabled: false
        )
        
        let report = RiskScorer.score(context: context, config: .default)
        
        XCTAssertEqual(report.score, 10, "仅 VPN 应加 10 分")
        XCTAssertFalse(report.isHighRisk, "仅 VPN 不应触发高风险")
    }
    
    func testProxyOnlyDeviceScore() {
        // 测试仅使用代理的设备
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: false,
            proxyEnabled: true
        )
        
        let report = RiskScorer.score(context: context, config: .default)
        
        XCTAssertEqual(report.score, 8, "仅代理应加 8 分")
        XCTAssertFalse(report.isHighRisk, "仅代理不应触发高风险")
    }
    
    func testVPNAndProxyCombined() {
        // 测试 VPN + 代理组合
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: true,
            proxyEnabled: true
        )
        
        let report = RiskScorer.score(context: context, config: .default)
        
        XCTAssertEqual(report.score, 18, "VPN + 代理应加 18 分")
        XCTAssertFalse(report.isHighRisk, "VPN + 代理不应触发高风险")
    }
    
    // MARK: - 越狱权重测试
    
    func testJailbreakWeight() {
        // 测试越狱权重为 0.6
        let confidence = 80
        let expectedContribution = max(Double(confidence) * 0.6, 60)  // 越狱分数下限为阈值

        let context = makeTestContext(
            jailbroken: true,
            jailbreakConfidence: Double(confidence),
            vpnActive: false,
            proxyEnabled: false
        )

        let report = RiskScorer.score(context: context, config: .default)
        XCTAssertEqual(report.score, expectedContribution, accuracy: 0.1)
    }
    
    func testLowJailbreakConfidence() {
        // 测试低越狱置信度
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 30,
            vpnActive: false,
            proxyEnabled: false
        )
        
        let report = RiskScorer.score(context: context, config: .default)
        let expectedScore = 30 * 0.6  // 18
        
        XCTAssertEqual(report.score, expectedScore, accuracy: 0.1)
        XCTAssertFalse(report.isHighRisk, "低置信度越狱信号不应触发高风险")
    }
    
    // MARK: - 阈值测试
    
    func testDefaultThreshold() {
        // 测试默认阈值 60
        XCTAssertEqual(RiskConfig.default.threshold, 60)
    }
    
    func testLightConfigThreshold() {
        // 测试轻量配置阈值 70
        XCTAssertEqual(RiskConfig.light.threshold, 70)
    }
    
    func testFullConfigThreshold() {
        // 测试完整配置阈值 55
        XCTAssertEqual(RiskConfig.full.threshold, 55)
    }
    
    func testCustomThreshold() {
        // 测试自定义阈值
        let customConfig = RiskConfig(threshold: 50)
        
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: true,
            proxyEnabled: true
        )
        
        let report = RiskScorer.score(context: context, config: customConfig)
        XCTAssertFalse(report.isHighRisk, "18 分低于 50 阈值")
    }
    
    // MARK: - 分数封顶测试
    
    func testScoreCappingAt100() {
        // 测试总分封顶在 100
        let context = makeTestContext(
            jailbroken: true,
            jailbreakConfidence: 100,
            vpnActive: true,
            proxyEnabled: true
        )
        
        // 添加额外的信号
        let extraSignals = [
            RiskSignal(id: "extra1", category: "test", score: 50, evidence: [:]),
            RiskSignal(id: "extra2", category: "test", score: 50, evidence: [:])
        ]
        
        let report = RiskScorer.score(context: context, config: .default, extraSignals: extraSignals)
        
        XCTAssertLessThanOrEqual(report.score, 100, "总分不应超过 100")
    }
    
    func testExtraSignalsCappedAt20() {
        // 测试额外信号封顶在 20
        let extraSignals = [
            RiskSignal(id: "e1", category: "test", score: 30, evidence: [:]),
            RiskSignal(id: "e2", category: "test", score: 30, evidence: [:])
        ]
        
        let context = makeTestContext(jailbroken: false, jailbreakConfidence: 0, vpnActive: false, proxyEnabled: false)
        let report = RiskScorer.score(context: context, config: .default, extraSignals: extraSignals)
        
        // 额外信号原始 60 分，应封顶到 20
        // 越狱 0 + 网络 0 + 行为 0 + 额外 20 = 20
        XCTAssertEqual(report.score, 20, "额外信号应封顶在 20")
    }
    
    // MARK: - 行为信号测试
    
    func testTouchSpreadLow() {
        // 测试触摸点分散度过低
        var behavior = makeTestBehavior()
        behavior.touch.coordinateSpread = 1.5
        behavior.touch.tapCount = 10
        
        let context = makeTestContextWithBehavior(behavior: behavior)
        let report = RiskScorer.score(context: context, config: .default)
        
        // 应增加 12 分
        XCTAssertEqual(report.score, 12, accuracy: 0.1)
    }
    
    func testTouchIntervalTooRegular() {
        // 测试触摸间隔过于规律
        var behavior = makeTestBehavior()
        behavior.touch.intervalCV = 0.15  // < 0.2
        behavior.touch.tapCount = 10
        
        let context = makeTestContextWithBehavior(behavior: behavior)
        let report = RiskScorer.score(context: context, config: .default)
        
        // 应增加 10 分
        XCTAssertEqual(report.score, 10, accuracy: 0.1)
    }
    
    func testMotionTooStill() {
        // 测试设备过于静止
        var behavior = makeTestBehavior()
        behavior.motion.stillnessRatio = 0.99
        behavior.touch.tapCount = 15
        
        let context = makeTestContextWithBehavior(behavior: behavior)
        let report = RiskScorer.score(context: context, config: .default)
        
        // 应增加 10 分
        XCTAssertEqual(report.score, 10, accuracy: 0.1)
    }
    
    func testBehaviorSignalsDisabled() {
        // 测试禁用行为信号
        let config = RiskConfig(enableBehaviorDetect: false)
        var behavior = makeTestBehavior()
        behavior.touch.coordinateSpread = 1.0
        behavior.touch.tapCount = 10
        
        let context = makeTestContextWithBehavior(behavior: behavior)
        let report = RiskScorer.score(context: context, config: config)
        
        XCTAssertEqual(report.score, 0, "禁用行为信号后不应有行为分数")
    }
    
    func testBehaviorScoreCap() {
        // 测试行为分数封顶在 30
        var behavior = makeTestBehavior()
        
        // 设置多个触发条件
        behavior.touch.coordinateSpread = 1.0      // +12
        behavior.touch.intervalCV = 0.1            // +10
        behavior.touch.swipeCount = 5
        behavior.touch.averageLinearity = 0.99     // +8
        behavior.motion.stillnessRatio = 0.99
        behavior.touch.tapCount = 15               // +10
        
        let context = makeTestContextWithBehavior(behavior: behavior)
        let report = RiskScorer.score(context: context, config: .default)
        
        XCTAssertLessThanOrEqual(report.score, 30, "行为分数应封顶在 30")
    }
    
    // MARK: - 组合场景测试
    
    func testJailbreakWithVPN() {
        // 越狱 + VPN
        let context = makeTestContext(
            jailbroken: true,
            jailbreakConfidence: 80,
            vpnActive: true,
            proxyEnabled: false
        )
        
        let report = RiskScorer.score(context: context, config: .default)
        // 80 * 0.6 + 10 = 58
        XCTAssertEqual(report.score, 60, "越狱应至少得阈值分数")
    }
    
    func testMultipleSoftSignals() {
        // 多个软信号组合
        var behavior = makeTestBehavior()
        behavior.touch.coordinateSpread = 1.0
        behavior.touch.tapCount = 10
        
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: true,
            proxyEnabled: true,
            behavior: behavior
        )
        
        let report = RiskScorer.score(context: context, config: .default)
        // 10 + 8 + 12 = 30
        XCTAssertEqual(report.score, 30, accuracy: 0.1)
    }
    
    func testHighRiskWithoutJailbreak() {
        // 无越狱但高风险场景
        var behavior = makeTestBehavior()
        behavior.touch.coordinateSpread = 1.0      // +12
        behavior.touch.intervalCV = 0.1            // +10
        behavior.touch.swipeCount = 5
        behavior.touch.averageLinearity = 0.99     // +8
        
        let extraSignals = [
            RiskSignal(id: "suspicious", category: "custom", score: 20, evidence: [:]),
            RiskSignal(id: "suspicious2", category: "custom", score: 20, evidence: [:])
        ]
        
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: true,
            proxyEnabled: true,
            behavior: behavior
        )
        
        let report = RiskScorer.score(context: context, config: .default, extraSignals: extraSignals)
        // 10 + 8 + 30(behavior capped) + 20(extra capped) = 68
        XCTAssertGreaterThanOrEqual(report.score, 60, "应触发高风险阈值")
    }
    
    // MARK: - 配置切换测试
    
    func testConfigSwitchAffectsScore() {
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 40,
            vpnActive: true,
            proxyEnabled: true
        )
        
        let defaultReport = RiskScorer.score(context: context, config: .default)
        let lightReport = RiskScorer.score(context: context, config: .light)
        let fullReport = RiskScorer.score(context: context, config: .full)
        
        // 分数相同但阈值不同
        XCTAssertEqual(defaultReport.score, lightReport.score)
        XCTAssertEqual(defaultReport.score, fullReport.score)
        
        // 阈值不同可能影响 isHighRisk
        // default: 60, light: 70, full: 55
    }
    
    func testNetworkSignalsDisabled() {
        let config = RiskConfig(enableNetworkSignals: false)
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: true,
            proxyEnabled: true
        )
        
        let report = RiskScorer.score(context: context, config: config)
        
        XCTAssertEqual(report.score, 0, "禁用网络信号后不应有网络分数")
    }
    
    // MARK: - 信号去重测试
    
    func testExtraSignalsDeduplication() {
        // 测试额外信号去重（按 category::id）
        let extraSignals = [
            RiskSignal(id: "dup", category: "test", score: 10, evidence: [:]),
            RiskSignal(id: "dup", category: "test", score: 20, evidence: [:]),  // 重复，应被忽略
            RiskSignal(id: "other", category: "test", score: 15, evidence: [:])
        ]
        
        let context = makeTestContext(jailbroken: false, jailbreakConfidence: 0, vpnActive: false, proxyEnabled: false)
        let report = RiskScorer.score(context: context, config: .default, extraSignals: extraSignals)
        
        // 10 + 15 = 25，但封顶在 20
        XCTAssertEqual(report.score, 20, "应去重并封顶")
    }
    
    func testSignalsAcrossCategories() {
        // 不同 category 的相同 id 不应去重
        let extraSignals = [
            RiskSignal(id: "same", category: "cat1", score: 10, evidence: [:]),
            RiskSignal(id: "same", category: "cat2", score: 15, evidence: [:])
        ]
        
        let context = makeTestContext(jailbroken: false, jailbreakConfidence: 0, vpnActive: false, proxyEnabled: false)
        let report = RiskScorer.score(context: context, config: .default, extraSignals: extraSignals)
        
        // 10 + 15 = 25，但封顶在 20
        XCTAssertEqual(report.score, 20, "不同 category 应分别计数但封顶")
    }
    
    // MARK: - 边界条件测试
    
    func testZeroScore() {
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: false,
            proxyEnabled: false
        )
        
        let report = RiskScorer.score(context: context, config: .default)
        XCTAssertEqual(report.score, 0, "无任何信号应为 0 分")
    }
    
    func testNegativeScoreNotPossible() {
        // 负分数信号不应被处理（由 RiskSignal 定义保证）
        let context = makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: false,
            proxyEnabled: false
        )
        
        let report = RiskScorer.score(context: context, config: .default)
        XCTAssertGreaterThanOrEqual(report.score, 0, "分数不应为负")
    }
    
    func testMaximumJailbreakConfidence() {
        let context = makeTestContext(
            jailbroken: true,
            jailbreakConfidence: 150,  // 超过 100
            vpnActive: false,
            proxyEnabled: false
        )
        
        let report = RiskScorer.score(context: context, config: .default)
        XCTAssertLessThanOrEqual(report.score, 100, "置信度应封顶在 100")
    }
    
    // MARK: - 辅助方法
    
    private func makeTestDevice() -> DeviceFingerprint {
        DeviceFingerprint(
            systemName: "iOS",
            systemVersion: "17.0",
            model: "iPhone",
            localizedModel: "iPhone",
            identifierForVendor: nil,
            localeIdentifier: "en_US",
            timeZoneIdentifier: "UTC",
            timeZoneOffsetSeconds: 0,
            screenWidth: 1170,
            screenHeight: 2532,
            screenScale: 3
        )
    }
    
    private func makeTestBehavior() -> BehaviorSignals {
        BehaviorSignals(
            touch: TouchMetrics(
                sampleCount: 0,
                tapCount: 0,
                swipeCount: 0,
                coordinateSpread: nil,
                intervalCV: nil,
                averageLinearity: nil,
                forceVariance: nil,
                majorRadiusVariance: nil
            ),
            motion: .empty
        )
    }
    
    private func makeTestContext(
        jailbroken: Bool,
        jailbreakConfidence: Double,
        vpnActive: Bool,
        proxyEnabled: Bool,
        behavior: BehaviorSignals? = nil
    ) -> RiskContext {
        RiskContext(
            device: makeTestDevice(),
            deviceID: "test_device",
            network: NetworkSignals(
                interfaceType: InterfaceTypeSignal(value: "wifi", method: "test"),
                isExpensive: false,
                isConstrained: false,
                vpn: DetectionSignal(detected: vpnActive, method: "test", evidence: nil, confidence: .weak),
                proxy: DetectionSignal(detected: proxyEnabled, method: "test", evidence: nil, confidence: .weak)
            ),
            behavior: behavior ?? makeTestBehavior(),
            jailbreak: DetectionResult(
                isJailbroken: jailbroken,
                confidence: jailbreakConfidence,
                detectedMethods: [],
                details: ""
            )
        )
    }
    
    private func makeTestContextWithBehavior(behavior: BehaviorSignals) -> RiskContext {
        makeTestContext(
            jailbroken: false,
            jailbreakConfidence: 0,
            vpnActive: false,
            proxyEnabled: false,
            behavior: behavior
        )
    }
}
