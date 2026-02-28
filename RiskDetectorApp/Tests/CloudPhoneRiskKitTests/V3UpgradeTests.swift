import XCTest
@testable import CloudPhoneRiskKit

final class V3UpgradeTests: XCTestCase {
    func test_riskSignalStateCodableRoundTrip() throws {
        let signal = RiskSignal(
            id: "tampering_detected",
            category: "anti_tamper",
            score: 0,
            evidence: ["hooked": "sysctlbyname"],
            state: .tampered,
            layer: 2,
            weightHint: 85
        )

        let data = try JSONEncoder().encode(signal)
        let decoded = try JSONDecoder().decode(RiskSignal.self, from: data)

        XCTAssertEqual(decoded.state, .tampered)
        XCTAssertEqual(decoded.layer, 2)
        XCTAssertEqual(decoded.weightHint, 85)
    }

    func test_vphoneHardwareProviderDetectsVirtualGPUAndInconsistency() {
        let provider = VPhoneHardwareProvider(
            probe: MockProbe(
                gpu: "Apple Paravirtual device",
                machine: "iPhone16,1",
                ioKitModelValue: "iPhone99,11",
                kernel: "Darwin Kernel Version RELEASE_ARM64_VRESEARCH1"
            )
        )

        let snapshot = RiskSnapshot(
            deviceID: "d",
            device: makeDevice(machine: "iPhone16,1"),
            network: makeCleanNetwork(),
            behavior: makeCleanBehavior(),
            jailbreak: DetectionResult(isJailbroken: false, confidence: 0, detectedMethods: [], details: "")
        )

        let signals = provider.signals(snapshot: snapshot)
        let ids = Set(signals.map(\.id))

        XCTAssertTrue(ids.contains("gpu_virtual"))
        XCTAssertTrue(ids.contains("vphone_hardware"))
        XCTAssertTrue(ids.contains("hardware_inconsistency"))
        XCTAssertEqual(signals.first(where: { $0.id == "gpu_virtual" })?.state, .hard(detected: true))
    }

    func test_vphoneHardwareProviderDetectsSuspiciousBoardID() {
        let provider = VPhoneHardwareProvider(
            probe: MockProbe(
                gpu: "Apple A18 GPU",
                machine: "iPhone16,1",
                ioKitModelValue: "iPhone16,1",
                kernel: "Darwin Kernel Version 24.0.0"
            )
        )

        let snapshot = RiskSnapshot(
            deviceID: "board",
            device: makeDevice(machine: "iPhone16,1", hardwareModel: "VRESEARCH101AP"),
            network: makeCleanNetwork(),
            behavior: makeCleanBehavior(),
            jailbreak: DetectionResult(isJailbroken: false, confidence: 0, detectedMethods: [], details: "")
        )

        let signals = provider.signals(snapshot: snapshot)
        XCTAssertEqual(signals.first(where: { $0.id == "board_id_virtual" })?.state, .hard(detected: true))
    }

    func test_riskDetectionEngineAppliesTamperedMultiplier() {
        let engine = RiskDetectionEngine(policy: .default, enableLogging: false)
        let context = makeContext(deviceID: "d")

        let verdict = engine.evaluate(
            context: context,
            scenario: .default,
            extraSignals: [
                RiskSignal(
                    id: "timing_anomaly",
                    category: "anti_tamper",
                    score: 0,
                    evidence: [:],
                    state: .soft(confidence: 0.8),
                    layer: 2,
                    weightHint: 45
                ),
                RiskSignal(
                    id: "tampering_detected",
                    category: "anti_tamper",
                    score: 0,
                    evidence: [:],
                    state: .tampered,
                    layer: 2,
                    weightHint: 85
                ),
            ]
        )

        XCTAssertGreaterThanOrEqual(verdict.score, 90, "tampered 乘子应显著抬高分数")
        XCTAssertTrue(verdict.isHighRisk)
    }

    func test_crossLayerInconsistencyBoostsTamperedRisk() {
        let engine = RiskDetectionEngine(policy: .default, enableLogging: false)
        let context = makeContext(deviceID: "cross")

        let verdict = engine.evaluate(
            context: context,
            scenario: .default,
            extraSignals: [
                RiskSignal(
                    id: "gpu_virtual",
                    category: "device",
                    score: 0,
                    evidence: [:],
                    state: .hard(detected: false),
                    layer: 1,
                    weightHint: 95
                ),
                RiskSignal(
                    id: "vphone_hardware",
                    category: "device",
                    score: 0,
                    evidence: [:],
                    state: .hard(detected: false),
                    layer: 1,
                    weightHint: 100
                ),
                RiskSignal(
                    id: "tampering_detected",
                    category: "anti_tamper",
                    score: 0,
                    evidence: [:],
                    state: .tampered,
                    layer: 2,
                    weightHint: 85
                ),
            ]
        )

        XCTAssertTrue(verdict.signals.contains(where: { $0.id == "cross_layer_inconsistency" && $0.state == .tampered }))
        XCTAssertEqual(verdict.score, 100, "跨层不一致应直接拉高 tamper 风险")
    }

    func test_blindChallengeAddsServerSideBonusWithoutRuleLeak() {
        let policy = EnginePolicy(
            name: "blind",
            version: "3.0-test",
            blindChallengePolicy: BlindChallengePolicy(
                enabled: true,
                challengeSalt: "salt",
                rules: [
                    BlindChallengeRule(
                        id: "hidden_rule_01",
                        allOfSignalIDs: ["probe_anchor"],
                        weight: 25
                    ),
                ]
            )
        )
        let engine = RiskDetectionEngine(policy: policy, enableLogging: false)
        let context = makeContext(deviceID: "blind")

        let verdict = engine.evaluate(
            context: context,
            scenario: .default,
            extraSignals: [
                RiskSignal(
                    id: "probe_anchor",
                    category: "custom",
                    score: 0,
                    evidence: [:],
                    state: .soft(confidence: 1.0),
                    layer: 2,
                    weightHint: 10
                ),
            ]
        )

        XCTAssertEqual(verdict.score, 28, accuracy: 0.001)
        XCTAssertFalse(verdict.reason.contains("hidden_rule_01"))
    }

    func test_blocklistHitAddsSignalAndForcesBlockAction() {
        let policy = EnginePolicy(
            name: "blocklist",
            version: "3.0-test",
            serverBlocklist: ["203.0.113.10", "as9009", "vip-botnet"],
            blocklistAction: .block
        )
        let engine = RiskDetectionEngine(policy: policy, enableLogging: false)

        let verdict = engine.evaluate(
            context: makeContext(deviceID: "blk"),
            scenario: .default,
            extraSignals: [
                RiskSignal(
                    id: "server_public_ip",
                    category: "server",
                    score: 0,
                    evidence: ["public_ip": "203.0.113.10"],
                    state: .serverRequired,
                    layer: 4
                ),
            ]
        )

        XCTAssertEqual(verdict.action, .block)
        XCTAssertTrue(verdict.signals.contains(where: { $0.id == "blocklist_hit" && $0.state == .hard(detected: true) }))
    }

    func test_mutationJitterDeterministicPerDevice() {
        let policy = EnginePolicy(
            name: "mutation",
            version: "3.0-test",
            mutationStrategy: MutationStrategy(
                seed: "v3-seed",
                shuffleChecks: true,
                thresholdJitterBps: 1800,
                scoreJitterBps: 5000
            )
        )
        let engine = RiskDetectionEngine(policy: policy, enableLogging: false)

        let verdictA1 = engine.evaluate(
            context: makeContext(deviceID: "dev-A"),
            scenario: .default,
            extraSignals: [
                RiskSignal(
                    id: "probe_anchor",
                    category: "custom",
                    score: 0,
                    evidence: [:],
                    state: .soft(confidence: 1),
                    layer: 2,
                    weightHint: 20
                ),
            ]
        )
        let verdictA2 = engine.evaluate(
            context: makeContext(deviceID: "dev-A"),
            scenario: .default,
            extraSignals: [
                RiskSignal(
                    id: "probe_anchor",
                    category: "custom",
                    score: 0,
                    evidence: [:],
                    state: .soft(confidence: 1),
                    layer: 2,
                    weightHint: 20
                ),
            ]
        )
        let verdictB = engine.evaluate(
            context: makeContext(deviceID: "dev-B"),
            scenario: .default,
            extraSignals: [
                RiskSignal(
                    id: "probe_anchor",
                    category: "custom",
                    score: 0,
                    evidence: [:],
                    state: .soft(confidence: 1),
                    layer: 2,
                    weightHint: 20
                ),
            ]
        )

        XCTAssertEqual(verdictA1.score, verdictA2.score, accuracy: 0.0001)
        XCTAssertNotEqual(verdictA1.score, verdictB.score, "不同 deviceID 应触发不同扰动结果")
    }

    private func makeContext(deviceID: String) -> RiskContext {
        RiskContext(
            device: makeDevice(machine: "iPhone16,1"),
            deviceID: deviceID,
            network: makeCleanNetwork(),
            behavior: makeCleanBehavior(),
            jailbreak: DetectionResult(isJailbroken: false, confidence: 0, detectedMethods: [], details: "")
        )
    }

    private func makeDevice(machine: String, hardwareModel: String = "D47AP") -> DeviceFingerprint {
        DeviceFingerprint(
            systemName: "iOS",
            systemVersion: "18.0",
            model: "iPhone",
            localizedModel: "iPhone",
            identifierForVendor: nil,
            localeIdentifier: "zh_CN",
            timeZoneIdentifier: "Asia/Shanghai",
            timeZoneOffsetSeconds: 8 * 3600,
            screenWidth: 1179,
            screenHeight: 2556,
            screenScale: 3,
            hardwareMachine: machine,
            hardwareModel: hardwareModel,
            isSimulator: false
        )
    }

    private func makeCleanNetwork() -> NetworkSignals {
        NetworkSignals(
            interfaceType: InterfaceTypeSignal(value: "wifi", method: "test"),
            isExpensive: false,
            isConstrained: false,
            vpn: DetectionSignal(detected: false, method: "test", evidence: nil, confidence: .weak),
            proxy: DetectionSignal(detected: false, method: "test", evidence: nil, confidence: .weak)
        )
    }

    private func makeCleanBehavior() -> BehaviorSignals {
        BehaviorSignals(
            touch: TouchMetrics(
                sampleCount: 20,
                tapCount: 10,
                swipeCount: 2,
                coordinateSpread: 3.0,
                intervalCV: 0.4,
                averageLinearity: 0.95,
                forceVariance: 0.2,
                majorRadiusVariance: 0.3
            ),
            motion: MotionMetrics(sampleCount: 50, stillnessRatio: 0.9, motionEnergy: 0.01)
        )
    }
}

private struct MockProbe: V3HardwareProbe {
    let gpu: String
    let machine: String
    let ioKitModelValue: String
    let kernel: String

    func gpuName() -> String? { gpu }
    func machine(from snapshot: RiskSnapshot) -> String { machine }
    func ioKitModel() -> String { ioKitModelValue }
    func kernelVersion() -> String { kernel }
}
