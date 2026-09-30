@testable import CloudPhoneRiskKit
import Foundation

private struct OfflineConfig: AdapterConfigManager {
    enum Failure: Error { case offline }
    func getCurrentConfig() async throws -> AdapterConfig { throw Failure.offline }
}

private struct RemoteConfig: AdapterConfigManager {
    func getCurrentConfig() async throws -> AdapterConfig {
        AdapterConfig(
            version: "fixture-remote",
            policy: PolicyConfigData(scenarios: ["default": .init(thresholds: .init(medium: 30, high: 65, critical: 90))]),
            detectors: AdapterDetectorsConfigData()
        )
    }
}

private func fixtureSnapshot() throws -> RiskSnapshot {
    let decoder = JSONDecoder()
    let device = try decoder.decode(DeviceFingerprint.self, from: Data(#"{"sn":"iOS","sv":"17.0","m":"iPhone","lm":"iPhone","li":"en_US","tz":"UTC","to":0,"sw":390,"sh":844,"ss":3,"is":false}"#.utf8))
    let network = try decoder.decode(NetworkSignals.self, from: Data(#"{"it":{"v":"wifi","m":"fixture"},"ie":false,"ic":false,"vp":{"d":false,"m":"fixture","c":"strong"},"px":{"d":false,"m":"fixture","c":"strong"}}"#.utf8))
    let behavior = try decoder.decode(BehaviorSignals.self, from: Data(#"{"t":{"sc":0,"tp":0,"sw":0},"m":{"sc":0},"ac":0}"#.utf8))
    return RiskSnapshot(
        deviceID: "adapter-fixture",
        device: device,
        network: network,
        behavior: behavior,
        jailbreak: DetectionResult(isJailbroken: false, confidence: 0, detectedMethods: [], details: "fixture")
    )
}

@main
private struct AdapterRegression {
    static func main() async throws {
        let snapshot = try fixtureSnapshot()
        let marker = "adapter_custom_provider_fixture"
        let engine = RiskDetectionEngine(enableLogging: false, customProviders: [
            "fixture": { context in
                [RiskSignal(id: marker, category: "fixture", score: 37,
                            evidence: ["device": context.deviceID])]
            }
        ])
        let replacementPolicy = EnginePolicy(name: "replacement", version: "fixture-2")
        let replacement = engine.replacingPolicy(replacementPolicy)
        precondition(!replacement.enableLogging, "Policy refresh re-enabled logging")
        precondition(replacement.policy.name == "replacement" && replacement.policy.version == "fixture-2")
        precondition(engine.policy.name == "default", "Policy refresh mutated the source engine")
        precondition(RiskDetectionEngine(enableLogging: true).replacingPolicy(replacementPolicy).enableLogging)
        func verify(_ result: LocalAssessment, _ label: String) {
            let matches = result.signals.filter { $0.id == marker }
            guard matches.count == 1, matches[0].evidence["device"] == snapshot.deviceID else {
                // A stable marker lets CI distinguish the regression from build/probe failures.
                fatalError("ADAPTER_PROVIDER_LOSS: \(label)")
            }
        }
        let local = LocalAssessmentAdapter(engine: engine)
        let replaced = LocalAssessmentAdapter(engine: replacement)
        verify(replaced.decideSync(snapshot: snapshot), "policy copy control")
        verify(local.decideSync(snapshot: snapshot), "sync control")
        let disabled = await local.assess(snapshot: snapshot, config: .init(useRemoteConfig: false))
        verify(disabled, "remote disabled")
        let absent = await local.assess(snapshot: snapshot, config: .init())
        verify(absent, "no config manager")
        let offline = LocalAssessmentAdapter(engine: engine, configManager: OfflineConfig())
        let fallback = await offline.assess(snapshot: snapshot, config: .init())
        verify(fallback, "remote failure fallback")
        let remote = LocalAssessmentAdapter(engine: engine, configManager: RemoteConfig())
        let refreshed = await remote.assess(snapshot: snapshot, config: .init())
        verify(refreshed, "remote success")
        let legacy = await remote.decide(snapshot: snapshot, config: .init())
        verify(legacy, "legacy async bridge")
        try verifyDefaultSelectionParity(snapshot: snapshot)
        try verifyPolicyAndMetadataCopies(snapshot: snapshot)
        try await verifyConfiguration(snapshot: snapshot)
        print("Adapter provider regression: PASS (sync control and 5 async paths)")
    }
}

// Configuration regressions use synthetic inputs; mandatory runtime integrity probes remain active.
private func verifyConfiguration(snapshot: RiskSnapshot) async throws {
    let marker = "adapter_config_marker"
    let engine = RiskDetectionEngine(enableLogging: false, customProviders: [
        "provider-name-is-not-a-category": { _ in
            [RiskSignal(id: marker, category: "custom", score: 37, evidence: [:]),
             RiskSignal(id: "network_fixture", category: "network", score: 2, evidence: [:]),
             RiskSignal(id: "device_fixture", category: "device", score: 2, evidence: [:]),
             RiskSignal(id: "environment_fixture", category: "environment", score: 2, evidence: [:]),
             RiskSignal(id: "anti_tamper_fixture", category: "anti_tamper", score: 2, evidence: [:]),
             RiskSignal(id: "jailbreak_fixture", category: "jailbreak", score: 2, evidence: [:])]
        }
    ])
    let config = LocalAssessmentConfig(useRemoteConfig: false, customThreshold: 35,
        enabledDetectors: ["network"], extras: ["requestId": "caller", "timestamp": "caller", "note": "local-only"])
    func verify(_ result: LocalAssessment, _ label: String) throws {
        precondition(result.signals.contains { $0.id == marker }, "CONFIG_PROVIDER_LOSS: \(label)")
        precondition(result.signals.contains { $0.id == "network_fixture" })
        for id in ["device_fixture", "environment_fixture", "anti_tamper_fixture", "jailbreak_fixture", "insufficient_behavior_data"] {
            precondition(!result.signals.contains { $0.id == id }, "CONFIG_DETECTOR_IGNORED: \(label): \(id)")
        }
        precondition(result.internalLevel == .high, "CONFIG_THRESHOLD_IGNORED: \(label)")
        precondition(result.extras["config.note"] == "local-only", "CONFIG_EXTRAS_LOST: \(label)")
        precondition(result.extras["requestId"] == result.requestId && result.requestId != "caller")
        precondition(result.extras["timestamp"] != "caller")
        precondition(result.extras["config.requestId"] == "caller")
        let wire = try JSONEncoder().encode(result)
        let json = String(decoding: wire, as: UTF8.self)
        precondition(!json.contains("local-only") && !json.contains("config.note"), "CONFIG_EXTRAS_LEAKED")
        let decoded = try JSONDecoder().decode(LocalAssessment.self, from: wire)
        precondition(decoded.extras["config.note"] == nil)
        precondition(decoded.requestId == result.requestId && decoded.timestamp == result.timestamp)
    }
    let local = LocalAssessmentAdapter(engine: engine)
    try verify(local.decideSync(snapshot: snapshot, config: config), "sync")
    try verify(await local.assess(snapshot: snapshot, config: config), "remote disabled")
    var remoteConfig = config
    remoteConfig.useRemoteConfig = true
    try verify(await local.assess(snapshot: snapshot, config: remoteConfig), "manager absent")
    let offline = LocalAssessmentAdapter(engine: engine, configManager: OfflineConfig())
    try verify(await offline.assess(snapshot: snapshot, config: remoteConfig), "remote failure")
    let remote = LocalAssessmentAdapter(engine: engine, configManager: RemoteConfig())
    try verify(await remote.assess(snapshot: snapshot, config: remoteConfig), "remote success")
    try verify(await remote.decide(snapshot: snapshot, config: remoteConfig), "legacy bridge")

    // Explicitly mutated and decoded empties match initializer defaults.
    var empty = LocalAssessmentConfig(useRemoteConfig: false)
    empty.enabledDetectors = []
    let decodedEmpty = try JSONDecoder().decode(LocalAssessmentConfig.self, from: JSONEncoder().encode(empty))
    for selection in [empty, decodedEmpty, LocalAssessmentConfig(useRemoteConfig: false)] {
        let result = local.decideSync(snapshot: snapshot, config: selection)
        precondition(result.signals.contains { $0.id == "device_fixture" })
        precondition(result.signals.contains { $0.id == "environment_fixture" })
    }

    // Excluding jailbreak must also remove context-derived force/family contributions.
    var jailbroken = snapshot
    jailbroken.jailbreak = DetectionResult(isJailbroken: true, confidence: 1,
        detectedMethods: ["fixture"], details: "fixture")
    let clean = local.decideSync(snapshot: snapshot, config: config)
    let selected = local.decideSync(snapshot: jailbroken, config: config)
    precondition(clean.score == selected.score && clean.internalAction == selected.internalAction)
    precondition(clean.confidence == selected.confidence)
    precondition(!selected.signals.contains { $0.id == "jailbreak_device" })

    // A disabled category never drops explicit tamper evidence.
    let integrity = LocalAssessmentAdapter(engine: RiskDetectionEngine(enableLogging: false, customProviders: [
        "integrity": { _ in [RiskSignal(id: "mandatory_integrity_fixture", category: "anti_tamper", score: 0, evidence: [:],
                                        state: .tampered, layer: 2, weightHint: 60)] }
    ]))
    precondition(integrity.decideSync(snapshot: snapshot, config: config).signals.contains {
        $0.id == "mandatory_integrity_fixture"
    })
    let comboPolicy = EnginePolicy(scenarioPolicies: [.default: ScenarioPolicy(comboRules: [
        .init(name: "excluded-evidence", requiredSignals: ["network_fixture", "device_fixture"],
              bonusScore: 100, forceAction: .block)
    ])])
    let combo = LocalAssessmentAdapter(engine: engine.replacingPolicy(comboPolicy))
    let selectedCombo = combo.decideSync(snapshot: snapshot, config: config)
    precondition(selectedCombo.score < 80 && selectedCombo.internalAction != .block,
                 "Disabled evidence leaked into combo scoring")
    let defaultCombo = combo.decideSync(snapshot: snapshot, config: .init(useRemoteConfig: false))
    precondition(defaultCombo.internalAction == .block)
    precondition(selectedCombo.compressedDigest == SignalCompressor.compress(signals: selectedCombo.signals).digest)
    let compressedPolicy = EnginePolicy(scenarioPolicies: [.default: ScenarioPolicy(compressedVerdictRules: [
        .init(id: "excluded-device", layerIndex: 1, bitMask: 2, matchValue: 2, action: .block)
    ])])
    let compressed = LocalAssessmentAdapter(engine: RiskDetectionEngine(policy: compressedPolicy,
        enableLogging: false, customProviders: ["hardware": { _ in
            [RiskSignal(id: "vphone_hardware", category: "device", score: 0, evidence: [:],
                        state: .hard(detected: true), layer: 1, weightHint: 50)]
        }]))
    let excludedDevice = compressed.decideSync(snapshot: snapshot, config: config)
    precondition(excludedDevice.internalAction != .block)
    precondition(!excludedDevice.signals.contains { $0.id == "vphone_hardware" })
    precondition((excludedDevice.compressedDigest![0] & 2) == 0,
                 "Disabled evidence leaked into compressed verdict rule")
    precondition(compressed.decideSync(snapshot: snapshot).internalAction == .block)
    print("Adapter configuration behavior: PASS")
}

private func verifyPolicyAndMetadataCopies(snapshot: RiskSnapshot) throws {
    let originalScenario = ScenarioPolicy(
        mediumThreshold: 20, highThreshold: 50, criticalThreshold: 80,
        actionMapping: [.low: .allow, .medium: .challenge, .high: .stepUpAuth, .critical: .block],
        signalWeights: .init(jailbreak: 0.8, network: 1.2, behavior: 0.7, device: 1.4, time: 0.6),
        comboRules: [.init(name: "preserve", requiredSignals: ["fixture"], bonusScore: 3, forceAction: .challenge)],
        enableForceRules: false,
        compressedVerdictRules: [.init(id: "preserve", layerIndex: 2, bitMask: 1, matchValue: 1, action: .block)]
    )
    let policy = EnginePolicy(
        name: "preserve", version: "v-preserve", killSwitchEnabled: true,
        enableNetworkSignals: false, enableBehaviorDetection: false, enableDeviceFingerprint: false,
        forceActionOnJailbreak: .block, signalWeightOverrides: ["fixture": 19],
        mutationStrategy: .init(seed: "fixture"),
        blindChallengePolicy: .init(challengeSalt: "fixture", rules: []),
        serverBlocklist: ["fixture"], blocklistAction: .stepUpAuth,
        scenarioPolicies: [.login: originalScenario, .payment: .payment]
    )
    func object<T: Encodable>(_ value: T) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as! [String: Any]
    }
    let config = LocalAssessmentConfig(scenario: .login, customThreshold: 35)
    let adjusted = LocalAssessmentAdapter.applyingLocalOverrides(config, to: policy)
    var originalFields = try object(policy)
    var adjustedFields = try object(adjusted)
    originalFields.removeValue(forKey: "sp")
    adjustedFields.removeValue(forKey: "sp")
    precondition(NSDictionary(dictionary: originalFields) == NSDictionary(dictionary: adjustedFields))
    var expectedScenario = try object(originalScenario)
    expectedScenario["ht"] = 35.0
    let actualScenario = try object(adjusted.scenarioPolicy(for: .login))
    precondition(NSDictionary(dictionary: expectedScenario) == NSDictionary(dictionary: actualScenario))
    let originalPayment = try object(policy.scenarioPolicy(for: .payment))
    let adjustedPayment = try object(adjusted.scenarioPolicy(for: .payment))
    precondition(NSDictionary(dictionary: originalPayment) == NSDictionary(dictionary: adjustedPayment))
    precondition(policy.scenarioPolicy(for: .login).highThreshold == 50)
    for invalid in [Double.nan, Double.infinity, -Double.infinity, -1, 0, 20, 80, 100, 101] {
        let unchanged = LocalAssessmentAdapter.applyingLocalOverrides(.init(scenario: .login, customThreshold: invalid), to: policy)
        precondition(unchanged.scenarioPolicy(for: .login).highThreshold == 50, "Invalid threshold changed policy")
    }
    for valid in [20.001, 79.999] {
        let changed = LocalAssessmentAdapter.applyingLocalOverrides(.init(scenario: .login, customThreshold: valid), to: policy)
        precondition(changed.scenarioPolicy(for: .login).highThreshold == valid)
    }
    let unchanged = LocalAssessmentAdapter.applyingLocalOverrides(.init(scenario: .login), to: policy)
    precondition(unchanged.scenarioPolicy(for: .login).highThreshold == 50)

    let original = LocalAssessment(score: 42, internalLevel: .medium, internalAction: .challenge,
        confidence: 0.7, primaryReasons: ["fixture"], signals: [], scenario: .login,
        compressedDigest: Data([1, 2, 3]), mappingVersion: "fixture", decisionMetadata: ["origin": "engine"])
    let copied = original.retainingLocalExtras(["dm.origin": "caller", "timestamp": "caller", "note": "local-only"])
    precondition(copied.requestId == original.requestId && copied.timestamp == original.timestamp)
    precondition(copied.extras["dm.origin"] == "engine" && copied.extras["config.dm.origin"] == "caller")
    let originalJSON = try object(original)
    let copiedJSON = try object(copied)
    precondition(NSDictionary(dictionary: originalJSON) == NSDictionary(dictionary: copiedJSON), "Local extras altered serialized result")
    precondition(original.extras["config.note"] == nil)

    // Kill-switch/early results also retain local metadata, without changing their action.
    let adapter = LocalAssessmentAdapter(engine: RiskDetectionEngine(policy: policy, enableLogging: false))
    let stopped = adapter.decideSync(snapshot: snapshot, config: .init(extras: ["note": "local-only"]))
    precondition(stopped.internalAction == .allow && stopped.score == 0)
    precondition(stopped.extras["config.note"] == "local-only")
    print("Adapter policy preservation and local metadata: PASS")
}

private func verifyDefaultSelectionParity(snapshot: RiskSnapshot) throws {
    var evidence = snapshot
    evidence.device.model = "simulator"
    evidence.network.vpn.detected = true
    evidence.network.proxy.detected = true
    evidence.behavior.actionCount = 20
    let policy = EnginePolicy(enableNetworkSignals: false, enableBehaviorDetection: false,
                              enableDeviceFingerprint: false)
    let engine = RiskDetectionEngine(policy: policy, enableLogging: false, customProviders: [
        "caller": { context in
            precondition(context.network.isVPNActive && context.device.model == "simulator",
                         "Adapter fabricated context for provider")
            return ["network", "behavior", "device", "custom"].map {
                RiskSignal(id: "parity_" + $0, category: $0, score: 1, evidence: [:])
            }
        }
    ])
    let context = RiskContext(device: evidence.device, deviceID: evidence.deviceID,
        network: evidence.network, behavior: evidence.behavior, jailbreak: evidence.jailbreak)
    let direct = engine.evaluate(context: context)
    let adapter = LocalAssessmentAdapter(engine: engine)
    let adapted = adapter.decideSync(snapshot: evidence)
    precondition(direct.score == adapted.score && direct.internalAction == adapted.internalAction)
    precondition(direct.confidence == adapted.confidence && direct.compressedDigest == adapted.compressedDigest)
    precondition(Set(direct.signals.map { $0.id }) == Set(adapted.signals.map { $0.id }))
    precondition(adapted.signals.contains { $0.id == "suspicious_device_name" })
    precondition(adapted.signals.contains { $0.id == "parity_network" })
    precondition(!adapted.signals.contains { $0.id == "proxy_enabled" })

    // Network context conditions must obey explicit selection as well as signal filtering.
    var evaluation = EvaluationContext(score: 0, signals: [], scenario: .default,
        riskContext: context, policy: .general)
    evaluation.networkEnabled = false
    precondition(!evaluation.isVPNActive && !evaluation.proxyEnabled)
    precondition(!ConditionExpression.isVPN.evaluate(context: evaluation))
    precondition(!ConditionExpression.isProxy.evaluate(context: evaluation))
    precondition(evaluation.riskContext.network.isVPNActive)
    print("Adapter default parity and original context: PASS")
}
