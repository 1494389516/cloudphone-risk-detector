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
            policy: PolicyConfigData(scenarios: [:]),
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
        func verify(_ result: LocalAssessment, _ label: String) {
            let matches = result.signals.filter { $0.id == marker }
            guard matches.count == 1, matches[0].evidence["device"] == snapshot.deviceID else {
                // A stable marker lets CI distinguish the regression from build/probe failures.
                fatalError("ADAPTER_PROVIDER_LOSS: \(label)")
            }
        }
        let local = LocalAssessmentAdapter(engine: engine)
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
        print("Adapter provider regression: PASS (sync control and 5 async paths)")
    }
}
