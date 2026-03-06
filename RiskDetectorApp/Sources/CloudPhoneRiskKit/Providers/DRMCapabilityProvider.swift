import Foundation
#if canImport(AVFoundation)
import AVFoundation
#endif

enum DRMCapabilityLevel: String, Codable {
    case hardwareSecure
    case softwareOnly
    case unavailable
}

protocol DRMProbe {
    func probeDRMLevel() -> DRMCapabilityLevel
}

#if canImport(AVFoundation)
final class AVContentKeySessionProbe: DRMProbe {
    func probeDRMLevel() -> DRMCapabilityLevel {
        #if targetEnvironment(simulator)
        return .unavailable
        #elseif os(macOS)
        return .unavailable
        #else
        _ = AVContentKeySession(keySystem: .fairPlayStreaming)
        return .hardwareSecure
        #endif
    }
}
#endif

#if !canImport(AVFoundation)
struct StubDRMProbe: DRMProbe {
    func probeDRMLevel() -> DRMCapabilityLevel { .unavailable }
}
#endif

final class DRMCapabilityProvider: RiskSignalProvider {
    static let shared = DRMCapabilityProvider()

    let id = "drm_capability"

    private let probe: DRMProbe

    private static let vphoneModelPatterns: [String] = [
        "iphone99",
        "vresearch",
        "paravirtual",
    ]

    init(probe: DRMProbe? = nil) {
        #if canImport(AVFoundation)
        self.probe = probe ?? AVContentKeySessionProbe()
        #else
        self.probe = probe ?? StubDRMProbe()
        #endif
    }

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let planner = MutationPlanner(
            strategy: activeMutationStrategy(),
            scope: id,
            deviceID: snapshot.deviceID
        )

        let checks: [() -> [RiskSignal]] = [
            { self.drmSignals(snapshot: snapshot) },
        ]

        var out: [RiskSignal] = []
        for check in planner.maybeShuffle(checks, salt: "drm_checks") {
            out.append(contentsOf: check())
        }
        return planner.maybeShuffle(out, salt: "drm_emit_order")
    }

    private func activeMutationStrategy() -> MutationStrategy? {
        guard let mutation = PolicyManager.shared.activePolicy?.mutation else { return nil }
        return MutationStrategy(
            seed: mutation.seed,
            shuffleChecks: mutation.shuffleChecks,
            thresholdJitterBps: mutation.thresholdJitterBps,
            scoreJitterBps: mutation.scoreJitterBps
        )
    }

    private func drmSignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var out: [RiskSignal] = []

        var drmLevel = probe.probeDRMLevel()
        let machine = snapshot.device.hardwareMachine ?? ""
        let machineLower = machine.lowercased()
        let dynamicPatterns = PolicyManager.shared.activePolicy?.newVPhonePatterns.map { $0.lowercased() } ?? []
        let allPatterns = Self.vphoneModelPatterns + dynamicPatterns
        let hasVPhonePattern = allPatterns.contains { machineLower.contains($0) }
        let deviceNormal = !hasVPhonePattern && !machine.isEmpty

        if drmLevel == .hardwareSecure && hasVPhonePattern {
            drmLevel = .softwareOnly
        }

        let drmEvidence: [String: String] = [
            "drm_level": drmLevel.rawValue,
            "hardware_machine": machine,
        ]

        out.append(
            RiskSignal(
                id: "drm_capability",
                category: "device",
                score: 0,
                evidence: drmEvidence,
                state: drmState(drmLevel: drmLevel, deviceNormal: deviceNormal),
                layer: 1,
                weightHint: 85
            )
        )

        if deviceNormal && (drmLevel == .softwareOnly || drmLevel == .unavailable) {
            out.append(
                RiskSignal(
                    id: "drm_device_mismatch",
                    category: "device",
                    score: 0,
                    evidence: [
                        "drm_level": drmLevel.rawValue,
                        "hardware_machine": machine,
                        "reason": "real_device_claims_but_drm_degraded",
                    ],
                    state: .hard(detected: true),
                    layer: 1,
                    weightHint: 100
                )
            )
        }

        return out
    }

    private func drmState(drmLevel: DRMCapabilityLevel, deviceNormal: Bool) -> RiskSignalState {
        #if targetEnvironment(simulator)
        if drmLevel == .unavailable {
            return .soft(confidence: 0.7)
        }
        #elseif os(macOS)
        if drmLevel == .unavailable {
            return .soft(confidence: 0.7)
        }
        #endif

        switch drmLevel {
        case .hardwareSecure:
            return .hard(detected: false)
        case .softwareOnly:
            return .soft(confidence: 0.85)
        case .unavailable:
            if deviceNormal {
                return .soft(confidence: 0.7)
            }
            return .hard(detected: true)
        }
    }
}
