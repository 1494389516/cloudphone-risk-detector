import Foundation

final class DeviceHardwareProvider: RiskSignalProvider {
    static let shared = DeviceHardwareProvider()
    private init() {}

    let id = "device_hardware"
    private static let suspiciousHostnameKeywords = [
        "cloudphone",
        "phonecloud",
        "vphone",
        "redfinger",
        "armcloud",
        "nowgg",
        "bignox",
        "remotefarm",
    ]

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var out: [RiskSignal] = []

        if snapshot.device.isSimulator {
            out.append(
                RiskSignal(
                    id: "simulator",
                    category: "device",
                    score: 0,
                    evidence: ["machine": snapshot.device.hardwareMachine ?? "unknown"]
                )
            )
            out.append(
                RiskSignal(
                    id: SignalID.isSimulator,
                    category: "device",
                    score: 0,
                    evidence: ["machine": snapshot.device.hardwareMachine ?? "unknown"],
                    state: .hard(detected: true),
                    layer: 1,
                    weightHint: 90
                )
            )
        }

        if let machine = snapshot.device.hardwareMachine, machine.isEmpty == false {
            out.append(
                RiskSignal(
                    id: "hw_machine",
                    category: "device",
                    score: 0,
                    evidence: ["machine": machine]
                )
            )
        }

        if let hostnameSignal = hostnameSignal() {
            out.append(hostnameSignal)
        }

        if let kernelSignal = kernelBuildSignal(snapshot: snapshot) {
            out.append(kernelSignal)
        }

        return out
    }

    private func hostnameSignal() -> RiskSignal? {
        let hostname = ProcessInfo.processInfo.hostName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !hostname.isEmpty else { return nil }

        let lower = hostname.lowercased()
        let suspicious = Self.suspiciousHostnameKeywords.first(where: { lower.contains($0) })
        guard let matched = suspicious else { return nil }

        return RiskSignal(
            id: SignalID.hostnameContainsCloud,
            category: "device",
            score: 0,
            evidence: [
                "hostname": hostname,
                "matched_keyword": matched,
            ],
            state: .soft(confidence: 0.82),
            layer: 1,
            weightHint: 70
        )
    }

    private func kernelBuildSignal(snapshot: RiskSnapshot) -> RiskSignal? {
        guard !snapshot.device.isSimulator else { return nil }

        guard let kernelBuild = snapshot.device.kernelBuild, !kernelBuild.isEmpty else {
            return RiskSignal(
                id: SignalID.kernelBuildAnomaly,
                category: "device",
                score: 0,
                evidence: ["reason": "kernel_build_missing"],
                state: .soft(confidence: 0.55),
                layer: 1,
                weightHint: 40
            )
        }

        guard !DeviceFingerprint.looksLikeKernelBuild(kernelBuild) else { return nil }

        return RiskSignal(
            id: SignalID.kernelBuildAnomaly,
            category: "device",
            score: 0,
            evidence: [
                "reason": "kernel_build_format_invalid",
                "kernel_build": kernelBuild,
            ],
            state: .soft(confidence: 0.72),
            layer: 1,
            weightHint: 55
        )
    }
}
