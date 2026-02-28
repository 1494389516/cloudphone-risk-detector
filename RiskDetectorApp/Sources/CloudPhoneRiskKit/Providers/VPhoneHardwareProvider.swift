import Foundation
#if canImport(Metal)
import Metal
#endif
#if canImport(IOKit)
import IOKit
#endif

protocol V3HardwareProbe {
    func gpuName() -> String?
    func machine(from snapshot: RiskSnapshot) -> String
    func ioKitModel() -> String
    func kernelVersion() -> String
}

struct SystemHardwareProbe: V3HardwareProbe {
    func gpuName() -> String? {
#if canImport(Metal)
        return MTLCreateSystemDefaultDevice()?.name
#else
        return nil
#endif
    }

    func machine(from snapshot: RiskSnapshot) -> String {
        if let machine = snapshot.device.hardwareMachine, machine.isEmpty == false {
            return machine
        }
        return Sysctl.string("hw.machine") ?? ""
    }

    func ioKitModel() -> String {
#if canImport(IOKit)
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        defer { IOObjectRelease(service) }
        guard service != IO_OBJECT_NULL else { return "" }
        guard
            let value = IORegistryEntryCreateCFProperty(
                service,
                "model" as CFString,
                kCFAllocatorDefault,
                0
            )?.takeRetainedValue() as? Data
        else {
            return ""
        }

        return String(data: value, encoding: .utf8)?
            .trimmingCharacters(in: .controlCharacters) ?? ""
#else
        return ""
#endif
    }

    func kernelVersion() -> String {
        var info = utsname()
        uname(&info)
        let versionTuple = info.version
        return withUnsafePointer(to: versionTuple) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: versionTuple)) {
                String(cString: $0)
            }
        }
    }
}

final class VPhoneHardwareProvider: RiskSignalProvider {
    static let shared = VPhoneHardwareProvider()

    let id = "vphone_hardware"

    private let probe: V3HardwareProbe

    static let knownVirtualGPUKeywords: [String] = [
        "apple paravirtual device",
        "apple paravirt",
        "llvmpipe",
        "llvm",
    ]

    static let vphoneModelPatterns: [String] = [
        "iphone99",
        "vresearch",
        "paravirtual",
    ]

    init(probe: V3HardwareProbe = SystemHardwareProbe()) {
        self.probe = probe
    }

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let planner = MutationPlanner(
            strategy: activeMutationStrategy(),
            scope: id,
            deviceID: snapshot.deviceID
        )
        let checks: [() -> [RiskSignal]] = [
            { self.gpuSignals() },
            { self.hardwareConsistencySignals(snapshot: snapshot) },
        ]

        var out: [RiskSignal] = []
        for check in planner.maybeShuffle(checks, salt: "layer1_checks") {
            out.append(contentsOf: check())
        }
        return planner.maybeShuffle(out, salt: "layer1_emit_order")
    }

    private func gpuSignals() -> [RiskSignal] {
        let gpu = probe.gpuName() ?? ""
        if gpu.isEmpty {
            return [
                RiskSignal(
                    id: "gpu_virtual",
                    category: "device",
                    score: 0,
                    evidence: ["detail": "metal_unavailable"],
                    state: .soft(confidence: 0.6),
                    layer: 1,
                    weightHint: 95
                ),
            ]
        }

        let lower = gpu.lowercased()
        let hitVirtualGPU = Self.knownVirtualGPUKeywords.contains { lower.contains($0) }
        let realChipLike = lower.contains("apple a") || lower.contains("apple m") || lower.contains("apple gpu")
        return [
            RiskSignal(
                id: "gpu_virtual",
                category: "device",
                score: 0,
                evidence: ["gpu_name": gpu],
                state: hitVirtualGPU ? .hard(detected: true) : (realChipLike ? .hard(detected: false) : .soft(confidence: 0.45)),
                layer: 1,
                weightHint: 95
            ),
        ]
    }

    private func hardwareConsistencySignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var out: [RiskSignal] = []

        let sysctlModel = probe.machine(from: snapshot)
        let iokitModel = probe.ioKitModel()
        let kernelVersion = probe.kernelVersion()
        let boardID = snapshot.device.hardwareModel ?? ""
        let all = [sysctlModel, iokitModel, kernelVersion]
        let dynamicPatterns = PolicyManager.shared.activePolicy?.newVPhonePatterns.map { $0.lowercased() } ?? []
        let allPatterns = Self.vphoneModelPatterns + dynamicPatterns

        let hasVPhonePattern = all.contains { value in
            let lower = value.lowercased()
            return allPatterns.contains(where: { lower.contains($0) })
        }

        out.append(
            RiskSignal(
                id: "vphone_hardware",
                category: "device",
                score: 0,
                evidence: [
                    "sysctl_model": sysctlModel,
                    "iokit_model": iokitModel,
                    "kernel": kernelVersion,
                ],
                state: .hard(detected: hasVPhonePattern),
                layer: 1,
                weightHint: 100
            )
        )

        if boardID.isEmpty {
            out.append(
                RiskSignal(
                    id: "board_id_virtual",
                    category: "device",
                    score: 0,
                    evidence: ["board_id": "unavailable"],
                    state: .unavailable,
                    layer: 1,
                    weightHint: 88
                )
            )
        } else {
            let boardLower = boardID.lowercased()
            let boardSuspicious = allPatterns.contains(where: { boardLower.contains($0) })
            out.append(
                RiskSignal(
                    id: "board_id_virtual",
                    category: "device",
                    score: 0,
                    evidence: ["board_id": boardID],
                    state: .hard(detected: boardSuspicious),
                    layer: 1,
                    weightHint: 88
                )
            )
        }

        if !sysctlModel.isEmpty, !iokitModel.isEmpty, sysctlModel != iokitModel {
            out.append(
                RiskSignal(
                    id: "hardware_inconsistency",
                    category: "device",
                    score: 0,
                    evidence: [
                        "sysctl": sysctlModel,
                        "iokit": iokitModel,
                    ],
                    state: .soft(confidence: 0.85),
                    layer: 2,
                    weightHint: 90
                )
            )
        }

        return out
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
}
