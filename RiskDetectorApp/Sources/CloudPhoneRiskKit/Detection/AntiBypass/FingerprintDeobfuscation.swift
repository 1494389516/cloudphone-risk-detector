import Darwin
import Foundation
#if canImport(UIKit)
import UIKit
#endif

struct FingerprintDeobfuscation: Detector {
    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        if isSimulatorLikeEnvironment() {
            score += 30
            methods.append("fingerprint:simulator_like")
        }

        if hasSuspiciousHardwareModel() {
            score += 20
            methods.append("fingerprint:suspicious_hw_model")
        }

        if hasVirtualizationArtifacts() {
            score += 25
            methods.append("fingerprint:virtualization_artifact")
        }

        if hasFingerprintMutation() {
            score += 12
            methods.append("fingerprint:fingerprint_changed")
        }

        return DetectorResult(score: score, methods: methods)
    }

    private func isSimulatorLikeEnvironment() -> Bool {
#if targetEnvironment(simulator)
        return true
#else
        let machine = (Sysctl.string("hw.machine") ?? "").lowercased()
        return machine.contains("x86") || machine.contains("simulator")
#endif
    }

    private func hasSuspiciousHardwareModel() -> Bool {
        let model = (Sysctl.string("hw.model") ?? "").lowercased()
        if model.isEmpty { return false }
        let keywords = ["vmware", "virtualbox", "qemu", "parallels", "kvm"]
        return keywords.contains { model.contains($0) }
    }

    private func hasVirtualizationArtifacts() -> Bool {
        let paths = [
            "/sys/hypervisor",
            "/sys/class/dmi/id/product_name",
            "/Applications/Simulator.app"
        ]
        for path in paths {
            var st = stat()
            if stat(path, &st) == 0 {
                return true
            }
        }
        return false
    }

    private func hasFingerprintMutation() -> Bool {
        let fingerprint = collectFingerprintSignature()
        let key = "CPRisk_FingerprintSignature"
        let defaults = UserDefaults.standard

        if let old = defaults.string(forKey: key) {
            if old != fingerprint {
                defaults.set(fingerprint, forKey: key)
                return true
            }
            return false
        }

        defaults.set(fingerprint, forKey: key)
        return false
    }

    private func collectFingerprintSignature() -> String {
        let machine = Sysctl.string("hw.machine") ?? "unknown"
        let model = Sysctl.string("hw.model") ?? "unknown"
        let memory = Sysctl.int64("hw.memsize") ?? 0
        let cpu = ProcessInfo.processInfo.processorCount

#if canImport(UIKit)
        let bounds = UIScreen.main.bounds
        let scale = UIScreen.main.scale
        let screen = "\(Int(bounds.width))x\(Int(bounds.height))@\(scale)"
#else
        let screen = "unknown"
#endif

        return "\(machine)|\(model)|\(memory)|\(cpu)|\(screen)"
    }
}
