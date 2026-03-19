import Darwin
import Foundation

/// Validates pointer-authentication posture on PAC-capable devices (A12+).
///
/// Heuristics:
/// 1) Feature gate reports disabled (`hw.optional.arm64e` / `hw.optional.arm.FEAT_PAuth`)
/// 2) Critical function pointers fail `dladdr`/readability checks
/// 3) Critical function pointers resolve to unexpected images
struct PACValidationDetector: Detector {
    struct SymbolProbe {
        let symbol: String
        let expectedImageTokens: [String]
    }

    struct Snapshot {
        let machine: String
        let pacCapable: Bool
        let arm64eFlag: Int?
        let pAuthFlag: Int?
        let unreadablePointers: [String]
        let unexpectedImages: [String]
    }

    struct Assessment {
        let score: Double
        let methods: [String]
        let pacCapable: Bool
        let pacReportedDisabled: Bool
        let invalidPointerCount: Int
    }

    private let probes: [SymbolProbe] = [
        .init(symbol: "open", expectedImageTokens: ["libsystem", "/usr/lib/system"]),
        .init(symbol: "stat", expectedImageTokens: ["libsystem", "/usr/lib/system"]),
        .init(symbol: "sysctl", expectedImageTokens: ["libsystem", "/usr/lib/system"]),
        .init(symbol: "dlopen", expectedImageTokens: ["libsystem", "/usr/lib/system"]),
        .init(symbol: "objc_msgSend", expectedImageTokens: ["libobjc"]),
    ]

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["pac:unavailable_simulator"])
#elseif !(arch(arm64) || arch(arm64e))
        return DetectorResult(score: 0, methods: ["pac:unavailable_arch"])
#else
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    func assess(snapshot: Snapshot) -> Assessment {
        guard snapshot.pacCapable else {
            return Assessment(
                score: 0,
                methods: ["pac:not_applicable"],
                pacCapable: false,
                pacReportedDisabled: false,
                invalidPointerCount: 0
            )
        }

        var score: Double = 0
        var methods: [String] = []

        let featureValues = [snapshot.arm64eFlag, snapshot.pAuthFlag].compactMap { $0 }
        let pacReportedDisabled = !featureValues.isEmpty && featureValues.contains(0)
        if pacReportedDisabled {
            score += 70
            methods.append("pac:feature_disabled")
        }

        let invalidPointerCount = snapshot.unreadablePointers.count
        if invalidPointerCount >= 2 {
            score += min(30 + Double(invalidPointerCount - 2) * 8, 45)
            methods.append("pac:pointer_invalid:\(invalidPointerCount)")
        } else if invalidPointerCount == 1 {
            score += 8
            methods.append("pac:pointer_invalid_hint:1")
        }

        if !snapshot.unexpectedImages.isEmpty {
            score += min(20 + Double(snapshot.unexpectedImages.count - 1) * 8, 40)
            methods.append("pac:pointer_unexpected_image:\(snapshot.unexpectedImages.count)")
        }

        if pacReportedDisabled && (invalidPointerCount > 0 || !snapshot.unexpectedImages.isEmpty) {
            score += 10
            methods.append("pac:disabled_and_pointer_anomaly")
        }

        return Assessment(
            score: min(score, 95),
            methods: methods,
            pacCapable: true,
            pacReportedDisabled: pacReportedDisabled,
            invalidPointerCount: invalidPointerCount
        )
    }

    private func collectSnapshot() -> Snapshot {
        let machine = (Sysctl.string("hw.machine") ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let pacCapable = isA12OrLater(machine: machine)
        let arm64eFlag = Sysctl.int("hw.optional.arm64e")
        let pAuthFlag = Sysctl.int("hw.optional.arm.FEAT_PAuth")

        guard pacCapable else {
            return Snapshot(
                machine: machine,
                pacCapable: false,
                arm64eFlag: arm64eFlag,
                pAuthFlag: pAuthFlag,
                unreadablePointers: [],
                unexpectedImages: []
            )
        }

        var unreadablePointers: [String] = []
        var unexpectedImages: [String] = []

        for probe in probes {
            guard let symbolPtr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), probe.symbol) else {
                unreadablePointers.append("\(probe.symbol):dlsym")
                continue
            }

            var info = Dl_info()
            guard dladdr(symbolPtr, &info) != 0, let imageName = info.dli_fname else {
                unreadablePointers.append("\(probe.symbol):dladdr")
                continue
            }

            let path = String(cString: imageName)
            let normalizedPath = path.lowercased()
            if !matchesExpectedImage(path: normalizedPath, expectedTokens: probe.expectedImageTokens) {
                unexpectedImages.append("\(probe.symbol)@\(path)")
            }

            if !isPointerReadable(symbolPtr) {
                unreadablePointers.append("\(probe.symbol):vm_read")
                continue
            }

            if let imageBase = info.dli_fbase,
               let textRange = MachOTextRange.textRange(header: UnsafeRawPointer(imageBase)) {
                let address = UInt64(bitPattern: Int64(Int(bitPattern: symbolPtr)))
                if address < textRange.lowerBound || address >= textRange.upperBound {
                    unreadablePointers.append("\(probe.symbol):text_range")
                }
            }
        }

        return Snapshot(
            machine: machine,
            pacCapable: true,
            arm64eFlag: arm64eFlag,
            pAuthFlag: pAuthFlag,
            unreadablePointers: unreadablePointers,
            unexpectedImages: unexpectedImages
        )
    }

    private func isPointerReadable(_ pointer: UnsafeMutableRawPointer) -> Bool {
        var instruction: UInt32 = 0
        var outSize: vm_size_t = 0
        let kr = withUnsafeMutablePointer(to: &instruction) { ptr in
            vm_read_overwrite(
                mach_task_self_,
                vm_address_t(UInt(bitPattern: pointer)),
                vm_size_t(MemoryLayout<UInt32>.size),
                vm_address_t(UInt(bitPattern: ptr)),
                &outSize
            )
        }
        return kr == KERN_SUCCESS && outSize == MemoryLayout<UInt32>.size
    }

    private func matchesExpectedImage(path: String, expectedTokens: [String]) -> Bool {
        expectedTokens.contains(where: { path.contains($0) })
    }

    private func isA12OrLater(machine: String) -> Bool {
        guard let parsed = parseMachine(machine) else { return false }
        switch parsed.family {
        case "iphone":
            return parsed.major >= 11
        case "ipad":
            return parsed.major >= 8
        case "ipod":
            return parsed.major >= 9
        default:
            return false
        }
    }

    private func parseMachine(_ machine: String) -> (family: String, major: Int)? {
        let lower = machine.lowercased()
        let families = ["iphone", "ipad", "ipod"]
        guard let family = families.first(where: { lower.hasPrefix($0) }) else { return nil }

        let rest = lower.dropFirst(family.count)
        var digits = ""
        for char in rest {
            if char.isNumber {
                digits.append(char)
            } else {
                break
            }
        }
        guard let major = Int(digits) else { return nil }
        return (family: family, major: major)
    }
}

extension PACValidationDetector {
    func asSignals() -> [RiskSignal] {
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        guard assessment.score > 0 else { return [] }

        var signals: [RiskSignal] = []
        if assessment.pacReportedDisabled {
            signals.append(
                RiskSignal(
                    id: SignalID.pacDisabled,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 85,
                    evidence: [
                        "machine": snapshot.machine,
                        "arm64e": snapshot.arm64eFlag.map(String.init) ?? "unknown",
                        "pauth": snapshot.pAuthFlag.map(String.init) ?? "unknown",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 97
                )
            )
        }

        if assessment.invalidPointerCount >= 2 || !snapshot.unexpectedImages.isEmpty {
            signals.append(
                RiskSignal(
                    id: SignalID.pacPointerInvalid,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(50 + Double(assessment.invalidPointerCount) * 5, 78),
                    evidence: [
                        "invalid_pointers": snapshot.unreadablePointers.joined(separator: ","),
                        "unexpected_images": snapshot.unexpectedImages.joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 88
                )
            )
        } else if assessment.invalidPointerCount == 1 {
            signals.append(
                RiskSignal(
                    id: SignalID.pacPointerInvalid,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 12,
                    evidence: ["invalid_pointers": snapshot.unreadablePointers.joined(separator: ",")],
                    state: .soft(confidence: 0.55),
                    layer: 2,
                    weightHint: 36
                )
            )
        }

        return signals
    }
}
