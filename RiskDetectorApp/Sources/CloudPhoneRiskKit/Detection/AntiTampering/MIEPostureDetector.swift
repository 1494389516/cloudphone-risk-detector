import CRiskCore
import Foundation

/// 基于 `sysctl hw.optional.arm.*` 与 CRiskCore 本地快照的内存完整性 / MTE 姿态评估。
///
/// 设计约束：
/// - 仅使用公开 `sysctl` 与 SDK 自身快照，不读取用户内容。
/// - 对硬件支持判断保持保守: 缺失、不可读或全零都不会被解释为“具备 MTE/EMTE”。
/// - 文档口径按“A17/A17 Pro 及后续较新产品线可能具备，最终以系统实际导出能力为准”表述。
struct MIEPostureDetector: Detector, Sendable {

    enum Level: String, Sendable, CaseIterable {
        case none
        case pacOnly
        case miePartial
        case mieFull
    }

    struct Assessment: Sendable {
        let level: Level
        let machine: String
        let pacCapable: Bool
        let likelyNewHardware: Bool
        let sysctlFeatMTE: Int?
        let sysctlFeatMTE2: Int?
        let sysctlFeatMTE3: Int?
        let sysctlFeatMTE4: Int?
        let sysctlFeatMTEAsync: Int?
        let sysctlFeatMTEStoreOnly: Int?
        let sysctlPAuth: Int?
        let sysctlArm64e: Int?
        let nativeCanaryInstalled: Bool
        let nativeCanaryViolationCount: UInt32
        let nativeSelfTestRC: Int32
        let downgradeReason: String?
    }

    func detect() throws -> DetectorResult {
        let assessment = Self.evaluate()
        let methods = [
            "mie:level:\(assessment.level.rawValue)",
            "mie:mte:\(Self.intEvidence(assessment.sysctlFeatMTE))",
            "mie:mte2:\(Self.intEvidence(assessment.sysctlFeatMTE2))",
            "mie:canary:\(assessment.nativeCanaryInstalled ? "installed" : "inactive")",
        ]
        let score = asSignals().map(\.score).reduce(0, max)
        return DetectorResult(score: score, methods: methods)
    }

    static func evaluate() -> Assessment {
#if targetEnvironment(simulator)
        return Assessment(
            level: .none,
            machine: Sysctl.string("hw.machine") ?? "",
            pacCapable: false,
            likelyNewHardware: false,
            sysctlFeatMTE: nil,
            sysctlFeatMTE2: nil,
            sysctlFeatMTE3: nil,
            sysctlFeatMTE4: nil,
            sysctlFeatMTEAsync: nil,
            sysctlFeatMTEStoreOnly: nil,
            sysctlPAuth: nil,
            sysctlArm64e: nil,
            nativeCanaryInstalled: false,
            nativeCanaryViolationCount: 0,
            nativeSelfTestRC: 0,
            downgradeReason: "simulator"
        )
#elseif !(arch(arm64) || arch(arm64e))
        return Assessment(
            level: .none,
            machine: Sysctl.string("hw.machine") ?? "",
            pacCapable: false,
            likelyNewHardware: false,
            sysctlFeatMTE: nil,
            sysctlFeatMTE2: nil,
            sysctlFeatMTE3: nil,
            sysctlFeatMTE4: nil,
            sysctlFeatMTEAsync: nil,
            sysctlFeatMTEStoreOnly: nil,
            sysctlPAuth: nil,
            sysctlArm64e: nil,
            nativeCanaryInstalled: false,
            nativeCanaryViolationCount: 0,
            nativeSelfTestRC: 0,
            downgradeReason: "arch"
        )
#else
        let machine = (Sysctl.string("hw.machine") ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let pacCapable = isA12OrLater(machine: machine)
        let likelyNewHardware = isA17OrLater(machine: machine)
        let pAuth = Sysctl.int("hw.optional.arm.FEAT_PAuth")
        let arm64e = Sysctl.int("hw.optional.arm64e")

        let mte = Sysctl.int("hw.optional.arm.FEAT_MTE")
        let mte2 = Sysctl.int("hw.optional.arm.FEAT_MTE2")
        let mte3 = Sysctl.int("hw.optional.arm.FEAT_MTE3")
        let mte4 = Sysctl.int("hw.optional.arm.FEAT_MTE4")
        let mteAsync = Sysctl.int("hw.optional.arm.FEAT_MTE_ASYNC")
        let mteStoreOnly = Sysctl.int("hw.optional.arm.FEAT_MTE_STORE_ONLY")

        var nativeSnapshot = cprisk_mte_guard_snapshot_t()
        let hasNativeSnapshot = cprisk_mte_guard_snapshot(&nativeSnapshot) == 0

        let level: Level
        var downgrade: String?

        if !pacCapable {
            level = .none
            downgrade = "below_pac_representative_generation"
        } else if mte3 == nil && mte4 == nil && mte == nil && mte2 == nil {
            level = .pacOnly
            downgrade = "mte_sysctl_unreadable"
        } else {
            let strong = (mte3 ?? 0) > 0 || (mte4 ?? 0) > 0
            let partial = (mte ?? 0) > 0 || (mte2 ?? 0) > 0

            if strong {
                level = .mieFull
            } else if partial {
                level = .miePartial
            } else {
                level = .pacOnly
                downgrade = [mte, mte2, mte3, mte4].allSatisfy({ $0 != nil })
                    ? "mte_family_sysctl_all_zero"
                    : "partial_mte_sysctl_missing"
            }
        }

        return Assessment(
            level: level,
            machine: machine,
            pacCapable: pacCapable,
            likelyNewHardware: likelyNewHardware,
            sysctlFeatMTE: mte,
            sysctlFeatMTE2: mte2,
            sysctlFeatMTE3: mte3,
            sysctlFeatMTE4: mte4,
            sysctlFeatMTEAsync: mteAsync,
            sysctlFeatMTEStoreOnly: mteStoreOnly,
            sysctlPAuth: pAuth,
            sysctlArm64e: arm64e,
            nativeCanaryInstalled: hasNativeSnapshot ? nativeSnapshot.canary_installed != 0 : false,
            nativeCanaryViolationCount: hasNativeSnapshot ? nativeSnapshot.canary_violation_count : 0,
            nativeSelfTestRC: hasNativeSnapshot ? nativeSnapshot.last_self_test_rc : 0,
            downgradeReason: downgrade
        )
#endif
    }

    func asSignals() -> [RiskSignal] {
        let a = Self.evaluate()
        var signals: [RiskSignal] = []

        var baseEvidence: [String: String] = [
            "mie_level": a.level.rawValue,
            "pac_capable": a.pacCapable ? "1" : "0",
            "likely_new_hardware": a.likelyNewHardware ? "1" : "0",
            "hw_machine": a.machine,
            "sysctl_mte": Self.intEvidence(a.sysctlFeatMTE),
            "sysctl_mte2": Self.intEvidence(a.sysctlFeatMTE2),
            "sysctl_mte3": Self.intEvidence(a.sysctlFeatMTE3),
            "sysctl_mte4": Self.intEvidence(a.sysctlFeatMTE4),
            "sysctl_mte_async": Self.intEvidence(a.sysctlFeatMTEAsync),
            "sysctl_mte_store_only": Self.intEvidence(a.sysctlFeatMTEStoreOnly),
            "sysctl_pauth": Self.intEvidence(a.sysctlPAuth),
            "sysctl_arm64e": Self.intEvidence(a.sysctlArm64e),
            "native_canary_installed": a.nativeCanaryInstalled ? "1" : "0",
            "native_canary_violation_count": "\(a.nativeCanaryViolationCount)",
            "native_self_test_rc": "\(a.nativeSelfTestRC)",
            "hardware_scope_note": "a17_or_newer_may_expose_more_mte_bits",
            "posture_note": "sysctl_and_local_runtime_only",
        ]
        if let downgradeReason = a.downgradeReason {
            baseEvidence["downgrade_reason"] = downgradeReason
        }

        signals.append(
            RiskSignal(
                id: SignalID.miePosture,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 0,
                evidence: baseEvidence,
                state: .hard(detected: false),
                layer: 3,
                weightHint: 0
            )
        )

        if let contradiction = Self.mteSysctlContradiction(assessment: a) {
            signals.append(
                RiskSignal(
                    id: SignalID.mteUnavailableOnCapable,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 22,
                    evidence: contradiction,
                    state: .soft(confidence: 0.42),
                    layer: 3,
                    weightHint: 28
                )
            )
        }

        if (a.level == .miePartial || a.level == .mieFull) && a.nativeSelfTestRC < 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.mteInactiveForProcess,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 28,
                    evidence: [
                        "mie_level": a.level.rawValue,
                        "native_self_test_rc": "\(a.nativeSelfTestRC)",
                        "note": "native_mte_runtime_self_test_failed",
                    ],
                    state: .soft(confidence: 0.62),
                    layer: 2,
                    weightHint: 68
                )
            )
        }

        if a.nativeCanaryViolationCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.mteCanaryTampered,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 48,
                    evidence: [
                        "mie_level": a.level.rawValue,
                        "violation_count": "\(a.nativeCanaryViolationCount)",
                        "native_canary_installed": a.nativeCanaryInstalled ? "1" : "0",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 84
                )
            )
        }

        return signals
    }

    private static func mteSysctlContradiction(assessment a: Assessment) -> [String: String]? {
        guard a.pacCapable, a.likelyNewHardware else { return nil }
        let mte = a.sysctlFeatMTE
        let mte2 = a.sysctlFeatMTE2
        let mte4 = a.sysctlFeatMTE4
        if let mte, mte == 0, let mte4, mte4 != 0, (mte2 ?? 0) == 0 {
            return [
                "case": "mte0_emte4_nonzero",
                "sysctl_mte": "0",
                "sysctl_mte4": "\(mte4)",
                "detail": "narrow_sysctl_shape_anomaly",
                "hardware_scope_note": "newer_a17_class_or_later_only",
            ]
        }
        return nil
    }

    private static func intEvidence(_ value: Int?) -> String {
        if let value {
            return "\(value)"
        }
        return "unavailable"
    }

    private static func isA12OrLater(machine: String) -> Bool {
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

    private static func isA17OrLater(machine: String) -> Bool {
        guard let parsed = parseMachine(machine) else { return false }
        switch parsed.family {
        case "iphone":
            return parsed.major >= 16
        case "ipad":
            return parsed.major >= 14
        default:
            return false
        }
    }

    private static func parseMachine(_ machine: String) -> (family: String, major: Int)? {
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
