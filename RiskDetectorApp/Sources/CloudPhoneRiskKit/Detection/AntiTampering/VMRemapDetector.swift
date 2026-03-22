import CRiskCore
import Darwin
import Foundation

private let vmRemapMaxIterations = 700
private let vmRemapAnonymousTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]

/// Detects suspicious vm_remap-like artifacts:
/// 1) shared anonymous executable mappings outside loaded images
/// 2) anonymous executable mappings that overlap loaded images (alias/remap symptom)
struct VMRemapDetector: Detector {
    private enum Keys {
        static let prefix = ObfuscatedConstants.keywordVMRemap
    }

    struct RegionFinding {
        let address: UInt64
        let size: UInt64
        let protection: vm_prot_t
        let userTag: UInt32
        let shareMode: UInt32
        let isAnonymous: Bool
        let inImage: Bool
    }

    struct Assessment {
        let score: Double
        let methods: [String]
        let sharedAnonymousExecutableCount: Int
        let imageAnonymousAliasCount: Int
    }

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["\(Keys.prefix):unavailable_simulator"])
#else
        let findings = collectFindings()
        let assessment = assess(findings: findings)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    func assess(findings: [RegionFinding]) -> Assessment {
        let sharedAnonymousExecutable = findings.filter {
            isExecutable($0.protection) && $0.isAnonymous && isSharedMode($0.shareMode) && !$0.inImage
        }
        let imageAnonymousAlias = findings.filter {
            isExecutable($0.protection) && $0.isAnonymous && $0.inImage
        }

        let sharedCount = sharedAnonymousExecutable.count
        let aliasCount = imageAnonymousAlias.count

        guard sharedCount > 0 || aliasCount > 0 else {
            return Assessment(
                score: 0,
                methods: ["\(Keys.prefix):clean"],
                sharedAnonymousExecutableCount: 0,
                imageAnonymousAliasCount: 0
            )
        }

        var score: Double = 0
        var methods: [String] = []

        if sharedCount >= 2 {
            score += min(35 + Double(sharedCount - 2) * 10, 60)
            methods.append("\(Keys.prefix):shared_anon_exec:\(sharedCount)")
        } else if sharedCount == 1 {
            score += 12
            methods.append("\(Keys.prefix):shared_anon_exec_hint:1")
        }

        if aliasCount > 0 {
            score += min(30 + Double(max(0, aliasCount - 1)) * 12, 55)
            methods.append("\(Keys.prefix):image_alias:\(aliasCount)")
        }

        if sharedCount > 0 && aliasCount > 0 {
            score += 15
            methods.append("\(Keys.prefix):coexistence")
        }

        return Assessment(
            score: min(score, 95),
            methods: methods,
            sharedAnonymousExecutableCount: sharedCount,
            imageAnonymousAliasCount: aliasCount
        )
    }

    private func collectFindings() -> [RegionFinding] {
        var findings: [RegionFinding] = []
        var address: vm_address_t = 0
        var iteration = 0

        while iteration < vmRemapMaxIterations {
            var size: vm_size_t = 0
            var objectName: mach_port_t = 0

            var basicInfo = vm_region_basic_info_data_64_t()
            var basicCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
            )

            let basicResult = withUnsafeMutablePointer(to: &basicInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                    vm_region_64(
                        mach_task_self_,
                        &address,
                        &size,
                        VM_REGION_BASIC_INFO_64,
                        rebound,
                        &basicCount,
                        &objectName
                    )
                }
            }
            guard basicResult == KERN_SUCCESS, size > 0 else { break }

            var extInfo = vm_region_extended_info_data_t()
            var extCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_extended_info_data_t>.stride / MemoryLayout<natural_t>.stride
            )
            var extAddress = address
            var extSize: vm_size_t = 0
            let extResult = withUnsafeMutablePointer(to: &extInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(extCount)) { rebound in
                    vm_region_64(
                        mach_task_self_,
                        &extAddress,
                        &extSize,
                        VM_REGION_EXTENDED_INFO,
                        rebound,
                        &extCount,
                        &objectName
                    )
                }
            }

            if extResult == KERN_SUCCESS {
                let userTag = UInt32(extInfo.user_tag)
                let shareMode = UInt32(extInfo.share_mode)
                let isAnonymous = isAnonymousRegion(shareMode: shareMode, userTag: userTag)
                let rawPtr = UnsafeRawPointer(bitPattern: UInt(address))
                let inImage = rawPtr.map { cprisk_addr_in_any_image($0) != 0 } ?? false

                if size >= 16 * 1024 {
                    findings.append(
                        RegionFinding(
                            address: UInt64(address),
                            size: UInt64(size),
                            protection: basicInfo.protection,
                            userTag: userTag,
                            shareMode: shareMode,
                            isAnonymous: isAnonymous,
                            inImage: inImage
                        )
                    )
                }
            }

            let next = UInt64(address) &+ UInt64(size)
            if next <= UInt64(address) { break }
            address = vm_address_t(next)
            iteration += 1
        }

        return findings
    }

    private func isExecutable(_ protection: vm_prot_t) -> Bool {
        (protection & VM_PROT_EXECUTE) != 0
    }

    private func isAnonymousRegion(shareMode: UInt32, userTag: UInt32) -> Bool {
        shareMode == 0 || shareMode == 3 || vmRemapAnonymousTags.contains(userTag)
    }

    private func isSharedMode(_ shareMode: UInt32) -> Bool {
        shareMode != 0 && shareMode != 3
    }
}

extension VMRemapDetector {
    func asSignals() -> [RiskSignal] {
        let findings = collectFindings()
        let assessment = assess(findings: findings)
        guard assessment.score > 0 else { return [] }

        var signals: [RiskSignal] = []
        if assessment.sharedAnonymousExecutableCount >= 2 {
            signals.append(
                RiskSignal(
                    id: SignalID.vmRemapSharedAnonymous,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(55 + Double(assessment.sharedAnonymousExecutableCount) * 4, 80),
                    evidence: [
                        "count": "\(assessment.sharedAnonymousExecutableCount)",
                        "detail": assessment.methods.joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 90
                )
            )
        }

        if assessment.imageAnonymousAliasCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.vmRemapImageAlias,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(48 + Double(assessment.imageAnonymousAliasCount) * 6, 78),
                    evidence: [
                        "count": "\(assessment.imageAnonymousAliasCount)",
                        "detail": assessment.methods.joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 88
                )
            )
        }

        if signals.isEmpty {
            signals.append(
                RiskSignal(
                    id: SignalID.vmRemapSharedAnonymous,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 16,
                    evidence: ["detail": assessment.methods.joined(separator: ",")],
                    state: .soft(confidence: 0.55),
                    layer: 2,
                    weightHint: 42
                )
            )
        }
        return signals
    }
}
