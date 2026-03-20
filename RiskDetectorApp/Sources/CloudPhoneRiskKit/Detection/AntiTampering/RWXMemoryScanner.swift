import CRiskCore
import Darwin
import Foundation
import MachO

private let rwxProtection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
private let maxIterations = 500
private let anonymousUserTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]

struct RWXMemoryScanner: Detector {
    struct SuspiciousRegion {
        var address: UInt64
        var size: UInt64
        var protection: vm_prot_t
        var isAnonymous: Bool
        var isAnonymousRX: Bool
        var userTag: UInt32
        var shareMode: UInt32
        var inImage: Bool
        var isJITLike: Bool
    }

    struct ScanAssessment {
        var score: Double
        var methods: [String]
        var anonymousRWXCount: Int
        var anonymousRXCount: Int
        var jitLikeCount: Int
        var totalCount: Int
    }

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["rwx:unavailable_simulator"])
#else
        let assessment = assess(regions: scanForRWXRegions())
        if assessment.totalCount == 0 {
            return DetectorResult(score: 0, methods: ["rwx:clean"])
        }
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    func assess(regions: [SuspiciousRegion]) -> ScanAssessment {
        if regions.isEmpty {
            return ScanAssessment(
                score: 0,
                methods: [],
                anonymousRWXCount: 0,
                anonymousRXCount: 0,
                jitLikeCount: 0,
                totalCount: 0
            )
        }

        var score: Double = 0
        var methods: [String] = []

        let anonymousRWXCount = regions.filter { region in
            region.isAnonymous && (region.protection & rwxProtection) == rwxProtection
        }.count
        if anonymousRWXCount > 0 {
            score += 40
            methods.append("rwx:anonymous_rwx")
        }

        let anonymousRXCount = regions.filter(\.isAnonymousRX).count
        if anonymousRXCount > 0 {
            score += 40
            methods.append("rwx:anonymous_executable_memory")
        }

        let jitLikeCount = regions.filter(\.isJITLike).count
        if jitLikeCount > 0 {
            score += min(20 + Double(max(0, jitLikeCount - 1)) * 5, 30)
            methods.append("rwx:jit_rwx_stalker_like")
        }

        if anonymousRWXCount > 0 && jitLikeCount > 0 {
            score += 15
            methods.append("rwx:jit_rwx_coexistence")
        }

        let extraCount = regions.count - 1
        if extraCount > 0 {
            score += min(Double(extraCount) * 10, 40)
            if !methods.contains("rwx:anonymous_rwx") {
                methods.append("rwx:rwx_regions")
            }
        }

        return ScanAssessment(
            score: min(score, 95),
            methods: methods,
            anonymousRWXCount: anonymousRWXCount,
            anonymousRXCount: anonymousRXCount,
            jitLikeCount: jitLikeCount,
            totalCount: regions.count
        )
    }

    func scanForRWXRegions() -> [SuspiciousRegion] {
#if targetEnvironment(simulator)
        return []
#else
        var result: [SuspiciousRegion] = []
        var address: vm_address_t = 0
        var iteration = 0

        while iteration < maxIterations {
            var size: vm_size_t = 0
            var objectName: mach_port_t = 0

            var basicInfo = vm_region_basic_info_data_64_t()
            var basicCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
            )

            let basicResult = withUnsafeMutablePointer(to: &basicInfo) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                    vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &basicCount, &objectName)
                }
            }

            guard basicResult == KERN_SUCCESS else { break }

            let prot = basicInfo.protection
            let isRWX = (prot & rwxProtection) == rwxProtection
            let isRX = (prot & VM_PROT_EXECUTE) != 0 && (prot & VM_PROT_WRITE) == 0
            
            if isRWX || isRX {
                var isAnonymous = false
                var isAnonymousRX = false
                var userTag: UInt32 = 0
                var shareMode: UInt32 = 0
                var inImage = false
                
                var extInfo = vm_region_extended_info_data_t()
                var extCount = mach_msg_type_number_t(
                    MemoryLayout<vm_region_extended_info_data_t>.stride / MemoryLayout<natural_t>.stride
                )
                var extAddress = address
                var extSize: vm_size_t = 0
                
                let extResult = withUnsafeMutablePointer(to: &extInfo) { ptr in
                    ptr.withMemoryRebound(to: integer_t.self, capacity: Int(extCount)) { rebound in
                        vm_region_64(mach_task_self_, &extAddress, &extSize, VM_REGION_EXTENDED_INFO, rebound, &extCount, &objectName)
                    }
                }
                
                if extResult == KERN_SUCCESS {
                    userTag = UInt32(extInfo.user_tag)
                    shareMode = UInt32(extInfo.share_mode)
                    isAnonymous = anonymousUserTags.contains(userTag)
                    if isRX {
                        isAnonymous = anonymousUserTags.contains(userTag)
                    }
                    if isRX {
                        inImage = UnsafeRawPointer(bitPattern: UInt(extAddress)).map { cprisk_addr_in_any_image($0) != 0 } ?? false
                        let isPrivateOrEmpty = extInfo.share_mode == 3 || extInfo.share_mode == 0
                        if isPrivateOrEmpty && isAnonymous && !inImage {
                            isAnonymousRX = true
                        }
                    }
                }

                if isRWX || (isRX && isAnonymousRX) {
                    let isJITLike = isRX &&
                        isAnonymous &&
                        !inImage &&
                        (shareMode == 0 || shareMode == 3) &&
                        UInt64(size) <= 512 * 1024
                    result.append(SuspiciousRegion(
                        address: UInt64(address),
                        size: UInt64(size),
                        protection: prot,
                        isAnonymous: isAnonymous,
                        isAnonymousRX: isAnonymousRX,
                        userTag: userTag,
                        shareMode: shareMode,
                        inImage: inImage,
                        isJITLike: isJITLike
                    ))
                }
            }

            if size == 0 { break }
            address += size
            iteration += 1
        }

        return result
#endif
    }
}

extension RWXMemoryScanner {
    func asSignals() -> [RiskSignal] {
        asSignals(regions: scanForRWXRegions())
    }

    func asSignals(regions: [SuspiciousRegion]) -> [RiskSignal] {
        if regions.isEmpty {
            return []
        }

        let assessment = assess(regions: regions)
        var signals: [RiskSignal] = []
        let anonymousRegions = regions.filter(\.isAnonymous)
        if !anonymousRegions.isEmpty {
            signals.append(
                RiskSignal(
                    id: "rwx_anonymous",
                    category: "anti_tamper",
                    score: 40,
                    evidence: [
                        "count": "\(anonymousRegions.count)",
                        "addresses": anonymousRegions.prefix(5).map { String(format: "0x%llx", $0.address) }.joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 90
                )
            )
        }

        let anonymousRXRegions = regions.filter(\.isAnonymousRX)
        if !anonymousRXRegions.isEmpty {
            signals.append(
                RiskSignal(
                    id: "anonymous_executable_memory",
                    category: "anti_tamper",
                    score: 40,
                    evidence: [
                        "count": "\(anonymousRXRegions.count)",
                        "addresses": anonymousRXRegions.prefix(5).map { String(format: "0x%llx", $0.address) }.joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 95
                )
            )
        }

        let jitLikeRegions = regions.filter(\.isJITLike)
        if !jitLikeRegions.isEmpty {
            signals.append(
                RiskSignal(
                    id: SignalID.stalkerJitRWX,
                    category: "anti_tamper",
                    score: min(Double(assessment.jitLikeCount) * 12 + 12, 42),
                    evidence: [
                        "count": "\(jitLikeRegions.count)",
                        "addresses": jitLikeRegions.prefix(5).map { String(format: "0x%llx", $0.address) }.joined(separator: ","),
                        "share_modes": Set(jitLikeRegions.map { "\($0.shareMode)" }).sorted().joined(separator: ","),
                        "tags": Set(jitLikeRegions.map { "\($0.userTag)" }).sorted().joined(separator: ","),
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 96
                )
            )
        }

        if assessment.anonymousRWXCount > 0 && assessment.jitLikeCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.rwxJitCoexistence,
                    category: "anti_tamper",
                    score: 18,
                    evidence: [
                        "anonymous_rwx_count": "\(assessment.anonymousRWXCount)",
                        "jit_like_rx_count": "\(assessment.jitLikeCount)",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 90
                )
            )
        }

        if regions.count > 1 {
            signals.append(
                RiskSignal(
                    id: "rwx_multiple",
                    category: "anti_tamper",
                    score: 20,
                    evidence: ["count": "\(regions.count)"],
                    state: .soft(confidence: 0.7),
                    layer: 2,
                    weightHint: 60
                )
            )
        }

        return signals
    }
}
