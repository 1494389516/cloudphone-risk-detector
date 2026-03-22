import CRiskCore
import Darwin
import Foundation

private let lldbJitMaxIterations = 600
private let lldbJitAnonymousTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]

/// Detects LLDB/JIT-like anonymous *small* RWX pages.
///
/// Characteristic pattern:
/// - anonymous mappings
/// - rwx permissions
/// - small chunks (typically 4KB~256KB)
/// - outside loaded images
struct LLDBJITDetector: Detector {
    struct RegionObservation {
        let address: UInt64
        let size: UInt64
        let userTag: UInt32
        let shareMode: UInt32
        let inImage: Bool
    }

    struct Assessment {
        let score: Double
        let methods: [String]
        let suspiciousRegionCount: Int
        let totalSuspiciousSize: UInt64
    }

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["lldb_jit:unavailable_simulator"])
#else
        let observations = scanSmallAnonymousRWX()
        let assessment = assess(observations: observations)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    func assess(observations: [RegionObservation]) -> Assessment {
        let count = observations.count
        let totalSize = observations.reduce(UInt64(0)) { $0 &+ $1.size }

        guard count > 0 else {
            return Assessment(
                score: 0,
                methods: ["lldb_jit:clean"],
                suspiciousRegionCount: 0,
                totalSuspiciousSize: 0
            )
        }

        var score: Double = 0
        var methods: [String] = []

        if count >= 3 {
            score += min(30 + Double(count - 3) * 7, 60)
            methods.append("lldb_jit:small_rwx_count:\(count)")
        } else {
            score += 8
            methods.append("lldb_jit:small_rwx_hint:\(count)")
        }

        if totalSize >= 512 * 1024 {
            score += 10
            methods.append("lldb_jit:total_size_kb:\(totalSize / 1024)")
        }

        let tagSet = Set(observations.map(\.userTag))
        if tagSet.count >= 3 {
            score += 6
            methods.append("lldb_jit:tag_diversity:\(tagSet.count)")
        }

        return Assessment(
            score: min(score, 72),
            methods: methods,
            suspiciousRegionCount: count,
            totalSuspiciousSize: totalSize
        )
    }

    private func scanSmallAnonymousRWX() -> [RegionObservation] {
        var observations: [RegionObservation] = []
        var address: vm_address_t = 0
        var iteration = 0

        while iteration < lldbJitMaxIterations {
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

            let rwx = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE
            if (basicInfo.protection & rwx) == rwx, size >= 4 * 1024, size <= 256 * 1024 {
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
                    let isAnonymous = shareMode == 0 || shareMode == 3 || lldbJitAnonymousTags.contains(userTag)
                    let pointer = UnsafeRawPointer(bitPattern: UInt(address))
                    let inImage = pointer.map { cprisk_addr_in_any_image($0) != 0 } ?? false

                    if isAnonymous && !inImage {
                        observations.append(
                            RegionObservation(
                                address: UInt64(address),
                                size: UInt64(size),
                                userTag: userTag,
                                shareMode: shareMode,
                                inImage: false
                            )
                        )
                    }
                }
            }

            let next = UInt64(address) &+ UInt64(size)
            if next <= UInt64(address) { break }
            address = vm_address_t(next)
            iteration += 1
        }

        return observations
    }
}

extension LLDBJITDetector {
    func asSignals() -> [RiskSignal] {
        let observations = scanSmallAnonymousRWX()
        let assessment = assess(observations: observations)
        guard assessment.score > 0 else { return [] }

        let addresses = observations
            .prefix(8)
            .map { String(format: "0x%llx", $0.address) }
            .joined(separator: ",")

        if assessment.suspiciousRegionCount >= 3 {
            return [
                RiskSignal(
                    id: SignalID.lldbJitSmallRWX,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(35 + Double(assessment.suspiciousRegionCount) * 5, 62),
                    evidence: [
                        "region_count": "\(assessment.suspiciousRegionCount)",
                        "total_size_kb": "\(assessment.totalSuspiciousSize / 1024)",
                        "addresses": addresses,
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 84
                ),
            ]
        }

        return [
            RiskSignal(
                id: SignalID.lldbJitSmallRWX,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 10,
                evidence: [
                    "region_count": "\(assessment.suspiciousRegionCount)",
                    "total_size_kb": "\(assessment.totalSuspiciousSize / 1024)",
                    "addresses": addresses,
                ],
                state: .soft(confidence: 0.58),
                layer: 3,
                weightHint: 34
            ),
        ]
    }
}
