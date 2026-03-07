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
    }

    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["rwx:unavailable_simulator"])
#else
        let regions = scanForRWXRegions()
        if regions.isEmpty {
            return DetectorResult(score: 0, methods: ["rwx:clean"])
        }

        var score: Double = 0
        var methods: [String] = []
        let anonymousCount = regions.filter(\.isAnonymous).count
        if anonymousCount > 0 {
            score += 40
            methods.append("rwx:anonymous_rwx")
        }
        let anonymousRXCount = regions.filter(\.isAnonymousRX).count
        if anonymousRXCount > 0 {
            score += 40
            methods.append("rwx:anonymous_executable_memory")
        }
        let extraCount = regions.count - 1
        if extraCount > 0 {
            score += min(Double(extraCount) * 10, 40)
            if !methods.contains("rwx:anonymous_rwx") {
                methods.append("rwx:rwx_regions")
            }
        }
        return DetectorResult(score: min(score, 80), methods: methods)
#endif
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
                    if isRWX {
                        isAnonymous = anonymousUserTags.contains(UInt32(extInfo.user_tag))
                    }
                    if isRX {
                        // 检查 share_mode (SM_PRIVATE 为 3，SM_EMPTY 为 0)
                        if extInfo.share_mode == 3 || extInfo.share_mode == 0 {
                            var info = Dl_info()
                            let found = dladdr(UnsafeRawPointer(bitPattern: UInt(extAddress)), &info)
                            if found == 0 || info.dli_fname == nil {
                                isAnonymousRX = true
                            }
                        }
                    }
                }

                if isRWX || (isRX && isAnonymousRX) {
                    result.append(SuspiciousRegion(
                        address: UInt64(address),
                        size: UInt64(size),
                        protection: prot,
                        isAnonymous: isAnonymous,
                        isAnonymousRX: isAnonymousRX
                    ))
                }
            }

            address += size
            if size == 0 { break }
            iteration += 1
        }

        return result
#endif
    }
}

extension RWXMemoryScanner {
    func asSignals() -> [RiskSignal] {
        let regions = scanForRWXRegions()
        if regions.isEmpty {
            return []
        }

        var signals: [RiskSignal] = []
        let anonymousRegions = regions.filter(\.isAnonymous)
        if !anonymousRegions.isEmpty {
            signals.append(
                RiskSignal(
                    id: "rwx_anonymous",
                    category: "anti_tamper",
                    score: 0,
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

        if regions.count > 1 {
            signals.append(
                RiskSignal(
                    id: "rwx_multiple",
                    category: "anti_tamper",
                    score: 0,
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
