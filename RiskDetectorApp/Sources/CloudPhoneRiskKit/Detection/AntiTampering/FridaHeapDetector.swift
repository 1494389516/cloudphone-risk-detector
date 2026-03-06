import Darwin
import Foundation
import MachO

private let maxIterations = 500
private let anonymousUserTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]

struct FridaHeapDetector: Detector {

    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["frida:unavailable_simulator"])
#else
        let heapResult = detectJSEngineHeap()
        let stalkerResult = detectStalkerJITPages()

        var score = heapResult.score + stalkerResult.score
        var methods = heapResult.methods + stalkerResult.methods

        if methods.isEmpty {
            return DetectorResult(score: 0, methods: ["frida:clean"])
        }

        return DetectorResult(score: min(score, 80), methods: methods)
#endif
    }

    // MARK: - V8/QuickJS Heap Detection

    /// Detects Frida's embedded JS engine (V8/QuickJS) memory footprint.
    /// Large anonymous rw- regions not in any loaded image are suspicious.
    private func detectJSEngineHeap() -> (score: Double, methods: [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        var address: vm_address_t = 0
        var largeAnonRWCount = 0
        var totalAnonRWSize: UInt64 = 0
        let threshold: UInt64 = 1024 * 1024  // 1MB minimum per region
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
            let isRW = (prot & VM_PROT_READ) != 0 &&
                      (prot & VM_PROT_WRITE) != 0 &&
                      (prot & VM_PROT_EXECUTE) == 0

            if isRW && UInt64(size) >= threshold {
                var isAnonymous = false
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
                    isAnonymous = anonymousUserTags.contains(UInt32(extInfo.user_tag))
                }

                if isAnonymous {
                    var dlInfo = Dl_info()
                    let inImage = dladdr(UnsafeRawPointer(bitPattern: UInt(address)), &dlInfo) != 0
                    if !inImage {
                        largeAnonRWCount += 1
                        totalAnonRWSize += UInt64(size)
                    }
                }
            }

            address += size
            if size == 0 { break }
            iteration += 1
        }

        var score: Double = 0
        var methods: [String] = []

        // V8 typically allocates 20–100MB of anonymous rw- memory
        if totalAnonRWSize > 30 * 1024 * 1024 {
            score += 20
            methods.append("frida_heap:v8_heap_\(totalAnonRWSize / (1024 * 1024))MB")
        } else if totalAnonRWSize > 15 * 1024 * 1024 && largeAnonRWCount > 5 {
            score += 12
            methods.append("frida_heap:suspicious_anon_\(largeAnonRWCount)_regions")
        }

        return (score, methods)
#endif
    }

    // MARK: - Stalker JIT Code Page Detection

    /// Detects Frida Stalker's JIT-compiled code pages.
    /// Anonymous r-x regions not in any dylib are Stalker's instrumented blocks.
    private func detectStalkerJITPages() -> (score: Double, methods: [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        var address: vm_address_t = 0
        var jitPageCount = 0
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
            let isRX = (prot & VM_PROT_READ) != 0 &&
                      (prot & VM_PROT_EXECUTE) != 0 &&
                      (prot & VM_PROT_WRITE) == 0

            if isRX {
                var isAnonymous = false
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
                    isAnonymous = anonymousUserTags.contains(UInt32(extInfo.user_tag))
                }

                if isAnonymous {
                    var dlInfo = Dl_info()
                    let inImage = dladdr(UnsafeRawPointer(bitPattern: UInt(address)), &dlInfo) != 0
                    if !inImage {
                        jitPageCount += 1
                    }
                }
            }

            address += size
            if size == 0 { break }
            iteration += 1
        }

        if jitPageCount > 3 {
            return (15, ["frida_stalker:jit_pages_\(jitPageCount)"])
        } else if jitPageCount > 0 {
            return (8, ["frida_stalker:jit_pages_\(jitPageCount)"])
        }

        return (0, [])
#endif
    }
}

// MARK: - Signal Conversion

extension FridaHeapDetector {
    func asSignals() -> [RiskSignal] {
        let result = detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let heapMethods = result.methods.filter { $0.hasPrefix("frida_heap") }
        if !heapMethods.isEmpty {
            signals.append(RiskSignal(
                id: "frida_js_engine_heap",
                category: "anti_tamper",
                score: min(Double(heapMethods.count) * 15, 25),
                evidence: ["detail": heapMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ))
        }

        let stalkerMethods = result.methods.filter { $0.hasPrefix("frida_stalker") }
        if !stalkerMethods.isEmpty {
            signals.append(RiskSignal(
                id: "frida_stalker_jit",
                category: "anti_tamper",
                score: 15,
                evidence: ["detail": stalkerMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 78
            ))
        }

        return signals
    }
}
