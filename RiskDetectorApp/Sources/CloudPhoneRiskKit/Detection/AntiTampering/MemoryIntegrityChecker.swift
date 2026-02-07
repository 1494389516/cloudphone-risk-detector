import Darwin
import Foundation
import MachO

struct MemoryIntegrityChecker: Detector {
    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        if hasSuspiciousImageLoaded() {
            score += 20
            methods.append("memory_integrity:suspicious_image")
        }

        if hasWritableExecutableRegion() {
            score += 25
            methods.append("memory_integrity:w_x_region")
        }

        if hasHookLikeBranchOnFunction("malloc") {
            score += 18
            methods.append("memory_integrity:inline_hook:malloc")
        }

        return DetectorResult(score: score, methods: methods)
#endif
    }

    private func hasSuspiciousImageLoaded() -> Bool {
        let count = _dyld_image_count()
        for index in 0..<count {
            guard let imageName = _dyld_get_image_name(index) else { continue }
            let name = String(cString: imageName).lowercased()
            if name.contains("frida") || name.contains("substrate") || name.contains("libhooker") {
                return true
            }
        }
        return false
    }

    private func hasWritableExecutableRegion() -> Bool {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "malloc") else {
            return false
        }

        var address = vm_address_t(UInt(bitPattern: symbol))
        var size: vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var count = mach_msg_type_number_t(MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride)
        var objectName: mach_port_t = 0

        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &count, &objectName)
            }
        }

        guard result == KERN_SUCCESS else { return false }
        let writable = (info.protection & VM_PROT_WRITE) != 0
        let executable = (info.protection & VM_PROT_EXECUTE) != 0
        return writable && executable
    }

    private func hasHookLikeBranchOnFunction(_ name: String) -> Bool {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else {
            return false
        }
        let firstInstruction = symbol.assumingMemoryBound(to: UInt32.self).pointee
        let isBranch = (firstInstruction & 0xFC000000) == 0x14000000 ||
            (firstInstruction & 0xFC000000) == 0x94000000
        return isBranch
    }
}
