import Darwin
import Foundation
import MachO

struct MemoryIntegrityChecker: Detector {
    let suspiciousImageTokens = [
        "frida",
        "gadget",
        "gum",
        "substrate",
        "substitute",
        "libhooker",
        "ellekit",
    ]

    let inlineHookWatchSymbols: [(name: String, score: Double)] = [
        ("malloc", 10),
        ("free", 8),
        ("open", 8),
        ("openat", 10),
        ("dlopen", 10),
        ("syscall", 12),
        ("__syscall", 12),
        ("objc_msgSend", 12),
    ]

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

        let inline = detectInlineHookTraces()
        score += inline.score
        methods.append(contentsOf: inline.methods)

        return DetectorResult(score: score, methods: methods)
#endif
    }

    func hasSuspiciousImageLoaded() -> Bool {
        let count = _dyld_image_count()
        for index in 0..<count {
            guard let imageName = _dyld_get_image_name(index) else { continue }
            let name = String(cString: imageName).lowercased()
            if suspiciousImageTokens.contains(where: { name.contains($0) }) {
                return true
            }
        }
        return false
    }

    func hasWritableExecutableRegion() -> Bool {
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

    func detectInlineHookTraces() -> DetectorResult {
        var total: Double = 0
        var methods: [String] = []

        for item in inlineHookWatchSymbols {
            guard let symbol = resolveSymbol(item.name) else { continue }
            let first = readInstruction(symbol)
            let second = readInstruction(symbol.advanced(by: MemoryLayout<UInt32>.size))
            if let first, isHookPattern(firstInstruction: first, secondInstruction: second) {
                total += item.score
                methods.append("memory_integrity:inline_hook:\(item.name)")
            } else if first == nil {
                let penalty = min(6, item.score * 0.5)
                total += penalty
                methods.append("memory_integrity:unreadable:\(item.name)")
            }
        }

        return DetectorResult(score: min(total, 40), methods: methods)
    }

    func resolveSymbol(_ name: String) -> UnsafeRawPointer? {
        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else {
            return nil
        }
        return UnsafeRawPointer(symbol)
    }

    func readInstruction(_ p: UnsafeRawPointer) -> UInt32? {
        guard isReadableAddress(p) else { return nil }
        return p.loadUnaligned(as: UInt32.self)
    }

    func isHookPattern(firstInstruction: UInt32, secondInstruction: UInt32?) -> Bool {
        if isUnconditionalBranch(firstInstruction) || isRegisterBranch(firstInstruction) {
            return true
        }
        if isLiteralLoad(firstInstruction), let secondInstruction {
            return isRegisterBranch(secondInstruction)
        }
        return false
    }

    func isUnconditionalBranch(_ ins: UInt32) -> Bool {
        let top6 = ins >> 26
        return top6 == 0b000101 || top6 == 0b100101
    }

    func isRegisterBranch(_ ins: UInt32) -> Bool {
        let mask: UInt32 = 0xFFFFFC1F
        return (ins & mask) == 0xD61F0000 || (ins & mask) == 0xD63F0000
    }

    func isLiteralLoad(_ ins: UInt32) -> Bool {
        (ins & 0xFF000000) == 0x58000000
    }

    func isReadableAddress(_ p: UnsafeRawPointer) -> Bool {
        var address = vm_address_t(UInt(bitPattern: p))
        var size: vm_size_t = 0
        var info = vm_region_basic_info_data_64_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
        )
        var objectName: mach_port_t = 0

        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
                vm_region_64(mach_task_self_, &address, &size, VM_REGION_BASIC_INFO_64, rebound, &count, &objectName)
            }
        }
        guard result == KERN_SUCCESS else { return false }
        return (info.protection & VM_PROT_READ) != 0
    }
}
