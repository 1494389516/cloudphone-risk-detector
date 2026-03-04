import Darwin
import Foundation

struct PrologueBranchDetector: Detector {
    let symbols: [(name: String, score: Double)] = [
        ("open", 10),
        ("openat", 10),
        ("fopen", 8),
        ("stat", 10),
        ("stat64", 10),
        ("lstat", 10),
        ("lstat64", 10),
        ("statfs", 10),
        ("access", 10),
        ("faccessat", 10),
        ("dlopen", 12),
        ("sysctl", 10),
        ("syscall", 15),
        ("__syscall", 15),
        ("getenv", 8),
        ("fork", 10),
        ("posix_spawn", 10),
        ("objc_msgSend", 12),
        ("vm_protect", 8),
    ]

    func detect() -> DetectorResult {
        #if arch(arm64) || arch(arm64e)
        var score: Double = 0
        var methods: [String] = []

        for item in symbols {
            guard let addr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), item.name) else { continue } // RTLD_DEFAULT
            let p = UnsafeRawPointer(addr)
            guard let first = readInstruction(p) else {
                // 对关键符号出现不可读页给出告警，避免 read 失败被攻击者用作“静默绕过”。
                let fallbackScore = min(6, item.score * 0.6)
                score += fallbackScore
                methods.append("prologue_unreadable:\(item.name)")
                Logger.log("jailbreak.prologue.unreadable: \(item.name) (+\(fallbackScore))")
                continue
            }
            let second = readInstruction(p.advanced(by: MemoryLayout<UInt32>.size))
            if isHooked(firstInstruction: first, secondInstruction: second) {
                score += item.score
                methods.append("prologue_branch:\(item.name)")
                Logger.log("jailbreak.prologue.hit: \(item.name) inst=0x\(String(first, radix: 16)) (+\(item.score))")
            }
        }

        return DetectorResult(score: score, methods: methods)
        #else
        return .empty
        #endif
    }

    #if arch(arm64) || arch(arm64e)
    func readInstruction(_ p: UnsafeRawPointer) -> UInt32? {
        guard isReadableAddress(p) else { return nil }
        return p.loadUnaligned(as: UInt32.self)
    }

    func isHooked(firstInstruction: UInt32, secondInstruction: UInt32?) -> Bool {
        if isUnconditionalBranch(firstInstruction) || isRegisterBranch(firstInstruction) {
            return true
        }
        // 覆盖常见 Frida trampoline：LDR literal + BR/BLR reg + literal target
        if isLiteralLoad(firstInstruction), let secondInstruction {
            return isRegisterBranch(secondInstruction)
        }
        return false
    }

    func isUnconditionalBranch(_ ins: UInt32) -> Bool {
        // A64 encoding:
        // B   imm26: op = 0b000101 (bits[31:26] == 0b000101)
        // BL  imm26: op = 0b100101 (bits[31:26] == 0b100101)
        let top6 = ins >> 26
        return top6 == 0b000101 || top6 == 0b100101
    }

    func isRegisterBranch(_ ins: UInt32) -> Bool {
        // BR  Xn: 1101011000011111000000nnnnn00000
        // BLR Xn: 1101011000111111000000nnnnn00000
        let mask: UInt32 = 0xFFFFFC1F
        return (ins & mask) == 0xD61F0000 || (ins & mask) == 0xD63F0000
    }

    func isLiteralLoad(_ ins: UInt32) -> Bool {
        // LDR (literal, 64-bit) 形态：0x58xxxxxx
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
    #endif
}
