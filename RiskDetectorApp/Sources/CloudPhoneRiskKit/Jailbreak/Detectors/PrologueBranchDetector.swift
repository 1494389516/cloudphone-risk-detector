import Darwin
import Foundation

struct PrologueBranchDetector: Detector {
    private let symbols: [(name: String, score: Double)] = [
        ("open", 10),
        ("stat", 10),
        ("lstat", 10),
        ("access", 10),
        ("sysctl", 10),
        ("getenv", 8),
        ("objc_msgSend", 12),
    ]

    func detect() -> DetectorResult {
        #if arch(arm64) || arch(arm64e)
        var score: Double = 0
        var methods: [String] = []

        for item in symbols {
            guard let addr = dlsym(UnsafeMutableRawPointer(bitPattern: -2), item.name) else { continue } // RTLD_DEFAULT
            let p = UnsafeRawPointer(addr)
            guard let first: UInt32 = readInstruction(p) else { continue }
            if isUnconditionalBranch(first) {
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
    private func readInstruction(_ p: UnsafeRawPointer) -> UInt32? {
        // Best-effort: ignore faults; if memory unreadable, just skip.
        p.loadUnaligned(as: UInt32.self)
    }

    private func isUnconditionalBranch(_ ins: UInt32) -> Bool {
        // A64 encoding:
        // B   imm26: op = 0b000101 (bits[31:26] == 0b000101)
        // BL  imm26: op = 0b100101 (bits[31:26] == 0b100101)
        let top6 = ins >> 26
        return top6 == 0b000101 || top6 == 0b100101
    }
    #endif
}

