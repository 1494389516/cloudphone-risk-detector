import Darwin
import Foundation

struct AntiTamperingDetector: Detector {
    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        if isTraced() {
            score += 30
            methods.append("anti_tampering:p_traced")
        }

        if hasSuspiciousParent() {
            score += 20
            methods.append("anti_tampering:suspicious_parent")
        }

        if hasDebugEnvironment() {
            score += 15
            methods.append("anti_tampering:debug_env")
        }

        if hasTimingAnomaly() {
            score += 12
            methods.append("anti_tampering:timing")
        }

        return DetectorResult(score: score, methods: methods)
#endif
    }

    private func isTraced() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.size
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return false }
        return (info.kp_proc.p_flag & tracedFlag) != 0
    }

    private func hasSuspiciousParent() -> Bool {
        let ppid = getppid()
        guard ppid > 1 else { return true }
        guard let parentPath = parentProcessPath(ppid)?.lowercased() else { return false }
        let suspicious = ["lldb", "gdb", "debugserver", "frida", "hopper", "ida"]
        return suspicious.contains { parentPath.contains($0) }
    }

    private func parentProcessPath(_ pid: pid_t) -> String? {
#if os(macOS)
        var pathBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        let result = proc_pidpath(pid, &pathBuffer, UInt32(PATH_MAX))
        guard result > 0 else { return nil }
        return String(cString: pathBuffer)
#else
        return nil
#endif
    }

    private func hasDebugEnvironment() -> Bool {
        let keys = [
            "DYLD_INSERT_LIBRARIES",
            "MallocStackLogging",
            "NSUnbufferedIO"
        ]
        return keys.contains { getenv($0) != nil }
    }

    private func hasTimingAnomaly() -> Bool {
        let start = DispatchTime.now().uptimeNanoseconds
        var value = 0
        for index in 0..<50_000 {
            value &+= index
        }
        _ = value
        let elapsedMs = (DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
        return elapsedMs > 50
    }
}

#if os(iOS) || os(tvOS) || os(watchOS)
private let tracedFlag: Int32 = 0x00000800
#else
private let tracedFlag: Int32 = 0x00000800
#endif
