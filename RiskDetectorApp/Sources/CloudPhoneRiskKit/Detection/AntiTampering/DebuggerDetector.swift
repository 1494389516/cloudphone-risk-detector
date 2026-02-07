import Darwin
import Foundation

struct DebuggerDetector: Detector {
    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        if isBeingDebugged() {
            score += 35
            methods.append("debugger:attached")
        }

        if hasDebuggerParent() {
            score += 20
            methods.append("debugger:parent")
        }

        if hasDebuggerEnv() {
            score += 15
            methods.append("debugger:environment")
        }

        if hasDebuggerPort() {
            score += 10
            methods.append("debugger:port")
        }

        return DetectorResult(score: score, methods: methods)
#endif
    }

    private func isBeingDebugged() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.size
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return false }
        return (info.kp_proc.p_flag & tracedFlag) != 0
    }

    private func hasDebuggerParent() -> Bool {
        guard let name = parentProcessPath(getppid())?.lowercased() else { return false }
        return ["lldb", "debugserver", "gdb", "xcode"].contains { name.contains($0) }
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

    private func hasDebuggerEnv() -> Bool {
        let keys = ["DYLD_INSERT_LIBRARIES", "OS_ACTIVITY_DT_MODE", "NSZombieEnabled"]
        for key in keys {
            if key.withCString({ getenv($0) != nil }) {
                return true
            }
        }
        return false
    }

    private func hasDebuggerPort() -> Bool {
        let ports = [12345, 2345, 27042]
        return ports.contains(where: isPortOpen)
    }

    private func isPortOpen(_ port: Int) -> Bool {
        let socketFd = socket(AF_INET, SOCK_STREAM, 0)
        guard socketFd >= 0 else { return false }
        defer { close(socketFd) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(socketFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }
}

private let tracedFlag: Int32 = 0x00000800
