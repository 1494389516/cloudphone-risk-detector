import CRiskCore
import Darwin
import Foundation

struct DebuggerDetector: Detector {
    let debuggerParentNeedles: [String] = ObfuscatedConstants.debuggerParentNeedles

    let debuggerEnvKeys: [String] = [
        "DYLD_INSERT_LIBRARIES",
        "OS_ACTIVITY_DT_MODE",
        "NSZombieEnabled",
        "MallocStackLogging",
    ]

    let debuggerPorts: [Int] = [12345, 2345, 27042, 27043, 23946]

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []
        let watchdogSnapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()

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

        if cprisk_csops_debug_check() != 0 {
            score += 30
            methods.append("debugger:csops_debugged")
        }

        if cprisk_detect_hardware_breakpoints() != 0 {
            score += 25
            methods.append("debugger:hardware_breakpoint")
        }

        let softwareBreakpointCount = softwareBreakpointScanCount()
        if softwareBreakpointCount > 0 {
            score += 18
            methods.append("debugger:software_breakpoint:\(softwareBreakpointCount)")
        } else if watchdogSnapshot.softwareBreakpointDetected ||
                    watchdogSnapshot.softwareBreakpointAnomalyCount > 0 ||
                    (watchdogSnapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP)) != 0 {
            score += 10
            methods.append("debugger:software_breakpoint:\(ObfuscatedConstants.keywordWatchdog)")
        }

        if cprisk_probe_debugger_via_signal() != 0 {
            score += 20
            methods.append("debugger:signal_probe")
        }

        if cprisk_detect_tty_debug() != 0 {
            score += 10
            methods.append("debugger:tty")
        }

        let suspiciousThreads = cprisk_detect_suspicious_threads()
        if suspiciousThreads > 0 {
            score += min(Double(suspiciousThreads) * 15, 30)
            methods.append("debugger:suspicious_threads:\(suspiciousThreads)")
        }

        if cprisk_detect_developer_disk() != 0 {
            score += 8
            methods.append("debugger:developer_disk")
        }

        if hasExceptionDeliveryTimeout(snapshot: watchdogSnapshot) {
            score += 14
            methods.append("debugger:exception_delivery_timeout")
        }

        return DetectorResult(score: min(score, 100), methods: methods)
#endif
    }

    private func isBeingDebugged() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, cprisk_getpid_direct()]
        var size = MemoryLayout<kinfo_proc>.size
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return false }
        return (info.kp_proc.p_flag & tracedFlag) != 0
    }

    private func hasDebuggerParent() -> Bool {
        guard let name = processPath(for: cprisk_getppid_direct()) else { return false }
        return firstDebuggerParentToken(in: name) != nil
    }

    private func hasDebuggerEnv() -> Bool {
        for key in debuggerEnvKeys {
            if key.withCString({ getenv($0) != nil }) {
                return true
            }
        }
        return false
    }

    private func hasDebuggerPort() -> Bool {
        debuggerPorts.contains(where: isPortOpen)
    }

    private func softwareBreakpointScanCount() -> Int32 {
        typealias SignalProbeFn = @convention(c) () -> Int32
        let probeFn: SignalProbeFn = cprisk_probe_debugger_via_signal
        let probePtr = unsafeBitCast(probeFn, to: UnsafeRawPointer.self)
        return cprisk_scan_software_breakpoints(probePtr, 256)
    }

    private func hasExceptionDeliveryTimeout(snapshot: CPRiskKit.AntiDebugWatchdogSnapshot) -> Bool {
        let timeoutFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT)) != 0
        return timeoutFlag ||
            snapshot.exceptionDeliveryTimeoutDetected ||
            snapshot.exceptionDeliveryTimeoutAnomalyCount > 0
    }

    private func isPortOpen(_ port: Int) -> Bool {
        var rawErrno: CInt = 0
        let socketFd = cprisk_socket_direct(AF_INET, SOCK_STREAM, 0, &rawErrno)
        guard socketFd >= 0 else { return false }
        defer { _ = cprisk_close_direct(socketFd, nil) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr -> Int32 in
                var connectErrno: CInt = 0
                return cprisk_connect_direct(socketFd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size), &connectErrno)
            }
        }
        return result == 0
    }

    func firstDebuggerParentToken(in parentProcessPath: String) -> String? {
        let normalized = parentProcessPath.lowercased()
        return debuggerParentNeedles.first(where: { normalized.contains($0) })
    }
}

private let tracedFlag: Int32 = 0x00000800
