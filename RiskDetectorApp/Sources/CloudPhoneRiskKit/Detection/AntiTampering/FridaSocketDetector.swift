import Darwin
import Foundation

/// Detects Frida via Unix domain socket artifacts and timing side-channels.
///
/// Implements two detection techniques:
/// 1. **Unix domain socket detection** — detect Frida's IPC sockets in /tmp
/// 2. **Timing side-channel** — detect instrumentation latency from Frida's Interceptor
struct FridaSocketDetector: Detector {

    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        let socket = detectFridaSockets()
        score += socket.score
        methods.append(contentsOf: socket.methods)

        let timing = detectTimingAnomaly()
        score += timing.score
        methods.append(contentsOf: timing.methods)

        return DetectorResult(score: score, methods: methods)
#endif
    }

    // MARK: - 1. Unix Domain Socket / File Artifact Detection

    private func detectFridaSockets() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // Check /tmp for Frida socket files
        let suspiciousPaths = [
            "/tmp/frida-",
            "/tmp/.frida-",
            "/tmp/linjector",
            "/private/tmp/frida-",
            "/private/tmp/.frida-",
        ]

        // Method 1: Check known paths using access()
        for prefix in suspiciousPaths {
            if access(prefix, F_OK) == 0 {
                score += 12
                methods.append("frida_socket:path:\(prefix)")
            }
        }

        // Method 2: Enumerate /tmp directory for suspicious entries
        if let dir = opendir("/tmp") {
            defer { closedir(dir) }
            while let entry = readdir(dir) {
                let name = withUnsafePointer(to: &entry.pointee.d_name) { ptr in
                    String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
                }
                let lower = name.lowercased()
                if lower.hasPrefix("frida") || lower.hasPrefix(".frida") || lower.contains("linjector") {
                    score += 15
                    methods.append("frida_socket:tmp_entry:\(name)")
                    break
                }
            }
        }

        // Method 3: Check for Frida's default listening sockets by scanning file descriptors
        for fd: Int32 in 3..<256 {
            var addr = sockaddr_un()
            var len = socklen_t(MemoryLayout<sockaddr_un>.size)
            let result = withUnsafeMutablePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    getsockname(fd, sockPtr, &len)
                }
            }
            if result == 0 && addr.sun_family == sa_family_t(AF_UNIX) {
                let path = withUnsafePointer(to: &addr.sun_path) { ptr in
                    String(cString: UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self))
                }
                guard !path.isEmpty else { continue }
                let lower = path.lowercased()
                if lower.contains("frida") || lower.contains("linjector") || lower.contains("gum") {
                    score += 18
                    methods.append("frida_socket:unix_fd:\(path)")
                    break
                }
            }
        }

        return (min(score, 30), methods)
    }

    // MARK: - 2. Timing Side-Channel Detection

    private func detectTimingAnomaly() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        // Measure the time for a cheap syscall (getpid) repeatedly
        let iterations = 50
        var times = [UInt64]()
        times.reserveCapacity(iterations)

        for _ in 0..<iterations {
            let start = mach_absolute_time()
            _ = getpid()
            let end = mach_absolute_time()
            times.append(end - start)
        }

        // Convert to nanoseconds
        var timebaseInfo = mach_timebase_info_data_t()
        mach_timebase_info(&timebaseInfo)
        let nsTimes = times.map { Double($0) * Double(timebaseInfo.numer) / Double(timebaseInfo.denom) }

        // Sort and take p95
        let sorted = nsTimes.sorted()
        let p95Idx = min(Int(Double(iterations) * 0.95), iterations - 1)
        let p95 = sorted[p95Idx]

        // Normal getpid: ~100-500ns
        // With Frida Interceptor: ~5000-50000ns (5-50μs)
        // Threshold: p95 > 3000ns is suspicious
        if p95 > 3000 {
            score += 15
            methods.append("timing_anomaly:getpid_p95_\(Int(p95))ns")
        }

        // Also measure stat() which is commonly hooked for jailbreak bypass
        var statTimes = [UInt64]()
        statTimes.reserveCapacity(iterations)
        let testPath = "/usr/lib/dyld"

        for _ in 0..<iterations {
            let start = mach_absolute_time()
            _ = access(testPath, F_OK)
            let end = mach_absolute_time()
            statTimes.append(end - start)
        }

        let statNs = statTimes.map { Double($0) * Double(timebaseInfo.numer) / Double(timebaseInfo.denom) }
        let statSorted = statNs.sorted()
        let statP95Idx = min(Int(Double(iterations) * 0.95), iterations - 1)
        let statP95 = statSorted[statP95Idx]

        // Normal stat: ~1000-5000ns
        // With Frida: ~10000-100000ns
        if statP95 > 15000 {
            score += 12
            methods.append("timing_anomaly:stat_p95_\(Int(statP95))ns")
        }

        return (min(score, 25), methods)
    }
}

// MARK: - RiskSignal Conversion

extension FridaSocketDetector {
    func asSignals() -> [RiskSignal] {
        let result = detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let socketMethods = result.methods.filter { $0.hasPrefix("frida_socket") }
        if !socketMethods.isEmpty {
            signals.append(RiskSignal(
                id: "frida_unix_socket",
                category: "anti_tamper",
                score: min(Double(socketMethods.count) * 12, 25),
                evidence: ["detail": socketMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 75
            ))
        }

        let timingMethods = result.methods.filter { $0.hasPrefix("timing_anomaly") }
        if !timingMethods.isEmpty {
            signals.append(RiskSignal(
                id: "frida_timing_anomaly",
                category: "anti_tamper",
                score: min(Double(timingMethods.count) * 10, 20),
                evidence: ["detail": timingMethods.joined(separator: ",")],
                state: .soft(confidence: 70),
                layer: 2,
                weightHint: 65
            ))
        }

        return signals
    }
}
