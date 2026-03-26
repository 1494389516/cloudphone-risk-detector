import CRiskCore
import Darwin
import Foundation

/// Detects Frida via Unix domain socket artifacts and timing side-channels.
///
/// Implements two detection techniques:
/// 1. **Unix domain socket detection** — detect Frida's IPC sockets in /tmp
/// 2. **Timing side-channel** — detect instrumentation latency from Frida's Interceptor
///    Uses dynamic baseline ratio (probe_median/getpid_median > 15), aligned with KernelHookSideChannel.
struct FridaSocketDetector: Detector {

    private static var timebaseInfo: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    private static func nanoseconds(from ticks: UInt64) -> UInt64 {
        ticks * UInt64(timebaseInfo.numer) / UInt64(max(timebaseInfo.denom, 1))
    }

    func detect() throws -> DetectorResult {
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

        let suspiciousPaths = DynamicFeatureList.shared.suspiciousPaths

        // Method 1: Enumerate /tmp directory for suspicious entries
        if let dir = opendir("/tmp") {
            defer { closedir(dir) }
            while let entry = readdir(dir) {
                let name = withUnsafePointer(to: &entry.pointee.d_name) { ptr in
                    let cptr = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
                    let len = strnlen(cptr, 256)
                    return String(data: Data(bytes: cptr, count: len), encoding: .utf8) ?? ""
                }
                let lower = name.lowercased()
                if ObfuscatedConstants.fridaSocketEntryMarkers.contains(where: { marker in
                    lower.hasPrefix(marker) || lower.contains(marker)
                }) {
                    score += 15
                    methods.append("\(ObfuscatedConstants.methodPrefixFridaSocketTmpEntry)\(name)")
                    break
                }
            }
        }

        // Method 2: Check for Frida's default listening sockets by scanning file descriptors
        for fd: Int32 in 3..<256 {
            var addr = sockaddr_un()
            var len = socklen_t(MemoryLayout<sockaddr_un>.size)
            let result = withUnsafeMutablePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    getsockname(fd, sockPtr, &len)
                }
            }
            if result == 0 && addr.sun_family == sa_family_t(AF_UNIX) {
                var sunPath = addr.sun_path
                let maxLen = MemoryLayout.size(ofValue: sunPath)
                let path = withUnsafePointer(to: &sunPath) { ptr in
                    let cptr = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
                    let len = strnlen(cptr, maxLen)
                    return String(data: Data(bytes: cptr, count: len), encoding: .utf8) ?? ""
                }
                guard !path.isEmpty else { continue }
                let lower = path.lowercased()
                if ObfuscatedConstants.fridaSocketPathMarkers.contains(where: { lower.contains($0) }) {
                    score += 18
                    methods.append("\(ObfuscatedConstants.methodPrefixFridaSocketUnixFd)\(path)")
                    break
                }
            }
        }

        // Method 3: Corroborate with direct-access path probes only after lower-noise runtime/socket hints.
        if shouldProbeSuspiciousPaths(score: score, methods: methods) {
            for prefix in suspiciousPaths where directFileExists(prefix) {
                score += 12
                methods.append("\(ObfuscatedConstants.methodPrefixFridaSocketPath)\(prefix)")
            }
        }

        return (min(score, 30), methods)
    }

    internal func shouldProbeSuspiciousPaths(score: Double, methods: [String]) -> Bool {
        score > 0 || !methods.isEmpty
    }

    private func directFileExists(_ path: String) -> Bool {
        if let exists = SVCDirectCall.secureAccess(path) {
            return exists
        }
        Logger.log("[FridaSocketDetector] secure access probe unavailable")
        return false
    }

    // MARK: - 2. Timing Side-Channel Detection

    /// 动态基线比值检测，与 KernelHookSideChannel 对齐。
    /// 采样顺序随机化（先文件探针或先 getpid），每次采样前插入噪声计算以放大 Stalker DBT 开销。
    private func detectTimingAnomaly() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        let iterations = TimingRatioBaseline.defaultSampleCount
        let statFirst = Bool.random()

        var getpidSamples: [UInt64] = []
        getpidSamples.reserveCapacity(iterations)
        var statSamples: [UInt64] = []
        statSamples.reserveCapacity(iterations)

        func sampleGetpid() {
            for _ in 0..<iterations {
                for _ in 0..<6 { TimingRatioBaseline.samplingNoise() }
                let start = mach_absolute_time()
                _ = cprisk_getpid_direct()
                let end = mach_absolute_time()
                getpidSamples.append(Self.nanoseconds(from: end - start))
            }
        }

        func sampleStat() {
            for _ in 0..<iterations {
                for _ in 0..<6 { TimingRatioBaseline.samplingNoise() }
                let start = mach_absolute_time()
                _ = SVCDirectCall.secureAccess("/usr/lib/dyld")
                let end = mach_absolute_time()
                statSamples.append(Self.nanoseconds(from: end - start))
            }
        }

        if statFirst {
            sampleStat()
            sampleGetpid()
        } else {
            sampleGetpid()
            sampleStat()
        }

        guard let evaluation = TimingRatioBaseline.evaluate(
            getpidSamples: getpidSamples,
            statSamples: statSamples
        ) else {
            return (0, [])
        }

        // 仅用比值判断：ratio > 15 为主条件，ratioP95 > 15 为辅助（均无量纲，不受机型/负载影响）
        if evaluation.isAnomalous {
            score = 25
            methods.append(
                "timing_anomaly:ratio=\(String(format: "%.1f", evaluation.medianRatio))_ratioP95=\(String(format: "%.1f", evaluation.p95Ratio))"
            )
        }

        // 二次放大探测：间接函数指针 + 交替 syscall 使 Stalker DBT 开销显著放大
        let amplified = TimingRatioBaseline.amplifiedSamples()
        if let ampEval = TimingRatioBaseline.evaluate(
            getpidSamples: amplified.getpid,
            statSamples: amplified.stat,
            ratioThreshold: 12.0
        ) {
            if ampEval.isAnomalous {
                score += 20
                methods.append(
                    "timing_stalker_amplified:ratio=\(String(format: "%.1f", ampEval.medianRatio))_ratioP95=\(String(format: "%.1f", ampEval.p95Ratio))"
                )
            }
        }

        return (min(score, 45), methods)
    }
}

// MARK: - RiskSignal Conversion

extension FridaSocketDetector {
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let socketMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.detectorIDFridaSocket) }
        if !socketMethods.isEmpty {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalFridaUnixSocket,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(socketMethods.count) * 12, 25),
                evidence: ["detail": socketMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 75
            ))
        }

        let timingMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixTimingAnomaly) }
        if !timingMethods.isEmpty {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalFridaTimingAnomaly,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(timingMethods.count) * 10, 20),
                evidence: ["detail": timingMethods.joined(separator: ",")],
                state: .soft(confidence: 0.70),
                layer: 2,
                weightHint: 65
            ))
        }

        let amplifiedMethods = result.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixTimingStalkerAmplified) }
        if !amplifiedMethods.isEmpty {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalFridaStalkerAmplified,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 20,
                evidence: ["detail": amplifiedMethods.joined(separator: ",")],
                state: .soft(confidence: 0.65),
                layer: 2,
                weightHint: 65
            ))
        }

        return signals
    }
}
