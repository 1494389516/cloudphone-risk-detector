import Darwin
import Foundation

struct KernelHookSideChannel: Detector {

    private struct TimingStats {
        let median: UInt64
        let p95: UInt64
        let stddev: Double
    }

    private static var timebaseInfo: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    private static func nanoseconds(from ticks: UInt64) -> UInt64 {
        ticks * UInt64(timebaseInfo.numer) / UInt64(timebaseInfo.denom)
    }

    private static func computeStats(_ samples: [UInt64]) -> TimingStats {
        let sorted = samples.sorted()
        let count = sorted.count
        guard count > 0 else {
            return TimingStats(median: 0, p95: 0, stddev: 0)
        }
        let median = sorted[count / 2]
        let p95Index = min(Int(Double(count) * 0.95), count - 1)
        let p95 = sorted[p95Index]

        let mean = Double(sorted.reduce(0, +)) / Double(count)
        let variance = sorted.reduce(0.0) { acc, v in
            let diff = Double(v) - mean
            return acc + diff * diff
        } / Double(count)
        let stddev = sqrt(variance)

        return TimingStats(median: median, p95: p95, stddev: stddev)
    }

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["kernel_hook_sc:unavailable_simulator"])
#else
        var totalScore: Double = 0
        var methods: [String] = []

        let (s1, m1) = detectTimingAnomaly()
        totalScore += s1
        methods.append(contentsOf: m1)

        let (s2, m2) = detectInodeMismatch()
        totalScore += s2
        methods.append(contentsOf: m2)

        let (s3, m3) = detectTimeDesync()
        totalScore += s3
        methods.append(contentsOf: m3)

        let (s4, m4) = detectReturnValueEntropy()
        totalScore += s4
        methods.append(contentsOf: m4)

        if methods.isEmpty {
            return DetectorResult(score: 0, methods: ["kernel_hook_sc:clean"])
        }

        return DetectorResult(score: min(totalScore, 100), methods: methods)
#endif
    }

    // MARK: - Strategy 1: Syscall Timing Distribution

    private func detectTimingAnomaly() -> (Double, [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        let iterations = 30

        var getpidSamples: [UInt64] = []
        getpidSamples.reserveCapacity(iterations)
        for _ in 0..<iterations {
            let start = mach_absolute_time()
            _ = getpid()
            let end = mach_absolute_time()
            getpidSamples.append(Self.nanoseconds(from: end - start))
        }

        var statSamples: [UInt64] = []
        statSamples.reserveCapacity(iterations)
        for _ in 0..<iterations {
            var st = stat()
            let start = mach_absolute_time()
            _ = "/usr/lib/dyld".withCString { stat($0, &st) }
            let end = mach_absolute_time()
            statSamples.append(Self.nanoseconds(from: end - start))
        }

        let getpidStats = Self.computeStats(getpidSamples)
        let statStats = Self.computeStats(statSamples)

        guard getpidStats.median > 0 else { return (0, []) }

        let ratio = Double(statStats.median) / Double(getpidStats.median)
        let statP95ns = statStats.p95

        var score: Double = 0
        var methods: [String] = []

        if ratio > 15 || statP95ns > 50_000 {
            score = 40
            methods.append("kernel_hook_timing_anomaly:ratio=\(String(format: "%.1f", ratio))_p95=\(statP95ns)ns")
        }

        return (score, methods)
#endif
    }

    // MARK: - Strategy 2: Syscall Pair Inode Consistency

    private typealias StatFn = @convention(c) (UnsafePointer<CChar>, UnsafeMutablePointer<stat>?) -> Int32

    private func rtldNextStat() -> StatFn? {
        guard let ptr = dlsym(UnsafeMutableRawPointer(bitPattern: -1), "stat") else { return nil }
        return unsafeBitCast(ptr, to: StatFn.self)
    }

    private func detectInodeMismatch() -> (Double, [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        let testPaths = ["/usr/lib/dyld", "/etc/passwd", "/dev/null"]
        var score: Double = 0
        var methods: [String] = []

        guard let secureFn = rtldNextStat() else { return (0, []) }

        for path in testPaths {
            var stdStat = stat()
            var secureStat = stat()

            let stdRet = path.withCString { stat($0, &stdStat) }
            let secureRet = path.withCString { cPath -> Int32 in
                secureFn(cPath, &secureStat)
            }

            guard stdRet == 0, secureRet == 0 else { continue }

            if stdStat.st_ino != secureStat.st_ino || stdStat.st_dev != secureStat.st_dev {
                score = 70
                let filename = (path as NSString).lastPathComponent
                methods.append("kernel_hook_inode_mismatch:\(filename)_ino=\(stdStat.st_ino)vs\(secureStat.st_ino)_dev=\(stdStat.st_dev)vs\(secureStat.st_dev)")
            }
        }

        return (score, methods)
#endif
    }

    // MARK: - Strategy 3: Uptime Cross-Validation

    private func detectTimeDesync() -> (Double, [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        let uptimeA = ProcessInfo.processInfo.systemUptime
        let machA = mach_absolute_time()

        // Small busy-wait to create a measurable interval
        for _ in 0..<10_000 { _ = getpid() }

        let uptimeB = ProcessInfo.processInfo.systemUptime
        let machB = mach_absolute_time()

        let uptimeDelta = uptimeB - uptimeA
        let machDeltaNs = Self.nanoseconds(from: machB - machA)
        let machDeltaSec = Double(machDeltaNs) / 1_000_000_000.0

        guard machDeltaSec > 0 else { return (0, []) }

        let divergence = abs(uptimeDelta - machDeltaSec)
        let relativeError = divergence / machDeltaSec

        // >15% divergence AND >10ms absolute difference
        if relativeError > 0.15 && divergence > 0.01 {
            return (50, [
                "kernel_hook_time_desync:divergence=\(String(format: "%.4f", divergence))s_rel=\(String(format: "%.1f", relativeError * 100))%"
            ])
        }

        return (0, [])
#endif
    }

    // MARK: - Strategy 4: Return Value Entropy

    private func detectReturnValueEntropy() -> (Double, [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        var score: Double = 0
        var methods: [String] = []

        let expectedPid = getpid()
        var pidUnstable = false
        for _ in 0..<9 {
            if getpid() != expectedPid {
                pidUnstable = true
                break
            }
        }

        let expectedUid = getuid()
        var uidUnstable = false
        for _ in 0..<9 {
            if getuid() != expectedUid {
                uidUnstable = true
                break
            }
        }

        if pidUnstable || uidUnstable {
            score = 80
            var detail = [String]()
            if pidUnstable { detail.append("pid") }
            if uidUnstable { detail.append("uid") }
            methods.append("kernel_hook_pid_unstable:\(detail.joined(separator: "+"))")
        }

        return (score, methods)
#endif
    }
}

// MARK: - Signal Conversion

extension KernelHookSideChannel {
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let timingMethods = result.methods.filter { $0.hasPrefix("kernel_hook_timing_anomaly") }
        if !timingMethods.isEmpty {
            signals.append(RiskSignal(
                id: "kernel_hook_timing_anomaly",
                category: "anti_tamper",
                score: 40,
                evidence: ["detail": timingMethods.joined(separator: ",")],
                state: .soft(confidence: 0.6),
                layer: 2,
                weightHint: 60
            ))
        }

        let inodeMethods = result.methods.filter { $0.hasPrefix("kernel_hook_inode_mismatch") }
        if !inodeMethods.isEmpty {
            signals.append(RiskSignal(
                id: "kernel_hook_inode_mismatch",
                category: "anti_tamper",
                score: 70,
                evidence: ["detail": inodeMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 90
            ))
        }

        let desyncMethods = result.methods.filter { $0.hasPrefix("kernel_hook_time_desync") }
        if !desyncMethods.isEmpty {
            signals.append(RiskSignal(
                id: "kernel_hook_time_desync",
                category: "anti_tamper",
                score: 50,
                evidence: ["detail": desyncMethods.joined(separator: ",")],
                state: .soft(confidence: 0.7),
                layer: 2,
                weightHint: 65
            ))
        }

        let entropyMethods = result.methods.filter { $0.hasPrefix("kernel_hook_pid_unstable") }
        if !entropyMethods.isEmpty {
            signals.append(RiskSignal(
                id: "kernel_hook_pid_unstable",
                category: "anti_tamper",
                score: 80,
                evidence: ["detail": entropyMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 95
            ))
        }

        return signals
    }
}
