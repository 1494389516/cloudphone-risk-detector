import CRiskCore
import Darwin
import Foundation

struct KernelHookSideChannel: Detector {
    private static var timebaseInfo: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    private static func nanoseconds(from ticks: UInt64) -> UInt64 {
        ticks * UInt64(timebaseInfo.numer) / UInt64(timebaseInfo.denom)
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
        var score: Double = 0
        var methods: [String] = []

        let statProbe = TimingRatioBaseline.evaluatePair(
            baselineName: "getpid",
            probeName: "stat:/usr/lib/dyld"
        ) {
            _ = cprisk_getpid_direct()
        } probe: {
            var st = stat()
            _ = "/usr/lib/dyld".withCString { cprisk_stat_direct($0, &st, nil) }
        }

        if let statProbe, statProbe.isAnomalous {
            score += 25
            methods.append(
                "kernel_hook_timing_anomaly:probe=\(statProbe.probeName)_baseline=\(statProbe.baselineName)_medianNs=\(statProbe.probeMedianNs)_baselineMedianNs=\(statProbe.baselineMedianNs)_ratio=\(String(format: "%.1f", statProbe.medianRatio))_ratioP95=\(String(format: "%.1f", statProbe.p95Ratio))"
            )
        }

        let sysctlProbe = TimingRatioBaseline.evaluatePair(
            baselineName: "getpid",
            probeName: "sysctl:kern.proc.pid",
            ratioThreshold: 14.0
        ) {
            _ = cprisk_getpid_direct()
        } probe: {
            var info = kinfo_proc()
            var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, cprisk_getpid_direct()]
            var size = MemoryLayout<kinfo_proc>.size
            _ = cprisk_sysctl_direct(&mib, 4, &info, &size, nil, 0, nil)
        }

        if let sysctlProbe, sysctlProbe.isAnomalous {
            score += 20
            methods.append(
                "kernel_hook_timing_anomaly:probe=\(sysctlProbe.probeName)_baseline=\(sysctlProbe.baselineName)_medianNs=\(sysctlProbe.probeMedianNs)_baselineMedianNs=\(sysctlProbe.baselineMedianNs)_ratio=\(String(format: "%.1f", sysctlProbe.medianRatio))_ratioP95=\(String(format: "%.1f", sysctlProbe.p95Ratio))"
            )
        }

        // 二次放大探测：间接函数指针 + 交替 syscall 使 Stalker DBT 开销显著放大，阈值更低即可触发。
        let amplified = TimingRatioBaseline.amplifiedSamples()
        if let ampEval = TimingRatioBaseline.evaluate(
            getpidSamples: amplified.getpid,
            statSamples: amplified.stat,
            ratioThreshold: 12.0
        ) {
            if ampEval.isAnomalous {
                score += 25
                methods.append(
                    "kernel_hook_stalker_amplified:ratio=\(String(format: "%.1f", ampEval.medianRatio))_ratioP95=\(String(format: "%.1f", ampEval.p95Ratio))"
                )
            }
        }

        return (score, methods)
#endif
    }

    // MARK: - Strategy 2: libc vs direct-syscall inode consistency

    private func detectInodeMismatch() -> (Double, [String]) {
#if targetEnvironment(simulator)
        return (0, [])
#else
        let testPaths = ["/usr/lib/dyld", "/etc/passwd", "/dev/null"]
        var score: Double = 0
        var methods: [String] = []

        for path in testPaths {
            var stdStat = stat()
            var secureStat = stat()

            let stdRet = path.withCString { stat($0, &stdStat) }
            let secureRet = path.withCString { cPath -> Int32 in
                var rawErrno: CInt = 0
                return cprisk_stat_direct(cPath, &secureStat, &rawErrno)
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
        for _ in 0..<10_000 { _ = cprisk_getpid_direct() }

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

        let expectedPid = cprisk_getpid_direct()
        var pidUnstable = false
        for _ in 0..<9 {
            if cprisk_getpid_direct() != expectedPid {
                pidUnstable = true
                break
            }
        }

        let expectedUid = cprisk_getuid_direct()
        var uidUnstable = false
        for _ in 0..<9 {
            if cprisk_getuid_direct() != expectedUid {
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
                score: min(Double(timingMethods.count) * 20, 45),
                evidence: [
                    "detail": timingMethods.joined(separator: ","),
                    "mechanism": "mach_absolute_time_ratio_probe",
                    "sample_pairs": "\(timingMethods.count)",
                ],
                state: .soft(confidence: timingMethods.count > 1 ? 0.75 : 0.65),
                layer: 2,
                weightHint: 68
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

        let amplifiedMethods = result.methods.filter { $0.hasPrefix("kernel_hook_stalker_amplified") }
        if !amplifiedMethods.isEmpty {
            signals.append(RiskSignal(
                id: "kernel_hook_stalker_amplified",
                category: "anti_tamper",
                score: 25,
                evidence: [
                    "detail": amplifiedMethods.joined(separator: ","),
                    "mechanism": "mach_absolute_time_stalker_amplified",
                ],
                state: .soft(confidence: 0.72),
                layer: 2,
                weightHint: 72
            ))
        }

        return signals
    }
}
