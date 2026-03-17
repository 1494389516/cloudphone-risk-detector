import Darwin
import CRiskCore
import Foundation

struct AntiTamperingDetector: Detector {

    let suspiciousParentNeedles: [String] = [
        "lldb",
        "gdb",
        "debugserver",
        "frida",
        "hopper",
        "ida",
        "cycript",
    ]

    let debugEnvironmentKeys: [String] = [
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FORCE_FLAT_NAMESPACE",
        "MallocStackLogging",
        "NSUnbufferedIO",
        "OS_ACTIVITY_DT_MODE",
    ]

    func detect() throws -> DetectorResult {
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

        let ptraceResult = denyDebuggerAttach()
        score += ptraceResult.score
        methods.append(contentsOf: ptraceResult.methods)

        return DetectorResult(score: min(score, 90), methods: methods)
#endif
    }

    private func isTraced() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, cprisk_getpid_direct()]
        var size = MemoryLayout<kinfo_proc>.size
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return false }
        return (info.kp_proc.p_flag & tracedFlag) != 0
    }

    private func hasSuspiciousParent() -> Bool {
        let ppid = cprisk_getppid_direct()
        guard ppid > 1 else { return false }
        guard let parentPath = processPath(for: ppid) else { return false }
        return firstSuspiciousParentToken(in: parentPath) != nil
    }

    private func hasDebugEnvironment() -> Bool {
        debugEnvironmentKeys.contains { getenv($0) != nil }
    }

    private func denyDebuggerAttach() -> (score: Double, methods: [String]) {
        #if targetEnvironment(simulator) || DEBUG
        return (0, [])
        #else
        var rawErrno: CInt = 0
        let result = cprisk_deny_attach_status(&rawErrno)
        if result != 0 {
            if rawErrno == ENOTSUP || rawErrno == EPERM {
                return (25, ["ptrace:debugger_already_attached"])
            }
            return (5, ["ptrace:direct_syscall_errno:\(rawErrno)"])
        }
        return (0, [])
        #endif
    }

    func isTimingRatioAnomalous(
        getpidSamples: [UInt64],
        statSamples: [UInt64],
        ratioThreshold: Double = TimingRatioBaseline.defaultRatioThreshold
    ) -> Bool {
        TimingRatioBaseline.isAnomalous(
            getpidSamples: getpidSamples,
            statSamples: statSamples,
            ratioThreshold: ratioThreshold
        )
    }

    /// 动态基线比值检测：先对 getpid 采样建立基准，再用「文件探针耗时/getpid_median」比值判断。
    /// 避免 50ms 绝对值在低端机/冷启动/后台复起时误报，与 KernelHookSideChannel 对齐。
    private func hasTimingAnomaly() -> Bool {
        let iterations = TimingRatioBaseline.defaultSampleCount
        var getpidSamples: [UInt64] = []
        getpidSamples.reserveCapacity(iterations)
        for _ in 0..<iterations {
            let start = DispatchTime.now().uptimeNanoseconds
            _ = cprisk_getpid_direct()
            let end = DispatchTime.now().uptimeNanoseconds
            getpidSamples.append(end - start)
        }

        var statSamples: [UInt64] = []
        statSamples.reserveCapacity(iterations)
        for _ in 0..<iterations {
            let start = DispatchTime.now().uptimeNanoseconds
            _ = "/usr/lib/dyld".withCString { cprisk_access_direct($0, F_OK, nil) }
            let end = DispatchTime.now().uptimeNanoseconds
            statSamples.append(end - start)
        }

        return isTimingRatioAnomalous(getpidSamples: getpidSamples, statSamples: statSamples)
    }

    func firstSuspiciousParentToken(in parentProcessPath: String) -> String? {
        let normalized = parentProcessPath.lowercased()
        return suspiciousParentNeedles.first(where: { normalized.contains($0) })
    }
}

#if os(iOS) || os(tvOS) || os(watchOS)
private let tracedFlag: Int32 = 0x00000800
#else
private let tracedFlag: Int32 = 0x00000800
#endif
