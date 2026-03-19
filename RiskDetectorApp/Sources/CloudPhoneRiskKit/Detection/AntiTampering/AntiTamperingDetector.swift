import Darwin
import CRiskCore
import Foundation

private enum AntiTamperingDetectorCFF {
    static let detectConfig = CFFConfig.adaptive(
        functionSeed: 0x7EA1_42D0_9B53_6C2F,
        protectionTier: .light,
        dispatcherStyle: .dualRail,
        codecStyle: .xorRotate
    )

    static func salt(
        suspiciousNeedles: [String],
        debugEnvironmentKeys: [String]
    ) -> UInt32 {
        CFFRuntimeSalt.derive(
            functionSeed: detectConfig.functionSeed,
            inputs: CFFRuntimeSaltInputs(
                extraWords: [
                    UInt64(suspiciousNeedles.count),
                    UInt64(debugEnvironmentKeys.count),
                    Date().timeIntervalSince1970.bitPattern,
                ],
                strings: [
                    "atd_core_v1",
                    suspiciousNeedles.prefix(3).joined(separator: "|"),
                    debugEnvironmentKeys.prefix(3).joined(separator: "|"),
                ],
                flags: [suspiciousNeedles.isEmpty, debugEnvironmentKeys.isEmpty]
            )
        )
    }
}

struct AntiTamperingDetector: Detector {

    let suspiciousParentNeedles: [String] = [
        ObfuscatedConstants.keywordLldb,
        "gdb",
        "debugserver",
        ObfuscatedConstants.keywordFrida,
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
        let antiTamperingPrefix = ObfuscatedConstants.detectorIDAntiTampering
        let cffConfig = AntiTamperingDetectorCFF.detectConfig
        let salt = AntiTamperingDetectorCFF.salt(
            suspiciousNeedles: suspiciousParentNeedles,
            debugEnvironmentKeys: debugEnvironmentKeys
        )

        let entryState: UInt32 = 0x21
        let tracedState: UInt32 = 0x22
        let parentState: UInt32 = 0x23
        let envState: UInt32 = 0x24
        let timingState: UInt32 = 0x25
        let ptraceState: UInt32 = 0x26
        let connectorState: UInt32 = 0x27
        let settleState: UInt32 = 0x28
        let finishState: UInt32 = 0x29

        let cffKey = CFFStateCodec.deriveSeed(function: "atd_core_v1", config: cffConfig)
        let effectiveSalt = cffConfig.enableRuntimeSalt ? salt : salt ^ 0x13579BDF

        func encodeState(_ rawState: UInt32) -> UInt32 {
            CFFStateCodec.encode(state: rawState, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        func decodeState(_ encoded: UInt32) -> UInt32 {
            CFFStateCodec.decode(state: encoded, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        var sink = CFFReturnSink<DetectorResult>()
        var encodedState = encodeState(entryState)
        var loopBudget = 64

        func finalizeResult() -> DetectorResult {
            DetectorResult(score: min(score, 90), methods: methods)
        }

        while !sink.isResolved {
            guard loopBudget > 0 else {
                sink.store(finalizeResult())
                break
            }
            loopBudget -= 1

            let decodedState = decodeState(encodedState)
            let dispatchPlan = CFFDispatcher.plan(encodedState: encodedState, salt: salt, config: cffConfig)
            let useIfElseRail = dispatchPlan.style == .ifElseChain || (dispatchPlan.branchSelector & 1) == 1

            if useIfElseRail {
                if decodedState == entryState {
                    encodedState = encodeState(tracedState)
                } else if decodedState == tracedState {
                    if isTraced() {
                        score += 30
                        methods.append("\(antiTamperingPrefix):p_traced")
                    }
                    encodedState = encodeState(parentState)
                } else if decodedState == parentState {
                    if hasSuspiciousParent() {
                        score += 20
                        methods.append("\(antiTamperingPrefix):suspicious_parent")
                    }
                    encodedState = encodeState(envState)
                } else if decodedState == envState {
                    if hasDebugEnvironment() {
                        score += 15
                        methods.append("\(antiTamperingPrefix):debug_env")
                    }
                    encodedState = encodeState(timingState)
                } else if decodedState == timingState {
                    if hasTimingAnomaly() {
                        score += 12
                        methods.append("\(antiTamperingPrefix):timing")
                    }
                    encodedState = encodeState(ptraceState)
                } else if decodedState == ptraceState {
                    let ptraceResult = denyDebuggerAttach()
                    score += ptraceResult.score
                    methods.append(contentsOf: ptraceResult.methods)
                    encodedState = encodeState(connectorState)
                } else if decodedState == connectorState {
                    let nextState = CFFOpaquePredicates.connectorGate(encodedState: encodedState, salt: salt) ? finishState : settleState
                    encodedState = encodeState(nextState)
                } else if decodedState == settleState {
                    encodedState = encodeState(finishState)
                } else if decodedState == finishState {
                    sink.store(finalizeResult())
                } else {
                    sink.store(finalizeResult())
                }
            } else {
                switch decodedState {
                case entryState:
                    encodedState = encodeState(tracedState)
                case tracedState:
                    if isTraced() {
                        score += 30
                        methods.append("\(antiTamperingPrefix):p_traced")
                    }
                    encodedState = encodeState(parentState)
                case parentState:
                    if hasSuspiciousParent() {
                        score += 20
                        methods.append("\(antiTamperingPrefix):suspicious_parent")
                    }
                    encodedState = encodeState(envState)
                case envState:
                    if hasDebugEnvironment() {
                        score += 15
                        methods.append("\(antiTamperingPrefix):debug_env")
                    }
                    encodedState = encodeState(timingState)
                case timingState:
                    if hasTimingAnomaly() {
                        score += 12
                        methods.append("\(antiTamperingPrefix):timing")
                    }
                    encodedState = encodeState(ptraceState)
                case ptraceState:
                    let ptraceResult = denyDebuggerAttach()
                    score += ptraceResult.score
                    methods.append(contentsOf: ptraceResult.methods)
                    encodedState = encodeState(connectorState)
                case connectorState:
                    let nextState = CFFDispatcher.branchKey(encodedState, salt: salt) & 1 == 0 ? finishState : settleState
                    encodedState = encodeState(nextState)
                case settleState:
                    encodedState = encodeState(finishState)
                case finishState:
                    sink.store(finalizeResult())
                default:
                    sink.store(finalizeResult())
                }
            }
        }

        return sink.resolve(or: finalizeResult())
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
                    return (25, ["dbg_attach:already_attached"])
            }
                return (5, ["dbg_attach:direct_syscall_errno:\(rawErrno)"])
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
