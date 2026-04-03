import CRiskCore
import Foundation

private enum AntiTamperingSignalProviderCFF {
    static let signalsConfig = CFFConfig.adaptive(
        functionSeed: 0x63AF_19D2_8C54_B7E1,
        protectionTier: .light,
        dispatcherStyle: .functionPointerTable,
        codecStyle: .feistelSpn
    )
    /// Non-semantic CFF domain tag to avoid leaking concrete symbol names.
    static let signalsDomainTag = "atsp_core_v1"

    static func salt(snapshot: RiskSnapshot, threshold: Double) -> UInt32 {
        CFFRuntimeSalt.derive(
            functionSeed: signalsConfig.functionSeed,
            inputs: CFFRuntimeSaltInputs(
                extraWords: [
                    snapshot.jailbreak.confidence.bitPattern,
                    UInt64(snapshot.jailbreak.detectedMethods.count),
                    threshold.bitPattern,
                    UInt64(snapshot.mutationStrategy?.thresholdJitterBps ?? 0),
                    UInt64(snapshot.mutationStrategy?.scoreJitterBps ?? 0),
                ],
                strings: [
                    signalsDomainTag,
                    snapshot.deviceID,
                    snapshot.mutationStrategy?.seed ?? "",
                ],
                flags: [
                    snapshot.mutationStrategy?.shuffleChecks ?? false,
                    snapshot.jailbreak.isJailbroken,
                ]
            )
        )
    }
}

/// 反篡改检测信号提供者
///
/// 将 AntiTamperingDetector、DebuggerDetector、FridaDetector、CodeSignatureValidator、MemoryIntegrityChecker
/// 的检测结果转换为 RiskSignal，供 RiskDetectionEngine 使用
///
/// ## 架构说明
/// - 遵循职责分离原则：检测器专注检测，SignalProvider 负责信号转换
/// - 实现 RiskSignalProvider 协议，可插拔到 RiskDetectionEngine
/// - 支持动态配置启用/禁用特定检测器
public final class AntiTamperingSignalProvider: RiskSignalProvider {

    /// 单例实例，供 registerProviders 使用；seal 后禁止替换，否则触发 provider_instance_replaced
    public static let shared = AntiTamperingSignalProvider()

    // MARK: - RiskSignalProvider

    public let id = ObfuscatedConstants.detectorIDAntiTampering
    
    /// 配置选项
    public struct Configuration: Sendable {
        var enableAntiTampering: Bool = true
        var enableDebugger: Bool = true
        var enableFrida: Bool = true
        var enableFridaModule: Bool = true
        var enableCodeSignature: Bool = true
        var enableAppSigningIdentity: Bool = true
        var enableMemoryIntegrity: Bool = true
        var enableRWXMemoryScan: Bool = true
        var enablePLTIntegrity: Bool = true
        var enableTextSegmentHash: Bool = true
        var enableFridaThreadDetect: Bool = true
        var enableFridaHeapDetect: Bool = true
        var enableObjCSwizzleDetect: Bool = true
        var enableFridaSocketDetect: Bool = true
        var enableMultiPathFileDetect: Bool = true
        var enableMultiPathCrossValidation: Bool = true
        var enableVMRemapDetect: Bool = true
        var enablePACValidation: Bool = true
        var enableMIEPosture: Bool = true
        var enableTaskPortAudit: Bool = true
        var enableDTraceKDebugDetect: Bool = true
        var enableLLDBJITDetect: Bool = true
        var enableDyldSharedCacheIntegrity: Bool = true
        var enableRandomizedDetection: Bool = true
        var enableFingerprintDeobfuscation: Bool = true
        var enableDyldInterposeDetect: Bool = true
        var enableSDKBinaryIntegrity: Bool = true
        var enableSensorReplayDetect: Bool = true
        var enablePhysicalSensorProbe: Bool = true
        var enableGPURenderProbe: Bool = true
        var enableIsaSwizzleDetect: Bool = true
        var enableCallStackValidate: Bool = true
        var enableHoneypotMemory: Bool = true
        var enableKernelHookSideChannel: Bool = true
        var enableSystemLibrarySegmentLayoutDetect: Bool = true
        var enableSwiftRuntimeIntegrity: Bool = true
        var enableLibcPrologueGuard: Bool = true
        var enableIfaceSpawnPathProbe: Bool = true
        var enableDyldImageMonitor: Bool = true
        var enableDylibInjectionDetect: Bool = true
        var enableAntiDebugWatchdog: Bool = true
        /// libc / arc4random fallback bitset from `AntiDebugWatchdogSnapshot` (independent of `enableAntiDebugWatchdog` so telemetry survives when watchdog checks are disabled).
        var enableLibcDirectSyscallFallbackReporting: Bool = true
        var enableEmulatorLayoutDetect: Bool = true
        var enableEmulatorBehaviorDetect: Bool = true
        var minScoreThreshold: Double = 0
        
        public static let `default` = Configuration()
    }
    
    private let configuration: Configuration
    private static let randomizedDetectorScope = ObfuscatedConstants.detectorScopeAntiTamperingProviderCoreChecks
    private static let protectedDuplicateSignalIDs: Set<String> = [
        SignalID.softwareBreakpointDetected,
        SignalID.exceptionDeliveryTimeout,
    ]

    private struct DetectorCheck {
        let id: String
        let execute: () throws -> [RiskSignal]
    }
    
    // MARK: - 初始化
    
    public init(configuration: Configuration = .default) {
        self.configuration = configuration
    }
    
    /// 便捷初始化（使用默认配置）
    public convenience init() {
        self.init(configuration: .default)
    }
    
    // MARK: - RiskSignalProvider 实现
    
    public func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var signals: [RiskSignal] = []
        let baseJailbreakScore = snapshot.jailbreak.confidence
        let ordered = orderedChecks(snapshot: snapshot, baseScore: baseJailbreakScore)
        let cffConfig = AntiTamperingSignalProviderCFF.signalsConfig
        let salt = AntiTamperingSignalProviderCFF.salt(snapshot: snapshot, threshold: configuration.minScoreThreshold)
        /* Salt-derived CFF state rung (7 consecutive values) — avoids a fixed 0x61…0x67 signature in TEXT. */
        let stateBase = UInt32(0x40) + (salt % 120)
        let entryState: UInt32 = stateBase
        let iterateState: UInt32 = stateBase &+ 1
        let executeState: UInt32 = stateBase &+ 2
        let connectorState: UInt32 = stateBase &+ 3
        let settleState: UInt32 = stateBase &+ 4
        let mprotectState: UInt32 = stateBase &+ 5
        let finishState: UInt32 = stateBase &+ 6

        let cffKey = CFFStateCodec.deriveSeed(function: AntiTamperingSignalProviderCFF.signalsDomainTag, config: cffConfig)
        let effectiveSalt = cffConfig.enableRuntimeSalt ? salt : salt ^ 0x13579BDF

        func encodeState(_ rawState: UInt32) -> UInt32 {
            CFFStateCodec.encode(state: rawState, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        func decodeState(_ encoded: UInt32) -> UInt32 {
            CFFStateCodec.decode(state: encoded, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        var checkIndex = 0
        var currentCheck: DetectorCheck?
        var loopBudget = max(40, ordered.count * 5 + 16)
        var sink = CFFReturnSink<[RiskSignal]>()
        var encodedState = encodeState(entryState)

        func finalizeSignals() -> [RiskSignal] {
            let merged = coalesceProtectedDuplicateSignals(signals)
            let withCorrelation = merged
                + fridaCorrelationSignals(from: merged)
                + antiDebugStrategySignals(from: merged)
                + signingChainSignals(from: merged)
            let withCross = withCorrelation + crossConsistencySignals(from: withCorrelation)
            var weighted = applyMiePostureWeighting(withCross)
            injectSigningEpochNoise(&weighted)

            let hintLevel = computeAdaptiveWatchdogHint(from: weighted)
            weighted.append(RiskSignal(
                id: ObfuscatedConstants.signalWatchdogAdaptiveHint,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 0,
                evidence: ["hint": "\(hintLevel)"],
                state: .soft(confidence: 0),
                layer: 0,
                weightHint: 0
            ))

            return weighted.filter { $0.score >= configuration.minScoreThreshold }
        }

        while !sink.isResolved {
            guard loopBudget > 0 else {
                sink.store(finalizeSignals())
                break
            }
            loopBudget -= 1

            let decodedState = decodeState(encodedState)
            let dispatchPlan = CFFDispatcher.plan(encodedState: encodedState, salt: salt, config: cffConfig)
            let useIfElseRail = dispatchPlan.style == .ifElseChain
                || (dispatchPlan.usesSecondaryDispatcher && CFFOpaquePredicates.connectorGate(encodedState: encodedState, salt: salt))

            if useIfElseRail {
                if decodedState == entryState {
                    encodedState = encodeState(iterateState)
                } else if decodedState == iterateState {
                    guard checkIndex < ordered.count else {
                        encodedState = encodeState(mprotectState)
                        continue
                    }
                    currentCheck = ordered[checkIndex]
                    encodedState = encodeState(executeState)
                } else if decodedState == executeState {
                    if let currentCheck {
                        isolatedAppend(currentCheck.id, &signals, currentCheck.execute)
                    }
                    currentCheck = nil
                    checkIndex += 1
                    encodedState = encodeState(connectorState)
                } else if decodedState == connectorState {
                    let nextState = CFFOpaquePredicates.parityFence(UInt32(checkIndex) &+ decodedState, salt: salt) ? iterateState : settleState
                    encodedState = encodeState(nextState)
                } else if decodedState == settleState {
                    encodedState = encodeState(iterateState)
                } else if decodedState == mprotectState {
                    appendMprotectSignals(&signals)
                    encodedState = encodeState(finishState)
                } else if decodedState == finishState {
                    sink.store(finalizeSignals())
                } else {
                    sink.store(finalizeSignals())
                }
            } else {
                switch decodedState {
                case entryState:
                    encodedState = encodeState(iterateState)
                case iterateState:
                    guard checkIndex < ordered.count else {
                        encodedState = encodeState(mprotectState)
                        continue
                    }
                    currentCheck = ordered[checkIndex]
                    encodedState = encodeState(executeState)
                case executeState:
                    if let currentCheck {
                        isolatedAppend(currentCheck.id, &signals, currentCheck.execute)
                    }
                    currentCheck = nil
                    checkIndex += 1
                    encodedState = encodeState(connectorState)
                case connectorState:
                    let nextState = CFFDispatcher.branchKey(encodedState, salt: salt) & 1 == 0 ? iterateState : settleState
                    encodedState = encodeState(nextState)
                case settleState:
                    encodedState = encodeState(iterateState)
                case mprotectState:
                    appendMprotectSignals(&signals)
                    encodedState = encodeState(finishState)
                case finishState:
                    sink.store(finalizeSignals())
                default:
                    sink.store(finalizeSignals())
                }
            }
        }

        return sink.resolve(or: finalizeSignals())
    }

    private func isolatedAppend(
        _ label: String,
        _ signals: inout [RiskSignal],
        _ block: () throws -> [RiskSignal]
    ) {
        do {
            let result = try block()
            signals.append(contentsOf: result)
        } catch {
            Logger.log("[ATSP] \(label) threw error(\(error)), treating as suspicious")
            signals.append(RiskSignal(
                id: "detector_anomaly_\(label)",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 80,
                evidence: ["error": "\(error)", "detector": label],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ))
        }
    }

    private func injectSigningEpochNoise(_ signals: inout [RiskSignal]) {
        guard !signals.isEmpty else { return }
        let epochNonce = mach_absolute_time() / 30_000_000_000
        guard let lowestIdx = signals.enumerated().min(by: { $0.element.score < $1.element.score })?.offset else { return }
        signals[lowestIdx].score += Double(epochNonce % 7) * 0.01
    }

    private func computeAdaptiveWatchdogHint(from signals: [RiskSignal]) -> Int {
        let tamperedCount = signals.filter { $0.state == .tampered }.count
        if tamperedCount >= 3 { return 1 }
        if tamperedCount >= 1 { return 2 }
        return 3
    }

    func orderedRandomizedDetectorIDs(snapshot: RiskSnapshot) -> [String] {
        orderedChecks(snapshot: snapshot, baseScore: snapshot.jailbreak.confidence)
            .map(\.id)
            .filter { Self.randomizableDetectorIDs.contains($0) }
    }

    func configuredCheckIDs(snapshot: RiskSnapshot) -> [String] {
        buildChecks(snapshot: snapshot, baseScore: snapshot.jailbreak.confidence).map(\.id)
    }

    private static let randomizableDetectorIDs: Set<String> = [
        ObfuscatedConstants.detectorIDAntiTampering,
        ObfuscatedConstants.detectorIDDebugger,
        ObfuscatedConstants.keywordFrida,
        ObfuscatedConstants.detectorIDFridaModule,
        ObfuscatedConstants.detectorIDFridaThread,
        ObfuscatedConstants.detectorIDFridaHeap,
        ObfuscatedConstants.detectorIDObjCSwizzle,
        ObfuscatedConstants.detectorIDFridaSocket,
        "dyld_interpose",
        "dyld_image_monitor",
        "dylib_injection",
        ObfuscatedConstants.detectorIDAntiDebugWatchdog,
    ]

    /// Descriptor-driven plan：`internalToken` 仅用于降低“整表能力清单”在静态阅读时的直观性，不改变对外 `DetectorCheck.id`。
    private enum CheckPlan {
        private struct Row {
            let internalToken: UInt64
            let enabled: (Configuration) -> Bool
            let make: (AntiTamperingSignalProvider, RiskSnapshot, Double) -> DetectorCheck
        }

        private static let tokenMix: UInt64 = 0xBADC_0FFE_EEDD_F011

        private static func nextKey(_ counter: inout UInt64) -> UInt64 {
            counter &+= 0x19E1_7000_0000_0003
            return counter ^ tokenMix
        }

        private static let rows: [Row] = {
            var c: UInt64 = 0x5010_0000_0000_0000
            return [
                Row(internalToken: nextKey(&c), enabled: { $0.enableAntiTampering }) { p, _, b in
                    DetectorCheck(id: ObfuscatedConstants.detectorIDAntiTampering) {
                        try p.detectAntiTampering(baseScore: b)
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableDebugger }) { p, _, b in
                    DetectorCheck(id: ObfuscatedConstants.detectorIDDebugger) {
                        try p.detectDebugger(baseScore: b)
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableFrida }) { p, _, b in
                    DetectorCheck(id: ObfuscatedConstants.keywordFrida) {
                        try p.detectFrida(baseScore: b)
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableFridaModule }) { p, _, b in
                    DetectorCheck(id: ObfuscatedConstants.detectorIDFridaModule) {
                        try p.detectFridaModule(baseScore: b)
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableCodeSignature }) { p, _, b in
                    DetectorCheck(id: "code_signature") {
                        try p.detectCodeSignatureIssues(baseScore: b)
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableAppSigningIdentity }) { p, _, b in
                    DetectorCheck(id: "app_signing_identity") {
                        try p.detectAppSigningIdentityIssues(baseScore: b)
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableMemoryIntegrity }) { p, _, b in
                    DetectorCheck(id: "memory_integrity") {
                        try p.detectMemoryIntegrityIssues(baseScore: b)
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableRWXMemoryScan }) { _, _, _ in
                    DetectorCheck(id: "rwx_memory") {
                        RWXMemoryScanner().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enablePLTIntegrity }) { _, _, _ in
                    DetectorCheck(id: "plt_integrity") {
                        let pltResult = PLTIntegrityGuard.verifyWithPersistedBaseline()
                        return PLTIntegrityGuard.asSignals(result: pltResult)
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableTextSegmentHash }) { _, _, _ in
                    DetectorCheck(id: "text_segment") {
                        let hashResult = TextSegmentIntegrityChecker.verify()
                        return TextSegmentIntegrityChecker.asSignals(result: hashResult)
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableFridaThreadDetect }) { _, _, _ in
                    DetectorCheck(id: ObfuscatedConstants.detectorIDFridaThread) {
                        try FridaThreadDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableFridaHeapDetect }) { _, _, _ in
                    DetectorCheck(id: ObfuscatedConstants.detectorIDFridaHeap) {
                        try FridaHeapDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableObjCSwizzleDetect }) { _, _, _ in
                    DetectorCheck(id: ObfuscatedConstants.detectorIDObjCSwizzle) {
                        try ObjCSwizzleDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableFridaSocketDetect }) { _, _, _ in
                    DetectorCheck(id: ObfuscatedConstants.detectorIDFridaSocket) {
                        try FridaSocketDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableMultiPathFileDetect }) { _, _, _ in
                    DetectorCheck(id: "multipath_file") {
                        let mpResult = try MultiPathFileDetector().detect()
                        guard mpResult.score > 0 else { return [] }

                        var mpSignals: [RiskSignal] = []
                        let hookMethods = mpResult.methods.filter { $0.hasPrefix(ObfuscatedConstants.methodPrefixMultipartHook) }
                        if !hookMethods.isEmpty {
                            mpSignals.append(RiskSignal(
                                id: ObfuscatedConstants.signalMultipathHookDetected,
                                category: ObfuscatedConstants.categoryAntiTamper,
                                score: min(Double(hookMethods.count) * 15, 30),
                                evidence: ["methods": hookMethods.joined(separator: ",")],
                                state: .tampered,
                                layer: 2,
                                weightHint: 82
                            ))
                        }

                        let pathMethods = mpResult.methods.filter { $0.hasPrefix("multipart:") && !$0.contains(ObfuscatedConstants.keywordHook) }
                        if !pathMethods.isEmpty {
                            mpSignals.append(RiskSignal(
                                id: ObfuscatedConstants.signalMultipathJailbreakFile,
                                category: ObfuscatedConstants.signalJailbreak,
                                score: min(Double(pathMethods.count) * 12, 25),
                                evidence: ["paths": pathMethods.joined(separator: ",")],
                                state: .hard(detected: true),
                                layer: 2,
                                weightHint: 70
                            ))
                        }
                        return mpSignals
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableMultiPathCrossValidation }) { _, _, _ in
                    DetectorCheck(id: "multipath_cross") {
                        MultiPathConsistencyCrossValidator().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableVMRemapDetect }) { _, _, _ in
                    DetectorCheck(id: ObfuscatedConstants.detectorIDVMRemap) {
                        VMRemapDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enablePACValidation }) { _, _, _ in
                    DetectorCheck(id: "pac_validation") {
                        PACValidationDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableMIEPosture }) { _, _, _ in
                    DetectorCheck(id: "mie_posture") {
                        MIEPostureDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableTaskPortAudit }) { _, _, _ in
                    DetectorCheck(id: ObfuscatedConstants.detectorIDTaskPortAudit) {
                        TaskPortAuditDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableDTraceKDebugDetect }) { _, _, _ in
                    DetectorCheck(id: "dtrace_kdebug") {
                        DTraceKDebugDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableLLDBJITDetect }) { _, _, _ in
                    DetectorCheck(id: "lldb_jit") {
                        LLDBJITDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableDyldSharedCacheIntegrity }) { _, _, _ in
                    DetectorCheck(id: "dyld_shared_cache_integrity") {
                        DyldSharedCacheIntegrityDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableRandomizedDetection }) { _, _, _ in
                    DetectorCheck(id: "randomized") {
                        let randResult = try RandomizedDetection().detect()
                        guard randResult.score > 0 else { return [] }
                        return [RiskSignal(
                            id: "randomized_env_anomaly",
                            category: ObfuscatedConstants.categoryAntiTamper,
                            score: randResult.score,
                            evidence: ["methods": randResult.methods.joined(separator: ",")],
                            state: .soft(confidence: min(randResult.score / 50.0, 1.0)),
                            layer: 2,
                            weightHint: 60
                        )]
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableFingerprintDeobfuscation }) { _, _, _ in
                    DetectorCheck(id: "fingerprint") {
                        let fpResult = try FingerprintDeobfuscation().detect()
                        guard fpResult.score > 0 else { return [] }

                        var fpSignals: [RiskSignal] = []
                        if fpResult.methods.contains(where: { $0.contains("simulator") }) {
                            fpSignals.append(RiskSignal(
                                id: "fingerprint_simulator",
                                category: "device",
                                score: 30,
                                evidence: ["type": "simulator_like_environment"],
                                state: .hard(detected: true),
                                layer: 1,
                                weightHint: 90
                            ))
                        }
                        if fpResult.methods.contains(where: { $0.contains("virtualization") }) {
                            fpSignals.append(RiskSignal(
                                id: "fingerprint_virtualization",
                                category: "device",
                                score: 25,
                                evidence: ["type": "virtualization_artifacts"],
                                state: .hard(detected: true),
                                layer: 1,
                                weightHint: 85
                            ))
                        }
                        if fpResult.methods.contains(where: { $0.contains("fingerprint_changed") }) {
                            fpSignals.append(RiskSignal(
                                id: "fingerprint_mutation",
                                category: "device",
                                score: 12,
                                evidence: ["type": "device_fingerprint_changed"],
                                state: .soft(confidence: 0.6),
                                layer: 1,
                                weightHint: 55
                            ))
                        }
                        if fpResult.methods.contains(where: { $0.contains("suspicious_hw") }) {
                            fpSignals.append(RiskSignal(
                                id: "fingerprint_suspicious_hw",
                                category: "device",
                                score: 20,
                                evidence: ["type": "suspicious_hardware_model"],
                                state: .hard(detected: true),
                                layer: 1,
                                weightHint: 80
                            ))
                        }
                        return fpSignals
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableDyldInterposeDetect }) { _, _, _ in
                    DetectorCheck(id: "dyld_interpose") {
                        try DyldInterposeDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableSDKBinaryIntegrity }) { _, _, _ in
                    DetectorCheck(id: "sdk_binary") {
                        let binResult = SDKBinaryIntegrityChecker.verify()
                        return SDKBinaryIntegrityChecker.asSignals(result: binResult)
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableSensorReplayDetect }) { _, _, _ in
                    DetectorCheck(id: "sensor_replay") {
                        try SensorReplayDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enablePhysicalSensorProbe }) { _, _, _ in
                    DetectorCheck(id: "physical_sensor") {
                        try PhysicalSensorProbe().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableGPURenderProbe }) { _, _, _ in
                    DetectorCheck(id: "gpu_render") {
                        try GPURenderProbe().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableIsaSwizzleDetect }) { _, _, _ in
                    DetectorCheck(id: "isa_swizzle") {
                        try IsaSwizzleDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableCallStackValidate }) { _, _, _ in
                    DetectorCheck(id: "call_stack") {
                        if let signal = CallStackUnwinder.validateCallStackAsSignal() {
                            return [signal]
                        }
                        return []
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableHoneypotMemory }) { _, _, _ in
                    DetectorCheck(id: "honeypot_memory") {
                        try HoneypotMemoryDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableKernelHookSideChannel }) { _, _, _ in
                    DetectorCheck(id: ObfuscatedConstants.detectorIDKernelHookSideChannel) {
                        try KernelHookSideChannel().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableSystemLibrarySegmentLayoutDetect }) { _, _, _ in
                    DetectorCheck(id: "system_library_segment_layout") {
                        try SystemLibrarySegmentLayoutDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableSwiftRuntimeIntegrity }) { _, _, _ in
                    DetectorCheck(id: SwiftRuntimeIntegrityDetector.detectorID) {
                        SwiftRuntimeIntegrityDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableLibcPrologueGuard }) { _, _, _ in
                    DetectorCheck(id: "libc_prologue") {
                        guard LibcPrologueGuard.checkAllCritical() else { return [] }
                        return [RiskSignal(
                            id: ObfuscatedConstants.signalLibcInlineHookDetected,
                            category: ObfuscatedConstants.categoryAntiTamper,
                            score: 95,
                            evidence: [
                                "mechanism": "mach_vm_read_overwrite_prologue_scan",
                                "detail": "critical_libc_function_entry_patched_with_branch_trampoline",
                            ],
                            state: .tampered,
                            layer: 2,
                            weightHint: 98
                        )]
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableIfaceSpawnPathProbe }) { _, _, _ in
                    DetectorCheck(id: "iface_spawn_probe") {
                        ProcessSpawnIfaceConsistencyDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableDyldImageMonitor }) { _, _, _ in
                    DetectorCheck(id: "dyld_image_monitor") {
                        try DyldImageMonitor.shared.asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableDylibInjectionDetect }) { _, _, _ in
                    DetectorCheck(id: "dylib_injection") {
                        try DylibInjectionDetector().asSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableAntiDebugWatchdog }) { p, _, _ in
                    DetectorCheck(id: ObfuscatedConstants.detectorIDAntiDebugWatchdog) {
                        p.detectAntiDebugWatchdogSignals()
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableLibcDirectSyscallFallbackReporting }) { p, snapshot, _ in
                    DetectorCheck(id: "libc_syscall_fallback") {
                        p.libcDirectSyscallFallbackSignals(from: snapshot)
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableEmulatorLayoutDetect }) { _, _, _ in
                    DetectorCheck(id: "emulator_layout") {
                        let result = try EmulatorLayoutDetector().detect()
                        guard result.score > 0 else { return [] }
                        return [RiskSignal(
                            id: "emulator_layout_anomaly",
                            category: ObfuscatedConstants.categoryAntiTamper,
                            score: result.score,
                            evidence: ["methods": result.methods.joined(separator: ",")],
                            state: .soft(confidence: min(result.score / 60.0, 1.0)),
                            layer: 2,
                            weightHint: 70
                        )]
                    }
                },
                Row(internalToken: nextKey(&c), enabled: { $0.enableEmulatorBehaviorDetect }) { _, _, _ in
                    DetectorCheck(id: "emulator_behavior") {
                        let result = try EmulatorBehaviorDetector().detect()
                        guard result.score > 0 else { return [] }
                        return [RiskSignal(
                            id: "emulator_behavior_anomaly",
                            category: ObfuscatedConstants.categoryAntiTamper,
                            score: result.score,
                            evidence: ["methods": result.methods.joined(separator: ",")],
                            state: .soft(confidence: min(result.score / 40.0, 1.0)),
                            layer: 2,
                            weightHint: 65
                        )]
                    }
                },
            ]
        }()

        static func makeChecks(
            configuration: Configuration,
            provider: AntiTamperingSignalProvider,
            snapshot: RiskSnapshot,
            baseScore: Double
        ) -> [DetectorCheck] {
            var checks: [DetectorCheck] = []
            checks.reserveCapacity(rows.count)
            for row in rows {
                _ = row.internalToken
                guard row.enabled(configuration) else { continue }
                checks.append(row.make(provider, snapshot, baseScore))
            }
            return checks
        }
    }

    private func buildChecks(snapshot: RiskSnapshot, baseScore: Double) -> [DetectorCheck] {
        CheckPlan.makeChecks(
            configuration: configuration,
            provider: self,
            snapshot: snapshot,
            baseScore: baseScore
        )
    }

    private func orderedChecks(snapshot: RiskSnapshot, baseScore: Double) -> [DetectorCheck] {
        let checks = buildChecks(snapshot: snapshot, baseScore: baseScore)
        let planner = MutationPlanner(
            strategy: snapshot.mutationStrategy,
            scope: Self.randomizedDetectorScope,
            deviceID: snapshot.deviceID
        )

        let selectedIndices = checks.indices.filter { Self.randomizableDetectorIDs.contains(checks[$0].id) }
        guard selectedIndices.count > 1 else { return checks }

        let selectedChecks = selectedIndices.map { checks[$0] }
        let shuffleSalt = [ObfuscatedConstants.categoryAntiTamper, ObfuscatedConstants.detectorIDDebugger, ObfuscatedConstants.keywordFrida]
            .joined(separator: "_")
        let shuffled = planner.maybeShuffle(selectedChecks, salt: shuffleSalt)

        var ordered = checks
        for (offset, index) in selectedIndices.enumerated() {
            ordered[index] = shuffled[offset]
        }
        return ordered
    }

    func coalesceProtectedDuplicateSignals(_ signals: [RiskSignal]) -> [RiskSignal] {
        var grouped: [String: [RiskSignal]] = [:]
        var orderedIDs: [String] = []
        var passthrough: [RiskSignal] = []

        for signal in signals {
            guard Self.protectedDuplicateSignalIDs.contains(signal.id) else {
                passthrough.append(signal)
                continue
            }

            if grouped[signal.id] == nil {
                orderedIDs.append(signal.id)
            }
            grouped[signal.id, default: []].append(signal)
        }

        let merged = orderedIDs.compactMap { mergeSignals(grouped[$0] ?? []) }
        return passthrough + merged
    }

    private func mergeSignals(_ signals: [RiskSignal]) -> RiskSignal? {
        guard let strongest = signals.max(by: { lhs, rhs in
            if lhs.score == rhs.score {
                return lhs.weightHint < rhs.weightHint
            }
            return lhs.score < rhs.score
        }) else {
            return nil
        }

        var mergedEvidence = strongest.evidence
        if signals.count > 1 {
            mergedEvidence["merged_count"] = "\(signals.count)"
            let mergedSources = Set(signals.compactMap { $0.evidence["source"] ?? $0.evidence["mechanism"] })
            if !mergedSources.isEmpty {
                mergedEvidence["merged_sources"] = mergedSources.sorted().joined(separator: ",")
            }
        }

        for signal in signals {
            for (key, value) in signal.evidence where mergedEvidence[key] == nil {
                mergedEvidence[key] = value
            }
        }

        let mergedState: RiskSignalState? = signals.contains(where: { $0.state == .tampered }) ? .tampered : strongest.state

        return RiskSignal(
            id: strongest.id,
            category: strongest.category,
            score: signals.map(\.score).max() ?? strongest.score,
            evidence: mergedEvidence,
            state: mergedState,
            layer: signals.compactMap(\.layer).min() ?? strongest.layer,
            weightHint: signals.map(\.weightHint).max() ?? strongest.weightHint
        )
    }
    
    // MARK: - 检测方法
    
    /// 反调试检测
    private func detectAntiTampering(baseScore: Double) throws -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        let result = try AntiTamperingDetector().detect()
        
        if result.score > 0 {
            // 基础反调试信号
            signals.append(
                RiskSignal(
                    id: ObfuscatedConstants.detectorIDAntiTampering,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: result.score,
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": ObfuscatedConstants.detectorNameAntiTamperingDetector
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 85
                )
            )
            
            // 分解具体方法为独立信号
            for method in result.methods {
                let signalID = method.replacingOccurrences(of: ":", with: "_")
                let methodScore = extractScore(from: method)
                
                signals.append(
                    RiskSignal(
                        id: signalID,
                        category: ObfuscatedConstants.categoryAntiTamper,
                        score: methodScore,
                        evidence: ["method": method]
                    )
                )
            }
        }
        
        return signals
    }
    
    /// 调试器检测
    private func detectDebugger(baseScore: Double) throws -> [RiskSignal] {
        var signals: [RiskSignal] = []
        let watchdogSnapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        
        let result = try DebuggerDetector().detect()
        
        if result.score > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.debuggerDetected,
                    category: "debugger",
                    score: result.score,
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": ObfuscatedConstants.detectorNameDebuggerDetector
                    ],
                    state: .soft(confidence: 0.7),
                    layer: 2,
                    weightHint: 50
                )
            )
            
            // 分解具体调试器类型
            for method in result.methods {
                if method.hasPrefix("debugger:parent:") {
                    let debuggerName = method.replacingOccurrences(of: "debugger:parent:", with: "")
                    signals.append(
                        RiskSignal(
                            id: "debugger_parent_\(debuggerName)",
                            category: "debugger",
                            score: 25,
                            evidence: ["parent_process": debuggerName]
                        )
                    )
                }
                
                if method.hasPrefix("debugger:port:") {
                    let port = method.replacingOccurrences(of: "debugger:port:", with: "")
                    signals.append(
                        RiskSignal(
                            id: "debugger_port_\(port)",
                            category: "debugger",
                            score: 15,
                            evidence: ["listening_port": port]
                        )
                    )
                }

                if method.hasPrefix("debugger:software_breakpoint:") {
                    let detail = method.replacingOccurrences(of: "debugger:software_breakpoint:", with: "")
                    signals.append(softwareBreakpointSignal(detail: detail, snapshot: watchdogSnapshot))
                }

                if method == "debugger:exception_delivery_timeout" {
                    signals.append(exceptionDeliveryTimeoutSignal(snapshot: watchdogSnapshot))
                }
            }
        }
        
        return signals
    }

    private func softwareBreakpointSignal(
        detail: String,
        snapshot: CPRiskKit.AntiDebugWatchdogSnapshot
    ) -> RiskSignal {
        let directCount = Int(detail)
        let isDirectScan = directCount != nil
        var evidence: [String: String] = [
            "mechanism": "arm64_brk_scan",
            "source": isDirectScan ? "direct_scan" : ObfuscatedConstants.keywordWatchdog,
            "\(ObfuscatedConstants.keywordWatchdog)_detected": snapshot.softwareBreakpointDetected ? "1" : "0",
            "\(ObfuscatedConstants.keywordWatchdog)_anomaly_count": "\(snapshot.softwareBreakpointAnomalyCount)"
        ]
        if let directCount {
            evidence["breakpoint_count"] = "\(directCount)"
        }

        return RiskSignal(
            id: SignalID.softwareBreakpointDetected,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: isDirectScan ? 58 : 34,
            evidence: evidence,
            state: .tampered,
            layer: 1,
            weightHint: isDirectScan ? 72 : 44
        )
    }

    private func exceptionDeliveryTimeoutSignal(
        snapshot: CPRiskKit.AntiDebugWatchdogSnapshot
    ) -> RiskSignal {
        let timeoutFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT)) != 0
        let anomalyCount = snapshot.exceptionDeliveryTimeoutAnomalyCount

        return RiskSignal(
            id: SignalID.exceptionDeliveryTimeout,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: timeoutFlag || anomalyCount > 1 ? 38 : 30,
            evidence: [
                "mechanism": "mach_exception_delivery_timeout",
                "\(ObfuscatedConstants.keywordWatchdog)_detected": snapshot.exceptionDeliveryTimeoutDetected ? "1" : "0",
                "\(ObfuscatedConstants.keywordWatchdog)_anomaly_count": "\(anomalyCount)",
                "anomaly_flag_set": timeoutFlag ? "1" : "0",
                "exception_anomaly_count": "\(snapshot.exceptionAnomalyCount)",
                "probe_handled": snapshot.exceptionDeliveryProbeHandled ? "1" : "0",
                "probe_ns": "\(snapshot.lastExceptionDeliveryProbeNs)"
            ],
            state: .soft(confidence: anomalyCount > 1 ? 0.9 : 0.82),
            layer: 2,
            weightHint: timeoutFlag || anomalyCount > 1 ? 50 : 40
        )
    }

    private func appendMprotectSignals(_ signals: inout [RiskSignal]) {
        guard cprisk_is_mprotect_tampered() != 0 else { return }

        let directFailureCount = Int(cprisk_get_mprotect_direct_failure_count())
        let fallbackSuccessCount = Int(cprisk_get_mprotect_fallback_success_count())
        let directFailed = directFailureCount > 0
        let fallbackSucceeded = fallbackSuccessCount > 0
        let semanticCase: String
        let baseScore: Double
        let baseWeightHint: Double

        switch (directFailed, fallbackSucceeded) {
        case (true, true):
            semanticCase = "direct_failure_with_fallback_success"
            baseScore = 92
            baseWeightHint = 97
        case (true, false):
            semanticCase = "direct_failure_without_fallback_success"
            baseScore = 86
            baseWeightHint = 91
        case (false, true):
            semanticCase = "fallback_success_without_observed_direct_failure"
            baseScore = 80
            baseWeightHint = 86
        case (false, false):
            semanticCase = "\(ObfuscatedConstants.keywordTamper)ed_flag_without_runtime_counters"
            baseScore = 82
            baseWeightHint = 88
        }

        var evidence: [String: String] = [
            "detail": "mprotect_syscall_\(ObfuscatedConstants.keywordTamper)ed",
            "direct_failure_count": "\(directFailureCount)",
            "fallback_success_count": "\(fallbackSuccessCount)",
            "fallback_in_use": fallbackSucceeded ? "1" : "0",
            "semantic_case": semanticCase,
            "high_risk_semantic": (directFailed && fallbackSucceeded) ? "1" : "0"
        ]
        if directFailed && fallbackSucceeded {
            evidence["severity_hint"] = "direct_failed_but_fallback_succeeded"
        }

        signals.append(RiskSignal(
            id: ObfuscatedConstants.signalMemoryProtectionTampered,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: baseScore,
            evidence: evidence,
            state: .tampered,
            layer: 1,
            weightHint: baseWeightHint
        ))

        if directFailed && fallbackSucceeded {
            signals.append(RiskSignal(
                id: ObfuscatedConstants.signalMemoryProtectionSemanticBypass,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 44,
                evidence: [
                    "detail": "mprotect_direct_path_failed_fallback_kept_working",
                    "direct_failure_count": "\(directFailureCount)",
                    "fallback_success_count": "\(fallbackSuccessCount)",
                    "semantic_case": semanticCase
                ],
                state: .tampered,
                layer: 2,
                weightHint: 68
            ))
        }
    }
    
    /// Frida 检测
    private func detectFrida(baseScore: Double) throws -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        let result = try FridaDetector().detect()
        let fridaPrefix = ObfuscatedConstants.keywordFrida

        if result.score > 0 {
            signals.append(
                RiskSignal(
                    id: "\(fridaPrefix)_detected",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(result.score, 55),
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": ObfuscatedConstants.detectorNameFridaDetector,
                        "scope": "runtime_surface"
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 85
                )
            )
        }

        let fridaCategories = [
            (ObfuscatedConstants.methodPrefixFridaPort, "\(fridaPrefix)_port", 30),
            (ObfuscatedConstants.methodPrefixFridaProto, "\(fridaPrefix)_proto", 34),
            (ObfuscatedConstants.methodPrefixFridaListen, "\(fridaPrefix)_listen", 14),
            (ObfuscatedConstants.methodPrefixFridaAnomalousProto, "\(fridaPrefix)_anom_proto", 34),
            (ObfuscatedConstants.methodPrefixFridaFile, "\(fridaPrefix)_file", 20),
            (ObfuscatedConstants.methodPrefixFridaSymbol, "\(fridaPrefix)_symbol", 20),
            (ObfuscatedConstants.methodPrefixFridaThread, "\(fridaPrefix)_thread", 20),
            (ObfuscatedConstants.methodPrefixFridaProcess, "\(fridaPrefix)_process", 30),
            (ObfuscatedConstants.methodPrefixFridaEnv, "\(fridaPrefix)_environment", 25),
            (ObfuscatedConstants.methodPrefixFridaMemorySig, "\(fridaPrefix)_memsig", 20),
            (ObfuscatedConstants.methodPrefixFridaRuntime, "\(fridaPrefix)_runtime", 22),
            (ObfuscatedConstants.methodPrefixFridaRuntimeFused, "\(fridaPrefix)_runtime_fused", 48),
            (FridaDetector.methodPrefixPatch, "\(fridaPrefix)_patch", 28),
            (FridaDetector.methodPrefixBehavior, "\(fridaPrefix)_behavior", 22),
        ]

        for method in result.methods {
            for (prefix, signalID, baseScore) in fridaCategories {
                if method.hasPrefix(prefix) {
                    let detail = method.replacingOccurrences(of: prefix, with: "")
                    signals.append(
                        RiskSignal(
                            id: "\(signalID)_\(detail.replacingOccurrences(of: ":", with: "_"))",
                            category: ObfuscatedConstants.categoryAntiTamper,
                            score: Double(baseScore),
                            evidence: ["detection_method": method]
                        )
                    )
                }
            }
        }

        let suspiciousPrefix = ObfuscatedConstants.methodPrefixSuspiciousLocalListen
        for method in result.methods where method.hasPrefix(suspiciousPrefix) {
            let detail = method.replacingOccurrences(of: suspiciousPrefix, with: "")
            let safeDetail = detail.replacingOccurrences(of: ":", with: "_")
            signals.append(
                RiskSignal(
                    id: "suspicious_local_listen_\(safeDetail)",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 4,
                    evidence: ["detection_method": method, "scope": "local_tcp_listen"],
                    state: .soft(confidence: 0.35),
                    layer: 1,
                    weightHint: 12
                )
            )
        }

        return signals
    }

    private func detectFridaModule(baseScore: Double) throws -> [RiskSignal] {
        try FridaModuleDetector().asSignals()
    }
    
    /// 代码签名验证
    private func detectCodeSignatureIssues(baseScore: Double) throws -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        let result = try CodeSignatureValidator().detect()
        
        if result.score > 0 {
            signals.append(
                RiskSignal(
                    id: "code_signature_invalid",
                    category: "integrity",
                    score: result.score,
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": "CodeSignatureValidator"
                    ],
                    state: .soft(confidence: 0.8),
                    layer: 2,
                    weightHint: 60
                )
            )
            
            // 分解具体签名问题
            for method in result.methods {
                if method.contains("invalid") {
                    signals.append(
                        RiskSignal(
                            id: "signature_invalid",
                            category: "integrity",
                            score: 40,
                            evidence: ["issue": "signature_validation_failed"]
                        )
                    )
                }
                
                if method.contains("resigned") {
                    signals.append(
                        RiskSignal(
                            id: "signature_resigned",
                            category: "integrity",
                            score: 30,
                            evidence: ["issue": "application_resigned"]
                        )
                    )
                }
                
                if method.contains("permissions") {
                    signals.append(
                        RiskSignal(
                            id: "signature_abnormal_permissions",
                            category: "integrity",
                            score: 25,
                            evidence: ["issue": "abnormal_segment_permissions"]
                        )
                    )
                }
            }
        }
        
        return signals
    }

    /// App 签名身份一致性检测
    private func detectAppSigningIdentityIssues(baseScore: Double) throws -> [RiskSignal] {
        try AppSigningIdentityDetector().asSignals()
    }
    
    /// 内存完整性检查
    private func detectMemoryIntegrityIssues(baseScore: Double) throws -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        let result = try MemoryIntegrityChecker().detect()
        
        if result.score > 0 {
            signals.append(
                RiskSignal(
                    id: "memory_integrity_violated",
                    category: "integrity",
                    score: result.score,
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": "MemoryIntegrityChecker"
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 75
                )
            )
            
            // 分解具体内存问题
            for method in result.methods {
                if method.hasPrefix(ObfuscatedConstants.methodPrefixMemoryHook) {
                    let functionName = method.replacingOccurrences(of: ObfuscatedConstants.methodPrefixMemoryHook, with: "")
                    signals.append(
                        RiskSignal(
                            id: "\(ObfuscatedConstants.signalPrefixHook)\(functionName)",
                            category: "integrity",
                            score: 20,
                            evidence: ["\(ObfuscatedConstants.keywordHook)ed_function": functionName]
                        )
                    )
                }
                
                if method.hasPrefix("memory_swizzle:") {
                    let className = method.replacingOccurrences(of: "memory_swizzle:objc:", with: "")
                    signals.append(
                        RiskSignal(
                            id: "swizzle_\(className.replacingOccurrences(of: ".", with: "_"))",
                            category: "integrity",
                            score: 22,
                            evidence: ["swizzled_class": className]
                        )
                    )
                }
                
                if method.hasPrefix(ObfuscatedConstants.methodPrefixMemoryInline) {
                    let functionName = method.replacingOccurrences(of: ObfuscatedConstants.methodPrefixMemoryInline, with: "")
                    signals.append(
                        RiskSignal(
                            id: "\(ObfuscatedConstants.signalPrefixInlineHook)\(functionName)",
                            category: "integrity",
                            score: 25,
                            evidence: ["inline_\(ObfuscatedConstants.keywordHook)ed": functionName]
                        )
                    )
                }
            }
        }
        
        return signals
    }

    private func detectAntiDebugWatchdogSignals() -> [RiskSignal] {
        let watchdogSnapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        let planSnapshot = CPRiskKit.shared.antiDebugPlanSnapshot()
        var signals = antiDebugWatchdogSignals(from: watchdogSnapshot)

        if watchdogSnapshot.csopsDebugged {
            signals.append(RiskSignal(
                id: SignalID.csopsDebugged,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 90,
                evidence: ["mechanism": "csops_cs_debugged_flag"],
                state: .tampered,
                layer: 1,
                weightHint: 95
            ))
        }
        if watchdogSnapshot.hardwareBpDetected {
            signals.append(RiskSignal(
                id: SignalID.hardwareBreakpointDetected,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 80,
                evidence: ["mechanism": "arm64_debug_registers"],
                state: .tampered,
                layer: 1,
                weightHint: 85
            ))
        }
        if watchdogSnapshot.softwareBreakpointDetected {
            signals.append(RiskSignal(
                id: SignalID.softwareBreakpointDetected,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 64,
                evidence: ["mechanism": "arm64_brk_opcode_scan", "source": "\(ObfuscatedConstants.keywordWatchdog)_probe"],
                state: .tampered,
                layer: 1,
                weightHint: 74
            ))
        }
        if watchdogSnapshot.signalProbeResult {
            signals.append(RiskSignal(
                id: SignalID.signalProbeDebugger,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 75,
                evidence: ["mechanism": "sigtrap_brk_probe"],
                state: .tampered,
                layer: 1,
                weightHint: 80
            ))
        }
        if watchdogSnapshot.exceptionDeliveryTimeoutDetected {
            signals.append(RiskSignal(
                id: SignalID.exceptionDeliveryTimeout,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: watchdogSnapshot.exceptionDeliveryProbeHandled ? 48 : 58,
                evidence: [
                    "mechanism": "mach_exception_delivery_probe",
                    "source": "\(ObfuscatedConstants.keywordWatchdog)_probe",
                    "handled": watchdogSnapshot.exceptionDeliveryProbeHandled ? "1" : "0",
                    "elapsed_ns": "\(watchdogSnapshot.lastExceptionDeliveryProbeNs)",
                ],
                state: .tampered,
                layer: 1,
                weightHint: watchdogSnapshot.exceptionDeliveryProbeHandled ? 54 : 66
            ))
        }
        if watchdogSnapshot.suspiciousThreadCount > 0 {
            signals.append(RiskSignal(
                id: "suspicious_threads_detected",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(watchdogSnapshot.suspiciousThreadCount) * 25, 85),
                evidence: ["count": "\(watchdogSnapshot.suspiciousThreadCount)", "mechanism": "mach_thread_enumeration"],
                state: .soft(confidence: 0.8),
                layer: 2,
                weightHint: 78
            ))
        }
        if watchdogSnapshot.developerDiskDetected {
            signals.append(RiskSignal(
                id: "developer_disk_mounted",
                category: "environment",
                score: 15,
                evidence: ["mechanism": "developer_tools_path_check"],
                state: .soft(confidence: 0.5),
                layer: 3,
                weightHint: 20
            ))
        }

        #if (arch(arm64) || arch(arm64e)) && !targetEnvironment(simulator)
        if cprisk_is_cntpct_clock_available() == 0 {
            signals.append(RiskSignal(
                id: "cntpct_clock_unavailable",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 42,
                evidence: ["mechanism": "cntpct_el0_probe", "detail": "hardware_clock_path_unavailable"],
                state: .soft(confidence: 0.72),
                layer: 2,
                weightHint: 62
            ))
        }

        var whiteboxProbe = cprisk_whitebox_probe_result()
        let whiteboxProbeRc = cprisk_whitebox_probe(&whiteboxProbe)
        if cprisk_whitebox_available() != 0 {
            let metaOk = (whiteboxProbe.flags & UInt32(CPRISK_WHITEBOX_PROBE_FLAG_METADATA_VALID)) != 0
            let engineOk = (whiteboxProbe.flags & UInt32(CPRISK_WHITEBOX_PROBE_FLAG_ENGINE_READY)) != 0
            if whiteboxProbeRc != 0 || !metaOk || !engineOk {
                signals.append(RiskSignal(
                    id: SignalID.whiteboxPrfProbeDegraded,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 58,
                    evidence: [
                        "probe_rc": "\(whiteboxProbeRc)",
                        "flags": "\(whiteboxProbe.flags)",
                        "abi_version": "\(whiteboxProbe.abi_version)",
                        "mechanism": "cprisk_whitebox_probe",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 76
                ))
            }
        }
        #endif

        if !planSnapshot.sectionPresent || !planSnapshot.sectionValid {
            signals.append(RiskSignal(
                id: "antidebug_plan_unavailable",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 36,
                evidence: [
                    "section_present": planSnapshot.sectionPresent ? "1" : "0",
                    "section_valid": planSnapshot.sectionValid ? "1" : "0",
                    "parse_error": "\(planSnapshot.parseError)"
                ],
                state: .soft(confidence: 0.68),
                layer: 2,
                weightHint: 50
            ))
        } else {
            let hasConsumedPlan = planSnapshot.consumeCount > 0
            let hasAppliedPolicy = planSnapshot.lastAppliedPolicyBits != 0

            if !hasConsumedPlan && !hasAppliedPolicy {
                signals.append(RiskSignal(
                    id: "antidebug_plan_not_consumed",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 34,
                    evidence: [
                        "entry_count": "\(planSnapshot.entryCount)",
                        "consume_count": "\(planSnapshot.consumeCount)",
                        "policy_union_bits": "\(planSnapshot.policyUnionBits)",
                        "last_applied_policy_bits": "\(planSnapshot.lastAppliedPolicyBits)",
                        "last_probe_bits": "\(planSnapshot.lastProbeBits)"
                    ],
                    state: .soft(confidence: 0.66),
                    layer: 2,
                    weightHint: 46
                ))
            }

            if hasConsumedPlan {
                let consumeScore = min(18 + Double(min(planSnapshot.consumeCount, 6)) * 3, 36)
                signals.append(RiskSignal(
                    id: "antidebug_plan_consumed",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: consumeScore,
                    evidence: [
                        "consume_count": "\(planSnapshot.consumeCount)",
                        "entry_count": "\(planSnapshot.entryCount)",
                        "policy_union_bits": "\(planSnapshot.policyUnionBits)",
                        "last_applied_policy_bits": "\(planSnapshot.lastAppliedPolicyBits)",
                        "last_probe_bits": "\(planSnapshot.lastProbeBits)"
                    ],
                    state: .soft(confidence: 0.72),
                    layer: 3,
                    weightHint: 40
                ))
            }

            if hasAppliedPolicy {
                let appliedBitCount = planSnapshot.lastAppliedPolicyBits.nonzeroBitCount
                let unionBitCount = planSnapshot.policyUnionBits.nonzeroBitCount
                let appliedScore = min(22 + Double(appliedBitCount * 6) + Double(min(unionBitCount, 4)), 54)
                signals.append(RiskSignal(
                    id: "antidebug_plan_policy_applied",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: appliedScore,
                    evidence: [
                        "last_applied_policy_bits": "\(planSnapshot.lastAppliedPolicyBits)",
                        "policy_union_bits": "\(planSnapshot.policyUnionBits)",
                        "entry_count": "\(planSnapshot.entryCount)",
                        "consume_count": "\(planSnapshot.consumeCount)",
                        "last_probe_bits": "\(planSnapshot.lastProbeBits)"
                    ],
                    state: .soft(confidence: 0.8),
                    layer: 2,
                    weightHint: 58
                ))
            }

            if planSnapshot.inlinePatchFailureCount > 0 || planSnapshot.inlinePatchTampered {
                signals.append(RiskSignal(
                    id: "antidebug_inline_patch_tamper",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 86,
                    evidence: [
                        "inline_patch_armed": planSnapshot.inlinePatchArmed ? "1" : "0",
                        "inline_patch_count": "\(planSnapshot.inlinePatchCount)",
                        "inline_patch_failure_count": "\(planSnapshot.inlinePatchFailureCount)",
                        "inline_patch_tampered": planSnapshot.inlinePatchTampered ? "1" : "0"
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 90
                ))
            }

            if planSnapshot.lastGateClosed ||
                planSnapshot.lastSoftFailMode ||
                planSnapshot.escalationCount > 0 ||
                planSnapshot.trapEventCount > 0 {
                let escalationSignalScore: Double
                if planSnapshot.trapEventCount > 0 || planSnapshot.escalationCount > 0 {
                    escalationSignalScore = 88
                } else if planSnapshot.lastSoftFailMode {
                    escalationSignalScore = 74
                } else {
                    escalationSignalScore = 66
                }

                signals.append(RiskSignal(
                    id: SignalID.antidebugPlanEscalated,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: escalationSignalScore,
                    evidence: [
                        "last_gate_closed": planSnapshot.lastGateClosed ? "1" : "0",
                        "last_soft_fail_mode": planSnapshot.lastSoftFailMode ? "1" : "0",
                        "escalation_count": "\(planSnapshot.escalationCount)",
                        "trap_event_count": "\(planSnapshot.trapEventCount)",
                        "last_delay_ns": "\(planSnapshot.lastDelayNs)",
                        "last_applied_policy_bits": "\(planSnapshot.lastAppliedPolicyBits)"
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 92
                ))
            }
        }

        return signals
    }
    
    // MARK: - 辅助方法
    
    /// 从方法字符串中提取分数
    private func extractScore(from method: String) -> Double {
        // 方法格式通常为 "category:method" 或 "category:method:(+score)"
        // 这里返回默认分数，实际应用中可以从配置中获取
        switch method {
        case let m where m.contains("p_traced"):
            return 30
        case let m where m.contains("parent"):
            return 25
        case let m where m.contains("timing"):
            return 20
        case let m where m.contains("exception_port"):
            return 25
        case let m where m.contains(ObfuscatedConstants.keywordFrida):
            return 35
        case let m where m.contains("signature"):
            return 30
        case let m where m.contains(ObfuscatedConstants.keywordHook):
            return 20
        default:
            return 15
        }
    }

    /// Emits a soft signal when CRiskCore reported use of libc (or arc4random) because direct-syscall paths were unavailable.
    func libcDirectSyscallFallbackSignals(from snapshot: RiskSnapshot) -> [RiskSignal] {
        libcDirectSyscallFallbackSignals(
            mask: snapshot.libcFallbackUsedMask,
            eventTotal: snapshot.libcFallbackEventTotal,
            watchdogSupported: snapshot.antiDebugWatchdogSupported
        )
    }

    /// Emits a soft signal when CRiskCore reported use of libc (or arc4random) because direct-syscall paths were unavailable.
    func libcDirectSyscallFallbackSignals(from snapshot: CPRiskKit.AntiDebugWatchdogSnapshot) -> [RiskSignal] {
        libcDirectSyscallFallbackSignals(
            mask: snapshot.libcFallbackUsedMask,
            eventTotal: snapshot.libcFallbackEventTotal,
            watchdogSupported: snapshot.supported
        )
    }

    private func libcDirectSyscallFallbackSignals(
        mask: UInt32,
        eventTotal: UInt32,
        watchdogSupported: Bool
    ) -> [RiskSignal] {
        guard mask != 0 else {
            return []
        }
        let labels = Self.libcFallbackClassLabels(mask: mask)
        let syscallSurfaceBits = mask & ~UInt32(CPRISK_LIBC_FALLBACK_USED_UNSUPPORTED_PLATFORM)
        #if targetEnvironment(simulator)
        let score: Double = 20
        let confidence: Double = 0.72
        let weightHint: Double = syscallSurfaceBits != 0 ? 24 : 12
        #else
        /* Device: direct SVC is expected; libc-only syscall surfaces are stronger tamper/hook hints than build-flavor. */
        let score: Double = syscallSurfaceBits != 0 ? 34 : 14
        let confidence: Double = syscallSurfaceBits != 0 ? 0.82 : 0.55
        let weightHint: Double = syscallSurfaceBits != 0 ? 34 : 18
        #endif
        return [
            RiskSignal(
                id: SignalID.libcDirectSyscallFallback,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: score + min(12, Double(eventTotal) * 0.25),
                evidence: [
                    "libc_fallback_used_mask": "\(mask)",
                    "mask_hex": String(mask, radix: 16),
                    "fallback_classes": labels,
                    "libc_fallback_event_total": "\(eventTotal)",
                    "watchdog_snapshot_supported": watchdogSupported ? "1" : "0",
                    "mechanism": ObfuscatedConstants.evidenceMechanismLibcDirectSyscallFallback,
                ],
                state: .soft(confidence: confidence),
                layer: 1,
                weightHint: weightHint
            ),
        ]
    }

    private static func libcFallbackClassLabels(mask: UInt32) -> String {
        let pairs: [(UInt32, String)] = [
            (UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_MPROTECT), "mprotect"),
            (UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_GETENTROPY), "getentropy"),
            (UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCTL), "sysctl"),
            (UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_STAT_PATH), "stat_path"),
            (UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO), "fd_io"),
            (UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_IDS), "ids"),
            (UInt32(CPRISK_LIBC_FALLBACK_USED_ARMOR_MPROTECT), "armor_mprotect"),
            (UInt32(CPRISK_LIBC_FALLBACK_USED_UNSUPPORTED_PLATFORM), "unsupported_platform"),
            (UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_CSOPS_UNAVAILABLE), "csops_unavailable"),
            (UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCALL_STUB_FALLBACK), "syscall_stub_fallback"),
        ]
        let knownMask = pairs.reduce(UInt32(0)) { $0 | $1.0 }
        var parts: [String] = []
        for (bit, name) in pairs where (mask & bit) != 0 {
            parts.append(name)
        }
        if (mask & ~knownMask) != 0 {
            parts.append("reserved")
        }
        if parts.isEmpty {
            return "unknown_0x\(String(mask, radix: 16))"
        }
        return parts.joined(separator: ",")
    }

    func antiDebugWatchdogSignals(from snapshot: CPRiskKit.AntiDebugWatchdogSnapshot) -> [RiskSignal] {
        guard snapshot.supported, snapshot.hasAnyAnomaly else {
            return []
        }

        let tracedFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED)) != 0
        let denyAttachFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH)) != 0
        let exceptionPortFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT)) != 0
        let exceptionQueryFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_QUERY)) != 0
        let softwareBreakpointFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP)) != 0
        let instantReturnPatchFlag =
            (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH)) != 0
        let exceptionDeliveryTimeoutFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT)) != 0
        let peerStallFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL)) != 0
        let shadowStackFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK)) != 0
        let dbiMarkerFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_MARKER)) != 0
        let dbiVmTraceCorrelFlag =
            (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL)) != 0
        let timingSidechannelFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL)) != 0
        let traceCrosscheckFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACE_CROSSCHECK)) != 0
        let dyldInjectionFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION)) != 0
        let denyAttachVerifyFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY)) != 0
        let amfiCsFlagsFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS)) != 0
        let getTaskAllowFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW)) != 0
        let guardPageFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GUARD_PAGE)) != 0
        let functionPrologueFlag =
            (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE)) != 0
        let pacThreadEntryFlag =
            (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_PAC_THREAD_ENTRY)) != 0
        let vmImageLayoutDriftFlag =
            (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_IMAGE_WHITELIST)) != 0

        var maxScore = 0.0
        var anomalyKinds: [String] = []
        var signals: [RiskSignal] = []

        if tracedFlag || snapshot.lastTraced {
            let score = 95.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("traced")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogTraced,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "iteration_count": "\(snapshot.iterationCount)",
                        "traced_event_count": "\(snapshot.tracedEventCount)",
                        "running": "\(snapshot.running)",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 98
                )
            )
        }

        if denyAttachFlag {
            let score = 70.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("deny_attach")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogDenyAttachFailed,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "result": "\(snapshot.lastDenyAttachResult)",
                        "errno": "\(snapshot.lastDenyAttachErrno)",
                        "error_count": "\(snapshot.denyAttachErrorCount)",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 92
                )
            )
        }

        if exceptionPortFlag {
            let score = snapshot.lastExceptionStartupRaceDetected ? 92.0 : (snapshot.lastExceptionHijackDetected ? 88.0 : 72.0)
            maxScore = max(maxScore, score)
            anomalyKinds.append("exception_port")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogExceptionPort,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "healthy": "\(snapshot.lastExceptionPortHealthy)",
                        "reclaim_attempted": "\(snapshot.lastExceptionReclaimAttempted)",
                        "hijack_detected": "\(snapshot.lastExceptionHijackDetected)",
                        "early_phase_captured": "\(snapshot.lastExceptionEarlyPhaseCaptured)",
                        "startup_race_detected": "\(snapshot.lastExceptionStartupRaceDetected)",
                        "verify_count": "\(snapshot.lastExceptionVerifyCount)",
                        "reclaim_count": "\(snapshot.lastExceptionReclaimCount)",
                        "startup_delta_ns": "\(snapshot.lastExceptionStartupDeltaNs)",
                        "register_kr": "\(snapshot.lastExceptionRegisterKernReturn)",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 95
                )
            )
        }

        if snapshot.lastExceptionStartupRaceDetected {
            let score = 91.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("exception_startup_race")
            signals.append(
                RiskSignal(
                    id: SignalID.fridaExceptionPortStartupRace,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "early_phase_captured": "\(snapshot.lastExceptionEarlyPhaseCaptured)",
                        "startup_race_detected": "true",
                        "verify_count": "\(snapshot.lastExceptionVerifyCount)",
                        "reclaim_count": "\(snapshot.lastExceptionReclaimCount)",
                        "startup_delta_ns": "\(snapshot.lastExceptionStartupDeltaNs)",
                        "port_healthy": "\(snapshot.lastExceptionPortHealthy)",
                        "hijack_detected": "\(snapshot.lastExceptionHijackDetected)",
                        "reclaim_attempted": "\(snapshot.lastExceptionReclaimAttempted)",
                        "register_kr": "\(snapshot.lastExceptionRegisterKernReturn)",
                        "query_kr": "\(snapshot.lastExceptionQueryKernReturn)",
                        "mechanism": "tls_constructor_exception_port_baseline_drift",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 96
                )
            )
        }

        if exceptionQueryFlag {
            let score = 55.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("exception_query")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogExceptionQuery,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "query_succeeded": "\(snapshot.lastExceptionQuerySucceeded)",
                        "query_kr": "\(snapshot.lastExceptionQueryKernReturn)",
                        "exception_anomaly_count": "\(snapshot.exceptionAnomalyCount)",
                    ],
                    state: .soft(confidence: 0.85),
                    layer: 2,
                    weightHint: 78
                )
            )
        }

        if traceCrosscheckFlag {
            let score = 66.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("trace_crosscheck")
            signals.append(
                RiskSignal(
                    id: "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_trace_crosscheck",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "anomaly_flags": "\(snapshot.anomalyFlags)",
                        "mechanism": "unix_sysctl_vs_mach_crosscheck"
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 82
                )
            )
        }

        if dyldInjectionFlag || snapshot.lastDyldInjectionFlags != 0 || snapshot.dyldInjectionAnomalyCount > 0 {
            let score = snapshot.lastDyldInjectionFlags != 0 ? 84.0 : 68.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("dyld_injection")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogDyldInjection,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "dyld_injection_flags": "\(snapshot.lastDyldInjectionFlags)",
                        "dyld_injection_anomaly_count": "\(snapshot.dyldInjectionAnomalyCount)",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 90
                )
            )
        }

        if denyAttachVerifyFlag || snapshot.lastDenyAttachVerifyBits != 0 || snapshot.denyAttachVerifyAnomalyCount > 0 {
            let score = snapshot.lastDenyAttachVerifyBits != 0 ? 74.0 : 58.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("deny_attach_verify")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogDenyAttachVerify,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "deny_attach_verify_bits": "\(snapshot.lastDenyAttachVerifyBits)",
                        "deny_attach_verify_anomaly_count": "\(snapshot.denyAttachVerifyAnomalyCount)",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 84
                )
            )
        }

        if amfiCsFlagsFlag || snapshot.lastAmfiProbeBits != 0 || snapshot.amfiCsFlagsAnomalyCount > 0 {
            let score = snapshot.lastAmfiProbeBits != 0 ? 88.0 : 70.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("amfi_cs_flags")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogAMFICsFlags,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "amfi_probe_bits": "\(snapshot.lastAmfiProbeBits)",
                        "csops_status_flags": "\(snapshot.lastCsopsStatusFlags)",
                        "amfi_csflags_anomaly_count": "\(snapshot.amfiCsFlagsAnomalyCount)",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 92
                )
            )
        }

        if getTaskAllowFlag || snapshot.lastGetTaskAllowSuspect || snapshot.getTaskAllowAnomalyCount > 0 {
            let score = snapshot.lastGetTaskAllowSuspect ? 92.0 : 76.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("get_task_allow")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogGetTaskAllow,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "get_task_allow_suspect": snapshot.lastGetTaskAllowSuspect ? "1" : "0",
                        "get_task_allow_anomaly_count": "\(snapshot.getTaskAllowAnomalyCount)",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 94
                )
            )
        }

        if guardPageFlag {
            let score = 82.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("guard_page")
            signals.append(
                RiskSignal(
                    id: "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_guard_page",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "signal_probe_anomaly_count": "\(snapshot.signalProbeAnomalyCount)",
                        "mechanism": "anti_dump_guard_page_sigbus",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 88
                )
            )
        }

        if pacThreadEntryFlag {
            let score = 91.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("pac_thread_entry")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogPacThreadEntry,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "mechanism": "pthread_pac_thunk_auth_failed",
                        "anomaly_flags": "\(snapshot.anomalyFlags)",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 93
                )
            )
        }

        if vmImageLayoutDriftFlag {
            let score = 78.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("vm_image_layout_drift")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogVmImageLayoutDrift,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "mechanism": "dyld_layout_digest_or_mem_guard_image_tick",
                        "vm_mprotect_cc": "\(snapshot.vmMprotectCrosscheckMismatchTotal)",
                        "vm_mprotect_mach": "\(snapshot.vmMprotectMachTrapMismatchTotal)",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 84
                )
            )
        }

        if functionPrologueFlag || snapshot.prologueIntegrityAnomalyCount > 0 {
            let mask = snapshot.lastPrologueFailMask
            let objcBit = UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OBJC_MSGSEND)
            let dyldIcBit = UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DYLD_IMAGE_COUNT)
            let score = 90.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("function_prologue")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogCriticalHookSurface,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "mechanism": "memcmp_prologue_baseline",
                        "prologue_integrity_anomaly_count": "\(snapshot.prologueIntegrityAnomalyCount)",
                        "last_prologue_fail_mask": "\(mask)",
                        "fail_objc_msgsend": ((mask & objcBit) != 0) ? "1" : "0",
                        "fail_dyld_image_count": ((mask & dyldIcBit) != 0) ? "1" : "0",
                        "fail_dlsym": ((mask & UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DLSYM)) != 0) ? "1" : "0",
                        "fail_pthread_create": ((mask & UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_PTHREAD_CREATE)) != 0) ? "1" : "0",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 94
                )
            )
        }

        if softwareBreakpointFlag || snapshot.softwareBreakpointDetected {
            let score = snapshot.softwareBreakpointDetected ? 58.0 : 34.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("software_breakpoint")
            signals.append(
                RiskSignal(
                    id: "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_software_breakpoint",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "detected": snapshot.softwareBreakpointDetected ? "1" : "0",
                        "anomaly_count": "\(snapshot.softwareBreakpointAnomalyCount)",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 72
                )
            )
        }

        if instantReturnPatchFlag {
            let score = 62.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("instant_return_patch")
            signals.append(
                RiskSignal(
                    id: "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_instant_return_patch",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "mechanism": "arm64_nop_ret_prefix",
                        "scope": "key_symbols",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 78
                )
            )
        }

        if exceptionDeliveryTimeoutFlag || snapshot.exceptionDeliveryTimeoutDetected {
            let score = snapshot.exceptionDeliveryProbeHandled ? 38.0 : 52.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("exception_delivery_timeout")
            signals.append(
                RiskSignal(
                    id: "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_exception_delivery_timeout",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "detected": snapshot.exceptionDeliveryTimeoutDetected ? "1" : "0",
                        "handled": snapshot.exceptionDeliveryProbeHandled ? "1" : "0",
                        "elapsed_ns": "\(snapshot.lastExceptionDeliveryProbeNs)",
                        "anomaly_count": "\(snapshot.exceptionDeliveryTimeoutAnomalyCount)",
                    ],
                    state: .soft(confidence: snapshot.exceptionDeliveryProbeHandled ? 0.8 : 0.9),
                    layer: 2,
                    weightHint: snapshot.exceptionDeliveryProbeHandled ? 58 : 76
                )
            )
        }

        if peerStallFlag {
            let score = 76.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("\(ObfuscatedConstants.keywordWatchdog)_peer_stall")
            signals.append(
                RiskSignal(
                    id: "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_peer_stall",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "peer_stall": "1",
                        "thread_active": snapshot.threadActive ? "1" : "0",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 90
                )
            )
        }

        if shadowStackFlag {
            let score = 72.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("shadow_stack")
            signals.append(
                RiskSignal(
                    id: "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_shadow_stack",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "shadow_stack_mismatch": "1",
                        "shadow_stack_anomaly_count": "\(snapshot.shadowStackAnomalyCount)",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 88
                )
            )
        }

        if dbiMarkerFlag || snapshot.dbiDetected {
            let score = snapshot.dbiDetected ? 68.0 : 54.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("dbi_marker")
            signals.append(
                RiskSignal(
                    id: "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_dbi_marker",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "detected": snapshot.dbiDetected ? "1" : "0",
                        "marker_flags": "\(snapshot.dbiMarkerFlags)",
                        "dbi_anomaly_count": "\(snapshot.dbiAnomalyCount)",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 84
                )
            )
        }

        if dbiVmTraceCorrelFlag
            || (snapshot.dbiMarkerFlags & UInt32(CPRISK_DBI_MARKER_STALKER_CORREL)) != 0
            || (snapshot.dbiMarkerFlags & UInt32(CPRISK_DBI_MARKER_ANON_EXEC_SLAB)) != 0 {
            let score = (snapshot.dbiMarkerFlags & UInt32(CPRISK_DBI_MARKER_STALKER_CORREL)) != 0 ? 78.0 : 70.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("dbi_vm_trace_correl")
            signals.append(
                RiskSignal(
                    id: "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_dbi_vm_trace_correl",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "marker_flags": "\(snapshot.dbiMarkerFlags)",
                        "stalker_correl": ((snapshot.dbiMarkerFlags & UInt32(CPRISK_DBI_MARKER_STALKER_CORREL)) != 0) ? "1" : "0",
                        "anon_exec_slab": ((snapshot.dbiMarkerFlags & UInt32(CPRISK_DBI_MARKER_ANON_EXEC_SLAB)) != 0) ? "1" : "0",
                        "suspicious_thread_count": "\(snapshot.suspiciousThreadCount)",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 93
                )
            )
        }

        if timingSidechannelFlag || snapshot.timingAnomalyFlags != 0 {
            let isHard = snapshot.timingProbeMaxNs > snapshot.timingProbeThresholdNs
                && snapshot.timingProbeThresholdNs > 0
            let cryptoTraceSlow =
                (snapshot.timingAnomalyFlags & UInt32(CPRISK_TIMING_ANOMALY_CRYPTO_TRACE)) != 0
            let cryptoTraceSkew =
                (snapshot.timingAnomalyFlags & UInt32(CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_SKEW)) != 0
            let cryptoTraceInvariant =
                (snapshot.timingAnomalyFlags & UInt32(CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_INVARIANT)) != 0
            let score = isHard ? 62.0 : 46.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("timing_sidechannel")
            signals.append(
                RiskSignal(
                    id: "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_timing_sidechannel",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: score,
                    evidence: [
                        "timing_anomaly_flags": "\(snapshot.timingAnomalyFlags)",
                        "timing_median_ns": "\(snapshot.timingProbeMedianNs)",
                        "timing_max_ns": "\(snapshot.timingProbeMaxNs)",
                        "timing_threshold_ns": "\(snapshot.timingProbeThresholdNs)",
                        "timing_anomaly_count": "\(snapshot.timingAnomalyCount)",
                        "crypto_trace_slow": cryptoTraceSlow ? "1" : "0",
                        "crypto_trace_cnt_mach_skew": cryptoTraceSkew ? "1" : "0",
                        "crypto_trace_invariant": cryptoTraceInvariant ? "1" : "0",
                    ],
                    state: isHard ? .tampered : .soft(confidence: 0.78),
                    layer: 2,
                    weightHint: isHard ? 78 : 64
                )
            )
        }

        signals.insert(
            RiskSignal(
                id: SignalID.antiDebugWatchdogAnomaly,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: maxScore,
                evidence: [
                    "anomaly_flags": "\(snapshot.anomalyFlags)",
                    "anomaly_kinds": anomalyKinds.joined(separator: ","),
                    "thread_active": "\(snapshot.threadActive)",
                    "interval_seconds": "\(snapshot.intervalSeconds)",
                    "last_check_monotonic_ns": "\(snapshot.lastCheckMonotonicNs)",
                    "software_bp_anomaly_count": "\(snapshot.softwareBreakpointAnomalyCount)",
                    "exception_delivery_timeout_anomaly_count": "\(snapshot.exceptionDeliveryTimeoutAnomalyCount)",
                    "dbi_marker_flags": "\(snapshot.dbiMarkerFlags)",
                    "dbi_anomaly_count": "\(snapshot.dbiAnomalyCount)",
                    "timing_anomaly_flags": "\(snapshot.timingAnomalyFlags)",
                    "timing_median_ns": "\(snapshot.timingProbeMedianNs)",
                    "timing_max_ns": "\(snapshot.timingProbeMaxNs)",
                    "timing_threshold_ns": "\(snapshot.timingProbeThresholdNs)",
                    "timing_anomaly_count": "\(snapshot.timingAnomalyCount)",
                    "crypto_trace_slow": ((snapshot.timingAnomalyFlags & UInt32(CPRISK_TIMING_ANOMALY_CRYPTO_TRACE)) != 0) ? "1" : "0",
                    "crypto_trace_cnt_mach_skew": ((snapshot.timingAnomalyFlags & UInt32(CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_SKEW)) != 0) ? "1" : "0",
                    "crypto_trace_invariant": ((snapshot.timingAnomalyFlags & UInt32(CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_INVARIANT)) != 0) ? "1" : "0",
                    "dyld_injection_flags": "\(snapshot.lastDyldInjectionFlags)",
                    "dyld_injection_anomaly_count": "\(snapshot.dyldInjectionAnomalyCount)",
                    "deny_attach_verify_bits": "\(snapshot.lastDenyAttachVerifyBits)",
                    "deny_attach_verify_anomaly_count": "\(snapshot.denyAttachVerifyAnomalyCount)",
                    "amfi_probe_bits": "\(snapshot.lastAmfiProbeBits)",
                    "amfi_csflags_anomaly_count": "\(snapshot.amfiCsFlagsAnomalyCount)",
                    "get_task_allow_suspect": snapshot.lastGetTaskAllowSuspect ? "1" : "0",
                    "get_task_allow_anomaly_count": "\(snapshot.getTaskAllowAnomalyCount)",
                    "vm_mprotect_crosscheck_mismatch_total": "\(snapshot.vmMprotectCrosscheckMismatchTotal)",
                    "vm_mprotect_mach_trap_mismatch_total": "\(snapshot.vmMprotectMachTrapMismatchTotal)",
                    "prologue_integrity_anomaly_count": "\(snapshot.prologueIntegrityAnomalyCount)",
                    "last_prologue_fail_mask": "\(snapshot.lastPrologueFailMask)",
                ],
                state: .tampered,
                layer: 2,
                weightHint: 94
            ),
            at: 0
        )

        return signals
    }

    internal func fridaCorrelationSignals(from signals: [RiskSignal]) -> [RiskSignal] {
        let familyRules: [(family: String, threshold: Double, predicate: (RiskSignal) -> Bool)] = [
            (
                "runtime_surface",
                22,
                {
                    $0.id == ObfuscatedConstants.signalFridaDetected
                        || $0.id.hasPrefix("frida_port_")
                        || $0.id.hasPrefix("frida_proto_")
                        || $0.id.hasPrefix("frida_anom_proto_")
                        || $0.id.hasPrefix("frida_listen_")
                        || $0.id.hasPrefix("frida_environment_")
                        || $0.id.hasPrefix("frida_memsig_")
                        || $0.id.hasPrefix("frida_runtime_")
                        || $0.id.hasPrefix("frida_behavior_")
                }
            ),
            (
                "module_surface",
                18,
                {
                    [
                        SignalID.fridaModuleDetected,
                        SignalID.fridaModuleImage,
                        SignalID.fridaModuleSection,
                        SignalID.fridaModuleString,
                        SignalID.fridaModuleTrampoline,
                    ].contains($0.id)
                }
            ),
            (
                "thread_surface",
                18,
                {
                    $0.id == ObfuscatedConstants.signalThreadAnomaly
                        || $0.id == ObfuscatedConstants.signalFridaExceptionPort
                        || $0.id == SignalID.fridaExceptionPortStartupRace
                }
            ),
            (
                "socket_surface",
                16,
                {
                    $0.id == ObfuscatedConstants.signalFridaUnixSocket
                        || $0.id == ObfuscatedConstants.signalFridaTimingAnomaly
                        || $0.id == ObfuscatedConstants.signalFridaStalkerAmplified
                }
            ),
            (
                "exec_surface",
                16,
                {
                    $0.id == ObfuscatedConstants.signalFridaJSEngineHeap
                        || $0.id == ObfuscatedConstants.signalFridaStalkerJit
                        || $0.id == SignalID.stalkerJitRWX
                        || $0.id == SignalID.rwxJitCoexistence
                }
            ),
            (
                "patch_surface",
                24,
                {
                    $0.id == SignalID.antiDebugWatchdogCriticalHookSurface
                        || $0.id.hasPrefix("frida_patch_")
                        || $0.id == ObfuscatedConstants.signalLibcInlineHookDetected
                        || $0.id == SignalID.fridaModuleTrampoline
                        || $0.id == "dyld_interpose_detected"
                        || $0.id == SwiftRuntimeIntegrityDetector.metadataSignalID
                        || $0.id == SwiftRuntimeIntegrityDetector.witnessSignalID
                        || $0.id == SwiftRuntimeIntegrityDetector.closureSignalID
                        || $0.id == SwiftRuntimeIntegrityDetector.existentialSignalID
                }
            ),
            (
                "loader_surface",
                18,
                {
                    [
                        SignalID.antiDebugWatchdogDyldInjection,
                        SignalID.dylibInjectImageCountLow,
                        SignalID.ifaceSpawnPathDivergence,
                        "dyld_env_abuse",
                        "dyld_image_overload",
                        "dyld_monitor_suspicious_injection",
                        "dyld_monitor_gen_anomaly",
                        "dyld_monitor_image_removed",
                        "dyld_monitor_silent_mutation",
                        "dylib_inject_image_count",
                        "dylib_inject_env_insert",
                        "dylib_inject_out_of_sandbox",
                        "dylib_inject_rootless_jailbreak",
                        "dylib_inject_suspicious_keyword",
                    ].contains($0.id)
                }
            ),
        ]

        var familyDrivers: [String: RiskSignal] = [:]
        for rule in familyRules {
            guard let strongest = strongestSignal(in: signals, threshold: rule.threshold, predicate: rule.predicate) else {
                continue
            }
            familyDrivers[rule.family] = strongest
        }

        let families = familyDrivers.keys.sorted()
        guard families.count >= 2 else { return [] }

        let behavioralFamilies = families.filter {
            ["thread_surface", "socket_surface", "exec_surface", "patch_surface", "loader_surface"].contains($0)
        }
        guard !behavioralFamilies.isEmpty else { return [] }

        let matched = families.compactMap { familyDrivers[$0] }
        let score = min(
            58,
            26
                + Double(families.count) * 6
                + Double(behavioralFamilies.count) * 4
                + (families.contains("patch_surface") ? 6 : 0)
        )
        let confidence = min(0.92, 0.58 + Double(families.count) * 0.08 + Double(behavioralFamilies.count) * 0.04)
        let consensusState: RiskSignalState = families.count >= 3 && behavioralFamilies.count >= 2
            ? .tampered
            : .soft(confidence: confidence)

        return [
            RiskSignal(
                id: SignalID.fridaRuntimeConsensus,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: score,
                evidence: [
                    "mode": "frida_multi_surface_runtime_consensus",
                    "families": families.joined(separator: ","),
                    "behavioral_families": behavioralFamilies.joined(separator: ","),
                    "matched_signals": matched.map(\.id).joined(separator: ","),
                    "family_count": "\(families.count)",
                    "behavioral_family_count": "\(behavioralFamilies.count)",
                ],
                state: consensusState,
                layer: 3,
                weightHint: min(88, score + 22)
            ),
        ]
    }

    internal func antiDebugStrategySignals(from signals: [RiskSignal]) -> [RiskSignal] {
        let familyRules: [(family: String, threshold: Double, predicate: (RiskSignal) -> Bool)] = [
            (
                "debugger_surface",
                18,
                {
                    $0.id == SignalID.debuggerDetected
                        || $0.id.hasPrefix("debugger_parent_")
                        || $0.id.hasPrefix("debugger_port_")
                }
            ),
            (
                "watchdog_surface",
                20,
                {
                    [
                        SignalID.antiDebugWatchdogAnomaly,
                        SignalID.antiDebugWatchdogTraced,
                        SignalID.antiDebugWatchdogDenyAttachFailed,
                        SignalID.antiDebugWatchdogExceptionPort,
                        SignalID.antiDebugWatchdogExceptionQuery,
                        SignalID.antiDebugWatchdogDyldInjection,
                        SignalID.antiDebugWatchdogDenyAttachVerify,
                        SignalID.antiDebugWatchdogAMFICsFlags,
                        SignalID.antiDebugWatchdogGetTaskAllow,
                        SignalID.antiDebugWatchdogCriticalHookSurface,
                        SignalID.antiDebugWatchdogPacThreadEntry,
                        SignalID.antiDebugWatchdogVmImageLayoutDrift,
                    ].contains($0.id)
                }
            ),
            (
                "breakpoint_surface",
                18,
                {
                    [
                        SignalID.softwareBreakpointDetected,
                        SignalID.hardwareBreakpointDetected,
                        SignalID.exceptionDeliveryTimeout,
                        SignalID.csopsDebugged,
                        SignalID.signalProbeDebugger,
                    ].contains($0.id)
                }
            ),
            (
                "plan_surface",
                18,
                {
                    [
                        SignalID.antidebugPlanEscalated,
                        "antidebug_plan_policy_applied",
                        "antidebug_inline_patch_tamper",
                    ].contains($0.id)
                }
            ),
            (
                "signing_surface",
                18,
                {
                    [
                        ObfuscatedConstants.signalAppSigningIdentityTampered,
                        ObfuscatedConstants.signalAppSigningBaselineChanged,
                        "app_get_task_allow_enabled",
                        "code_signature_invalid",
                    ].contains($0.id)
                }
            ),
            (
                "syscall_surface",
                16,
                {
                    [
                        SignalID.libcDirectSyscallFallback,
                        ObfuscatedConstants.signalMemoryProtectionTampered,
                        ObfuscatedConstants.signalMemoryProtectionSemanticBypass,
                    ].contains($0.id)
                }
            ),
        ]

        var familyDrivers: [String: RiskSignal] = [:]
        for rule in familyRules {
            guard let strongest = strongestSignal(in: signals, threshold: rule.threshold, predicate: rule.predicate) else {
                continue
            }
            familyDrivers[rule.family] = strongest
        }

        let families = familyDrivers.keys.sorted()
        guard families.count >= 2 else { return [] }
        let matched = families.compactMap { familyDrivers[$0] }
        let confidence = min(0.90, 0.56 + Double(families.count) * 0.09)
        let score = min(48, 20 + Double(families.count) * 7)
        let state: RiskSignalState = families.count >= 3 ? .tampered : .soft(confidence: confidence)

        return [
            RiskSignal(
                id: SignalID.antiDebugRuntimeConsensus,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: score,
                evidence: [
                    "mode": "anti_debug_multi_strategy_consensus",
                    "families": families.joined(separator: ","),
                    "family_count": "\(families.count)",
                    "matched_signals": matched.map(\.id).joined(separator: ","),
                    "driver_confidence": String(format: "%.2f", confidence),
                ],
                state: state,
                layer: 3,
                weightHint: min(84, score + 20)
            ),
        ]
    }

    internal func signingChainSignals(from signals: [RiskSignal]) -> [RiskSignal] {
        let codeSignature = strongestSignal(in: signals, threshold: 22) {
            [
                "code_signature_invalid",
                "signature_invalid",
                "signature_resigned",
                "signature_abnormal_permissions",
                "sdk_code_signature_missing",
            ].contains($0.id)
        }
        let signingIdentity = strongestSignal(in: signals, threshold: 18) {
            [
                ObfuscatedConstants.signalAppSigningIdentityTampered,
                ObfuscatedConstants.signalAppSigningBaselineChanged,
                "app_identifier_bundle_mismatch",
                "app_team_identifier_mismatch",
                "app_bundle_identifier_mismatch",
                "app_get_task_allow_enabled",
                "app_identifier_malformed",
                "app_bundle_identifier_missing",
            ].contains($0.id)
        }

        guard let codeSignature, let signingIdentity else { return [] }

        let tamperedDrivers = [codeSignature, signingIdentity].filter { $0.state == .tampered }.count
        let score = min(
            56,
            30 + max(codeSignature.score, signingIdentity.score) * 0.2 + Double(tamperedDrivers) * 6
        )
        let confidence = min(
            0.94,
            0.72 + Double(tamperedDrivers) * 0.10 + (signingIdentity.id == ObfuscatedConstants.signalAppSigningBaselineChanged ? 0.04 : 0)
        )
        let state: RiskSignalState = tamperedDrivers >= 1 ? .tampered : .soft(confidence: confidence)

        return [
            RiskSignal(
                id: SignalID.signingChainConsensus,
                category: "integrity",
                score: score,
                evidence: [
                    "mode": "code_signature_signing_identity_consensus",
                    "matched_signals": [codeSignature.id, signingIdentity.id].joined(separator: ","),
                    "tampered_driver_count": "\(tamperedDrivers)",
                    "code_signature_driver": codeSignature.id,
                    "signing_identity_driver": signingIdentity.id,
                ],
                state: state,
                layer: 3,
                weightHint: min(88, score + 24)
            ),
        ]
    }

    private func strongestSignal(
        in signals: [RiskSignal],
        threshold: Double,
        predicate: (RiskSignal) -> Bool
    ) -> RiskSignal? {
        signals
            .filter { predicate($0) && (($0.state == .tampered) || $0.score >= threshold) }
            .max { lhs, rhs in
                if lhs.score == rhs.score {
                    return lhs.weightHint < rhs.weightHint
                }
                return lhs.score < rhs.score
            }
    }

    /// Lightweight multi-family consensus; `internal` for `@testable` regression tests.
    func crossConsistencySignals(from signals: [RiskSignal]) -> [RiskSignal] {
        let familyRules: [(family: String, ids: Set<String>, threshold: Double)] = [
            ("pac", [SignalID.pacDisabled, SignalID.pacPointerInvalid], 42),
            (ObfuscatedConstants.keywordVMRemap, [SignalID.vmRemapSharedAnonymous, SignalID.vmRemapImageAlias], 42),
            (ObfuscatedConstants.keywordTaskPort, [SignalID.taskPortExceptionHijack, SignalID.taskPortRightsAnomaly], 32),
            (
                "dyld_shared_cache",
                [
                    SignalID.dyldSharedCacheIntegrity,
                    SignalID.dyldSharedCacheUUIDMismatch,
                    SignalID.dyldSharedCacheSlideMismatch,
                    SignalID.dyldSharedCacheSymbolMismatch,
                ],
                36
            ),
            (
                "dyld_topology",
                [
                    "dyld_interpose_detected",
                    "dyld_env_abuse",
                    "dyld_image_overload",
                    SignalID.dylibInjectImageCountLow,
                    SignalID.antiDebugWatchdogDyldInjection,
                    "dyld_monitor_suspicious_injection",
                    "dyld_monitor_gen_anomaly",
                    "dyld_monitor_image_removed",
                    "dyld_monitor_silent_mutation",
                    "dylib_inject_image_count",
                    "dylib_inject_env_insert",
                    "dylib_inject_out_of_sandbox",
                    "dylib_inject_rootless_jailbreak",
                    "dylib_inject_suspicious_keyword",
                    SignalID.ifaceSpawnPathDivergence,
                ],
                28
            ),
            ("lldb_jit", [SignalID.lldbJitSmallRWX], 36),
        ]

        var familyDrivers: [String: RiskSignal] = [:]
        for rule in familyRules {
            let matchedSignals = signals.filter {
                rule.ids.contains($0.id) && (($0.state == .tampered) || ($0.score >= rule.threshold))
            }
            guard let strongest = matchedSignals.max(by: { lhs, rhs in
                if lhs.score == rhs.score {
                    return lhs.weightHint < rhs.weightHint
                }
                return lhs.score < rhs.score
            }) else {
                continue
            }
            familyDrivers[rule.family] = strongest
        }

        let families = familyDrivers.keys.sorted()
        let matched = families.compactMap { familyDrivers[$0] }
        guard families.count >= 2 else { return [] }

        let layers = Set(matched.compactMap(\.layer))
        let averageDriverScore = matched.reduce(0.0) { $0 + $1.score } / Double(matched.count)
        let hasLayer1 = layers.contains(1)
        let confidence = min(0.86, 0.52 + Double(families.count) * 0.08 + (hasLayer1 ? 0.04 : 0))
        let score = min(20 + Double(families.count) * 5 + max(0, averageDriverScore - 40) * 0.10, 44)

        return [
            RiskSignal(
                id: "multi_path_consistency_consensus",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: score,
                evidence: [
                    "mode": "lightweight_runtime_family_consensus",
                    "matched_signals": matched.map(\.id).joined(separator: ","),
                    "family_count": "\(families.count)",
                    "families": families.joined(separator: ","),
                    "average_driver_score": String(format: "%.2f", averageDriverScore),
                    "distinct_layers": "\(layers.count)",
                    "driver_confidence": String(format: "%.2f", confidence)
                ],
                state: .soft(confidence: confidence),
                layer: 3,
                weightHint: min(64.0, score + 14.0)
            )
        ]
    }

    /// 在 `miePartial` / `mieFull` 时对少数高价值抗注入/内存族信号做**小幅**加分，并写入 `device_mie_level` 供服务端解释。
    private func applyMiePostureWeighting(_ signals: [RiskSignal]) -> [RiskSignal] {
        guard configuration.enableMIEPosture else { return signals }
        guard let mie = signals.first(where: { $0.id == SignalID.miePosture }),
              let raw = mie.evidence["mie_level"] else {
            return signals
        }
        return signals.map { signal in
            var ev = signal.evidence
            if ev["device_mie_level"] == nil {
                ev["device_mie_level"] = raw
            }
            guard raw == MIEPostureDetector.Level.miePartial.rawValue || raw == MIEPostureDetector.Level.mieFull.rawValue else {
                return RiskSignal(
                    id: signal.id,
                    category: signal.category,
                    score: signal.score,
                    evidence: ev,
                    state: signal.state,
                    layer: signal.layer,
                    weightHint: signal.weightHint
                )
            }
            guard Self.mieBoostSignalIDs.contains(signal.id) else {
                return RiskSignal(
                    id: signal.id,
                    category: signal.category,
                    score: signal.score,
                    evidence: ev,
                    state: signal.state,
                    layer: signal.layer,
                    weightHint: signal.weightHint
                )
            }
            let deltaScore: Double = raw == MIEPostureDetector.Level.mieFull.rawValue ? 4 : 2
            let deltaHint: Double = raw == MIEPostureDetector.Level.mieFull.rawValue ? 2 : 1
            return RiskSignal(
                id: signal.id,
                category: signal.category,
                score: min(100, signal.score + deltaScore),
                evidence: ev,
                state: signal.state,
                layer: signal.layer,
                weightHint: signal.weightHint + deltaHint
            )
        }
    }

    private static let mieBoostSignalIDs: Set<String> = [
        SignalID.fridaModuleDetected,
        SignalID.fridaModuleImage,
        SignalID.fridaModuleSection,
        SignalID.fridaModuleString,
        SignalID.pacDisabled,
        SignalID.pacPointerInvalid,
        SignalID.vmRemapSharedAnonymous,
        SignalID.vmRemapImageAlias,
        SignalID.taskPortExceptionHijack,
        SignalID.taskPortRightsAnomaly,
        ObfuscatedConstants.signalMemoryProtectionTampered,
        ObfuscatedConstants.signalMemoryProtectionSemanticBypass,
        SignalID.lldbJitSmallRWX,
        SignalID.stalkerJitRWX,
        SignalID.rwxJitCoexistence,
        "rwx_anonymous",
        "anonymous_executable_memory",
        "frida_detected",
        "memory_integrity_violated",
        "text_segment_tampered",
    ]
}

// MARK: - 便捷扩展

extension AntiTamperingSignalProvider {
    
    /// 创建高敏感度配置（严格检测）
    public static func strictConfiguration() -> Configuration {
        var config = Configuration()
        config.enableAntiTampering = true
        config.enableDebugger = true
        config.enableFrida = true
        config.enableCodeSignature = true
        config.enableAppSigningIdentity = true
        config.enableMemoryIntegrity = true
        config.enableMIEPosture = true
        config.minScoreThreshold = 0  // 不过滤任何信号
        return config
    }
    
    /// 创建性能优先配置（只检测关键项）
    public static func performanceConfiguration() -> Configuration {
        var config = Configuration()
        config.enableAntiTampering = true
        config.enableDebugger = true
        config.enableFrida = true
        config.enableCodeSignature = false  // 跳过较慢的签名验证
        config.enableAppSigningIdentity = true  // entitlement/bundle 校验开销低，性能模式保留
        config.enableMemoryIntegrity = false  // 跳过较慢的内存检查
        config.enableVMRemapDetect = false
        config.enableLLDBJITDetect = false
        config.enableSystemLibrarySegmentLayoutDetect = false
        config.enableAntiDebugWatchdog = true
        config.enableMIEPosture = true
        config.minScoreThreshold = 15  // 过滤低分信号
        return config
    }
}

// MARK: - JailbreakEngine 集成

/// JailbreakConfig 扩展，支持反篡改检测
extension JailbreakConfig {
    
    /// 创建包含反篡改检测的配置
    public static func withAntiTampering(
        threshold: Double = 30,
        enableAntiTampering: Bool = true,
        enableDebugger: Bool = true,
        enableFrida: Bool = true
    ) -> JailbreakConfig {
        let config = JailbreakConfig(
            enableFileDetect: true,
            enableDyldDetect: true,
            enableEnvDetect: true,
            enableSysctlDetect: true,
            enableSchemeDetect: true,
            enableHookDetect: true,
            threshold: threshold
        )
        
        // 存储反篡改配置（通过 extras 或关联对象）
        // 这里简化处理，实际使用时可以通过配置系统传递
        
        return config
    }
}
