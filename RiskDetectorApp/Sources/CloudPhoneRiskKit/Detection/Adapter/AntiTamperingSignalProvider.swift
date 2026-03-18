import CRiskCore
import Foundation

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

    public let id = "anti_tampering"
    
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
        var enableLibcPrologueGuard: Bool = true
        var enableDyldImageMonitor: Bool = true
        var enableDylibInjectionDetect: Bool = true
        var enableAntiDebugWatchdog: Bool = true
        var minScoreThreshold: Double = 0
        
        public static let `default` = Configuration()
    }
    
    private let configuration: Configuration
    private static let randomizedDetectorScope = "anti_tampering_provider.core_checks"
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

        for check in orderedChecks(snapshot: snapshot, baseScore: baseJailbreakScore) {
            isolatedAppend(check.id, &signals, check.execute)
        }

        if cprisk_is_mprotect_tampered() != 0 {
            signals.append(RiskSignal(
                id: "memory_protection_tampered",
                category: "anti_tamper",
                score: 85,
                evidence: ["detail": "mprotect_syscall_blocked"],
                state: .tampered,
                layer: 1,
                weightHint: 90
            ))
        }

        return coalesceProtectedDuplicateSignals(signals)
            .filter { $0.score >= configuration.minScoreThreshold }
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
            Logger.log("[AntiTamperingSignalProvider] \(label) threw error(\(error)), treating as suspicious")
            signals.append(RiskSignal(
                id: "detector_anomaly_\(label)",
                category: "anti_tamper",
                score: 80,
                evidence: ["error": "\(error)", "detector": label],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ))
        }
    }

    func orderedRandomizedDetectorIDs(snapshot: RiskSnapshot) -> [String] {
        orderedChecks(snapshot: snapshot, baseScore: snapshot.jailbreak.confidence)
            .map(\.id)
            .filter { Self.randomizableDetectorIDs.contains($0) }
    }

    private static let randomizableDetectorIDs: Set<String> = [
        "anti_tampering",
        "debugger",
        "frida",
        "frida_module",
        "frida_thread",
        "frida_heap",
        "objc_swizzle",
        "frida_socket",
        "dyld_interpose",
        "dyld_image_monitor",
        "dylib_injection",
        "anti_debug_watchdog",
    ]

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
        let shuffled = planner.maybeShuffle(selectedChecks, salt: "anti_tamper_debugger_frida")

        var ordered = checks
        for (offset, index) in selectedIndices.enumerated() {
            ordered[index] = shuffled[offset]
        }
        return ordered
    }

    private func buildChecks(snapshot: RiskSnapshot, baseScore: Double) -> [DetectorCheck] {
        var checks: [DetectorCheck] = []

        if configuration.enableAntiTampering {
            checks.append(DetectorCheck(id: "anti_tampering") {
                try self.detectAntiTampering(baseScore: baseScore)
            })
        }

        if configuration.enableDebugger {
            checks.append(DetectorCheck(id: "debugger") {
                try self.detectDebugger(baseScore: baseScore)
            })
        }

        if configuration.enableFrida {
            checks.append(DetectorCheck(id: "frida") {
                try self.detectFrida(baseScore: baseScore)
            })
        }

        if configuration.enableFridaModule {
            checks.append(DetectorCheck(id: "frida_module") {
                try self.detectFridaModule(baseScore: baseScore)
            })
        }

        if configuration.enableCodeSignature {
            checks.append(DetectorCheck(id: "code_signature") {
                try self.detectCodeSignatureIssues(baseScore: baseScore)
            })
        }

        if configuration.enableAppSigningIdentity {
            checks.append(DetectorCheck(id: "app_signing_identity") {
                try self.detectAppSigningIdentityIssues(baseScore: baseScore)
            })
        }

        if configuration.enableMemoryIntegrity {
            checks.append(DetectorCheck(id: "memory_integrity") {
                try self.detectMemoryIntegrityIssues(baseScore: baseScore)
            })
        }

        if configuration.enableRWXMemoryScan {
            checks.append(DetectorCheck(id: "rwx_memory") {
                RWXMemoryScanner().asSignals()
            })
        }

        if configuration.enablePLTIntegrity {
            checks.append(DetectorCheck(id: "plt_integrity") {
                let pltResult = PLTIntegrityGuard.verifyWithPersistedBaseline()
                return PLTIntegrityGuard.asSignals(result: pltResult)
            })
        }

        if configuration.enableTextSegmentHash {
            checks.append(DetectorCheck(id: "text_segment") {
                let hashResult = TextSegmentIntegrityChecker.verify()
                return TextSegmentIntegrityChecker.asSignals(result: hashResult)
            })
        }

        if configuration.enableFridaThreadDetect {
            checks.append(DetectorCheck(id: "frida_thread") {
                try FridaThreadDetector().asSignals()
            })
        }

        if configuration.enableFridaHeapDetect {
            checks.append(DetectorCheck(id: "frida_heap") {
                try FridaHeapDetector().asSignals()
            })
        }

        if configuration.enableObjCSwizzleDetect {
            checks.append(DetectorCheck(id: "objc_swizzle") {
                try ObjCSwizzleDetector().asSignals()
            })
        }

        if configuration.enableFridaSocketDetect {
            checks.append(DetectorCheck(id: "frida_socket") {
                try FridaSocketDetector().asSignals()
            })
        }

        if configuration.enableMultiPathFileDetect {
            checks.append(DetectorCheck(id: "multipath_file") {
                let mpResult = try MultiPathFileDetector().detect()
                guard mpResult.score > 0 else { return [] }

                var mpSignals: [RiskSignal] = []
                let hookMethods = mpResult.methods.filter { $0.hasPrefix("multipart_hook:") }
                if !hookMethods.isEmpty {
                    mpSignals.append(RiskSignal(
                        id: "multipath_hook_detected",
                        category: "anti_tamper",
                        score: min(Double(hookMethods.count) * 15, 30),
                        evidence: ["methods": hookMethods.joined(separator: ",")],
                        state: .tampered,
                        layer: 2,
                        weightHint: 82
                    ))
                }

                let pathMethods = mpResult.methods.filter { $0.hasPrefix("multipart:") && !$0.contains("hook") }
                if !pathMethods.isEmpty {
                    mpSignals.append(RiskSignal(
                        id: "multipath_jailbreak_file",
                        category: "jailbreak",
                        score: min(Double(pathMethods.count) * 12, 25),
                        evidence: ["paths": pathMethods.joined(separator: ",")],
                        state: .hard(detected: true),
                        layer: 2,
                        weightHint: 70
                    ))
                }
                return mpSignals
            })
        }

        if configuration.enableRandomizedDetection {
            checks.append(DetectorCheck(id: "randomized") {
                let randResult = try RandomizedDetection().detect()
                guard randResult.score > 0 else { return [] }
                return [RiskSignal(
                    id: "randomized_env_anomaly",
                    category: "anti_tamper",
                    score: randResult.score,
                    evidence: ["methods": randResult.methods.joined(separator: ",")],
                    state: .soft(confidence: min(randResult.score / 50.0, 1.0)),
                    layer: 2,
                    weightHint: 60
                )]
            })
        }

        if configuration.enableFingerprintDeobfuscation {
            checks.append(DetectorCheck(id: "fingerprint") {
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
            })
        }

        if configuration.enableDyldInterposeDetect {
            checks.append(DetectorCheck(id: "dyld_interpose") {
                try DyldInterposeDetector().asSignals()
            })
        }

        if configuration.enableSDKBinaryIntegrity {
            checks.append(DetectorCheck(id: "sdk_binary") {
                let binResult = SDKBinaryIntegrityChecker.verify()
                return SDKBinaryIntegrityChecker.asSignals(result: binResult)
            })
        }

        if configuration.enableSensorReplayDetect {
            checks.append(DetectorCheck(id: "sensor_replay") {
                try SensorReplayDetector().asSignals()
            })
        }

        if configuration.enablePhysicalSensorProbe {
            checks.append(DetectorCheck(id: "physical_sensor") {
                try PhysicalSensorProbe().asSignals()
            })
        }

        if configuration.enableGPURenderProbe {
            checks.append(DetectorCheck(id: "gpu_render") {
                try GPURenderProbe().asSignals()
            })
        }

        if configuration.enableIsaSwizzleDetect {
            checks.append(DetectorCheck(id: "isa_swizzle") {
                try IsaSwizzleDetector().asSignals()
            })
        }

        if configuration.enableCallStackValidate {
            checks.append(DetectorCheck(id: "call_stack") {
                if let signal = CallStackUnwinder.validateCallStackAsSignal() {
                    return [signal]
                }
                return []
            })
        }

        if configuration.enableHoneypotMemory {
            checks.append(DetectorCheck(id: "honeypot_memory") {
                try HoneypotMemoryDetector().asSignals()
            })
        }

        if configuration.enableKernelHookSideChannel {
            checks.append(DetectorCheck(id: "kernel_hook_sc") {
                try KernelHookSideChannel().asSignals()
            })
        }

        if configuration.enableSystemLibrarySegmentLayoutDetect {
            checks.append(DetectorCheck(id: "system_library_segment_layout") {
                try SystemLibrarySegmentLayoutDetector().asSignals()
            })
        }

        if configuration.enableLibcPrologueGuard {
            checks.append(DetectorCheck(id: "libc_prologue") {
                guard LibcPrologueGuard.checkAllCritical() else { return [] }
                return [RiskSignal(
                    id: "libc_inline_hook_detected",
                    category: "anti_tamper",
                    score: 95,
                    evidence: [
                        "mechanism": "mach_vm_read_overwrite_prologue_scan",
                        "detail": "critical_libc_function_entry_patched_with_branch_trampoline",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 98
                )]
            })
        }

        if configuration.enableDyldImageMonitor {
            checks.append(DetectorCheck(id: "dyld_image_monitor") {
                try DyldImageMonitor.shared.asSignals()
            })
        }

        if configuration.enableDylibInjectionDetect {
            checks.append(DetectorCheck(id: "dylib_injection") {
                try DylibInjectionDetector().asSignals()
            })
        }

        if configuration.enableAntiDebugWatchdog {
            checks.append(DetectorCheck(id: "anti_debug_watchdog") {
                self.detectAntiDebugWatchdogSignals()
            })
        }

        return checks
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
                    id: "anti_tampering",
                    category: "anti_tamper",
                    score: result.score,
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": "AntiTamperingDetector"
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
                        category: "anti_tamper",
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
                    id: "debugger_detected",
                    category: "debugger",
                    score: result.score,
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": "DebuggerDetector"
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
            "source": isDirectScan ? "direct_scan" : "watchdog",
            "watchdog_detected": snapshot.softwareBreakpointDetected ? "1" : "0",
            "watchdog_anomaly_count": "\(snapshot.softwareBreakpointAnomalyCount)"
        ]
        if let directCount {
            evidence["breakpoint_count"] = "\(directCount)"
        }

        return RiskSignal(
            id: SignalID.softwareBreakpointDetected,
            category: "anti_tamper",
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
            category: "anti_tamper",
            score: timeoutFlag || anomalyCount > 1 ? 38 : 30,
            evidence: [
                "mechanism": "mach_exception_delivery_timeout",
                "watchdog_detected": snapshot.exceptionDeliveryTimeoutDetected ? "1" : "0",
                "watchdog_anomaly_count": "\(anomalyCount)",
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
    
    /// Frida 检测
    private func detectFrida(baseScore: Double) throws -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        let result = try FridaDetector().detect()
        
        if result.score > 0 {
            signals.append(
                RiskSignal(
                    id: "frida_detected",
                    category: "anti_tamper",
                    score: min(result.score, 55),
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": "FridaDetector",
                        "scope": "runtime_surface"
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 85
                )
            )
            
            // 分解具体检测维度
            let fridaCategories = [
                ("frida:port:", "frida_port", 30),
                ("frida:file:", "frida_file", 20),
                ("frida:symbol:", "frida_symbol", 20),
                ("frida:thread:", "frida_thread", 20),
                ("frida:process:", "frida_process", 30),
                ("frida:env:", "frida_environment", 25)
            ]
            
            for method in result.methods {
                for (prefix, signalID, baseScore) in fridaCategories {
                    if method.hasPrefix(prefix) {
                        let detail = method.replacingOccurrences(of: prefix, with: "")
                        signals.append(
                            RiskSignal(
                                id: "\(signalID)_\(detail.replacingOccurrences(of: ":", with: "_"))",
                                category: "anti_tamper",
                                score: Double(baseScore),
                                evidence: ["detection_method": method]
                            )
                        )
                    }
                }
            }
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
                if method.hasPrefix("memory_hook:") {
                    let functionName = method.replacingOccurrences(of: "memory_hook:", with: "")
                    signals.append(
                        RiskSignal(
                            id: "hook_\(functionName)",
                            category: "integrity",
                            score: 20,
                            evidence: ["hooked_function": functionName]
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
                
                if method.hasPrefix("memory_inline:") {
                    let functionName = method.replacingOccurrences(of: "memory_inline:", with: "")
                    signals.append(
                        RiskSignal(
                            id: "inline_hook_\(functionName)",
                            category: "integrity",
                            score: 25,
                            evidence: ["inline_hooked": functionName]
                        )
                    )
                }
            }
        }
        
        return signals
    }

    private func detectAntiDebugWatchdogSignals() -> [RiskSignal] {
        let watchdogSnapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        var signals = antiDebugWatchdogSignals(from: watchdogSnapshot)

        if watchdogSnapshot.csopsDebugged {
            signals.append(RiskSignal(
                id: "csops_debugged",
                category: "anti_tamper",
                score: 90,
                evidence: ["mechanism": "csops_cs_debugged_flag"],
                state: .tampered,
                layer: 1,
                weightHint: 95
            ))
        }
        if watchdogSnapshot.hardwareBpDetected {
            signals.append(RiskSignal(
                id: "hardware_breakpoint_detected",
                category: "anti_tamper",
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
                category: "anti_tamper",
                score: 64,
                evidence: ["mechanism": "arm64_brk_opcode_scan", "source": "watchdog_probe"],
                state: .tampered,
                layer: 1,
                weightHint: 74
            ))
        }
        if watchdogSnapshot.signalProbeResult {
            signals.append(RiskSignal(
                id: "signal_probe_debugger",
                category: "anti_tamper",
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
                category: "anti_tamper",
                score: watchdogSnapshot.exceptionDeliveryProbeHandled ? 48 : 58,
                evidence: [
                    "mechanism": "mach_exception_delivery_probe",
                    "source": "watchdog_probe",
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
                category: "anti_tamper",
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
        case let m where m.contains("frida"):
            return 35
        case let m where m.contains("signature"):
            return 30
        case let m where m.contains("hook"):
            return 20
        default:
            return 15
        }
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
        let exceptionDeliveryTimeoutFlag = (snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT)) != 0

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
                    category: "anti_tamper",
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
                    category: "anti_tamper",
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
            let score = snapshot.lastExceptionHijackDetected ? 88.0 : 72.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("exception_port")
            signals.append(
                RiskSignal(
                    id: SignalID.antiDebugWatchdogExceptionPort,
                    category: "anti_tamper",
                    score: score,
                    evidence: [
                        "healthy": "\(snapshot.lastExceptionPortHealthy)",
                        "reclaim_attempted": "\(snapshot.lastExceptionReclaimAttempted)",
                        "hijack_detected": "\(snapshot.lastExceptionHijackDetected)",
                        "register_kr": "\(snapshot.lastExceptionRegisterKernReturn)",
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 95
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
                    category: "anti_tamper",
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

        if softwareBreakpointFlag || snapshot.softwareBreakpointDetected {
            let score = snapshot.softwareBreakpointDetected ? 58.0 : 34.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("software_breakpoint")
            signals.append(
                RiskSignal(
                    id: "anti_debug_watchdog_software_breakpoint",
                    category: "anti_tamper",
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

        if exceptionDeliveryTimeoutFlag || snapshot.exceptionDeliveryTimeoutDetected {
            let score = snapshot.exceptionDeliveryProbeHandled ? 38.0 : 52.0
            maxScore = max(maxScore, score)
            anomalyKinds.append("exception_delivery_timeout")
            signals.append(
                RiskSignal(
                    id: "anti_debug_watchdog_exception_delivery_timeout",
                    category: "anti_tamper",
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

        signals.insert(
            RiskSignal(
                id: SignalID.antiDebugWatchdogAnomaly,
                category: "anti_tamper",
                score: maxScore,
                evidence: [
                    "anomaly_flags": "\(snapshot.anomalyFlags)",
                    "anomaly_kinds": anomalyKinds.joined(separator: ","),
                    "thread_active": "\(snapshot.threadActive)",
                    "interval_seconds": "\(snapshot.intervalSeconds)",
                    "last_check_monotonic_ns": "\(snapshot.lastCheckMonotonicNs)",
                    "software_bp_anomaly_count": "\(snapshot.softwareBreakpointAnomalyCount)",
                    "exception_delivery_timeout_anomaly_count": "\(snapshot.exceptionDeliveryTimeoutAnomalyCount)",
                ],
                state: .tampered,
                layer: 2,
                weightHint: 94
            ),
            at: 0
        )

        return signals
    }
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
        config.enableSystemLibrarySegmentLayoutDetect = false
        config.enableAntiDebugWatchdog = true
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
