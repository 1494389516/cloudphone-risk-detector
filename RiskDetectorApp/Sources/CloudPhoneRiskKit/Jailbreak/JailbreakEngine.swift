import Foundation

// MARK: - Jailbreak Detection Engine
//
// Runs a configurable chain of detectors, each returning a DetectorResult
// with a score and list of detected methods. The engine aggregates scores and
// applies a confidence threshold to produce a final DetectionResult.
//
// Detector Chain (each independently toggleable via JailbreakConfig):
//   FileDetector              → stat/access on known jailbreak paths
//   DyldDetector              → _dyld_image_count / image name scanning
//   EnvDetector               → DYLD_INSERT_LIBRARIES and related env vars
//   SysctlDetector            → kern.proc P_TRACED flag, process list
//   SchemeDetector            → canOpenURL for Cydia/Sileo/Filza schemes (UIKit only)
//   HookDetector              → composite: ObjC classes + symbol image + sub-detectors
//     (invoked when enableHookDetect; sub-detectors run inside HookDetector.detect()):
//     PointerValidationDetector      → pointer authentication checks
//     HookFrameworkSymbolDetector   → dlsym for Substrate/fishhook/Frida symbols
//     PrologueBranchDetector        → ARM64 branch instruction at function entry
//     IndirectSymbolPointerDetector → indirect symbol table integrity
//     ObjCIMPDetector               → method_getImplementation + dladdr validation
//     ObjCMetadataDetector          → objc_copyClassList / protocol / NSObject extension scan
//
// Simulator: returns unavailable by default (set CPRISK_SIMULATE_JAILBREAK=1
// to enable simulated jailbreak for testing)

final class JailbreakEngine {
    /// 置信度上限
    private static let confidenceCap: Double = 100
    /// 单个检测器连续异常（抛异常/负分）达到该次数时才升级计分。
    /// 故障（检测器本身出错）与“检测到越狱”是两回事：单次故障只标记、
    /// 不直接加高分，避免故障设备被误判高危；连续故障才视为可疑并升级。
    private static let consecutiveFaultEscalationThreshold = 2
    /// 连续故障升级时计入的分值（远低于旧的单次故障 +80）。
    private static let consecutiveFaultEscalationScore: Double = 40
    /// 各检测器连续故障计数（跨次评估累计，成功一次即清零）。
    private var consecutiveFaults: [String: Int] = [:]

    func detect(config: JailbreakConfig) -> DetectionResult {
#if targetEnvironment(simulator)
    #if DEBUG
        let simulate = ProcessInfo.processInfo.environment["CPRISK_SIMULATE_JAILBREAK"] == "1"
            || UserDefaults.standard.bool(forKey: "cloudphone_risk_debug_simulate_jailbreak")
        if simulate {
            Logger.log("jailbreak: simulator -> simulated_jailbreak (DEBUG only)")
            return DetectionResult(
                isJailbroken: true,
                confidence: Self.confidenceCap,
                detectedMethods: ["simulated:targetEnvironment(simulator)"],
                details: "simulated_jailbreak_simulator"
            )
        }
    #endif
        Logger.log("jailbreak: simulator -> unavailable")
        return DetectionResult(
            isJailbroken: false,
            confidence: 0,
            detectedMethods: [],
            details: "unavailable_simulator",
            unavailable: true
        )
#endif

        var score: Double = 0
        var methods: [String] = []
        var faultLabels: [String] = []

        #if DEBUG
        Logger.log("jailbreak: start(threshold=\(config.threshold))")
        #endif

        if config.enableFileDetect {
            accumulateDetector("file", &score, &methods, &faultLabels) { try FileDetector().detect() }
        }

        if config.enableDyldDetect {
            accumulateDetector("dyld", &score, &methods, &faultLabels) { try DyldDetector().detect() }
        }

        if config.enableEnvDetect {
            accumulateDetector("env", &score, &methods, &faultLabels) { try EnvDetector().detect() }
        }

        if config.enableSysctlDetect {
            accumulateDetector("sysctl", &score, &methods, &faultLabels) { try SysctlDetector().detect() }
        }

        #if canImport(UIKit)
        if config.enableSchemeDetect {
            accumulateDetector("scheme", &score, &methods, &faultLabels) { try SchemeDetector().detect() }
        }
        #endif

        if config.enableHookDetect {
            accumulateDetector(ObfuscatedConstants.keywordHook, &score, &methods, &faultLabels) { try HookDetector().detect() }
        }

        methods = Array(Set(methods)).sorted()
        let isJailbroken = score >= config.threshold
        #if DEBUG
        Logger.log("jailbreak: done(score=\(min(score, Self.confidenceCap)) isJailbroken=\(isJailbroken) methods=\(methods.joined(separator: ",")))")
        #endif
        return DetectionResult(
            isJailbroken: isJailbroken,
            confidence: min(score, Self.confidenceCap),
            detectedMethods: methods,
            details: details(methods: methods, score: score, faults: faultLabels)
        )
    }

    private func accumulateDetector(
        _ label: String,
        _ score: inout Double,
        _ methods: inout [String],
        _ faults: inout [String],
        _ block: () throws -> DetectorResult
    ) {
        do {
            let result = try block()
            if result.score < 0 {
                // 检测器故障（负分），不是“检测到越狱”：只标记，不加高分。
                recordDetectorFault(label: label, reason: "negative_score", score: &score, methods: &methods, faults: &faults)
            } else {
                consecutiveFaults[label] = 0
                #if DEBUG
                Logger.log("jailbreak.\(label): score=\(result.score) hits=\(result.methods.count)")
                #endif
                score += result.score
                methods.append(contentsOf: result.methods)
            }
        } catch {
            // 检测器故障（抛异常），不是“检测到越狱”：只标记，不加高分。
            recordDetectorFault(label: label, reason: "threw", score: &score, methods: &methods, faults: &faults)
        }
    }

    /// 记录一次检测器故障：标记 `jailbreak_fault:<label>:<reason>`，并在该检测器
    /// 连续故障达到阈值时才升级计分（熔断/去重），同时记录日志。
    private func recordDetectorFault(
        label: String,
        reason: String,
        score: inout Double,
        methods: inout [String],
        faults: inout [String]
    ) {
        let streak = (consecutiveFaults[label] ?? 0) + 1
        consecutiveFaults[label] = streak
        faults.append("\(label):\(reason):streak=\(streak)")
        methods.append("jailbreak_fault:\(label):\(reason)")
        Logger.log("jailbreak.\(label): detector fault (\(reason)), consecutive streak=\(streak) — marked, not scored as jailbreak")
        if streak >= Self.consecutiveFaultEscalationThreshold {
            score += Self.consecutiveFaultEscalationScore
            methods.append("jailbreak_fault_escalated:\(label)")
            Logger.log("jailbreak.\(label): consecutive faults escalated (streak=\(streak), +\(Self.consecutiveFaultEscalationScore))")
        }
    }

    private func details(methods: [String], score: Double, faults: [String] = []) -> String {
        """
        jailbreak_score=\(min(score, Self.confidenceCap))
        hits=\(methods.count)
        methods=\(methods.joined(separator: ","))
        detector_faults=\(faults.isEmpty ? "none" : faults.joined(separator: ","))
        """
    }
}
