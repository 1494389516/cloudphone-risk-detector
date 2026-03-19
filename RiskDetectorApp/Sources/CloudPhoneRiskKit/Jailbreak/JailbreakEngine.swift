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
    /// 检测器异常（负分/抛异常）时的惩罚分（高危权重，避免静默通过）
    private static let detectorAnomalyPenalty: Double = 80

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
            details: "unavailable_simulator"
        )
#endif

        var score: Double = 0
        var methods: [String] = []

        #if DEBUG
        Logger.log("jailbreak: start(threshold=\(config.threshold))")
        #endif

        if config.enableFileDetect {
            accumulateDetector("file", &score, &methods) { try FileDetector().detect() }
        }

        if config.enableDyldDetect {
            accumulateDetector("dyld", &score, &methods) { try DyldDetector().detect() }
        }

        if config.enableEnvDetect {
            accumulateDetector("env", &score, &methods) { try EnvDetector().detect() }
        }

        if config.enableSysctlDetect {
            accumulateDetector("sysctl", &score, &methods) { try SysctlDetector().detect() }
        }

        #if canImport(UIKit)
        if config.enableSchemeDetect {
            accumulateDetector("scheme", &score, &methods) { try SchemeDetector().detect() }
        }
        #endif

        if config.enableHookDetect {
            accumulateDetector(ObfuscatedConstants.keywordHook, &score, &methods) { try HookDetector().detect() }
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
            details: details(methods: methods, score: score)
        )
    }

    private func accumulateDetector(
        _ label: String,
        _ score: inout Double,
        _ methods: inout [String],
        _ block: () throws -> DetectorResult
    ) {
        do {
            let result = try block()
            if result.score < 0 {
                #if DEBUG
                Logger.log("jailbreak.\(label): negative score(\(result.score)), treating as suspicious")
                #endif
                score += Self.detectorAnomalyPenalty
                methods.append("jailbreak_anomaly:\(label):negative_score")
            } else {
                #if DEBUG
                Logger.log("jailbreak.\(label): score=\(result.score) hits=\(result.methods.count)")
                #endif
                score += result.score
                methods.append(contentsOf: result.methods)
            }
        } catch {
            #if DEBUG
            Logger.log("jailbreak.\(label): detector threw error(\(error)), treating as suspicious")
            #endif
            score += Self.detectorAnomalyPenalty
            methods.append("jailbreak_anomaly:\(label):threw")
        }
    }

    private func details(methods: [String], score: Double) -> String {
        """
        jailbreak_score=\(min(score, Self.confidenceCap))
        hits=\(methods.count)
        methods=\(methods.joined(separator: ","))
        """
    }
}
