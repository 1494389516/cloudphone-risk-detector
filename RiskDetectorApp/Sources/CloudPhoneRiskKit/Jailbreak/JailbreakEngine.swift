import Foundation

final class JailbreakEngine {
    func detect(config: JailbreakConfig) -> DetectionResult {
#if targetEnvironment(simulator)
        // iOS Simulator runs as a macOS process and shares host filesystem/dyld state.
        // Most jailbreak heuristics will false-positive here (e.g. dylib count, /bin/bash).
        var simulate = ProcessInfo.processInfo.environment["CPRISK_SIMULATE_JAILBREAK"] == "1"
        #if DEBUG
        simulate = simulate || UserDefaults.standard.bool(forKey: "cloudphone_risk_debug_simulate_jailbreak")
        #endif
        if simulate {
            Logger.log("jailbreak: simulator -> simulated_jailbreak")
            return DetectionResult(
                isJailbroken: true,
                confidence: 100,
                detectedMethods: ["simulated:targetEnvironment(simulator)"],
                details: "simulated_jailbreak_simulator"
            )
        } else {
            Logger.log("jailbreak: simulator -> unavailable")
            return DetectionResult(
                isJailbroken: false,
                confidence: 0,
                detectedMethods: [],
                details: "unavailable_simulator"
            )
        }
#endif

        var score: Double = 0
        var methods: [String] = []

        Logger.log("jailbreak: start(threshold=\(config.threshold))")

        if config.enableFileDetect {
            accumulateDetector("file", &score, &methods) { FileDetector().detect() }
        }

        if config.enableDyldDetect {
            accumulateDetector("dyld", &score, &methods) { DyldDetector().detect() }
        }

        if config.enableEnvDetect {
            accumulateDetector("env", &score, &methods) { EnvDetector().detect() }
        }

        if config.enableSysctlDetect {
            accumulateDetector("sysctl", &score, &methods) { SysctlDetector().detect() }
        }

        #if canImport(UIKit)
        if config.enableSchemeDetect {
            accumulateDetector("scheme", &score, &methods) { SchemeDetector().detect() }
        }
        #endif

        if config.enableHookDetect {
            accumulateDetector("hook", &score, &methods) { HookDetector().detect() }
        }

        methods = Array(Set(methods)).sorted()
        let isJailbroken = score >= config.threshold
        Logger.log("jailbreak: done(score=\(min(score, 100)) isJailbroken=\(isJailbroken) methods=\(methods.joined(separator: ",")))")
        return DetectionResult(
            isJailbroken: isJailbroken,
            confidence: min(score, 100),
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
                Logger.log("jailbreak.\(label): negative score(\(result.score)), treating as suspicious")
                score += 5
                methods.append("jailbreak_anomaly:\(label):negative_score")
            } else {
                Logger.log("jailbreak.\(label): score=\(result.score) hits=\(result.methods.count)")
                score += result.score
                methods.append(contentsOf: result.methods)
            }
        } catch {
            Logger.log("jailbreak.\(label): detector threw error(\(error)), treating as suspicious")
            score += 5
            methods.append("jailbreak_anomaly:\(label):threw")
        }
    }

    private func details(methods: [String], score: Double) -> String {
        """
        jailbreak_score=\(min(score, 100))
        hits=\(methods.count)
        methods=\(methods.joined(separator: ","))
        """
    }
}
