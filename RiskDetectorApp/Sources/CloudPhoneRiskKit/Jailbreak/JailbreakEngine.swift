import Foundation

final class JailbreakEngine {
    func detect(config: JailbreakConfig) -> DetectionResult {
#if targetEnvironment(simulator)
        // iOS Simulator runs as a macOS process and shares host filesystem/dyld state.
        // Most jailbreak heuristics will false-positive here (e.g. dylib count, /bin/bash).
        let simulate = (ProcessInfo.processInfo.environment["CPRISK_SIMULATE_JAILBREAK"] == "1")
            || UserDefaults.standard.bool(forKey: "cloudphone_risk_debug_simulate_jailbreak")
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
            let result = FileDetector().detect()
            Logger.log("jailbreak.file: score=\(result.score) hits=\(result.methods.count)")
            score += result.score
            methods.append(contentsOf: result.methods)
        }

        if config.enableDyldDetect {
            let result = DyldDetector().detect()
            Logger.log("jailbreak.dyld: score=\(result.score) hits=\(result.methods.count)")
            score += result.score
            methods.append(contentsOf: result.methods)
        }

        if config.enableEnvDetect {
            let result = EnvDetector().detect()
            Logger.log("jailbreak.env: score=\(result.score) hits=\(result.methods.count)")
            score += result.score
            methods.append(contentsOf: result.methods)
        }

        if config.enableSysctlDetect {
            let result = SysctlDetector().detect()
            Logger.log("jailbreak.sysctl: score=\(result.score) hits=\(result.methods.count)")
            score += result.score
            methods.append(contentsOf: result.methods)
        }

        #if canImport(UIKit)
        if config.enableSchemeDetect {
            let result = SchemeDetector().detect()
            Logger.log("jailbreak.scheme: score=\(result.score) hits=\(result.methods.count)")
            score += result.score
            methods.append(contentsOf: result.methods)
        }
        #endif

        if config.enableHookDetect {
            let result = HookDetector().detect()
            Logger.log("jailbreak.hook: score=\(result.score) hits=\(result.methods.count)")
            score += result.score
            methods.append(contentsOf: result.methods)
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

    private func details(methods: [String], score: Double) -> String {
        """
        jailbreak_score=\(min(score, 100))
        hits=\(methods.count)
        methods=\(methods.joined(separator: ","))
        """
    }
}
