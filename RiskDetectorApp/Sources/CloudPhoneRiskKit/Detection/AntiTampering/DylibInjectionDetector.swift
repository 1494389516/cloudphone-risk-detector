import Darwin
import Foundation
import MachO

/// Detects malicious dylib injection via IPA repackaging.
///
/// Attackers who cannot attach at runtime (Frida attach blocked by TLS/ptrace)
/// fall back to inserting `LC_LOAD_DYLIB` commands in the Mach-O header or
/// using `DYLD_INSERT_LIBRARIES`. These injected dylibs load before any SDK
/// initialisation code, making this a high-priority detection surface.
///
/// Detection dimensions:
/// 1. Abnormal loaded-image count (baseline overflow)
/// 2. Suspicious dylib path keywords (hooking frameworks, rootless jailbreak paths)
/// 3. `DYLD_INSERT_LIBRARIES` environment variable presence
/// 4. Non-system, non-bundle dylibs (loaded from outside the app sandbox)
struct DylibInjectionDetector: Detector {

    // MARK: - Thresholds

    private static let imageCountSoftLimit: UInt32 = 400
    private static let imageCountHardLimit: UInt32 = 500

    // MARK: - Known-bad keywords (lowercase)

    private static let suspiciousKeywords: [String] = [
        "substrate", "substitute", "ellekit", "libhooker",
        "cynject", "pspawn", "tweakinject", "cydiasubstrate",
        "shadow", "libblackjack", "choicy", "sslkillswitch",
        "flex", "revealdebug", "cycript",
    ]

    /// Rootless jailbreak and other non-standard prefixes.
    private static let suspiciousPrefixes: [String] = [
        "/var/jb/",
        "/var/LIB/",
        "/var/ulb/",
        "/usr/lib/tweaks/",
    ]

    /// System / legitimate path prefixes that are expected on a stock device.
    private static let allowedPrefixes: [String] = [
        "/usr/lib/",
        "/System/",
        "/Library/",
        "/private/var/containers/",
        "/Developer/",
    ]

    // MARK: - Detector

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["dylib_inject:unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        let countResult = detectAbnormalImageCount()
        score += countResult.score
        methods.append(contentsOf: countResult.methods)

        let keywordResult = detectSuspiciousDylibPaths()
        score += keywordResult.score
        methods.append(contentsOf: keywordResult.methods)

        let envResult = detectDyldInsertEnv()
        score += envResult.score
        methods.append(contentsOf: envResult.methods)

        let sandboxResult = detectOutOfSandboxDylibs()
        score += sandboxResult.score
        methods.append(contentsOf: sandboxResult.methods)

        return DetectorResult(score: min(score, 100), methods: methods)
#endif
    }

    // MARK: - 1a. Abnormal image count

    private func detectAbnormalImageCount() -> (score: Double, methods: [String]) {
        let count = _dyld_image_count()
        if count > Self.imageCountHardLimit {
            return (20, ["dylib_inject:image_count_hard:\(count)"])
        } else if count > Self.imageCountSoftLimit {
            return (10, ["dylib_inject:image_count_soft:\(count)"])
        }
        return (0, [])
    }

    // MARK: - 1b. Suspicious dylib path keywords

    private func detectSuspiciousDylibPaths() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []
        let count = _dyld_image_count()

        for index in 0..<count {
            guard let rawName = _dyld_get_image_name(index) else { continue }
            let path = String(cString: rawName)
            let lower = path.lowercased()

            for keyword in Self.suspiciousKeywords {
                if lower.contains(keyword) {
                    score += 25
                    methods.append("dylib_inject:keyword:\(keyword)")
                    break
                }
            }

            for prefix in Self.suspiciousPrefixes {
                if path.hasPrefix(prefix) {
                    score += 20
                    methods.append("dylib_inject:rootless_path:\(prefix)")
                    break
                }
            }
        }
        return (min(score, 50), methods)
    }

    // MARK: - 1c. DYLD_INSERT_LIBRARIES

    private func detectDyldInsertEnv() -> (score: Double, methods: [String]) {
        guard let rawValue = getenv("DYLD_INSERT_LIBRARIES") else {
            return (0, [])
        }
        let value = String(cString: rawValue)
        guard !value.isEmpty else { return (0, []) }
        return (30, ["dylib_inject:env_dyld_insert:\(value)"])
    }

    // MARK: - 1d. Non-system, non-bundle dylibs

    private func detectOutOfSandboxDylibs() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []

        let bundlePath = Bundle.main.bundlePath
        let count = _dyld_image_count()

        for index in 0..<count {
            guard let rawName = _dyld_get_image_name(index) else { continue }
            let path = String(cString: rawName)

            if path.hasPrefix(bundlePath) { continue }
            if Self.allowedPrefixes.contains(where: { path.hasPrefix($0) }) { continue }

            // Anything else is an out-of-sandbox, non-system dylib.
            score += 15
            methods.append("dylib_inject:out_of_sandbox:\(path)")
        }
        return (min(score, 40), methods)
    }
}

// MARK: - Signal Conversion

extension DylibInjectionDetector {
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let countMethods = result.methods.filter { $0.hasPrefix("dylib_inject:image_count") }
        if !countMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dylib_inject_image_count",
                category: "anti_tamper",
                score: min(Double(countMethods.count) * 15, 20),
                evidence: ["detail": countMethods.joined(separator: ",")],
                state: .soft(confidence: 0.6),
                layer: 2,
                weightHint: 55
            ))
        }

        let keywordMethods = result.methods.filter { $0.hasPrefix("dylib_inject:keyword") }
        if !keywordMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dylib_inject_suspicious_keyword",
                category: "anti_tamper",
                score: min(Double(keywordMethods.count) * 20, 50),
                evidence: ["detail": keywordMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        let rootlessMethods = result.methods.filter { $0.hasPrefix("dylib_inject:rootless_path") }
        if !rootlessMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dylib_inject_rootless_jailbreak",
                category: "anti_tamper",
                score: min(Double(rootlessMethods.count) * 18, 40),
                evidence: ["detail": rootlessMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 82
            ))
        }

        let envMethods = result.methods.filter { $0.hasPrefix("dylib_inject:env_dyld_insert") }
        if !envMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dylib_inject_env_insert",
                category: "anti_tamper",
                score: 30,
                evidence: ["detail": envMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 88
            ))
        }

        let sandboxMethods = result.methods.filter { $0.hasPrefix("dylib_inject:out_of_sandbox") }
        if !sandboxMethods.isEmpty {
            signals.append(RiskSignal(
                id: "dylib_inject_out_of_sandbox",
                category: "anti_tamper",
                score: min(Double(sandboxMethods.count) * 12, 35),
                evidence: ["detail": sandboxMethods.joined(separator: ",")],
                state: .soft(confidence: 0.75),
                layer: 2,
                weightHint: 78
            ))
        }

        return signals
    }
}
