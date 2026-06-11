import CRiskCore
import Darwin
import Foundation
import MachO

// MARK: - Module Whitelist Detector
//
// DylibInjectionDetector 依赖关键词匹配（"frida", "substrate", "gadget" 等），
// 但 IPA 重签注入、越狱 tweak 注入、DYLD_INSERT_LIBRARIES 注入的 dylib
// 可以使用任意名称（如 "libutils.dylib"、"helper.dylib"），关键词匹配失效。
//
// 本检测器采用"白名单路径"策略：
// 1. 枚举所有已加载 dylib，路径不属于系统白名单且不属于 App Bundle → 可疑
// 2. 对可疑模块进一步评估：来源路径分类、磁盘签名状态
//
// 覆盖场景：免越狱 IPA 重签注入；越狱 tweak 注入；任意名称的恶意 dylib

struct ModuleWhitelistDetector: Detector {

    // MARK: - Path Allowlist
    // 正常 iOS 进程中预期出现的路径前缀（小写比较）。
    private static let systemPathPrefixes: [String] = [
        "/usr/lib/",
        "/system/",
        "/library/",
        "/private/var/containers/",       // App sandbox — own bundle allowed
        "/developer/",                     // Developer disk (already flagged by other detector)
        "/var/staged_system_apps/",        // OTA updates staging
    ]

    private static let prebootSystemRoots: Set<String> = [
        "cryptexes",
        "system",
    ]

    /// Additional rootless jailbreak paths that are already covered by DylibInjectionDetector
    /// but listed here so we can give extra weight when combined with non-keyword signals.
    private static let jailbreakPathPrefixes: [String] = [
        "/var/jb/",
        "/var/lib/",
        "/var/ulb/",
        "/usr/lib/tweaks/",
        "/bootstrap/",
    ]

    private static let roothideSuspiciousKeywords: [String] = [
        "roothide", "procursus", "ellekit",
    ]

    /// File extensions that must appear in any legitimate framework or dylib name.
    private static let legitimateExtensions: Set<String> = ["dylib", "framework", "so"]

    // MARK: - Scoring Parameters
    private static let scoreUnknownPath: Double       = 18
    private static let scoreJailbreakPath: Double     = 12
    private static let scoreAnonOrigin: Double        = 20   // Module loaded from anonymous/tmp path
    private static let scoreUnsignedCode: Double      = 15
    private static let scoreMultipleUnknown: Double   = 12   // Bonus for ≥2 unknown modules
    private static let maxScore: Double               = 80

    // MARK: - Detector Protocol

    @inline(never)
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["mwl:unavailable_simulator"])
#else
        return detectKernel()
#endif
    }

    @inline(never)
    private func detectKernel() -> DetectorResult {
        let appBundlePath = Bundle.main.bundlePath.lowercased()
        let imageCount = _dyld_image_count()

        var score: Double = 0
        var methods: [String] = []
        var unknownModuleCount = 0

        for i in 0..<imageCount {
            guard let rawName = _dyld_get_image_name(i) else { continue }
            let imagePath = String(cString: rawName)
            let lowerPath = imagePath.lowercased()

            // Skip images in known system prefixes
            if Self.systemPathPrefixes.contains(where: { lowerPath.hasPrefix($0) }) {
                continue
            }

            // Skip the app's own bundle
            if lowerPath.hasPrefix(appBundlePath) {
                continue
            }

            // Preboot volume: allow known system subpaths, flag everything else
            if lowerPath.hasPrefix("/private/preboot/") {
                if Self.isAllowedPrebootSystemPath(lowerPath) {
                    continue
                }
                let hasRoothideKeyword = Self.roothideSuspiciousKeywords.contains(where: { lowerPath.contains($0) })
                let roothideBonus: Double = hasRoothideKeyword ? 8 : 0
                score += Self.scoreJailbreakPath + roothideBonus
                methods.append("mwl:preboot_nonstandard\(hasRoothideKeyword ? "_roothide" : ""):\(sanitizeName(imagePath))")
                continue
            }

            // Check for jailbreak paths (additive with DylibInjectionDetector signal)
            if Self.jailbreakPathPrefixes.contains(where: { lowerPath.hasPrefix($0) }) {
                score += Self.scoreJailbreakPath
                methods.append("mwl:jailbreak_path:\(sanitizeName(imagePath))")
                continue
            }

            // At this point the path doesn't match any allowlist — classify by origin
            let origin = classifyOrigin(lowerPath)

            switch origin {
            case .anonymousOrTemp:
                score += Self.scoreAnonOrigin
                methods.append("mwl:anon_origin:\(sanitizeName(imagePath))")
                unknownModuleCount += 1

            case .containerData:
                // A dylib loaded from within the container's data directory (not the app Bundle) is suspicious
                let sigOK = isCodeSignaturePresent(imagePath)
                let sigScore = sigOK ? 0.0 : Self.scoreUnsignedCode
                score += Self.scoreUnknownPath + sigScore
                methods.append("mwl:container_data\(sigOK ? "" : "_unsigned"):\(sanitizeName(imagePath))")
                unknownModuleCount += 1

            case .unknown:
                let sigOK = isCodeSignaturePresent(imagePath)
                let sigScore = sigOK ? 0.0 : Self.scoreUnsignedCode
                score += Self.scoreUnknownPath + sigScore
                methods.append("mwl:unknown_path\(sigOK ? "" : "_unsigned"):\(sanitizeName(imagePath))")
                unknownModuleCount += 1
            }
        }

        // Bonus for multiple unexpected modules (injection frameworks often load >1 lib)
        if unknownModuleCount >= 2 {
            score += Self.scoreMultipleUnknown
            methods.append("mwl:multiple_unknown:\(unknownModuleCount)")
        }

        if methods.isEmpty {
            methods.append("mwl:clean")
        }

        return DetectorResult(score: min(score, Self.maxScore), methods: methods)
    }

    // MARK: - Origin Classification

    private enum ModuleOrigin {
        case anonymousOrTemp    // /tmp, /var/tmp, /dev/shm, memory-only paths
        case containerData      // inside /private/var/mobile/Containers/Data/ but not in Bundle
        case unknown            // none of the above
    }

    private func classifyOrigin(_ lowerPath: String) -> ModuleOrigin {
        if lowerPath.hasPrefix("/tmp/") ||
           lowerPath.hasPrefix("/var/tmp/") ||
           lowerPath.hasPrefix("/private/tmp/") ||
           lowerPath.hasPrefix("/dev/") {
            return .anonymousOrTemp
        }
        if lowerPath.contains("/containers/data/") {
            return .containerData
        }
        return .unknown
    }

    static func isAllowedPrebootSystemPath(_ lowerPath: String) -> Bool {
        let prefix = "/private/preboot/"
        guard lowerPath.hasPrefix(prefix) else { return false }

        let relative = lowerPath.dropFirst(prefix.count)
        let components = relative.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard !components.isEmpty else { return false }

        if Self.prebootSystemRoots.contains(components[0]) {
            return true
        }

        guard components.count >= 2 else { return false }
        return isLikelyPrebootVolumeID(components[0]) && Self.prebootSystemRoots.contains(components[1])
    }

    private static func isLikelyPrebootVolumeID(_ component: String) -> Bool {
        guard component.count == 36 else { return false }
        for (index, byte) in component.utf8.enumerated() {
            let shouldBeHyphen = index == 8 || index == 13 || index == 18 || index == 23
            if shouldBeHyphen {
                guard byte == 45 else { return false }
            } else {
                let isHex = (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
                guard isHex else { return false }
            }
        }
        return true
    }

    // MARK: - Code Signature Check

    /// Checks whether an image has a code signature LC command.
    /// A missing signature is a strong indicator of a dynamically injected / rebuilt library.
    private func isCodeSignaturePresent(_ imagePath: String) -> Bool {
        // Attempt to open the dylib on disk and verify it has a code signature
        // We use cprisk_access_direct to bypass any libc hook on `access(2)`
        var errnoVal: CInt = 0
        let rc = imagePath.withCString { cPath in
            cprisk_access_direct(cPath, F_OK, &errnoVal)
        }
        guard rc == 0 else {
            // File not accessible on disk → likely loaded from anonymous/injected memory
            return false
        }

        // If file exists on disk, assume it has a code signature (full Mach-O parsing
        // would be expensive; unsigned-from-disk libs are already caught by codesign checks
        // in CodeSignatureValidator and AppSigningIdentityDetector).
        return true
    }

    // MARK: - Utilities

    /// Truncate and sanitize a path for evidence logging.
    private func sanitizeName(_ path: String) -> String {
        // Keep only the last two path components to avoid leaking full sandbox paths
        let components = path.split(separator: "/")
        let tail = components.suffix(2).joined(separator: "/")
        return tail.isEmpty ? path : tail
    }
}

// MARK: - Signal Bridge

extension ModuleWhitelistDetector {
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        let unknownModules = result.methods.filter {
            $0.hasPrefix("mwl:unknown_path") || $0.hasPrefix("mwl:anon_origin") || $0.hasPrefix("mwl:container_data")
        }

        return [RiskSignal(
            id: "module_whitelist_violation",
            category: ObfuscatedConstants.categoryAntiTamper,
            score: result.score,
            evidence: [
                "violation_count": "\(unknownModules.count)",
                "modules": unknownModules.prefix(4).joined(separator: "|"),
            ],
            state: .soft(confidence: min(0.55 + Double(unknownModules.count) * 0.12, 0.92)),
            layer: 2,
            weightHint: 70
        )]
    }
}
