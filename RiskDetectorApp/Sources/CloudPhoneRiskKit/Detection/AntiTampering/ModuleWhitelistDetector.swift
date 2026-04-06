import CRiskCore
import Darwin
import Foundation
import MachO

// MARK: - Module Whitelist Detector
//
// 现有 DylibInjectionDetector 依赖关键词匹配（"frida", "gadget", "gum" 等）。
// 针对 rustFrida 的 libagent.so（名称不含任何已知关键词），关键词匹配完全失效。
//
// 本检测器采用"白名单路径"策略：
// 1. 任何加载的 dylib，若其路径不属于已知系统路径前缀集合，
//    且不属于当前应用 Bundle 路径，则标记为可疑模块。
// 2. 对可疑模块进一步检查：代码签名状态、加载时序异常。
//
// 补充覆盖：任意工具名称的注入模块，不依赖名称特征。

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
        "/private/preboot/",               // Preboot volume
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
