import Darwin
import Foundation

// MARK: - 金丝雀文件系统探针 [4.4.5]

/// 在检查越狱文件前，强制 stat 绝对存在的系统文件。
/// 如果连金丝雀文件都返回 ENOENT 或 EPERM，说明底层 syscall 遭到无差别拦截/屏蔽。
/// 同时通过 DualPathValidator 双路验证检测 stat hook 篡改。
enum CanaryFileProbe {

    private static let allCanaryComponents: [[String]] = [
        ["usr", "lib", "dyld"],
        ["System", "Library", "CoreServices", "SystemVersion.plist"],
        ["usr", "lib", "libSystem.B.dylib"],
        ["etc", "passwd"],
        ["dev", "null"],
        ["usr", "lib", "libc++.1.dylib"],
        ["usr", "lib", "libobjc.A.dylib"],
        ["System", "Library", "Frameworks", "Foundation.framework", "Foundation"],
        ["System", "Library", "Frameworks", "UIKit.framework", "UIKit"],
        ["System", "Library", "Frameworks", "Security.framework", "Security"],
        ["System", "Library", "Frameworks", "CoreFoundation.framework", "CoreFoundation"],
        ["private", "var", "db", "timezone", "localtime"],
        ["usr", "lib", "libz.1.dylib"],
        ["usr", "lib", "libsqlite3.dylib"],
        ["dev", "urandom"],
        ["System", "Library", "CoreServices", "SpringBoard.app", "Info.plist"],
    ]

    private static let subsetSize = 6

    private static func buildPath(_ components: [String]) -> String {
        "/" + components.joined(separator: "/")
    }

    private static func dynamicCanaryPaths() -> [String] {
        var paths: [String] = []

        let infoPlist = Bundle.main.bundlePath + "/Info.plist"
        paths.append(infoPlist)

        let libraryDir = NSHomeDirectory() + "/Library"
        paths.append(libraryDir)

        if let executablePath = Bundle.main.executablePath {
            paths.append(executablePath)
        }

        return paths
    }

    /// 金丝雀探针权重
    static let canaryDeadWeight: Double = 90

    /// 执行金丝雀探针，若 syscall 被致盲或 stat 被 hook 则返回异常结果
    static func probe() -> DetectorResult? {
#if targetEnvironment(simulator)
        return nil
#else
        let selected = Array(allCanaryComponents.shuffled().prefix(subsetSize))

        for components in selected {
            let path = buildPath(components)
            let validation = DualPathValidator.validateFileStat(path: path)

            if !validation.exists {
                Logger.log("jailbreak.canary.hit: syscall_blinded_canary_dead path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["syscall_blinded_canary_dead"])
            }

            if validation.tampered {
                Logger.log("jailbreak.canary.hit: canary_stat_tampered path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["canary_stat_tampered"])
            }

            if validation.traced {
                Logger.log("jailbreak.canary.hit: dbi_stalker_traced path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["dbi_stalker_traced"])
            }
        }

        for path in dynamicCanaryPaths() {
            let validation = DualPathValidator.validateFileStat(path: path)

            if !validation.exists {
                Logger.log("jailbreak.canary.hit: syscall_blinded_canary_dead path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["syscall_blinded_canary_dead"])
            }

            if validation.tampered {
                Logger.log("jailbreak.canary.hit: canary_stat_tampered path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["canary_stat_tampered"])
            }

            if validation.traced {
                Logger.log("jailbreak.canary.hit: dbi_stalker_traced path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["dbi_stalker_traced"])
            }
        }

        if DualPathValidator.inlineHookDetected {
            Logger.log("jailbreak.canary.hit: libc_inline_hook_detected (+95)")
            return DetectorResult(score: 95, methods: ["libc_inline_hook_detected"])
        }

        return nil
#endif
    }
}
