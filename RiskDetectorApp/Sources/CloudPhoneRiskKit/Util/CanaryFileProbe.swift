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
    ]

    private static let subsetSize = 3

    private static func buildPath(_ components: [String]) -> String {
        "/" + components.joined(separator: "/")
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
        }
        return nil
#endif
    }
}
