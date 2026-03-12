import Darwin
import Foundation

// MARK: - 金丝雀文件系统探针 [4.4.5]

/// 在检查越狱文件前，强制 stat 绝对存在的系统文件。
/// 如果连金丝雀文件都返回 ENOENT 或 EPERM，说明底层 syscall 遭到无差别拦截/屏蔽。
enum CanaryFileProbe {

    private static let canaryPaths = [
        "/usr/lib/dyld",
        "/System/Library/CoreServices/SystemVersion.plist",
    ]

    /// 金丝雀探针权重
    static let canaryDeadWeight: Double = 90

    /// 执行金丝雀探针，若 syscall 被致盲则返回异常结果
    /// - Returns: 若金丝雀死亡则返回 (score: 90, methods: ["syscall_blinded_canary_dead"])，否则返回 nil
    static func probe() -> DetectorResult? {
#if targetEnvironment(simulator)
        return nil
#else
        for path in canaryPaths {
            if isCanaryDead(path: path) {
                Logger.log("jailbreak.canary.hit: syscall_blinded_canary_dead path=\(path) (+\(Int(canaryDeadWeight)))")
                return DetectorResult(score: canaryDeadWeight, methods: ["syscall_blinded_canary_dead"])
            }
        }
        return nil
#endif
    }

    /// 对指定路径执行 stat，若失败且 errno 为 ENOENT 或 EPERM 则判定金丝雀死亡
    private static func isCanaryDead(path: String) -> Bool {
        path.withCString { cPath in
            var st = stat()
            let result = stat(cPath, &st)
            if result == 0 {
                return false
            }
            let e = errno
            return e == ENOENT || e == EPERM
        }
    }
}
