import Darwin
import Foundation

private let rtldNext = UnsafeMutableRawPointer(bitPattern: -1)

typealias SysctlbynameFn = @convention(c) (
    UnsafePointer<CChar>?,
    UnsafeMutableRawPointer?,
    UnsafeMutablePointer<Int>?,
    UnsafeMutableRawPointer?,
    Int
) -> Int32

typealias StatFn = @convention(c) (UnsafePointer<CChar>, UnsafeMutablePointer<stat>?) -> Int32

enum SVCDirectCall {
    private static func originalSysctlbyname() -> SysctlbynameFn? {
        guard let ptr = dlsym(rtldNext, "sysctlbyname") else { return nil }
        return unsafeBitCast(ptr, to: SysctlbynameFn.self)
    }

    private static func originalStat() -> StatFn? {
        guard let ptr = dlsym(rtldNext, "stat") else { return nil }
        return unsafeBitCast(ptr, to: StatFn.self)
    }

    /// 通过 RTLD_NEXT 获取下一跳 sysctlbyname，绕过当前进程的 PLT hook
    static func secureSysctlbyname(_ name: String) -> String? {
        guard let fn = originalSysctlbyname() else {
            return Sysctl.string(name)
        }
        return name.withCString { cName in
            var size: size_t = 0
            if fn(cName, nil, &size, nil, 0) != 0 { return nil }
            var buf = [CChar](repeating: 0, count: max(1, Int(size)))
            if fn(cName, &buf, &size, nil, 0) != 0 { return nil }
            return String(cString: buf)
        }
    }

    /// 通过 RTLD_NEXT 获取下一跳 stat，绕过当前进程的 PLT hook
    static func secureStat(_ path: String) -> Bool {
        guard let fn = originalStat() else {
            var st = stat()
            return path.withCString { stat($0, &st) == 0 }
        }
        return path.withCString { cPath in
            var st = stat()
            return fn(cPath, &st) == 0
        }
    }
}

struct DualPathValidator {
    /// 同时调用标准 libc 与加固版本，结果不一致则判定为 tampered
    static func validateSysctl(key: String) -> (value: String?, tampered: Bool) {
        let std = Sysctl.string(key)
        let secure = SVCDirectCall.secureSysctlbyname(key)
        if std == nil && secure == nil { return (nil, false) }
        if std == nil || secure == nil { return (secure ?? std, true) }
        let tampered = std != secure
        return (secure, tampered)
    }

    /// 同时调用标准 stat 与加固版本，结果不一致则判定为 tampered
    static func validateFileStat(path: String) -> (exists: Bool, tampered: Bool) {
        var stStd = stat()
        let stdExists = path.withCString { stat($0, &stStd) == 0 }
        let secureExists = SVCDirectCall.secureStat(path)
        let tampered = stdExists != secureExists
        return (secureExists, tampered)
    }
}
