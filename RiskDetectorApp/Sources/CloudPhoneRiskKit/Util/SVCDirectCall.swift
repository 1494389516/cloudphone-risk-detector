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

typealias SysctlFn = @convention(c) (
    UnsafeMutablePointer<Int32>?,
    u_int,
    UnsafeMutableRawPointer?,
    UnsafeMutablePointer<size_t>?,
    UnsafeMutableRawPointer?,
    size_t
) -> Int32

typealias StatFn = @convention(c) (UnsafePointer<CChar>, UnsafeMutablePointer<stat>?) -> Int32
typealias LstatFn = @convention(c) (UnsafePointer<CChar>, UnsafeMutablePointer<stat>?) -> Int32
typealias AccessFn = @convention(c) (UnsafePointer<CChar>, CInt) -> Int32

enum SVCDirectCall {
    private static func originalSysctlbyname() -> SysctlbynameFn? {
        guard let ptr = dlsym(rtldNext, "sysctlbyname") else { return nil }
        return unsafeBitCast(ptr, to: SysctlbynameFn.self)
    }

    private static func originalSysctl() -> SysctlFn? {
        guard let ptr = dlsym(rtldNext, "sysctl") else { return nil }
        return unsafeBitCast(ptr, to: SysctlFn.self)
    }

    private static func originalStat() -> StatFn? {
        guard let ptr = dlsym(rtldNext, "stat") else { return nil }
        return unsafeBitCast(ptr, to: StatFn.self)
    }

    private static func originalLstat() -> LstatFn? {
        guard let ptr = dlsym(rtldNext, "lstat") else { return nil }
        return unsafeBitCast(ptr, to: LstatFn.self)
    }

    private static func originalAccess() -> AccessFn? {
        guard let ptr = dlsym(rtldNext, "access") else { return nil }
        return unsafeBitCast(ptr, to: AccessFn.self)
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

    static func standardSysctlData(_ mib: [Int32]) -> Data? {
        var mibCopy = mib
        guard !mibCopy.isEmpty else { return nil }

        var length: size_t = 0
        let sizeResult = mibCopy.withUnsafeMutableBufferPointer { buffer in
            Darwin.sysctl(buffer.baseAddress, u_int(buffer.count), nil, &length, nil, 0)
        }
        guard sizeResult == 0, length > 0 else { return nil }

        var data = Data(count: Int(length))
        let success = data.withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return false }
            var sizeCopy = length
            return mibCopy.withUnsafeMutableBufferPointer { buffer in
                Darwin.sysctl(buffer.baseAddress, u_int(buffer.count), baseAddress, &sizeCopy, nil, 0) == 0 && sizeCopy > 0
            }
        }
        return success ? data : nil
    }

    /// 通过 RTLD_NEXT 获取下一跳 sysctl，绕过当前进程对 sysctl 的统一重绑定。
    static func secureSysctlData(_ mib: [Int32]) -> Data? {
        guard let fn = originalSysctl() else {
            return standardSysctlData(mib)
        }

        var mibCopy = mib
        guard !mibCopy.isEmpty else { return nil }

        var length: size_t = 0
        let sizeResult = mibCopy.withUnsafeMutableBufferPointer { buffer in
            fn(buffer.baseAddress, u_int(buffer.count), nil, &length, nil, 0)
        }
        guard sizeResult == 0, length > 0 else { return nil }

        var data = Data(count: Int(length))
        let success = data.withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return false }
            var sizeCopy = length
            return mibCopy.withUnsafeMutableBufferPointer { buffer in
                fn(buffer.baseAddress, u_int(buffer.count), baseAddress, &sizeCopy, nil, 0) == 0 && sizeCopy > 0
            }
        }
        return success ? data : nil
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

    static func secureLstat(_ path: String) -> Bool {
        guard let fn = originalLstat() else {
            var st = stat()
            return path.withCString { lstat($0, &st) == 0 }
        }
        return path.withCString { cPath in
            var st = stat()
            return fn(cPath, &st) == 0
        }
    }

    static func secureAccess(_ path: String, mode: CInt = F_OK) -> Bool {
        guard let fn = originalAccess() else {
            return path.withCString { access($0, mode) == 0 }
        }
        return path.withCString { cPath in
            fn(cPath, mode) == 0
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

    static func validateSysctlData(mib: [Int32]) -> (data: Data?, tampered: Bool) {
        let std = SVCDirectCall.standardSysctlData(mib)
        let secure = SVCDirectCall.secureSysctlData(mib)
        if std == nil && secure == nil { return (nil, false) }
        if std == nil || secure == nil { return (secure ?? std, true) }
        let tampered = std != secure
        return (secure ?? std, tampered)
    }

    /// 同时调用标准 stat/lstat/access 与加固版本，结果不一致则判定为 tampered
    static func validateFileStat(path: String) -> (exists: Bool, tampered: Bool) {
        var stStd = stat()
        let stdExists = path.withCString { stat($0, &stStd) == 0 }
        var stLstatStd = stat()
        let stdLstatExists = path.withCString { lstat($0, &stLstatStd) == 0 }
        let stdAccessExists = path.withCString { access($0, F_OK) == 0 }

        let secureStatExists = SVCDirectCall.secureStat(path)
        let secureLstatExists = SVCDirectCall.secureLstat(path)
        let secureAccessExists = SVCDirectCall.secureAccess(path)

        let tampered = stdExists != secureStatExists
            || stdLstatExists != secureLstatExists
            || stdAccessExists != secureAccessExists
        let exists = secureStatExists || secureLstatExists || secureAccessExists
            || stdExists || stdLstatExists || stdAccessExists
        return (exists, tampered)
    }
}
