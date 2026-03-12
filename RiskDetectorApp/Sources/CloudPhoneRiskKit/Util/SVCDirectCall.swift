import Darwin
import Foundation

private let rtldNext = UnsafeMutableRawPointer(bitPattern: -1)
private let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

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

enum LibcPrologueGuard {
    private static let criticalSymbols = [
        "stat", "lstat", "access", "sysctlbyname", "sysctl", "dladdr", "backtrace"
    ]

    private static let lock = NSLock()
    private static var lastScannedResult: Bool?
    private static let rescanProbabilityPercent = 30

    static func checkAllCritical() -> Bool {
        let shouldRescan = arc4random_uniform(100) < UInt32(rescanProbabilityPercent)
        if shouldRescan || lastScannedResult == nil {
            let result = performFullScan()
            lock.lock()
            lastScannedResult = result
            lock.unlock()
            return result
        }
        lock.lock()
        let cached = lastScannedResult ?? false
        lock.unlock()
        return cached
    }

    private static func performFullScan() -> Bool {
        for sym in criticalSymbols {
            if isInlineHooked(symbol: sym) {
                return true
            }
        }
        return false
    }

    static func isInlineHooked(symbol: String) -> Bool {
        guard let ptr = dlsym(rtldDefault, symbol) else { return false }
        let addr = UInt(bitPattern: ptr)

        var buf = [UInt8](repeating: 0, count: 16)
        var outSize: vm_size_t = 0

        let kr = buf.withUnsafeMutableBufferPointer { bufPtr -> kern_return_t in
            guard let base = bufPtr.baseAddress else { return KERN_FAILURE }
            return vm_read_overwrite(
                mach_task_self_,
                vm_address_t(addr),
                vm_size_t(16),
                vm_address_t(UInt(bitPattern: base)),
                &outSize
            )
        }

        guard kr == KERN_SUCCESS, outSize >= 8 else { return false }

        let insn0 = UInt32(buf[0])
            | (UInt32(buf[1]) << 8)
            | (UInt32(buf[2]) << 16)
            | (UInt32(buf[3]) << 24)

        let insn1 = UInt32(buf[4])
            | (UInt32(buf[5]) << 8)
            | (UInt32(buf[6]) << 16)
            | (UInt32(buf[7]) << 24)

        if isSuspiciousFirstInstruction(insn0) { return true }

        if isAdrpOrLdrLiteral(insn0) && isBranchRegister(insn1) { return true }

        return false
    }

    private static func isSuspiciousFirstInstruction(_ insn: UInt32) -> Bool {
        if insn & 0xFC00_0000 == 0x1400_0000 { return true }  // B (unconditional)
        if insn & 0xFC00_0000 == 0x9400_0000 { return true }  // BL
        if insn == 0xD61F_0200 { return true }                 // BR  x16
        if insn == 0xD61F_0220 { return true }                 // BR  x17
        if insn == 0xD63F_0200 { return true }                 // BLR x16
        if insn == 0xD63F_0220 { return true }                 // BLR x17
        if insn & 0xFF00_0000 == 0x5800_0000 && insn & 0x1F == 0x10 { return true }  // LDR x16
        if insn & 0xFF00_0000 == 0x5800_0000 && insn & 0x1F == 0x11 { return true }  // LDR x17
        // ADRP alone is NOT flagged here: complex library functions (dladdr, backtrace)
        // routinely start with ADRP for PC-relative addressing, producing false positives.
        // The ADRP+BR-register two-instruction pattern is handled by isInlineHooked's
        // second check (isAdrpOrLdrLiteral && isBranchRegister).
        return false
    }

    private static func isAdrpOrLdrLiteral(_ insn: UInt32) -> Bool {
        // ADRP: only flag when destination is x16 (IP0) or x17 (IP1).
        // The caller pairs this with isBranchRegister (BR x16/x17), so the
        // destination must match the branch register to form a valid trampoline.
        // Accepting any ADRP destination caused false positives when normal code
        // happened to have ADRP Xn + BR x16/x17 with n ≠ 16/17.
        if insn & 0x9F00_0000 == 0x9000_0000 {
            let rd = insn & 0x1F
            return rd == 0x10 || rd == 0x11
        }
        if insn & 0xFF00_0000 == 0x5800_0000 {
            let rd = insn & 0x1F
            if rd == 0x10 || rd == 0x11 { return true }
        }
        return false
    }

    private static func isBranchRegister(_ insn: UInt32) -> Bool {
        insn == 0xD61F_0200 || insn == 0xD61F_0220
    }
}

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
    static var timebaseInfo: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    static func measure(_ block: () -> Void) -> UInt64 {
        let start = mach_absolute_time()
        block()
        let end = mach_absolute_time()
        return (end - start) * UInt64(timebaseInfo.numer) / UInt64(timebaseInfo.denom)
    }

    static var inlineHookDetected: Bool {
        LibcPrologueGuard.checkAllCritical()
    }

    /// 同时调用标准 libc 与加固版本，结果不一致则判定为 tampered
    static func validateSysctl(key: String) -> (value: String?, tampered: Bool, bypassed: Bool, inlineHooked: Bool) {
        let hooked = inlineHookDetected

        var std: String?
        let t1 = measure { std = Sysctl.string(key) }
        
        var secure: String?
        let t2 = measure { secure = SVCDirectCall.secureSysctlbyname(key) }
        
        let bypassed = t1 < 50 || t2 < 50

        if std == nil && secure == nil { return (nil, false, bypassed, hooked) }
        if std == nil || secure == nil { return (secure ?? std, true, bypassed, hooked) }
        let tampered = std != secure
        return (secure, tampered, bypassed, hooked)
    }

    static func validateSysctlData(mib: [Int32]) -> (data: Data?, tampered: Bool, bypassed: Bool, inlineHooked: Bool) {
        let hooked = inlineHookDetected

        var std: Data?
        let t1 = measure { std = SVCDirectCall.standardSysctlData(mib) }
        
        var secure: Data?
        let t2 = measure { secure = SVCDirectCall.secureSysctlData(mib) }
        
        let bypassed = t1 < 50 || t2 < 50

        if std == nil && secure == nil { return (nil, false, bypassed, hooked) }
        if std == nil || secure == nil { return (secure ?? std, true, bypassed, hooked) }
        let tampered = std != secure
        return (secure ?? std, tampered, bypassed, hooked)
    }

    /// 同时调用标准 stat/lstat/access 与加固版本，结果不一致则判定为 tampered
    static func validateFileStat(path: String) -> (exists: Bool, tampered: Bool, bypassed: Bool, inlineHooked: Bool) {
        let hooked = inlineHookDetected

        var stdExists = false
        var stdLstatExists = false
        var stdAccessExists = false

        let t1 = measure {
            var stStd = stat()
            stdExists = path.withCString { stat($0, &stStd) == 0 }
        }
        let t2 = measure {
            var stLstatStd = stat()
            stdLstatExists = path.withCString { lstat($0, &stLstatStd) == 0 }
        }
        let t3 = measure {
            stdAccessExists = path.withCString { access($0, F_OK) == 0 }
        }

        var secureStatExists = false
        var secureLstatExists = false
        var secureAccessExists = false

        let t4 = measure { secureStatExists = SVCDirectCall.secureStat(path) }
        let t5 = measure { secureLstatExists = SVCDirectCall.secureLstat(path) }
        let t6 = measure { secureAccessExists = SVCDirectCall.secureAccess(path) }

        let bypassed = t1 < 50 || t2 < 50 || t3 < 50 || t4 < 50 || t5 < 50 || t6 < 50

        let tampered = stdExists != secureStatExists
            || stdLstatExists != secureLstatExists
            || stdAccessExists != secureAccessExists
        let exists = secureStatExists || secureLstatExists || secureAccessExists
            || stdExists || stdLstatExists || stdAccessExists
        return (exists, tampered, bypassed, hooked)
    }
}
