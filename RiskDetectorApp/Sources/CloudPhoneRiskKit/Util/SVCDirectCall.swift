import CoreFoundation
import CRiskCore
import Darwin
import Foundation

private let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

enum LibcPrologueGuard {
    private static let criticalSymbols = [
        "access", "sysctlbyname", "sysctl", "dladdr", "backtrace"
    ]

    private static let lock = NSLock()
    private static var lastScannedResult: Bool?
    private static var lastScannedTimestamp: CFTimeInterval?
    private static let rescanProbabilityPercent = 50
    /// 距上次扫描超过此秒数强制重扫，缓解晚注入盲区
    private static let rescanIntervalSeconds: CFTimeInterval = 5

    /// 供 DualPathValidator 在检测到 tampered 时调用，清除缓存以强制下次完整扫描
    static func invalidateCache() {
        lock.lock()
        lastScannedResult = nil
        lastScannedTimestamp = nil
        lock.unlock()
    }

    static func checkAllCritical() -> Bool {
        let now = CFAbsoluteTimeGetCurrent()
        lock.lock()
        let cached = lastScannedResult
        let lastTs = lastScannedTimestamp
        lock.unlock()

        let timeDecayForced = lastTs.map { now - $0 > rescanIntervalSeconds } ?? true
        let shouldRescan = timeDecayForced
            || cached == nil
            || arc4random_uniform(100) < UInt32(rescanProbabilityPercent)

        if shouldRescan {
            let result = performFullScan()
            lock.lock()
            lastScannedResult = result
            lastScannedTimestamp = now
            lock.unlock()
            return result
        }
        return cached ?? false
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
    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 sysctlbyname。
    /// 当直 syscall 不可用或失败时返回 nil，不静默回退到标准 libc，
    /// 以便 DualPathValidator 识别安全路径失效。
    static func secureSysctlbyname(_ name: String) -> String? {
        return name.withCString { cName in
            var size: size_t = 0
            var rawErrno: CInt = 0
            if cprisk_sysctlbyname_direct(cName, nil, &size, nil, 0, &rawErrno) != 0 || size == 0 {
                return nil
            }
            var buf = [CChar](repeating: 0, count: max(1, Int(size)))
            let result = buf.withUnsafeMutableBufferPointer { buffer in
                cprisk_sysctlbyname_direct(cName, buffer.baseAddress, &size, nil, 0, &rawErrno)
            }
            if result != 0 || size == 0 {
                return nil
            }
            if buf[Int(size) - 1] != 0 {
                buf.append(0)
            }
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

    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 sysctl。
    /// 当直 syscall 不可用或失败时返回 nil，不静默回退到 standardSysctlData，
    /// 以便 DualPathValidator 识别安全路径失效。
    static func secureSysctlData(_ mib: [Int32]) -> Data? {
        var mibCopy = mib
        guard !mibCopy.isEmpty else { return nil }

        var length: size_t = 0
        var rawErrno: CInt = 0
        let sizeResult = mibCopy.withUnsafeMutableBufferPointer { buffer in
            cprisk_sysctl_direct(buffer.baseAddress, u_int(buffer.count), nil, &length, nil, 0, &rawErrno)
        }
        guard sizeResult == 0, length > 0 else { return nil }

        var data = Data(count: Int(length))
        let success = data.withUnsafeMutableBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return false }
            var sizeCopy = length
            return mibCopy.withUnsafeMutableBufferPointer { buffer in
                cprisk_sysctl_direct(buffer.baseAddress, u_int(buffer.count), baseAddress, &sizeCopy, nil, 0, &rawErrno) == 0
                    && sizeCopy > 0
            }
        }
        return success ? data : nil
    }

    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 stat。
    /// 直 syscall 不可用或失败时返回 nil（安全路径不可用），不静默回退到标准 libc。
    static func secureStat(_ path: String) -> Bool? {
        return path.withCString { cPath in
            var rawErrno: CInt = 0
            let result = cprisk_stat_direct(cPath, nil, &rawErrno)
            if result == 0 { return true }
            if rawErrno == ENOENT || rawErrno == ENOTDIR { return false }
            return nil
        }
    }

    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 lstat。
    /// 直 syscall 不可用或失败时返回 nil（安全路径不可用），不静默回退到标准 libc。
    static func secureLstat(_ path: String) -> Bool? {
        return path.withCString { cPath in
            var rawErrno: CInt = 0
            let result = cprisk_lstat_direct(cPath, nil, &rawErrno)
            if result == 0 { return true }
            if rawErrno == ENOENT || rawErrno == ENOTDIR { return false }
            return nil
        }
    }

    /// App Store 兼容路径不再依赖文件元数据类 API，因此不暴露 inode/st_dev/st_size。
    /// 若后续需要恢复元数据基线能力，应在企业分发构建中单独启用。
    static func secureLstatDetail(path: String) -> (inode: UInt64, stDev: UInt32, stSize: Int64)? {
        nil
    }

    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 access。
    /// 直 syscall 不可用或失败时返回 nil（安全路径不可用），不静默回退到标准 libc。
    static func secureAccess(_ path: String, mode: CInt = F_OK) -> Bool? {
        return path.withCString { cPath in
            var rawErrno: CInt = 0
            let result = cprisk_access_direct(cPath, mode, &rawErrno)
            if result == 0 { return true }
            if rawErrno == ENOENT || rawErrno == ENOTDIR || rawErrno == EACCES || rawErrno == EPERM { return false }
            return nil
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

    // MARK: - getpid SVC 动态基线（DBI 过慢检测）

    private static let baselineLock = NSLock()
    private static var cachedGetpidBaseline: UInt64 = 0
    private static var baselineTimestamp: CFTimeInterval = 0
    private static let baselineCacheDuration: CFTimeInterval = 5.0
    /// 实际 syscall 耗时超过 getpid 基线的此倍数即判定为 DBI traced
    private static let stalkerSlowdownMultiplier: UInt64 = 500

    static var getpidBaseline: UInt64 {
        let now = CFAbsoluteTimeGetCurrent()
        baselineLock.lock()
        let cached = cachedGetpidBaseline
        let ts = baselineTimestamp
        baselineLock.unlock()

        if cached > 0 && (now - ts) < baselineCacheDuration {
            return cached
        }
        let baseline = measure { _ = cprisk_getpid_direct() }
        let value = max(baseline, 1)
        baselineLock.lock()
        cachedGetpidBaseline = value
        baselineTimestamp = now
        baselineLock.unlock()
        return value
    }

    static func isTracedTiming(_ durations: UInt64...) -> Bool {
        let threshold = getpidBaseline &* stalkerSlowdownMultiplier
        return durations.contains { $0 > threshold }
    }

    /// 同时调用标准 libc 与加固版本，结果不一致则判定为 tampered
    static func validateSysctl(key: String) -> (value: String?, tampered: Bool, bypassed: Bool, traced: Bool, inlineHooked: Bool) {
        let hooked = inlineHookDetected

        var std: String?
        let t1 = measure { std = Sysctl.string(key) }
        
        var secure: String?
        let t2 = measure { secure = SVCDirectCall.secureSysctlbyname(key) }
        
        // 50 纳秒：检测「时序注入绕过」——syscall 异常快（如被 stub 或直接返回）时判定 bypassed。
        let bypassed = t1 < 50 || t2 < 50
        let traced = isTracedTiming(t1, t2)

        if std == nil && secure == nil { return (nil, false, bypassed, traced, hooked) }
        if std == nil || secure == nil { return (secure ?? std, true, bypassed, traced, hooked) }
        let tampered = std != secure
        if tampered { LibcPrologueGuard.invalidateCache() }
        return (secure, tampered, bypassed, traced, hooked)
    }

    static func validateSysctlData(mib: [Int32]) -> (data: Data?, tampered: Bool, bypassed: Bool, traced: Bool, inlineHooked: Bool) {
        let hooked = inlineHookDetected

        var std: Data?
        let t1 = measure { std = SVCDirectCall.standardSysctlData(mib) }
        
        var secure: Data?
        let t2 = measure { secure = SVCDirectCall.secureSysctlData(mib) }
        
        // 50 纳秒：检测「时序注入绕过」，非 stat 延迟阈值（见上方 validateSysctl 注释）
        let bypassed = t1 < 50 || t2 < 50
        let traced = isTracedTiming(t1, t2)

        if std == nil && secure == nil { return (nil, false, bypassed, traced, hooked) }
        if std == nil || secure == nil { return (secure ?? std, true, bypassed, traced, hooked) }
        let tampered = std != secure
        if tampered { LibcPrologueGuard.invalidateCache() }
        return (secure ?? std, tampered, bypassed, traced, hooked)
    }

    /// 同时调用高层 fileExists / 标准 access / 加固 access，结果不一致则判定为 tampered。
    /// 当 secure 路径返回 nil（安全路径不可用）且标准路径有值时，判定 tampered=true。
    static func validateFileStat(path: String) -> (exists: Bool, tampered: Bool, bypassed: Bool, traced: Bool, inlineHooked: Bool) {
        let hooked = inlineHookDetected

        var fileManagerExists = false
        var stdAccessExists = false

        let t1 = measure {
            fileManagerExists = FileManager.default.fileExists(atPath: path)
        }
        let t2 = measure {
            stdAccessExists = path.withCString { access($0, F_OK) == 0 }
        }

        var secureAccessExists: Bool?

        let t3 = measure { secureAccessExists = SVCDirectCall.secureAccess(path) }

        // 50 纳秒：检测「时序注入绕过」，任一探针异常快则 bypassed。
        let bypassed = t1 < 50 || t2 < 50 || t3 < 50
        let traced = isTracedTiming(t1, t2, t3)

        // 安全路径返回 nil 且 std 有值：安全路径失效本身即异常，判定 tampered
        let secureUnavailableButStdHasValue =
            secureAccessExists == nil && (fileManagerExists || stdAccessExists)
        // 双路均有值时，结果不一致则 tampered
        let mismatchWhenBothAvailable =
            (secureAccessExists != nil && secureAccessExists != fileManagerExists)
            || (secureAccessExists != nil && secureAccessExists != stdAccessExists)
        let tampered = secureUnavailableButStdHasValue || mismatchWhenBothAvailable
        if tampered { LibcPrologueGuard.invalidateCache() }
        let exists = secureAccessExists ?? stdAccessExists || fileManagerExists
        return (exists, tampered, bypassed, traced, hooked)
    }
}
