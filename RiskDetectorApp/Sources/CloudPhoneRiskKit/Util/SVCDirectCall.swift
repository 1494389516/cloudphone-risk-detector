import CoreFoundation
import CRiskCore
import Darwin
import Foundation

private let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

/// Centralized runtime symbol resolver for sensitive libc APIs.
/// - Stores symbol bytes in obfuscated form.
/// - Resolves via dlsym at runtime.
/// - Signs/authenticates resolved function pointers with PAC when available.
enum DynamicSymbolResolver {
    typealias SocketFn = @convention(c) (Int32, Int32, Int32) -> Int32
    typealias ConnectFn = @convention(c) (Int32, UnsafePointer<sockaddr>?, socklen_t) -> Int32
    typealias CloseFn = @convention(c) (Int32) -> Int32
    typealias AccessFn = @convention(c) (UnsafePointer<CChar>?, Int32) -> Int32
    typealias SysctlByNameFn = @convention(c) (
        UnsafePointer<CChar>?,
        UnsafeMutableRawPointer?,
        UnsafeMutablePointer<size_t>?,
        UnsafeRawPointer?,
        size_t
    ) -> Int32
    typealias DlopenFn = @convention(c) (UnsafePointer<CChar>?, Int32) -> UnsafeMutableRawPointer?
    typealias TaskForPidFn = @convention(c) (
        mach_port_name_t,
        pid_t,
        UnsafeMutablePointer<mach_port_name_t>?
    ) -> kern_return_t

    private enum SymbolID: String {
        case sysctlByName
        case socket
        case connect
        case close
        case access
        case dlopen
        case taskForPid
    }

    private struct SymbolRecipe {
        let encodedSymbol: [UInt8]
        let symbolKey: UInt8
        let encodedImage: [UInt8]?
        let imageKey: UInt8
        let discriminatorSalt: UInt64
    }

    private struct SignedEntry {
        let signedPointer: UnsafeMutableRawPointer
        let discriminator: UInt
    }

    private static let lock = UnfairLock()
    private static var cache: [SymbolID: SignedEntry] = [:]

    private static let recipes: [SymbolID: SymbolRecipe] = [
        .sysctlByName: SymbolRecipe(
            encodedSymbol: [0x45, 0x4F, 0x45, 0x55, 0x42, 0x5A, 0x54, 0x4F, 0x58, 0x57, 0x5B, 0x53],
            symbolKey: 0x36,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0xA179_F31C_05D2_8441
        ),
        .socket: SymbolRecipe(
            encodedSymbol: [0x5A, 0x46, 0x4A, 0x42, 0x4C, 0x5D],
            symbolKey: 0x29,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0xFC12_E739_BA9D_0042
        ),
        .connect: SymbolRecipe(
            encodedSymbol: [0x28, 0x24, 0x25, 0x25, 0x2E, 0x28, 0x3F],
            symbolKey: 0x4B,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0x88D1_7C2A_E963_91D4
        ),
        .close: SymbolRecipe(
            encodedSymbol: [0x10, 0x1F, 0x1C, 0x00, 0x16],
            symbolKey: 0x73,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0x3E71_2B95_C004_F8AA
        ),
        .access: SymbolRecipe(
            encodedSymbol: [0x34, 0x36, 0x36, 0x30, 0x26, 0x26],
            symbolKey: 0x55,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0xD7B6_4E51_93CB_262A
        ),
        .dlopen: SymbolRecipe(
            encodedSymbol: [0x7B, 0x73, 0x70, 0x6F, 0x7A, 0x71],
            symbolKey: 0x1F,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0x4FB9_1887_4602_1CE1
        ),
        .taskForPid: SymbolRecipe(
            encodedSymbol: [0x4D, 0x58, 0x4A, 0x52, 0x66, 0x5F, 0x56, 0x4B, 0x66, 0x49, 0x50, 0x5D],
            symbolKey: 0x39,
            encodedImage: nil,
            imageKey: 0x00,
            discriminatorSalt: 0x6C51_0A9D_14E2_77BC
        )
    ]

    static func socket(_ domain: Int32, _ type: Int32, _ protocol: Int32) -> Int32 {
        if let socketFn: SocketFn = resolveFunction(for: .socket, as: SocketFn.self) {
            return socketFn(domain, type, `protocol`)
        }

        var rawErrno: CInt = 0
        let fd = cprisk_socket_direct(domain, type, `protocol`, &rawErrno)
        if rawErrno != 0 {
            errno = rawErrno
        }
        return fd
    }

    static func connect(_ sockfd: Int32, _ addr: UnsafePointer<sockaddr>?, _ addrlen: socklen_t) -> Int32 {
        if let connectFn: ConnectFn = resolveFunction(for: .connect, as: ConnectFn.self) {
            return connectFn(sockfd, addr, addrlen)
        }

        var rawErrno: CInt = 0
        let rc = cprisk_connect_direct(sockfd, addr, addrlen, &rawErrno)
        if rawErrno != 0 {
            errno = rawErrno
        }
        return rc
    }

    static func close(_ fd: Int32) -> Int32 {
        if let closeFn: CloseFn = resolveFunction(for: .close, as: CloseFn.self) {
            return closeFn(fd)
        }

        var rawErrno: CInt = 0
        let rc = cprisk_close_direct(fd, &rawErrno)
        if rawErrno != 0 {
            errno = rawErrno
        }
        return rc
    }

    static func access(_ path: UnsafePointer<CChar>?, _ mode: Int32) -> Int32 {
        if let accessFn: AccessFn = resolveFunction(for: .access, as: AccessFn.self) {
            return accessFn(path, mode)
        }

        var rawErrno: CInt = 0
        let rc = cprisk_access_direct(path, mode, &rawErrno)
        if rawErrno != 0 {
            errno = rawErrno
        }
        return rc
    }

    static func sysctlByName(
        _ name: UnsafePointer<CChar>?,
        _ oldp: UnsafeMutableRawPointer?,
        _ oldlenp: UnsafeMutablePointer<size_t>?,
        _ newp: UnsafeRawPointer?,
        _ newlen: size_t
    ) -> Int32 {
        if let sysctlByNameFn: SysctlByNameFn = resolveFunction(for: .sysctlByName, as: SysctlByNameFn.self) {
            return sysctlByNameFn(name, oldp, oldlenp, newp, newlen)
        }

        var rawErrno: CInt = 0
        let rc = cprisk_sysctlbyname_direct(name, oldp, oldlenp, newp, newlen, &rawErrno)
        if rawErrno != 0 {
            errno = rawErrno
        }
        return rc
    }

    static func dlopen(_ path: UnsafePointer<CChar>?, _ mode: Int32) -> UnsafeMutableRawPointer? {
        if let dlopenFn: DlopenFn = resolveFunction(for: .dlopen, as: DlopenFn.self) {
            return dlopenFn(path, mode)
        }
        return nil
    }

    static func taskForPid(
        _ targetTask: mach_port_name_t,
        _ pid: pid_t,
        _ taskOut: UnsafeMutablePointer<mach_port_name_t>?
    ) -> kern_return_t {
        if let taskForPidFn: TaskForPidFn = resolveFunction(for: .taskForPid, as: TaskForPidFn.self) {
            return taskForPidFn(targetTask, pid, taskOut)
        }
        taskOut?.pointee = mach_port_name_t(MACH_PORT_NULL)
        return kern_return_t(KERN_FAILURE)
    }

    private static func resolveFunction<T>(for symbolID: SymbolID, as type: T.Type) -> T? {
        guard let entry = resolveSignedEntry(for: symbolID) else {
            return nil
        }
        guard let authed = authenticate(entry, for: symbolID) else {
            return nil
        }
        return unsafeBitCast(authed, to: type)
    }

    private static func resolveSignedEntry(for symbolID: SymbolID) -> SignedEntry? {
        if let cached = lock.withLock({ cache[symbolID] }) { return cached }

        guard let recipe = recipes[symbolID] else {
            return nil
        }

        let symbolName = deobfuscate(recipe.encodedSymbol, key: recipe.symbolKey)
        let imageName: String? = recipe.encodedImage.map { deobfuscate($0, key: recipe.imageKey) }
        let handle = imageName.flatMap { name in
            name.withCString { Darwin.dlopen($0, RTLD_NOW | RTLD_LOCAL) }
        } ?? rtldDefault

        guard let handle else {
            return nil
        }

        guard let symbolPtr = symbolName.withCString({ dlsym(handle, $0) }) else {
            return nil
        }

        let discriminator = makeDiscriminator(symbol: symbolName, image: imageName, salt: recipe.discriminatorSalt)
        guard let signed = cprisk_pac_sign_function_pointer(symbolPtr, discriminator) else {
            return nil
        }
        let created = SignedEntry(signedPointer: signed, discriminator: discriminator)

        return lock.withLock {
            let existing = cache[symbolID]
            if existing == nil {
                cache[symbolID] = created
            }
            return cache[symbolID]
        }
    }

    private static func authenticate(_ entry: SignedEntry, for symbolID: SymbolID) -> UnsafeMutableRawPointer? {
        guard let authed = cprisk_pac_auth_function_pointer(entry.signedPointer, entry.discriminator) else {
            cprisk_integrity_poison_svc_iface_lane()
            lock.withLock { cache.removeValue(forKey: symbolID) }
            return nil
        }
        return authed
    }

    @inline(__always)
    private static func deobfuscate(_ bytes: [UInt8], key: UInt8) -> String {
        let decoded = bytes.map { $0 ^ key }
        return String(decoding: decoded, as: UTF8.self)
    }

    @inline(__always)
    private static func makeDiscriminator(symbol: String, image: String?, salt: UInt64) -> UInt {
        var state = fnv1a64(symbol)
        if let image {
            state ^= fnv1a64(image)
        }
        return UInt(truncatingIfNeeded: state ^ salt)
    }

    @inline(__always)
    private static func fnv1a64(_ input: String) -> UInt64 {
        var hash: UInt64 = 0xCBF2_9CE4_8422_2325
        for byte in input.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01B3
        }
        return hash
    }
}

enum LibcPrologueGuard {
    private static let criticalSymbols = [
        "access", "sysctlbyname", "sysctl", "dladdr", "backtrace"
    ]

    private static let lock = UnfairLock()
    private static var lastScannedResult: Bool?
    private static var lastScannedTimestamp: CFTimeInterval?
    private static let rescanProbabilityPercent = 50
    /// 距上次扫描超过此秒数强制重扫，缓解晚注入盲区
    private static let rescanIntervalSeconds: CFTimeInterval = 5

    /// 供 DualPathValidator 在检测到 tampered 时调用，清除缓存以强制下次完整扫描
    static func invalidateCache() {
        lock.withLock {
            lastScannedResult = nil
            lastScannedTimestamp = nil
        }
    }

    static func checkAllCritical() -> Bool {
        let now = CFAbsoluteTimeGetCurrent()
        let (cached, lastTs) = lock.withLock { (lastScannedResult, lastScannedTimestamp) }

        let timeDecayForced = lastTs.map { now - $0 > rescanIntervalSeconds } ?? true
        let shouldRescan = timeDecayForced
            || cached == nil
            || arc4random_uniform(100) < UInt32(rescanProbabilityPercent)

        if shouldRescan {
            let result = performFullScan()
            lock.withLock {
                lastScannedResult = result
                lastScannedTimestamp = now
            }
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
    struct StandardPathProbeSnapshot {
        let access: Bool?
        let stat: Bool?
        let fopen: Bool?

        var availableProbeCount: Int {
            [access, stat, fopen].filter { $0 != nil }.count
        }

        var availableValues: [Bool] {
            [access, stat, fopen].compactMap { $0 }
        }

        var existsAny: Bool {
            availableValues.contains(true)
        }
    }

    struct SecurePathProbeSnapshot {
        let access: Bool?
        let stat: Bool?
        let lstat: Bool?

        var availableProbeCount: Int {
            [access, stat, lstat].compactMap { $0 }.count
        }

        var unavailableProbeCount: Int {
            3 - availableProbeCount
        }

        var anySecureProbeAvailable: Bool {
            availableProbeCount > 0
        }
    }

    private struct MaskedPathEnvelope {
        var bytes: [UInt8]
        let seed: UInt32
    }

    @inline(__always)
    private static func pathMaskLane(seed: UInt32, index: Int) -> UInt8 {
        let shift = UInt32((index & 3) * 8)
        var lane = UInt8(truncatingIfNeeded: seed >> shift)
        lane ^= UInt8(truncatingIfNeeded: index &* 17 &+ 0x5D)
        let rot = index & 7
        if rot != 0 {
            lane = (lane << rot) | (lane >> (8 - rot))
        }
        lane ^= UInt8(truncatingIfNeeded: index &* 29 &+ 0xA7)
        return lane
    }

    private static func maskedPathEnvelope(_ path: String) -> MaskedPathEnvelope? {
        var bytes = path.utf8CString.map { UInt8(bitPattern: $0) }
        guard !bytes.isEmpty else { return nil }

        let seed = UInt32(truncatingIfNeeded: mach_absolute_time())
            ^ arc4random()
            ^ UInt32(truncatingIfNeeded: bytes.count &* 0x45D9)

        for index in bytes.indices {
            bytes[index] ^= pathMaskLane(seed: seed, index: index)
        }
        return MaskedPathEnvelope(bytes: bytes, seed: seed)
    }

    private static func zeroizeMaskedPath(_ bytes: inout [UInt8]) {
        for index in bytes.indices {
            bytes[index] = 0
        }
    }

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
            var buf = [CChar](repeating: 0, count: max(1, Int(size) + 1))
            let result = buf.withUnsafeMutableBufferPointer { buffer in
                cprisk_sysctlbyname_direct(cName, buffer.baseAddress, &size, nil, 0, &rawErrno)
            }
            if result != 0 || size == 0 || Int(size) >= buf.count {
                return nil
            }
            buf[Int(size)] = 0
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
        guard var envelope = maskedPathEnvelope(path) else { return nil }
        defer { zeroizeMaskedPath(&envelope.bytes) }
        return envelope.bytes.withUnsafeBufferPointer { buffer in
            var rawErrno: CInt = 0
            let result = cprisk_stat_masked(buffer.baseAddress, buffer.count, envelope.seed, nil, &rawErrno)
            if result == 0 { return true }
            if rawErrno == ENOENT || rawErrno == ENOTDIR { return false }
            return nil
        }
    }

    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 lstat。
    /// 直 syscall 不可用或失败时返回 nil（安全路径不可用），不静默回退到标准 libc。
    static func secureLstat(_ path: String) -> Bool? {
        guard var envelope = maskedPathEnvelope(path) else { return nil }
        defer { zeroizeMaskedPath(&envelope.bytes) }
        return envelope.bytes.withUnsafeBufferPointer { buffer in
            var rawErrno: CInt = 0
            let result = cprisk_lstat_masked(buffer.baseAddress, buffer.count, envelope.seed, nil, &rawErrno)
            if result == 0 { return true }
            if rawErrno == ENOENT || rawErrno == ENOTDIR { return false }
            return nil
        }
    }

    /// 通过 direct lstat 读取 inode/st_dev/st_size，用于跨时间基线漂移检测。
    /// 失败时返回 nil，由上层回退为“无基线可用”逻辑而非崩溃。
    static func secureLstatDetail(path: String) -> (inode: UInt64, stDev: UInt32, stSize: Int64)? {
        guard var envelope = maskedPathEnvelope(path) else { return nil }
        defer { zeroizeMaskedPath(&envelope.bytes) }
        return envelope.bytes.withUnsafeBufferPointer { buffer in
            var rawErrno: CInt = 0
            var sb = stat()
            let result = cprisk_lstat_masked(buffer.baseAddress, buffer.count, envelope.seed, &sb, &rawErrno)
            guard result == 0 else {
                return nil
            }

            let inode = UInt64(sb.st_ino)
            let stDev = UInt32(truncatingIfNeeded: sb.st_dev)
            let stSize = Int64(sb.st_size)
            return (inode: inode, stDev: stDev, stSize: stSize)
        }
    }

    static func securePathProbeSnapshot(_ path: String, mode: CInt = F_OK) -> SecurePathProbeSnapshot {
        SecurePathProbeSnapshot(
            access: secureAccess(path, mode: mode),
            stat: secureStat(path),
            lstat: secureLstat(path)
        )
    }

    static func standardPathProbeSnapshot(_ path: String) -> StandardPathProbeSnapshot {
        guard var envelope = maskedPathEnvelope(path) else {
            return StandardPathProbeSnapshot(access: nil, stat: nil, fopen: nil)
        }
        defer { zeroizeMaskedPath(&envelope.bytes) }
        var cSnapshot = cprisk_path_probe_snapshot_t(available_mask: 0, exists_mask: 0)
        let status = envelope.bytes.withUnsafeBufferPointer {
            cprisk_probe_path_snapshot_masked($0.baseAddress, $0.count, envelope.seed, &cSnapshot)
        }
        guard status == 0 else {
            return StandardPathProbeSnapshot(access: nil, stat: nil, fopen: nil)
        }

        func probeValue(_ probeMask: UInt32) -> Bool? {
            guard (cSnapshot.available_mask & probeMask) != 0 else { return nil }
            return (cSnapshot.exists_mask & probeMask) != 0
        }

        return StandardPathProbeSnapshot(
            access: probeValue(UInt32(CPRISK_PATH_PROBE_ACCESS)),
            stat: probeValue(UInt32(CPRISK_PATH_PROBE_STAT)),
            fopen: probeValue(UInt32(CPRISK_PATH_PROBE_FOPEN))
        )
    }

    /// 通过 CRiskCore 的 arm64 直 syscall 路径调用 access。
    /// 直 syscall 不可用或失败时返回 nil（安全路径不可用），不静默回退到标准 libc。
    static func secureAccess(_ path: String, mode: CInt = F_OK) -> Bool? {
        guard var envelope = maskedPathEnvelope(path) else { return nil }
        defer { zeroizeMaskedPath(&envelope.bytes) }
        return envelope.bytes.withUnsafeBufferPointer { buffer in
            var rawErrno: CInt = 0
            let result = cprisk_access_masked(buffer.baseAddress, buffer.count, envelope.seed, mode, &rawErrno)
            if result == 0 { return true }
            if rawErrno == ENOENT || rawErrno == ENOTDIR || rawErrno == EACCES || rawErrno == EPERM { return false }
            return nil
        }
    }

    static func standardAccessErrnoMasked(_ path: String, mode: CInt = F_OK) -> (exists: Bool, errno: Int32)? {
        guard var envelope = maskedPathEnvelope(path) else { return nil }
        defer { zeroizeMaskedPath(&envelope.bytes) }
        return envelope.bytes.withUnsafeBufferPointer { buffer in
            var rawErrno: CInt = 0
            let result = cprisk_access_masked_libc(buffer.baseAddress, buffer.count, envelope.seed, mode, &rawErrno)
            if result == 0 {
                return (true, 0)
            }
            return (false, rawErrno)
        }
    }
}

struct DualPathValidator {
    static let timebaseInfo: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    static func measure(_ block: () -> Void) -> UInt64 {
        let start = mach_absolute_time()
        block()
        let end = mach_absolute_time()
        // Divide first to avoid UInt64 overflow for large time deltas
        let elapsed = end - start
        let denom = UInt64(max(timebaseInfo.denom, 1))
        let numer = UInt64(timebaseInfo.numer)
        return elapsed / denom * numer
    }

    static var inlineHookDetected: Bool {
        LibcPrologueGuard.checkAllCritical()
    }

    // MARK: - getpid SVC 动态基线（DBI 过慢检测）

    private static let baselineLock = UnfairLock()
    private static var cachedGetpidBaseline: UInt64 = 0
    private static var baselineTimestamp: CFTimeInterval = 0
    private static let baselineCacheDuration: CFTimeInterval = 5.0
    /// 实际 syscall 耗时超过 getpid 基线的此倍数即判定为 DBI traced
    private static let stalkerSlowdownMultiplier: UInt64 = 500

    static var getpidBaseline: UInt64 {
        let now = CFAbsoluteTimeGetCurrent()
        let (cached, ts) = baselineLock.withLock { (cachedGetpidBaseline, baselineTimestamp) }

        if cached > 0 && (now - ts) < baselineCacheDuration {
            return cached
        }
        let baseline = measure { _ = cprisk_getpid_direct() }
        let value = max(baseline, 1)
        baselineLock.withLock {
            cachedGetpidBaseline = value
            baselineTimestamp = now
        }
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

    /// 同时调用 C 层标准路径探针（access/stat/fopen）与加固 access；
    /// 结果不一致或安全路径不可用且标准路径命中时，判定 tampered。
    static func validateFileStat(path: String) -> (exists: Bool, tampered: Bool, bypassed: Bool, traced: Bool, inlineHooked: Bool) {
        let hooked = inlineHookDetected

        var standardSnapshot = SVCDirectCall.StandardPathProbeSnapshot(access: nil, stat: nil, fopen: nil)
        let t1 = measure {
            standardSnapshot = SVCDirectCall.standardPathProbeSnapshot(path)
        }

        var secureAccessExists: Bool?
        let t2 = measure { secureAccessExists = SVCDirectCall.secureAccess(path) }

        // 50 纳秒：检测「时序注入绕过」，任一探针异常快则 bypassed。
        let bypassed = t1 < 50 || t2 < 50
        let traced = isTracedTiming(t1, t2)

        let standardValues = standardSnapshot.availableValues
        let standardExists = standardSnapshot.existsAny

        // 安全路径返回 nil 且标准探针命中：安全路径失效本身即异常，判定 tampered
        let secureUnavailableButStdHasValue =
            secureAccessExists == nil && standardExists
        // 双路均有值时，任一标准探针与 secure 结论冲突则 tampered
        let mismatchWhenBothAvailable =
            secureAccessExists != nil && standardValues.contains { $0 != secureAccessExists }
        let tampered = secureUnavailableButStdHasValue || mismatchWhenBothAvailable
        if tampered { LibcPrologueGuard.invalidateCache() }
        let exists = (secureAccessExists ?? standardExists) || standardExists
        return (exists, tampered, bypassed, traced, hooked)
    }
}
