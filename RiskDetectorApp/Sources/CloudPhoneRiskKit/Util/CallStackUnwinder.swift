import Darwin
import Foundation
import MachO

/// SDK 4.4 Phase 3: 执行流栈回溯 (Call Stack Unwinding & CFI)
///
/// 在核心加解密、关键检测逻辑、抛出高危 tampered 信号的瞬间，触发轻量级栈回溯。
/// 将提取到的返回地址交给多层验证：
///   1) RTLD_NEXT dual-path dladdr（检测 dladdr 自身被 hook）
///   2) 动态信任镜像缓存（启动时快照）
///   3) 严格前缀匹配（含 .framework/ 后缀）
///   4) vm_region_64 交叉验证（匿名可执行内存 = 恶意）
///
/// 纯 Swift 实现，仅使用 import Darwin 调用系统 API，无 C 代码。
public enum CallStackUnwinder {

    public static let ropChainSignalId = "rop_chain_detected"
    public static let dladdrHookSignalId = "dladdr_hook_detected"

    private static let maliciousWeight = 90

    // MARK: - RTLD_NEXT dual-path resolution

    private static let rtldNext = UnsafeMutableRawPointer(bitPattern: -1)

    private typealias DladdrFn = @convention(c) (
        UnsafeRawPointer?, UnsafeMutablePointer<Dl_info>?
    ) -> Int32

    private typealias BacktraceFn = @convention(c) (
        UnsafeMutablePointer<UnsafeMutableRawPointer?>?, Int32
    ) -> Int32

    private static let nextDladdrFn: DladdrFn? = {
        guard let ptr = dlsym(rtldNext, "dladdr") else { return nil }
        return unsafeBitCast(ptr, to: DladdrFn.self)
    }()

    private static let nextBacktraceFn: BacktraceFn? = {
        guard let ptr = dlsym(rtldNext, "backtrace") else { return nil }
        return unsafeBitCast(ptr, to: BacktraceFn.self)
    }()

    // MARK: - Strict system library path prefixes

    private static let knownSystemLibPrefixes: [String] = [
        "/usr/lib/system/",
        "/usr/lib/libsystem",
        "/usr/lib/libobjc",
        "/usr/lib/dyld",
        "/usr/lib/libdispatch",
        "/System/Library/Frameworks/Foundation.framework/",
        "/System/Library/Frameworks/CoreFoundation.framework/",
        "/System/Library/Frameworks/Security.framework/",
        "/System/Library/Frameworks/CFNetwork.framework/",
        "/System/Library/Frameworks/UIKit.framework/",
        "/System/Library/Frameworks/QuartzCore.framework/",
        "/System/Library/Frameworks/Accelerate.framework/",
        "/System/Library/Frameworks/ImageIO.framework/",
        "/System/Library/Frameworks/Metal.framework/",
        "/System/Library/Frameworks/AVFoundation.framework/",
        "/System/Library/Frameworks/CoreGraphics.framework/",
        "/System/Library/Frameworks/CoreText.framework/",
        "/System/Library/PrivateFrameworks/UIKitCore.framework/",
        "/System/Library/PrivateFrameworks/GraphicsServices.framework/",
        "/System/Library/PrivateFrameworks/FrontBoardServices.framework/",
    ]

    // MARK: - Dynamic trusted image cache (snapshot at first access)

    private static let trustedImagePaths: Set<String> = {
        var paths = Set<String>()
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let raw = _dyld_get_image_name(i) else { continue }
            paths.insert(String(cString: raw))
        }
        return paths
    }()

    // MARK: - VM region anonymous-executable tags (shared with RWXMemoryScanner)

    private static let anonymousUserTags: Set<UInt32> = [240, 241, 242, 243, 244, 245]

    // MARK: - Public API

    /// 校验当前调用栈合法性
    ///
    /// - Returns: (isMalicious: 是否检测到恶意跳转, signalId: 若恶意则返回信号 ID)
    public static func validateCallStack() -> (isMalicious: Bool, signalId: String?) {
        #if targetEnvironment(simulator)
        return (false, nil)
        #else
        let addresses = captureReturnAddresses()
        guard !addresses.isEmpty else {
            return (false, nil)
        }

        var trustedRanges: [Range<UInt64>] = []
        if let main = mainAppTextSegmentRange() {
            trustedRanges.append(main)
        }
        if let sdk = sdkTextSegmentRange() {
            trustedRanges.append(sdk)
        }

        for addr in addresses {
            let result = validateAddress(addr, trustedRanges: trustedRanges)
            if result.dladdrHooked {
                return (true, dladdrHookSignalId)
            }
            if !result.legitimate {
                return (true, ropChainSignalId)
            }
        }
        return (false, nil)
        #endif
    }

    /// 校验调用栈并返回 RiskSignal（供 AntiTamperingSignalProvider 等使用）
    public static func validateCallStackAsSignal() -> RiskSignal? {
        let (isMalicious, signalId) = validateCallStack()
        guard isMalicious, let id = signalId else { return nil }
        return RiskSignal(
            id: id,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 0,
            evidence: [
                "detail": "call_stack_return_address_outside_trusted_regions",
                "mechanism": "dladdr_dual_path_vm_region_validation",
            ],
            state: .tampered,
            layer: 2,
            weightHint: Double(maliciousWeight)
        )
    }

    // MARK: - Stack capture (RTLD_NEXT backtrace to bypass PLT hook)

    private static func captureReturnAddresses() -> [UInt64] {
        var buffer = [UnsafeMutableRawPointer?](repeating: nil, count: 64)

        let count: Int32
        if let fn = nextBacktraceFn {
            count = fn(&buffer, Int32(buffer.count))
        } else {
            count = backtrace(&buffer, Int32(buffer.count))
        }

        guard count > 0 else {
            return parseAddressesFromThreadCallStackSymbols()
        }

        var addresses: [UInt64] = []
        for i in 0..<Int(count) {
            guard let ptr = buffer[i] else { continue }
            addresses.append(UInt64(bitPattern: Int64(Int(bitPattern: ptr))))
        }

        return addresses.isEmpty ? parseAddressesFromThreadCallStackSymbols() : addresses
    }

    /// 备选：从 Thread.callStackSymbols 解析地址（纯 Swift）
    private static func parseAddressesFromThreadCallStackSymbols() -> [UInt64] {
        let symbols = Thread.callStackSymbols
        var addresses: [UInt64] = []

        for line in symbols {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            for part in parts {
                let s = String(part)
                if s.hasPrefix("0x"), s.count >= 10, s.count <= 18 {
                    if let addr = UInt64(s.dropFirst(2), radix: 16) {
                        addresses.append(addr)
                        break
                    }
                }
            }
        }
        return addresses
    }

    // MARK: - __TEXT segment ranges

    private static func mainAppTextSegmentRange() -> Range<UInt64>? {
        guard let header = _dyld_get_image_header(0) else { return nil }
        return textSegmentRange(header: UnsafeRawPointer(header))
    }

    private static func sdkTextSegmentRange() -> Range<UInt64>? {
        let count = _dyld_image_count()
        for i in 0..<count {
            guard let raw = _dyld_get_image_name(i) else { continue }
            let path = String(cString: raw)
            if path.lowercased().contains("cloudphoneriskkit") {
                guard let header = _dyld_get_image_header(i) else { continue }
                return textSegmentRange(header: UnsafeRawPointer(header))
            }
        }
        return nil
    }

    private static func textSegmentRange(header: UnsafeRawPointer) -> Range<UInt64>? {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 || ptr.pointee.magic == MH_CIGAM_64 else {
            return nil
        }
        let imageBase = UInt64(bitPattern: Int64(Int(bitPattern: header)))
        var cmd = header.advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<ptr.pointee.ncmds {
            let load = cmd.assumingMemoryBound(to: load_command.self).pointee
            guard load.cmdsize >= MemoryLayout<load_command>.size else { break }
            if load.cmd == LC_SEGMENT_64 {
                let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                if tupleStringEquals(seg.segname, "__TEXT") {
                    let start = imageBase + seg.vmaddr
                    return start..<(start + seg.vmsize)
                }
            }
            cmd = cmd.advanced(by: Int(load.cmdsize))
        }
        return nil
    }

    private static func tupleStringEquals<T>(_ tuple: T, _ target: String) -> Bool {
        withUnsafePointer(to: tuple) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) { cPtr in
                strncmp(cPtr, target, MemoryLayout<T>.size) == 0
            }
        }
    }

    // MARK: - Multi-layer address validation

    private struct AddressValidation {
        var legitimate: Bool
        var dladdrHooked: Bool
    }

    /// Layer 1 → trusted __TEXT range
    /// Layer 2 → dual-path dladdr (hook detection)
    /// Layer 3 → trusted image cache (startup snapshot)
    /// Layer 4 → strict system library prefix matching
    /// Layer 5 → vm_region_64 cross-validation
    private static func validateAddress(
        _ addr: UInt64,
        trustedRanges: [Range<UInt64>]
    ) -> AddressValidation {
        // Layer 1: within app / SDK __TEXT
        for range in trustedRanges {
            if range.contains(addr) {
                return AddressValidation(legitimate: true, dladdrHooked: false)
            }
        }

        guard let rawPtr = UnsafeRawPointer(bitPattern: UInt(addr)) else {
            return AddressValidation(legitimate: false, dladdrHooked: false)
        }

        // Layer 2: dual-path dladdr — compare standard vs RTLD_NEXT
        var stdInfo = Dl_info()
        let stdFound = dladdr(rawPtr, &stdInfo)

        var nextInfo = Dl_info()
        let nextFound: Int32
        if let fn = nextDladdrFn {
            nextFound = fn(rawPtr, &nextInfo)
        } else {
            nextFound = stdFound
            nextInfo = stdInfo
        }

        if stdFound != nextFound {
            return AddressValidation(legitimate: false, dladdrHooked: true)
        }

        if stdFound != 0, nextFound != 0 {
            let stdPath = stdInfo.dli_fname.map { String(cString: $0) }
            let nextPath = nextInfo.dli_fname.map { String(cString: $0) }
            if stdPath != nextPath {
                return AddressValidation(legitimate: false, dladdrHooked: true)
            }
        }

        let info = nextInfo
        let found = nextFound

        // dladdr could not resolve → cross-validate with vm_region
        guard found != 0, let fname = info.dli_fname else {
            let vmClass = vmRegionClassify(addr)
            let legitimate = vmClass == .fileMapped
            return AddressValidation(legitimate: legitimate, dladdrHooked: false)
        }

        let path = String(cString: fname)

        // Layer 3: trusted image cache (built from startup snapshot)
        if trustedImagePaths.contains(path) {
            return AddressValidation(legitimate: true, dladdrHooked: false)
        }

        // Layer 4: strict system library prefix matching
        if isKnownSystemLibPath(path) {
            return AddressValidation(legitimate: true, dladdrHooked: false)
        }

        // Layer 5: vm_region cross-validation for unknown/suspicious paths.
        // fileMapped  → address backed by a file on disk (legitimate late-loaded framework)
        // anonymousExecutable → shellcode / ROP gadget page (malicious)
        // unknown     → vm_region failed or ambiguous → treat as suspect
        let vmClass = vmRegionClassify(addr)
        return AddressValidation(legitimate: vmClass == .fileMapped, dladdrHooked: false)
    }

    // MARK: - vm_region_64 cross-validation

    private enum VMRegionClass {
        case fileMapped
        case anonymousExecutable
        case unknown
    }

    private static func vmRegionClassify(_ addr: UInt64) -> VMRegionClass {
        var address = vm_address_t(addr)
        var size: vm_size_t = 0
        var objectName: mach_port_t = 0

        var basicInfo = vm_region_basic_info_data_64_t()
        var basicCount = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.stride
                / MemoryLayout<natural_t>.stride
        )

        let result = withUnsafeMutablePointer(to: &basicInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                vm_region_64(
                    mach_task_self_, &address, &size,
                    VM_REGION_BASIC_INFO_64, rebound, &basicCount, &objectName
                )
            }
        }

        guard result == KERN_SUCCESS else { return .unknown }

        // Verify the returned region actually contains our target address
        guard addr >= UInt64(address), addr < UInt64(address) + UInt64(size) else {
            return .unknown
        }

        let isExecutable = (basicInfo.protection & VM_PROT_EXECUTE) != 0

        var extInfo = vm_region_extended_info_data_t()
        var extCount = mach_msg_type_number_t(
            MemoryLayout<vm_region_extended_info_data_t>.stride
                / MemoryLayout<natural_t>.stride
        )
        var extAddress = vm_address_t(addr)
        var extSize: vm_size_t = 0

        let extResult = withUnsafeMutablePointer(to: &extInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(extCount)) { rebound in
                vm_region_64(
                    mach_task_self_, &extAddress, &extSize,
                    VM_REGION_EXTENDED_INFO, rebound, &extCount, &objectName
                )
            }
        }

        guard extResult == KERN_SUCCESS else {
            return isExecutable ? .anonymousExecutable : .unknown
        }

        // SM_PRIVATE = 3, SM_EMPTY = 0 → anonymous memory
        let isAnonymous = (extInfo.share_mode == 3 || extInfo.share_mode == 0)
            || anonymousUserTags.contains(UInt32(extInfo.user_tag))

        if isAnonymous && isExecutable {
            return .anonymousExecutable
        }

        if !isAnonymous {
            return .fileMapped
        }

        return .unknown
    }

    // MARK: - Path validation (case-sensitive, no normalization)

    private static func isKnownSystemLibPath(_ path: String) -> Bool {
        for prefix in knownSystemLibPrefixes {
            if path.hasPrefix(prefix) {
                return true
            }
        }
        return false
    }
}
