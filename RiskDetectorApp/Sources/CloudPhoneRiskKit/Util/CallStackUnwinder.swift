import Darwin
import Foundation
import MachO

/// SDK 4.4 Phase 3: 执行流栈回溯 (Call Stack Unwinding & CFI)
///
/// 在核心加解密、关键检测逻辑、抛出高危 tampered 信号的瞬间，触发轻量级栈回溯。
/// 将提取到的返回地址交给 dladdr 验证：若存在地址不在主 App __TEXT、不在已知系统库内，
/// 或落在匿名/未知内存中 → 判定为 ROP/JOP 链注入，抛出 rop_chain_detected。
///
/// 纯 Swift 实现，仅使用 import Darwin 调用系统 API，无 C 代码。
public enum CallStackUnwinder {

    /// 信号 ID：检测到恶意调用栈（ROP/JOP 链）
    public static let ropChainSignalId = "rop_chain_detected"

    /// 权重（一击毙命）
    private static let maliciousWeight = 90

    /// 已知可信系统库路径前缀（dladdr 返回的 dli_fname）
    private static let knownSystemLibPrefixes: [String] = [
        "/usr/lib/system/",
        "/usr/lib/libsystem",
        "/usr/lib/libobjc",
        "/usr/lib/dyld",
        "/usr/lib/libdispatch",
        "/System/Library/Frameworks/Foundation",
        "/System/Library/Frameworks/CoreFoundation",
        "/System/Library/Frameworks/Security",
        "/System/Library/Frameworks/CFNetwork",
        "/System/Library/PrivateFrameworks/",
        "/System/Library/Frameworks/UIKit",
        "/System/Library/Frameworks/QuartzCore",
        "/System/Library/Frameworks/Accelerate",
        "/System/Library/Frameworks/ImageIO",
        "/System/Library/Frameworks/Metal",
        "/System/Library/Frameworks/AVFoundation",
        "/System/Library/Frameworks/CoreGraphics",
        "/System/Library/Frameworks/CoreText",
        "/System/Library/Frameworks/JavaScriptCore",
        "/System/Library/Frameworks/WebKit",
    ]

    // MARK: - 公开 API

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
            if !isAddressLegitimate(addr, trustedRanges: trustedRanges) {
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
            category: "anti_tamper",
            score: 0,
            evidence: [
                "detail": "call_stack_return_address_outside_trusted_regions",
                "mechanism": "dladdr_validation"
            ],
            state: .tampered,
            layer: 2,
            weightHint: Double(maliciousWeight)
        )
    }

    // MARK: - 栈回溯

    /// 捕获当前线程的返回地址列表
    private static func captureReturnAddresses() -> [UInt64] {
        var buffer = [UnsafeMutableRawPointer?](repeating: nil, count: 64)
        let count = backtrace(&buffer, Int32(buffer.count))
        guard count > 0 else {
            return parseAddressesFromThreadCallStackSymbols()
        }

        var addresses: [UInt64] = []
        for i in 0..<Int(count) {
            guard let ptr = buffer[i] else { continue }
            let addr = UInt64(bitPattern: Int64(Int(bitPattern: ptr)))
            addresses.append(addr)
        }

        if addresses.isEmpty {
            return parseAddressesFromThreadCallStackSymbols()
        }

        return addresses
    }

    /// 备选：从 Thread.callStackSymbols 解析地址（纯 Swift）
    /// 格式示例: "1   App  0x0000000102abc123 0x0000000102abc000 + 291"
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

    // MARK: - 主 App __TEXT 段

    /// 获取主 App（image 0）的 __TEXT 段地址范围
    private static func mainAppTextSegmentRange() -> Range<UInt64>? {
        guard let header = _dyld_get_image_header(0) else { return nil }
        return textSegmentRange(header: UnsafeRawPointer(header))
    }

    /// 获取 CloudPhoneRiskKit SDK 的 __TEXT 段地址范围
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

    /// 从 Mach-O header 解析 __TEXT 段范围
    private static func textSegmentRange(header: UnsafeRawPointer) -> Range<UInt64>? {
        let ptr = header.assumingMemoryBound(to: mach_header_64.self)
        guard ptr.pointee.magic == MH_MAGIC_64 || ptr.pointee.magic == MH_CIGAM_64 else {
            return nil
        }
        let imageBase = UInt64(bitPattern: Int64(Int(bitPattern: header)))
        var cmd = header.advanced(by: MemoryLayout<mach_header_64>.size)

        for _ in 0..<ptr.pointee.ncmds {
            let load = cmd.assumingMemoryBound(to: load_command.self).pointee
            if load.cmd == LC_SEGMENT_64 {
                let seg = cmd.assumingMemoryBound(to: segment_command_64.self).pointee
                if tupleStringEquals(seg.segname, "__TEXT") {
                    let start = imageBase + seg.vmaddr
                    let end = start + seg.vmsize
                    return start..<end
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

    // MARK: - 地址合法性校验

    /// 判断返回地址是否合法：在主 App / SDK __TEXT 内，或在已知系统库内
    private static func isAddressLegitimate(
        _ addr: UInt64,
        trustedRanges: [Range<UInt64>]
    ) -> Bool {
        for range in trustedRanges {
            if range.contains(addr) {
                return true
            }
        }

        guard let ptr = UnsafeRawPointer(bitPattern: UInt(addr)) else {
            return false
        }

        var info = Dl_info()
        let found = dladdr(ptr, &info)

        if found == 0 || info.dli_fname == nil {
            return false
        }

        let path = String(cString: info.dli_fname!)
        return isKnownSystemLibPath(path)
    }

    /// 判断路径是否为已知系统库
    private static func isKnownSystemLibPath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        return knownSystemLibPrefixes.contains { normalized.hasPrefix($0.lowercased()) }
    }
}
