import Darwin
import Foundation

/// 敏感数据内存生命周期管理。适用于：字符串解密后的明文、电池电压采样原始值、
/// 硬件指纹比对的中间结果、最终评分值。
final class SecureBuffer {
    private var buffer: [UInt8]

    init(size: Int) {
        // 保证至少分配 1 字节，使 withUnsafeMutableBytes.baseAddress 始终非 nil，
        // 消除 dummy 指针 fallback（调用方可能写入超过 1 字节导致越界）。
        self.buffer = [UInt8](repeating: 0, count: max(1, size))
    }

    func use<T>(_ block: (UnsafeMutableRawPointer) -> T) -> T {
        let result: T = buffer.withUnsafeMutableBytes { raw in
            // buffer 至少 1 字节，baseAddress 在正常情况下不为 nil；
            // 若仍为 nil（理论上不可能），用 preconditionFailure 明确暴露问题而非静默越界。
            guard let base = raw.baseAddress else {
                preconditionFailure("SecureBuffer: baseAddress is nil, buffer is in inconsistent state")
            }
            return block(base)
        }
        secureZero(&buffer)
        return result
    }

    deinit {
        secureZero(&buffer)
    }
}

/// 敏感字符串封装，使用完毕后自动清零。适用于解密后的明文、临时密钥等。
final class SecureString {
    private var bytes: [UInt8]

    init(_ string: String) {
        self.bytes = Array(string.utf8)
    }

    func use<T>(_ block: (String) -> T) -> T {
        let str = String(bytes: bytes, encoding: .utf8) ?? ""
        let result = block(str)
        secureZero(&bytes)
        return result
    }

    /// 常量时间比较，避免通过时序泄露
    func secureCompare(with other: String) -> Bool {
        let otherBytes = Array(other.utf8)
        guard bytes.count == otherBytes.count else { return false }
        var acc: UInt8 = 0
        for i in 0..<bytes.count {
            acc |= bytes[i] ^ otherBytes[i]
        }
        return acc == 0
    }

    var count: Int { bytes.count }

    deinit {
        secureZero(&bytes)
    }
}

private func secureZero(_ buffer: inout [UInt8]) {
    buffer.withUnsafeMutableBytes { ptr in
        guard let base = ptr.baseAddress else { return }
        memset_s(base, ptr.count, 0, ptr.count)
    }
}

internal func secureZeroBytes(_ buffer: inout [UInt8]) {
    buffer.withUnsafeMutableBytes { ptr in
        guard let base = ptr.baseAddress else { return }
        memset_s(base, ptr.count, 0, ptr.count)
    }
}

internal func secureZeroData(_ data: inout Data) {
    data.withUnsafeMutableBytes { ptr in
        guard let base = ptr.baseAddress else { return }
        memset_s(base, ptr.count, 0, ptr.count)
    }
}

/// 作用域内创建临时敏感值，闭包结束自动清零
enum SecureScope {
    static func withSecureValue<T>(_ value: String, _ body: (String) -> T) -> T {
        var bytes = Array(value.utf8)
        defer { secureZero(&bytes) }
        let str = String(bytes: bytes, encoding: .utf8) ?? ""
        return body(str)
    }

    static func withSecureBytes<T>(_ bytes: [UInt8], _ body: (UnsafeBufferPointer<UInt8>) -> T) -> T {
        var mutable = bytes
        defer { secureZero(&mutable) }
        return mutable.withUnsafeBufferPointer { body($0) }
    }
}
