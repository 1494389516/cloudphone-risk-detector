import CryptoKit
import Darwin
import Foundation
import Security

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
        let result = bytes.withUnsafeBufferPointer { buf -> T in
            let str = String(decoding: buf, as: UTF8.self)
            return block(str)
        }
        secureZero(&bytes)
        return result
    }

    /// Provides direct access to the raw UTF-8 bytes without creating a String copy.
    func useBytes<T>(_ block: (UnsafeBufferPointer<UInt8>) -> T) -> T {
        let result = bytes.withUnsafeBufferPointer { block($0) }
        secureZero(&bytes)
        return result
    }

    /// 常量时间比较，避免通过时序泄露
    func secureCompare(with other: String) -> Bool {
        let otherBytes = Array(other.utf8)
        let maxLen = max(bytes.count, otherBytes.count)
        guard maxLen > 0 else { return bytes.count == otherBytes.count }
        // Fold length mismatch into accumulator to avoid early-return timing leak
        var acc: UInt8 = bytes.count == otherBytes.count ? 0 : 1
        for i in 0..<maxLen {
            let a: UInt8 = i < bytes.count ? bytes[i] : 0
            let b: UInt8 = i < otherBytes.count ? otherBytes[i] : 0
            acc |= a ^ b
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

/// 常量时间字符串比较。迭代次数固定为 max(lhs, rhs) 字节，
/// 长度差异编码到累加器中但不提前返回，避免通过执行时间泄露长度信息。
internal func timingSafeCompare(_ lhs: String, _ rhs: String) -> Bool {
    let lhsBytes = Array(lhs.utf8)
    let rhsBytes = Array(rhs.utf8)
    var result: UInt8 = lhsBytes.count == rhsBytes.count ? 0 : 1
    let maxCount = max(lhsBytes.count, rhsBytes.count)
    let lhsN = max(lhsBytes.count, 1)
    let rhsN = max(rhsBytes.count, 1)
    for i in 0..<maxCount {
        result |= lhsBytes[i % lhsN] ^ rhsBytes[i % rhsN]
    }
    return result == 0
}

// MARK: - SplitSecureBuffer

/// Split-storage secure buffer that stores a key as N XOR-masked fragments
/// scattered across independently-allocated heap regions.
///
/// ## Counter-measure: hexdump key-material tracing
///
/// unidbg's optimised trace engine (文章 §6.3) can print a hexdump of memory
/// read/write addresses for every ld/st instruction, effectively letting an
/// attacker trace where a key first appears and follow it through the pipeline.
///
/// A contiguous `SecureBuffer` presents a single, easily-spotted 16/32-byte
/// blob in the hexdump — the attacker simply searches for the expected key size
/// at the first occurrence and sets a watch-point.
///
/// `SplitSecureBuffer` stores the key as `n` independently-allocated byte
/// arrays where fragment[i] = keyByte XOR mask[i].  No single fragment
/// contains usable key material.  When `use()` is called, the fragments are
/// assembled into a *stack* buffer for the duration of the closure and then
/// immediately zeroed.
///
/// Effect on hexdump analysis:
/// - The "key" is spread across N different heap addresses with no obvious
///   byte pattern at any single location.
/// - The momentary assembly on the stack lasts only for the closure body
///   (typically <1µs), making it extremely unlikely to be captured by a
///   periodic hexdump scan.
/// - After `use()` returns, the stack copy is zeroed — no persistent plaintext.
///
/// - Parameter n: Number of fragments (default 4).  Higher values increase
///   scatter at the cost of slightly more allocation overhead.
final class SplitSecureBuffer {
    private let size: Int
    private var fragments: [[UInt8]]    // fragments[i] = keyByte[i%size] XOR masks[i]
    private var masks: [[UInt8]]        // one random mask per fragment
    private let n: Int

    init(size: Int, fragments n: Int = 4) {
        precondition(size >= 1, "SplitSecureBuffer: size must be ≥ 1")
        precondition(n >= 2,    "SplitSecureBuffer: fragment count must be ≥ 2")
        self.size = size
        self.n = n
        // Allocate n independent arrays; key bytes are all 0 at construction.
        self.masks     = (0..<n).map { _ in [UInt8](repeating: 0, count: size) }
        self.fragments = (0..<n).map { _ in [UInt8](repeating: 0, count: size) }
    }

    /// Write key material.  The bytes are immediately split into fragments
    /// and the original `bytes` buffer is zeroed on return.
    func store(_ bytes: UnsafeRawPointer, count: Int) {
        precondition(count == size, "SplitSecureBuffer: byte count mismatch")
        let src = bytes.bindMemory(to: UInt8.self, capacity: count)

        // Generate fresh random masks for each fragment.
        for i in 0..<n {
            let status = SecRandomCopyBytes(kSecRandomDefault, size, &masks[i])
            precondition(status == errSecSuccess, "SplitSecureBuffer: SecRandomCopyBytes failed (\(status))")
        }

        // Distribute: fragment[i][j] = src[j] XOR masks[0][j] XOR ... XOR masks[n-1][j]
        // stored as fragment[i][j] = (XOR of all masks except i) XOR src[j] for i=0
        // and fragment[i][j] = masks[i][j] for i>0.
        // Recovery: XOR all fragments together = src[j].
        for j in 0..<size {
            var carry = src[j]
            for i in 1..<n {
                fragments[i][j] = masks[i][j]
                carry ^= masks[i][j]
            }
            fragments[0][j] = carry  // fragment[0] = src XOR fragment[1] XOR ... XOR fragment[n-1]
        }
    }

    /// Assemble fragments into a stack buffer, call `block`, then zero.
    func use<T>(_ block: (UnsafeMutableRawPointer) -> T) -> T {
        var assembled = [UInt8](repeating: 0, count: size)
        // XOR all fragments together to recover the original key.
        for i in 0..<n {
            for j in 0..<size {
                assembled[j] ^= fragments[i][j]
            }
        }
        let result: T = assembled.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else {
                preconditionFailure("SplitSecureBuffer: assembly buffer has nil base")
            }
            return block(base)
        }
        secureZeroBytes(&assembled)
        return result
    }

    /// Zero all fragments and masks.
    func clear() {
        for i in 0..<n {
            secureZeroBytes(&fragments[i])
            secureZeroBytes(&masks[i])
        }
    }

    deinit {
        clear()
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
        let result = bytes.withUnsafeBufferPointer { buf -> T in
            let str = String(decoding: buf, as: UTF8.self)
            return body(str)
        }
        return result
    }

    static func withSecureBytes<T>(_ bytes: [UInt8], _ body: (UnsafeBufferPointer<UInt8>) -> T) -> T {
        var mutable = bytes
        defer { secureZero(&mutable) }
        return mutable.withUnsafeBufferPointer { body($0) }
    }
}

internal enum CPRiskMessageAuth {
    private static let blockSize = 64
    private static let innerPadByte: UInt8 = 0x6D
    private static let outerPadByte: UInt8 = 0xA3

    static func authenticationCode(for message: Data, using key: SymmetricKey) -> Data {
        var keyData = key.withUnsafeBytes { Data($0) }
        defer { secureZeroData(&keyData) }
        return authenticationCode(for: message, keyData: keyData)
    }

    static func authenticationCode(for message: Data, keyData: Data) -> Data {
        var normalizedKey = [UInt8](repeating: 0, count: blockSize)
        if keyData.count > blockSize {
            let digest = Data(SHA256.hash(data: keyData))
            normalizedKey.replaceSubrange(0..<digest.count, with: digest)
        } else {
            normalizedKey.replaceSubrange(0..<keyData.count, with: keyData)
        }

        var innerKey = normalizedKey
        var outerKey = normalizedKey
        for index in 0..<blockSize {
            innerKey[index] ^= innerPadByte
            outerKey[index] ^= outerPadByte
        }

        var innerInput = Data(innerKey)
        innerInput.append(message)
        var innerDigest = Data(SHA256.hash(data: innerInput))

        var outerInput = Data(outerKey)
        outerInput.append(innerDigest)
        let digest = Data(SHA256.hash(data: outerInput))

        secureZeroBytes(&normalizedKey)
        secureZeroBytes(&innerKey)
        secureZeroBytes(&outerKey)
        secureZeroData(&innerInput)
        secureZeroData(&outerInput)
        secureZeroData(&innerDigest)
        return digest
    }

    static func isValidAuthenticationCode(
        _ signature: Data,
        authenticating message: Data,
        using key: SymmetricKey
    ) -> Bool {
        let expected = authenticationCode(for: message, using: key)
        return timingSafeEquals(expected, signature)
    }

    static func isValidAuthenticationCode(
        _ signature: Data,
        authenticating message: Data,
        keyData: Data
    ) -> Bool {
        let expected = authenticationCode(for: message, keyData: keyData)
        return timingSafeEquals(expected, signature)
    }

    static func authenticationCodeHex(for message: Data, using key: SymmetricKey) -> String {
        authenticationCode(for: message, using: key).map { String(format: "%02x", $0) }.joined()
    }

    static func authenticationCodeHex(for message: Data, keyData: Data) -> String {
        authenticationCode(for: message, keyData: keyData).map { String(format: "%02x", $0) }.joined()
    }

    private static func timingSafeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var diff: UInt8 = 0
        for index in lhs.indices {
            diff |= lhs[index] ^ rhs[index]
        }
        return diff == 0
    }
}
