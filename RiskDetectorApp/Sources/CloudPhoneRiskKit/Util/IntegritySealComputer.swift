import CRiskCore
import CryptoKit
import Foundation

/// 完整性印章 — 把任意输入压成 16 字节摘要后，过一道 GF(2) 128-bit 仿射变换。
///
/// 设计借鉴小红书 x-mini-sig 的 transform_16：
///   - 单纯 SHA-256 摘要可以被攻击者通过 hook CryptoKit 替换成常量返回值；
///   - 但叠加一层 128×128 GF(2) 矩阵乘法后，攻击者必须同时还原矩阵才能伪造正确 seal；
///   - GF(2) 仿射只产生 AND/XOR/popcount 指令，没有可识别的密码学常量，反向时极难定位。
///
/// 用途：作为 evidence 字段嵌入在风险信号里，给上游审计/未来服务器侧校验当签名锚点。
///
/// 用法示例:
///   let seal = IntegritySealComputer.seal(Data("vendor=Apple,model=iPhone".utf8))
///   evidence["seal"] = seal.hexString
///
/// **API 设计（v7.7 audit-fix F6）**：从 3-overload `seal(...)` 收敛为 2 个非歧义入口
/// (`seal(_:)` 接 Data；`sealFromDigestPrefix(_:)` 接 16 字节摘要)，避免 armor policy 的
/// tail-match 在多个同名 overload 间踩错的歧义。
enum IntegritySealComputer {

    /// 16 字节印章。
    struct Seal: Equatable {
        let bytes: [UInt8]

        var hexString: String {
            bytes.map { String(format: "%02x", $0) }.joined()
        }
    }

    /// 对任意 Data 生成 16 字节印章。
    /// 流程：SHA-256 → 取前 16 字节 → GF(2) 仿射变换。
    static func seal(_ data: Data) -> Seal {
        let hash = SHA256.hash(data: data)
        return sealFromDigestPrefix(Array(hash.prefix(16)))
    }

    /// 直接对 16 字节 SHA-256 前缀做 GF(2) 仿射（跳过 SHA-256 — 调用方已自备摘要时使用）。
    /// **v7.7 audit-fix N3**: `@inline(never)` 防止编译器把这段折进 `seal(_:)`，让 armor
    /// policy 上的 `IntegritySealComputer.sealFromDigestPrefix` 条目不至于变成死 entry。
    @inline(never)
    static func sealFromDigestPrefix(_ input: [UInt8]) -> Seal {
        precondition(input.count == 16, "GF(2) affine input must be exactly 16 bytes")
        var output = [UInt8](repeating: 0, count: 16)
        input.withUnsafeBufferPointer { inBuf in
            output.withUnsafeMutableBufferPointer { outBuf in
                cprisk_gf2_affine_transform_16(
                    outBuf.baseAddress,
                    inBuf.baseAddress,
                    nil,  // 使用 SDK 默认矩阵
                    nil   // 使用 SDK 默认平移向量
                )
            }
        }
        return Seal(bytes: output)
    }

    /// 矩阵自校验。返回 true = 矩阵未被改 .rodata 篡改。
    ///
    /// **v7.7 audit-fix F5**：5s TTL 缓存，self_check 在锁内执行。
    ///
    /// `cprisk_gf2_affine_self_check` 内部对 2064 字节 (matrix 2048 + translation 16) 做
    /// FNV-1a，每次 ~10μs。signal pipeline 可能在一次 evaluate 内多次询问，叠加在
    /// RiskDetectionEngine busy 路径上时累计成本可见。5s 窗口在篡改检测延迟（max 5s）
    /// 与 hot path 性能之间取折中。
    ///
    /// **F5 post-1st-pass 修复**：先前版本把 self_check 放在锁外为了"不阻塞 reader"，
    /// 但引入了 TOCTOU 竞态：两个并发 reader 都 miss → 都跑 self_check → 慢的那个用旧
    /// 时间戳和（可能过时的）结果**覆盖**了快的那个写入。如果篡改在两次 self_check 之
    /// 间发生，5s 内仍会返回 intact=true。10μs 的锁内序列化是廉价代价，换来"最新
    /// 调用 wins"的正确性。
    ///
    /// 篡改是单向事件（攻击者改了就不会自己改回去），TTL 内的 stale read 不会丢报，
    /// 只会推迟 ≤5s 报。
    static var isMatrixIntact: Bool {
        cacheLock.lock()
        defer { cacheLock.unlock() }

        let now = Date()
        if let cached = cachedIntact, let at = cachedAt, now.timeIntervalSince(at) < cacheTTL {
            return cached
        }

        // 在锁内 self_check：避免并发 reader 用旧结果覆盖新结果。10μs 的串行化代价远
        // 小于"5s 内 attacker 篡改被掩盖"的安全代价。
        let result = cprisk_gf2_affine_self_check() == 0
        cachedIntact = result
        cachedAt = now
        return result
    }

    /// 测试用：清空 isMatrixIntact 缓存。
    static func resetMatrixIntactCacheForTesting() {
        cacheLock.lock()
        cachedIntact = nil
        cachedAt = nil
        cacheLock.unlock()
    }

    // MARK: - F5 cache state
    private static let cacheLock = NSLock()
    private static var cachedIntact: Bool? = nil
    private static var cachedAt: Date? = nil
    private static let cacheTTL: TimeInterval = 5.0
}
