import Foundation

// Compatibility type name; observes only this process's identity changes.
/// A single installation changing fingerprints is NOT multiple devices.
/// No network/account key is emitted in evidence; cross-device aggregation is server-only.
public final class LocalDeviceClusterDetector: @unchecked Sendable {

    public static let shared = LocalDeviceClusterDetector()

    /// 同一 key 下不同指纹数量阈值
    public static let clusterThreshold = 5

    /// 时间窗口（秒）
    public static let timeWindowSeconds: TimeInterval = 300  // 5 分钟

    /// 保留最近 N 次评估
    private static let maxHistoryCount = 20

    private struct Entry: Sendable {
        let hwProfileHash: String
        let timestamp: TimeInterval
    }

    /// key: IP 或 sessionId，value: [(hwProfileHash, timestamp)]
    private var cache: [String: [Entry]] = [:]
    private let lock = UnfairLock()

    private init() {}

    /// 记录一次评估，并检测是否触发 local_identity_churn
    /// - Parameters:
    ///   - hwProfileHash: 设备指纹哈希（GraphFeatureCollector 产出的 hwProfileHash）
    ///   - key: 关联键，优先使用 IP，否则 sessionId
    /// - Returns: 若触发则返回 RiskSignal，否则 nil
    public func recordAndDetect(
        hwProfileHash: String,
        key: String?
    ) -> RiskSignal? {
        guard let k = key, !k.isEmpty else { return nil }
        guard !hwProfileHash.isEmpty else { return nil }

        return lock.withLock {
            let now = Date().timeIntervalSince1970
            let cutoff = now - Self.timeWindowSeconds

            var entries = cache[k] ?? []
            entries.append(Entry(hwProfileHash: hwProfileHash, timestamp: now))

            // 清理过期
            entries = entries.filter { $0.timestamp > cutoff }

            // 限制历史长度
            if entries.count > Self.maxHistoryCount {
                entries = Array(entries.suffix(Self.maxHistoryCount))
            }

            cache[k] = entries

            // Evict stale keys to prevent unbounded memory growth
            if cache.count > 100 {
                let staleKeys = cache.filter { $0.value.allSatisfy { $0.timestamp <= cutoff } }.map(\.key)
                for key in staleKeys { cache.removeValue(forKey: key) }
            }

            let distinctHashes = Set(entries.map(\.hwProfileHash))
            if distinctHashes.count >= Self.clusterThreshold {
                return RiskSignal(
                    id: "local_identity_churn",
                    category: "device",
                    score: 12,
                    evidence: [
                        "scope": "local_installation",
                        "distinct_local_fingerprints": "\(distinctHashes.count)",
                        "window_seconds": "\(Int(Self.timeWindowSeconds))"
                    ],
                    state: .soft(confidence: min(1.0, Double(distinctHashes.count) / 10.0)),
                    layer: 4,
                    weightHint: 55
                )
            }

            return nil
        }
    }

    /// 清空缓存（如用户登出时调用，降低内存驻留）
    public func clear() {
        lock.withLock { cache.removeAll() }
    }
}
