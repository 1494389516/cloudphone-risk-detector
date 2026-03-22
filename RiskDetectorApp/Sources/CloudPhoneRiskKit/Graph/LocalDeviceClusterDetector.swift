import Foundation

// MARK: - 端侧轻量关联检测
///
/// 本地维护最近 N 次评估的设备指纹摘要，若短时间内同一 IP/WiFi 下出现大量不同设备指纹，
/// 产出 local_device_cluster 信号。使用简单内存缓存，不做完整图算法。
///
/// ## 隐私保护
/// - 上报的图特征必须单向哈希（由 GraphFeatureCollector 保证）
/// - 可选：对聚合度计数添加拉普拉斯噪声（Laplace mechanism）以增强差分隐私；
///   占位说明，暂不实现；若未来需要，可在 distinctHashes.count 输出前注入噪声。
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

    /// 记录一次评估，并检测是否触发 local_device_cluster
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
                    id: "local_device_cluster",
                    category: "server",
                    score: 12,
                    evidence: [
                        "key": k,
                        "distinct_devices": "\(distinctHashes.count)",
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
