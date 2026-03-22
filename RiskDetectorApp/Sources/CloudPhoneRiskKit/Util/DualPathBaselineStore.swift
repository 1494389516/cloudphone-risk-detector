import Darwin
import Foundation

/// 跨时间点基线快照存储（参照 Frida map_gen 双阶段模型）
///
/// 在 CPRiskKit.start() 时对关键路径执行基线采集，记录 path + inode + st_dev + st_size。
/// 在 validateFileStat 流程中与基线对比，若 inode/st_dev 变化且基线采集时间早于当前超过 1 秒，
/// 则判定为 late_tamper（跨时间点篡改）。
///
/// - 基线采集使用 SVC 直调（cprisk_lstat_direct），与校验路径一致
/// - 存储使用 UnfairLock 保证线程安全
/// - 若 start() 未被调用（evaluate-only 路径），基线为空，跳过基线校验
public enum DualPathBaselineStore {
    private static let lock = UnfairLock()

    /// 单条基线记录：path + inode + st_dev + st_size + 采集时间
    public struct BaselineEntry: Sendable {
        public let path: String
        public let inode: UInt64
        public let stDev: UInt32
        public let stSize: Int64
        public let timestamp: TimeInterval

        public init(path: String, inode: UInt64, stDev: UInt32, stSize: Int64, timestamp: TimeInterval) {
            self.path = path
            self.inode = inode
            self.stDev = stDev
            self.stSize = stSize
            self.timestamp = timestamp
        }
    }

    private static var baselineByPath: [String: BaselineEntry] = [:]
    private static var hasCollected = false

    /// 是否已执行过基线采集（start() 被调用后为 true）
    public static var hasBaseline: Bool {
        lock.withLock { hasCollected }
    }

    /// 对指定路径列表执行基线采集，使用 SVC 直调 cprisk_lstat_direct。
    /// 仅记录成功 stat 的路径；ENOENT/失败的不入库，校验时视为无基线可对比。
    public static func collectBaseline(paths: [String]) {
        let now = Date().timeIntervalSince1970
        var collected: [String: BaselineEntry] = [:]

        for path in paths {
            guard let detail = SVCDirectCall.secureLstatDetail(path: path) else { continue }
            collected[path] = BaselineEntry(
                path: path,
                inode: detail.inode,
                stDev: detail.stDev,
                stSize: detail.stSize,
                timestamp: now
            )
        }

        // Set hasCollected atomically with the data to prevent TOCTOU race
        lock.withLock {
            baselineByPath = collected
            hasCollected = true
        }

        #if DEBUG
        Logger.log("dual_path_baseline: collected \(collected.count) entries for \(paths.count) paths")
        #endif
    }

    /// 检查当前 stat 与基线是否发生漂移（inode/st_dev 变化）。
    /// 仅当基线采集时间早于当前超过 `minDriftIntervalSeconds` 秒时才判定为 drift，
    /// 避免启动后立即 evaluate 的瞬时差异误报。
    ///
    /// - Parameters:
    ///   - path: 路径
    ///   - currentInode: 当前 inode（来自 SVC 直调）
    ///   - currentStDev: 当前 st_dev
    ///   - minDriftIntervalSeconds: 最小时间间隔（秒），默认 1.0
    /// - Returns: 若检测到漂移返回 true，否则 false
    public static func checkForDrift(
        path: String,
        currentInode: UInt64,
        currentStDev: UInt32,
        minDriftIntervalSeconds: TimeInterval = 1.0
    ) -> Bool {
        let entry = lock.withLock { baselineByPath[path] }

        guard let entry else { return false }

        let now = Date().timeIntervalSince1970
        guard (now - entry.timestamp) >= minDriftIntervalSeconds else { return false }

        if entry.inode != currentInode || entry.stDev != currentStDev {
            return true
        }
        return false
    }

    /// 判断指定路径是否有基线记录（用于短路逻辑）
    public static func hasBaseline(for path: String) -> Bool {
        lock.withLock { baselineByPath[path] != nil }
    }
}
