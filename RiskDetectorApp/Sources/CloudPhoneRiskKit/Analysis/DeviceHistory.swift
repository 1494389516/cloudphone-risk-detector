import Foundation

// MARK: - 设备检测快照
/// 单次检测的完整快照，包含所有检测信号
public struct DeviceDetectionSnapshot: Codable, Sendable {
    /// 检测时间戳
    public var timestamp: TimeInterval

    /// 设备 ID
    public var deviceID: String

    /// 风险分数
    public var riskScore: Double

    /// 是否高风险
    public var isHighRisk: Bool

    /// 越狱检测结果
    public var jailbreakStatus: JailbreakStatus

    /// VPN 是否激活
    public var isVPNActive: Bool

    /// 代理是否启用
    public var isProxyEnabled: Bool

    /// 行为信号摘要
    public var behaviorSummary: BehaviorSummary?

    /// 网络接口类型
    public var networkInterfaceType: String

    public init(
        timestamp: TimeInterval,
        deviceID: String,
        riskScore: Double,
        isHighRisk: Bool,
        jailbreakStatus: JailbreakStatus,
        isVPNActive: Bool,
        isProxyEnabled: Bool,
        behaviorSummary: BehaviorSummary? = nil,
        networkInterfaceType: String
    ) {
        self.timestamp = timestamp
        self.deviceID = deviceID
        self.riskScore = riskScore
        self.isHighRisk = isHighRisk
        self.jailbreakStatus = jailbreakStatus
        self.isVPNActive = isVPNActive
        self.isProxyEnabled = isProxyEnabled
        self.behaviorSummary = behaviorSummary
        self.networkInterfaceType = networkInterfaceType
    }

    /// 从 RiskSnapshot 和 RiskScoreReport 创建快照
    public static func from(snapshot: RiskSnapshot, report: RiskScoreReport) -> DeviceDetectionSnapshot {
        let now = Date().timeIntervalSince1970

        return DeviceDetectionSnapshot(
            timestamp: now,
            deviceID: snapshot.deviceID,
            riskScore: report.score,
            isHighRisk: report.isHighRisk,
            jailbreakStatus: JailbreakStatus(
                isJailbroken: snapshot.jailbreak.isJailbroken,
                confidence: snapshot.jailbreak.confidence,
                detectedMethods: snapshot.jailbreak.detectedMethods
            ),
            isVPNActive: snapshot.network.isVPNActive,
            isProxyEnabled: snapshot.network.proxyEnabled,
            behaviorSummary: BehaviorSummary(from: snapshot.behavior),
            networkInterfaceType: snapshot.network.interfaceType.value
        )
    }
}

// MARK: - 越狱状态摘要
public struct JailbreakStatus: Codable, Sendable {
    public var isJailbroken: Bool
    public var confidence: Double
    public var detectedMethods: [String]

    public init(isJailbroken: Bool, confidence: Double, detectedMethods: [String]) {
        self.isJailbroken = isJailbroken
        self.confidence = confidence
        self.detectedMethods = detectedMethods
    }
}

// MARK: - 行为摘要
public struct BehaviorSummary: Codable, Sendable {
    public var touchSampleCount: Int
    public var tapCount: Int
    public var swipeCount: Int
    public var motionSampleCount: Int
    public var actionCount: Int
    public var touchMotionCorrelation: Double?

    public init(from signals: BehaviorSignals) {
        self.touchSampleCount = signals.touch.sampleCount
        self.tapCount = signals.touch.tapCount
        self.swipeCount = signals.touch.swipeCount
        self.motionSampleCount = signals.motion.sampleCount
        self.actionCount = signals.actionCount
        self.touchMotionCorrelation = signals.touchMotionCorrelation
    }
}

// MARK: - 历史查询结果
public struct HistoryQueryResult: Sendable {
    public var snapshots: [DeviceDetectionSnapshot]
    public var totalCount: Int
    public var timeRange: (start: TimeInterval, end: TimeInterval)?

    public init(snapshots: [DeviceDetectionSnapshot], timeRange: (start: TimeInterval, end: TimeInterval)? = nil) {
        self.snapshots = snapshots
        self.totalCount = snapshots.count
        self.timeRange = timeRange
    }
}

// MARK: - 设备历史存储
/// 负责设备检测快照的存储、查询和清理
public final class DeviceHistory {
    public static let shared = DeviceHistory()

    private let lock = NSLock()
    private let fileManager = FileManager.default
    private let storeURL: URL

    /// 最大存储快照数量
    private let maxSnapshots = 500

    /// 快照最大保留时间（30天）
    private let maxAgeSeconds: TimeInterval = 30 * 24 * 3600

    /// 内存缓存
    private var cachedSnapshots: [DeviceDetectionSnapshot] = []

    /// 缓存是否脏（需要持久化）
    private var isDirty = false

    private init() {
        let paths = fileManager.urls(for: .documentDirectory, in: .userDomainMask)
        let documentsDirectory = paths[0]
        self.storeURL = documentsDirectory.appendingPathComponent("cloudphone_device_history_v1.json")
        loadFromDisk()
    }

    // MARK: - 添加快照

    /// 添加新的检测快照
    public func addSnapshot(_ snapshot: DeviceDetectionSnapshot) {
        lock.lock()
        defer { lock.unlock() }

        cachedSnapshots.append(snapshot)
        isDirty = true

        // 限制内存中的快照数量
        if cachedSnapshots.count > maxSnapshots {
            cachedSnapshots = Array(cachedSnapshots.suffix(maxSnapshots))
        }

        // 异步持久化
        DispatchQueue.global(qos: .utility).async { [weak self] in
            self?.persistIfDirty()
        }
    }

    /// 从 RiskSnapshot 和 RiskScoreReport 创建并添加快照
    public func addSnapshot(from riskSnapshot: RiskSnapshot, report: RiskScoreReport) {
        let snapshot = DeviceDetectionSnapshot.from(snapshot: riskSnapshot, report: report)
        addSnapshot(snapshot)
    }

    // MARK: - 查询操作

    /// 查询所有快照
    public func getAllSnapshots() -> [DeviceDetectionSnapshot] {
        lock.lock()
        defer { lock.unlock() }
        return cleanAndReturn()
    }

    /// 查询指定时间范围内的快照
    public func getSnapshots(from startTime: TimeInterval, to endTime: TimeInterval) -> [DeviceDetectionSnapshot] {
        lock.lock()
        defer { lock.unlock() }

        let cleaned = cleanAndReturnLocked()
        return cleaned.filter { $0.timestamp >= startTime && $0.timestamp <= endTime }
    }

    /// 查询最近的 N 个快照
    public func getRecentSnapshots(count: Int) -> [DeviceDetectionSnapshot] {
        lock.lock()
        defer { lock.unlock() }

        let cleaned = cleanAndReturnLocked()
        let recentCount = min(count, cleaned.count)
        return Array(cleaned.suffix(recentCount))
    }

    /// 查询指定设备 ID 的快照
    public func getSnapshots(for deviceID: String) -> [DeviceDetectionSnapshot] {
        lock.lock()
        defer { lock.unlock() }

        let cleaned = cleanAndReturnLocked()
        return cleaned.filter { $0.deviceID == deviceID }
    }

    /// 查询首次越狱时间
    public func getFirstJailbreakTime(for deviceID: String? = nil) -> TimeInterval? {
        lock.lock()
        defer { lock.unlock() }

        let cleaned = cleanAndReturnLocked()
        let filtered = deviceID != nil ? cleaned.filter { $0.deviceID == deviceID } : cleaned

        let jailbrokenSnapshots = filtered.filter { $0.jailbreakStatus.isJailbroken }
        return jailbrokenSnapshots.map { $0.timestamp }.min()
    }

    /// 查询最近 N 天内的越狱次数
    public func getJailbreakCount(days: Int = 7, for deviceID: String? = nil) -> Int {
        lock.lock()
        defer { lock.unlock() }

        let now = Date().timeIntervalSince1970
        let startTime = now - TimeInterval(days * 24 * 3600)

        let cleaned = cleanAndReturnLocked()
        let filtered = deviceID != nil ? cleaned.filter { $0.deviceID == deviceID } : cleaned

        return filtered.filter { $0.timestamp >= startTime && $0.jailbreakStatus.isJailbroken }.count
    }

    /// 查询首次出现时间（设备年龄）
    public func getFirstSeenTime(for deviceID: String) -> TimeInterval? {
        lock.lock()
        defer { lock.unlock() }

        let cleaned = cleanAndReturnLocked()
        let deviceSnapshots = cleaned.filter { $0.deviceID == deviceID }
        return deviceSnapshots.map { $0.timestamp }.min()
    }

    /// 获取总检测次数
    public func getTotalDetectionCount(for deviceID: String) -> Int {
        lock.lock()
        defer { lock.unlock() }

        let cleaned = cleanAndReturnLocked()
        return cleaned.filter { $0.deviceID == deviceID }.count
    }

    /// 获取 VPN 使用频率（最近 N 天）
    public func getVPNUsageFrequency(days: Int = 7, for deviceID: String? = nil) -> Double {
        lock.lock()
        defer { lock.unlock() }

        let now = Date().timeIntervalSince1970
        let startTime = now - TimeInterval(days * 24 * 3600)

        let cleaned = cleanAndReturnLocked()
        let filtered = deviceID != nil ? cleaned.filter { $0.deviceID == deviceID } : cleaned
        let recentSnapshots = filtered.filter { $0.timestamp >= startTime }

        guard !recentSnapshots.isEmpty else { return 0 }

        let vpnCount = recentSnapshots.filter { $0.isVPNActive }.count
        return Double(vpnCount) / Double(recentSnapshots.count)
    }

    /// 获取风险分数历史
    public func getRiskScoreHistory(days: Int = 30, for deviceID: String? = nil) -> [(timestamp: TimeInterval, score: Double)] {
        lock.lock()
        defer { lock.unlock() }

        let now = Date().timeIntervalSince1970
        let startTime = now - TimeInterval(days * 24 * 3600)

        let cleaned = cleanAndReturnLocked()
        let filtered = deviceID != nil ? cleaned.filter { $0.deviceID == deviceID } : cleaned
        let recentSnapshots = filtered.filter { $0.timestamp >= startTime }

        return recentSnapshots
            .sorted { $0.timestamp < $1.timestamp }
            .map { (timestamp: $0.timestamp, score: $0.riskScore) }
    }

    // MARK: - 数据清理

    /// 执行数据清理，移除过期快照
    public func cleanup() {
        lock.lock()
        defer { lock.unlock() }

        let before = cachedSnapshots.count
        _ = cleanAndReturnLocked()
        let after = cachedSnapshots.count

        if before != after {
            isDirty = true
            persistIfDirty()
        }
    }

    /// 清空所有历史数据
    public func clearAll() {
        lock.lock()
        defer { lock.unlock() }

        cachedSnapshots.removeAll()
        isDirty = true
        persistToDiskLocked()
    }

    // MARK: - 持久化

    private func loadFromDisk() {
        lock.lock()
        defer { lock.unlock() }

        guard fileManager.fileExists(atPath: storeURL.path) else {
            cachedSnapshots = []
            return
        }

        guard let data = try? Data(contentsOf: storeURL) else {
            cachedSnapshots = []
            return
        }

        guard let decoded = try? JSONDecoder().decode([DeviceDetectionSnapshot].self, from: data) else {
            cachedSnapshots = []
            return
        }

        cachedSnapshots = decoded
        isDirty = false
    }

    private func persistIfDirty() {
        lock.lock()
        defer { lock.unlock() }

        guard isDirty else { return }
        persistToDiskLocked()
        isDirty = false
    }

    private func persistToDiskLocked() {
        do {
            let data = try JSONEncoder().encode(cachedSnapshots)
            try data.write(to: storeURL, options: .atomic)
            Logger.log("DeviceHistory: persisted \(cachedSnapshots.count) snapshots")
        } catch {
            Logger.log("DeviceHistory: failed to persist - \(error.localizedDescription)")
        }
    }

    // MARK: - 辅助方法

    private func cleanAndReturn() -> [DeviceDetectionSnapshot] {
        lock.lock()
        defer { lock.unlock() }
        return cleanAndReturnLocked()
    }

    private func cleanAndReturnLocked() -> [DeviceDetectionSnapshot] {
        let now = Date().timeIntervalSince1970
        let minTimestamp = now - maxAgeSeconds

        // 移除过期的快照
        let before = cachedSnapshots.count
        cachedSnapshots = cachedSnapshots.filter { $0.timestamp >= minTimestamp }
        let after = cachedSnapshots.count

        if before != after {
            isDirty = true
        }

        // 按时间戳排序
        return cachedSnapshots.sorted { $0.timestamp < $1.timestamp }
    }
}
