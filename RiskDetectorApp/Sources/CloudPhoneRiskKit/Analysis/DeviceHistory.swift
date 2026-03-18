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

  private enum CodingKeys: String, CodingKey {
    case timestamp = "ts"
    case deviceID = "di"
    case riskScore = "rs"
    case isHighRisk = "hr"
    case jailbreakStatus = "js"
    case isVPNActive = "va"
    case isProxyEnabled = "pe"
    case behaviorSummary = "bs"
    case networkInterfaceType = "ni"
  }

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
  public static func from(snapshot: RiskSnapshot, report: RiskScoreReport)
    -> DeviceDetectionSnapshot
  {
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

  private enum CodingKeys: String, CodingKey {
    case isJailbroken = "ij"
    case confidence = "c"
    case detectedMethods = "dm"
  }

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

  private enum CodingKeys: String, CodingKey {
    case touchSampleCount = "tc"
    case tapCount = "tp"
    case swipeCount = "sw"
    case motionSampleCount = "ms"
    case actionCount = "ac"
    case touchMotionCorrelation = "tm"
  }

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

  public init(
    snapshots: [DeviceDetectionSnapshot], timeRange: (start: TimeInterval, end: TimeInterval)? = nil
  ) {
    self.snapshots = snapshots
    self.totalCount = snapshots.count
    self.timeRange = timeRange
  }
}

// MARK: - 设备历史存储
/// 负责设备检测快照的存储、查询和清理
public final class DeviceHistory {
  public static let shared = DeviceHistory()

  private struct StoredEnvelope: Codable {
    var schemaVersion: Int
    var snapshots: [DeviceDetectionSnapshot]
    var latestTimestamp: Double
    var sequence: UInt64

    private enum CodingKeys: String, CodingKey {
      case schemaVersion = "sv"
      case snapshots = "sn"
      case latestTimestamp = "lt"
      case sequence = "sq"
    }
  }

  private let lock = NSLock()
  private let fileManager = FileManager.default
  private let storeURL: URL
  private let hmacURL: URL
  private let hmacPurpose = "device_history"
  private let freshnessAnchor = FreshnessAnchor(account: "device_history_v2_freshness")

  private let maxSnapshots = 500

  /// 快照最大保留时间（30天）
  private let maxAgeSeconds: TimeInterval = 30 * 24 * 3600

  /// 内存缓存
  private var cachedSnapshots: [DeviceDetectionSnapshot] = []
  private var cachedFreshness: FreshnessState = .zero

  /// 缓存是否脏（需要持久化）
  private var isDirty = false

  private init() {
    let storageDirectory = Self.resolveStorageDirectory(fileManager: fileManager)
    do {
      try fileManager.createDirectory(
        at: storageDirectory,
        withIntermediateDirectories: true,
        attributes: [FileAttributeKey.protectionKey: FileProtectionType.complete]
      )
    } catch {
      Logger.log(
        "DeviceHistory: failed to create storage directory - \(error.localizedDescription)")
    }
    self.storeURL = storageDirectory.appendingPathComponent("cloudphone_device_history_v2.json")
    self.hmacURL = storageDirectory.appendingPathComponent("cloudphone_device_history_v2.json.hmac")
    migrateFromDocumentsIfNeeded()
    loadFromDisk()
  }

  static func resolveStorageDirectory(
    applicationSupportDirectories: [URL],
    cachesDirectories: [URL],
    temporaryDirectory: URL
  ) -> URL {
    if let appSupportDirectory = applicationSupportDirectories.first {
      return appSupportDirectory
    }
    if let cachesDirectory = cachesDirectories.first {
      Logger.log(
        "DeviceHistory: applicationSupportDirectory unavailable, falling back to cachesDirectory")
      return cachesDirectory.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
    }
    Logger.log(
      "DeviceHistory: applicationSupportDirectory unavailable, falling back to temporaryDirectory")
    return temporaryDirectory.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
  }

  private static func resolveStorageDirectory(fileManager: FileManager) -> URL {
    resolveStorageDirectory(
      applicationSupportDirectories: fileManager.urls(
        for: .applicationSupportDirectory, in: .userDomainMask),
      cachesDirectories: fileManager.urls(for: .cachesDirectory, in: .userDomainMask),
      temporaryDirectory: fileManager.temporaryDirectory
    )
  }

  private func migrateFromDocumentsIfNeeded() {
    let oldPaths = fileManager.urls(for: .documentDirectory, in: .userDomainMask)
    guard let docDir = oldPaths.first else { return }
    let oldStore = docDir.appendingPathComponent("cloudphone_device_history_v1.json")
    guard fileManager.fileExists(atPath: oldStore.path) else { return }
    do {
      try fileManager.removeItem(at: oldStore)
    } catch {
      Logger.log("DeviceHistory: failed to remove legacy store - \(error.localizedDescription)")
    }
    let oldHmac = docDir.appendingPathComponent("cloudphone_device_history_v1.json.hmac")
    do {
      try fileManager.removeItem(at: oldHmac)
    } catch {
      Logger.log("DeviceHistory: failed to remove legacy hmac - \(error.localizedDescription)")
    }
    Logger.log("DeviceHistory: migrated from Documents to ApplicationSupport")
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
    return cleanAndReturnLocked()
  }

  /// 查询指定时间范围内的快照
  public func getSnapshots(from startTime: TimeInterval, to endTime: TimeInterval)
    -> [DeviceDetectionSnapshot]
  {
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
  public func getRiskScoreHistory(days: Int = 30, for deviceID: String? = nil) -> [(
    timestamp: TimeInterval, score: Double
  )] {
    lock.lock()
    defer { lock.unlock() }

    let now = Date().timeIntervalSince1970
    let startTime = now - TimeInterval(days * 24 * 3600)

    let cleaned = cleanAndReturnLocked()
    let filtered = deviceID != nil ? cleaned.filter { $0.deviceID == deviceID } : cleaned
    let recentSnapshots = filtered.filter { $0.timestamp >= startTime }

    return
      recentSnapshots
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
      persistIfDirtyLocked()
    }
  }

  /// 清空所有历史数据
  public func clearAll() {
    lock.lock()
    defer { lock.unlock() }

    cachedSnapshots.removeAll()
    cachedFreshness = .zero
    isDirty = true
    persistToDiskLocked(resetAnchor: true)
  }

  // MARK: - 持久化

  private func loadFromDisk() {
    lock.lock()
    defer { lock.unlock() }

    let anchor = freshnessAnchor.read() ?? .zero
    guard fileManager.fileExists(atPath: storeURL.path) else {
      cachedSnapshots = []
      cachedFreshness = anchor
      isDirty = false
      return
    }

    let data: Data
    do {
      data = try Data(contentsOf: storeURL)
    } catch {
      Logger.log("DeviceHistory: failed to read store file - \(error.localizedDescription)")
      cachedSnapshots = []
      cachedFreshness = anchor
      return
    }

    guard let signature = (try? Data(contentsOf: hmacURL)),
      StorageIntegrityGuard.verify(data, signature: signature, purpose: hmacPurpose)
    else {
      clearPersistedFilesLocked(resetAnchor: false)
      cachedSnapshots = []
      cachedFreshness = anchor
      return
    }

    let decryptedData: Data
    #if DEBUG
      if let dec = try? PayloadCrypto.decrypt(data) {
        decryptedData = dec
      } else {
        decryptedData = data
      }
    #else
      guard let dec = try? PayloadCrypto.decrypt(data) else {
        Logger.log("DeviceHistory: decrypt failed, clearing corrupted data in release build")
        clearPersistedFilesLocked(resetAnchor: false)
        cachedSnapshots = []
        cachedFreshness = anchor
        return
      }
      decryptedData = dec
    #endif

    let decodedSnapshots: [DeviceDetectionSnapshot]
    let diskFreshness: FreshnessState
    if let envelope = try? JSONDecoder().decode(StoredEnvelope.self, from: decryptedData) {
      decodedSnapshots = envelope.snapshots
      diskFreshness = FreshnessState(
        latestTimestamp: envelope.latestTimestamp,
        sequence: envelope.sequence
      )
    } else if let legacy = try? JSONDecoder().decode(
      [DeviceDetectionSnapshot].self, from: decryptedData)
    {
      decodedSnapshots = legacy
      diskFreshness = FreshnessState(
        latestTimestamp: legacy.map(\.timestamp).max() ?? 0,
        sequence: 0
      )
    } else {
      cachedSnapshots = []
      cachedFreshness = anchor
      return
    }

    if diskFreshness.sequence < anchor.sequence
      || diskFreshness.latestTimestamp < anchor.latestTimestamp
    {
      Logger.log("DeviceHistory: freshness rollback detected")
      clearPersistedFilesLocked(resetAnchor: false)
      cachedSnapshots = []
      cachedFreshness = anchor
      isDirty = false
      return
    }

    let cleaned = pruneSnapshotsLocked(decodedSnapshots)
    cachedSnapshots = cleaned.snapshots
    cachedFreshness = maxFreshness(anchor, diskFreshness)
    isDirty = cleaned.didPrune

    if diskFreshness.sequence > anchor.sequence
      || diskFreshness.latestTimestamp > anchor.latestTimestamp
    {
      _ = freshnessAnchor.write(diskFreshness)
    }
  }

  private func persistIfDirty() {
    lock.lock()
    defer { lock.unlock() }
    persistIfDirtyLocked()
  }

  /// Must be called with `lock` already held.
  private func persistIfDirtyLocked() {
    guard isDirty else { return }
    let persisted = persistToDiskLocked(resetAnchor: false)
    if persisted {
      isDirty = false
    }
  }

  @discardableResult
  private func persistToDiskLocked(resetAnchor: Bool) -> Bool {
    if resetAnchor {
      clearPersistedFilesLocked(resetAnchor: true)
      return true
    }

    do {
      let anchor = freshnessAnchor.read() ?? .zero
      let latestSnapshotTimestamp = cachedSnapshots.map(\.timestamp).max() ?? 0
      let freshness = FreshnessState(
        latestTimestamp: max(
          latestSnapshotTimestamp, max(anchor.latestTimestamp, cachedFreshness.latestTimestamp)),
        sequence: max(anchor.sequence, cachedFreshness.sequence) + 1
      )
      let envelope = StoredEnvelope(
        schemaVersion: 2,
        snapshots: cachedSnapshots,
        latestTimestamp: freshness.latestTimestamp,
        sequence: freshness.sequence
      )
      let rawData = try JSONEncoder().encode(envelope)
      let dataToWrite: Data
      #if DEBUG
        dataToWrite = (try? PayloadCrypto.encrypt(rawData)) ?? rawData
      #else
        dataToWrite = try PayloadCrypto.encrypt(rawData)
      #endif
      try dataToWrite.write(to: storeURL, options: .atomic)
      try fileManager.setAttributes(
        [FileAttributeKey.protectionKey: FileProtectionType.complete],
        ofItemAtPath: storeURL.path
      )
      let signature = StorageIntegrityGuard.sign(dataToWrite, purpose: hmacPurpose)
      try signature.write(to: hmacURL, options: .atomic)
      try fileManager.setAttributes(
        [FileAttributeKey.protectionKey: FileProtectionType.complete],
        ofItemAtPath: hmacURL.path
      )
      guard freshnessAnchor.write(freshness) else {
        Logger.log("DeviceHistory: failed to update freshness anchor")
        if BuildConfig.isRelease {
          clearPersistedFilesLocked(resetAnchor: false)
        }
        return false
      }
      cachedFreshness = freshness
      Logger.log("DeviceHistory: persisted \(cachedSnapshots.count) snapshots (encrypted)")
      return true
    } catch {
      Logger.log("DeviceHistory: failed to persist - \(error.localizedDescription)")
      return false
    }
  }

  // MARK: - 辅助方法

  private func cleanAndReturn() -> [DeviceDetectionSnapshot] {
    lock.lock()
    defer { lock.unlock() }
    return cleanAndReturnLocked()
  }

  private func cleanAndReturnLocked() -> [DeviceDetectionSnapshot] {
    let pruned = pruneSnapshotsLocked(cachedSnapshots)
    cachedSnapshots = pruned.snapshots
    if pruned.didPrune {
      isDirty = true
    }

    // 按时间戳排序
    return cachedSnapshots.sorted { $0.timestamp < $1.timestamp }
  }

  private func pruneSnapshotsLocked(_ snapshots: [DeviceDetectionSnapshot]) -> (
    snapshots: [DeviceDetectionSnapshot], didPrune: Bool
  ) {
    let now = Date().timeIntervalSince1970
    let minTimestamp = now - maxAgeSeconds
    let timeFiltered = snapshots.filter { $0.timestamp >= minTimestamp }
    let limited =
      timeFiltered.count > maxSnapshots ? Array(timeFiltered.suffix(maxSnapshots)) : timeFiltered
    return (limited, limited.count != snapshots.count)
  }

  private func clearPersistedFilesLocked(resetAnchor: Bool) {
    do {
      try fileManager.removeItem(at: storeURL)
    } catch {
      if (error as NSError).code != NSFileNoSuchFileError {
        Logger.log("DeviceHistory: failed to remove store file - \(error.localizedDescription)")
      }
    }
    do {
      try fileManager.removeItem(at: hmacURL)
    } catch {
      if (error as NSError).code != NSFileNoSuchFileError {
        Logger.log("DeviceHistory: failed to remove hmac file - \(error.localizedDescription)")
      }
    }
    if resetAnchor {
      freshnessAnchor.remove()
    }
  }

  private func maxFreshness(_ lhs: FreshnessState, _ rhs: FreshnessState) -> FreshnessState {
    FreshnessState(
      latestTimestamp: max(lhs.latestTimestamp, rhs.latestTimestamp),
      sequence: max(lhs.sequence, rhs.sequence)
    )
  }
}
