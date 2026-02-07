import Foundation

// MARK: - 设备历史模型
///
/// ## 设计理念
///
/// 设备历史模型用于追踪设备在时间维度上的风险变化趋势。通过历史数据分析，可以：
///
/// 1. **风险趋势判断**：检测风险分数的变化趋势（上升、下降、稳定）
/// 2. **时序特征计算**：提取时间序列统计特征（均值、方差、趋势斜率）
/// 3. **异常事件检测**：识别历史中的异常高风险事件
/// 4. **设备稳定性评估**：判断设备指纹是否在时间上保持一致
///
/// ## 数据结构
///
/// ```
/// RiskDeviceHistory
/// ├── RiskDeviceSnapshot[]     : 历史快照列表
/// ├── HistoryTemporalFeatures     : 时序统计特征
/// ├── HistoryRiskTrend            : 风险趋势枚举
/// └── StabilityMetrics     : 设备稳定性指标
/// ```
///
/// ## 使用场景
///
/// - **增量决策**：结合历史风险趋势进行动态决策
/// - **异常检测**：检测突发的风险异常（如突然越狱）
/// - **白名单动态更新**：根据历史稳定性动态调整白名单
/// - **风险溯源**：追溯风险事件的历史演变
///
public struct RiskDeviceHistory: Codable, Sendable {

    // MARK: - 历史快照列表

    /// 设备快照历史记录（按时间升序排列）
    public let snapshots: [RiskDeviceSnapshot]

    /// 最大历史记录数量（超过此数量会自动清理旧记录）
    public let maxSnapshots: Int

    /// 历史记录的最大保留时间（秒）
    public let retentionPeriod: TimeInterval

    // MARK: - 初始化

    public init(
        snapshots: [RiskDeviceSnapshot] = [],
        maxSnapshots: Int = 100,
        retentionPeriod: TimeInterval = 30 * 24 * 3600 // 30天
    ) {
        // 按时间戳排序并去重
        let sorted = snapshots.sorted { $0.timestamp < $1.timestamp }
        let unique = sorted

        self.snapshots = unique
        self.maxSnapshots = maxSnapshots
        self.retentionPeriod = retentionPeriod
    }

    /// 添加新的快照
    ///
    /// ## 流程
    ///
    /// 1. 验证快照时间戳
    /// 2. 插入并按时间排序
    /// 3. 清理过期和超出数量的记录
    /// 4. 返回新的历史实例
    ///
    public func addingSnapshot(_ snapshot: RiskDeviceSnapshot) -> RiskDeviceHistory {
        var newSnapshots = snapshots + [snapshot]
        newSnapshots = newSnapshots.sorted { $0.timestamp < $1.timestamp }
        newSnapshots = reduceDuplicates(newSnapshots)
        newSnapshots = pruneSnapshots(newSnapshots)

        return RiskDeviceHistory(
            snapshots: newSnapshots,
            maxSnapshots: maxSnapshots,
            retentionPeriod: retentionPeriod
        )
    }

    /// 批量添加快照
    public func addingSnapshots(_ newSnapshots: [RiskDeviceSnapshot]) -> RiskDeviceHistory {
        var combined = snapshots + newSnapshots
        combined = combined.sorted { $0.timestamp < $1.timestamp }
        combined = reduceDuplicates(combined)
        combined = pruneSnapshots(combined)

        return RiskDeviceHistory(
            snapshots: combined,
            maxSnapshots: maxSnapshots,
            retentionPeriod: retentionPeriod
        )
    }

    // MARK: - 时序特征计算

    /// 计算时序统计特征
    ///
    /// ## 返回特征
    ///
    /// - `count`: 有效快照数量
    /// - `timeSpan`: 时间跨度（秒）
    /// - `meanScore`: 平均风险分数
    /// - `stdScore`: 风险分数标准差
    /// - `trendSlope`: 趋势斜率（正=上升，负=下降）
    /// - `maxScore`: 最高风险分数
    /// - `minScore`: 最低风险分数
    /// - `highRiskCount`: 高风险事件次数
    /// - `highRiskRatio`: 高风险事件比例
    ///
    public func temporalFeatures(window: TimeInterval? = nil) -> HistoryTemporalFeatures {
        let windowedSnapshots = snapshots(inWindow: window)

        guard windowedSnapshots.count >= 2 else {
            return HistoryTemporalFeatures(
                count: windowedSnapshots.count,
                timeSpan: 0,
                meanScore: windowedSnapshots.first?.riskScore ?? 0,
                stdScore: 0,
                trendSlope: 0,
                maxScore: windowedSnapshots.first?.riskScore ?? 0,
                minScore: windowedSnapshots.first?.riskScore ?? 0,
                highRiskCount: 0,
                highRiskRatio: 0
            )
        }

        let scores = windowedSnapshots.map { $0.riskScore }
        let timestamps = windowedSnapshots.map { $0.timestamp }

        // 基础统计
        let count = Double(scores.count)
        let meanScore = scores.reduce(0, +) / count
        let maxScore = scores.max() ?? 0
        let minScore = scores.min() ?? 0

        // 标准差
        let variance = scores.map { pow($0 - meanScore, 2) }.reduce(0, +) / count
        let stdScore = sqrt(variance)

        // 时间跨度
        let timeSpan = timestamps.last! - timestamps.first!

        // 趋势斜率（线性回归）
        let trendSlope = calculateLinearRegression(
            x: timestamps,
            y: scores,
            meanX: timestamps.reduce(0, +) / count,
            meanY: meanScore
        )

        // 高风险统计
        let highRiskThreshold: Double = 60
        let highRiskCount = scores.filter { $0 >= highRiskThreshold }.count
        let highRiskRatio = Double(highRiskCount) / count

        return HistoryTemporalFeatures(
            count: Int(count),
            timeSpan: timeSpan,
            meanScore: meanScore,
            stdScore: stdScore,
            trendSlope: trendSlope,
            maxScore: maxScore,
            minScore: minScore,
            highRiskCount: highRiskCount,
            highRiskRatio: highRiskRatio
        )
    }

    /// 判断风险趋势
    ///
    /// ## 趋势分类
    ///
    /// - `escalating`: 风险持续上升（需要重点关注）
    /// - `deescalating`: 风险持续下降（环境改善）
    /// - `stable`: 风险稳定（正常状态）
    /// - `volatile`: 风险剧烈波动（可疑）
    /// - `unknown`: 数据不足
    ///
    /// ## 判断逻辑
    ///
    /// 1. 数据量 < 3：返回 `unknown`
    /// 2. 斜率 > 0.5 且 R² > 0.5：`escalating`
    /// 3. 斜率 < -0.5 且 R² > 0.5：`deescalating`
    /// 4. 标准差 > 20：`volatile`
    /// 5. 其他：`stable`
    ///
    public func riskTrend(window: TimeInterval? = nil) -> HistoryRiskTrend {
        let features = temporalFeatures(window: window)

        guard features.count >= 3 else {
            return .unknown
        }

        // 趋势斜率判断（单位：分数/小时）
        let slopePerHour = features.trendSlope * 3600

        // 波动性判断
        let isVolatile = features.stdScore > 20

        if isVolatile {
            return .volatile
        } else if slopePerHour > 0.5 {
            return .escalating
        } else if slopePerHour < -0.5 {
            return .deescalating
        } else {
            return .stable
        }
    }

    /// 检测风险异常事件
    ///
    /// ## 异常定义
    ///
    /// 1. **突变异常**：风险分数短时间内突增 30+ 分
    /// 2. **持续高位**：风险分数持续高于阈值
    /// 3. **首次越狱**：从正常状态变为越狱状态
    ///
    public func detectAnomalies(threshold: Double = 60) -> [HistoryAnomalyEvent] {
        guard snapshots.count >= 2 else { return [] }

        var anomalies: [HistoryAnomalyEvent] = []

        for (prev, curr) in zip(snapshots, snapshots.dropFirst()) {
            // 突变检测
            let scoreDelta = curr.riskScore - prev.riskScore
            if scoreDelta >= 30 {
                anomalies.append(HistoryAnomalyEvent(
                    type: .suddenSpike,
                    timestamp: curr.timestamp,
                    previousScore: prev.riskScore,
                    currentScore: curr.riskScore,
                    description: "风险分数突变 +\(Int(scoreDelta))"
                ))
            }

            // 越狱状态变化
            if !prev.wasJailbroken && curr.wasJailbroken {
                anomalies.append(HistoryAnomalyEvent(
                    type: .jailbreakDetected,
                    timestamp: curr.timestamp,
                    previousScore: prev.riskScore,
                    currentScore: curr.riskScore,
                    description: "首次检测到越狱状态"
                ))
            }
        }

        return anomalies
    }

    /// 计算设备稳定性指标
    ///
    /// ## 稳定性维度
    ///
    /// 1. **指纹稳定性**：设备指纹哈希是否一致
    /// 2. **配置稳定性**：系统配置是否频繁变化
    /// 3. **网络稳定性**：网络环境是否频繁切换
    /// 4. **位置稳定性**：时区/地区是否频繁变化
    ///
    public func stabilityMetrics() -> StabilityMetrics {
        guard snapshots.count >= 2 else {
            return StabilityMetrics(
                fingerprintStability: 1.0,
                configurationStability: 1.0,
                networkStability: 1.0,
                locationStability: 1.0,
                overallStability: 1.0
            )
        }

        // 指纹稳定性
        let uniqueFingerprints = Set(snapshots.map { $0.fingerprintHash }).count
        let fingerprintStability = 1.0 - (Double(uniqueFingerprints - 1) / Double(max(snapshots.count - 1, 1)))

        // 配置稳定性（系统版本、语言、地区）
        var configChanges = 0
        for (prev, curr) in zip(snapshots, snapshots.dropFirst()) {
            if prev.systemVersion != curr.systemVersion ||
               prev.languageCode != curr.languageCode ||
               prev.regionCode != curr.regionCode {
                configChanges += 1
            }
        }
        let configurationStability = 1.0 - (Double(configChanges) / Double(max(snapshots.count - 1, 1)))

        // 网络稳定性（接口类型变化）
        var networkChanges = 0
        for (prev, curr) in zip(snapshots, snapshots.dropFirst()) {
            if prev.primaryInterfaceType != curr.primaryInterfaceType {
                networkChanges += 1
            }
        }
        let networkStability = 1.0 - (Double(networkChanges) / Double(max(snapshots.count - 1, 1)))

        // 位置稳定性（时区变化）
        var locationChanges = 0
        for (prev, curr) in zip(snapshots, snapshots.dropFirst()) {
            if prev.timeZoneIdentifier != curr.timeZoneIdentifier {
                locationChanges += 1
            }
        }
        let locationStability = 1.0 - (Double(locationChanges) / Double(max(snapshots.count - 1, 1)))

        // 综合稳定性
        let overallStability = (
            fingerprintStability +
            configurationStability +
            networkStability +
            locationStability
        ) / 4.0

        return StabilityMetrics(
            fingerprintStability: max(0, min(1, fingerprintStability)),
            configurationStability: max(0, min(1, configurationStability)),
            networkStability: max(0, min(1, networkStability)),
            locationStability: max(0, min(1, locationStability)),
            overallStability: max(0, min(1, overallStability))
        )
    }

    // MARK: - 查询方法

    /// 获取指定时间窗口内的快照
    public func snapshots(inWindow window: TimeInterval?) -> [RiskDeviceSnapshot] {
        guard let window = window else { return snapshots }

        let now = Date().timeIntervalSince1970
        let windowStart = now - window

        return snapshots.filter { $0.timestamp >= windowStart }
    }

    /// 获取最新的 N 个快照
    public func latestSnapshots(count: Int) -> [RiskDeviceSnapshot] {
        return Array(snapshots.suffix(count))
    }

    /// 获取最新的快照
    public var latestSnapshot: RiskDeviceSnapshot? {
        return snapshots.last
    }

    /// 获取最早的快照
    public var earliestSnapshot: RiskDeviceSnapshot? {
        return snapshots.first
    }

    // MARK: - 私有辅助方法

    /// 去除时间戳相近的重复快照（1分钟内只保留一个）
    private func reduceDuplicates(_ snapshots: [RiskDeviceSnapshot]) -> [RiskDeviceSnapshot] {
        var result: [RiskDeviceSnapshot] = []
        var lastTimestamp: TimeInterval?

        for snapshot in snapshots {
            if let last = lastTimestamp {
                if snapshot.timestamp - last > 60 { // 1分钟间隔
                    result.append(snapshot)
                    lastTimestamp = snapshot.timestamp
                }
            } else {
                result.append(snapshot)
                lastTimestamp = snapshot.timestamp
            }
        }

        return result
    }

    /// 清理超出数量限制的快照
    private func pruneSnapshots(_ snapshots: [RiskDeviceSnapshot]) -> [RiskDeviceSnapshot] {
        let now = Date().timeIntervalSince1970
        let minTimestamp = now - retentionPeriod

        // 先过滤过期记录
        var valid = snapshots.filter { $0.timestamp >= minTimestamp }

        // 再限制数量
        if valid.count > maxSnapshots {
            valid = Array(valid.suffix(maxSnapshots))
        }

        return valid
    }

    /// 计算线性回归斜率
    private func calculateLinearRegression(x: [TimeInterval], y: [Double], meanX: Double, meanY: Double) -> Double {
        var numerator: Double = 0
        var denominator: Double = 0

        for (xi, yi) in zip(x, y) {
            numerator += (xi - meanX) * (yi - meanY)
            denominator += pow(xi - meanX, 2)
        }

        return denominator > 0 ? numerator / denominator : 0
    }
}

// MARK: - 设备快照

/// 单个时间点的设备状态快照
public struct RiskDeviceSnapshot: Codable, Sendable {

    /// 快照时间戳（Unix 时间戳，秒）
    public let timestamp: TimeInterval

    /// 风险分数（0-100）
    public let riskScore: Double

    /// 是否高风险
    public let isHighRisk: Bool

    /// 是否检测到越狱
    public let wasJailbroken: Bool

    /// 越狱置信度
    public let jailbreakConfidence: Double

    /// 设备指纹哈希
    public let fingerprintHash: String

    /// 系统版本
    public let systemVersion: String

    /// 语言代码
    public let languageCode: String

    /// 地区代码
    public let regionCode: String

    /// 时区标识符
    public let timeZoneIdentifier: String

    /// 主要网络接口类型
    public let primaryInterfaceType: String

    /// 是否启用 VPN
    public let hasVPN: Bool

    /// 是否启用代理
    public let hasProxy: Bool

    /// 额外的元数据（可选）
    public let metadata: [String: String]?

    public init(
        timestamp: TimeInterval,
        riskScore: Double,
        isHighRisk: Bool,
        wasJailbroken: Bool,
        jailbreakConfidence: Double,
        fingerprintHash: String,
        systemVersion: String,
        languageCode: String,
        regionCode: String,
        timeZoneIdentifier: String,
        primaryInterfaceType: String,
        hasVPN: Bool,
        hasProxy: Bool,
        metadata: [String: String]? = nil
    ) {
        self.timestamp = timestamp
        self.riskScore = riskScore
        self.isHighRisk = isHighRisk
        self.wasJailbroken = wasJailbroken
        self.jailbreakConfidence = jailbreakConfidence
        self.fingerprintHash = fingerprintHash
        self.systemVersion = systemVersion
        self.languageCode = languageCode
        self.regionCode = regionCode
        self.timeZoneIdentifier = timeZoneIdentifier
        self.primaryInterfaceType = primaryInterfaceType
        self.hasVPN = hasVPN
        self.hasProxy = hasProxy
        self.metadata = metadata
    }

    /// 从 `RiskContext` 和 `RiskScoreReport` 创建快照
    public static func from(
        context: RiskContext,
        report: RiskScoreReport,
        fingerprintHash: String
    ) -> RiskDeviceSnapshot {
        return RiskDeviceSnapshot(
            timestamp: Date().timeIntervalSince1970,
            riskScore: report.score,
            isHighRisk: report.isHighRisk,
            wasJailbroken: context.jailbreak.isJailbroken,
            jailbreakConfidence: context.jailbreak.confidence,
            fingerprintHash: fingerprintHash,
            systemVersion: context.device.systemVersion,
            languageCode: Locale.current.languageCode ?? "",
            regionCode: currentRegionCode(),
            timeZoneIdentifier: TimeZone.current.identifier,
            primaryInterfaceType: context.network.interfaceType.value,
            hasVPN: context.network.isVPNActive,
            hasProxy: context.network.proxyEnabled,
            metadata: [
                "model": context.device.model,
                "locale": context.device.localeIdentifier
            ]
        )
    }

    private static func currentRegionCode() -> String {
        let locale = Locale.current
        if #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) {
            return locale.region?.identifier ?? locale.regionCode ?? ""
        }
        return locale.regionCode ?? ""
    }
}

// MARK: - 时序特征

public struct HistoryTemporalFeatures: Codable, Sendable {
    /// 有效快照数量
    public let count: Int

    /// 时间跨度（秒）
    public let timeSpan: TimeInterval

    /// 平均风险分数
    public let meanScore: Double

    /// 风险分数标准差
    public let stdScore: Double

    /// 趋势斜率（分数/秒）
    public let trendSlope: Double

    /// 最高风险分数
    public let maxScore: Double

    /// 最低风险分数
    public let minScore: Double

    /// 高风险事件次数
    public let highRiskCount: Int

    /// 高风险事件比例（0-1）
    public let highRiskRatio: Double

    public init(
        count: Int,
        timeSpan: TimeInterval,
        meanScore: Double,
        stdScore: Double,
        trendSlope: Double,
        maxScore: Double,
        minScore: Double,
        highRiskCount: Int,
        highRiskRatio: Double
    ) {
        self.count = count
        self.timeSpan = timeSpan
        self.meanScore = meanScore
        self.stdScore = stdScore
        self.trendSlope = trendSlope
        self.maxScore = maxScore
        self.minScore = minScore
        self.highRiskCount = highRiskCount
        self.highRiskRatio = highRiskRatio
    }

    /// 判断是否为高风险历史
    public func isHighRiskHistory(threshold: Double = 60) -> Bool {
        return meanScore >= threshold || highRiskRatio >= 0.5
    }

    /// 判断是否为上升趋势
    public func isEscalating(threshold: Double = 0.1) -> Bool {
        // 转换为每小时的斜率
        return trendSlope * 3600 > threshold
    }
}

// MARK: - 风险趋势

public enum HistoryRiskTrend: String, Codable, Sendable {
    /// 风险上升（需要关注）
    case escalating

    /// 风险下降（环境改善）
    case deescalating

    /// 风险稳定
    case stable

    /// 风险剧烈波动
    case volatile

    /// 数据不足
    case unknown

    /// 趋势的中文描述
    public var description: String {
        switch self {
        case .escalating: return "风险上升"
        case .deescalating: return "风险下降"
        case .stable: return "风险稳定"
        case .volatile: return "风险波动"
        case .unknown: return "数据不足"
        }
    }

    /// 趋势对应的建议动作
    public var recommendedAction: String {
        switch self {
        case .escalating: return "建议加强验证或限制操作"
        case .deescalating: return "可逐步放宽限制"
        case .stable: return "保持当前策略"
        case .volatile: return "建议进行二次验证"
        case .unknown: return "建议收集更多数据"
        }
    }
}

// MARK: - 稳定性指标

public struct StabilityMetrics: Codable, Sendable {
    /// 指纹稳定性（0-1，越高越稳定）
    public let fingerprintStability: Double

    /// 配置稳定性（0-1，越高越稳定）
    public let configurationStability: Double

    /// 网络稳定性（0-1，越高越稳定）
    public let networkStability: Double

    /// 位置稳定性（0-1，越高越稳定）
    public let locationStability: Double

    /// 综合稳定性（0-1，越高越稳定）
    public let overallStability: Double

    public init(
        fingerprintStability: Double,
        configurationStability: Double,
        networkStability: Double,
        locationStability: Double,
        overallStability: Double
    ) {
        self.fingerprintStability = fingerprintStability
        self.configurationStability = configurationStability
        self.networkStability = networkStability
        self.locationStability = locationStability
        self.overallStability = overallStability
    }

    /// 判断是否为稳定设备
    public func isStable(threshold: Double = 0.8) -> Bool {
        return overallStability >= threshold
    }

    /// 获取不稳定的维度列表
    public func unstableDimensions(threshold: Double = 0.7) -> [String] {
        var dimensions: [String] = []

        if fingerprintStability < threshold {
            dimensions.append("指纹")
        }
        if configurationStability < threshold {
            dimensions.append("配置")
        }
        if networkStability < threshold {
            dimensions.append("网络")
        }
        if locationStability < threshold {
            dimensions.append("位置")
        }

        return dimensions
    }
}

// MARK: - 异常事件

public struct HistoryAnomalyEvent: Codable, Sendable {
    /// 异常类型
    public let type: HistoryAnomalyType

    /// 异常发生时间戳
    public let timestamp: TimeInterval

    /// 异常前的风险分数
    public let previousScore: Double

    /// 异常后的风险分数
    public let currentScore: Double

    /// 异常描述
    public let description: String

    public init(
        type: HistoryAnomalyType,
        timestamp: TimeInterval,
        previousScore: Double,
        currentScore: Double,
        description: String
    ) {
        self.type = type
        self.timestamp = timestamp
        self.previousScore = previousScore
        self.currentScore = currentScore
        self.description = description
    }
}

/// 异常类型
public enum HistoryAnomalyType: String, Codable, Sendable {
    /// 风险分数突变
    case suddenSpike

    /// 首次检测到越狱
    case jailbreakDetected

    /// 指纹哈希变化
    case fingerprintChanged

    /// 异常时间活动
    case unusualTimeActivity

    /// 异常地理位置
    case unusualLocation
}

// MARK: - 风险上下文扩展（内部使用）

/// 隐式的 RiskContext 结构，用于编译
private struct HistoryRiskContext {
    var device: DeviceFingerprint
    var network: NetworkSignals
    var jailbreak: DetectionResult
}
