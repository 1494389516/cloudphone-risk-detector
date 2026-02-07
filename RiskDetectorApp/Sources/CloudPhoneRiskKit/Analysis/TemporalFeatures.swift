import Foundation

// MARK: - 风险趋势
/// 风险分数随时间的变化趋势
public enum RiskTrend: String, Codable, Sendable {
    /// 风险在改善（分数下降）
    case improving

    /// 风险稳定（分数变化不大）
    case stable

    /// 风险在恶化（分数上升）
    case deteriorating

    /// 未知（数据不足）
    case unknown
}

// MARK: - 时序特征
/// 从设备历史数据中计算得到的时序特征
public struct TemporalFeatures: Codable, Sendable {
    /// 设备年龄：首次见到设备至今的天数
    public var deviceAgeDays: Int

    /// 总检测次数
    public var totalDetectionCount: Int

    /// 风险趋势
    public var riskTrend: RiskTrend

    /// 首次越狱时间（时间戳，nil 表示从未检测到越狱）
    public var firstJailbreakTime: TimeInterval?

    /// 首次越狱距今的天数
    public var daysSinceFirstJailbreak: Int?

    /// 最近 7 天内的越狱次数
    public var jailbreakCount7Days: Int

    /// 最近 30 天内的越狱次数
    public var jailbreakCount30Days: Int

    /// VPN 使用频率（0-1）
    public var vpnUsageFrequency: Double

    /// VPN 切换次数（最近 7 天内 VPN 状态变化的次数）
    public var vpnSwitchCount7Days: Int

    /// 行为一致性分数（0-1，越高越一致）
    public var behaviorConsistency: Double

    /// 平均风险分数
    public var averageRiskScore: Double

    /// 风险分数标准差
    public var riskScoreStdDev: Double

    /// 最大风险分数
    public var maxRiskScore: Double

    /// 最小风险分数
    public var minRiskScore: Double

    /// 高风险检测次数占比
    public var highRiskRatio: Double

    /// 最近一次检测时间距现在的秒数
    public var secondsSinceLastDetection: TimeInterval

    /// 活跃天数：有检测记录的不同天数
    public var activeDays: Int

    /// 计算时间戳
    public var calculatedAt: TimeInterval

    public init(
        deviceAgeDays: Int,
        totalDetectionCount: Int,
        riskTrend: RiskTrend,
        firstJailbreakTime: TimeInterval?,
        daysSinceFirstJailbreak: Int?,
        jailbreakCount7Days: Int,
        jailbreakCount30Days: Int,
        vpnUsageFrequency: Double,
        vpnSwitchCount7Days: Int,
        behaviorConsistency: Double,
        averageRiskScore: Double,
        riskScoreStdDev: Double,
        maxRiskScore: Double,
        minRiskScore: Double,
        highRiskRatio: Double,
        secondsSinceLastDetection: TimeInterval,
        activeDays: Int,
        calculatedAt: TimeInterval
    ) {
        self.deviceAgeDays = deviceAgeDays
        self.totalDetectionCount = totalDetectionCount
        self.riskTrend = riskTrend
        self.firstJailbreakTime = firstJailbreakTime
        self.daysSinceFirstJailbreak = daysSinceFirstJailbreak
        self.jailbreakCount7Days = jailbreakCount7Days
        self.jailbreakCount30Days = jailbreakCount30Days
        self.vpnUsageFrequency = vpnUsageFrequency
        self.vpnSwitchCount7Days = vpnSwitchCount7Days
        self.behaviorConsistency = behaviorConsistency
        self.averageRiskScore = averageRiskScore
        self.riskScoreStdDev = riskScoreStdDev
        self.maxRiskScore = maxRiskScore
        self.minRiskScore = minRiskScore
        self.highRiskRatio = highRiskRatio
        self.secondsSinceLastDetection = secondsSinceLastDetection
        self.activeDays = activeDays
        self.calculatedAt = calculatedAt
    }

    /// 便捷初始化：空特征（无历史数据时使用）
    public static func empty(at timestamp: TimeInterval = Date().timeIntervalSince1970) -> TemporalFeatures {
        return TemporalFeatures(
            deviceAgeDays: 0,
            totalDetectionCount: 0,
            riskTrend: .unknown,
            firstJailbreakTime: nil,
            daysSinceFirstJailbreak: nil,
            jailbreakCount7Days: 0,
            jailbreakCount30Days: 0,
            vpnUsageFrequency: 0,
            vpnSwitchCount7Days: 0,
            behaviorConsistency: 1.0,
            averageRiskScore: 0,
            riskScoreStdDev: 0,
            maxRiskScore: 0,
            minRiskScore: 0,
            highRiskRatio: 0,
            secondsSinceLastDetection: 0,
            activeDays: 0,
            calculatedAt: timestamp
        )
    }
}

// MARK: - 时序特征计算器
/// 负责从历史数据中计算时序特征
public final class TemporalFeaturesCalculator {
    private let history: DeviceHistory
    private let calendar = Calendar(identifier: .gregorian)

    public init(history: DeviceHistory = .shared) {
        self.history = history
    }

    /// 为指定设备计算时序特征
    public func calculate(for deviceID: String) -> TemporalFeatures {
        let now = Date().timeIntervalSince1970

        // 获取所有历史快照
        let snapshots = history.getSnapshots(for: deviceID)

        guard !snapshots.isEmpty else {
            return TemporalFeatures.empty(at: now)
        }

        // 1. 设备年龄
        let deviceAgeDays = calculateDeviceAgeDays(snapshots: snapshots, now: now)

        // 2. 总检测次数
        let totalDetectionCount = snapshots.count

        // 3. 风险趋势
        let riskTrend = calculateRiskTrend(snapshots: snapshots)

        // 4. 越狱相关
        let firstJailbreakTime = history.getFirstJailbreakTime(for: deviceID)
        let daysSinceFirstJailbreak = firstJailbreakTime.map { Int((now - $0) / (24 * 3600)) }
        let jailbreakCount7Days = history.getJailbreakCount(days: 7, for: deviceID)
        let jailbreakCount30Days = history.getJailbreakCount(days: 30, for: deviceID)

        // 5. VPN 相关
        let vpnUsageFrequency = history.getVPNUsageFrequency(days: 7, for: deviceID)
        let vpnSwitchCount7Days = calculateVPNSwitchCount(snapshots: snapshots, windowDays: 7)

        // 6. 行为一致性
        let behaviorConsistency = calculateBehaviorConsistency(snapshots: snapshots)

        // 7. 风险分数统计
        let scores = snapshots.map { $0.riskScore }
        let averageRiskScore = scores.reduce(0, +) / Double(scores.count)
        let variance = scores.map { pow($0 - averageRiskScore, 2) }.reduce(0, +) / Double(scores.count)
        let riskScoreStdDev = sqrt(variance)
        let maxRiskScore = scores.max() ?? 0
        let minRiskScore = scores.min() ?? 0

        // 8. 高风险占比
        let highRiskCount = snapshots.filter { $0.isHighRisk }.count
        let highRiskRatio = Double(highRiskCount) / Double(snapshots.count)

        // 9. 距离最后一次检测的时间
        let lastTimestamp = snapshots.map { $0.timestamp }.max() ?? now
        let secondsSinceLastDetection = now - lastTimestamp

        // 10. 活跃天数
        let activeDays = calculateActiveDays(snapshots: snapshots)

        return TemporalFeatures(
            deviceAgeDays: deviceAgeDays,
            totalDetectionCount: totalDetectionCount,
            riskTrend: riskTrend,
            firstJailbreakTime: firstJailbreakTime,
            daysSinceFirstJailbreak: daysSinceFirstJailbreak,
            jailbreakCount7Days: jailbreakCount7Days,
            jailbreakCount30Days: jailbreakCount30Days,
            vpnUsageFrequency: vpnUsageFrequency,
            vpnSwitchCount7Days: vpnSwitchCount7Days,
            behaviorConsistency: behaviorConsistency,
            averageRiskScore: averageRiskScore,
            riskScoreStdDev: riskScoreStdDev,
            maxRiskScore: maxRiskScore,
            minRiskScore: minRiskScore,
            highRiskRatio: highRiskRatio,
            secondsSinceLastDetection: secondsSinceLastDetection,
            activeDays: activeDays,
            calculatedAt: now
        )
    }

    // MARK: - 私有计算方法

    /// 计算设备年龄（天数）
    private func calculateDeviceAgeDays(snapshots: [DeviceDetectionSnapshot], now: TimeInterval) -> Int {
        guard let firstTimestamp = snapshots.map({ $0.timestamp }).min() else {
            return 0
        }
        return Int((now - firstTimestamp) / (24 * 3600))
    }

    /// 计算风险趋势
    private func calculateRiskTrend(snapshots: [DeviceDetectionSnapshot]) -> RiskTrend {
        guard snapshots.count >= 3 else {
            return .unknown
        }

        // 取最近的 10 个快照（或全部，如果少于 10 个）
        let recent = Array(snapshots.suffix(min(10, snapshots.count)))
        let scores = recent.map { $0.riskScore }

        // 使用线性回归计算趋势斜率
        let n = Double(scores.count)
        let xValues = Array(0..<scores.count).map { Double($0) }

        let sumX = xValues.reduce(0, +)
        let sumY = scores.reduce(0, +)
        let sumXY = zip(xValues, scores).map(*).reduce(0, +)
        let sumXX = xValues.map { $0 * $0 }.reduce(0, +)

        let slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX)
        let avgScore = sumY / n

        // 根据斜率判断趋势
        let threshold = avgScore * 0.1 // 10% 的平均分数作为阈值

        if abs(slope) < threshold {
            return .stable
        } else if slope < 0 {
            return .improving
        } else {
            return .deteriorating
        }
    }

    /// 计算 VPN 切换次数
    private func calculateVPNSwitchCount(snapshots: [DeviceDetectionSnapshot], windowDays: Int) -> Int {
        let now = Date().timeIntervalSince1970
        let windowStart = now - TimeInterval(windowDays * 24 * 3600)

        let recent = snapshots.filter { $0.timestamp >= windowStart }
        guard recent.count >= 2 else { return 0 }

        let sorted = recent.sorted { $0.timestamp < $1.timestamp }
        var switchCount = 0
        var previousVPNStatus = sorted.first?.isVPNActive

        for snapshot in sorted.dropFirst() {
            if snapshot.isVPNActive != previousVPNStatus {
                switchCount += 1
                previousVPNStatus = snapshot.isVPNActive
            }
        }

        return switchCount
    }

    /// 计算行为一致性分数
    private func calculateBehaviorConsistency(snapshots: [DeviceDetectionSnapshot]) -> Double {
        guard snapshots.count >= 2 else { return 1.0 }

        // 过滤出有行为摘要的快照
        let withBehavior = snapshots.compactMap { $0.behaviorSummary }

        guard withBehavior.count >= 2 else { return 1.0 }

        // 计算各项指标的变异系数（CV = 标准差/均值）
        var cvs: [Double] = []

        // 1. 操作数量的一致性
        let actionCounts = withBehavior.map { Double($0.actionCount) }
        if actionCounts.max() ?? 0 > 0 {
            let avg = actionCounts.reduce(0, +) / Double(actionCounts.count)
            let variance = actionCounts.map { pow($0 - avg, 2) }.reduce(0, +) / Double(actionCounts.count)
            let stdDev = sqrt(variance)
            if avg > 0 {
                cvs.append(stdDev / avg)
            }
        }

        // 2. 点击与滑动比例的一致性
        let tapSwipeRatios = withBehavior.map { summary -> Double in
            guard summary.tapCount + summary.swipeCount > 0 else { return 0 }
            return Double(summary.tapCount) / Double(summary.tapCount + summary.swipeCount)
        }
        if tapSwipeRatios.max() ?? 0 > 0 {
            let avg = tapSwipeRatios.reduce(0, +) / Double(tapSwipeRatios.count)
            let variance = tapSwipeRatios.map { pow($0 - avg, 2) }.reduce(0, +) / Double(tapSwipeRatios.count)
            let stdDev = sqrt(variance)
            if avg > 0 {
                cvs.append(stdDev / avg)
            }
        }

        // 3. 触摸-运动相关性的一致性
        let correlations = withBehavior.compactMap { $0.touchMotionCorrelation }
        if correlations.count >= 2 {
            let avg = correlations.reduce(0, +) / Double(correlations.count)
            let variance = correlations.map { pow($0 - avg, 2) }.reduce(0, +) / Double(correlations.count)
            let stdDev = sqrt(variance)
            if avg > 0 {
                cvs.append(stdDev / avg)
            }
        }

        // 平均 CV 转换为一致性分数（CV 越小，一致性越高）
        guard !cvs.isEmpty else { return 1.0 }

        let avgCV = cvs.reduce(0, +) / Double(cvs.count)
        // 使用指数衰减将 CV 转换为 0-1 的一致性分数
        let consistency = exp(-avgCV)

        return max(0, min(1, consistency))
    }

    /// 计算活跃天数（有检测记录的不同天数）
    private func calculateActiveDays(snapshots: [DeviceDetectionSnapshot]) -> Int {
        let dates = snapshots.map { Date(timeIntervalSince1970: $0.timestamp) }
        var uniqueDays = Set<String>()

        for date in dates {
            let components = calendar.dateComponents([.year, .month, .day], from: date)
            if let year = components.year, let month = components.month, let day = components.day {
                let key = "\(year)-\(month)-\(day)"
                uniqueDays.insert(key)
            }
        }

        return uniqueDays.count
    }
}

// MARK: - 数学辅助函数
private func pow(_ base: Double, _ exp: Double) -> Double {
    return Darwin.pow(base, exp)
}

private func sqrt(_ x: Double) -> Double {
    return Darwin.sqrt(x)
}

private func exp(_ x: Double) -> Double {
    return Darwin.exp(x)
}
