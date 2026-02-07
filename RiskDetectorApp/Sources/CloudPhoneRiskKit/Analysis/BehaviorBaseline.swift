import Foundation

// MARK: - 统计特征
/// 数值数据的统计特征
public struct StatisticalFeatures: Codable, Sendable {
    /// 均值
    public var mean: Double

    /// 中位数
    public var median: Double

    /// 标准差
    public var stdDev: Double

    /// 方差
    public var variance: Double

    /// 最小值
    public var min: Double

    /// 最大值
    public var max: Double

    /// 第 25 百分位数
    public var percentile25: Double

    /// 第 75 百分位数
    public var percentile75: Double

    /// 四分位距 (IQR)
    public var iqr: Double

    /// 变异系数 (CV = stdDev / mean)
    public var coefficientOfVariation: Double

    /// 样本数量
    public var count: Int

    public init(
        mean: Double,
        median: Double,
        stdDev: Double,
        variance: Double,
        min: Double,
        max: Double,
        percentile25: Double,
        percentile75: Double,
        iqr: Double,
        coefficientOfVariation: Double,
        count: Int
    ) {
        self.mean = mean
        self.median = median
        self.stdDev = stdDev
        self.variance = variance
        self.min = min
        self.max = max
        self.percentile25 = percentile25
        self.percentile75 = percentile75
        self.iqr = iqr
        self.coefficientOfVariation = coefficientOfVariation
        self.count = count
    }

    /// 从数组计算统计特征
    public static func from(_ values: [Double]) -> StatisticalFeatures? {
        guard !values.isEmpty else { return nil }

        let sorted = values.sorted()
        let count = Double(values.count)

        let sum = values.reduce(0, +)
        let mean = sum / count

        let variance = values.map { pow($0 - mean, 2) }.reduce(0, +) / count
        let stdDev = sqrt(variance)

        let min = sorted.first ?? 0
        let max = sorted.last ?? 0

        let median = percentile(sorted: sorted, p: 50)
        let p25 = percentile(sorted: sorted, p: 25)
        let p75 = percentile(sorted: sorted, p: 75)

        let iqr = p75 - p25
        let cv = mean > 0 ? stdDev / mean : 0

        return StatisticalFeatures(
            mean: mean,
            median: median,
            stdDev: stdDev,
            variance: variance,
            min: min,
            max: max,
            percentile25: p25,
            percentile75: p75,
            iqr: iqr,
            coefficientOfVariation: cv,
            count: values.count
        )
    }

    private static func percentile(sorted: [Double], p: Double) -> Double {
        guard !sorted.isEmpty else { return 0 }
        let count = Double(sorted.count)
        let index = (p / 100.0) * (count - 1)
        let lower = Int(floor(index))
        let upper = Int(ceil(index))
        guard lower >= 0, upper < sorted.count else { return sorted[0] }

        if lower == upper {
            return sorted[lower]
        }

        let weight = index - Double(lower)
        return sorted[lower] * (1 - weight) + sorted[upper] * weight
    }
}

// MARK: - 行为基线
/// 设备行为的历史基线
public struct BehaviorBaseline: Codable, Sendable {
    /// 基线创建时间
    public var createdAt: TimeInterval

    /// 基线最后更新时间
    public var updatedAt: TimeInterval

    /// 操作数量统计
    public var actionCountStats: StatisticalFeatures

    /// 点击数量统计
    public var tapCountStats: StatisticalFeatures

    /// 滑动数量统计
    public var swipeCountStats: StatisticalFeatures

    /// 点击-滑动比例统计
    public var tapSwipeRatioStats: StatisticalFeatures

    /// 触摸-运动相关性统计
    public var touchMotionCorrelationStats: StatisticalFeatures?

    /// 用于计算此基线的样本数量
    public var sampleCount: Int

    public init(
        createdAt: TimeInterval,
        updatedAt: TimeInterval,
        actionCountStats: StatisticalFeatures,
        tapCountStats: StatisticalFeatures,
        swipeCountStats: StatisticalFeatures,
        tapSwipeRatioStats: StatisticalFeatures,
        touchMotionCorrelationStats: StatisticalFeatures?,
        sampleCount: Int
    ) {
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.actionCountStats = actionCountStats
        self.tapCountStats = tapCountStats
        self.swipeCountStats = swipeCountStats
        self.tapSwipeRatioStats = tapSwipeRatioStats
        self.touchMotionCorrelationStats = touchMotionCorrelationStats
        self.sampleCount = sampleCount
    }

    /// 空基线
    public static func empty(at timestamp: TimeInterval = Date().timeIntervalSince1970) -> BehaviorBaseline {
        let emptyStats = StatisticalFeatures(
            mean: 0,
            median: 0,
            stdDev: 0,
            variance: 0,
            min: 0,
            max: 0,
            percentile25: 0,
            percentile75: 0,
            iqr: 0,
            coefficientOfVariation: 0,
            count: 0
        )

        return BehaviorBaseline(
            createdAt: timestamp,
            updatedAt: timestamp,
            actionCountStats: emptyStats,
            tapCountStats: emptyStats,
            swipeCountStats: emptyStats,
            tapSwipeRatioStats: emptyStats,
            touchMotionCorrelationStats: nil,
            sampleCount: 0
        )
    }
}

// MARK: - 行为基线构建器
/// 负责从历史数据构建和更新行为基线
public final class BehaviorBaselineBuilder {
    private let history: DeviceHistory
    private let lock = NSLock()

    /// 缓存已计算的基线
    private var cachedBaselines: [String: BehaviorBaseline] = [:]

    /// 基线最大有效期（秒），默认 7 天
    private let baselineMaxAge: TimeInterval = 7 * 24 * 3600

    /// 最小样本数量，少于则不建立基线
    private let minSampleCount = 5

    public init(history: DeviceHistory = .shared) {
        self.history = history
    }

    // MARK: - 获取/构建基线

    /// 获取设备的行为基线，如果不存在或过期则重新构建
    public func getBaseline(for deviceID: String, forceRebuild: Bool = false) -> BehaviorBaseline {
        lock.lock()
        defer { lock.unlock() }

        let now = Date().timeIntervalSince1970

        // 检查缓存
        if !forceRebuild, let cached = cachedBaselines[deviceID] {
            let age = now - cached.updatedAt
            if age < baselineMaxAge {
                return cached
            }
        }

        // 重新构建
        let rebuiltBaseline = buildBaseline(for: deviceID)
        cachedBaselines[deviceID] = rebuiltBaseline

        return rebuiltBaseline
    }

    /// 增量更新基线
    public func updateBaseline(for deviceID: String, with newBehavior: BehaviorSignals) {
        lock.lock()
        defer { lock.unlock() }

        // 获取当前基线
        let currentBaseline = getBaseline(for: deviceID)

        // 如果基线为空，直接重建
        guard currentBaseline.sampleCount >= minSampleCount else {
            cachedBaselines[deviceID] = buildBaseline(for: deviceID)
            return
        }

        // 获取历史数据用于重新计算
        let rebuiltBaseline = buildBaseline(for: deviceID)
        cachedBaselines[deviceID] = rebuiltBaseline
    }

    /// 清除缓存的基线
    public func clearCache(for deviceID: String? = nil) {
        lock.lock()
        defer { lock.unlock() }

        if let deviceID = deviceID {
            cachedBaselines.removeValue(forKey: deviceID)
        } else {
            cachedBaselines.removeAll()
        }
    }

    // MARK: - 私有方法

    /// 从历史数据构建基线
    private func buildBaseline(for deviceID: String) -> BehaviorBaseline {
        let now = Date().timeIntervalSince1970

        let snapshots = history.getSnapshots(for: deviceID)
        let summaries = snapshots.compactMap { $0.behaviorSummary }

        guard summaries.count >= minSampleCount else {
            return BehaviorBaseline.empty(at: now)
        }

        // 提取各项指标
        let actionCounts = summaries.map { Double($0.actionCount) }
        let tapCounts = summaries.map { Double($0.tapCount) }
        let swipeCounts = summaries.map { Double($0.swipeCount) }

        // 计算点击-滑动比例
        let tapSwipeRatios = summaries.map { summary -> Double in
            guard summary.tapCount + summary.swipeCount > 0 else { return 0.5 }
            return Double(summary.tapCount) / Double(summary.tapCount + summary.swipeCount)
        }

        // 提取触摸-运动相关性
        let correlations = summaries.compactMap { $0.touchMotionCorrelation }

        // 计算统计特征
        guard let actionStats = StatisticalFeatures.from(actionCounts),
              let tapStats = StatisticalFeatures.from(tapCounts),
              let swipeStats = StatisticalFeatures.from(swipeCounts),
              let ratioStats = StatisticalFeatures.from(tapSwipeRatios) else {
            return BehaviorBaseline.empty(at: now)
        }

        let correlationStats = correlations.isEmpty ? nil : StatisticalFeatures.from(correlations)

        // 找出最早的记录时间
        let firstSeen = snapshots.map { $0.timestamp }.min() ?? now

        return BehaviorBaseline(
            createdAt: firstSeen,
            updatedAt: now,
            actionCountStats: actionStats,
            tapCountStats: tapStats,
            swipeCountStats: swipeStats,
            tapSwipeRatioStats: ratioStats,
            touchMotionCorrelationStats: correlationStats,
            sampleCount: summaries.count
        )
    }
}

// MARK: - 基线比较器
/// 用于比较当前行为与基线的偏差
public struct BaselineDeviation: Sendable {
    /// 偏差指标名称
    public var metricName: String

    /// 当前值
    public var currentValue: Double

    /// 基线均值
    public var baselineMean: Double

    /// Z-score
    public var zScore: Double

    /// 是否异常
    public var isAnomalous: Bool

    /// 偏差百分比
    public var deviationPercent: Double

    public init(
        metricName: String,
        currentValue: Double,
        baselineMean: Double,
        zScore: Double,
        isAnomalous: Bool,
        deviationPercent: Double
    ) {
        self.metricName = metricName
        self.currentValue = currentValue
        self.baselineMean = baselineMean
        self.zScore = zScore
        self.isAnomalous = isAnomalous
        self.deviationPercent = deviationPercent
    }
}

public final class BaselineComparator {
    /// Z-score 阈值
    public var zScoreThreshold: Double

    public init(zScoreThreshold: Double = 2.5) {
        self.zScoreThreshold = zScoreThreshold
    }

    /// 比较当前行为与基线的偏差
    public func compare(current: BehaviorSignals, baseline: BehaviorBaseline) -> [BaselineDeviation] {
        var deviations: [BaselineDeviation] = []

        guard baseline.sampleCount > 0 else {
            return deviations
        }

        // 比较操作数量
        let actionDeviation = compareMetric(
            name: "action_count",
            current: Double(current.actionCount),
            stats: baseline.actionCountStats
        )
        deviations.append(actionDeviation)

        // 比较点击数量
        let tapDeviation = compareMetric(
            name: "tap_count",
            current: Double(current.touch.tapCount),
            stats: baseline.tapCountStats
        )
        deviations.append(tapDeviation)

        // 比较滑动数量
        let swipeDeviation = compareMetric(
            name: "swipe_count",
            current: Double(current.touch.swipeCount),
            stats: baseline.swipeCountStats
        )
        deviations.append(swipeDeviation)

        // 比较点击-滑动比例
        let currentRatio: Double
        if current.touch.tapCount + current.touch.swipeCount > 0 {
            currentRatio = Double(current.touch.tapCount) / Double(current.touch.tapCount + current.touch.swipeCount)
        } else {
            currentRatio = 0.5
        }
        let ratioDeviation = compareMetric(
            name: "tap_swipe_ratio",
            current: currentRatio,
            stats: baseline.tapSwipeRatioStats
        )
        deviations.append(ratioDeviation)

        // 比较触摸-运动相关性（如果有）
        if let correlationStats = baseline.touchMotionCorrelationStats,
           let currentCorrelation = current.touchMotionCorrelation {
            let correlationDeviation = compareMetric(
                name: "touch_motion_correlation",
                current: currentCorrelation,
                stats: correlationStats
            )
            deviations.append(correlationDeviation)
        }

        return deviations
    }

    /// 获取异常偏差
    public func getAnomalies(current: BehaviorSignals, baseline: BehaviorBaseline) -> [BaselineDeviation] {
        return compare(current: current, baseline: baseline)
            .filter { $0.isAnomalous }
    }

    // MARK: - 私有方法

    private func compareMetric(name: String, current: Double, stats: StatisticalFeatures) -> BaselineDeviation {
        guard stats.stdDev > 0 else {
            // 标准差为 0，无法计算 Z-score
            let deviation = stats.mean > 0 ? (current - stats.mean) / stats.mean : 0
            return BaselineDeviation(
                metricName: name,
                currentValue: current,
                baselineMean: stats.mean,
                zScore: 0,
                isAnomalous: false,
                deviationPercent: deviation
            )
        }

        let zScore = abs((current - stats.mean) / stats.stdDev)
        let isAnomalous = zScore > zScoreThreshold
        let deviationPercent = stats.mean > 0 ? (current - stats.mean) / stats.mean : 0

        return BaselineDeviation(
            metricName: name,
            currentValue: current,
            baselineMean: stats.mean,
            zScore: zScore,
            isAnomalous: isAnomalous,
            deviationPercent: deviationPercent
        )
    }
}

// MARK: - 数学辅助函数
private func pow(_ base: Double, _ exp: Double) -> Double {
    return Darwin.pow(base, exp)
}

private func sqrt(_ x: Double) -> Double {
    return Darwin.sqrt(x)
}
