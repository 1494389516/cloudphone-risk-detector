import Foundation

// MARK: - 异常类型
/// 检测到的异常类型
public enum AnomalyType: String, Codable, Sendable {
    /// 统计异常（基于 Z-score 或 IQR）
    case statistical

    /// 行为异常（与历史基线偏离）
    case behavioral

    /// 时间异常（异常的检测时间）
    case temporal

    /// 设备状态突变（如突然越狱）
    case stateChange
}

// MARK: - 异常严重程度
public enum AnomalySeverity: String, Codable, Sendable {
    case low
    case medium
    case high
    case critical
}

// MARK: - 异常检测结果
public struct AnomalyDetectionResult: Codable, Sendable {
    /// 是否检测到异常
    public var isAnomalous: Bool

    /// 异常类型
    public var type: AnomalyType

    /// 严重程度
    public var severity: AnomalySeverity

    /// 异常分数（0-1，越高越异常）
    public var anomalyScore: Double

    /// 异常描述
    public var description: String

    /// 异常相关的字段/指标
    public var affectedMetrics: [String]

    /// 检测方法
    public var detectionMethod: String

    public init(
        isAnomalous: Bool,
        type: AnomalyType,
        severity: AnomalySeverity,
        anomalyScore: Double,
        description: String,
        affectedMetrics: [String],
        detectionMethod: String
    ) {
        self.isAnomalous = isAnomalous
        self.type = type
        self.severity = severity
        self.anomalyScore = anomalyScore
        self.description = description
        self.affectedMetrics = affectedMetrics
        self.detectionMethod = detectionMethod
    }
}

// MARK: - Z-score 异常检测结果
public struct ZScoreResult: Sendable {
    /// Z-score 值
    public var zScore: Double

    /// 是否异常
    public var isAnomalous: Bool

    /// 异常阈值
    public var threshold: Double

    public init(zScore: Double, isAnomalous: Bool, threshold: Double) {
        self.zScore = zScore
        self.isAnomalous = isAnomalous
        self.threshold = threshold
    }
}

// MARK: - IQR 异常检测结果
public struct IQRResult: Sendable {
    /// 下界
    public var lowerBound: Double

    /// 上界
    public var upperBound: Double

    /// 是否低于下界
    public var isBelowLowerBound: Bool

    /// 是否高于上界
    public var isAboveUpperBound: Bool

    /// 是否异常
    public var isAnomalous: Bool

    public init(lowerBound: Double, upperBound: Double, isBelowLowerBound: Bool, isAboveUpperBound: Bool, isAnomalous: Bool) {
        self.lowerBound = lowerBound
        self.upperBound = upperBound
        self.isBelowLowerBound = isBelowLowerBound
        self.isAboveUpperBound = isAboveUpperBound
        self.isAnomalous = isAnomalous
    }
}

// MARK: - 异常检测器
/// 提供多种异常检测算法
public final class AnomalyDetector {
    private let history: DeviceHistory

    public init(history: DeviceHistory = .shared) {
        self.history = history
    }

    // MARK: - Z-score 异常检测

    /// 使用 Z-score 检测单个值是否异常
    /// - Parameters:
    ///   - value: 待检测的值
    ///   - samples: 历史样本数据
    ///   - threshold: Z-score 阈值，默认 3.0（即 3σ 原则）
    /// - Returns: Z-score 检测结果
    public func detectZScore(value: Double, samples: [Double], threshold: Double = 3.0) -> ZScoreResult {
        guard samples.count >= 3 else {
            // 样本数量不足，无法判断
            return ZScoreResult(zScore: 0, isAnomalous: false, threshold: threshold)
        }

        let mean = samples.reduce(0, +) / Double(samples.count)
        let variance = samples.map { pow($0 - mean, 2) }.reduce(0, +) / Double(samples.count)
        let stdDev = sqrt(variance)

        guard stdDev > 0 else {
            // 所有样本值相同，无法判断
            return ZScoreResult(zScore: 0, isAnomalous: false, threshold: threshold)
        }

        let zScore = abs((value - mean) / stdDev)
        let isAnomalous = zScore > threshold

        return ZScoreResult(zScore: zScore, isAnomalous: isAnomalous, threshold: threshold)
    }

    /// 使用 Z-score 检测风险分数是否异常
    public func detectRiskScoreAnomaly(deviceID: String, currentScore: Double, threshold: Double = 3.0) -> ZScoreResult {
        let snapshots = history.getSnapshots(for: deviceID)
        let historicalScores = snapshots.map { $0.riskScore }

        return detectZScore(value: currentScore, samples: historicalScores, threshold: threshold)
    }

    // MARK: - IQR 异常检测

    /// 使用四分位距（IQR）检测异常值
    /// - Parameters:
    ///   - value: 待检测的值
    ///   - samples: 历史样本数据
    ///   - multiplier: IQR 倍数，默认 1.5（箱线图标准）
    /// - Returns: IQR 检测结果
    public func detectIQR(value: Double, samples: [Double], multiplier: Double = 1.5) -> IQRResult {
        guard samples.count >= 4 else {
            // 样本数量不足，至少需要 4 个值才能计算四分位数
            return IQRResult(lowerBound: 0, upperBound: 0, isBelowLowerBound: false, isAboveUpperBound: false, isAnomalous: false)
        }

        let sorted = samples.sorted()
        let count = sorted.count

        // 计算四分位数
        let q1Index = count / 4
        let q2Index = count / 2
        let q3Index = (3 * count) / 4

        let q1 = sorted[q1Index]
        let q3 = sorted[min(q3Index, count - 1)]
        let iqr = q3 - q1

        guard iqr > 0 else {
            return IQRResult(lowerBound: q1, upperBound: q3, isBelowLowerBound: false, isAboveUpperBound: false, isAnomalous: false)
        }

        let lowerBound = q1 - multiplier * iqr
        let upperBound = q3 + multiplier * iqr

        let isBelowLowerBound = value < lowerBound
        let isAboveUpperBound = value > upperBound
        let isAnomalous = isBelowLowerBound || isAboveUpperBound

        return IQRResult(lowerBound: lowerBound, upperBound: upperBound, isBelowLowerBound: isBelowLowerBound, isAboveUpperBound: isAboveUpperBound, isAnomalous: isAnomalous)
    }

    /// 使用 IQR 检测风险分数是否异常
    public func detectRiskScoreAnomalyIQR(deviceID: String, currentScore: Double, multiplier: Double = 1.5) -> IQRResult {
        let snapshots = history.getSnapshots(for: deviceID)
        let historicalScores = snapshots.map { $0.riskScore }

        return detectIQR(value: currentScore, samples: historicalScores, multiplier: multiplier)
    }

    // MARK: - 行为基线异常检测

    /// 检测当前行为是否偏离历史基线
    public func detectBehaviorAnomaly(current: BehaviorSignals, deviceID: String) -> AnomalyDetectionResult? {
        let snapshots = history.getSnapshots(for: deviceID)

        guard snapshots.count >= 5 else {
            // 历史数据不足
            return nil
        }

        let historicalSummaries = snapshots.compactMap { $0.behaviorSummary }
        guard historicalSummaries.count >= 5 else {
            return nil
        }

        // 提取历史行为特征
        let actionCounts = historicalSummaries.map { Double($0.actionCount) }
        let tapSwipeRatios = historicalSummaries.map { summary -> Double in
            guard summary.tapCount + summary.swipeCount > 0 else { return 0.5 }
            return Double(summary.tapCount) / Double(summary.tapCount + summary.swipeCount)
        }

        // 检测当前行为
        let currentActionCount = Double(current.actionCount)
        let currentTapSwipeRatio: Double
        if current.touch.tapCount + current.touch.swipeCount > 0 {
            currentTapSwipeRatio = Double(current.touch.tapCount) / Double(current.touch.tapCount + current.touch.swipeCount)
        } else {
            currentTapSwipeRatio = 0.5
        }

        // Z-score 检测
        let actionCountZ = detectZScore(value: currentActionCount, samples: actionCounts, threshold: 2.5)
        let tapSwipeRatioZ = detectZScore(value: currentTapSwipeRatio, samples: tapSwipeRatios, threshold: 2.5)

        var anomalies: [String] = []
        var scores: [Double] = []

        if actionCountZ.isAnomalous {
            anomalies.append("action_count")
            scores.append(min(actionCountZ.zScore / 3.0, 1.0))
        }

        if tapSwipeRatioZ.isAnomalous {
            anomalies.append("tap_swipe_ratio")
            scores.append(min(tapSwipeRatioZ.zScore / 3.0, 1.0))
        }

        guard !anomalies.isEmpty else {
            return nil
        }

        // 计算综合异常分数
        let avgScore = scores.reduce(0, +) / Double(scores.count)

        // 确定严重程度
        let severity: AnomalySeverity
        switch avgScore {
        case 0..<0.3:
            severity = .low
        case 0.3..<0.6:
            severity = .medium
        case 0.6..<0.9:
            severity = .high
        default:
            severity = .critical
        }

        return AnomalyDetectionResult(
            isAnomalous: true,
            type: .behavioral,
            severity: severity,
            anomalyScore: avgScore,
            description: "行为特征偏离历史基线：\(anomalies.joined(separator: ", "))",
            affectedMetrics: anomalies,
            detectionMethod: "z_score_baseline"
        )
    }

    // MARK: - 设备状态突变检测

    /// 检测设备状态是否发生突变（如突然越狱）
    public func detectStateChangeAnomaly(currentSnapshot: DeviceDetectionSnapshot, deviceID: String) -> AnomalyDetectionResult? {
        let snapshots = history.getSnapshots(for: deviceID)

        guard !snapshots.isEmpty else {
            return nil
        }

        let recentSnapshots = Array(snapshots.suffix(10))
        let previousJailbroken = recentSnapshots.filter { $0.jailbreakStatus.isJailbroken }
        let currentJailbroken = currentSnapshot.jailbreakStatus.isJailbroken

        // 检测突然越狱
        if currentJailbroken && previousJailbroken.isEmpty {
            return AnomalyDetectionResult(
                isAnomalous: true,
                type: .stateChange,
                severity: .critical,
                anomalyScore: 1.0,
                description: "设备首次检测到越狱状态",
                affectedMetrics: ["jailbreak_status"],
                detectionMethod: "first_jailbreak_detection"
            )
        }

        // 检测越狱状态消失（可能为反检测对抗）
        if !currentJailbroken && !previousJailbroken.isEmpty {
            let recentJailbreakRatio = Double(previousJailbroken.count) / Double(recentSnapshots.count)
            if recentJailbreakRatio > 0.5 {
                // 之前 50% 以上检测都是越狱，现在正常，可疑
                return AnomalyDetectionResult(
                    isAnomalous: true,
                    type: .stateChange,
                    severity: .high,
                    anomalyScore: 0.8,
                    description: "越狱状态突然消失（可能存在反检测对抗）",
                    affectedMetrics: ["jailbreak_status"],
                    detectionMethod: "jailbreak_disappearance"
                )
            }
        }

        // 检测 VPN 突然出现
        if currentSnapshot.isVPNActive {
            let previousVPN = recentSnapshots.filter { $0.isVPNActive }
            if previousVPN.isEmpty {
                return AnomalyDetectionResult(
                    isAnomalous: true,
                    type: .stateChange,
                    severity: .medium,
                    anomalyScore: 0.6,
                    description: "首次检测到 VPN 连接",
                    affectedMetrics: ["vpn_status"],
                    detectionMethod: "first_vpn_detection"
                )
            }
        }

        return nil
    }

    // MARK: - 综合异常检测

    /// 执行全面的异常检测
    public func detectAnomalies(deviceID: String, currentSnapshot: DeviceDetectionSnapshot, currentBehavior: BehaviorSignals? = nil) -> [AnomalyDetectionResult] {
        var results: [AnomalyDetectionResult] = []

        // 1. 风险分数异常检测（Z-score）
        let riskScoreZ = detectRiskScoreAnomaly(deviceID: deviceID, currentScore: currentSnapshot.riskScore, threshold: 2.5)
        if riskScoreZ.isAnomalous {
            let severity: AnomalySeverity
            switch riskScoreZ.zScore {
            case 0..<3.0:
                severity = .low
            case 3.0..<4.0:
                severity = .medium
            case 4.0..<5.0:
                severity = .high
            default:
                severity = .critical
            }

            results.append(AnomalyDetectionResult(
                isAnomalous: true,
                type: .statistical,
                severity: severity,
                anomalyScore: min(riskScoreZ.zScore / 5.0, 1.0),
                description: "风险分数异常：Z-score = \(String(format: "%.2f", riskScoreZ.zScore))",
                affectedMetrics: ["risk_score"],
                detectionMethod: "z_score"
            ))
        }

        // 2. 风险分数异常检测（IQR）
        let riskScoreIQR = detectRiskScoreAnomalyIQR(deviceID: deviceID, currentScore: currentSnapshot.riskScore)
        if riskScoreIQR.isAnomalous {
            let severity: AnomalySeverity
            let score: Double
            if riskScoreIQR.isAboveUpperBound {
                score = 0.8
                severity = .high
            } else {
                score = 0.5
                severity = .medium
            }

            // 避免重复添加
            if !results.contains(where: { $0.detectionMethod == "iqr" }) {
                results.append(AnomalyDetectionResult(
                    isAnomalous: true,
                    type: .statistical,
                    severity: severity,
                    anomalyScore: score,
                    description: "风险分数超出四分位距范围",
                    affectedMetrics: ["risk_score"],
                    detectionMethod: "iqr"
                ))
            }
        }

        // 3. 状态突变检测
        if let stateChange = detectStateChangeAnomaly(currentSnapshot: currentSnapshot, deviceID: deviceID) {
            results.append(stateChange)
        }

        // 4. 行为异常检测
        if let behavior = currentBehavior {
            if let behaviorAnomaly = detectBehaviorAnomaly(current: behavior, deviceID: deviceID) {
                results.append(behaviorAnomaly)
            }
        }

        return results
    }
}

// MARK: - 数学辅助函数
private func pow(_ base: Double, _ exp: Double) -> Double {
    return Darwin.pow(base, exp)
}

private func sqrt(_ x: Double) -> Double {
    return Darwin.sqrt(x)
}
