//
//  TemporalAnalyzer.swift
//  CloudPhoneRiskKit
//
//  Created by CloudPhone Risk Team
//  Copyright © 2026 CloudPhone Risk Kit. All rights reserved.
//

import Foundation

// MARK: - Temporal Analyzer Protocol

/// 时序分析器协议
///
/// 负责分析历史事件的时间模式，检测异常行为。
/// 
/// # 功能概述
/// - 分析 24 小时内事件的时间分布
/// - 检测异常的时间模式（如凌晨高频操作）
/// - 计算频率统计指标
/// - 识别序列模式
/// 
/// # 使用示例
/// ```swift
/// let analyzer = DefaultTemporalAnalyzer()
/// let result = await analyzer.analyze(
///     history: events,
///     window: .last24Hours
/// )
/// if result.anomalyScore > threshold {
///     // 检测到异常
/// }
/// ```
public protocol TemporalAnalyzer: Sendable {
    
    /// 分析时间模式
    ///
    /// - Parameters:
    ///   - history: 历史事件列表
    ///   - window: 分析时间窗口
    /// - Returns: 时序分析结果
    func analyze(
        history: [TemporalRiskHistoryEvent],
        window: TimeWindow
    ) async -> TemporalAnalysisResult
    
    /// 检测异常模式
    ///
    /// - Parameters:
    ///   - history: 历史事件列表
    ///   - current: 当前待检测事件
    /// - Returns: 异常检测结果
    func detectAnomaly(
        history: [TemporalRiskHistoryEvent],
        current: TemporalRiskHistoryEvent
    ) async -> TemporalAnomalyDetectionResult
    
    /// 获取基线模式
    ///
    /// 基于历史数据计算正常行为的基线
    ///
    /// - Parameter history: 历史事件列表
    /// - Returns: 基线统计信息
    func calculateBaseline(
        history: [TemporalRiskHistoryEvent]
    ) async -> BaselineStatistics
}

// MARK: - Time Window

/// 时间窗口
///
/// ���义分析的时间范围
public struct TimeWindow: Sendable, Codable {
    
    /// 窗口时长（秒）
    public var duration: TimeInterval
    
    /// 窗口开始时间（可选，默认为当前时间往前推 duration）
    public var startTime: TimeInterval?
    
    /// 窗口结束时间（可选，默认为当前时间）
    public var endTime: TimeInterval?
    
    public init(
        duration: TimeInterval,
        startTime: TimeInterval? = nil,
        endTime: TimeInterval? = nil
    ) {
        self.duration = duration
        self.startTime = startTime
        self.endTime = endTime
    }
    
    /// 预定义时间窗口
    public static let last1Hour = TimeWindow(duration: 3600)
    public static let last6Hours = TimeWindow(duration: 21600)
    public static let last24Hours = TimeWindow(duration: 86400)
    public static let last7Days = TimeWindow(duration: 604800)
    public static let last30Days = TimeWindow(duration: 2592000)
    
    /// 获取窗口的实际起止时间
    public func getActualRange() -> (start: TimeInterval, end: TimeInterval) {
        let end = endTime ?? Date().timeIntervalSince1970
        let start = startTime ?? (end - duration)
        return (start, end)
    }
    
    /// 检查给定时间戳是否在窗口内
    public func contains(_ timestamp: TimeInterval) -> Bool {
        let (start, end) = getActualRange()
        return timestamp >= start && timestamp <= end
    }
}

// MARK: - Temporal Analysis Result

/// 时序分析结果
///
/// 包含时间模式分析的完整结果
public struct TemporalAnalysisResult: Sendable, Codable {
    
    /// 分析窗口
    public var window: TimeWindow
    
    /// 事件数量
    public var eventCount: Int
    
    /// 时间分布统计
    public var timeDistribution: TimeDistribution
    
    /// 频率指标
    public var frequencyMetrics: FrequencyMetrics
    
    /// 序列模式
    public var sequencePatterns: [SequencePattern]
    
    /// 异常分数 (0-100)
    public var anomalyScore: Double
    
    /// 提取的风险信号
    public var riskSignals: [RiskSignal]
    
    /// 分析时间戳
    public var analyzedAt: Date
    
    public init(
        window: TimeWindow,
        eventCount: Int,
        timeDistribution: TimeDistribution,
        frequencyMetrics: FrequencyMetrics,
        sequencePatterns: [SequencePattern],
        anomalyScore: Double,
        riskSignals: [RiskSignal],
        analyzedAt: Date = Date()
    ) {
        self.window = window
        self.eventCount = eventCount
        self.timeDistribution = timeDistribution
        self.frequencyMetrics = frequencyMetrics
        self.sequencePatterns = sequencePatterns
        self.anomalyScore = anomalyScore
        self.riskSignals = riskSignals
        self.analyzedAt = analyzedAt
    }
    
    /// 是否检测到异常
    public var hasAnomaly: Bool {
        return anomalyScore > 0
    }
    
    /// 获取风险摘要
    public var riskSummary: String {
        if anomalyScore >= 80 {
            return "high_temporal_risk"
        } else if anomalyScore >= 50 {
            return "medium_temporal_risk"
        } else if anomalyScore > 0 {
            return "low_temporal_risk"
        } else {
            return "normal_temporal_pattern"
        }
    }
}

// MARK: - Time Distribution

/// 时间分布
///
/// 描述事件在不同时间维度的分布情况
public struct TimeDistribution: Sendable, Codable {
    
    /// 每小时事件计数 (0-23)
    public var hourlyCount: [Int: Int]
    
    /// 每周几天事件计数 (1-7, 1=周日)
    public var weekdayCount: [Int: Int]
    
    /// 凌晨时段 (0-5点) 事件数
    public var nightCount: Int
    
    /// 工作时间 (9-18点) 事件数
    public var workHoursCount: Int
    
    /// 活跃小时数（有事件的小时数）
    public var activeHours: Int
    
    public init(
        hourlyCount: [Int: Int] = [:],
        weekdayCount: [Int: Int] = [:],
        nightCount: Int = 0,
        workHoursCount: Int = 0,
        activeHours: Int = 0
    ) {
        self.hourlyCount = hourlyCount
        self.weekdayCount = weekdayCount
        self.nightCount = nightCount
        self.workHoursCount = workHoursCount
        self.activeHours = activeHours
    }
    
    /// 获取最活跃的小时
    public var mostActiveHour: Int? {
        return hourlyCount.max(by: { $0.value < $1.value })?.key
    }
    
    /// 获取夜间活动比例
    public var nightActivityRatio: Double? {
        let total = hourlyCount.values.reduce(0, +)
        return total > 0 ? Double(nightCount) / Double(total) : nil
    }
    
    /// 是否全时段活跃（24小时内有事件）
    public var isFullDayActive: Bool {
        return activeHours >= 20
    }
}

// MARK: - Frequency Metrics

/// 频率指标
///
/// 描述事件发生的频率特征
public struct FrequencyMetrics: Sendable, Codable {
    
    /// 平均间隔（秒）
    public var averageInterval: Double?
    
    /// 最小间隔（秒）
    public var minInterval: Double?
    
    /// 最大间隔（秒）
    public var maxInterval: Double?
    
    /// 间隔方差
    public var intervalVariance: Double?
    
    /// 间隔标准差
    public var intervalStdDev: Double?
    
    /// 间隔变异系数（CV = std/mean）
    public var intervalCV: Double?
    
    /// 每小时平均事件数
    public var eventsPerHour: Double?
    
    public init(
        averageInterval: Double? = nil,
        minInterval: Double? = nil,
        maxInterval: Double? = nil,
        intervalVariance: Double? = nil,
        intervalStdDev: Double? = nil,
        intervalCV: Double? = nil,
        eventsPerHour: Double? = nil
    ) {
        self.averageInterval = averageInterval
        self.minInterval = minInterval
        self.maxInterval = maxInterval
        self.intervalVariance = intervalVariance
        self.intervalStdDev = intervalStdDev
        self.intervalCV = intervalCV
        self.eventsPerHour = eventsPerHour
    }
    
    /// 间隔是否过于规律（机器特征）
    public var isTooRegular: Bool {
        guard let cv = intervalCV else { return false }
        return cv < 0.2
    }
    
    /// 间隔是否过于混乱（人工特征）
    public var isTooChaotic: Bool {
        guard let cv = intervalCV else { return false }
        return cv > 0.8
    }
    
    /// 是否高频（间隔小于1分钟）
    public var isHighFrequency: Bool {
        guard let avg = averageInterval else { return false }
        return avg < 60
    }
}

// MARK: - Sequence Pattern

/// 序列模式
///
/// 描述事件序列的重复模式
public struct SequencePattern: Sendable, Codable, Identifiable {
    
    /// 模式唯一标识
    public let id: String
    
    /// 模式类型
    public var type: PatternType
    
    /// 模式内容
    public var pattern: [String]
    
    /// 出现次数
    public var frequency: Int
    
    /// 置信度 (0-1)
    public var confidence: Double
    
    /// 首次出现时间
    public var firstSeen: Date
    
    /// 最后出现时间
    public var lastSeen: Date
    
    public enum PatternType: String, Sendable, Codable {
        case periodic = "periodic"           // 周期性
        case fixedInterval = "fixed_interval" // 固定间隔
        case sequential = "sequential"       // 序列性
        case clustered = "clustered"         // 聚集性
    }
    
    public init(
        id: String,
        type: PatternType,
        pattern: [String],
        frequency: Int,
        confidence: Double,
        firstSeen: Date,
        lastSeen: Date
    ) {
        self.id = id
        self.type = type
        self.pattern = pattern
        self.frequency = frequency
        self.confidence = confidence
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }
}

// MARK: - Anomaly Detection Result

/// 异常检测结果
///
/// 描述单个事件是否异常及原因
public struct TemporalAnomalyDetectionResult: Sendable, Codable {
    
    /// 是否异常
    public var isAnomalous: Bool
    
    /// 异常分数 (0-100)
    public var deviation: Double
    
    /// 置信度 (0-1)
    public var confidence: Double
    
    /// 异常原因列表
    public var reasons: [AnomalyReason]
    
    /// 检测时间
    public var detectedAt: Date
    
    public init(
        isAnomalous: Bool,
        deviation: Double,
        confidence: Double,
        reasons: [AnomalyReason],
        detectedAt: Date = Date()
    ) {
        self.isAnomalous = isAnomalous
        self.deviation = deviation
        self.confidence = confidence
        self.reasons = reasons
        self.detectedAt = detectedAt
    }
    
    /// 异常严重程度
    public var severity: TemporalAnomalySeverity {
        switch deviation {
        case 0..<30: return .low
        case 30..<60: return .medium
        case 60..<100: return .high
        default: return .critical
        }
    }
}

/// 异常原因
public struct AnomalyReason: Sendable, Codable, Identifiable {
    
    public let id: String
    public var type: TemporalAnomalyType
    public var description: String
    public var evidence: [String: String]
    
    public init(
        id: String = UUID().uuidString,
        type: TemporalAnomalyType,
        description: String,
        evidence: [String: String] = [:]
    ) {
        self.id = id
        self.type = type
        self.description = description
        self.evidence = evidence
    }
    
    /// 异常类型
    public enum TemporalAnomalyType: String, Sendable, Codable {
        case unusualTime = "unusual_time"           // 异常时间
        case highFrequency = "high_frequency"       // 高频
        case regularPattern = "regular_pattern"     // 过于规律
        case burstActivity = "burst_activity"       // 突发活动
        case nightActivity = "night_activity"       // 夜间活跃
        case fullDayActive = "full_day_active"      // 全天活跃
    }
}

/// 异常严重程度
public enum TemporalAnomalySeverity: Int, Sendable, Codable {
    case low = 0
    case medium = 1
    case high = 2
    case critical = 3
    
    public var displayName: String {
        switch self {
        case .low: return "低"
        case .medium: return "中"
        case .high: return "高"
        case .critical: return "严重"
        }
    }
}

// MARK: - Baseline Statistics

/// 基线统计
///
/// 描述正常行为的统计基线
public struct BaselineStatistics: Sendable, Codable {
    
    /// 平均每日事件数
    public var averageDailyEvents: Double
    
    /// 典型活跃小时
    public var typicalActiveHours: Set<Int>
    
    /// 典型夜间活动比例
    public var typicalNightRatio: Double
    
    /// 典型间隔统计
    public var typicalIntervalStats: IntervalStatistics
    
    /// 计算时间
    public var calculatedAt: Date
    
    /// 数据范围（天数）
    public var dataRangeDays: Int
    
    public init(
        averageDailyEvents: Double,
        typicalActiveHours: Set<Int>,
        typicalNightRatio: Double,
        typicalIntervalStats: IntervalStatistics,
        calculatedAt: Date = Date(),
        dataRangeDays: Int
    ) {
        self.averageDailyEvents = averageDailyEvents
        self.typicalActiveHours = typicalActiveHours
        self.typicalNightRatio = typicalNightRatio
        self.typicalIntervalStats = typicalIntervalStats
        self.calculatedAt = calculatedAt
        self.dataRangeDays = dataRangeDays
    }
}

/// 间隔统计
public struct IntervalStatistics: Sendable, Codable {
    
    /// 平均间隔
    public var mean: Double
    
    /// 标准差
    public var stdDev: Double
    
    /// 中位数
    public var median: Double
    
    /// P25
    public var p25: Double
    
    /// P75
    public var p75: Double
    
    public init(
        mean: Double,
        stdDev: Double,
        median: Double,
        p25: Double,
        p75: Double
    ) {
        self.mean = mean
        self.stdDev = stdDev
        self.median = median
        self.p25 = p25
        self.p75 = p75
    }
}

// MARK: - Temporal Analysis Config

/// 时序分析配置
public struct TemporalAnalysisConfig: Sendable {
    
    /// 异常检测阈值
    public var anomalyThreshold: Double
    
    /// 最小分析事件数
    public var minEventsForAnalysis: Int
    
    /// 夜间时段定义 (小时)
    public var nightHoursRange: ClosedRange<Int>
    
    /// 工作时段定义 (小时)
    public var workHoursRange: ClosedRange<Int>
    
    /// 高频阈值（秒）
    public var highFrequencyThreshold: Double
    
    /// 规律性 CV 阈值
    public var regularityCVThreshold: Double
    
    /// 全天活跃阈值（小时）
    public var fullDayActiveThreshold: Int
    
    public init(
        anomalyThreshold: Double = 2.0,
        minEventsForAnalysis: Int = 10,
        nightHoursRange: ClosedRange<Int> = 0...5,
        workHoursRange: ClosedRange<Int> = 9...18,
        highFrequencyThreshold: Double = 60,
        regularityCVThreshold: Double = 0.2,
        fullDayActiveThreshold: Int = 20
    ) {
        self.anomalyThreshold = anomalyThreshold
        self.minEventsForAnalysis = minEventsForAnalysis
        self.nightHoursRange = nightHoursRange
        self.workHoursRange = workHoursRange
        self.highFrequencyThreshold = highFrequencyThreshold
        self.regularityCVThreshold = regularityCVThreshold
        self.fullDayActiveThreshold = fullDayActiveThreshold
    }
    
    public static let `default` = TemporalAnalysisConfig()
}

// MARK: - Risk History Event (Extended)

/// 风险历史事件（扩展版，支持时序分析）
public struct TemporalRiskHistoryEvent: Sendable, Codable {
    
    /// 时间戳
    public var timestamp: TimeInterval
    
    /// 风险分数
    public var score: Double
    
    /// 是否高风险
    public var isHighRisk: Bool
    
    /// 摘要
    public var summary: String
    
    /// 场景
    public var scenario: RiskScenario?
    
    /// 执行的动作
    public var action: RiskAction?
    
    /// 额外信息
    public var extras: [String: String]
    
    public init(
        timestamp: TimeInterval,
        score: Double,
        isHighRisk: Bool,
        summary: String,
        scenario: RiskScenario? = nil,
        action: RiskAction? = nil,
        extras: [String: String] = [:]
    ) {
        self.timestamp = timestamp
        self.score = score
        self.isHighRisk = isHighRisk
        self.summary = summary
        self.scenario = scenario
        self.action = action
        self.extras = extras
    }
    
    /// 获取日期
    public var date: Date {
        return Date(timeIntervalSince1970: timestamp)
    }
    
    /// 获取小时 (0-23)
    public var hour: Int {
        return Calendar.current.component(.hour, from: date)
    }
    
    /// 获取星期几 (1-7)
    public var weekday: Int {
        return Calendar.current.component(.weekday, from: date)
    }
    
    /// 是否在夜间
    public func isNight(hoursRange: ClosedRange<Int> = 0...5) -> Bool {
        return hoursRange.contains(hour)
    }
    
    /// 是否在工作时间
    public func isWorkHours(hoursRange: ClosedRange<Int> = 9...18) -> Bool {
        return hoursRange.contains(hour)
    }
}

// MARK: - Helper Extensions

extension Array where Element == TemporalRiskHistoryEvent {
    
    /// 按时间排序
    public func sortedByTime() -> [TemporalRiskHistoryEvent] {
        return sorted { $0.timestamp < $1.timestamp }
    }
    
    /// 筛选时间窗口内的事件
    public func filtered(by window: TimeWindow) -> [TemporalRiskHistoryEvent] {
        return filter { window.contains($0.timestamp) }
    }
    
    /// 计算事件间隔
    public func calculateIntervals() -> [Double] {
        let sorted = sortedByTime()
        guard sorted.count > 1 else { return [] }
        
        var intervals: [Double] = []
        for i in 1..<sorted.count {
            intervals.append(sorted[i].timestamp - sorted[i-1].timestamp)
        }
        return intervals
    }
    
    /// 计算平均间隔
    public func averageInterval() -> Double? {
        let intervals = calculateIntervals()
        return intervals.isEmpty ? nil : (intervals.reduce(0, +) / Double(intervals.count))
    }
}
