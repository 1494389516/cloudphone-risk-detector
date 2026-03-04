import Foundation

/// 分级上报时机策略
public struct UploadPolicy: Codable, Sendable {

    // MARK: - Risk Level

    /// 风险等级
    public enum RiskLevel: String, Codable, Sendable {
        /// 高危：立即上报
        case high
        /// 中危：延迟上报
        case medium
        /// 低危：批量上报
        case low
    }

    // MARK: - Policy Config

    /// 上报策略配置
    public struct PolicyConfig: Codable, Sendable {
        /// 高危上报延迟范围（秒），默认 0-2 秒
        public let highRiskDelayRange: ClosedRange<Double>
        /// 中危上报延迟范围（秒），默认 30-120 秒
        public let mediumRiskDelayRange: ClosedRange<Double>
        /// 低危批量上报间隔（秒），默认 300 秒（5 分钟）
        public let lowRiskBatchInterval: Double
        /// 随机抖动比例，默认 0.2（20%）
        public let jitterRatio: Double

        /// 默认配置
        public static let `default` = PolicyConfig(
            highRiskDelayRange: 0...2,
            mediumRiskDelayRange: 30...120,
            lowRiskBatchInterval: 300,
            jitterRatio: 0.2
        )

        public init(
            highRiskDelayRange: ClosedRange<Double> = 0...2,
            mediumRiskDelayRange: ClosedRange<Double> = 30...120,
            lowRiskBatchInterval: Double = 300,
            jitterRatio: Double = 0.2
        ) {
            self.highRiskDelayRange = highRiskDelayRange
            self.mediumRiskDelayRange = mediumRiskDelayRange
            self.lowRiskBatchInterval = lowRiskBatchInterval
            self.jitterRatio = jitterRatio
        }
    }

    // MARK: - Properties

    /// 风险评分阈值配置
    private let highRiskThreshold: Int    // 默认 80
    private let mediumRiskThreshold: Int  // 默认 50

    /// 当前策略配置
    public let config: PolicyConfig

    // MARK: - Initialization

    /// 使用默认配置初始化
    public init(
        highRiskThreshold: Int = 80,
        mediumRiskThreshold: Int = 50,
        config: PolicyConfig = .default
    ) {
        self.highRiskThreshold = highRiskThreshold
        self.mediumRiskThreshold = mediumRiskThreshold
        self.config = config
    }

    // MARK: - Public Methods

    /// 根据评分计算风险等级
    /// - Parameter score: 风险评分 (0-100)
    /// - Returns: 对应的风险等级
    public func riskLevel(for score: Int) -> RiskLevel {
        if score >= highRiskThreshold {
            return .high
        } else if score >= mediumRiskThreshold {
            return .medium
        } else {
            return .low
        }
    }

    /// 计算实际延迟（包含随机抖动）
    /// - Parameter score: 风险评分 (0-100)
    /// - Returns: 延迟秒数
    public func calculateDelay(for score: Int) -> Double {
        let level = riskLevel(for: score)

        let baseDelay: Double
        switch level {
        case .high:
            baseDelay = Double.random(in: config.highRiskDelayRange)
        case .medium:
            baseDelay = Double.random(in: config.mediumRiskDelayRange)
        case .low:
            baseDelay = config.lowRiskBatchInterval
        }

        // 添加随机抖动
        let jitter = baseDelay * config.jitterRatio * Double.random(in: -1...1)
        return max(0, baseDelay + jitter)
    }

    /// 判断是否应该立即上报
    /// - Parameter score: 风险评分 (0-100)
    /// - Returns: 是否应该立即上报
    public func shouldImmediateUpload(score: Int) -> Bool {
        return riskLevel(for: score) == .high
    }

    /// 判断是否应该批量上报
    /// - Parameter score: 风险评分 (0-100)
    /// - Returns: 是否应该批量上报
    public func shouldBatch(score: Int) -> Bool {
        return riskLevel(for: score) == .low
    }

    /// 获取下次批量上报的剩余时间
    /// - Parameter lastBatchTime: 上次批量上报的时间戳
    /// - Returns: 剩余秒数，如果应该立即上报则返回 0
    public func nextBatchDelay(since lastBatchTime: TimeInterval) -> Double {
        let elapsed = Date().timeIntervalSince1970 - lastBatchTime
        let remaining = config.lowRiskBatchInterval - elapsed
        return max(0, remaining)
    }
}

// MARK: - Convenience Factory

extension UploadPolicy {

    /// 严格模式配置（更敏感的上报策略）
    public static let strict = UploadPolicy(
        highRiskThreshold: 70,
        mediumRiskThreshold: 40,
        config: PolicyConfig(
            highRiskDelayRange: 0...1,
            mediumRiskDelayRange: 15...60,
            lowRiskBatchInterval: 180,
            jitterRatio: 0.1
        )
    )

    /// 宽松模式配置（较少干扰的上报策略）
    public static let lenient = UploadPolicy(
        highRiskThreshold: 90,
        mediumRiskThreshold: 60,
        config: PolicyConfig(
            highRiskDelayRange: 0...5,
            mediumRiskDelayRange: 60...300,
            lowRiskBatchInterval: 600,
            jitterRatio: 0.3
        )
    )
}
