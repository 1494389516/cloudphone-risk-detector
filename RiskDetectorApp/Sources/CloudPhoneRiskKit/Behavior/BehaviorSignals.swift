import Foundation

public struct BehaviorSignals: Codable, Sendable {
    public var touch: TouchMetrics
    public var motion: MotionMetrics
    public var touchMotionCorrelation: Double?
    public var actionCount: Int

    private enum CodingKeys: String, CodingKey {
        case touch = "t"
        case motion = "m"
        case touchMotionCorrelation = "tc"
        case actionCount = "ac"
    }

    init(touch: TouchMetrics, motion: MotionMetrics, touchMotionCorrelation: Double? = nil, actionCount: Int? = nil) {
        self.touch = touch
        self.motion = motion
        self.touchMotionCorrelation = touchMotionCorrelation
        self.actionCount = actionCount ?? (touch.tapCount + touch.swipeCount)
    }

    // MARK: - 样本充足性

    /// 行为信号统计可靠的最小触摸样本量
    public static let minimumTouchSamples = 15
    /// 行为信号统计可靠的最小动作数（tap + swipe）
    public static let minimumActionCount = 8
    /// 传感器耦合分析的最小运动样本量
    public static let minimumMotionSamples = 40

    /// 触摸样本是否达到统计可靠的最小阈值
    public var hasSufficientTouchSamples: Bool {
        touch.sampleCount >= Self.minimumTouchSamples && actionCount >= Self.minimumActionCount
    }

    /// 运动样本是否达到统计可靠的最小阈值
    public var hasSufficientMotionSamples: Bool {
        motion.sampleCount >= Self.minimumMotionSamples
    }

    /// 样本充足性等级，用于评分引擎判断行为信号的置信度
    public enum SampleSufficiency: Sendable {
        /// 样本充足，分析结果可信
        case sufficient
        /// 样本不足，分析结果应降权或忽略
        case insufficient
        /// 无有效样本
        case none
    }

    /// 当前行为数据的样本充足性
    public var sampleSufficiency: SampleSufficiency {
        if touch.sampleCount == 0 && motion.sampleCount == 0 { return .none }
        if hasSufficientTouchSamples { return .sufficient }
        return .insufficient
    }
}

public struct TouchMetrics: Codable, Sendable {
    public var sampleCount: Int
    public var tapCount: Int
    public var swipeCount: Int
    public var coordinateSpread: Double?
    public var intervalCV: Double?
    public var averageLinearity: Double?
    public var forceVariance: Double?
    public var majorRadiusVariance: Double?
    public var swipeSpeedCV: Double?

    private enum CodingKeys: String, CodingKey {
        case sampleCount = "sc"
        case tapCount = "tp"
        case swipeCount = "sw"
        case coordinateSpread = "cs"
        case intervalCV = "cv"
        case averageLinearity = "al"
        case forceVariance = "fv"
        case majorRadiusVariance = "mr"
        case swipeSpeedCV = "ss"
    }
}

public struct MotionMetrics: Codable, Sendable {
    public var sampleCount: Int
    public var stillnessRatio: Double?
    public var motionEnergy: Double?

    private enum CodingKeys: String, CodingKey {
        case sampleCount = "sc"
        case stillnessRatio = "sr"
        case motionEnergy = "me"
    }

    public static let empty = MotionMetrics(sampleCount: 0, stillnessRatio: nil, motionEnergy: nil)
}
