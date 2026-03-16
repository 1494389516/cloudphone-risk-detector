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

    private enum CodingKeys: String, CodingKey {
        case sampleCount = "sc"
        case tapCount = "tp"
        case swipeCount = "sw"
        case coordinateSpread = "cs"
        case intervalCV = "cv"
        case averageLinearity = "al"
        case forceVariance = "fv"
        case majorRadiusVariance = "mr"
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
