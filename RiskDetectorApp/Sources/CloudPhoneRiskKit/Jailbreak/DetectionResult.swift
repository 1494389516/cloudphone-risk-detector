import Foundation

// MARK: - 最终检测结果
/// 整个检测流程完成后返回的结果
public struct DetectionResult: Sendable {

    /// 是否判定为越狱设备
    /// true = 越狱, false = 正常
    public let isJailbroken: Bool

    /// 置信度分数 (0-100)
    /// 分数越高，越狱可能性越大
    /// 例如: 80 表示 80% 置信度认为是越狱设备
    public let confidence: Double

    /// 命中的检测方法列表
    /// 例如: ["file:/Applications/Cydia.app", "dylib:FridaGadget"]
    public let detectedMethods: [String]

    /// 详细信息（可用于日志/调试）
    public let details: String
}

// MARK: - 单个检测器的结果
/// 每个检测模块（如 FileDetector）返回的结果
public struct DetectorResult: Sendable {

    /// 该检测模块的得分
    /// 不同检测项有不同权重，命中后累加
    public let score: Double

    /// 该模块命中的检测方法
    public let methods: [String]

    /// 创建一个空结果（未检测到任何异常）
    public static var empty: DetectorResult {
        return DetectorResult(score: 0, methods: [])
    }
}
