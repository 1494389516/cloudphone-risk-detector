import Foundation

// MARK: - 检测器协议
/// 所有检测模块必须实现此协议
/// 这是"面向协议编程"的体现
protocol Detector {

    /// 执行检测
    /// - Returns: 检测结果（分数 + 命中方法）
    func detect() -> DetectorResult
}

/*
 为什么用协议？

 1. 统一接口：所有检测器都有 detect() 方法
 2. 易于扩展：添加新检测器只需实现协议
 3. 可测试：可以 mock 实现进行单元测试

 使用示例：
    let detector: Detector = FileDetector()
    let result = detector.detect()
 */
