import Foundation

// MARK: - 检测器注册中心协议
/// 将 DetectorRegistry 的核心 API 抽象为协议，便于单元测试中注入 Mock 实现。
///
/// 典型用法（测试中）：
/// ```swift
/// class MockDetectorRegistry: DetectorRegistering {
///     var stubbedResult: DetectorResult = .empty
///     func detect(type: DetectorRegistry.DetectorType) -> DetectorResult { stubbedResult }
///     ...
/// }
/// ```
public protocol DetectorRegistering: AnyObject {
    /// 执行指定类型的检测
    func detect(type: DetectorRegistry.DetectorType) -> DetectorResult

    /// 执行指定分组的所有检测
    func detect(group: DetectorRegistry.DetectorGroup) -> GroupDetectionResult

    /// 执行所有启用的检测
    func detectAll(enabledTypes: Set<DetectorRegistry.DetectorType>) -> ComprehensiveDetectionResult

    /// 注册自定义检测器
    func register(type: DetectorRegistry.DetectorType, factory: @escaping DetectorRegistry.DetectorFactory)

    /// 注销检测器
    func unregister(type: DetectorRegistry.DetectorType)

    /// 封印注册表
    func seal()

    /// 注册表是否已封印
    var isSealed: Bool { get }

    /// 创建检测器实例
    func createDetector(type: DetectorRegistry.DetectorType) -> Detector?

    /// 获取检测器元数据
    func manifest(for type: DetectorRegistry.DetectorType) -> DetectorRegistry.DetectorManifest

    /// 检测器在当前 iOS 版本是否可用
    func isAvailable(_ type: DetectorRegistry.DetectorType, osVersion: Double) -> Bool
}

// MARK: - DetectorRegistry 默认遵循协议
extension DetectorRegistry: DetectorRegistering {}
