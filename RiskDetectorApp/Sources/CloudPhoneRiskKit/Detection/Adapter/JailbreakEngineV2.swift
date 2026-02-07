import Foundation

/// JailbreakEngine V2 - 集成新架构检测器
///
/// 这个适配器将新的反篡改检测器集成到现有的 JailbreakEngine 中，
/// 保持向后兼容的同时增强检测能力。
///
/// ## 设计原则
/// 1. **向后兼容**: 保持现有 API 不变
/// 2. **渐进增强**: 通过配置启用新检测器
/// 3. **职责分离**: 检测器专注检测，引擎负责编排
/// 4. **可观测性**: 详细的日志输出
public final class JailbreakEngineV2 {
    
    // MARK: - 配置
    
    /// V2 扩展配置
    public struct V2Config {
        /// 是否启用反篡改检测
        var enableAntiTampering: Bool = true
        
        /// 是否启用调试器检测
        var enableDebugger: Bool = true
        
        /// 是否启用 Frida 检测
        var enableFrida: Bool = true
        
        /// 是否启用代码签名验证
        var enableCodeSignature: Bool = true
        
        /// 是否启用内存完整性检查
        var enableMemoryIntegrity: Bool = true
        
        /// 检测器超时时间（毫秒）
        var detectionTimeout: Int = 5000
        
        /// 是否启用详细日志
        var verboseLogging: Bool = false
        
        public static let `default` = V2Config()
        
        /// 严格配置（所有检测启用）
        public static let strict = V2Config(
            enableAntiTampering: true,
            enableDebugger: true,
            enableFrida: true,
            enableCodeSignature: true,
            enableMemoryIntegrity: true,
            verboseLogging: true
        )
        
        /// 性能优先配置（跳过耗时检测）
        public static let performance = V2Config(
            enableAntiTampering: true,
            enableDebugger: true,
            enableFrida: true,
            enableCodeSignature: false,
            enableMemoryIntegrity: false,
            verboseLogging: false
        )
    }
    
    // MARK: - 属性
    
    private let legacyEngine: JailbreakEngine
    private let v2Config: V2Config
    
    // MARK: - 初始化
    
    public init(v2Config: V2Config = .default) {
        self.v2Config = v2Config
        self.legacyEngine = JailbreakEngine()
    }
    
    // MARK: - 公开 API
    
    /// 执行检测（V2 增强版）
    /// - Parameter config: 检测配置
    /// - Returns: 检测结果
    public func detect(config: JailbreakConfig) -> DetectionResult {
        Logger.log("JailbreakEngineV2: start detection")
        
#if targetEnvironment(simulator)
        return handleSimulator(config: config)
#else
        // 1. 执行原有检测
        let legacyResult = legacyEngine.detect(config: config)
        var score = legacyResult.confidence
        var methods = legacyResult.detectedMethods
        
        Logger.log("JailbreakEngineV2: legacy score=\(score), methods=\(methods.count)")
        
        // 2. 执行 V2 新增检测
        let v2Result = detectV2(baseScore: score)
        score += v2Result.score
        methods.append(contentsOf: v2Result.methods)
        
        // 3. 去重并排序
        methods = Array(Set(methods)).sorted()
        
        let finalScore = min(score, 100)
        let isJailbroken = finalScore >= config.threshold
        
        Logger.log("JailbreakEngineV2: final score=\(finalScore), isJailbroken=\(isJailbroken), methods=\(methods.count)")
        
        return DetectionResult(
            isJailbroken: isJailbroken,
            confidence: finalScore,
            detectedMethods: methods,
            details: buildDetails(
                score: finalScore,
                methods: methods,
                legacyScore: legacyResult.confidence,
                v2Score: v2Result.score
            )
        )
#endif
    }
    
    /// 快速检测（仅执行关键检测）
    /// - Returns: 简化的检测结果
    public func quickDetect() -> QuickDetectionResult {
        Logger.log("JailbreakEngineV2: quick detect")
        
#if targetEnvironment(simulator)
        return QuickDetectionResult(
            isRisky: false,
            riskLevel: .none,
            detectedCategories: []
        )
#else
        var detectedCategories: [String] = []
        var totalScore: Double = 0
        
        // 只执行快速检测项
        let quickDetectors: [(String, Detector)] = [
            ("anti_tamper", AntiTamperingDetector()),
            ("debugger", DebuggerDetector()),
            ("frida", FridaDetector())
        ]
        
        for (category, detector) in quickDetectors {
            let result = detector.detect()
            if result.score > 0 {
                detectedCategories.append(category)
                totalScore += result.score
            }
        }
        
        let riskLevel = QuickDetectionResult.RiskLevel.from(score: totalScore)
        
        return QuickDetectionResult(
            isRisky: !detectedCategories.isEmpty,
            riskLevel: riskLevel,
            detectedCategories: detectedCategories
        )
#endif
    }
    
    /// 获取检测器状态
    /// - Returns: 检测器状态信息
    public func detectorStatus() -> DetectorStatus {
        var status = DetectorStatus()
        
        // 检查各检测器状态
        status.antiTampering = v2Config.enableAntiTampering
        status.debugger = v2Config.enableDebugger
        status.frida = v2Config.enableFrida
        status.codeSignature = v2Config.enableCodeSignature
        status.memoryIntegrity = v2Config.enableMemoryIntegrity
        
        return status
    }
    
    // MARK: - 私有方法
    
#if !targetEnvironment(simulator)
    
    /// 执行 V2 新增检测
    private func detectV2(baseScore: Double) -> V2DetectionResult {
        var score: Double = 0
        var methods: [String] = []
        
        // 1. 反调试检测
        if v2Config.enableAntiTampering {
            let result = AntiTamperingDetector().detect()
            score += result.score
            methods.append(contentsOf: result.methods)
            logV2("AntiTamperingDetector", result.score, result.methods.count)
        }
        
        // 2. 调试器检测
        if v2Config.enableDebugger {
            let result = DebuggerDetector().detect()
            score += result.score
            methods.append(contentsOf: result.methods)
            logV2("DebuggerDetector", result.score, result.methods.count)
        }
        
        // 3. Frida 检测
        if v2Config.enableFrida {
            let result = FridaDetector().detect()
            score += result.score
            methods.append(contentsOf: result.methods)
            logV2("FridaDetector", result.score, result.methods.count)
        }
        
        // 4. 代码签名验证
        if v2Config.enableCodeSignature {
            let result = CodeSignatureValidator().detect()
            score += result.score
            methods.append(contentsOf: result.methods)
            logV2("CodeSignatureValidator", result.score, result.methods.count)
        }
        
        // 5. 内存完整性检查
        if v2Config.enableMemoryIntegrity {
            let result = MemoryIntegrityChecker().detect()
            score += result.score
            methods.append(contentsOf: result.methods)
            logV2("MemoryIntegrityChecker", result.score, result.methods.count)
        }
        
        return V2DetectionResult(score: score, methods: methods)
    }
    
#endif
    
    /// 处理模拟器环境
    private func handleSimulator(config: JailbreakConfig) -> DetectionResult {
        let simulate = ProcessInfo.processInfo.environment["CPRISK_SIMULATE_JAILBREAK"] == "1"
        
        if simulate {
            return DetectionResult(
                isJailbroken: true,
                confidence: 100,
                detectedMethods: ["simulated:simulator"],
                details: "simulated_jailbreak"
            )
        }
        
        return DetectionResult(
            isJailbroken: false,
            confidence: 0,
            detectedMethods: ["unavailable_simulator"],
            details: "simulator_environment"
        )
    }
    
    /// 构建详情字符串
    private func buildDetails(
        score: Double,
        methods: [String],
        legacyScore: Double,
        v2Score: Double
    ) -> String {
        """
        total_score=\(score)
        legacy_score=\(legacyScore)
        v2_score=\(v2Score)
        methods_hit=\(methods.count)
        methods=\(methods.prefix(20).joined(separator: ","))
        """
    }
    
    /// V2 日志输出
    private func logV2(_ detector: String, _ score: Double, _ count: Int) {
        if v2Config.verboseLogging {
            Logger.log("JailbreakEngineV2.\(detector): score=\(score), hits=\(count)")
        }
    }
}

// MARK: - 结果类型

/// V2 检测结果
private struct V2DetectionResult {
    let score: Double
    let methods: [String]
}

/// 快速检测结果
public struct QuickDetectionResult {
    /// 是否存在风险
    public let isRisky: Bool
    
    /// 风险等级
    public let riskLevel: RiskLevel
    
    /// 检测到的风险类别
    public let detectedCategories: [String]
    
    /// 风险等级
    public enum RiskLevel {
        case none
        case low
        case medium
        case high
        
        public static func from(score: Double) -> RiskLevel {
            switch score {
            case 0..<10: return .none
            case 10..<30: return .low
            case 30..<60: return .medium
            default: return .high
            }
        }
    }
}

/// 检测器状态
public struct DetectorStatus {
    public var antiTampering: Bool = false
    public var debugger: Bool = false
    public var frida: Bool = false
    public var codeSignature: Bool = false
    public var memoryIntegrity: Bool = false
    
    /// 启用的检测器数量
    public var enabledCount: Int {
        var count = 0
        if antiTampering { count += 1 }
        if debugger { count += 1 }
        if frida { count += 1 }
        if codeSignature { count += 1 }
        if memoryIntegrity { count += 1 }
        return count
    }
    
    /// 是否启用了所有检测器
    public var isFullyEnabled: Bool {
        antiTampering && debugger && frida && codeSignature && memoryIntegrity
    }
}

// MARK: - 向后兼容扩展

extension JailbreakConfig {
    
    /// 创建 V2 配置
    public static func v2(
        threshold: Double = 30,
        v2Config: JailbreakEngineV2.V2Config = .default
    ) -> (JailbreakConfig, JailbreakEngineV2.V2Config) {
        let jailbreakConfig = JailbreakConfig(
            enableFileDetect: true,
            enableDyldDetect: true,
            enableEnvDetect: true,
            enableSysctlDetect: true,
            enableSchemeDetect: true,
            enableHookDetect: true,
            threshold: threshold
        )
        
        return (jailbreakConfig, v2Config)
    }
}

// MARK: - 使用示例

/*
 ## 使用示例
 
 ### 1. 基本使用（向后兼容）
 ```swift
 let engine = JailbreakEngineV2()
 let result = engine.detect(config: .default)
 if result.isJailbroken {
     // 处理越狱设备
 }
 ```
 
 ### 2. 使用 V2 配置
 ```swift
 let v2Config = JailbreakEngineV2.V2Config.strict
 let engine = JailbreakEngineV2(v2Config: v2Config)
 let result = engine.detect(config: .default)
 ```
 
 ### 3. 快速检测
 ```swift
 let engine = JailbreakEngineV2()
 let quickResult = engine.quickDetect()
 if quickResult.isRisky {
     // 处理风险设备
 }
 ```
 
 ### 4. 检查检测器状态
 ```swift
 let engine = JailbreakEngineV2()
 let status = engine.detectorStatus()
 print("启用了 \(status.enabledCount) 个检测器")
 ```
 */
