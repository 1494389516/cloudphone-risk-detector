import Foundation

/// 反篡改检测信号提供者
///
/// 将 AntiTamperingDetector、DebuggerDetector、FridaDetector、CodeSignatureValidator、MemoryIntegrityChecker
/// 的检测结果转换为 RiskSignal，供 RiskDetectionEngine 使用
///
/// ## 架构说明
/// - 遵循职责分离原则：检测器专注检测，SignalProvider 负责信号转换
/// - 实现 RiskSignalProvider 协议，可插拔到 RiskDetectionEngine
/// - 支持动态配置启用/禁用特定检测器
public final class AntiTamperingSignalProvider: RiskSignalProvider {
    
    // MARK: - RiskSignalProvider
    
    public let id = "anti_tampering"
    
    /// 配置选项
    public struct Configuration: Sendable {
        /// 是否启用反调试检测
        var enableAntiTampering: Bool = true
        
        /// 是否启用调试器检测
        var enableDebugger: Bool = true
        
        /// 是否启用 Frida 检测
        var enableFrida: Bool = true
        
        /// 是否启用代码签名验证
        var enableCodeSignature: Bool = true
        
        /// 是否启用内存完整性检查
        var enableMemoryIntegrity: Bool = true
        
        /// 最低风险分数阈值（低于此分数的信号不会上报）
        var minScoreThreshold: Double = 0
        
        public static let `default` = Configuration()
    }
    
    private let configuration: Configuration
    
    // MARK: - 初始化
    
    public init(configuration: Configuration = .default) {
        self.configuration = configuration
    }
    
    /// 便捷初始化（使用默认配置）
    public convenience init() {
        self.init(configuration: .default)
    }
    
    // MARK: - RiskSignalProvider 实现
    
    public func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        // 越狱检测结果作为基础
        let baseJailbreakScore = snapshot.jailbreak.confidence
        
        // 1. 反调试检测
        if configuration.enableAntiTampering {
            let antiTamperSignals = detectAntiTampering(baseScore: baseJailbreakScore)
            signals.append(contentsOf: antiTamperSignals)
        }
        
        // 2. 调试器检测
        if configuration.enableDebugger {
            let debuggerSignals = detectDebugger(baseScore: baseJailbreakScore)
            signals.append(contentsOf: debuggerSignals)
        }
        
        // 3. Frida 检测
        if configuration.enableFrida {
            let fridaSignals = detectFrida(baseScore: baseJailbreakScore)
            signals.append(contentsOf: fridaSignals)
        }
        
        // 4. 代码签名验证
        if configuration.enableCodeSignature {
            let signatureSignals = detectCodeSignatureIssues(baseScore: baseJailbreakScore)
            signals.append(contentsOf: signatureSignals)
        }
        
        // 5. 内存完整性检查
        if configuration.enableMemoryIntegrity {
            let memorySignals = detectMemoryIntegrityIssues(baseScore: baseJailbreakScore)
            signals.append(contentsOf: memorySignals)
        }
        
        // 过滤低分信号
        return signals.filter { $0.score >= configuration.minScoreThreshold }
    }
    
    // MARK: - 检测方法
    
    /// 反调试检测
    private func detectAntiTampering(baseScore: Double) -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        let result = AntiTamperingDetector().detect()
        
        if result.score > 0 {
            // 基础反调试信号
            signals.append(
                RiskSignal(
                    id: "anti_tampering",
                    category: "anti_tamper",
                    score: result.score,
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": "AntiTamperingDetector"
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 85
                )
            )
            
            // 分解具体方法为独立信号
            for method in result.methods {
                let signalID = method.replacingOccurrences(of: ":", with: "_")
                let methodScore = extractScore(from: method)
                
                signals.append(
                    RiskSignal(
                        id: signalID,
                        category: "anti_tamper",
                        score: methodScore,
                        evidence: ["method": method]
                    )
                )
            }
        }
        
        return signals
    }
    
    /// 调试器检测
    private func detectDebugger(baseScore: Double) -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        let result = DebuggerDetector().detect()
        
        if result.score > 0 {
            signals.append(
                RiskSignal(
                    id: "debugger_detected",
                    category: "debugger",
                    score: result.score,
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": "DebuggerDetector"
                    ],
                    state: .soft(confidence: 0.7),
                    layer: 2,
                    weightHint: 50
                )
            )
            
            // 分解具体调试器类型
            for method in result.methods {
                if method.hasPrefix("debugger:parent:") {
                    let debuggerName = method.replacingOccurrences(of: "debugger:parent:", with: "")
                    signals.append(
                        RiskSignal(
                            id: "debugger_parent_\(debuggerName)",
                            category: "debugger",
                            score: 25,
                            evidence: ["parent_process": debuggerName]
                        )
                    )
                }
                
                if method.hasPrefix("debugger:port:") {
                    let port = method.replacingOccurrences(of: "debugger:port:", with: "")
                    signals.append(
                        RiskSignal(
                            id: "debugger_port_\(port)",
                            category: "debugger",
                            score: 15,
                            evidence: ["listening_port": port]
                        )
                    )
                }
            }
        }
        
        return signals
    }
    
    /// Frida 检测
    private func detectFrida(baseScore: Double) -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        let result = FridaDetector().detect()
        
        if result.score > 0 {
            // Frida 是高风险信号，给予额外权重
            let fridaScore = result.score * 1.2  // 20% 加权
            
            signals.append(
                RiskSignal(
                    id: "frida_detected",
                    category: "anti_tamper",
                    score: min(fridaScore, 100),  // 最高 100 分
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": "FridaDetector",
                        "severity": "high"
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 85
                )
            )
            
            // 分解具体检测维度
            let fridaCategories = [
                ("frida:dylib:", "frida_library", 35),
                ("frida:port:", "frida_port", 30),
                ("frida:file:", "frida_file", 20),
                ("frida:symbol:", "frida_symbol", 20),
                ("frida:thread:", "frida_thread", 20),
                ("frida:process:", "frida_process", 30),
                ("frida:env:", "frida_environment", 25)
            ]
            
            for method in result.methods {
                for (prefix, signalID, baseScore) in fridaCategories {
                    if method.hasPrefix(prefix) {
                        let detail = method.replacingOccurrences(of: prefix, with: "")
                        signals.append(
                            RiskSignal(
                                id: "\(signalID)_\(detail.replacingOccurrences(of: ":", with: "_"))",
                                category: "anti_tamper",
                                score: Double(baseScore),
                                evidence: ["detection_method": method]
                            )
                        )
                    }
                }
            }
        }
        
        return signals
    }
    
    /// 代码签名验证
    private func detectCodeSignatureIssues(baseScore: Double) -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        let result = CodeSignatureValidator().detect()
        
        if result.score > 0 {
            signals.append(
                RiskSignal(
                    id: "code_signature_invalid",
                    category: "integrity",
                    score: result.score,
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": "CodeSignatureValidator"
                    ],
                    state: .soft(confidence: 0.8),
                    layer: 2,
                    weightHint: 60
                )
            )
            
            // 分解具体签名问题
            for method in result.methods {
                if method.contains("invalid") {
                    signals.append(
                        RiskSignal(
                            id: "signature_invalid",
                            category: "integrity",
                            score: 40,
                            evidence: ["issue": "signature_validation_failed"]
                        )
                    )
                }
                
                if method.contains("resigned") {
                    signals.append(
                        RiskSignal(
                            id: "signature_resigned",
                            category: "integrity",
                            score: 30,
                            evidence: ["issue": "application_resigned"]
                        )
                    )
                }
                
                if method.contains("permissions") {
                    signals.append(
                        RiskSignal(
                            id: "signature_abnormal_permissions",
                            category: "integrity",
                            score: 25,
                            evidence: ["issue": "abnormal_segment_permissions"]
                        )
                    )
                }
            }
        }
        
        return signals
    }
    
    /// 内存完整性检查
    private func detectMemoryIntegrityIssues(baseScore: Double) -> [RiskSignal] {
        var signals: [RiskSignal] = []
        
        let result = MemoryIntegrityChecker().detect()
        
        if result.score > 0 {
            signals.append(
                RiskSignal(
                    id: "memory_integrity_violated",
                    category: "integrity",
                    score: result.score,
                    evidence: [
                        "methods": result.methods.joined(separator: ","),
                        "detector": "MemoryIntegrityChecker"
                    ],
                    state: .tampered,
                    layer: 2,
                    weightHint: 75
                )
            )
            
            // 分解具体内存问题
            for method in result.methods {
                if method.hasPrefix("memory_hook:") {
                    let functionName = method.replacingOccurrences(of: "memory_hook:", with: "")
                    signals.append(
                        RiskSignal(
                            id: "hook_\(functionName)",
                            category: "integrity",
                            score: 20,
                            evidence: ["hooked_function": functionName]
                        )
                    )
                }
                
                if method.hasPrefix("memory_swizzle:") {
                    let className = method.replacingOccurrences(of: "memory_swizzle:objc:", with: "")
                    signals.append(
                        RiskSignal(
                            id: "swizzle_\(className.replacingOccurrences(of: ".", with: "_"))",
                            category: "integrity",
                            score: 22,
                            evidence: ["swizzled_class": className]
                        )
                    )
                }
                
                if method.hasPrefix("memory_inline:") {
                    let functionName = method.replacingOccurrences(of: "memory_inline:", with: "")
                    signals.append(
                        RiskSignal(
                            id: "inline_hook_\(functionName)",
                            category: "integrity",
                            score: 25,
                            evidence: ["inline_hooked": functionName]
                        )
                    )
                }
            }
        }
        
        return signals
    }
    
    // MARK: - 辅助方法
    
    /// 从方法字符串中提取分数
    private func extractScore(from method: String) -> Double {
        // 方法格式通常为 "category:method" 或 "category:method:(+score)"
        // 这里返回默认分数，实际应用中可以从配置中获取
        switch method {
        case let m where m.contains("p_traced"):
            return 30
        case let m where m.contains("parent"):
            return 25
        case let m where m.contains("timing"):
            return 20
        case let m where m.contains("exception_port"):
            return 25
        case let m where m.contains("frida"):
            return 35
        case let m where m.contains("signature"):
            return 30
        case let m where m.contains("hook"):
            return 20
        default:
            return 15
        }
    }
}

// MARK: - 便捷扩展

extension AntiTamperingSignalProvider {
    
    /// 创建高敏感度配置（严格检测）
    public static func strictConfiguration() -> Configuration {
        var config = Configuration()
        config.enableAntiTampering = true
        config.enableDebugger = true
        config.enableFrida = true
        config.enableCodeSignature = true
        config.enableMemoryIntegrity = true
        config.minScoreThreshold = 0  // 不过滤任何信号
        return config
    }
    
    /// 创建性能优先配置（只检测关键项）
    public static func performanceConfiguration() -> Configuration {
        var config = Configuration()
        config.enableAntiTampering = true
        config.enableDebugger = true
        config.enableFrida = true
        config.enableCodeSignature = false  // 跳过较慢的签名验证
        config.enableMemoryIntegrity = false  // 跳过较慢的内存检查
        config.minScoreThreshold = 15  // 过滤低分信号
        return config
    }
}

// MARK: - JailbreakEngine 集成

/// JailbreakConfig 扩展，支持反篡改检测
extension JailbreakConfig {
    
    /// 创建包含反篡改检测的配置
    public static func withAntiTampering(
        threshold: Double = 30,
        enableAntiTampering: Bool = true,
        enableDebugger: Bool = true,
        enableFrida: Bool = true
    ) -> JailbreakConfig {
        var config = JailbreakConfig(
            enableFileDetect: true,
            enableDyldDetect: true,
            enableEnvDetect: true,
            enableSysctlDetect: true,
            enableSchemeDetect: true,
            enableHookDetect: true,
            threshold: threshold
        )
        
        // 存储反篡改配置（通过 extras 或关联对象）
        // 这里简化处理，实际使用时可以通过配置系统传递
        
        return config
    }
}
