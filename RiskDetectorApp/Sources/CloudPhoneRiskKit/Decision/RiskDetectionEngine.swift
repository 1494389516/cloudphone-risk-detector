import Foundation

// MARK: - 风险检测引擎
/// 智能风控决策引擎，支持场景化检测、动态权重和组合规则
///
/// ## 核心设计原则
/// 1. **场景化**: 不同业务场景使用不同的风险阈值和权重
/// 2. **可配置**: 所有阈值、权重、规则都可通过 Policy 配置
/// 3. **可扩展**: 支持自定义信号提供者和决策树
/// 4. **向后兼容**: 与现有 RiskScorer API 保持兼容
///
/// ## 使用示例
/// ```swift
/// let engine = RiskDetectionEngine(policy: .payment)
/// let verdict = engine.evaluate(context: riskContext, scenario: .payment)
///
/// switch verdict.action {
/// case .allow: print("允许交易")
/// case .challenge: print("需要验证码")
/// case .stepUpAuth: print("需要短信验证")
/// case .block: print("拒绝交易")
/// }
/// ```
public struct RiskDetectionEngine: Sendable {

    // MARK: - 属性

    /// 引擎策略配置
    public let policy: EnginePolicy

    /// 是否启用日志
    public let enableLogging: Bool

    /// 自定义信号提供者
    private let customProviders: [String: @Sendable (RiskContext) -> [RiskSignal]]

    // MARK: - 初始化

    public init(
        policy: EnginePolicy = .default,
        enableLogging: Bool = true,
        customProviders: [String: @Sendable (RiskContext) -> [RiskSignal]] = [:]
    ) {
        self.policy = policy
        self.enableLogging = enableLogging
        self.customProviders = customProviders
    }

    // MARK: - 核心评估方法

    /// 评估风险并返回判决结果
    /// - Parameters:
    ///   - context: 风险上下文，包含所有检测信号
    ///   - scenario: 检测场景
    ///   - extraSignals: 额外的风险信号（可选）
    /// - Returns: 风险判决结果
    public func evaluate(
        context: RiskContext,
        scenario: RiskScenario = .default,
        extraSignals: [RiskSignal] = []
    ) -> RiskVerdict {
        log("=== RiskDetectionEngine evaluation started ===")
        log("Scenario: \(scenario.rawValue)")
        log("Policy: \(policy.name)")

        // 1. 获取场景策略
        let scenarioPolicy = policy.scenarioPolicy(for: scenario)
        log("Scenario policy - medium: \(scenarioPolicy.mediumThreshold), high: \(scenarioPolicy.highThreshold), critical: \(scenarioPolicy.criticalThreshold)")

        // 2. 收集所有风险信号
        var allSignals = collectSignals(
            context: context,
            scenarioPolicy: scenarioPolicy,
            extraSignals: extraSignals
        )
        log("Collected \(allSignals.count) signals")

        // 3. 应用组合规则
        let comboBonus = applyComboRules(
            signals: allSignals,
            comboRules: scenarioPolicy.comboRules
        )
        if comboBonus > 0 {
            log("Combo rules bonus: +\(comboBonus)")
        }

        // 4. 计算基础分数
        let baseScore = calculateBaseScore(
            signals: allSignals,
            weights: scenarioPolicy.signalWeights
        )
        log("Base score: \(baseScore)")

        // 5. 应用组合规则加成
        let finalScore = min(baseScore + comboBonus, 100)
        log("Final score: \(finalScore)")

        // 6. 应用强制规则
        let (adjustedScore, forcedAction) = applyForceRules(
            score: finalScore,
            context: context,
            scenarioPolicy: scenarioPolicy
        )
        if forcedAction != nil {
            log("Force rule applied, action: \(forcedAction!.rawValue)")
        }

        // 7. 使用决策树确定最终动作
        let evaluationContext = EvaluationContext(
            score: adjustedScore,
            signals: allSignals,
            scenario: scenario,
            riskContext: context,
            policy: scenarioPolicy
        )

        let decisionTree = DecisionTree.tree(for: scenario)
        let treeAction = decisionTree.decide(context: evaluationContext)
        log("Decision tree action: \(treeAction.rawValue)")

        // 8. 强制动作优先级高于决策树
        let finalAction = forcedAction ?? treeAction

        // 9. 创建判决结果
        let verdict = RiskVerdict(
            score: adjustedScore,
            internalLevel: InternalRiskLevel.from(score: adjustedScore),
            internalAction: finalAction,
            confidence: calculateConfidence(
                context: context,
                signals: allSignals,
                score: adjustedScore
            ),
            primaryReasons: extractPrimaryReasons(signals: allSignals),
            signals: allSignals,
            scenario: scenario
        )

        log("=== Evaluation complete ===")
        log("Verdict - level: \(verdict.level.rawValue), action: \(verdict.action.rawValue), confidence: \(verdict.confidence)")

        return verdict
    }

    // MARK: - 信号收集

    /// 收集所有风险信号
    private func collectSignals(
        context: RiskContext,
        scenarioPolicy: ScenarioPolicy,
        extraSignals: [RiskSignal]
    ) -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // 1. 越狱信号
        if context.jailbreak.confidence > 0 {
            let jbScore = context.jailbreak.confidence
            signals.append(
                RiskSignal(
                    id: "jailbreak",
                    category: "jailbreak",
                    score: jbScore,
                    evidence: [
                        "is_jailbroken": "\(context.jailbreak.isJailbroken)",
                        "confidence": "\(jbScore)",
                        "methods": context.jailbreak.detectedMethods.joined(separator: ",")
                    ]
                )
            )
        }

        // 2. 网络信号
        if policy.enableNetworkSignals {
            if context.network.isVPNActive {
                signals.append(
                    RiskSignal(
                        id: "vpn_active",
                        category: "network",
                        score: 10,
                        evidence: ["type": "VPN"]
                    )
                )
            }
            if context.network.proxyEnabled {
                signals.append(
                    RiskSignal(
                        id: "proxy_enabled",
                        category: "network",
                        score: 8,
                        evidence: ["type": "Proxy"]
                    )
                )
            }
        }

        // 3. 行为信号
        if policy.enableBehaviorDetection {
            let behaviorSignals = extractBehaviorSignals(behavior: context.behavior)
            signals.append(contentsOf: behaviorSignals)
        }

        // 4. 设备信号
        let deviceSignals = extractDeviceSignals(
            device: context.device,
            jailbreak: context.jailbreak
        )
        signals.append(contentsOf: deviceSignals)

        // 5. 自定义提供者信号
        for (_, provider) in customProviders {
            signals.append(contentsOf: provider(context))
        }

        // 6. 额外信号
        signals.append(contentsOf: extraSignals)

        return signals
    }

    /// 提取行为信号
    private func extractBehaviorSignals(behavior: BehaviorSignals) -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // 触摸坐标分散度异常
        if let spread = behavior.touch.coordinateSpread, behavior.touch.tapCount >= 6 {
            if spread < 2.0 {
                signals.append(
                    RiskSignal(
                        id: "touch_spread_low",
                        category: "behavior",
                        score: 12,
                        evidence: ["spread": "\(spread)"]
                    )
                )
            } else if spread > 10.0 {
                signals.append(
                    RiskSignal(
                        id: "touch_spread_high",
                        category: "behavior",
                        score: 4,
                        evidence: ["spread": "\(spread)"]
                    )
                )
            }
        }

        // 触摸间隔规律性异常
        if let cv = behavior.touch.intervalCV, behavior.touch.tapCount >= 6 {
            if cv < 0.2 {
                signals.append(
                    RiskSignal(
                        id: "touch_interval_too_regular",
                        category: "behavior",
                        score: 10,
                        evidence: ["cv": "\(cv)"]
                    )
                )
            } else if cv > 0.6 {
                signals.append(
                    RiskSignal(
                        id: "touch_interval_too_chaotic",
                        category: "behavior",
                        score: 4,
                        evidence: ["cv": "\(cv)"]
                    )
                )
            }
        }

        // 滑动线性度异常
        if let lin = behavior.touch.averageLinearity, behavior.touch.swipeCount >= 3 {
            if lin > 0.98 {
                signals.append(
                    RiskSignal(
                        id: "swipe_too_linear",
                        category: "behavior",
                        score: 8,
                        evidence: ["linearity": "\(lin)"]
                    )
                )
            } else if lin < 0.90 {
                signals.append(
                    RiskSignal(
                        id: "swipe_too_curvy",
                        category: "behavior",
                        score: 4,
                        evidence: ["linearity": "\(lin)"]
                    )
                )
            }
        }

        // 设备静止度过高
        if let still = behavior.motion.stillnessRatio,
           still > 0.98,
           (behavior.touch.tapCount + behavior.touch.swipeCount) >= 10 {
            signals.append(
                RiskSignal(
                    id: "motion_too_still",
                    category: "behavior",
                    score: 10,
                    evidence: ["stillness": "\(still)"]
                )
            )
        }

        // 触摸与运动弱耦合
        if let corr = behavior.touchMotionCorrelation,
           corr < 0.10,
           behavior.actionCount >= 10,
           (behavior.motion.stillnessRatio ?? 0) > 0.95 {
            signals.append(
                RiskSignal(
                    id: "touch_motion_weak_coupling",
                    category: "behavior",
                    score: 8,
                    evidence: ["correlation": "\(corr)"]
                )
            )
        }

        return signals
    }

    /// 提取设备信号
    private func extractDeviceSignals(
        device: DeviceFingerprint,
        jailbreak: DetectionResult
    ) -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // 设备年龄过短（可能是新设备或虚拟机）
        // 当前 DeviceFingerprint 不包含 deviceAgeDays 字段，跳过该项。

        // 设备名称可疑（如包含模拟器关键词）
        let suspiciousNames = ["simulator", "emulator", "x86", "arm64"]
        let deviceName = device.model.lowercased()
        if suspiciousNames.contains(where: { deviceName.contains($0) }) {
            signals.append(
                RiskSignal(
                    id: "suspicious_device_name",
                    category: "device",
                    score: 15,
                    evidence: ["name": device.model]
                )
            )
        }

        // 越狱设备加分
        if jailbreak.isJailbroken {
            signals.append(
                RiskSignal(
                    id: "jailbreak_device",
                    category: "device",
                    score: 20,
                    evidence: ["methods": jailbreak.detectedMethods.joined(separator: ",")]
                )
            )
        }

        return signals
    }

    // MARK: - 分数计算

    /// 计算基础风险分数（应用权重）
    private func calculateBaseScore(
        signals: [RiskSignal],
        weights: SignalWeights
    ) -> Double {
        var total: Double = 0

        for signal in signals {
            let weight = weights.weight(for: signal.category)
            total += signal.score * weight
        }

        return min(total, 100)
    }

    /// 应用组合规则
    private func applyComboRules(
        signals: [RiskSignal],
        comboRules: [ComboRule]
    ) -> Double {
        var bonus: Double = 0

        for rule in comboRules {
            if rule.matches(signals: signals) {
                log("Combo rule matched: \(rule.name), bonus: +\(rule.bonusScore)")
                bonus += rule.bonusScore
            }
        }

        return bonus
    }

    /// 应用强制规则
    private func applyForceRules(
        score: Double,
        context: RiskContext,
        scenarioPolicy: ScenarioPolicy
    ) -> (Double, RiskAction?) {
        var adjustedScore = score
        var forcedAction: RiskAction? = nil

        guard scenarioPolicy.enableForceRules else {
            return (adjustedScore, forcedAction)
        }

        // 越狱设备强制规则
        if context.jailbreak.isJailbroken {
            if policy.forceActionOnJailbreak != nil {
                forcedAction = policy.forceActionOnJailbreak
            }
            // 确保分数不低于高阈值
            adjustedScore = max(adjustedScore, scenarioPolicy.highThreshold)
        }

        return (adjustedScore, forcedAction)
    }

    // MARK: - 置信度计算

    /// 计算决策置信度
    private func calculateConfidence(
        context: RiskContext,
        signals: [RiskSignal],
        score: Double
    ) -> Double {
        var confidence = 0.3 // 基础置信度

        // 信号数量越多，置信度越高
        let signalCount = signals.count
        confidence += min(Double(signalCount) * 0.05, 0.3)

        // 高分信号增加置信度
        let highScoreSignals = signals.filter { $0.score >= 10 }.count
        confidence += min(Double(highScoreSignals) * 0.1, 0.2)

        // 越狱检测命中显著提高置信度
        if context.jailbreak.isJailbroken {
            confidence += 0.2
        }

        // 行为数据充足提高置信度
        if context.behavior.actionCount >= 10 {
            confidence += 0.1
        }

        return min(confidence, 1.0)
    }

    /// 提取主要原因
    private func extractPrimaryReasons(signals: [RiskSignal]) -> [String] {
        signals
            .sorted { $0.score > $1.score }
            .prefix(5)
            .map { signal in
                var reason = signal.category
                if !signal.id.isEmpty && signal.id != signal.category {
                    reason += "_" + signal.id
                }
                return reason
            }
    }

    // MARK: - 日志辅助

    private func log(_ message: String) {
        if enableLogging {
            Logger.log("[RiskDetectionEngine] \(message)")
        }
    }
}

// MARK: - 引擎策略配置
/// 决策引擎的全局策略配置
public struct EnginePolicy: Codable, Sendable {

    // MARK: - 全局开关

    /// 是否启用网络信号检测
    public let enableNetworkSignals: Bool

    /// 是否启用行为检测
    public let enableBehaviorDetection: Bool

    /// 是否启用设备指纹检测
    public let enableDeviceFingerprint: Bool

    // MARK: - 强制规则

    /// 越狱设备的强制动作（nil表示不强制）
    public let forceActionOnJailbreak: RiskAction?

    // MARK: - 场景策略

    /// 各场景的默认策略映射
    public let scenarioPolicies: [RiskScenario: ScenarioPolicy]

    // MARK: - 元数据

    /// 策略名称
    public let name: String

    /// 策略版本
    public let version: String

    // MARK: - 初始化

    public init(
        name: String = "default",
        version: String = "1.0.0",
        enableNetworkSignals: Bool = true,
        enableBehaviorDetection: Bool = true,
        enableDeviceFingerprint: Bool = true,
        forceActionOnJailbreak: RiskAction? = nil,
        scenarioPolicies: [RiskScenario: ScenarioPolicy] = [:]
    ) {
        self.name = name
        self.version = version
        self.enableNetworkSignals = enableNetworkSignals
        self.enableBehaviorDetection = enableBehaviorDetection
        self.enableDeviceFingerprint = enableDeviceFingerprint
        self.forceActionOnJailbreak = forceActionOnJailbreak
        self.scenarioPolicies = scenarioPolicies
    }

    /// 获取指定场景的策略
    public func scenarioPolicy(for scenario: RiskScenario) -> ScenarioPolicy {
        scenarioPolicies[scenario] ?? .policy(for: scenario)
    }

    // MARK: - 预设策略

    /// 默认策略
    public static let `default` = EnginePolicy(
        name: "default",
        version: "1.0.0"
    )

    /// 严格策略
    public static let strict = EnginePolicy(
        name: "strict",
        version: "1.0.0",
        enableNetworkSignals: true,
        enableBehaviorDetection: true,
        enableDeviceFingerprint: true,
        forceActionOnJailbreak: .block
    )

    /// 宽松策略
    public static let lenient = EnginePolicy(
        name: "lenient",
        version: "1.0.0",
        enableNetworkSignals: true,
        enableBehaviorDetection: false,
        enableDeviceFingerprint: false,
        forceActionOnJailbreak: nil
    )

    /// 金融级策略（最高安全）
    public static let financial = EnginePolicy(
        name: "financial",
        version: "1.0.0",
        enableNetworkSignals: true,
        enableBehaviorDetection: true,
        enableDeviceFingerprint: true,
        forceActionOnJailbreak: .block,
        scenarioPolicies: [
            .payment: .payment,
            .login: .login,
            .register: .register,
            .accountChange: .accountChange,
            .sensitiveAction: .sensitiveAction
        ]
    )
}

// MARK: - 向后兼容扩展
extension RiskDetectionEngine {

    /// 兼容旧版 RiskScorer 接口
    /// 使用默认场景和策略评估风险
    func score(
        context: RiskContext,
        config: RiskConfig,
        extraSignals: [RiskSignal] = []
    ) -> RiskScoreReport {
        // 将 RiskConfig 转换为 EnginePolicy
        let policy = EnginePolicy(
            enableNetworkSignals: config.enableNetworkSignals,
            enableBehaviorDetection: config.enableBehaviorDetect,
            enableDeviceFingerprint: true,
            forceActionOnJailbreak: context.jailbreak.isJailbroken ? .block : nil
        )

        let engine = RiskDetectionEngine(policy: policy)
        let verdict = engine.evaluate(
            context: context,
            scenario: .default,
            extraSignals: extraSignals
        )

        return RiskScoreReport(
            score: verdict.score,
            isHighRisk: verdict.isHighRisk,
            signals: verdict.signals,
            summary: verdict.summary
        )
    }
}

extension RiskVerdict {
    /// 旧版兼容字段
    public var legacySummary: String {
        if action == .block {
            return "blocked(\(level.rawValue))"
        } else if action == .challenge {
            return "challenged(\(level.rawValue))"
        } else {
            return "allowed(\(level.rawValue))"
        }
    }
}
