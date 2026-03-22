import Foundation

// MARK: - 场景策略配置
/// 定义特定场景下的风控策略：阈值、动作、权重等
public struct ScenarioPolicy: Codable, Sendable {

    public let mediumThreshold: Double
    public let highThreshold: Double
    public let criticalThreshold: Double
    public let actionMapping: [InternalRiskLevel: RiskAction]
    public let signalWeights: SignalWeights
    public let comboRules: [ComboRule]
    public let enableForceRules: Bool
    public let compressedVerdictRules: [CompressedVerdictRule]

    private enum CodingKeys: String, CodingKey {
        case mediumThreshold = "mt"
        case highThreshold = "ht"
        case criticalThreshold = "ct"
        case actionMapping = "am"
        case signalWeights = "sw"
        case comboRules = "cr"
        case enableForceRules = "ef"
        case compressedVerdictRules = "cv"
    }

    // MARK: - 初始化

    public init(
        mediumThreshold: Double = 30,
        highThreshold: Double = 55,
        criticalThreshold: Double = 80,
        actionMapping: [InternalRiskLevel: RiskAction]? = nil,
        signalWeights: SignalWeights = .default,
        comboRules: [ComboRule] = [],
        enableForceRules: Bool = true,
        compressedVerdictRules: [CompressedVerdictRule] = []
    ) {
        self.mediumThreshold = mediumThreshold
        self.highThreshold = highThreshold
        self.criticalThreshold = criticalThreshold
        self.actionMapping = actionMapping ?? Self.defaultActionMapping()
        self.signalWeights = signalWeights
        self.comboRules = comboRules
        self.enableForceRules = enableForceRules
        self.compressedVerdictRules = compressedVerdictRules
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        var m = try container.decodeIfPresent(Double.self, forKey: .mediumThreshold) ?? 30
        var h = try container.decodeIfPresent(Double.self, forKey: .highThreshold) ?? 55
        var c = try container.decodeIfPresent(Double.self, forKey: .criticalThreshold) ?? 80
        if !m.isFinite || !h.isFinite || !c.isFinite || !(0 <= m && m < h && h < c && c <= 100) {
            m = 30; h = 55; c = 80
        }
        mediumThreshold = m
        highThreshold = h
        criticalThreshold = c
        actionMapping = try container.decodeIfPresent([InternalRiskLevel: RiskAction].self, forKey: .actionMapping) ?? Self.defaultActionMapping()
        signalWeights = try container.decodeIfPresent(SignalWeights.self, forKey: .signalWeights) ?? .default
        comboRules = try container.decodeIfPresent([ComboRule].self, forKey: .comboRules) ?? []
        enableForceRules = try container.decodeIfPresent(Bool.self, forKey: .enableForceRules) ?? true
        compressedVerdictRules = try container.decodeIfPresent([CompressedVerdictRule].self, forKey: .compressedVerdictRules) ?? []
    }

    // MARK: - 便捷方法

    /// 根据分数和策略阈值计算风险等级
    public func level(for score: Double) -> InternalRiskLevel {
        guard score.isFinite, score >= 0 else { return .low }
        switch score {
        case ..<mediumThreshold: return .low
        case mediumThreshold..<highThreshold: return .medium
        case highThreshold..<criticalThreshold: return .high
        default: return .critical
        }
    }

    /// 根据风险等级获取建议动作
    public func action(for level: InternalRiskLevel) -> RiskAction {
        actionMapping[level] ?? Self.defaultAction(for: level)
    }

    /// 默认动作映射
    private static func defaultActionMapping() -> [InternalRiskLevel: RiskAction] {
        [
            .low: .allow,
            .medium: .allow,
            .high: .challenge,
            .critical: .block
        ]
    }

    /// 默认动作逻辑（备用）
    private static func defaultAction(for level: InternalRiskLevel) -> RiskAction {
        switch level {
        case .low, .medium:
            return .allow
        case .high:
            return .challenge
        case .critical:
            return .block
        }
    }

    // MARK: - 预设策略

    /// SDK 5.2 Impossible States：录屏+充电static+USB音频+无蜂窝+未录入生物识别 -> 强制 block
    private static let impossibleStatesRule = ComboRule(
        name: "impossible_states_cloudphone",
        requiredSignals: [
            "screen_captured",
            "battery_state_static",
            "usb_audio_routed",
            "no_cellular_provider",
            "biometric_not_enrolled",
        ],
        bonusScore: 100,
        forceAction: .block,
        description: "录屏+充电态静态+USB音频+无蜂窝+未录入生物识别 -> 云手机不可能状态"
    )

    /// 通用策略（默认）
    public static let general = ScenarioPolicy(
        mediumThreshold: 30,
        highThreshold: 55,
        criticalThreshold: 80,
        comboRules: [impossibleStatesRule]
    )

    /// 登录策略：相对宽松，允许一定风险但需要监控
    public static let login = ScenarioPolicy(
        mediumThreshold: 35,
        highThreshold: 60,
        criticalThreshold: 85,
        signalWeights: .init(
            jailbreak: 0.5,      // 登录场景对越狱容忍度稍高
            network: 1.0,
            behavior: 1.2,        // 重视行为异常
            device: 1.0,
            time: 1.0
        ),
        comboRules: [impossibleStatesRule]
    )

    /// 注册策略：严格，防止批量注册
    public static let register = ScenarioPolicy(
        mediumThreshold: 25,
        highThreshold: 50,
        criticalThreshold: 75,
        actionMapping: [
            .low: .allow,
            .medium: .challenge,  // 中风险即挑战
            .high: .stepUpAuth,
            .critical: .block
        ],
        signalWeights: .init(
            jailbreak: 0.7,       // 注册对越狱更敏感
            network: 1.2,         // 关注网络环境
            behavior: 0.8,        // 注册时行为数据少
            device: 1.3,          // 重视设备指纹
            time: 1.1
        ),
        comboRules: [
            .init(
                name: "vm_register",
                requiredSignals: ["vm_detected", "suspicious_time"],
                bonusScore: 30
            ),
            impossibleStatesRule,
        ]
    )

    /// 支付策略：最严格，任何高风险都应拦截
    public static let payment = ScenarioPolicy(
        mediumThreshold: 20,
        highThreshold: 45,
        criticalThreshold: 70,
        actionMapping: [
            .low: .allow,
            .medium: .stepUpAuth,  // 中风险也要升级认证
            .high: .block,         // 高风险直接拒绝
            .critical: .block
        ],
        signalWeights: .init(
            jailbreak: 0.8,
            network: 1.3,
            behavior: 1.0,
            device: 1.2,
            time: 0.8
        ),
        comboRules: [
            // 支付场景的组合规则
            .init(
                name: "jailbreak_vpn_payment",
                requiredSignals: [ObfuscatedConstants.signalJailbreak, ObfuscatedConstants.requiredSignalVpnActive],
                bonusScore: 40,
                forceAction: .block
            ),
            .init(
                name: "high_risk_behavior_payment",
                requiredSignals: ["touch_spread_low", "swipe_too_linear"],
                bonusScore: 25,
                forceAction: .stepUpAuth
            ),
            impossibleStatesRule,
        ]
    )

    /// 账户变更策略：严格
    public static let accountChange = ScenarioPolicy(
        mediumThreshold: 25,
        highThreshold: 50,
        criticalThreshold: 75,
        actionMapping: [
            .low: .allow,
            .medium: .challenge,
            .high: .stepUpAuth,
            .critical: .block
        ],
        comboRules: [impossibleStatesRule]
    )

    /// 敏感操作策略：最严格
    public static let sensitiveAction = ScenarioPolicy(
        mediumThreshold: 15,
        highThreshold: 40,
        criticalThreshold: 65,
        actionMapping: [
            .low: .challenge,      // 即使低风险也要验证
            .medium: .stepUpAuth,
            .high: .block,
            .critical: .block
        ],
        signalWeights: .init(
            jailbreak: 1.0,
            network: 1.5,
            behavior: 1.2,
            device: 1.5,
            time: 1.0
        ),
        comboRules: [impossibleStatesRule]
    )

    /// API访问策略：适中
    public static let apiAccess = ScenarioPolicy(
        mediumThreshold: 30,
        highThreshold: 55,
        criticalThreshold: 80,
        signalWeights: .init(
            jailbreak: 0.6,
            network: 1.0,
            behavior: 0.5,
            device: 1.2,
            time: 1.0
        ),
        comboRules: [impossibleStatesRule]
    )

    /// 根据场景获取预设策略
    public static func policy(for scenario: RiskScenario) -> ScenarioPolicy {
        switch scenario {
        case .default: return .general
        case .login: return .login
        case .register: return .register
        case .payment: return .payment
        case .accountChange: return .accountChange
        case .sensitiveAction: return .sensitiveAction
        case .apiAccess: return .apiAccess
        case .query: return .general
        }
    }
}

// MARK: - 信号权重配置
/// 不同类别信号在特定场景下的权重系数
public struct SignalWeights: Codable, Sendable {
    public let jailbreak: Double
    public let network: Double
    public let behavior: Double
    public let device: Double
    public let time: Double

    private enum CodingKeys: String, CodingKey {
        case jailbreak = "j"
        case network = "n"
        case behavior = "b"
        case device = "d"
        case time = "t"
    }

    public init(
        jailbreak: Double = 1.0,
        network: Double = 1.0,
        behavior: Double = 1.0,
        device: Double = 1.0,
        time: Double = 1.0
    ) {
        self.jailbreak = jailbreak
        self.network = network
        self.behavior = behavior
        self.device = device
        self.time = time
    }

    /// 默认权重（全部为1.0）
    public static let `default` = SignalWeights()

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        func valid(_ v: Double) -> Double {
            (v.isFinite && v >= 0 && v <= 10) ? v : 1.0
        }
        jailbreak = valid(try container.decodeIfPresent(Double.self, forKey: .jailbreak) ?? 1.0)
        network = valid(try container.decodeIfPresent(Double.self, forKey: .network) ?? 1.0)
        behavior = valid(try container.decodeIfPresent(Double.self, forKey: .behavior) ?? 1.0)
        device = valid(try container.decodeIfPresent(Double.self, forKey: .device) ?? 1.0)
        time = valid(try container.decodeIfPresent(Double.self, forKey: .time) ?? 1.0)
    }

    /// 获取指定类别的权重
    public func weight(for category: String) -> Double {
        switch category.lowercased() {
        case ObfuscatedConstants.signalJailbreak: return jailbreak
        case "network": return network
        case "behavior": return behavior
        case "device": return device
        case "time": return time
        default: return 1.0
        }
    }
}

// MARK: - 组合规则
/// 当多个特定信号同时出现时，触发额外的风险加分或强制动作
public struct ComboRule: Codable, Sendable {
    public let name: String
    public let requiredSignals: [String]
    public let bonusScore: Double
    public let forceAction: RiskAction?
    public let description: String?

    private enum CodingKeys: String, CodingKey {
        case name = "n"
        case requiredSignals = "rs"
        case bonusScore = "bs"
        case forceAction = "fa"
        case description = "ds"
    }

    public init(
        name: String,
        requiredSignals: [String],
        bonusScore: Double = 20,
        forceAction: RiskAction? = nil,
        description: String? = nil
    ) {
        self.name = name
        self.requiredSignals = requiredSignals
        self.bonusScore = bonusScore
        self.forceAction = forceAction
        self.description = description
    }

    /// 检查信号是否匹配此规则
    public func matches(signals: [RiskSignal]) -> Bool {
        guard !requiredSignals.isEmpty else { return false }
        let signalIds = Set(signals.map { $0.id })
        let required = Set(requiredSignals)
        return required.isSubset(of: signalIds)
    }
}

// MARK: - 策略构建器
/// 流式接口用于构建自定义策略
public struct ScenarioPolicyBuilder {
    private var mediumThreshold: Double = 30
    private var highThreshold: Double = 55
    private var criticalThreshold: Double = 80
    private var actionMapping: [InternalRiskLevel: RiskAction] = [:]
    private var signalWeights: SignalWeights = .default
    private var comboRules: [ComboRule] = []
    private var enableForceRules: Bool = true
    private var compressedVerdictRules: [CompressedVerdictRule] = []

    public init() {}

    public func setThresholds(medium: Double, high: Double, critical: Double) -> ScenarioPolicyBuilder {
        var builder = self
        builder.mediumThreshold = medium
        builder.highThreshold = high
        builder.criticalThreshold = critical
        return builder
    }

    public func setAction(_ action: RiskAction, for level: InternalRiskLevel) -> ScenarioPolicyBuilder {
        var builder = self
        builder.actionMapping[level] = action
        return builder
    }

    public func setSignalWeights(_ weights: SignalWeights) -> ScenarioPolicyBuilder {
        var builder = self
        builder.signalWeights = weights
        return builder
    }

    public func addComboRule(_ rule: ComboRule) -> ScenarioPolicyBuilder {
        var builder = self
        builder.comboRules.append(rule)
        return builder
    }

    public func setEnableForceRules(_ enable: Bool) -> ScenarioPolicyBuilder {
        var builder = self
        builder.enableForceRules = enable
        return builder
    }

    public func setCompressedVerdictRules(_ rules: [CompressedVerdictRule]) -> ScenarioPolicyBuilder {
        var builder = self
        builder.compressedVerdictRules = rules
        return builder
    }

    public func build() -> ScenarioPolicy {
        ScenarioPolicy(
            mediumThreshold: mediumThreshold,
            highThreshold: highThreshold,
            criticalThreshold: criticalThreshold,
            actionMapping: actionMapping.isEmpty ? nil : actionMapping,
            signalWeights: signalWeights,
            comboRules: comboRules,
            enableForceRules: enableForceRules,
            compressedVerdictRules: compressedVerdictRules
        )
    }
}
