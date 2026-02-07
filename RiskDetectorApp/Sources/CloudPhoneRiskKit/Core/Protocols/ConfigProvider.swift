import Foundation

public protocol ConfigProvider: Sendable {
    func fetchConfig() async throws -> ProviderConfig
    func getCachedConfig() -> ProviderConfig?
    func clearCache()
}

public protocol ConfigReading: Sendable {
    func getDecisionConfig(for scenario: ProtocolRiskScenario) async -> DecisionConfig
    func getPolicy(for scenario: ProtocolRiskScenario) async -> PolicyConfig
    func getProviderDetectorConfig(for detectorId: String) -> ProviderDetectorConfig?
    func isDetectorEnabled(_ detectorId: String) -> Bool
}

public protocol ConfigUpdating: Sendable {
    func updateConfig(_ config: ProviderConfig) async throws
    func updatePolicy(for scenario: ProtocolRiskScenario, policy: PolicyConfig) async
    func setDetectorEnabled(_ detectorId: String, enabled: Bool) async
}

public struct ProviderConfig: Sendable, Codable {
    public var version: String
    public var effectiveTime: Date
    public var expireTime: Date
    public var detectors: ProviderDetectorConfigs
    public var policies: PolicyConfigs
    public var scenarios: ScenarioConfigs
    public var signature: String

    public init(
        version: String,
        effectiveTime: Date,
        expireTime: Date,
        detectors: ProviderDetectorConfigs,
        policies: PolicyConfigs,
        scenarios: ScenarioConfigs,
        signature: String
    ) {
        self.version = version
        self.effectiveTime = effectiveTime
        self.expireTime = expireTime
        self.detectors = detectors
        self.policies = policies
        self.scenarios = scenarios
        self.signature = signature
    }

    public var isExpired: Bool { Date() > expireTime }
    public var isEffective: Bool { Date() >= effectiveTime && !isExpired }
}

public protocol ProviderDetectorConfig: Sendable, Codable {
    var detectorId: String { get }
    var isEnabled: Bool { get set }
}

public struct ProviderDetectorConfigs: Sendable, Codable {
    public var jailbreak: JailbreakProviderDetectorConfig
    public var antiTamper: AntiTamperProviderDetectorConfig
    public var behavior: BehaviorProviderDetectorConfig
    public var network: NetworkProviderDetectorConfig
    public var device: DeviceProviderDetectorConfig
    public var environment: EnvironmentProviderDetectorConfig

    public init(
        jailbreak: JailbreakProviderDetectorConfig = .default,
        antiTamper: AntiTamperProviderDetectorConfig = .default,
        behavior: BehaviorProviderDetectorConfig = .default,
        network: NetworkProviderDetectorConfig = .default,
        device: DeviceProviderDetectorConfig = .default,
        environment: EnvironmentProviderDetectorConfig = .default
    ) {
        self.jailbreak = jailbreak
        self.antiTamper = antiTamper
        self.behavior = behavior
        self.network = network
        self.device = device
        self.environment = environment
    }

    public subscript(_ detectorId: String) -> ProviderDetectorConfig? {
        switch detectorId {
        case "jailbreak": return jailbreak
        case "anti_tamper": return antiTamper
        case "behavior": return behavior
        case "network": return network
        case "device": return device
        case "environment": return environment
        default: return nil
        }
    }
}

public struct JailbreakProviderDetectorConfig: ProviderDetectorConfig {
    public let detectorId = "jailbreak"
    public var isEnabled: Bool
    public var threshold: Double
    public var enableFileDetect: Bool
    public var enableDyldDetect: Bool
    public var enableEnvDetect: Bool
    public var enableSysctlDetect: Bool
    public var enableSchemeDetect: Bool
    public var enableHookDetect: Bool

    public init(
        isEnabled: Bool = true,
        threshold: Double = 50,
        enableFileDetect: Bool = true,
        enableDyldDetect: Bool = true,
        enableEnvDetect: Bool = true,
        enableSysctlDetect: Bool = true,
        enableSchemeDetect: Bool = true,
        enableHookDetect: Bool = true
    ) {
        self.isEnabled = isEnabled
        self.threshold = threshold
        self.enableFileDetect = enableFileDetect
        self.enableDyldDetect = enableDyldDetect
        self.enableEnvDetect = enableEnvDetect
        self.enableSysctlDetect = enableSysctlDetect
        self.enableSchemeDetect = enableSchemeDetect
        self.enableHookDetect = enableHookDetect
    }

    public static let `default` = Self()
    public static let light = Self(threshold: 70, enableHookDetect: false)
    public static let full = Self()
}

public struct AntiTamperProviderDetectorConfig: ProviderDetectorConfig {
    public let detectorId = "anti_tamper"
    public var isEnabled: Bool
    public var threshold: Double
    public var enableCodeIntegrityCheck: Bool
    public var enableDylibInjectionCheck: Bool
    public var enableDebuggerCheck: Bool
    public var enableFridaCheck: Bool
    public var enableEmulatorCheck: Bool

    public init(
        isEnabled: Bool = true,
        threshold: Double = 50,
        enableCodeIntegrityCheck: Bool = true,
        enableDylibInjectionCheck: Bool = true,
        enableDebuggerCheck: Bool = true,
        enableFridaCheck: Bool = true,
        enableEmulatorCheck: Bool = true
    ) {
        self.isEnabled = isEnabled
        self.threshold = threshold
        self.enableCodeIntegrityCheck = enableCodeIntegrityCheck
        self.enableDylibInjectionCheck = enableDylibInjectionCheck
        self.enableDebuggerCheck = enableDebuggerCheck
        self.enableFridaCheck = enableFridaCheck
        self.enableEmulatorCheck = enableEmulatorCheck
    }

    public static let `default` = Self()
}

public struct BehaviorProviderDetectorConfig: ProviderDetectorConfig {
    public let detectorId = "behavior"
    public var isEnabled: Bool
    public var touchSamplingDuration: TimeInterval
    public var motionSamplingDuration: TimeInterval
    public var minTouchCount: Int
    public var touchSpreadLowThreshold: Double
    public var touchSpreadHighThreshold: Double
    public var touchIntervalCVLowThreshold: Double
    public var touchIntervalCVHighThreshold: Double

    public init(
        isEnabled: Bool = true,
        touchSamplingDuration: TimeInterval = 30,
        motionSamplingDuration: TimeInterval = 30,
        minTouchCount: Int = 6,
        touchSpreadLowThreshold: Double = 2.0,
        touchSpreadHighThreshold: Double = 10.0,
        touchIntervalCVLowThreshold: Double = 0.2,
        touchIntervalCVHighThreshold: Double = 0.6
    ) {
        self.isEnabled = isEnabled
        self.touchSamplingDuration = touchSamplingDuration
        self.motionSamplingDuration = motionSamplingDuration
        self.minTouchCount = minTouchCount
        self.touchSpreadLowThreshold = touchSpreadLowThreshold
        self.touchSpreadHighThreshold = touchSpreadHighThreshold
        self.touchIntervalCVLowThreshold = touchIntervalCVLowThreshold
        self.touchIntervalCVHighThreshold = touchIntervalCVHighThreshold
    }

    public static let `default` = Self()
}

public struct NetworkProviderDetectorConfig: ProviderDetectorConfig {
    public let detectorId = "network"
    public var isEnabled: Bool
    public var detectVPN: Bool
    public var detectProxy: Bool
    public var vpnRiskScore: Double
    public var proxyRiskScore: Double

    public init(
        isEnabled: Bool = true,
        detectVPN: Bool = true,
        detectProxy: Bool = true,
        vpnRiskScore: Double = 10,
        proxyRiskScore: Double = 8
    ) {
        self.isEnabled = isEnabled
        self.detectVPN = detectVPN
        self.detectProxy = detectProxy
        self.vpnRiskScore = vpnRiskScore
        self.proxyRiskScore = proxyRiskScore
    }

    public static let `default` = Self()
}

public struct DeviceProviderDetectorConfig: ProviderDetectorConfig {
    public let detectorId = "device"
    public var isEnabled: Bool
    public var detectSimulator: Bool
    public var oldDeviceFamilyThreshold: Int
    public var simulatorRiskScore: Double

    public init(
        isEnabled: Bool = true,
        detectSimulator: Bool = true,
        oldDeviceFamilyThreshold: Int = 11,
        simulatorRiskScore: Double = 0
    ) {
        self.isEnabled = isEnabled
        self.detectSimulator = detectSimulator
        self.oldDeviceFamilyThreshold = oldDeviceFamilyThreshold
        self.simulatorRiskScore = simulatorRiskScore
    }

    public static let `default` = Self()
}

public struct EnvironmentProviderDetectorConfig: ProviderDetectorConfig {
    public let detectorId = "environment"
    public var isEnabled: Bool
    public var detectProxy: Bool
    public var detectJailbreakEnv: Bool

    public init(
        isEnabled: Bool = true,
        detectProxy: Bool = true,
        detectJailbreakEnv: Bool = true
    ) {
        self.isEnabled = isEnabled
        self.detectProxy = detectProxy
        self.detectJailbreakEnv = detectJailbreakEnv
    }

    public static let `default` = Self()
}

public struct PolicyConfigs: Sendable, Codable {
    public var thresholds: ThresholdConfig
    public var weights: WeightConfig
    public var rules: [RuleConfig]

    public init(thresholds: ThresholdConfig = .default, weights: WeightConfig = .default, rules: [RuleConfig] = []) {
        self.thresholds = thresholds
        self.weights = weights
        self.rules = rules
    }
}

public struct ThresholdConfig: Sendable, Codable {
    public var lowRisk: Double
    public var mediumRisk: Double
    public var highRisk: Double

    public init(lowRisk: Double = 40, mediumRisk: Double = 60, highRisk: Double = 80) {
        self.lowRisk = lowRisk
        self.mediumRisk = mediumRisk
        self.highRisk = highRisk
    }

    public static let `default` = Self()

    public func getLevel(for score: Double) -> ProtocolRiskLevel {
        if score >= highRisk { return .high }
        if score >= mediumRisk { return .medium }
        return .low
    }
}

public struct WeightConfig: Sendable, Codable {
    public var jailbreak: Double
    public var antiTamper: Double
    public var behavior: Double
    public var network: Double
    public var device: Double
    public var environment: Double

    public init(
        jailbreak: Double = 0.6,
        antiTamper: Double = 0.5,
        behavior: Double = 0.3,
        network: Double = 0.1,
        device: Double = 0.1,
        environment: Double = 0.1
    ) {
        self.jailbreak = jailbreak
        self.antiTamper = antiTamper
        self.behavior = behavior
        self.network = network
        self.device = device
        self.environment = environment
    }

    public static let `default` = Self()

    public subscript(_ detectorId: String) -> Double {
        switch detectorId {
        case "jailbreak": return jailbreak
        case "anti_tamper": return antiTamper
        case "behavior": return behavior
        case "network": return network
        case "device": return device
        case "environment": return environment
        default: return 0.1
        }
    }
}

public struct RuleConfig: Sendable, Codable, Identifiable {
    public var id: String
    public var name: String
    public var description: String
    public var condition: RuleCondition
    public var action: RuleAction
    public var priority: Int

    public init(
        id: String,
        name: String,
        description: String = "",
        condition: RuleCondition,
        action: RuleAction,
        priority: Int = 0
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.condition = condition
        self.action = action
        self.priority = priority
    }
}

public indirect enum RuleCondition: Sendable, Codable {
    case always
    case never
    case signalEquals(signal: String, value: String)
    case signalGreaterThan(signal: String, value: Double)
    case signalLessThan(signal: String, value: Double)
    case signalInRange(signal: String, min: Double, max: Double)
    case and([RuleCondition])
    case or([RuleCondition])
    case not(RuleCondition)
}

public enum RuleAction: Sendable, Codable {
    case setScore(score: Double)
    case setProtocolRiskLevel(level: ProtocolRiskLevel)
    case block
    case allow
    case challenge
}

public struct ScenarioConfigs: Sendable, Codable {
    public var login: ScenarioConfig
    public var payment: ScenarioConfig
    public var register: ScenarioConfig
    public var query: ScenarioConfig
    public var `default`: ScenarioConfig

    public init(
        login: ScenarioConfig = .login,
        payment: ScenarioConfig = .payment,
        register: ScenarioConfig = .register,
        query: ScenarioConfig = .query,
        default: ScenarioConfig = .default
    ) {
        self.login = login
        self.payment = payment
        self.register = register
        self.query = query
        self.`default` = `default`
    }

    public subscript(_ scenario: ProtocolRiskScenario) -> ScenarioConfig {
        switch scenario {
        case .login: return login
        case .payment: return payment
        case .register: return register
        case .query: return query
        default: return `default`
        }
    }
}

public struct ScenarioConfig: Sendable, Codable {
    public var enabled: Bool
    public var threshold: Double
    public var enabledDetectors: [String]
    public var customWeights: WeightConfig?
    public var mediumProtocolRiskAction: ProtocolRiskAction
    public var highProtocolRiskAction: ProtocolRiskAction

    public init(
        enabled: Bool = true,
        threshold: Double = 60,
        enabledDetectors: [String] = [],
        customWeights: WeightConfig? = nil,
        mediumProtocolRiskAction: ProtocolRiskAction = .challenge,
        highProtocolRiskAction: ProtocolRiskAction = .block
    ) {
        self.enabled = enabled
        self.threshold = threshold
        self.enabledDetectors = enabledDetectors.isEmpty ? Self.defaultDetectors : enabledDetectors
        self.customWeights = customWeights
        self.mediumProtocolRiskAction = mediumProtocolRiskAction
        self.highProtocolRiskAction = highProtocolRiskAction
    }

    private static let defaultDetectors: [String] = [
        "jailbreak", "anti_tamper", "behavior", "network", "device"
    ]

    public static let login = ScenarioConfig(threshold: 60, mediumProtocolRiskAction: .challenge, highProtocolRiskAction: .block)
    public static let payment = ScenarioConfig(threshold: 50, mediumProtocolRiskAction: .challenge, highProtocolRiskAction: .block)
    public static let register = ScenarioConfig(threshold: 70, mediumProtocolRiskAction: .allow, highProtocolRiskAction: .challenge)
    public static let query = ScenarioConfig(threshold: 80, mediumProtocolRiskAction: .allow, highProtocolRiskAction: .allow)
    public static let `default` = ScenarioConfig(threshold: 60)
}

public struct PolicyConfig: Sendable, Codable {
    public var threshold: Double
    public var mediumProtocolRiskAction: ProtocolRiskAction
    public var highProtocolRiskAction: ProtocolRiskAction
    public var enabledDetectors: Set<String>
    public var customWeights: [String: Double]?

    public init(
        threshold: Double,
        mediumProtocolRiskAction: ProtocolRiskAction = .challenge,
        highProtocolRiskAction: ProtocolRiskAction = .block,
        enabledDetectors: Set<String> = [],
        customWeights: [String: Double]? = nil
    ) {
        self.threshold = threshold
        self.mediumProtocolRiskAction = mediumProtocolRiskAction
        self.highProtocolRiskAction = highProtocolRiskAction
        self.enabledDetectors = enabledDetectors.isEmpty ? ["jailbreak", "anti_tamper", "behavior", "network", "device"] : enabledDetectors
        self.customWeights = customWeights
    }
}

public enum ProviderConfigError: Error, Sendable {
    case networkError(Error)
    case invalidResponse
    case httpError(Int)
    case invalidSignature
    case expiredConfig
    case decodeError(Error)
    case unsupportedVersion(String)
}
