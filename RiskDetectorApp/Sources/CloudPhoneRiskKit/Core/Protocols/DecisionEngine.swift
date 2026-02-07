import Foundation

// MARK: - Decision Engine Protocol

public protocol DecisionEngine: Sendable {
    func decide(snapshot: RiskSnapshot, config: DecisionConfig) async -> RiskVerdict
    var supportedFeatures: [String] { get }
    func reset() async
}

public protocol DecisionModel: Sendable {
    var id: String { get }
    var version: String { get }
    var supportedFeatures: [String] { get }

    func evaluate(features: FeatureVector, policy: PolicyConfig) async -> ModelResult
    func reset() async
}

// MARK: - Config and Supporting Types

public struct DecisionConfig: Sendable, Codable {
    public var scenario: RiskScenario
    public var useRemoteConfig: Bool
    public var customThreshold: Double?
    public var enabledDetectors: Set<String>
    public var extras: [String: String]

    public init(
        scenario: RiskScenario = .default,
        useRemoteConfig: Bool = true,
        customThreshold: Double? = nil,
        enabledDetectors: Set<String> = [],
        extras: [String: String] = [:]
    ) {
        self.scenario = scenario
        self.useRemoteConfig = useRemoteConfig
        self.customThreshold = customThreshold
        self.enabledDetectors = enabledDetectors.isEmpty ? Self.defaultDetectors : enabledDetectors
        self.extras = extras
    }

    private static let defaultDetectors: Set<String> = [
        "jailbreak",
        "anti_tamper",
        "behavior",
        "network",
        "device",
        "environment"
    ]
}

public struct FeatureVector: Sendable, Codable {
    public var values: [String: Double]
    public var metadata: [String: String]

    public init(values: [String: Double] = [:], metadata: [String: String] = [:]) {
        self.values = values
        self.metadata = metadata
    }

    public subscript(_ key: String) -> Double? {
        get { values[key] }
        set { values[key] = newValue }
    }
}

public struct ModelResult: Sendable, Codable {
    public var score: Double
    public var confidence: Double
    public var explanation: [String: String]

    public init(score: Double, confidence: Double, explanation: [String: String] = [:]) {
        self.score = score
        self.confidence = confidence
        self.explanation = explanation
    }
}

// MARK: - Compatibility Aliases

public typealias ProtocolRiskScenario = RiskScenario
public typealias ProtocolRiskLevel = PublicRiskLevel
public typealias ProtocolRiskAction = PublicRiskAction
public typealias ProtocolRiskVerdict = RiskVerdict
public typealias ProtocolAnySendable = String
