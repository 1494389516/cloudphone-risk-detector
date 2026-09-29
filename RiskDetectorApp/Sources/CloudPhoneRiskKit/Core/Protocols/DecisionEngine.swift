import Foundation

// MARK: - Local Assessment Boundary

/// Evaluates device evidence locally. Suggested actions do not authorize server operations.
public protocol LocalAssessmentEngine: Sendable {
    func assess(snapshot: RiskSnapshot, config: LocalAssessmentConfig) async -> LocalAssessment
    var supportedFeatures: [String] { get }
    func reset() async
}

/// Legacy protocol. Existing conformers only implementing `decide` remain valid.
public protocol DecisionEngine: LocalAssessmentEngine {
    func decide(snapshot: RiskSnapshot, config: DecisionConfig) async -> RiskVerdict
}

extension DecisionEngine {
    public func assess(snapshot: RiskSnapshot, config: LocalAssessmentConfig) async -> LocalAssessment {
        await decide(snapshot: snapshot, config: config)
    }
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

    private enum CodingKeys: String, CodingKey {
        case scenario = "sc"
        case useRemoteConfig = "ur"
        case customThreshold = "ct"
        case enabledDetectors = "ed"
        case extras = "ex"
    }

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

    private static var defaultDetectors: Set<String> { [
        ObfuscatedConstants.signalJailbreak,
        ObfuscatedConstants.categoryAntiTamper,
        "behavior",
        "network",
        "device",
        "environment"
    ] }
}

public struct FeatureVector: Sendable, Codable {
    public var values: [String: Double]
    public var metadata: [String: String]

    private enum CodingKeys: String, CodingKey {
        case values = "v"
        case metadata = "m"
    }

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

    private enum CodingKeys: String, CodingKey {
        case score = "s"
        case confidence = "c"
        case explanation = "e"
    }

    public init(score: Double, confidence: Double, explanation: [String: String] = [:]) {
        self.score = score
        self.confidence = confidence
        self.explanation = explanation
    }
}

// MARK: - Compatibility Aliases

/// Local configuration retains the legacy Codable representation and initializer.
public typealias LocalAssessmentConfig = DecisionConfig
public typealias ProtocolRiskScenario = RiskScenario
public typealias ProtocolRiskLevel = PublicRiskLevel
public typealias ProtocolRiskAction = PublicRiskAction
public typealias ProtocolRiskVerdict = RiskVerdict
