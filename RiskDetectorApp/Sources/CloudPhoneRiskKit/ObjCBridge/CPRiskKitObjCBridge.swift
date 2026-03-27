import Foundation
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Objective-C Risk Level Wrapper

/// ObjC-friendly risk level enum wrapping `PublicRiskLevel`.
@objc(CPRiskLevel)
public enum CPRiskLevelObjC: Int, CaseIterable {
    case low = 0
    case medium = 1
    case high = 2

    public init(from level: PublicRiskLevel) {
        self.init(rawValue: level.rawValue) ?? .low
    }

    public var toSwift: PublicRiskLevel {
        PublicRiskLevel(rawValue: rawValue) ?? .low
    }

    @objc public var displayName: String {
        toSwift.displayName
    }
}

// MARK: - Objective-C Risk Action Wrapper

/// ObjC-friendly risk action enum wrapping `PublicRiskAction`.
@objc(CPRiskActionObjC)
public enum CPRiskActionObjC: Int, CaseIterable {
    case allow = 0
    case challenge = 1
    case block = 2

    public init(from action: PublicRiskAction) {
        self.init(rawValue: action.rawValue) ?? .allow
    }

    public var toSwift: PublicRiskAction {
        PublicRiskAction(rawValue: rawValue) ?? .allow
    }

    @objc public var displayName: String {
        toSwift.displayName
    }
}

// MARK: - Objective-C Risk Scenario Wrapper

/// ObjC-friendly scenario enum wrapping `RiskScenario`.
@objc(CPRiskScenarioObjC)
public enum CPRiskScenarioObjC: Int, CaseIterable {
    case login = 0
    case payment = 1
    case register = 2
    case query = 3
    case defaultScenario = 4
    case accountChange = 5
    case sensitiveAction = 6
    case apiAccess = 7

    public init(from scenario: RiskScenario) {
        self.init(rawValue: scenario.rawValue) ?? .defaultScenario
    }

    public var toSwift: RiskScenario {
        RiskScenario(rawValue: rawValue) ?? .default
    }

    @objc public var displayName: String {
        toSwift.displayName
    }
}

// MARK: - Evaluation Result (ObjC-friendly wrapper)

/// Immutable result object returned by the ObjC bridge's evaluation methods.
@objc(CPEvaluationResult)
public final class CPEvaluationResult: NSObject {

    @objc public let report: CPRiskReport
    @objc public let score: Double
    @objc public let isHighRisk: Bool
    @objc public let riskLevel: CPRiskLevelObjC
    @objc public let summary: String
    @objc public let deviceID: String
    @objc public let signalCount: Int

    init(report: CPRiskReport) {
        self.report = report
        self.score = report.score
        self.isHighRisk = report.isHighRisk
        self.riskLevel = CPRiskLevelObjC(
            from: InternalRiskLevel.from(score: report.score).toPublicRiskLevel()
        )
        self.summary = report.summary
        self.deviceID = report.deviceID
        self.signalCount = report.signals.count
        super.init()
    }

    @objc public override var description: String {
        "<CPEvaluationResult score=\(score) level=\(riskLevel.displayName) signals=\(signalCount)>"
    }
}

// MARK: - CPRiskKitObjCBridge

/// Objective-C bridge exposing all major CPRiskKit APIs.
///
/// Usage from Objective-C:
/// ```objc
/// CPRiskKitObjCBridge *bridge = [[CPRiskKitObjCBridge alloc] init];
/// [bridge startWithDefaultConfig];
/// [bridge evaluateWithScenario:CPRiskScenarioObjCPayment
///                   completion:^(CPEvaluationResult *result) {
///     NSLog(@"Score: %f", result.score);
/// }];
/// ```
@objc(CPRiskKitObjCBridge)
public final class CPRiskKitObjCBridge: NSObject {

    private let kit: CPRiskKit

    // MARK: - Init

    @objc
    public override init() {
        self.kit = CPRiskKit.shared
        super.init()
    }

    // MARK: - Lifecycle

    /// Start the SDK with default configuration.
    @objc(startWithDefaultConfig)
    public func startWithDefaultConfig() {
        kit.start()
    }

    /// Start the SDK with a custom ObjC configuration object.
    @objc(startWithConfig:)
    public func start(config: CPRiskConfig) {
        kit.start(config: config)
    }

    /// Stop the SDK, halting all sampling and releasing resources.
    @objc
    public func stop() {
        kit.stop()
    }

    // MARK: - Configuration

    /// Enable or disable SDK logging.
    @objc(setLogEnabled:)
    public func setLogEnabled(_ enabled: Bool) {
        CPRiskKit.setLogEnabled(enabled)
    }

    /// Configure server-side signing key for report verification.
    @objc(configureServerSigningKey:)
    public func configureServerSigningKey(_ key: String) {
        CPRiskKit.configureServerSigningKey(key)
    }

    /// Configure pinned certificate hashes for TLS certificate pinning.
    @objc(configurePinnedCertificateHashes:)
    public func configurePinnedCertificateHashes(_ hashes: [String]) {
        CPRiskKit.configurePinnedCertificateHashes(hashes)
    }

    // MARK: - Account Binding

    /// Bind the current user account for graph-based risk analysis.
    @objc(bindAccount:scene:)
    public func bindAccount(_ accountId: String, scene: String?) {
        kit.bindAccount(accountId, scene: scene)
    }

    /// Unbind the current user account.
    @objc
    public func unbindAccount() {
        kit.unbindAccount()
    }

    // MARK: - Synchronous Evaluation

    /// Evaluate risk synchronously with default config and scenario.
    /// - Returns: The raw `CPRiskReport`.
    @objc(evaluate)
    public func evaluate() -> CPRiskReport {
        kit.evaluate()
    }

    /// Evaluate risk synchronously and return a wrapped result object.
    @objc(evaluateAndWrap)
    public func evaluateAndWrap() -> CPEvaluationResult {
        CPEvaluationResult(report: kit.evaluate())
    }

    /// Evaluate risk synchronously for a specific scenario.
    @objc(evaluateWithScenarioRaw:)
    public func evaluateWithScenarioRaw(_ scenario: CPRiskScenarioObjC) -> CPRiskReport {
        kit.evaluate(config: .default, scenario: scenario.toSwift)
    }

    // MARK: - Asynchronous Evaluation (Completion Handler)

    /// Evaluate risk asynchronously with default config.
    /// The completion handler is called on a background queue.
    @objc(evaluateWithCompletion:)
    public func evaluate(completion: @escaping (CPRiskReport) -> Void) {
        kit.evaluateAsync(completion: completion)
    }

    /// Evaluate risk asynchronously for a specific scenario.
    @objc(evaluateWithScenario:completion:)
    public func evaluate(
        scenario: CPRiskScenarioObjC,
        completion: @escaping (CPEvaluationResult) -> Void
    ) {
        DispatchQueue.global(qos: .utility).async { [kit] in
            let report = kit.evaluate(config: .default, scenario: scenario.toSwift)
            let result = CPEvaluationResult(report: report)
            completion(result)
        }
    }

    /// Evaluate risk asynchronously with a custom config.
    @objc(evaluateWithConfig:completion:)
    public func evaluate(
        config: CPRiskConfig,
        completion: @escaping (CPEvaluationResult) -> Void
    ) {
        DispatchQueue.global(qos: .utility).async { [kit] in
            let report = kit.evaluate(config: config)
            let result = CPEvaluationResult(report: report)
            completion(result)
        }
    }

    // MARK: - Report Retrieval

    /// Get the JSON string of the last evaluation report (unencrypted, debug only).
    @objc(lastReportJSONPrettyPrinted:)
    public func lastReportJSON(prettyPrinted: Bool) -> String? {
        let report = kit.evaluate()
        return report.unencryptedPayloadString(prettyPrinted: prettyPrinted)
    }

    /// Get the encrypted payload of the last evaluation (production use).
    @objc(lastReportSecurePayloadAndReturnError:)
    public func lastReportSecurePayload() throws -> Data {
        let report = kit.evaluate()
        return try report.securePayload()
    }

    // MARK: - Server Signals

    /// Inject server-side aggregation signals into the report.
    @objc(setServerSignalsOnReport:publicIP:asn:asOrg:isDatacenter:ipDeviceAgg:ipAccountAgg:geoCountry:geoRegion:riskTags:)
    public func setServerSignals(
        on report: CPRiskReport,
        publicIP: String?,
        asn: String?,
        asOrg: String?,
        isDatacenter: NSNumber?,
        ipDeviceAgg: NSNumber?,
        ipAccountAgg: NSNumber?,
        geoCountry: String?,
        geoRegion: String?,
        riskTags: [String]?
    ) {
        report.setServerSignals(
            publicIP: publicIP,
            asn: asn,
            asOrg: asOrg,
            isDatacenter: isDatacenter,
            ipDeviceAgg: ipDeviceAgg,
            ipAccountAgg: ipAccountAgg,
            geoCountry: geoCountry,
            geoRegion: geoRegion,
            riskTags: riskTags
        )
    }

    // MARK: - Cleanup

    /// Clear all cached external server signals.
    @objc
    public func clearExternalServerSignals() {
        CPRiskKit.clearExternalServerSignals()
    }

    /// Clear any cached realtime telemetry feedback.
    @objc
    public func clearRealtimeTelemetryFeedback() {
        CPRiskKit.clearRealtimeTelemetryFeedback()
    }

    // MARK: - Utility

    /// Returns the current SDK version string.
    @objc public var sdkVersion: String {
        Version.current
    }

    /// Returns whether the SDK is currently in Kill Switch mode.
    @objc public var isKillSwitchActive: Bool {
        false
    }
}
