// MARK: - CloudPhoneRiskKit — Main Entry Point
// Singleton orchestrator: start/stop, evaluate, config, report.
// Implementations split into Core/ extensions:
//   Configuration / Lifecycle / Evaluation / ArmorBridge / Reporting / Diagnostics

import CryptoKit
import CRiskCore
import Foundation
#if canImport(UIKit)
import UIKit
#endif

@objc(CPR_RiskKit)
public final class CPRiskKit: NSObject {
    @objc public static let shared = CPRiskKit()

    public static let graphRiskFeedbackDidApplyNotification = ExternalServerAggregateProvider.graphRiskFeedbackDidApplyNotification
    public static var autoReEvaluateOnGraphFeedback: Bool = true

    public enum SecureUploadError: Error, LocalizedError {
        case payloadFieldMappingRequired
        case payloadFieldMappingExpired(version: String)
        case invalidPayloadShape
        case armorRuntimeUnavailable(reason: String)

        public var errorDescription: String? {
            switch self {
            case .payloadFieldMappingRequired:
                return "当前策略要求字段混淆，但 payloadFieldMapping 未下发"
            case .payloadFieldMappingExpired(let version):
                return "payloadFieldMapping 已过期（version=\(version)）"
            case .invalidPayloadShape:
                return "上报 payload 结构无效，无法构建安全信封"
            case .armorRuntimeUnavailable(let reason):
                return "armor 运行时不可用，无法派生签名密钥（reason=\(reason)），服务端验签将失败"
            }
        }
    }

    // MARK: - Stored Properties

#if canImport(UIKit)
    internal let touchCapture = TouchCapture.shared
    internal let motionSampler = MotionSampler.shared
    internal let jailbreakEngine = JailbreakEngine()
#else
    internal let jailbreakEngine = JailbreakEngine()
#endif

    internal let evaluateQueue = DispatchQueue(label: "CloudPhoneRiskKit.Evaluate", qos: .utility)
    internal let stateLock = UnfairLock()
    internal let armorInitLock = UnfairLock()

    internal static let verifyThrottleInterval: TimeInterval = 5.0
    internal static var lastExceptionVerifyTime: TimeInterval = 0
    internal static let verifyThrottleLock = UnfairLock()

    internal var remoteConfigProvider: RemoteConfigProvider?
    internal var remoteConfigEndpoint: URL?
    internal var latestRemoteConfig: RemoteConfig?
    internal var textSegmentReferenceResolver: (any TextSegmentReferenceResolving)?

    /// Register a reporter to receive C-layer hostile-environment signals for
    /// server-side risk assessment.  The reporter is called after each
    /// evaluation cycle when any emulator/unidbg signals are active.
    ///
    /// Setting this to `nil` (default) disables server-side reporting.
    public weak var hostileEnvironmentReporter: (any HostileEnvironmentReporter)?

    internal var boundAccountId: String?
    internal var boundSceneTag: String?
    internal var currentSessionId: String?
    internal var graphFeedbackObserver: Any?
    internal var mainThreadWatchdogHeartbeatTimer: Timer?

    internal var previousSignalIds: Set<String> = []
    internal var previousSignalsDigest: String?
    internal var adaptiveCachedReport: CPRiskReport?
    internal var adaptiveCachedKey: String?
    internal var adaptiveLastEvaluationAtEpochSeconds: TimeInterval = 0

    internal static let highRiskSignalIds: Set<String> = [
        ObfuscatedConstants.signalFridaDetected,
        SignalID.fridaModuleDetected, SignalID.fridaModuleImage,
        SignalID.fridaModuleSection, SignalID.fridaModuleString, SignalID.fridaModuleTrampoline,
        ObfuscatedConstants.detectorIDFridaHeap, ObfuscatedConstants.signalFridaStalker,
        ObfuscatedConstants.detectorIDFridaSocket, ObfuscatedConstants.detectorIDFridaThread,
        ObfuscatedConstants.signalFridaJSEngineHeap, ObfuscatedConstants.signalFridaStalkerJit,
        ObfuscatedConstants.signalFridaUnixSocket, ObfuscatedConstants.signalFridaExceptionPort,
        SignalID.fridaExceptionPortStartupRace,
        ObfuscatedConstants.signalThreadAnomaly,
        SignalID.hookDetected, ObfuscatedConstants.detectorIDObjCSwizzle, "rwx_memory",
        ObfuscatedConstants.signalArmorRuntimeInitFailed, ObfuscatedConstants.signalIntegrityRuntimeTampered,
        "code_signature_invalid", ObfuscatedConstants.signalTextSegmentTampered,
        ObfuscatedConstants.signalAppSigningIdentityTampered, ObfuscatedConstants.signalAppSigningBaselineChanged,
        SignalID.fridaRuntimeConsensus, SignalID.antiDebugRuntimeConsensus, SignalID.signingChainConsensus,
        ObfuscatedConstants.signalKernelHookTimingAnomaly, ObfuscatedConstants.signalKernelHookStalkerAmplified,
        "system_library_wx_mapping", "system_library_anonymous_exec_region",
        "app_image_segment_layout_anomaly",
        SignalID.antiDebugWatchdogDyldInjection, SignalID.antiDebugWatchdogAMFICsFlags,
        SignalID.antiDebugWatchdogGetTaskAllow, SignalID.antiDebugWatchdogDenyAttachVerify,
        SignalID.dylibInjectImageCountLow, SignalID.ifaceSpawnPathDivergence,
        "dyld_monitor_suspicious_injection", "dyld_monitor_silent_mutation",
        "dyld_image_overload", "dyld_env_abuse"
    ]

    internal static let remoteConfigEndpointKey = "com.cloudphone.riskkit.remote.endpoint"
    internal static let isRunningUnderXCTest: Bool = {
        let env = ProcessInfo.processInfo.environment
        if env["XCTestConfigurationFilePath"] != nil || env["XCTestSessionIdentifier"] != nil { return true }
        let name = ProcessInfo.processInfo.processName.lowercased()
        if name.contains("xctest") || name.contains("swiftpm-xctest-helper") { return true }
        return NSClassFromString("XCTestCase") != nil
    }()
    internal static let remoteTrustLock = UnfairLock()
    internal static var pinnedCertificatePinMaterial: PinnedCertificatePinMaterial = .empty
    internal static let localPolicyInjectionAllowed: Bool = {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }()
    internal static let localRemoteConfigRollbackAllowed: Bool = {
        #if DEBUG
        return ProcessInfo.processInfo.environment["CPRISKKIT_ALLOW_CONFIG_ROLLBACK"] == "1"
        #else
        return false
        #endif
    }()
    internal static let localSynthesizedChallengeBindingAllowed: Bool = {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }()
    internal static let armorRootKeyEnvironmentKey = "CPRISKKIT_ARMOR_ROOT_KEY_HEX"
    #if DEBUG
    internal static let armorDebugFallbackRootKeyHex = "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"
    #endif

    internal var armorRuntimeSnapshot = ArmorRuntimeSnapshot.inactive
    internal var lastLocalAntiDebugMode: CPRiskAntiDebugRuntimeMode = .production
    internal var lastAppliedEffectiveAntiDebugMode: CPRiskAntiDebugRuntimeMode = .production
    internal var lastEnableRemoteConfig: Bool = true
    internal var lastRemoteAppStoreSafeProfileFlag: Bool = false

    // MARK: - Init

    private override init() {
        super.init()
        if let endpoint = UserDefaults.standard.string(forKey: Self.remoteConfigEndpointKey) {
            _ = configureRemoteConfigProvider(urlString: endpoint)
        }
    }

    // MARK: - Public API (thin wrappers — implementations in Core/*.swift extensions)

    @objc public func start() { startImpl() }

    @objc(startWithConfig:)
    public func start(config: CPRiskConfig) { startImpl(config: config) }

    @objc public func stop() { stopImpl() }

    public func protectionStabilitySnapshot() -> ProtectionStabilitySnapshot {
        ProtectionStabilityStore.shared.currentSnapshot()
    }

    @objc public func evaluate() -> CPRiskReport { evaluate(config: .default) }

    @objc(evaluateWithConfig:)
    public func evaluate(config: CPRiskConfig = .default) -> CPRiskReport {
        evaluate(config: config, scenario: config.defaultScenario)
    }

    @objc(evaluateWithConfig:scenario:)
    public func evaluate(config: CPRiskConfig, scenario: RiskScenario) -> CPRiskReport {
        evaluateImpl(config: config, scenario: scenario)
    }

    @available(*, deprecated, message: "Use async/await evaluateAsync() or RiskEvaluationActor.shared.evaluate() instead")
    @objc(evaluateAsyncWithCompletion:)
    public func evaluateAsync(completion: @escaping (CPRiskReport) -> Void) {
        evaluateAsync(config: .default, scenario: .default, completion: completion)
    }

    @available(*, deprecated, message: "Use async/await evaluateAsync(config:) instead")
    @objc(evaluateAsyncWithConfig:completion:)
    public func evaluateAsync(config: CPRiskConfig, completion: @escaping (CPRiskReport) -> Void) {
        evaluateAsync(config: config, scenario: config.defaultScenario, completion: completion)
    }

    @objc(evaluateWithScenario:completion:)
    public func evaluate(scenario: RiskScenario, completion: @escaping (CPRiskReport) -> Void) {
        evaluateAsync(config: .default, scenario: scenario, completion: completion)
    }

    @available(*, deprecated, message: "Use async/await evaluateAsync(config:scenario:) instead")
    public func evaluateAsync(config: CPRiskConfig, scenario: RiskScenario, completion: @escaping (CPRiskReport) -> Void) {
        let cfg = config
        evaluateQueue.async { [self] in
            let report = evaluate(config: cfg, scenario: scenario)
            DispatchQueue.main.async { completion(report) }
        }
    }

    public func buildSecureReportEnvelope(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", attestationKeyId: String? = nil, requireArmor: Bool = true
    ) throws -> ReportEnvelope {
        try buildSecureReportEnvelopeImpl(
            report: report, sessionToken: sessionToken, signingKey: signingKey,
            keyId: keyId, attestationKeyId: attestationKeyId, requireArmor: requireArmor
        )
    }

    public func buildSecureReportEnvelopeJSON(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", prettyPrinted: Bool = false
    ) throws -> String {
        try buildSecureReportEnvelope(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: keyId)
            .toJSONString(prettyPrinted: prettyPrinted)
    }

    public func buildSecureReportEnvelopeGrpcCompatibleJSON(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", appId: String = "", prettyPrinted: Bool = false
    ) throws -> String {
        let envelope = try buildSecureReportEnvelope(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: keyId)
        let ctx = GrpcReportContext(appId: appId, deviceId: report.deviceID, scene: stateLock.withLock { boundSceneTag } ?? "")
        return try envelope.toGrpcCompatibleJSON(context: ctx, prettyPrinted: prettyPrinted)
    }

    public func buildSecureReportEnvelopeGrpcRequestBytes(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", appId: String = ""
    ) throws -> Data {
        let envelope = try buildSecureReportEnvelope(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: keyId)
        let ctx = GrpcReportContext(appId: appId, deviceId: report.deviceID, scene: stateLock.withLock { boundSceneTag } ?? "")
        return try envelope.toGrpcRequestBytes(context: ctx)
    }

    @available(iOS 14.0, macOS 11.0, *)
    public func buildSecureReportEnvelopeWithAttestation(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", requireAttestation: Bool = true
    ) async throws -> ReportEnvelope {
        try await buildSecureReportEnvelopeWithAttestationImpl(
            report: report, sessionToken: sessionToken, signingKey: signingKey,
            keyId: keyId, requireAttestation: requireAttestation)
    }

    internal func debugArmorRuntimeSnapshot() -> ArmorRuntimeDebugSnapshot { debugArmorRuntimeSnapshotImpl() }
    public func antiDebugWatchdogSnapshot() -> AntiDebugWatchdogSnapshot { antiDebugWatchdogSnapshotImpl() }
    public func antiDebugPlanSnapshot() -> AntiDebugPlanSnapshot { antiDebugPlanSnapshotImpl() }

    func validateEnvelopeWithArmorDerivedSignature(
        _ envelope: ReportEnvelope, baseKey: String,
        nonceStore: NonceReplayProtecting? = nil, config: ReportEnvelope.Config = .init()
    ) -> Result<Void, ReportEnvelope.ReportEnvelopeError> {
        let snapshot = ensureArmorRuntimeStarted(trigger: "validate_envelope")
        guard snapshot.status == .active else { return .failure(.signingFailed) }
        guard cprisk_is_integrity_poisoned() == 0 else { return .failure(.signingFailed) }
        return envelope.validate(
            signatureValidator: { Self.verifyWithArmorDerivedKey(baseKey: baseKey, signatureInput: $0, expectedSignature: $1) },
            nonceStore: nonceStore, config: config
        )
    }

    // MARK: - Static Public API

    @objc public static func setLogEnabled(_ enabled: Bool) {
        #if DEBUG
        Logger.isEnabled = enabled
        #endif
    }

    @objc(setExternalServerSignalsPublicIP:asn:asOrg:isDatacenter:ipDeviceAgg:ipAccountAgg:geoCountry:geoRegion:riskTags:)
    public static func setExternalServerSignals(
        publicIP: String?, asn: String?, asOrg: String?, isDatacenter: NSNumber?,
        ipDeviceAgg: NSNumber?, ipAccountAgg: NSNumber?,
        geoCountry: String?, geoRegion: String?, riskTags: [String]?
    ) {
        ExternalServerAggregateProvider.shared.setDebugBypassingVerification(
            ServerSignals(publicIP: publicIP, asn: asn, asOrg: asOrg, isDatacenter: isDatacenter?.boolValue,
                          ipDeviceAgg: ipDeviceAgg?.intValue, ipAccountAgg: ipAccountAgg?.intValue,
                          geoCountry: geoCountry, geoRegion: geoRegion, riskTags: riskTags))
    }

    @objc(setGraphFeaturesWithCommunityId:communityRiskDensity:hwProfileDegree:devicePageRank:isInDenseSubgraph:riskTags:)
    public static func setGraphFeatures(
        communityId: String?, communityRiskDensity: NSNumber?, hwProfileDegree: NSNumber?,
        devicePageRank: NSNumber?, isInDenseSubgraph: NSNumber?, riskTags: [String]?
    ) {
        ExternalServerAggregateProvider.shared.setGraphFeatures(
            communityId: communityId, communityRiskDensity: communityRiskDensity?.doubleValue,
            hwProfileDegree: hwProfileDegree?.intValue, devicePageRank: devicePageRank?.doubleValue,
            isInDenseSubgraph: isInDenseSubgraph?.boolValue, riskTags: riskTags)
    }

    @objc public static func configureServerSigningKey(_ key: String) {
        ConfigSignatureVerifier.configure(serverSigningKey: key)
        shared.refreshRemoteTrustState()
    }

    @objc public static func configurePinnedCertificateHashes(_ hashes: [String]) {
        let material = PinnedCertificatePinMaterial(pinStrings: normalizedPinnedCertificateHashes(from: hashes))
        remoteTrustLock.withLock { pinnedCertificatePinMaterial = material }
        PolicyManager.shared.configurePinning(pinMaterial: material)
        shared.applyPinnedCertificateHashes(material)
    }

    @objc public static func clearExternalServerSignals() { ExternalServerAggregateProvider.shared.clear() }

    @objc(setRealtimeTelemetryFeedbackWithRiskPressure:minEvaluationIntervalMillis:defaultWeightScaleBps:jailbreakWeightScaleBps:networkWeightScaleBps:behaviorWeightScaleBps:deviceWeightScaleBps:timeWeightScaleBps:ttlSeconds:)
    public static func setRealtimeTelemetryFeedback(
        riskPressure: NSNumber?, minEvaluationIntervalMillis: NSNumber?, defaultWeightScaleBps: NSNumber?,
        jailbreakWeightScaleBps: NSNumber?, networkWeightScaleBps: NSNumber?, behaviorWeightScaleBps: NSNumber?,
        deviceWeightScaleBps: NSNumber?, timeWeightScaleBps: NSNumber?, ttlSeconds: NSNumber?
    ) {
        var cs: [String: Int] = [:]
        if let v = jailbreakWeightScaleBps?.intValue { cs["jailbreak"] = v }
        if let v = networkWeightScaleBps?.intValue { cs["network"] = v }
        if let v = behaviorWeightScaleBps?.intValue { cs["behavior"] = v }
        if let v = deviceWeightScaleBps?.intValue { cs["device"] = v }
        if let v = timeWeightScaleBps?.intValue { cs["time"] = v }
        let exp = ttlSeconds.map { Date().timeIntervalSince1970 + max(0, TimeInterval($0.intValue)) }
        ExternalServerAggregateProvider.shared.setRealtimeTelemetryFeedback(
            .init(riskPressure: riskPressure?.doubleValue, minEvaluationIntervalMillis: minEvaluationIntervalMillis?.intValue,
                  defaultWeightScaleBps: defaultWeightScaleBps?.intValue, categoryWeightScaleBps: cs, expiresAtEpochSeconds: exp))
    }

    @objc public static func clearRealtimeTelemetryFeedback() { ExternalServerAggregateProvider.shared.clearRealtimeTelemetryFeedback() }
    public static func applyGraphRiskFeedback(_ feedback: GraphRiskFeedback) { ExternalServerAggregateProvider.shared.applyGraphRiskFeedback(feedback) }

    public static func applyChallengeResult(_ result: ChallengeVerificationResult) {
        if let s = ChallengeSession.shared.verifyResult(result) { ChallengeResultStore.shared.storePendingMismatchSignal(s); return }
        ChallengeResultStore.shared.apply(result: result)
    }

    @objc(applyChallengeResultWithChallengeId:passed:failedProbes:adjustedScore:)
    public static func applyChallengeResult(challengeId: String, passed: Bool, failedProbes: [String], adjustedScore: NSNumber?) {
        applyChallengeResult(ChallengeVerificationResult(challengeId: challengeId, passed: passed, failedProbes: failedProbes, adjustedScore: adjustedScore?.doubleValue))
    }

    @objc public func bindAccount(_ accountId: String, scene: String? = nil) {
        stateLock.withLock { boundAccountId = accountId; boundSceneTag = scene }
    }

    @objc public func unbindAccount() {
        resetArmorRuntime()
        stateLock.withLock { boundAccountId = nil; boundSceneTag = nil; currentSessionId = nil; previousSignalIds = []; previousSignalsDigest = nil }
        PolicyManager.shared.clearCachedPolicy()
        LocalDeviceClusterDetector.shared.clear()
    }

    @objc(setServerRiskPolicyJSON:) @discardableResult
    public func setServerRiskPolicyJSON(_ json: String) -> Bool {
        guard Self.localPolicyInjectionAllowed else { return false }
        return PolicyManager.shared.update(fromJSON: json)
    }

    @objc public func clearServerRiskPolicy() { PolicyManager.shared.clear() }
    public static func register(provider: RiskSignalProvider) { RiskSignalProviderRegistry.shared.register(provider) }
    public static func unregisterProvider(id: String) { RiskSignalProviderRegistry.shared.unregister(id: id) }
    public static func registeredProviderIDs() -> [String] { RiskSignalProviderRegistry.shared.listIDs() }

    @discardableResult @objc(setRemoteConfigEndpoint:)
    public func setRemoteConfigEndpoint(_ endpoint: String) -> Bool { configureRemoteConfigProvider(urlString: endpoint) }

    @objc public func clearRemoteConfigEndpoint() {
        stateLock.withLock { remoteConfigProvider = nil; remoteConfigEndpoint = nil; latestRemoteConfig = nil; lastRemoteAppStoreSafeProfileFlag = false }
        reapplyAntiDebugRuntimeModeAfterRemoteConfigChange()
        UserDefaults.standard.removeObject(forKey: Self.remoteConfigEndpointKey)
    }

    @discardableResult @objc(setRemoteConfigJSON:)
    public func setRemoteConfigJSON(_ json: String) -> Bool {
        guard Self.localPolicyInjectionAllowed else { return false }
        guard let config = RemoteConfig.from(jsonString: json) else { return false }
        return applyRemoteConfigIfAccepted(config, source: "inject_json", validateStrictly: false)
    }

    @objc(updateRemoteConfigWithCompletion:)
    public func updateRemoteConfig(completion: @escaping (Bool) -> Void) {
        guard let provider = currentRemoteConfigProvider() else { DispatchQueue.main.async { completion(false) }; return }
        provider.fetchLatest { [weak self] result in
            switch result {
            case .success(let config):
                let ok = self?.applyRemoteConfigIfAccepted(config, source: "fetch_latest") ?? false
                DispatchQueue.main.async { completion(ok) }
            case .failure:
                DispatchQueue.main.async { completion(false) }
            }
        }
    }

    public func setTextSegmentReferenceResolver(_ resolver: (any TextSegmentReferenceResolving)?) {
        stateLock.withLock { textSegmentReferenceResolver = resolver }
    }
}
