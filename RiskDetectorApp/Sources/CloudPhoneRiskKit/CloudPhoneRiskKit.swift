import CryptoKit
import Foundation
#if canImport(UIKit)
import UIKit
#endif

@objc(CPRiskKit)
public final class CPRiskKit: NSObject {
    @objc public static let shared = CPRiskKit()

    public enum SecureUploadError: Error, LocalizedError {
        case payloadFieldMappingRequired
        case payloadFieldMappingExpired(version: String)
        case invalidPayloadShape

        public var errorDescription: String? {
            switch self {
            case .payloadFieldMappingRequired:
                return "当前策略要求字段混淆，但 payloadFieldMapping 未下发"
            case .payloadFieldMappingExpired(let version):
                return "payloadFieldMapping 已过期（version=\(version)）"
            case .invalidPayloadShape:
                return "上报 payload 结构无效，无法构建安全信封"
            }
        }
    }

#if canImport(UIKit)
    private let touchCapture = TouchCapture.shared
    private let motionSampler = MotionSampler.shared
    private let jailbreakEngine = JailbreakEngine()
#else
    private let jailbreakEngine = JailbreakEngine()
#endif

    private let evaluateQueue = DispatchQueue(label: "CloudPhoneRiskKit.Evaluate", qos: .utility)
    private let stateLock = NSLock()

    private var remoteConfigProvider: RemoteConfigProvider?
    private var remoteConfigEndpoint: URL?
    private var latestRemoteConfig: RemoteConfig?

    private var boundAccountId: String?
    private var boundSceneTag: String?
    private var currentSessionId: String?

    private static let remoteConfigEndpointKey = "com.cloudphone.riskkit.remote.endpoint"
    private static let localPolicyInjectionAllowed: Bool = {
#if DEBUG
        return true
#else
        return false
#endif
    }()
    private static let localRemoteConfigRollbackAllowed: Bool = {
#if DEBUG
        return ProcessInfo.processInfo.environment["CPRISKKIT_ALLOW_CONFIG_ROLLBACK"] == "1"
#else
        return false
#endif
    }()

    private struct CapabilityProbeRuntimeResult {
        let score: CapabilityScore
        let probes: [ProbeResult]
    }

    private override init() {
        super.init()
        if let endpoint = UserDefaults.standard.string(forKey: Self.remoteConfigEndpointKey) {
            _ = configureRemoteConfigProvider(urlString: endpoint)
        }
    }

    /// 启动自动采集（全局触摸 + 传感器）。
    /// 建议在 `application(_:didFinishLaunchingWithOptions:)` 里尽早调用。
    @objc public func start() {
        BuildConfig.configureForRelease()
        stateLock.lock()
        currentSessionId = UUID().uuidString
        stateLock.unlock()
        Logger.log("start() sessionId=\(currentSessionId ?? "")")
        registerProviders(for: .default)
        RiskSignalProviderRegistry.shared.seal()
#if canImport(UIKit)
        touchCapture.start()
        motionSampler.start()
#endif
    }

    @objc public func stop() {
        Logger.log("stop()")
#if canImport(UIKit)
        motionSampler.stop()
        touchCapture.stop()
#endif
    }

    @objc public static func setLogEnabled(_ enabled: Bool) {
#if DEBUG
        Logger.isEnabled = enabled
        Logger.log("Logger.isEnabled=\(enabled)")
#endif
    }

    @objc(setExternalServerSignalsPublicIP:asn:asOrg:isDatacenter:ipDeviceAgg:ipAccountAgg:geoCountry:geoRegion:riskTags:)
    public static func setExternalServerSignals(
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
        ExternalServerAggregateProvider.shared.set(
            ServerSignals(
                publicIP: publicIP,
                asn: asn,
                asOrg: asOrg,
                isDatacenter: isDatacenter?.boolValue,
                ipDeviceAgg: ipDeviceAgg?.intValue,
                ipAccountAgg: ipAccountAgg?.intValue,
                geoCountry: geoCountry,
                geoRegion: geoRegion,
                riskTags: riskTags
            )
        )
    }

    /// 注入图算法反哺的特征（社区 ID、风险密度、PageRank 等）。
    /// 服务端图分析完成后回传给 SDK，用于增强本地评分。
    @objc(setGraphFeaturesWithCommunityId:communityRiskDensity:hwProfileDegree:devicePageRank:isInDenseSubgraph:riskTags:)
    public static func setGraphFeatures(
        communityId: String?,
        communityRiskDensity: NSNumber?,
        hwProfileDegree: NSNumber?,
        devicePageRank: NSNumber?,
        isInDenseSubgraph: NSNumber?,
        riskTags: [String]?
    ) {
        ExternalServerAggregateProvider.shared.setGraphFeatures(
            communityId: communityId,
            communityRiskDensity: communityRiskDensity?.doubleValue,
            hwProfileDegree: hwProfileDegree?.intValue,
            devicePageRank: devicePageRank?.doubleValue,
            isInDenseSubgraph: isInDenseSubgraph?.boolValue,
            riskTags: riskTags
        )
    }

    @objc public static func configureServerSigningKey(_ key: String) {
        ConfigSignatureVerifier.configure(serverSigningKey: key)
        Logger.log("server_signing_key configured")
    }

    @objc public static func clearExternalServerSignals() {
        ExternalServerAggregateProvider.shared.set(nil)
    }

    /// 绑定业务账号 ID，用于设备-账号关联图构建。
    /// - Parameters:
    ///   - accountId: 业务侧的用户/账号唯一标识
    ///   - scene: 当前业务场景标签（如 "login", "register", "payment"）
    @objc public func bindAccount(_ accountId: String, scene: String? = nil) {
        stateLock.lock()
        boundAccountId = accountId
        boundSceneTag = scene
        stateLock.unlock()
        Logger.log("account.bind: accountId=\(accountId) scene=\(scene ?? "nil")")
    }

    /// 解绑业务账号（用户登出时调用）。
    @objc public func unbindAccount() {
        stateLock.lock()
        boundAccountId = nil
        boundSceneTag = nil
        stateLock.unlock()
        Logger.log("account.unbind")
    }

    /// 注入服务端策略（JSON 字符串）。
    /// 支持离线缓存，重启后仍可生效。
    @objc(setServerRiskPolicyJSON:)
    @discardableResult
    public func setServerRiskPolicyJSON(_ json: String) -> Bool {
        guard Self.localPolicyInjectionAllowed else {
            Logger.log("server_policy.update_json rejected: local injection disabled in release build")
            return false
        }

        let ok = PolicyManager.shared.update(fromJSON: json)
        Logger.log("server_policy.update_json: \(ok ? "success" : "failed")")
        return ok
    }

    /// 清空服务端策略缓存，回退本地默认策略。
    @objc public func clearServerRiskPolicy() {
        PolicyManager.shared.clear()
        Logger.log("server_policy.clear_cache")
    }

    /// Register a custom signal provider (Swift only).
    public static func register(provider: RiskSignalProvider) {
        RiskSignalProviderRegistry.shared.register(provider)
        Logger.log("provider.register: id=\(provider.id)")
    }

    public static func unregisterProvider(id: String) {
        RiskSignalProviderRegistry.shared.unregister(id: id)
        Logger.log("provider.unregister: id=\(id)")
    }

    public static func registeredProviderIDs() -> [String] {
        RiskSignalProviderRegistry.shared.listIDs()
    }

    // MARK: - Remote Config (2.0)

    /// 设置远程配置地址（持久化保存）。
    @discardableResult
    @objc(setRemoteConfigEndpoint:)
    public func setRemoteConfigEndpoint(_ endpoint: String) -> Bool {
        configureRemoteConfigProvider(urlString: endpoint)
    }

    /// 清除远程配置地址和缓存状态。
    @objc public func clearRemoteConfigEndpoint() {
        stateLock.lock()
        remoteConfigProvider = nil
        remoteConfigEndpoint = nil
        latestRemoteConfig = nil
        stateLock.unlock()

        UserDefaults.standard.removeObject(forKey: Self.remoteConfigEndpointKey)
        Logger.log("remote_config.endpoint cleared")
    }

    /// 直接注入远程配置 JSON（用于灰度联调、离线测试和回归）。
    /// 成功后会覆盖内存中的 latestRemoteConfig，但不会写入 endpoint。
    @discardableResult
    @objc(setRemoteConfigJSON:)
    public func setRemoteConfigJSON(_ json: String) -> Bool {
        guard Self.localPolicyInjectionAllowed else {
            Logger.log("remote_config.inject rejected: local injection disabled in release build")
            return false
        }

        guard let config = RemoteConfig.from(jsonString: json) else {
            Logger.log("remote_config.inject failed: invalid json")
            return false
        }

        guard applyRemoteConfigIfAccepted(config, source: "inject_json", validateStrictly: false) else {
            return false
        }

        Logger.log("remote_config.inject success: version=\(config.version)")
        return true
    }

    /// 更新远程配置（2.0 API）。
    @objc(updateRemoteConfigWithCompletion:)
    public func updateRemoteConfig(completion: @escaping (Bool) -> Void) {
        guard let provider = currentRemoteConfigProvider() else {
            Logger.log("remote_config.update skipped: endpoint not configured")
            DispatchQueue.main.async { completion(false) }
            return
        }

        provider.fetchLatest { [weak self] result in
            switch result {
            case .success(let config):
                guard let self else {
                    DispatchQueue.main.async { completion(false) }
                    return
                }
                let accepted = self.applyRemoteConfigIfAccepted(config, source: "fetch_latest")
                if accepted {
                    Logger.log("remote_config.update success: version=\(config.version)")
                } else {
                    Logger.log("remote_config.update rejected: version=\(config.version)")
                }
                DispatchQueue.main.async { completion(accepted) }
            case .failure(let error):
                Logger.log("remote_config.update failed: \(error.localizedDescription)")
                DispatchQueue.main.async { completion(false) }
            }
        }
    }

    // MARK: - Evaluation

    @objc public func evaluate() -> CPRiskReport {
        evaluate(config: .default)
    }

    /// 生成一次完整风控报告（保持 1.0 入口，内部走 2.0 决策链路）。
    @objc(evaluateWithConfig:)
    public func evaluate(config: CPRiskConfig = .default) -> CPRiskReport {
        evaluate(config: config, scenario: config.defaultScenario)
    }

    /// 同步场景化评估（2.0 核心入口，Swift/ObjC 可用）。
    @objc(evaluateWithConfig:scenario:)
    public func evaluate(config: CPRiskConfig, scenario: RiskScenario) -> CPRiskReport {
        var runtimeConfig = resolveRuntimeConfig(from: config)
        enforceSecurityFloor(&runtimeConfig)
        let remoteConfig = config.enableRemoteConfig ? currentRemoteConfig() : nil

        Logger.log(
            "evaluate(config,scenario): scenario=\(scenario.identifier) threshold=\(runtimeConfig.threshold) " +
            "behavior=\(runtimeConfig.enableBehaviorDetect) network=\(runtimeConfig.enableNetworkSignals) " +
            "remote=\(remoteConfig != nil) temporal=\(config.enableTemporalAnalysis) antiTamper=\(config.enableAntiTamper)"
        )

        registerProviders(for: config)

        let context = buildRiskContext(config: runtimeConfig)
        let snapshot = RiskSnapshot(
            deviceID: context.deviceID,
            device: context.device,
            network: context.network,
            behavior: context.behavior,
            jailbreak: context.jailbreak
        )
        let capabilityRuntime = runCapabilityProbe(remoteConfig: remoteConfig)
        var extraSignals = RiskSignalProviderRegistry.shared.signals(snapshot: snapshot)
        extraSignals.append(capabilityRuntime.score.toSignal())

        let serverPolicy = PolicyManager.shared.activePolicy
        let policy = buildEnginePolicy(
            runtimeConfig: runtimeConfig,
            remoteConfig: remoteConfig,
            enableTemporalAnalysis: config.enableTemporalAnalysis,
            serverPolicy: serverPolicy
        )
        let decisionEngine = RiskDetectionEngine(policy: policy, enableLogging: Logger.isEnabled)
        let verdict = decisionEngine.evaluate(
            context: context,
            scenario: scenario,
            extraSignals: extraSignals
        )

        let scoreReport = RiskScoreReport(
            score: verdict.score,
            isHighRisk: verdict.isHighRisk,
            signals: verdict.signals,
            summary: verdict.summary
        )

        Logger.log(
            "final: score=\(scoreReport.score) isHighRisk=\(scoreReport.isHighRisk) " +
            "signals=\(scoreReport.signals.count) summary=\(scoreReport.summary)"
        )

        let out = CPRiskReport(context: context, report: scoreReport)
        out.setServerSignals(RiskSignalProviderRegistry.shared.serverSignals(snapshot: snapshot))
        stateLock.lock()
        let acctId = boundAccountId
        let sessId = currentSessionId
        let scnTag = boundSceneTag
        stateLock.unlock()
        out.setGraphBindings(accountId: acctId, sessionId: sessId, sceneTag: scnTag)

        RiskHistoryStore.shared.append(
            RiskHistoryEvent(
                t: Date().timeIntervalSince1970,
                score: scoreReport.score,
                isHighRisk: scoreReport.isHighRisk,
                summary: scoreReport.summary
            )
        )

        let pattern = RiskHistoryStore.shared.pattern()
        out.setLocalSignals(
            LocalSignals(
                timePattern: pattern,
                cloudPhone: CloudPhoneLocalSignalsBuilder.build(
                    device: context.device,
                    behavior: context.behavior,
                    timePattern: pattern
                )
            )
        )

        if let challengeBinding = buildChallengeBindingIfNeeded(
            remoteConfig: remoteConfig,
            serverPolicy: serverPolicy,
            capabilityRuntime: capabilityRuntime,
            signals: verdict.signals,
            deviceID: context.deviceID
        ) {
            out.setChallengeBinding(challengeBinding)
            Logger.log(
                "challenge.binding: challengeId=\(challengeBinding.challengeId) " +
                "probes=\(challengeBinding.probeIds.count) reason=\(challengeBinding.triggerReason ?? "n/a")"
            )
        }

        return out
    }

    /// 构建安全上报信封（签名 + nonce + 可选字段混淆）。
    ///
    /// 默认读取当前 `RemoteConfig.securityHardening` 与 `payloadFieldMapping`：
    /// - `enforcePayloadFieldMapping=true` 且映射缺失/过期时会抛错。
    /// - `enableEnvelopeSignatureV2=false` 时自动降级为 v1 签名串格式。
    public func buildSecureReportEnvelope(
        report: CPRiskReport,
        sessionToken: String,
        signingKey: String,
        keyId: String = "k1"
    ) throws -> ReportEnvelope {
        let remoteConfig = currentRemoteConfig()
        let hardening = remoteConfig?.securityHardening ?? .default

        var mapping = remoteConfig?.payloadFieldMapping
        if let currentMapping = mapping, currentMapping.isExpired() {
            if hardening.enforcePayloadFieldMapping {
                throw SecureUploadError.payloadFieldMappingExpired(version: currentMapping.version)
            }
            mapping = nil
        }

        if hardening.enforcePayloadFieldMapping, mapping == nil {
            throw SecureUploadError.payloadFieldMappingRequired
        }

        var payloadData = report.jsonData(prettyPrinted: false)
        if !hardening.enableChallengeBinding {
            payloadData = try removingPayloadKey("challengeBinding", from: payloadData)
        }

        let signatureVersion = hardening.enableEnvelopeSignatureV2 ? "v2" : "v1"
        let envelopeConfig = ReportEnvelope.Config(signatureVersion: signatureVersion)

        return try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: report.reportID,
            sessionToken: sessionToken,
            signingKey: signingKey,
            keyId: keyId,
            fieldMapping: mapping,
            config: envelopeConfig
        )
    }

    public func buildSecureReportEnvelopeJSON(
        report: CPRiskReport,
        sessionToken: String,
        signingKey: String,
        keyId: String = "k1",
        prettyPrinted: Bool = false
    ) throws -> String {
        let envelope = try buildSecureReportEnvelope(
            report: report,
            sessionToken: sessionToken,
            signingKey: signingKey,
            keyId: keyId
        )
        return try envelope.toJSONString(prettyPrinted: prettyPrinted)
    }

    /// 异步生成报告（避免在主线程做重活）。
    /// completion 始终回到主线程。
    @objc(evaluateAsyncWithCompletion:)
    public func evaluateAsync(completion: @escaping (CPRiskReport) -> Void) {
        evaluateAsync(config: .default, scenario: .default, completion: completion)
    }

    /// 异步生成报告（保持 1.0 API）。
    /// completion 始终回到主线程。
    @objc(evaluateAsyncWithConfig:completion:)
    public func evaluateAsync(config: CPRiskConfig, completion: @escaping (CPRiskReport) -> Void) {
        evaluateAsync(config: config, scenario: config.defaultScenario, completion: completion)
    }

    /// 异步场景化评估（2.0 API）。
    @objc(evaluateWithScenario:completion:)
    public func evaluate(
        scenario: RiskScenario,
        completion: @escaping (CPRiskReport) -> Void
    ) {
        evaluateAsync(config: .default, scenario: scenario, completion: completion)
    }

    /// 异步场景化评估（带配置）。
    public func evaluateAsync(
        config: CPRiskConfig,
        scenario: RiskScenario,
        completion: @escaping (CPRiskReport) -> Void
    ) {
        let cfg = config
        evaluateQueue.async {
            let report = self.evaluate(config: cfg, scenario: scenario)
            DispatchQueue.main.async {
                completion(report)
            }
        }
    }

    // MARK: - Internal Helpers

    private func registerProviders(for config: CPRiskConfig) {
        RiskSignalProviderRegistry.shared.register(ExternalServerAggregateProvider.shared)
        RiskSignalProviderRegistry.shared.register(DeviceHardwareProvider.shared)
        RiskSignalProviderRegistry.shared.register(DeviceAgeProvider.shared)
        RiskSignalProviderRegistry.shared.register(VPhoneHardwareProvider.shared)
        RiskSignalProviderRegistry.shared.register(LayeredConsistencyProvider.shared)
        RiskSignalProviderRegistry.shared.register(MountPointProvider.shared)
        RiskSignalProviderRegistry.shared.register(DRMCapabilityProvider.shared)
        RiskSignalProviderRegistry.shared.register(BatteryEntropyProvider.shared)

        if config.enableTemporalAnalysis {
            RiskSignalProviderRegistry.shared.register(TimePatternProvider.shared)
        } else {
            RiskSignalProviderRegistry.shared.unregister(id: TimePatternProvider.shared.id)
        }

        RiskSignalProviderRegistry.shared.register(AntiTamperingSignalProvider())
    }

    private func runCapabilityProbe(remoteConfig: RemoteConfig?) -> CapabilityProbeRuntimeResult {
        let engine: CapabilityProbeEngine
        if let probeConfig = remoteConfig?.probeConfig {
            engine = CapabilityProbeEngine.fromRemoteConfig(probeConfig)
        } else {
            engine = CapabilityProbeEngine()
        }

        let detailed = engine.evaluateDetailed()
        Logger.log(
            "capability.probe: anomaly=\(detailed.score.basicAnomalyCount) " +
            "quality=\(detailed.score.qualitySuspicion) total=\(detailed.score.totalProbes)"
        )

        return CapabilityProbeRuntimeResult(score: detailed.score, probes: detailed.probes)
    }

    private func buildChallengeBindingIfNeeded(
        remoteConfig: RemoteConfig?,
        serverPolicy: ServerRiskPolicy?,
        capabilityRuntime: CapabilityProbeRuntimeResult,
        signals: [RiskSignal],
        deviceID: String
    ) -> ChallengeBindingPayload? {
        let hardening = remoteConfig?.securityHardening ?? .default
        guard hardening.enableChallengeBinding else {
            return nil
        }

        guard let blindConfig = serverPolicy?.blindChallenge, blindConfig.enabled else {
            Logger.log("challenge.binding skipped: missing server blindChallenge context")
            return nil
        }

        if blindConfig.probePool.isEmpty {
            Logger.log("challenge.binding skipped: probePool is empty")
            return nil
        }

        let tamperedCount = signals.reduce(into: 0) { partialResult, signal in
            if case .tampered? = signal.state {
                partialResult += 1
            }
        }

        let blindRules = blindConfig.rules
        let trigger = ChallengeTrigger.shouldTriggerBlindChallenge(
            capabilityScore: capabilityRuntime.score,
            tamperedCount: tamperedCount,
            existingRules: blindRules
        )
        guard trigger.triggered else {
            return nil
        }

        guard let challenge = buildBlindChallenge(config: blindConfig, deviceID: deviceID) else {
            Logger.log("challenge.binding skipped: failed to build challenge from server config")
            return nil
        }
        guard ChallengeTrigger.isChallengeValid(challenge) else {
            return nil
        }

        return ChallengeTrigger.buildChallengeBindingPayload(
            challenge: challenge,
            capabilityScore: capabilityRuntime.score,
            tamperedCount: tamperedCount,
            executedProbeIDs: capabilityRuntime.probes.map(\.id),
            triggerReason: trigger.reason
        )
    }

    private func buildBlindChallenge(
        config: ServerRiskPolicy.BlindChallengeConfig,
        deviceID: String
    ) -> ChallengeTrigger.BlindChallenge? {
        let now = ChallengeTrigger.nowMillis()
        let ttl = max(10_000, config.challengeTTLMillis)
        let salt = config.challengeSalt.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !salt.isEmpty else {
            return nil
        }

        let seedSource = "\(salt)|\(deviceID)|\(now)"
        let selectedProbeIDs = selectChallengeProbeIDs(
            source: config.probePool,
            seedSource: seedSource
        )
        guard !selectedProbeIDs.isEmpty else {
            return nil
        }

        let challengeSeed = "\(salt):\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        return ChallengeTrigger.BlindChallenge(
            challengeId: UUID().uuidString,
            probeIds: selectedProbeIDs,
            seed: challengeSeed,
            expiresAt: now + ttl
        )
    }

    private func selectChallengeProbeIDs(
        source: [String],
        seedSource: String,
        maxCount: Int = 3
    ) -> [String] {
        let normalized = Array(Set(source.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty })).sorted()
        guard !normalized.isEmpty else {
            return []
        }

        let rolling = seedSource.utf8.reduce(0) { partial, byte in
            ((partial &* 31) &+ Int(byte)) & 0x7fffffff
        }
        let start = rolling % normalized.count

        var selected: [String] = []
        selected.reserveCapacity(min(maxCount, normalized.count))
        for index in 0..<min(maxCount, normalized.count) {
            selected.append(normalized[(start + index) % normalized.count])
        }
        return selected
    }

    private func removingPayloadKey(_ key: String, from payloadData: Data) throws -> Data {
        guard var object = try JSONSerialization.jsonObject(with: payloadData, options: []) as? [String: Any] else {
            throw SecureUploadError.invalidPayloadShape
        }
        object.removeValue(forKey: key)
        guard JSONSerialization.isValidJSONObject(object) else {
            throw SecureUploadError.invalidPayloadShape
        }
        return try JSONSerialization.data(withJSONObject: object, options: [])
    }

    private func enforceSecurityFloor(_ config: inout RiskConfig) {
        config.jailbreak.enableFileDetect = true
        config.jailbreak.enableDyldDetect = true
        config.jailbreak.enableSysctlDetect = true
        if config.jailbreak.threshold > 100 {
            config.jailbreak.threshold = 50
        }
        if config.threshold > 100 {
            config.threshold = 55
        }
    }

    private func resolveRuntimeConfig(from config: CPRiskConfig) -> RiskConfig {
        var resolved: RiskConfig

        if config.enableRemoteConfig {
            _ = configureRemoteConfigProvider(urlString: config.remoteConfigURLString)
            if let remoteConfig = currentRemoteConfig() {
                resolved = remoteConfig.toRiskConfig()
            } else {
                resolved = config.toSwift()
            }
        } else {
            resolved = config.toSwift()
        }

        if !config.enableAntiTamper {
            resolved.jailbreak.enableHookDetect = false
        }

        return resolved
    }

    private func buildRiskContext(config: RiskConfig) -> RiskContext {
#if canImport(UIKit)
        let (touchMetrics, actionTimestamps) = touchCapture.snapshotDetailAndReset()
        let (motionMetrics, motionSeries) = motionSampler.snapshotDetailAndReset()
        let coupling = BehaviorCoupling.touchMotionCorrelation(
            actionTimestamps: actionTimestamps,
            motion: motionSeries
        )
        Logger.log("behavior.coupling: actions=\(actionTimestamps.count) corr=\(coupling?.description ?? "nil")")

        return RiskContext(
            device: DeviceFingerprint.current(),
            deviceID: KeychainDeviceID.shared.getOrCreate(),
            network: NetworkSignals.current(),
            behavior: BehaviorSignals(
                touch: touchMetrics,
                motion: motionMetrics,
                touchMotionCorrelation: coupling,
                actionCount: actionTimestamps.count
            ),
            jailbreak: jailbreakEngine.detect(config: config.jailbreak)
        )
#else
        return RiskContext(
            device: DeviceFingerprint.current(),
            deviceID: KeychainDeviceID.shared.getOrCreate(),
            network: NetworkSignals.current(),
            behavior: BehaviorSignals(
                touch: TouchMetrics(
                    sampleCount: 0,
                    tapCount: 0,
                    swipeCount: 0,
                    coordinateSpread: nil,
                    intervalCV: nil,
                    averageLinearity: nil,
                    forceVariance: nil,
                    majorRadiusVariance: nil
                ),
                motion: .empty
            ),
            jailbreak: DetectionResult(
                isJailbroken: false,
                confidence: 0,
                detectedMethods: [],
                details: "unsupported_platform"
            )
        )
#endif
    }

    private func buildEnginePolicy(
        runtimeConfig: RiskConfig,
        remoteConfig: RemoteConfig?,
        enableTemporalAnalysis: Bool,
        serverPolicy: ServerRiskPolicy?
    ) -> EnginePolicy {
        let remoteWeights = remoteConfig.map { config in
            SignalWeights(
                jailbreak: config.policy.weights.jailbreak,
                network: config.policy.weights.network,
                behavior: config.policy.weights.behavior,
                device: config.policy.weights.cloudPhone,
                time: enableTemporalAnalysis ? config.policy.weights.timePattern : 0
            )
        }

        let serverHigh = serverPolicy?.thresholds.challenge
        let highThreshold = max(1, min(100, serverHigh ?? runtimeConfig.threshold))
        let remoteMedium = remoteConfig?.policy.mediumThreshold

        var scenarioPolicies: [RiskScenario: ScenarioPolicy] = [:]
        for scenario in RiskScenario.allCases {
            let base = ScenarioPolicy.policy(for: scenario)
            let rawMedium = serverPolicy?.thresholds.monitor ?? remoteMedium ?? base.mediumThreshold
            let mediumThreshold = max(0, min(highThreshold - 1, rawMedium))
            let serverCritical = serverPolicy?.thresholds.block
            let criticalThreshold = min(
                100,
                max(highThreshold + 1, serverCritical ?? max(base.criticalThreshold, highThreshold + 20))
            )

            let effectiveWeights: SignalWeights
            if let remoteWeights {
                effectiveWeights = remoteWeights
            } else if enableTemporalAnalysis {
                effectiveWeights = base.signalWeights
            } else {
                effectiveWeights = SignalWeights(
                    jailbreak: base.signalWeights.jailbreak,
                    network: base.signalWeights.network,
                    behavior: base.signalWeights.behavior,
                    device: base.signalWeights.device,
                    time: 0
                )
            }

            scenarioPolicies[scenario] = ScenarioPolicy(
                mediumThreshold: mediumThreshold,
                highThreshold: highThreshold,
                criticalThreshold: criticalThreshold,
                actionMapping: base.actionMapping,
                signalWeights: effectiveWeights,
                comboRules: base.comboRules,
                enableForceRules: base.enableForceRules
            )
        }

        let mutationStrategy = serverPolicy?.mutation.map { mutation in
            MutationStrategy(
                seed: mutation.seed,
                shuffleChecks: mutation.shuffleChecks,
                thresholdJitterBps: mutation.thresholdJitterBps,
                scoreJitterBps: mutation.scoreJitterBps
            )
        }

        let blindChallengePolicy = serverPolicy?.blindChallenge.map { challenge in
            BlindChallengePolicy(
                enabled: challenge.enabled,
                challengeSalt: challenge.challengeSalt,
                windowSeconds: challenge.windowSeconds,
                rules: challenge.rules.map { rule in
                    BlindChallengeRule(
                        id: rule.id,
                        allOfSignalIDs: rule.allOfSignalIDs,
                        anyOfSignalIDs: rule.anyOfSignalIDs,
                        minTamperedCount: rule.minTamperedCount,
                        minDistinctRiskLayers: rule.minDistinctRiskLayers,
                        requireCrossLayerInconsistency: rule.requireCrossLayerInconsistency,
                        weight: rule.weight
                    )
                }
            )
        }

        return EnginePolicy(
            name: remoteConfig.map { "remote_\($0.version)" } ?? "local_sdk3",
            version: remoteConfig.map { String($0.version) } ?? "3.0-local",
            enableNetworkSignals: runtimeConfig.enableNetworkSignals,
            enableBehaviorDetection: runtimeConfig.enableBehaviorDetect,
            enableDeviceFingerprint: true,
            forceActionOnJailbreak: .block,
            signalWeightOverrides: serverPolicy?.signalWeights ?? [:],
            mutationStrategy: mutationStrategy,
            blindChallengePolicy: blindChallengePolicy,
            serverBlocklist: serverPolicy?.blocklist,
            blocklistAction: (serverPolicy?.blocklist.isEmpty == false) ? .block : nil,
            scenarioPolicies: scenarioPolicies
        )
    }

    private func currentRemoteConfigProvider() -> RemoteConfigProvider? {
        stateLock.lock()
        let provider = remoteConfigProvider
        let endpoint = remoteConfigEndpoint
        stateLock.unlock()

        if let provider {
            return provider
        }

        if let endpoint {
            _ = configureRemoteConfigProvider(urlString: endpoint.absoluteString)
        } else if let persisted = UserDefaults.standard.string(forKey: Self.remoteConfigEndpointKey) {
            _ = configureRemoteConfigProvider(urlString: persisted)
        }

        stateLock.lock()
        let refreshed = remoteConfigProvider
        stateLock.unlock()
        return refreshed
    }

    private func currentRemoteConfig() -> RemoteConfig? {
        stateLock.lock()
        let cached = latestRemoteConfig
        let provider = remoteConfigProvider
        stateLock.unlock()

        if let cached {
            return cached
        }

        return provider?.currentConfig
    }

    @discardableResult
    private func configureRemoteConfigProvider(urlString: String?) -> Bool {
        guard let rawURL = urlString?.trimmingCharacters(in: .whitespacesAndNewlines), !rawURL.isEmpty else {
            return false
        }
        guard
            let url = URL(string: rawURL),
            let scheme = url.scheme?.lowercased(),
            scheme == "https" || scheme == "http"
        else {
            Logger.log("remote_config.endpoint invalid: \(urlString ?? "nil")")
            return false
        }

#if !DEBUG
        if scheme == "http" {
            Logger.log("remote_config.endpoint rejected: http not allowed in release build, use https")
            return false
        }
#endif

        stateLock.lock()
        let sameEndpoint = (remoteConfigEndpoint == url)
        let existingProvider = remoteConfigProvider
        let hasCachedConfig = (latestRemoteConfig != nil)
        stateLock.unlock()

        if sameEndpoint, let existingProvider {
            if !hasCachedConfig {
                _ = applyRemoteConfigIfAccepted(existingProvider.currentConfig, source: "provider_reuse")
            }
            return true
        }

        let provider = RemoteConfigProvider(configURL: url)
        stateLock.lock()
        remoteConfigEndpoint = url
        remoteConfigProvider = provider
        stateLock.unlock()

        _ = applyRemoteConfigIfAccepted(provider.currentConfig, source: "provider_init")
        UserDefaults.standard.set(rawURL, forKey: Self.remoteConfigEndpointKey)

        Logger.log("remote_config.endpoint set: \(url.absoluteString)")
        return true
    }

    @discardableResult
    private func applyRemoteConfigIfAccepted(
        _ config: RemoteConfig,
        source: String,
        validateStrictly: Bool = true
    ) -> Bool {
        let validation = config.validate()
        if !validation.isValid, validateStrictly {
            let detail = validation.errors.joined(separator: " | ")
            Logger.log("remote_config.\(source) rejected: invalid config, errors=\(detail)")
            return false
        }
        if !validation.isValid {
            let detail = validation.errors.joined(separator: " | ")
            Logger.log("remote_config.\(source) warning: invalid config accepted for local testing, errors=\(detail)")
        }
        if !validation.warnings.isEmpty {
            let warning = validation.warnings.joined(separator: " | ")
            Logger.log("remote_config.\(source) warning: \(warning)")
        }

        stateLock.lock()
        defer { stateLock.unlock() }

        if let currentVersion = latestRemoteConfig?.version {
            if config.version < currentVersion, !Self.localRemoteConfigRollbackAllowed {
                Logger.log(
                    "remote_config.\(source) rejected: rollback detected " +
                    "incoming=\(config.version) < current=\(currentVersion)"
                )
                return false
            }
            if config.version == currentVersion {
                let currentHash = latestRemoteConfig.map {
                    SHA256.hash(data: (try? JSONEncoder().encode($0)) ?? Data())
                }
                let newHash = SHA256.hash(data: (try? JSONEncoder().encode(config)) ?? Data())
                if let currentHash, Data(currentHash) == Data(newHash) {
                    return true
                }
                Logger.log("remote_config.\(source) rejected: same version but different content hash")
                return false
            }
        }

        latestRemoteConfig = config
        return true
    }
}

// MARK: - async/await APIs (2.0)
extension CPRiskKit {
    @available(iOS 13.0, macOS 10.15, *)
    public func evaluateAsync() async -> CPRiskReport {
        await withCheckedContinuation { continuation in
            evaluateAsync { report in
                continuation.resume(returning: report)
            }
        }
    }

    @available(iOS 13.0, macOS 10.15, *)
    public func evaluateAsync(config: CPRiskConfig) async -> CPRiskReport {
        await withCheckedContinuation { continuation in
            evaluateAsync(config: config) { report in
                continuation.resume(returning: report)
            }
        }
    }

    @available(iOS 13.0, macOS 10.15, *)
    public func evaluateAsync(
        config: CPRiskConfig = .default,
        scenario: RiskScenario = .default
    ) async -> CPRiskReport {
        await withCheckedContinuation { continuation in
            evaluateAsync(config: config, scenario: scenario) { report in
                continuation.resume(returning: report)
            }
        }
    }

    @available(iOS 13.0, macOS 10.15, *)
    public func updateRemoteConfigAsync() async throws {
        try await withCheckedThrowingContinuation { continuation in
            updateRemoteConfig { success in
                if success {
                    continuation.resume()
                } else {
                    let error = NSError(
                        domain: "CloudPhoneRiskKit",
                        code: -1,
                        userInfo: [NSLocalizedDescriptionKey: "更新远程配置失败"]
                    )
                    continuation.resume(throwing: ConfigError.networkError(underlying: error))
                }
            }
        }
    }
}
