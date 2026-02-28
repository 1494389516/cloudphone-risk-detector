import Foundation
#if canImport(UIKit)
import UIKit
#endif

@objc(CPRiskKit)
public final class CPRiskKit: NSObject {
    @objc public static let shared = CPRiskKit()

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

    private static let remoteConfigEndpointKey = "com.cloudphone.riskkit.remote.endpoint"

    private override init() {
        super.init()
        if let endpoint = UserDefaults.standard.string(forKey: Self.remoteConfigEndpointKey) {
            _ = configureRemoteConfigProvider(urlString: endpoint)
        }
    }

    /// 启动自动采集（全局触摸 + 传感器）。
    /// 建议在 `application(_:didFinishLaunchingWithOptions:)` 里尽早调用。
    @objc public func start() {
        Logger.log("start()")
        registerProviders(for: .default)
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
        Logger.isEnabled = enabled
        Logger.log("Logger.isEnabled=\(enabled)")
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

    @objc public static func clearExternalServerSignals() {
        ExternalServerAggregateProvider.shared.set(nil)
    }

    /// 注入服务端策略（JSON 字符串）。
    /// 支持离线缓存，重启后仍可生效。
    @objc(setServerRiskPolicyJSON:)
    @discardableResult
    public func setServerRiskPolicyJSON(_ json: String) -> Bool {
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
                self?.stateLock.lock()
                self?.latestRemoteConfig = config
                self?.stateLock.unlock()

                Logger.log("remote_config.update success: version=\(config.version)")
                DispatchQueue.main.async { completion(true) }
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
        let runtimeConfig = resolveRuntimeConfig(from: config)
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
        let extraSignals = RiskSignalProviderRegistry.shared.signals(snapshot: snapshot)

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

        return out
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

        if config.enableTemporalAnalysis {
            RiskSignalProviderRegistry.shared.register(TimePatternProvider.shared)
        } else {
            RiskSignalProviderRegistry.shared.unregister(id: TimePatternProvider.shared.id)
        }

        if config.enableAntiTamper {
            RiskSignalProviderRegistry.shared.register(AntiTamperingSignalProvider())
        } else {
            RiskSignalProviderRegistry.shared.unregister(id: "anti_tampering")
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

        stateLock.lock()
        defer { stateLock.unlock() }

        if remoteConfigEndpoint == url, let existingProvider = remoteConfigProvider {
            if latestRemoteConfig == nil {
                latestRemoteConfig = existingProvider.currentConfig
            }
            return true
        }

        remoteConfigEndpoint = url
        let provider = RemoteConfigProvider(configURL: url)
        remoteConfigProvider = provider
        latestRemoteConfig = provider.currentConfig
        UserDefaults.standard.set(rawURL, forKey: Self.remoteConfigEndpointKey)

        Logger.log("remote_config.endpoint set: \(url.absoluteString)")
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
