// MARK: - CloudPhoneRiskKit — Main Entry Point
//
// Architecture Overview:
//
//   ┌─────────────────────────────────────────────────────────────┐
//   │                     CPRiskKit (this file)                   │
//   │  Singleton orchestrator: start/stop, evaluate, config       │
//   ├────────────┬──────────────┬─────────────┬──────────────────┤
//   │ Jailbreak  │ AntiTamper   │  Providers  │   Decision       │
//   │ Engine     │ + AntiBypass │  (Signals)  │   Engine         │
//   ├────────────┼──────────────┼─────────────┼──────────────────┤
//   │ 11 Detectors│ FridaThread │ DRM/Battery │ DecisionTree     │
//   │ (File,Dyld, │ FridaHeap   │ MountPoint  │ ScenarioPolicy   │
//   │  Sysctl,..) │ ObjCSwizzle │ Hardware    │ ComboRules       │
//   │            │ RWXMemory   │ Behavior    │ SignalWeights     │
//   ├────────────┴──────────────┴─────────────┴──────────────────┤
//   │         RiskScorer  →  RiskVerdict  →  CPRiskReport        │
//   ├────────────────────────────────────────────────────────────┤
//   │  Storage (AES-GCM) │ Config (Remote+Signed) │ Network     │
//   └────────────────────────────────────────────────────────────┘
//
// Data Flow:
//   1. start() → begins touch/motion sampling + registers providers
//   2. evaluate() → snapshot context → run detectors → score → decide → report
//   3. stop() → halt sampling
//
// Thread Safety:
//   - All mutable state guarded by NSLock
//   - Provider registry sealed after start() to prevent runtime injection
//   - Keychain operations use per-key locks to avoid TOCTOU races

import CryptoKit
import CRiskCore
import Foundation
#if canImport(UIKit)
import UIKit
#endif

@objc(CPRiskKit)
public final class CPRiskKit: NSObject {
    @objc public static let shared = CPRiskKit()

    /// 图风控反馈应用后发送的通知名。业务侧可观察此通知并调用 evaluate() 重新评估风险。
    /// 用法：`NotificationCenter.default.addObserver(..., name: CPRiskKit.graphRiskFeedbackDidApplyNotification, ...)`
    public static let graphRiskFeedbackDidApplyNotification = ExternalServerAggregateProvider.graphRiskFeedbackDidApplyNotification

    /// 图风控反馈应用后是否自动触发一次异步 re-evaluate。默认 true；设为 false 时仅发送通知，由业务侧自行调用 evaluate()。
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

#if canImport(UIKit)
    private let touchCapture = TouchCapture.shared
    private let motionSampler = MotionSampler.shared
    private let jailbreakEngine = JailbreakEngine()
#else
    private let jailbreakEngine = JailbreakEngine()
#endif

    private let evaluateQueue = DispatchQueue(label: "CloudPhoneRiskKit.Evaluate", qos: .utility)
    private let stateLock = NSLock()
    /// 保护 cprisk_init_protection 单次执行，避免在持 stateLock 期间调用可能阻塞的 C 函数
    private let armorInitLock = NSLock()

    /// Throttle cprisk_verify_exception_handler to avoid syscall on every evaluate().
    private static let verifyThrottleInterval: TimeInterval = 5.0
    private static var lastExceptionVerifyTime: TimeInterval = 0
    private static let verifyThrottleLock = NSLock()

    private var remoteConfigProvider: RemoteConfigProvider?
    private var remoteConfigEndpoint: URL?
    private var latestRemoteConfig: RemoteConfig?
    private var textSegmentReferenceResolver: (any TextSegmentReferenceResolving)?

    private var boundAccountId: String?
    private var boundSceneTag: String?
    private var currentSessionId: String?
    private var graphFeedbackObserver: Any?

    /// Signal IDs from the previous evaluate() call, used for suppression detection.
    private var previousSignalIds: Set<String> = []
    /// SHA-256 digest of previous evaluate()'s full signal content (id+score+state).
    private var previousSignalsDigest: String?
    /// High-risk signal IDs that are candidates for suppression detection.
    private static let highRiskSignalIds: Set<String> = [
        "frida_heap", "frida_stalker", "frida_socket", "frida_thread",
        "hook_detected", "objc_swizzle", "rwx_memory",
        "armor_runtime_init_failed", "integrity_runtime_tampered",
        "code_signature_invalid", "text_segment_tampered",
        "kernel_hook_timing_anomaly", "kernel_hook_stalker_amplified",
        "system_library_wx_mapping", "system_library_anonymous_exec_region",
        "app_image_segment_layout_anomaly"
    ]

    private static let remoteConfigEndpointKey = "com.cloudphone.riskkit.remote.endpoint"
    private static let remoteTrustLock = NSLock()
    private static var pinnedCertificateHashes: Set<String> = []
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
    private static let localSynthesizedChallengeBindingAllowed: Bool = {
#if DEBUG
        return true
#else
        return false
#endif
    }()

    private struct CapabilityProbeRuntimeResult {
        let score: CapabilityScore
        let probes: [ProbeResult]
    }

    private enum ArmorRootKeySource: String {
        case environment

        case debugFallback
        case missing
        case invalidEnvironment

    }

    private enum ArmorRuntimeStatus: String {
        case inactive
        case active
        case unavailable
        case failed
    }

    internal struct ArmorRuntimeDebugSnapshot {
        let status: String
        let reason: String
        let initCode: Int32?
        let trigger: String
        let rootKeySource: String
        let debugFallbackUsed: Bool
        let anchorPresent: Bool
        let attemptCount: Int
    }

    private struct ArmorRootKeyResolution {
        let keyData: Data?
        let source: ArmorRootKeySource
        let debugFallbackUsed: Bool
        let failureReason: String?
    }

    private struct ArmorRuntimeSnapshot {
        let status: ArmorRuntimeStatus
        let reason: String
        let initCode: Int32?
        let trigger: String
        let rootKeySource: ArmorRootKeySource
        let debugFallbackUsed: Bool
        let anchorPresent: Bool
        let attemptCount: Int

        static let inactive = ArmorRuntimeSnapshot(
            status: .inactive,
            reason: "not_started",
            initCode: nil,
            trigger: "none",
            rootKeySource: .missing,
            debugFallbackUsed: false,
            anchorPresent: false,
            attemptCount: 0
        )
    }

    private static let armorRootKeyEnvironmentKey = "CPRISKKIT_ARMOR_ROOT_KEY_HEX"

#if DEBUG
    private static let armorDebugFallbackRootKeyHex = "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f"
#endif

    private override init() {
        super.init()
        if let endpoint = UserDefaults.standard.string(forKey: Self.remoteConfigEndpointKey) {
            _ = configureRemoteConfigProvider(urlString: endpoint)
        }
    }

    private var armorRuntimeSnapshot = ArmorRuntimeSnapshot.inactive

    /// 启动自动采集（全局触摸 + 传感器）。
    /// 建议在 `application(_:didFinishLaunchingWithOptions:)` 里尽早调用。
    @objc public func start() {
        cprisk_erase_macho_header()
        cprisk_deny_attach()
        cprisk_register_exception_handler()
        _ = ensureArmorRuntimeStarted(trigger: "start")
        DyldImageMonitor.shared.start()
        BuildConfig.configureForRelease()
        stateLock.lock()
        currentSessionId = UUID().uuidString
        stateLock.unlock()
        #if DEBUG
        Logger.log("start() sessionId=\(currentSessionId ?? "")")
        #endif
        if !AppAttestSignalProvider.isHardwareTrustSupported {
            Logger.log("app_attest: hardware_trust_unsupported (evaluate will emit signal weight=95)")
        }
        registerProviders(for: .default)
        RiskSignalProviderRegistry.shared.seal()
        ConditionExpression.sealCustomEvaluators()
        installGraphFeedbackReEvaluateObserver()
#if canImport(UIKit)
        touchCapture.start()
        motionSampler.start()
        PhysicalSensorProbe.prewarm()
#endif
    }

    @objc public func stop() {
        Logger.log("stop()")
        removeGraphFeedbackReEvaluateObserver()
        resetArmorRuntime()
#if canImport(UIKit)
        motionSampler.stop()
        touchCapture.stop()
#endif
    }

    private func installGraphFeedbackReEvaluateObserver() {
        removeGraphFeedbackReEvaluateObserver()
        guard Self.autoReEvaluateOnGraphFeedback else { return }
        graphFeedbackObserver = NotificationCenter.default.addObserver(
            forName: Self.graphRiskFeedbackDidApplyNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.evaluateAsync { _ in }
        }
    }

    private func removeGraphFeedbackReEvaluateObserver() {
        if let obs = graphFeedbackObserver {
            NotificationCenter.default.removeObserver(obs)
            graphFeedbackObserver = nil
        }
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
        shared.refreshRemoteTrustState()
        Logger.log("server_signing_key configured")
    }

    @objc public static func configurePinnedCertificateHashes(_ hashes: [String]) {
        let normalized = normalizedPinnedCertificateHashes(from: hashes)
        remoteTrustLock.lock()
        pinnedCertificateHashes = normalized
        remoteTrustLock.unlock()

        PolicyManager.shared.configurePinning(hashes: normalized)
        shared.applyPinnedCertificateHashes(normalized)
        Logger.log("remote_transport_pinning configured: pins=\(normalized.count)")
    }

    @objc public static func clearExternalServerSignals() {
        ExternalServerAggregateProvider.shared.clear()
    }

    /// 应用图风控反馈：服务端返回图计算结果后调用，注入到 ExternalServerAggregateProvider。
    /// 注入后会发送 `graphRiskFeedbackDidApplyNotification`，业务侧可观察该通知并调用 evaluate() 重新评估风险。
    /// - Parameter feedback: 图风控反馈（communityId、communityRiskDensity、hwProfileDegree 等）
    public static func applyGraphRiskFeedback(_ feedback: GraphRiskFeedback) {
        ExternalServerAggregateProvider.shared.applyGraphRiskFeedback(feedback)
    }

    /// 应用服务端返回的挑战验证结果（回注路径）
    /// 若配置了 HMAC 密钥，先校验；校验失败则拒绝应用并注入 challenge_hmac_mismatch 信号。
    /// adjustedScore 语义：增量偏移（delta），与 baseScore 相加；非绝对分数。超出 [-100, 100] 时裁剪并打日志。
    /// - Parameter result: 服务端返回的 ChallengeVerificationResult
    public static func applyChallengeResult(_ result: ChallengeVerificationResult) {
        if let mismatchSignal = ChallengeSession.shared.verifyResult(result) {
            ChallengeResultStore.shared.storePendingMismatchSignal(mismatchSignal)
            return
        }
        ChallengeResultStore.shared.apply(result: result)
    }

    /// ObjC 兼容：应用挑战验证结果
    @objc(applyChallengeResultWithChallengeId:passed:failedProbes:adjustedScore:)
    public static func applyChallengeResult(
        challengeId: String,
        passed: Bool,
        failedProbes: [String],
        adjustedScore: NSNumber?
    ) {
        let result = ChallengeVerificationResult(
            challengeId: challengeId,
            passed: passed,
            failedProbes: failedProbes,
            adjustedScore: adjustedScore?.doubleValue
        )
        applyChallengeResult(result)
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
        #if DEBUG
        Logger.log("account.bind: accountId=\(accountId) scene=\(scene ?? "nil")")
        #endif
    }

    /// 解绑业务账号（用户登出时调用）。
    ///
    /// 清除 boundAccountId、boundSceneTag、currentSessionId 的引用，并清空 PolicyManager 内存策略缓存，
    /// 减少内存转储风险。Swift 无 SecureString，无法清零字符串内存；及时置 nil 可缩短敏感数据驻留时间。
    /// **调用方应在用户登出时调用本方法。**
    @objc public func unbindAccount() {
        stateLock.lock()
        boundAccountId = nil
        boundSceneTag = nil
        currentSessionId = nil
        previousSignalIds = []
        previousSignalsDigest = nil
        stateLock.unlock()
        PolicyManager.shared.clearCachedPolicy()
        LocalDeviceClusterDetector.shared.clear()
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

    /// 注入自定义 __TEXT.__text 参考哈希解析器。
    ///
    /// 默认情况下 SDK 使用 `RemoteConfig.textSegmentHashReference`。
    /// 若已接入业务侧签名配置中心，可通过该解析器提供同样的参考哈希。
    /// 解析器返回 `nil` 时，SDK 会继续回退到默认 RemoteConfig 逻辑。
    public func setTextSegmentReferenceResolver(_ resolver: (any TextSegmentReferenceResolving)?) {
        stateLock.lock()
        textSegmentReferenceResolver = resolver
        stateLock.unlock()
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
        // If start() was never called, seal the registry so provider tampering is detectable.
        if !RiskSignalProviderRegistry.shared.isSealed {
            RiskSignalProviderRegistry.shared.seal()
            ConditionExpression.sealCustomEvaluators()
        }
        // Ensure CRiskCore and armor runtime are initialized even if start() was never called.
        cprisk_deny_attach()
        cprisk_register_exception_handler()
        let armorRuntimeSnapshot = ensureArmorRuntimeStarted(trigger: "evaluate")
        // Recheck integrity when armor runtime is active; on tampering, material may
        // silently switch to decoy bytes instead of surfacing a direct return-code oracle.
        if armorRuntimeSnapshot.status == .active {
            _ = cprisk_recheck_integrity()
        }
        Self.maybeVerifyExceptionHandler()

        let context = buildRiskContext(config: runtimeConfig)
        let snapshot = RiskSnapshot(
            deviceID: context.deviceID,
            device: context.device,
            network: context.network,
            behavior: context.behavior,
            jailbreak: context.jailbreak
        )
        let serverSignals = RiskSignalProviderRegistry.shared.serverSignals(snapshot: snapshot)
        stateLock.lock()
        let acctIdForGraph = boundAccountId
        let sessIdForGraph = currentSessionId
        stateLock.unlock()

        let graphNodeDescriptor = GraphFeatureCollector.collect(
            snapshot: snapshot,
            serverSignals: serverSignals,
            accountId: acctIdForGraph
        )
        var extraSignalsForGraph: [RiskSignal] = []
        if let localClusterSignal = LocalDeviceClusterDetector.shared.recordAndDetect(
            hwProfileHash: graphNodeDescriptor.hwProfileHash,
            key: serverSignals?.publicIP ?? sessIdForGraph
        ) {
            extraSignalsForGraph = [localClusterSignal]
        }

        let capabilityRuntime = runCapabilityProbe(remoteConfig: remoteConfig)
        var extraSignals = RiskSignalProviderRegistry.shared.signals(snapshot: snapshot)
        if let armorRuntimeSignal = Self.armorRuntimeSignal(from: armorRuntimeSnapshot) {
            extraSignals.append(armorRuntimeSignal)
        }
        if cprisk_is_integrity_poisoned() != 0 {
            extraSignals.append(Self.integrityRecheckPoisonedSignal())
        }
        // memory_protection_tampered 由 AntiTamperingSignalProvider 统一注入，此处不再重复追加
        extraSignals.append(capabilityRuntime.score.toSignal())
        extraSignals.append(contentsOf: extraSignalsForGraph)
        extraSignals.append(contentsOf: ChallengeResultStore.shared.consumePendingMismatchSignals())

        if let provider = currentRemoteConfigProvider(), provider.isConfigStale {
            extraSignals.append(RiskSignal(
                id: "remote_config_stale",
                category: "config",
                score: 0,
                evidence: ["age_seconds": "\(Int(provider.configAge))"],
                state: .soft(confidence: 0.3),
                layer: 4,
                weightHint: 10
            ))
        }

        // Signal continuity check: detect sudden disappearance of high-risk signals between evaluations.
        let allCurrentSignalIds = Set(extraSignals.map(\.id))
        stateLock.lock()
        let prevIds = previousSignalIds
        stateLock.unlock()
        if !prevIds.isEmpty {
            let previousHighRisk = prevIds.intersection(Self.highRiskSignalIds)
            let currentHighRisk = allCurrentSignalIds.intersection(Self.highRiskSignalIds)
            let suppressedIds = previousHighRisk.subtracting(currentHighRisk)
            if suppressedIds.count >= 2 || (previousHighRisk.count > 0 && currentHighRisk.isEmpty && previousHighRisk.count >= 1) {
                let evidence = [
                    "suppressed_ids": suppressedIds.sorted().joined(separator: ","),
                    "previous_count": "\(previousHighRisk.count)",
                    "current_count": "\(currentHighRisk.count)"
                ]
                extraSignals.append(RiskSignal(
                    id: "signal_suppression_detected",
                    category: "integrity",
                    score: 80,
                    evidence: evidence,
                    state: .tampered,
                    layer: 1,
                    weightHint: 80
                ))
                Logger.log("signal_suppression: \(suppressedIds.sorted()) disappeared between evaluations")
            }
        }

        let serverPolicy = PolicyManager.shared.activePolicy
        let policy = buildEnginePolicy(
            runtimeConfig: runtimeConfig,
            remoteConfig: remoteConfig,
            enableTemporalAnalysis: config.enableTemporalAnalysis,
            serverPolicy: serverPolicy
        )
        if policy.killSwitchEnabled {
            Logger.log("⚠️ killSwitch is ACTIVE — evaluation will force low-risk/allow verdict")
        }
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
            summary: verdict.summary,
            compressedDigest: verdict.compressedDigest,
            mappingVersion: verdict.mappingVersion
        )

        Logger.log(
            "final: score=\(scoreReport.score) isHighRisk=\(scoreReport.isHighRisk) " +
            "signals=\(scoreReport.signals.count) summary=\(scoreReport.summary)"
        )

        // 如果 anti_tamper 信号触发，补强 legacy jailbreak 结论以避免分裂
        let tamperedSignals = extraSignals.filter {
            if case .tampered? = $0.state { return true }
            return false
        }
        let antiTamperHit = tamperedSignals.contains { $0.category == "anti_tamper" || $0.category == "integrity" }
        var mergedJailbreak = context.jailbreak
        if antiTamperHit && !mergedJailbreak.isJailbroken {
            let antiTamperMethods = tamperedSignals
                .filter { $0.category == "anti_tamper" || $0.category == "integrity" }
                .map { "anti_tamper:\($0.id)" }
            let boostedConfidence = max(mergedJailbreak.confidence, tamperedSignals.map { $0.score }.reduce(0, +) * 0.5)
            mergedJailbreak = DetectionResult(
                isJailbroken: boostedConfidence >= 50,
                confidence: min(100, boostedConfidence),
                detectedMethods: mergedJailbreak.detectedMethods + antiTamperMethods,
                details: mergedJailbreak.details
            )
        }
        let finalContext = RiskContext(
            device: context.device,
            deviceID: context.deviceID,
            network: context.network,
            behavior: context.behavior,
            jailbreak: mergedJailbreak
        )

        let out = CPRiskReport(context: finalContext, report: scoreReport)
        out.setServerSignals(serverSignals)
        out.setGraphNodeDescriptor(graphNodeDescriptor)
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

        // Update signal continuity state for next evaluate() call.
        let allVerdictSignalIds = Set(verdict.signals.map(\.id))
        stateLock.lock()
        previousSignalIds = allVerdictSignalIds
        previousSignalsDigest = SignalDigest.computeFullDigest(verdict.signals)
        stateLock.unlock()

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
    /// - `challengeBinding` 仅是 SDK 本地联调字段；Release 默认不会生成本地合成 challenge。
    ///
    /// **与 buildSecureReportEnvelopeWithAttestation 的区别**：本方法不附加 App Attest 硬件信任根；
    /// 若业务要求硬件信任根，请使用 `buildSecureReportEnvelopeWithAttestation`，并检查返回的
    /// `envelope.hasHardwareAttestation` 或 `attestationKeyId`/`attestationAssertion` 是否存在。
    public func buildSecureReportEnvelope(
        report: CPRiskReport,
        sessionToken: String,
        signingKey: String,
        keyId: String = "k1",
        attestationKeyId: String? = nil,
        requireArmor: Bool = true
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

        let effectiveKeyId = (keyId == "k1" && TrustChainManager.currentKeyRotationPolicy() != nil)
            ? TrustChainManager.currentKeyId(baseKeyId: keyId)
            : keyId

        let trustLevel = TrustChainManager.evaluateTrustLevel(
            deviceID: report.deviceID,
            hardwareMachine: report.device.hardwareMachine ?? "",
            kernelVersion: Sysctl.string("kern.version") ?? ""
        )

        let armorSnapshot = ensureArmorRuntimeStarted(trigger: "build_envelope")
        let effectiveSigningKey: String
        let signatureVersion: String

        if armorSnapshot.status == .active {
            let (armorMaterial, authentic) = Self.armorRuntimeMaterial()
            if authentic {
                effectiveSigningKey = Self.deriveEffectiveSigningKey(
                    baseKey: signingKey,
                    armorMaterial: armorMaterial
                )
                #if DEBUG
                signatureVersion = hardening.enableEnvelopeSignatureV2 ? "v2a" : "v1"
                #else
                signatureVersion = "v2a"
                #endif
            } else if requireArmor {
                Logger.log("buildSecureReportEnvelope: armor material marked poisoned by runtime state")
                throw SecureUploadError.armorRuntimeUnavailable(reason: "material_poisoned")
            } else {
                Logger.log("buildSecureReportEnvelope: armor material marked poisoned, degrading to v2 signature")
                effectiveSigningKey = signingKey
                signatureVersion = "v2"
            }
        } else if requireArmor {
            Logger.log("buildSecureReportEnvelope: armor unavailable status=\(armorSnapshot.status.rawValue) reason=\(armorSnapshot.reason)")
            throw SecureUploadError.armorRuntimeUnavailable(reason: armorSnapshot.reason)
        } else {
            Logger.log("buildSecureReportEnvelope: armor unavailable, degrading to v2 signature (status=\(armorSnapshot.status.rawValue))")
            effectiveSigningKey = signingKey
            signatureVersion = "v2"
        }

        let envelopeConfig = ReportEnvelope.Config(signatureVersion: signatureVersion)

        return try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: report.reportID,
            sessionToken: sessionToken,
            signingKey: effectiveSigningKey,
            keyId: effectiveKeyId,
            fieldMapping: mapping,
            attestationKeyId: attestationKeyId,
            trustLevel: trustLevel,
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

    /// 构建 gRPC/JSON 兼容的上报载荷（SDK 4.4）。
    /// 返回与 `UploadRiskReportRequest` proto 结构匹配的 JSON，供 HTTP/2 或 gRPC 客户端发送。
    /// - Parameters:
    ///   - report: 风险报告
    ///   - sessionToken: 服务端下发会话 token
    ///   - signingKey: HMAC 签名密钥
    ///   - keyId: 密钥标识
    ///   - appId: 应用标识（可选，用于网关索引）
    ///   - prettyPrinted: 是否格式化 JSON（调试用）
    /// - Returns: 与 proto 结构匹配的 JSON 字符串
    public func buildSecureReportEnvelopeGrpcCompatibleJSON(
        report: CPRiskReport,
        sessionToken: String,
        signingKey: String,
        keyId: String = "k1",
        appId: String = "",
        prettyPrinted: Bool = false
    ) throws -> String {
        let envelope = try buildSecureReportEnvelope(
            report: report,
            sessionToken: sessionToken,
            signingKey: signingKey,
            keyId: keyId
        )
        stateLock.lock()
        let sceneTag = boundSceneTag
        stateLock.unlock()
        let context = GrpcReportContext(
            appId: appId,
            deviceId: report.deviceID,
            scene: sceneTag ?? ""
        )
        return try envelope.toGrpcCompatibleJSON(context: context, prettyPrinted: prettyPrinted)
    }

    /// 构建 gRPC/JSON 兼容的上报载荷（SDK 4.4）。
    /// 返回与 `UploadRiskReportRequest` proto 结构匹配的 JSON Data，供 HTTP/2 或 gRPC 客户端发送。
    public func buildSecureReportEnvelopeGrpcRequestBytes(
        report: CPRiskReport,
        sessionToken: String,
        signingKey: String,
        keyId: String = "k1",
        appId: String = ""
    ) throws -> Data {
        let envelope = try buildSecureReportEnvelope(
            report: report,
            sessionToken: sessionToken,
            signingKey: signingKey,
            keyId: keyId
        )
        stateLock.lock()
        let sceneTag = boundSceneTag
        stateLock.unlock()
        let context = GrpcReportContext(
            appId: appId,
            deviceId: report.deviceID,
            scene: sceneTag ?? ""
        )
        return try envelope.toGrpcRequestBytes(context: context)
    }

    /// 构建带 App Attest 硬件信任根的安全信封（SDK 4.4）
    ///
    /// **行为约定**：
    /// - 当 `requireAttestation == true`（默认）：若 App Attest 不可用（`AppAttestSigner.isSupported == false`）
    ///   或 assertion 生成失败，将 **throw** 而非静默退回普通 HMAC envelope，保证调用方收到的信封一定带硬件信任根。
    /// - 当 `requireAttestation == false`：允许降级，失败时退回普通 envelope；调用方应检查
    ///   `envelope.hasHardwareAttestation` 或 `attestationKeyId != nil && attestationAssertion != nil` 以识别降级。
    ///
    /// - Parameter requireAttestation: 是否强制要求硬件信任根；默认 true，失败时 throw。
    /// - Throws: `AppAttestSigner.AppAttestError` 当 requireAttestation 为 true 且 App Attest 不可用或失败时。
    @available(iOS 14.0, macOS 11.0, *)
    public func buildSecureReportEnvelopeWithAttestation(
        report: CPRiskReport,
        sessionToken: String,
        signingKey: String,
        keyId: String = "k1",
        requireAttestation: Bool = true
    ) async throws -> ReportEnvelope {
        let effectiveKeyId = (keyId == "k1" && TrustChainManager.currentKeyRotationPolicy() != nil)
            ? TrustChainManager.currentKeyId(baseKeyId: keyId)
            : keyId

        guard AppAttestSigner.isSupported else {
            if requireAttestation {
                throw AppAttestSigner.AppAttestError.hardwareTrustUnsupported
            }
            Logger.log("app_attest: hardware_trust_unsupported, falling back to plain HMAC envelope (requireAttestation=false)")
            return try buildSecureReportEnvelope(
                report: report,
                sessionToken: sessionToken,
                signingKey: signingKey,
                keyId: effectiveKeyId,
                requireArmor: false
            )
        }
        do {
            let attestKeyId = try await AppAttestSigner.resolveKeyId()
            var envelope = try buildSecureReportEnvelope(
                report: report,
                sessionToken: sessionToken,
                signingKey: signingKey,
                keyId: effectiveKeyId,
                attestationKeyId: attestKeyId
            )
            let canonicalPayload = try envelope.canonicalPayloadString()
            guard let payloadData = canonicalPayload.data(using: .utf8) else {
                if requireAttestation {
                    throw SecureUploadError.invalidPayloadShape
                }
                return envelope
            }
            let (_, assertion) = try await AppAttestSigner.generateAssertion(for: payloadData)
            envelope = envelope.withAttestation(attestationKeyId: attestKeyId, assertion: assertion)
            if TrustChainManager.shouldRefreshAttestation(),
               let challenge = PolicyManager.shared.activePolicy?.reAttestationChallenge,
               !challenge.isEmpty {
                do {
                    let (_, reAssertion) = try await AppAttestSigner.generateAssertion(for: challenge)
                    envelope = envelope.withReAttestationAssertion(reAssertion)
                    TrustChainManager.markAttestationChecked()
                    Logger.log("app_attest: re-attestation completed, challenge signed")
                } catch {
                    Logger.log("app_attest: re-attestation failed, degrading: \(error.localizedDescription)")
                    envelope = envelope.withTrustLevel(TrustChainManager.degradedTrustLevel())
                }
            } else {
                TrustChainManager.markAttestationChecked()
            }
            Logger.log("app_attest: envelope augmented with hardware assertion")
            return envelope
        } catch {
            if requireAttestation {
                throw error
            }
            Logger.log("app_attest: failed to generate assertion, envelope without attestation: \(error.localizedDescription)")
            let fallback = try buildSecureReportEnvelope(
                report: report,
                sessionToken: sessionToken,
                signingKey: signingKey,
                keyId: effectiveKeyId,
                requireArmor: false
            )
            return fallback.withTrustLevel(TrustChainManager.degradedTrustLevel())
        }
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

    internal func debugArmorRuntimeSnapshot() -> ArmorRuntimeDebugSnapshot {
        stateLock.lock()
        let snapshot = armorRuntimeSnapshot
        stateLock.unlock()
        return ArmorRuntimeDebugSnapshot(
            status: snapshot.status.rawValue,
            reason: snapshot.reason,
            initCode: snapshot.initCode,
            trigger: snapshot.trigger,
            rootKeySource: snapshot.rootKeySource.rawValue,
            debugFallbackUsed: snapshot.debugFallbackUsed,
            anchorPresent: snapshot.anchorPresent,
            attemptCount: snapshot.attemptCount
        )
    }

    private func registerProviders(for config: CPRiskConfig) {
        RiskSignalProviderRegistry.shared.register(ExternalServerAggregateProvider.shared)
        RiskSignalProviderRegistry.shared.register(DeviceHardwareProvider.shared)
        RiskSignalProviderRegistry.shared.register(DeviceAgeProvider.shared)
        RiskSignalProviderRegistry.shared.register(AppAttestSignalProvider.shared)
        RiskSignalProviderRegistry.shared.register(VPhoneHardwareProvider.shared)
        RiskSignalProviderRegistry.shared.register(HardwareCapabilityProvider.shared)
        RiskSignalProviderRegistry.shared.register(DisplayMuxProvider.shared)
        RiskSignalProviderRegistry.shared.register(BiometricStateProvider.shared)
        RiskSignalProviderRegistry.shared.register(LayeredConsistencyProvider.shared)
        RiskSignalProviderRegistry.shared.register(MountPointProvider.shared)
        RiskSignalProviderRegistry.shared.register(NetworkInterfaceProvider.shared)
        RiskSignalProviderRegistry.shared.register(DRMCapabilityProvider.shared)
        RiskSignalProviderRegistry.shared.register(BatteryEntropyProvider.shared)
        RiskSignalProviderRegistry.shared.register(EnvironmentConsistencyProvider.shared)
        RiskSignalProviderRegistry.shared.register(AudioRouteProvider.shared)
        RiskSignalProviderRegistry.shared.register(BasebandIsolationProvider.shared)

        if config.enableTemporalAnalysis {
            RiskSignalProviderRegistry.shared.register(TimePatternProvider.shared)
        } else {
            RiskSignalProviderRegistry.shared.unregister(id: TimePatternProvider.shared.id)
        }

        RiskSignalProviderRegistry.shared.register(AntiTamperingSignalProvider.shared)
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

    @discardableResult
    private func ensureArmorRuntimeStarted(trigger: String) -> ArmorRuntimeSnapshot {
        stateLock.lock()
        if armorRuntimeSnapshot.status != .inactive {
            let existing = armorRuntimeSnapshot
            stateLock.unlock()
            return existing
        }

        let attemptCount = armorRuntimeSnapshot.attemptCount + 1
        let anchorPresent = Self.hasArmorAnchor()
        let keyResolution = Self.resolveArmorRootKey()
        stateLock.unlock()

        // 在锁外构建 snapshot，避免持 stateLock 期间调用可能阻塞的 cprisk_init_protection
        let snapshot: ArmorRuntimeSnapshot
        if let failureReason = keyResolution.failureReason {
            snapshot = ArmorRuntimeSnapshot(
                status: .unavailable,
                reason: failureReason,
                initCode: nil,
                trigger: trigger,
                rootKeySource: keyResolution.source,
                debugFallbackUsed: keyResolution.debugFallbackUsed,
                anchorPresent: anchorPresent,
                attemptCount: attemptCount
            )
        } else if let keyData = keyResolution.keyData {
            armorInitLock.lock()
            stateLock.lock()
            if armorRuntimeSnapshot.status != .inactive {
                let existing = armorRuntimeSnapshot
                stateLock.unlock()
                armorInitLock.unlock()
                return existing
            }
            stateLock.unlock()

            let initCode = keyData.withUnsafeBytes { rawBuffer -> Int32 in
                guard let baseAddress = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return -1
                }
                return Int32(cprisk_init_protection(baseAddress, keyData.count))
            }

            snapshot = Self.makeArmorRuntimeSnapshot(
                trigger: trigger,
                initCode: initCode,
                keySource: keyResolution.source,
                debugFallbackUsed: keyResolution.debugFallbackUsed,
                anchorPresent: anchorPresent,
                attemptCount: attemptCount
            )
            stateLock.lock()
            armorRuntimeSnapshot = snapshot
            stateLock.unlock()
            armorInitLock.unlock()
        } else {
            snapshot = ArmorRuntimeSnapshot(
                status: .unavailable,
                reason: "missing_root_key",
                initCode: nil,
                trigger: trigger,
                rootKeySource: .missing,
                debugFallbackUsed: false,
                anchorPresent: anchorPresent,
                attemptCount: attemptCount
            )
        }

        stateLock.lock()
        if armorRuntimeSnapshot.status == .inactive {
            armorRuntimeSnapshot = snapshot
        }
        let finalSnapshot = armorRuntimeSnapshot
        stateLock.unlock()

        Self.logArmorRuntimeSnapshot(finalSnapshot)
        return finalSnapshot
    }

    private func resetArmorRuntime() {
        stateLock.lock()
        let shouldCleanup = armorRuntimeSnapshot.status != .inactive || armorRuntimeSnapshot.attemptCount > 0
        armorRuntimeSnapshot = .inactive
        stateLock.unlock()

        if shouldCleanup {
            cprisk_cleanup_protection()
            Logger.log("armor_runtime.cleanup")
        }
    }

    private func buildChallengeBindingIfNeeded(
        remoteConfig: RemoteConfig?,
        serverPolicy: ServerRiskPolicy?,
        capabilityRuntime: CapabilityProbeRuntimeResult,
        signals: [RiskSignal],
        deviceID: String
    ) -> ChallengeBindingPayload? {
        guard Self.localSynthesizedChallengeBindingAllowed else {
            Logger.log("challenge.binding skipped: local synthesized binding disabled in release; require server-issued challenge")
            return nil
        }

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

        let session = ChallengeSession.shared
        if session.hasSubmitted(challenge.challengeId) {
            Logger.log("challenge.binding skipped: challengeId=\(challenge.challengeId) already submitted (replay)")
            return nil
        }
        guard session.markSubmitted(challenge.challengeId) else {
            return nil
        }
        let expectedHash = ChallengeTrigger.computeExpectedHash(
            seed: challenge.seed,
            deviceFingerprint: deviceID
        )
        return ChallengeTrigger.buildChallengeBindingPayload(
            challenge: challenge,
            capabilityScore: capabilityRuntime.score,
            tamperedCount: tamperedCount,
            executedProbeIDs: capabilityRuntime.probes.map(\.id),
            triggerReason: "local_sdk_synthesized/\(trigger.reason)",
            expectedHash: expectedHash
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
#if !DEBUG
        config.jailbreak.enableEnvDetect = true
        config.jailbreak.enableSchemeDetect = true
        config.jailbreak.enableHookDetect = true
        config.enableBehaviorDetect = true
        config.enableNetworkSignals = true
        if config.jailbreak.threshold > 50 {
            config.jailbreak.threshold = 50
        }
        if config.threshold > 100 {
            config.threshold = 55
        }
#else
        if config.jailbreak.threshold > 100 {
            config.jailbreak.threshold = 50
        }
#endif
        // Release 下：关键检测开关不允许被远程配置或调用方关闭（最终强制覆盖）
#if !DEBUG
        config.enableBehaviorDetect = true
        config.enableNetworkSignals = true
        config.jailbreak.enableFileDetect = true
        config.jailbreak.enableDyldDetect = true
        config.jailbreak.enableSysctlDetect = true
        config.jailbreak.enableHookDetect = true
#endif
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
        #if DEBUG
        Logger.log("behavior.coupling: actions=\(actionTimestamps.count) corr=\(coupling?.description ?? "nil")")
        #endif

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
                enableForceRules: base.enableForceRules,
                compressedVerdictRules: base.compressedVerdictRules
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
            killSwitchEnabled: remoteConfig?.securityHardening?.killSwitchEnabled ?? false,
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

    /// 供 TextSegmentIntegrityChecker 等服务端参考哈希校验使用
    internal func currentRemoteConfig() -> RemoteConfig? {
        stateLock.lock()
        let cached = latestRemoteConfig
        let provider = remoteConfigProvider
        stateLock.unlock()

        if let cached {
            return cached
        }

        return provider?.currentConfig
    }


    /// 解析当前 SDK 版本的可信 __TEXT.__text 参考哈希。
    /// 优先走业务方注入的解析器；若未提供或返回 nil，则回退到 RemoteConfig。
    internal func resolveTextSegmentReference(for sdkVersion: String) -> TextSegmentReference? {
        stateLock.lock()
        let resolver = textSegmentReferenceResolver
        let cached = latestRemoteConfig
        let provider = remoteConfigProvider
        stateLock.unlock()

        if let resolved = resolver?.resolveTextSegmentReference(for: sdkVersion) {
            return resolved
        }

        let config = cached ?? provider?.currentConfig
        guard let config,
              let expectedHash = config.textSegmentHashReference?[sdkVersion] else {
            return nil
        }

        return TextSegmentReference(
            expectedHash: expectedHash,
            source: "remote_config",
            version: String(config.version)
        )
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
            existingProvider.configurePinning(hashes: Self.currentPinnedCertificateHashes())
            existingProvider.reloadCachedConfigTrustState()
            if !hasCachedConfig {
                _ = applyRemoteConfigIfAccepted(existingProvider.currentConfig, source: "provider_reuse")
            }
            return true
        }

        let provider = RemoteConfigProvider(
            configURL: url,
            pinnedCertificateHashes: Self.currentPinnedCertificateHashes()
        )
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
        let effectiveConfig = Self.releaseHardenedRemoteConfig(config)
        let validation = effectiveConfig.validate()
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
            if effectiveConfig.version < currentVersion, !Self.localRemoteConfigRollbackAllowed {
                Logger.log(
                    "remote_config.\(source) rejected: rollback detected " +
                    "incoming=\(effectiveConfig.version) < current=\(currentVersion)"
                )
                return false
            }
            if effectiveConfig.version == currentVersion {
                let currentHash = latestRemoteConfig.flatMap(Self.stableConfigHash)
                let newHash = Self.stableConfigHash(effectiveConfig)
                if let currentHash, currentHash == newHash {
                    return true
                }
                Logger.log("remote_config.\(source) rejected: same version but different content hash")
                return false
            }
        }

        latestRemoteConfig = effectiveConfig

        DynamicFeatureList.shared.applyRemoteConfig(
            additionalSuspiciousLibraries: effectiveConfig.additionalSuspiciousLibraries,
            additionalSuspiciousPaths: effectiveConfig.additionalSuspiciousPaths,
            additionalSuspiciousPorts: effectiveConfig.additionalSuspiciousPorts
        )

        return true
    }

    private func applyPinnedCertificateHashes(_ hashes: Set<String>) {
        currentRemoteConfigProvider()?.configurePinning(hashes: hashes)
    }

    private func refreshRemoteTrustState() {
        if let provider = currentRemoteConfigProvider() {
            provider.reloadCachedConfigTrustState()
            _ = applyRemoteConfigIfAccepted(provider.currentConfig, source: "trust_refresh", validateStrictly: false)
        } else {
            stateLock.lock()
            latestRemoteConfig = nil
            stateLock.unlock()
        }
        PolicyManager.shared.reloadTrustedCacheState()
    }

    /// Throttled cprisk_verify_exception_handler to reduce task_get_exception_ports syscall frequency.
    private static func maybeVerifyExceptionHandler() {
        verifyThrottleLock.lock()
        let now = Date().timeIntervalSince1970
        let shouldVerify = (now - lastExceptionVerifyTime) >= verifyThrottleInterval
        if shouldVerify {
            lastExceptionVerifyTime = now
            verifyThrottleLock.unlock()
            cprisk_verify_exception_handler()
        } else {
            verifyThrottleLock.unlock()
        }
    }

    private static func resolveArmorRootKey() -> ArmorRootKeyResolution {
        if let rawValue = ProcessInfo.processInfo.environment[armorRootKeyEnvironmentKey] {
            let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else {
                return ArmorRootKeyResolution(
                    keyData: nil,
                    source: .invalidEnvironment,
                    debugFallbackUsed: false,
                    failureReason: "invalid_root_key_hex"
                )
            }
            guard let keyData = Data(hexString: trimmed), keyData.count == 32 else {
                return ArmorRootKeyResolution(
                    keyData: nil,
                    source: .invalidEnvironment,
                    debugFallbackUsed: false,
                    failureReason: "invalid_root_key_hex"
                )
            }
            return ArmorRootKeyResolution(
                keyData: keyData,
                source: .environment,
                debugFallbackUsed: false,
                failureReason: nil
            )
        }


#if DEBUG
        return ArmorRootKeyResolution(
            keyData: Data(hexString: armorDebugFallbackRootKeyHex),
            source: .debugFallback,
            debugFallbackUsed: true,
            failureReason: nil
        )
#else
        return ArmorRootKeyResolution(
            keyData: nil,
            source: .missing,
            debugFallbackUsed: false,
            failureReason: "missing_root_key"
        )
#endif
    }

    private static func hasArmorAnchor() -> Bool {
        var anchor = [UInt8](repeating: 0, count: 32)
        return cprisk_read_full_anchor_hash(&anchor) == 0
    }

    private static func makeArmorRuntimeSnapshot(
        trigger: String,
        initCode: Int32,
        keySource: ArmorRootKeySource,
        debugFallbackUsed: Bool,
        anchorPresent: Bool,
        attemptCount: Int
    ) -> ArmorRuntimeSnapshot {
        let status: ArmorRuntimeStatus
        let reason: String

        switch initCode {
        case 0:
            status = .active
            reason = "initialized"
        case -1:
            status = .unavailable
            reason = "invalid_root_key"
        case -2:
            status = .failed
            reason = "integrity_hash_failed"
        case -3:
            status = anchorPresent ? .failed : .unavailable
            reason = anchorPresent ? "full_anchor_read_failed" : "armor_payload_missing"
        case -4:
            status = .failed
            reason = "anchor_hmac_failed"
        case -5:
            status = .failed
            reason = "anchor_accumulator_failed"
        case -6:
            status = .failed
            reason = "data_loader_init_failed"
        case -7:
            status = .failed
            reason = "protected_data_load_failed"
        default:
            status = .failed
            reason = "init_failed_\(initCode)"
        }

        return ArmorRuntimeSnapshot(
            status: status,
            reason: reason,
            initCode: initCode,
            trigger: trigger,
            rootKeySource: keySource,
            debugFallbackUsed: debugFallbackUsed,
            anchorPresent: anchorPresent,
            attemptCount: attemptCount
        )
    }

    private static func logArmorRuntimeSnapshot(_ snapshot: ArmorRuntimeSnapshot) {
        let message = "armor_runtime status=\(snapshot.status.rawValue) reason=\(snapshot.reason) " +
            "trigger=\(snapshot.trigger) source=\(snapshot.rootKeySource.rawValue) " +
            "anchor=\(snapshot.anchorPresent ? "present" : "missing") attempts=\(snapshot.attemptCount)" +
            (snapshot.initCode.map { " initCode=\($0)" } ?? "") +
            (snapshot.debugFallbackUsed ? " debugFallback=1" : "")

        Logger.log(message)
        if snapshot.status != .active && snapshot.status != .inactive {
            NSLog("[CloudPhoneRiskKit] %@", message)
        }
    }

    private static func armorRuntimeSignal(from snapshot: ArmorRuntimeSnapshot) -> RiskSignal? {
        guard snapshot.status != .active && snapshot.status != .inactive else {
            return nil
        }

        let signalID: String
        let score: Double
        let state: RiskSignalState

        switch snapshot.status {
        case .unavailable:
            signalID = "armor_runtime_unavailable"
            score = snapshot.anchorPresent ? 40 : 18
            state = .unavailable
        case .failed:
            signalID = "armor_runtime_init_failed"
            score = 72
            state = .tampered
        case .inactive, .active:
            return nil
        }

        var evidence: [String: String] = [
            "reason": snapshot.reason,
            "trigger": snapshot.trigger,
            "root_key_source": snapshot.rootKeySource.rawValue,
            "anchor_present": snapshot.anchorPresent ? "1" : "0",
            "attempt_count": "\(snapshot.attemptCount)"
        ]
        if let initCode = snapshot.initCode {
            evidence["init_code"] = "\(initCode)"
        }
        if snapshot.debugFallbackUsed {
            evidence["debug_fallback"] = "1"
        }

        return RiskSignal(
            id: signalID,
            category: "anti_tamper",
            score: score,
            evidence: evidence,
            state: state,
            layer: 2,
            weightHint: score
        )
    }

    /// Signal emitted when cprisk_recheck_integrity() detected runtime tampering.
    /// Runtime material may become visible-poison or hidden-decoy; in both cases
    /// envelope signing eventually uses the wrong key and server verification fails.
    private static func integrityRecheckPoisonedSignal() -> RiskSignal {
        RiskSignal(
            id: "integrity_runtime_tampered",
            category: "integrity",
            score: 85,
            evidence: ["reason": "recheck_hash_mismatch"],
            state: .tampered,
            layer: 2,
            weightHint: 85
        )
    }

    private static func mprotectTamperedSignal() -> RiskSignal {
        RiskSignal(
            id: "memory_protection_tampered",
            category: "anti_tamper",
            score: 85,
            evidence: ["detail": "mprotect_syscall_blocked"],
            state: .tampered,
            layer: 1,
            weightHint: 90
        )
    }

    private static func normalizedPinnedCertificateHashes(from hashes: [String]) -> Set<String> {
        Set(
            hashes
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        )
    }

    private static func currentPinnedCertificateHashes() -> Set<String> {
        remoteTrustLock.lock()
        defer { remoteTrustLock.unlock() }
        return pinnedCertificateHashes
    }

    private static func releaseHardenedRemoteConfig(_ config: RemoteConfig) -> RemoteConfig {
#if DEBUG
        return config
#else
        return config.enforcingReleaseSecurityFloor()
#endif
    }

    private static func stableConfigHash(_ config: RemoteConfig) -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(config) else { return nil }
        return SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Armor Runtime Material for Envelope Signing

    private static func armorRuntimeMaterial() -> (material: Data, authentic: Bool) {
        var buffer = [UInt8](repeating: 0, count: 32)
        _ = cprisk_get_runtime_material(&buffer)
        let authentic = cprisk_is_integrity_poisoned() == 0
        return (Data(buffer), authentic)
    }

    /// Derive an effective signing key by HMAC(armorMaterial, baseKey).
    /// If armor switches to visible poison or hidden decoy material, effectiveKey
    /// becomes wrong and server-side HMAC verification fails.
    private static func deriveEffectiveSigningKey(baseKey: String, armorMaterial: Data) -> String {
        guard let keyData = baseKey.data(using: .utf8) else {
            Logger.log("deriveEffectiveSigningKey: UTF-8 encoding failed for baseKey, using empty string")
            return ""
        }
        let derived = HMAC<SHA256>.authenticationCode(
            for: keyData,
            using: SymmetricKey(data: armorMaterial)
        )
        return Data(derived).map { String(format: "%02x", $0) }.joined()
    }

    /// 返回 v2a 信封验签所需的派生密钥。
    /// 确保 armor runtime 已启动，并用 baseKey + armor material 派生。
    /// 供 validateSecureReportEnvelope 在 sigVer == "v2a" 时使用。
    /// 若 runtime 未激活或显式暴露 poisoned 状态则返回 nil；若 deception 已激活，
    /// 这里可能继续返回基于 decoy material 的派生密钥，让失败延后表现为签名不匹配。
    func effectiveSigningKeyForV2aValidation(baseKey: String) -> String? {
        let snapshot = ensureArmorRuntimeStarted(trigger: "validate_envelope")
        guard snapshot.status == .active else { return nil }
        let (armorMaterial, authentic) = Self.armorRuntimeMaterial()
        guard authentic else { return nil }
        return Self.deriveEffectiveSigningKey(baseKey: baseKey, armorMaterial: armorMaterial)
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
