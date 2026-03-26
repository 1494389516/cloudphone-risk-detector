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

@objc(CPR_RiskKit)
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
    private let stateLock = UnfairLock()
    /// 保护 cprisk_init_protection 单次执行，避免在持 stateLock 期间调用可能阻塞的 C 函数
    private let armorInitLock = UnfairLock()

    /// Throttle cprisk_verify_exception_handler to avoid syscall on every evaluate().
    private static let verifyThrottleInterval: TimeInterval = 5.0
    private static var lastExceptionVerifyTime: TimeInterval = 0
    private static let verifyThrottleLock = UnfairLock()

    private var remoteConfigProvider: RemoteConfigProvider?
    private var remoteConfigEndpoint: URL?
    private var latestRemoteConfig: RemoteConfig?
    private var textSegmentReferenceResolver: (any TextSegmentReferenceResolving)?

    private var boundAccountId: String?
    private var boundSceneTag: String?
    private var currentSessionId: String?
    private var graphFeedbackObserver: Any?
    /// Repeating main-thread ping for `cprisk_watchdog_note_main_thread_alive` (skipped when App Store safe disables the watchdog).
    private var mainThreadWatchdogHeartbeatTimer: Timer?

    /// Signal IDs from the previous evaluate() call, used for suppression detection.
    private var previousSignalIds: Set<String> = []
    /// SHA-256 digest of previous evaluate()'s full signal content (id+score+state).
    private var previousSignalsDigest: String?
    /// High-risk signal IDs that are candidates for suppression detection.
    private static let highRiskSignalIds: Set<String> = [
        ObfuscatedConstants.signalFridaDetected,
        SignalID.fridaModuleDetected,
        SignalID.fridaModuleImage,
        SignalID.fridaModuleSection,
        SignalID.fridaModuleString,
        SignalID.fridaModuleTrampoline,
        ObfuscatedConstants.detectorIDFridaHeap, ObfuscatedConstants.signalFridaStalker, ObfuscatedConstants.detectorIDFridaSocket, ObfuscatedConstants.detectorIDFridaThread,
        ObfuscatedConstants.signalFridaJSEngineHeap, ObfuscatedConstants.signalFridaStalkerJit, ObfuscatedConstants.signalFridaUnixSocket, ObfuscatedConstants.signalFridaExceptionPort, ObfuscatedConstants.signalThreadAnomaly,
        SignalID.hookDetected, ObfuscatedConstants.detectorIDObjCSwizzle, "rwx_memory",
        ObfuscatedConstants.signalArmorRuntimeInitFailed, ObfuscatedConstants.signalIntegrityRuntimeTampered,
        "code_signature_invalid", ObfuscatedConstants.signalTextSegmentTampered,
        ObfuscatedConstants.signalAppSigningIdentityTampered, ObfuscatedConstants.signalAppSigningBaselineChanged,
        SignalID.fridaRuntimeConsensus, SignalID.antiDebugRuntimeConsensus, SignalID.signingChainConsensus,
        ObfuscatedConstants.signalKernelHookTimingAnomaly, ObfuscatedConstants.signalKernelHookStalkerAmplified,
        "system_library_wx_mapping", "system_library_anonymous_exec_region",
        "app_image_segment_layout_anomaly",
        SignalID.antiDebugWatchdogDyldInjection,
        SignalID.antiDebugWatchdogAMFICsFlags,
        SignalID.antiDebugWatchdogGetTaskAllow,
        SignalID.antiDebugWatchdogDenyAttachVerify,
        SignalID.dylibInjectImageCountLow,
        SignalID.ifaceSpawnPathDivergence,
        "dyld_monitor_suspicious_injection",
        "dyld_monitor_silent_mutation",
        "dyld_image_overload",
        "dyld_env_abuse"
    ]

    private static let remoteConfigEndpointKey = "com.cloudphone.riskkit.remote.endpoint"
    /// XCTest host marker: avoid carrying persisted protection-stability degradation state
    /// across unit-test runs, which can silently force App Store safe mode and mask watchdog assertions.
    private static let isRunningUnderXCTest: Bool = {
        let env = ProcessInfo.processInfo.environment
        if env["XCTestConfigurationFilePath"] != nil || env["XCTestSessionIdentifier"] != nil {
            return true
        }
        let processName = ProcessInfo.processInfo.processName.lowercased()
        if processName.contains("xctest") || processName.contains("swiftpm-xctest-helper") {
            return true
        }
        if NSClassFromString("XCTestCase") != nil {
            return true
        }
        return false
    }()
    private static let remoteTrustLock = UnfairLock()
    /// Digest-backed pin material (no long-lived `Set<String>` of `sha256/...` literals in static storage).
    private static var pinnedCertificatePinMaterial: PinnedCertificatePinMaterial = .empty
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

    public struct AntiDebugWatchdogSnapshot: Sendable {
        public let supported: Bool
        public let running: Bool
        public let threadActive: Bool
        public let intervalSeconds: UInt32
        public let anomalyFlags: UInt32
        public let iterationCount: UInt64
        public let tracedEventCount: UInt64
        public let denyAttachErrorCount: UInt64
        public let exceptionAnomalyCount: UInt64
        public let lastDenyAttachResult: Int32
        public let lastDenyAttachErrno: Int32
        public let lastTraced: Bool
        public let lastExceptionPortHealthy: Bool
        public let lastExceptionQuerySucceeded: Bool
        public let lastExceptionReclaimAttempted: Bool
        public let lastExceptionHijackDetected: Bool
        public let lastExceptionQueryKernReturn: Int32
        public let lastExceptionRegisterKernReturn: Int32
        public let lastCheckMonotonicNs: UInt64
        public let signalProbeResult: Bool
        public let hardwareBpDetected: Bool
        public let softwareBreakpointDetected: Bool
        public let csopsDebugged: Bool
        public let suspiciousThreadCount: UInt32
        public let singleStepDetected: Bool
        public let ttyDetected: Bool
        public let developerDiskDetected: Bool
        public let exceptionDeliveryTimeoutDetected: Bool
        public let exceptionDeliveryProbeHandled: Bool
        public let lastExceptionDeliveryProbeNs: UInt64
        public let signalProbeAnomalyCount: UInt64
        public let hardwareBpAnomalyCount: UInt64
        public let softwareBreakpointAnomalyCount: UInt64
        public let csopsAnomalyCount: UInt64
        public let suspiciousThreadAnomalyCount: UInt64
        public let exceptionDeliveryTimeoutAnomalyCount: UInt64
        public let peerWatchdogAnomalyCount: UInt64
        public let shadowStackAnomalyCount: UInt64
        public let lastPeerWatchdogStalled: Bool
        public let lastShadowStackMismatch: Bool
        public let dbiDetected: Bool
        public let dbiMarkerFlags: UInt32
        public let timingAnomalyFlags: UInt32
        public let timingProbeMedianNs: UInt64
        public let timingProbeMaxNs: UInt64
        public let timingProbeThresholdNs: UInt64
        public let dbiAnomalyCount: UInt64
        public let timingAnomalyCount: UInt64
        public let prologueIntegrityAnomalyCount: UInt64
        public let dyldInjectionAnomalyCount: UInt64
        public let lastPrologueFailMask: UInt32
        public let lastDyldInjectionFlags: UInt32
        public let lastCsopsStatusFlags: UInt32
        public let lastAmfiProbeBits: UInt32
        public let lastGetTaskAllowSuspect: Bool
        public let lastDenyAttachVerifyBits: UInt32
        public let denyAttachVerifyAnomalyCount: UInt64
        public let amfiCsFlagsAnomalyCount: UInt64
        public let getTaskAllowAnomalyCount: UInt64
        public let vmMprotectCrosscheckMismatchTotal: UInt64
        public let vmMprotectMachTrapMismatchTotal: UInt64
        /// Bitset from `cprisk_get_libc_fallback_used_mask` (libc / arc4random substitution for unavailable direct syscalls).
        public let libcFallbackUsedMask: UInt32
        /// Monotonic fallback notifications since last mask reset (`cprisk_get_libc_fallback_event_total`).
        public let libcFallbackEventTotal: UInt32
        /// Lower 8 bits = primary pthread entry path, next 8 = secondary (thunk/bridge/impl fallbacks).
        public let watchdogStartPathMask: UInt32
        /// First iteration / thread activity observed within startup grace window.
        public let watchdogStartupLivenessOk: Bool
        /// Last `cprisk_watchdog_note_main_thread_alive` monotonic timestamp (ns).
        public let mainThreadAliveMonotonicNs: UInt64
        /// Dyld injection-related env bits from earliest constructor scan.
        public let earlyInjectionEnvMask: UInt32
        /// Additional anomaly flags when `anomalyFlags` has no free bits (`CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXT_*`).
        public let watchdogExtendedAnomalyFlags: UInt32
        /// Incremented on each main-thread heartbeat ping (device watchdog path).
        public let mainThreadHeartbeatSeq: UInt64
        /// Cumulative latched main-thread stall episodes (C layer).
        public let mainThreadHeartbeatStallCount: UInt64
        /// Last primary iteration observed a latched main-thread heartbeat stall.
        public let lastMainThreadHeartbeatStalled: Bool

        public var hasAnyAnomaly: Bool {
            anomalyFlags != 0 || watchdogExtendedAnomalyFlags != 0
        }
    }

    public struct AntiDebugPlanSnapshot: Sendable {
        public let sectionPresent: Bool
        public let sectionValid: Bool
        public let parseError: UInt32
        public let entryCount: UInt32
        public let policyUnionBits: UInt32
        public let lastAppliedPolicyBits: UInt32
        public let lastProbeBits: UInt32
        public let lastGateClosed: Bool
        public let lastSoftFailMode: Bool
        public let lastDelayNs: UInt64
        public let consumeCount: UInt64
        public let escalationCount: UInt64
        public let trapEventCount: UInt64
        public let inlinePatchCount: UInt64
        public let inlinePatchFailureCount: UInt64
        public let inlinePatchArmed: Bool
        public let inlinePatchTampered: Bool
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
    /// 最近一次 `CPRiskConfig.antiDebugRuntimeMode`（不含远程叠加）。
    private var lastLocalAntiDebugMode: CPRiskAntiDebugRuntimeMode = .production
    /// 最近一次实际下发到 CRiskCore 的有效模式（本地 + `enableAppStoreSafeProfile`）。
    private var lastAppliedEffectiveAntiDebugMode: CPRiskAntiDebugRuntimeMode = .production
    private var lastEnableRemoteConfig: Bool = true
    /// 与 `latestRemoteConfig.securityHardening.enableAppStoreSafeProfile` 同步，用于远程变更后重算有效模式。
    private var lastRemoteAppStoreSafeProfileFlag: Bool = false

    /// 启动自动采集（全局触摸 + 传感器）。
    /// 建议在 `application(_:didFinishLaunchingWithOptions:)` 里尽早调用。
    @objc public func start() {
        if Self.isRunningUnderXCTest {
            // Keep XCTest deterministic: avoid mutable shared `CPRiskConfig.default` state bleed.
            start(config: CPRiskConfig())
        } else {
            start(config: .default)
        }
    }

    /// 与 `start()` 相同，但可指定 `CPRiskConfig.antiDebugRuntimeMode`（须在 armor 首次初始化前生效，见 `ensureArmorRuntimeStarted`）。
    @objc(startWithConfig:)
    public func start(config: CPRiskConfig) {
        if Self.isRunningUnderXCTest {
            ProtectionStabilityStore.shared.resetForTesting()
            stateLock.withLock {
                // Keep XCTest host deterministic: do not inherit persisted remote safe-profile flags.
                latestRemoteConfig = nil
                lastRemoteAppStoreSafeProfileFlag = false
                lastEnableRemoteConfig = false
            }
        }

        let remoteVersion = currentRemoteConfig()?.version
        let remoteSafeFlag =
            config.enableRemoteConfig && (currentRemoteConfig()?.securityHardening?.enableAppStoreSafeProfile == true)
        let effectiveForStability = Self.effectiveAntiDebugRuntimeMode(
            localMode: config.antiDebugRuntimeMode,
            remoteRequestsAppStoreSafeProfile: remoteSafeFlag
        )
        let bootstrap = ProtectionStabilityStore.shared.beginSession(
            remoteConfigVersion: remoteVersion,
            antiDebugMode: effectiveForStability,
            safeProfileAlreadyActive: false
        )
        if bootstrap.didRollbackRemoteConfig {
            refreshRemoteTrustState()
            Logger.log(
                "protection_stability: auto-rollback applied version=\(bootstrap.rolledBackToVersion.map { String($0) } ?? "nil")"
            )
        }
        if bootstrap.didEnterLocalSafeProfile || bootstrap.didActivateLocalStabilityKillSwitch {
            Logger.log(
                "protection_stability: degraded mode safeProfile=\(bootstrap.didEnterLocalSafeProfile) killSwitch=\(bootstrap.didActivateLocalStabilityKillSwitch)"
            )
        }

        let startConfig = Self.duplicatingRiskConfig(
            config,
            forceAppStoreSafe: Self.isRunningUnderXCTest ? false : ProtectionStabilityStore.shared.isLocalSafeProfileActive()
        )
        if Self.isRunningUnderXCTest {
            // Unit tests exercise watchdog/anti-debug paths; remote safe-profile override hides those assertions.
            startConfig.enableRemoteConfig = false
        }

        applyAntiDebugRuntimeConfigToCore(startConfig)
        let appStoreSafe = stateLock.withLock { lastAppliedEffectiveAntiDebugMode == .appStoreSafe }
        if appStoreSafe {
            Logger.log(
                "app_store_safe_profile: enabled — skipping cprisk_deny_attach, exception handler registration, " +
                "anti_debug_watchdog, anti_dump_probe, cprisk_erase_macho_header (armor + risk evaluation remain active)"
            )
        }

        ProtectionStabilityStore.shared.markPhase(.antiDebugPrepare)

        var watchdogStartResult: Int32 = 0
        if !appStoreSafe {
            cprisk_deny_attach()
            cprisk_register_exception_handler()
            watchdogStartResult = Int32(cprisk_start_anti_debug_watchdog())
            if watchdogStartResult != 0 {
                Logger.log("anti_debug_\(ObfuscatedConstants.keywordWatchdog).start failed rc=\(watchdogStartResult)")
                invalidateMainThreadWatchdogHeartbeat()
            } else {
                scheduleMainThreadWatchdogHeartbeat()
            }
        }

        ProtectionStabilityStore.shared.markPhase(.armorRuntimeInit)
        let armorSnapshot = ensureArmorRuntimeStarted(trigger: "start", config: startConfig)
#if os(iOS) && !targetEnvironment(macCatalyst)
        if !appStoreSafe, armorSnapshot.status == .active {
            cprisk_erase_macho_header()
        }
#endif

        ProtectionStabilityStore.shared.markPhase(.antiDumpPrepare)
        var antiDumpStartResult: Int32 = 0
        if !appStoreSafe {
            antiDumpStartResult = Int32(cprisk_start_anti_dump_probe(5))
            if antiDumpStartResult != 0 {
                Logger.log("anti_dump_probe.start failed rc=\(antiDumpStartResult)")
            }
        }

        let watchdogAnomalyFlags = antiDebugWatchdogSnapshot().anomalyFlags
        ProtectionStabilityStore.shared.recordRuntimeHealth(
            armorStatus: armorSnapshot.status.rawValue,
            armorReason: armorSnapshot.reason,
            watchdogStartResult: watchdogStartResult,
            antiDumpStartResult: antiDumpStartResult,
            watchdogAnomalyFlags: watchdogAnomalyFlags
        )

        DyldImageMonitor.shared.start()
        BuildConfig.configureForRelease()
        let sid = stateLock.withLock { () -> String? in
            currentSessionId = UUID().uuidString
            return currentSessionId
        }
        #if DEBUG
        Logger.log("sdk_start sid=\(sid ?? "")")
        #endif
        if !AppAttestSignalProvider.isHardwareTrustSupported {
            Logger.log("app_attest: hardware_trust_unsupported (evaluate will emit signal weight=95)")
        }
        ProtectionStabilityStore.shared.markPhase(.providerRegistration)
        registerProviders(for: startConfig)
        RiskSignalProviderRegistry.shared.seal()
        ConditionExpression.sealCustomEvaluators()
        installGraphFeedbackReEvaluateObserver()
#if canImport(UIKit)
        touchCapture.start()
        motionSampler.start()
        PhysicalSensorProbe.prewarm()
#endif
        ProtectionStabilityStore.shared.markStartupCompleted(remoteConfigVersion: currentRemoteConfig()?.version)
    }

    /// 保护链路稳定性与崩溃归因快照（线上排障 / 测试）。
    public func protectionStabilitySnapshot() -> ProtectionStabilitySnapshot {
        ProtectionStabilityStore.shared.currentSnapshot()
    }

    private static func duplicatingRiskConfig(_ config: CPRiskConfig, forceAppStoreSafe: Bool) -> CPRiskConfig {
        let c = CPRiskConfig()
        c.enableBehaviorDetect = config.enableBehaviorDetect
        c.enableNetworkSignals = config.enableNetworkSignals
        c.threshold = config.threshold
        c.jailbreakEnableFileDetect = config.jailbreakEnableFileDetect
        c.jailbreakEnableDyldDetect = config.jailbreakEnableDyldDetect
        c.jailbreakEnableEnvDetect = config.jailbreakEnableEnvDetect
        c.jailbreakEnableSysctlDetect = config.jailbreakEnableSysctlDetect
        c.jailbreakEnableSchemeDetect = config.jailbreakEnableSchemeDetect
        c.jailbreakEnableHookDetect = config.jailbreakEnableHookDetect
        c.jailbreakThreshold = config.jailbreakThreshold
        c.enableRemoteConfig = config.enableRemoteConfig
        c.defaultScenario = config.defaultScenario
        c.enableTemporalAnalysis = config.enableTemporalAnalysis
        c.enableAntiTamper = config.enableAntiTamper
        c.remoteConfigURLString = config.remoteConfigURLString
        if forceAppStoreSafe {
            c.antiDebugRuntimeMode = .appStoreSafe
        } else {
            c.antiDebugRuntimeMode = config.antiDebugRuntimeMode
        }
        return c
    }

    @objc public func stop() {
        Logger.log("sdk_stop")
        removeGraphFeedbackReEvaluateObserver()
        invalidateMainThreadWatchdogHeartbeat()
        cprisk_stop_anti_dump_probe()
        cprisk_stop_anti_debug_watchdog()
        resetArmorRuntime()
#if canImport(UIKit)
        motionSampler.stop()
        touchCapture.stop()
#endif
        if Self.isRunningUnderXCTest {
            ProtectionStabilityStore.shared.resetForTesting()
            stateLock.withLock {
                latestRemoteConfig = nil
                lastRemoteAppStoreSafeProfileFlag = false
                lastEnableRemoteConfig = false
                lastLocalAntiDebugMode = .production
                lastAppliedEffectiveAntiDebugMode = .production
            }
            applyAntiDebugRuntimeModeToCore(.production)
        }
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

    private func scheduleMainThreadWatchdogHeartbeat() {
        let install = { [weak self] in
            guard let self else { return }
            self.invalidateMainThreadWatchdogHeartbeatOnCurrentThread()
            cprisk_watchdog_note_main_thread_alive()
            let timer = Timer(timeInterval: 1.0, repeats: true) { _ in
                cprisk_watchdog_note_main_thread_alive()
            }
            RunLoop.main.add(timer, forMode: .common)
            self.mainThreadWatchdogHeartbeatTimer = timer
        }
        if Thread.isMainThread {
            install()
        } else {
            DispatchQueue.main.async(execute: install)
        }
    }

    private func invalidateMainThreadWatchdogHeartbeat() {
        if Thread.isMainThread {
            invalidateMainThreadWatchdogHeartbeatOnCurrentThread()
        } else {
            DispatchQueue.main.async { [weak self] in
                self?.invalidateMainThreadWatchdogHeartbeatOnCurrentThread()
            }
        }
    }

    private func invalidateMainThreadWatchdogHeartbeatOnCurrentThread() {
        mainThreadWatchdogHeartbeatTimer?.invalidate()
        mainThreadWatchdogHeartbeatTimer = nil
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
        ExternalServerAggregateProvider.shared.setDebugBypassingVerification(
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
        let material = PinnedCertificatePinMaterial(pinStrings: normalized)
        remoteTrustLock.withLock {
            pinnedCertificatePinMaterial = material
        }

        PolicyManager.shared.configurePinning(pinMaterial: material)
        shared.applyPinnedCertificateHashes(material)
        Logger.log("remote_transport_pinning configured: pins=\(material.digestCount)")
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
        stateLock.withLock {
            boundAccountId = accountId
            boundSceneTag = scene
        }
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
        resetArmorRuntime()
        stateLock.withLock {
            boundAccountId = nil
            boundSceneTag = nil
            currentSessionId = nil
            previousSignalIds = []
            previousSignalsDigest = nil
        }
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
        return configureRemoteConfigProvider(urlString: endpoint)
    }

    /// 清除远程配置地址和缓存状态。
    @objc public func clearRemoteConfigEndpoint() {
        stateLock.withLock {
            remoteConfigProvider = nil
            remoteConfigEndpoint = nil
            latestRemoteConfig = nil
            lastRemoteAppStoreSafeProfileFlag = false
        }
        reapplyAntiDebugRuntimeModeAfterRemoteConfigChange()

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
        stateLock.withLock {
            textSegmentReferenceResolver = resolver
        }
    }

    // MARK: - Evaluation

    @objc public func evaluate() -> CPRiskReport {
        return evaluate(config: .default)
    }

    /// 生成一次完整风控报告（保持 1.0 入口，内部走 2.0 决策链路）。
    @objc(evaluateWithConfig:)
    public func evaluate(config: CPRiskConfig = .default) -> CPRiskReport {
        return evaluate(config: config, scenario: config.defaultScenario)
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
        // Ensure CRiskCore mode matches config + remote before any attach/exception paths; production keeps deny_attach before armor init.
        applyAntiDebugRuntimeConfigToCore(config)
        let appStoreSafeEval = stateLock.withLock { lastAppliedEffectiveAntiDebugMode == .appStoreSafe }
        if !appStoreSafeEval {
            cprisk_deny_attach()
            cprisk_register_exception_handler()
        }
        let armorRuntimeSnapshot = ensureArmorRuntimeStarted(trigger: "evaluate", config: nil)
        // Recheck integrity when armor runtime is active; on tampering, material may
        // silently switch to decoy bytes instead of surfacing a direct return-code oracle.
        if armorRuntimeSnapshot.status == .active {
            _ = cprisk_recheck_integrity()
        }
        if !appStoreSafeEval {
            Self.maybeVerifyExceptionHandler()
        }

        let context = buildRiskContext(config: runtimeConfig)
        let serverPolicy = PolicyManager.shared.activePolicy
        let watchdogSnapshot = antiDebugWatchdogSnapshot()
        let snapshot = RiskSnapshot(
            deviceID: context.deviceID,
            device: context.device,
            network: context.network,
            behavior: context.behavior,
            jailbreak: context.jailbreak,
            mutationStrategy: resolveMutationStrategy(from: serverPolicy),
            antiDebugWatchdogSupported: watchdogSnapshot.supported,
            libcFallbackUsedMask: watchdogSnapshot.libcFallbackUsedMask,
            libcFallbackEventTotal: watchdogSnapshot.libcFallbackEventTotal
        )
        let serverSignals = RiskSignalProviderRegistry.shared.serverSignals(snapshot: snapshot)
        let (acctIdForGraph, sessIdForGraph) = stateLock.withLock {
            (boundAccountId, currentSessionId)
        }

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
        let prevIds = stateLock.withLock { previousSignalIds }
        if !prevIds.isEmpty {
            let previousHighRisk = prevIds.intersection(Self.highRiskSignalIds)
            let currentHighRisk = allCurrentSignalIds.intersection(Self.highRiskSignalIds)
            let suppressedIds = previousHighRisk.subtracting(currentHighRisk)
            if suppressedIds.count >= 2 || (previousHighRisk.count > 0 && currentHighRisk.isEmpty) {
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
            mappingVersion: verdict.mappingVersion,
            action: verdict.internalAction,
            primaryReasons: verdict.primaryReasons,
            decisionMetadata: verdict.decisionMetadata
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
        let antiTamperHit = tamperedSignals.contains { $0.category == ObfuscatedConstants.categoryAntiTamper || $0.category == "integrity" }
        var mergedJailbreak = context.jailbreak
        if antiTamperHit && !mergedJailbreak.isJailbroken {
            let antiTamperMethods = tamperedSignals
                .filter { $0.category == ObfuscatedConstants.categoryAntiTamper || $0.category == "integrity" }
                .map { "\(ObfuscatedConstants.antiTamperMethodPrefix)\($0.id)" }
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
        let (acctId, sessId, scnTag) = stateLock.withLock {
            (boundAccountId, currentSessionId, boundSceneTag)
        }
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
        // Use pre-engine extraSignals IDs (not verdict.signals) so the comparison in the
        // continuity check at the start of evaluate() compares the same signal stage.
        stateLock.withLock {
            previousSignalIds = allCurrentSignalIds
            previousSignalsDigest = SignalDigest.computeFullDigest(verdict.signals)
        }

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

        var payloadData = report.unencryptedPayloadData(prettyPrinted: false)
        if !hardening.enableChallengeBinding {
            payloadData = try removingPayloadKey("challengeBinding", from: payloadData)
        }

        let effectiveKeyId: String
        if keyId == "k1",
           TrustChainManager.currentKeyRotationPolicy() != nil {
            effectiveKeyId = TrustChainManager.currentKeyId(baseKeyId: keyId)
        } else {
            effectiveKeyId = keyId
        }

        let trustLevel = TrustChainManager.evaluateTrustLevel(
            deviceID: report.deviceID,
            hardwareMachine: report.device.hardwareMachine ?? "",
            kernelVersion: Sysctl.string("kern.version") ?? ""
        )

        let armorSnapshot = ensureArmorRuntimeStarted(trigger: "build_envelope")
        let signatureVersion: String
        let signatureProvider: ((Data) throws -> String)?
        let bindingMode: String

        if armorSnapshot.status == .active {
            let authentic = cprisk_is_integrity_poisoned() == 0
            if authentic {
                signatureProvider = { signatureInput in
                    guard let signature = Self.signWithArmorDerivedKey(
                        baseKey: signingKey,
                        signatureInput: signatureInput
                    ) else {
                        throw ReportEnvelope.ReportEnvelopeError.signingFailed
                    }
                    return signature
                }
                #if DEBUG
                signatureVersion = hardening.enableEnvelopeSignatureV2 ? "v2a" : "v1"
                #else
                signatureVersion = "v2a"
                #endif
                bindingMode = "armor_request_binding_sha256_v1"
            } else if requireArmor {
                Logger.log("buildSecureReportEnvelope: armor material marked poisoned by runtime state")
                throw SecureUploadError.armorRuntimeUnavailable(reason: "material_poisoned")
            } else {
                Logger.log("buildSecureReportEnvelope: armor material marked poisoned, degrading to v2d signature")
                signatureProvider = nil
                signatureVersion = "v2d"
                bindingMode = "plain_hmac_fallback_v1"
            }
        } else if requireArmor {
            Logger.log("buildSecureReportEnvelope: armor unavailable status=\(armorSnapshot.status.rawValue) reason=\(armorSnapshot.reason)")
            throw SecureUploadError.armorRuntimeUnavailable(reason: armorSnapshot.reason)
        } else {
            Logger.log("buildSecureReportEnvelope: armor unavailable, degrading to v2d signature (status=\(armorSnapshot.status.rawValue))")
            signatureProvider = nil
            signatureVersion = "v2d"
            bindingMode = "plain_hmac_fallback_v1"
        }

        let envelopeConfig = ReportEnvelope.Config(signatureVersion: signatureVersion)

        return try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: report.reportID,
            sessionToken: sessionToken,
            signingKey: signingKey,
            keyId: effectiveKeyId,
            fieldMapping: mapping,
            attestationKeyId: attestationKeyId,
            trustLevel: trustLevel,
            config: envelopeConfig,
            signatureProvider: signatureProvider,
            bindingMode: bindingMode
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
        let sceneTag = stateLock.withLock { boundSceneTag }
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
        let sceneTag = stateLock.withLock { boundSceneTag }
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
        let effectiveKeyId: String
        if keyId == "k1",
           TrustChainManager.currentKeyRotationPolicy() != nil {
            effectiveKeyId = TrustChainManager.currentKeyId(baseKeyId: keyId)
        } else {
            effectiveKeyId = keyId
        }

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
    ///
    /// - Note: 建议迁移到 async/await 版本 `evaluateAsync()` 或 `RiskEvaluationActor.shared.evaluate()`。
    @available(*, deprecated, message: "Use async/await evaluateAsync() or RiskEvaluationActor.shared.evaluate() instead")
    @objc(evaluateAsyncWithCompletion:)
    public func evaluateAsync(completion: @escaping (CPRiskReport) -> Void) {
        evaluateAsync(config: .default, scenario: .default, completion: completion)
    }

    /// 异步生成报告（保持 1.0 API）。
    /// completion 始终回到主线程。
    ///
    /// - Note: 建议迁移到 async/await 版本。
    @available(*, deprecated, message: "Use async/await evaluateAsync(config:) instead")
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
    ///
    /// - Note: 建议迁移到 async/await 版本。
    @available(*, deprecated, message: "Use async/await evaluateAsync(config:scenario:) instead")
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
        let snapshot = stateLock.withLock { armorRuntimeSnapshot }
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

    public func antiDebugWatchdogSnapshot() -> AntiDebugWatchdogSnapshot {
        var raw = cprisk_anti_debug_watchdog_snapshot_t()
        _ = cprisk_get_anti_debug_watchdog_snapshot(&raw)
        return AntiDebugWatchdogSnapshot(
            supported: raw.supported != 0,
            running: raw.running != 0,
            threadActive: raw.thread_active != 0,
            intervalSeconds: raw.interval_seconds,
            anomalyFlags: raw.anomaly_flags,
            iterationCount: raw.iteration_count,
            tracedEventCount: raw.traced_event_count,
            denyAttachErrorCount: raw.deny_attach_error_count,
            exceptionAnomalyCount: raw.exception_anomaly_count,
            lastDenyAttachResult: raw.last_deny_attach_result,
            lastDenyAttachErrno: raw.last_deny_attach_errno,
            lastTraced: raw.last_traced != 0,
            lastExceptionPortHealthy: raw.last_exception_port_healthy != 0,
            lastExceptionQuerySucceeded: raw.last_exception_query_succeeded != 0,
            lastExceptionReclaimAttempted: raw.last_exception_reclaim_attempted != 0,
            lastExceptionHijackDetected: raw.last_exception_hijack_detected != 0,
            lastExceptionQueryKernReturn: raw.last_exception_query_kern_return,
            lastExceptionRegisterKernReturn: raw.last_exception_register_kern_return,
            lastCheckMonotonicNs: raw.last_check_monotonic_ns,
            signalProbeResult: raw.last_signal_probe_result != 0,
            hardwareBpDetected: raw.last_hardware_bp_detected != 0,
            softwareBreakpointDetected: raw.last_software_bp_detected != 0,
            csopsDebugged: raw.last_csops_debugged != 0,
            suspiciousThreadCount: raw.last_suspicious_thread_count,
            singleStepDetected: raw.last_single_step_detected != 0,
            ttyDetected: raw.last_tty_detected != 0,
            developerDiskDetected: raw.last_developer_disk_detected != 0,
            exceptionDeliveryTimeoutDetected: raw.last_exception_delivery_timeout_detected != 0,
            exceptionDeliveryProbeHandled: raw.last_exception_delivery_probe_handled != 0,
            lastExceptionDeliveryProbeNs: raw.last_exception_delivery_probe_ns,
            signalProbeAnomalyCount: raw.signal_probe_anomaly_count,
            hardwareBpAnomalyCount: raw.hardware_bp_anomaly_count,
            softwareBreakpointAnomalyCount: raw.software_bp_anomaly_count,
            csopsAnomalyCount: raw.csops_anomaly_count,
            suspiciousThreadAnomalyCount: raw.suspicious_thread_anomaly_count,
            exceptionDeliveryTimeoutAnomalyCount: raw.exception_delivery_timeout_anomaly_count,
            peerWatchdogAnomalyCount: raw.peer_watchdog_anomaly_count,
            shadowStackAnomalyCount: raw.shadow_stack_anomaly_count,
            lastPeerWatchdogStalled: raw.last_peer_watchdog_stalled != 0,
            lastShadowStackMismatch: raw.last_shadow_stack_mismatch != 0,
            dbiDetected: raw.last_dbi_detected != 0,
            dbiMarkerFlags: raw.last_dbi_marker_flags,
            timingAnomalyFlags: raw.last_timing_anomaly_flags,
            timingProbeMedianNs: raw.last_timing_probe_median_ns,
            timingProbeMaxNs: raw.last_timing_probe_max_ns,
            timingProbeThresholdNs: raw.last_timing_probe_threshold_ns,
            dbiAnomalyCount: raw.dbi_anomaly_count,
            timingAnomalyCount: raw.timing_anomaly_count,
            prologueIntegrityAnomalyCount: raw.prologue_integrity_anomaly_count,
            dyldInjectionAnomalyCount: raw.dyld_injection_anomaly_count,
            lastPrologueFailMask: raw.last_prologue_fail_mask,
            lastDyldInjectionFlags: raw.last_dyld_injection_flags,
            lastCsopsStatusFlags: raw.last_csops_status_flags,
            lastAmfiProbeBits: raw.last_amfi_probe_bits,
            lastGetTaskAllowSuspect: raw.last_get_task_allow_suspect != 0,
            lastDenyAttachVerifyBits: raw.last_deny_attach_verify_bits,
            denyAttachVerifyAnomalyCount: raw.deny_attach_verify_anomaly_count,
            amfiCsFlagsAnomalyCount: raw.amfi_cs_flags_anomaly_count,
            getTaskAllowAnomalyCount: raw.get_task_allow_anomaly_count,
            vmMprotectCrosscheckMismatchTotal: raw.vm_mprotect_crosscheck_mismatch_total,
            vmMprotectMachTrapMismatchTotal: raw.vm_mprotect_mach_trap_mismatch_total,
            libcFallbackUsedMask: raw.libc_fallback_used_mask,
            libcFallbackEventTotal: raw.libc_fallback_event_total,
            watchdogStartPathMask: raw.watchdog_start_path_mask,
            watchdogStartupLivenessOk: raw.watchdog_startup_liveness_ok != 0,
            mainThreadAliveMonotonicNs: raw.main_thread_alive_monotonic_ns,
            earlyInjectionEnvMask: raw.early_injection_env_mask,
            watchdogExtendedAnomalyFlags: raw.watchdog_extended_anomaly_flags,
            mainThreadHeartbeatSeq: raw.main_thread_heartbeat_seq,
            mainThreadHeartbeatStallCount: raw.main_thread_heartbeat_stall_count,
            lastMainThreadHeartbeatStalled: raw.last_main_thread_heartbeat_stalled != 0
        )
    }

    public func antiDebugPlanSnapshot() -> AntiDebugPlanSnapshot {
        var raw = cprisk_antidebug_plan_snapshot_t()
        _ = cprisk_get_antidebug_plan_snapshot(&raw)
        return AntiDebugPlanSnapshot(
            sectionPresent: raw.section_present != 0,
            sectionValid: raw.section_valid != 0,
            parseError: raw.parse_error,
            entryCount: raw.entry_count,
            policyUnionBits: raw.policy_union_bits,
            lastAppliedPolicyBits: raw.last_applied_policy_bits,
            lastProbeBits: raw.last_probe_bits,
            lastGateClosed: raw.last_gate_closed != 0,
            lastSoftFailMode: raw.last_soft_fail_mode != 0,
            lastDelayNs: raw.last_delay_ns,
            consumeCount: raw.consume_count,
            escalationCount: raw.escalation_count,
            trapEventCount: raw.trap_event_count,
            inlinePatchCount: raw.inline_patch_count,
            inlinePatchFailureCount: raw.inline_patch_failure_count,
            inlinePatchArmed: raw.inline_patch_armed != 0,
            inlinePatchTampered: raw.last_inline_patch_tamper != 0
        )
    }

    private func registerProviders(for config: CPRiskConfig) {
        BuiltInProviderBootstrap.apply(to: RiskSignalProviderRegistry.shared, config: config)
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

    private func applyAntiDebugRuntimeModeToCore(_ mode: CPRiskAntiDebugRuntimeMode) {
        switch mode {
        case .production:
            cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_PRODUCTION))
        case .relaxedDevelopmentQA:
            cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA))
        case .appStoreSafe:
            cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE))
        @unknown default:
            cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_PRODUCTION))
        }
    }

    /// 合并本地 `antiDebugRuntimeMode` 与远程 `enableAppStoreSafeProfile`；本地 `.appStoreSafe` 优先且不要求远程。
    internal static func effectiveAntiDebugRuntimeMode(
        localMode: CPRiskAntiDebugRuntimeMode,
        remoteRequestsAppStoreSafeProfile: Bool
    ) -> CPRiskAntiDebugRuntimeMode {
        if localMode == .appStoreSafe { return .appStoreSafe }
        if remoteRequestsAppStoreSafeProfile { return .appStoreSafe }
        return localMode
    }

    private func applyAntiDebugRuntimeConfigToCore(_ config: CPRiskConfig) {
        stateLock.withLock {
            lastLocalAntiDebugMode = config.antiDebugRuntimeMode
            lastEnableRemoteConfig = config.enableRemoteConfig
        }
        let remoteFlag = stateLock.withLock {
            lastEnableRemoteConfig && lastRemoteAppStoreSafeProfileFlag
        }
        let effective = Self.effectiveAntiDebugRuntimeMode(
            localMode: config.antiDebugRuntimeMode,
            remoteRequestsAppStoreSafeProfile: remoteFlag
        )
        stateLock.withLock { lastAppliedEffectiveAntiDebugMode = effective }
        applyAntiDebugRuntimeModeToCore(effective)
    }

    private func reapplyAntiDebugRuntimeModeAfterRemoteConfigChange() {
        let local = stateLock.withLock { lastLocalAntiDebugMode }
        let remote = stateLock.withLock { lastEnableRemoteConfig && lastRemoteAppStoreSafeProfileFlag }
        let effective = Self.effectiveAntiDebugRuntimeMode(
            localMode: local,
            remoteRequestsAppStoreSafeProfile: remote
        )
        stateLock.withLock { lastAppliedEffectiveAntiDebugMode = effective }
        applyAntiDebugRuntimeModeToCore(effective)
    }

    @discardableResult
    private func ensureArmorRuntimeStarted(trigger: String, config: CPRiskConfig? = nil) -> ArmorRuntimeSnapshot {
        if let config {
            applyAntiDebugRuntimeConfigToCore(config)
        } else {
            let mode = stateLock.withLock { lastAppliedEffectiveAntiDebugMode }
            applyAntiDebugRuntimeModeToCore(mode)
        }

        let existing: ArmorRuntimeSnapshot? = stateLock.withLock {
            armorRuntimeSnapshot.status != .inactive ? armorRuntimeSnapshot : nil
        }
        if let existing { return existing }

        let (attemptCount, anchorPresent, keyResolution) = stateLock.withLock {
            (armorRuntimeSnapshot.attemptCount + 1, Self.hasArmorAnchor(), Self.resolveArmorRootKey())
        }

        // 在锁外构建 snapshot，避免持 stateLock 期间调用可能阻塞的 cprisk_init_protection
        var snapshot = ArmorRuntimeSnapshot(
            status: .unavailable,
            reason: "uninitialized",
            initCode: nil,
            trigger: trigger,
            rootKeySource: keyResolution.source,
            debugFallbackUsed: keyResolution.debugFallbackUsed,
            anchorPresent: anchorPresent,
            attemptCount: attemptCount
        )
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
            let earlySnapshot: ArmorRuntimeSnapshot? = armorInitLock.withLock {
                let alreadyStarted = stateLock.withLock { armorRuntimeSnapshot.status != .inactive }
                if alreadyStarted {
                    return stateLock.withLock { armorRuntimeSnapshot }
                }

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
                stateLock.withLock { armorRuntimeSnapshot = snapshot }
                return nil
            }
            if let earlySnapshot { return earlySnapshot }
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

        let finalSnapshot: ArmorRuntimeSnapshot = stateLock.withLock {
            if armorRuntimeSnapshot.status == .inactive {
                armorRuntimeSnapshot = snapshot
            }
            return armorRuntimeSnapshot
        }

        Self.logArmorRuntimeSnapshot(finalSnapshot)
        return finalSnapshot
    }

    private func resetArmorRuntime() {
        let shouldCleanup = stateLock.withLock {
            lastLocalAntiDebugMode = .production
            lastAppliedEffectiveAntiDebugMode = Self.effectiveAntiDebugRuntimeMode(
                localMode: .production,
                remoteRequestsAppStoreSafeProfile: lastEnableRemoteConfig && lastRemoteAppStoreSafeProfileFlag
            )
            let cleanup = armorRuntimeSnapshot.status != .inactive || armorRuntimeSnapshot.attemptCount > 0
            armorRuntimeSnapshot = .inactive
            return cleanup
        }

        if shouldCleanup {
            cprisk_cleanup_protection()
            Logger.log("armor_runtime.cleanup")
        }
        applyAntiDebugRuntimeModeToCore(
            stateLock.withLock { lastAppliedEffectiveAntiDebugMode }
        )
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

        let mutationStrategy = resolveMutationStrategy(from: serverPolicy)

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
            killSwitchEnabled: (remoteConfig?.securityHardening?.killSwitchEnabled ?? false)
                || ProtectionStabilityStore.shared.isLocalStabilityKillSwitchEnabled(),
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

    private func resolveMutationStrategy(from serverPolicy: ServerRiskPolicy?) -> MutationStrategy? {
        serverPolicy?.mutation.map { mutation in
            MutationStrategy(
                seed: mutation.seed,
                shuffleChecks: mutation.shuffleChecks,
                thresholdJitterBps: mutation.thresholdJitterBps,
                scoreJitterBps: mutation.scoreJitterBps
            )
        }
    }

    private func currentRemoteConfigProvider() -> RemoteConfigProvider? {
        let (provider, endpoint) = stateLock.withLock { (remoteConfigProvider, remoteConfigEndpoint) }

        if let provider {
            return provider
        }

        if let endpoint {
            _ = configureRemoteConfigProvider(urlString: endpoint.absoluteString)
        } else if let persisted = UserDefaults.standard.string(forKey: Self.remoteConfigEndpointKey) {
            _ = configureRemoteConfigProvider(urlString: persisted)
        }

        return stateLock.withLock { remoteConfigProvider }
    }

    /// 供 TextSegmentIntegrityChecker 等服务端参考哈希校验使用
    internal func currentRemoteConfig() -> RemoteConfig? {
        let (cached, provider) = stateLock.withLock { (latestRemoteConfig, remoteConfigProvider) }

        if let cached {
            return cached
        }

        return provider?.currentConfig
    }


    /// 解析当前 SDK 版本的可信 __TEXT.__text 参考哈希。
    /// 优先走业务方注入的解析器；若未提供或返回 nil，则回退到 RemoteConfig。
    internal func resolveTextSegmentReference(for sdkVersion: String) -> TextSegmentReference? {
        let (resolver, cached, provider) = stateLock.withLock { (textSegmentReferenceResolver, latestRemoteConfig, remoteConfigProvider) }

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

        let (sameEndpoint, existingProvider, hasCachedConfig) = stateLock.withLock {
            (remoteConfigEndpoint == url, remoteConfigProvider, latestRemoteConfig != nil)
        }

        if sameEndpoint, let existingProvider {
            existingProvider.configurePinning(pinMaterial: Self.currentPinnedPinMaterial())
            existingProvider.reloadCachedConfigTrustState()
            if !hasCachedConfig {
                _ = applyRemoteConfigIfAccepted(existingProvider.currentConfig, source: "provider_reuse")
            }
            return true
        }

        let provider = RemoteConfigProvider(
            configURL: url,
            pinnedPinMaterial: Self.currentPinnedPinMaterial()
        )
        stateLock.withLock {
            remoteConfigEndpoint = url
            remoteConfigProvider = provider
        }

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

        let remoteSafe = effectiveConfig.securityHardening?.enableAppStoreSafeProfile ?? false

        let accepted = stateLock.withLock { () -> Bool in
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

        if accepted {
            stateLock.withLock { lastRemoteAppStoreSafeProfileFlag = remoteSafe }
            reapplyAntiDebugRuntimeModeAfterRemoteConfigChange()
        }

        return accepted
    }

    private func applyPinnedCertificateHashes(_ material: PinnedCertificatePinMaterial) {
        currentRemoteConfigProvider()?.configurePinning(pinMaterial: material)
    }

    private func refreshRemoteTrustState() {
        if let provider = currentRemoteConfigProvider() {
            provider.reloadCachedConfigTrustState()
            _ = applyRemoteConfigIfAccepted(provider.currentConfig, source: "trust_refresh", validateStrictly: false)
        } else {
            stateLock.withLock {
                latestRemoteConfig = nil
                lastRemoteAppStoreSafeProfileFlag = false
            }
            reapplyAntiDebugRuntimeModeAfterRemoteConfigChange()
        }
        PolicyManager.shared.reloadTrustedCacheState()
    }

    /// Throttled cprisk_verify_exception_handler to reduce task_get_exception_ports syscall frequency.
    private static func maybeVerifyExceptionHandler() {
        let shouldVerify = verifyThrottleLock.withLock {
            let now = Date().timeIntervalSince1970
            let verify = (now - lastExceptionVerifyTime) >= verifyThrottleInterval
            if verify { lastExceptionVerifyTime = now }
            return verify
        }
        if shouldVerify {
            cprisk_verify_exception_handler()
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
            signalID = ObfuscatedConstants.signalArmorRuntimeInitFailed
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
            category: ObfuscatedConstants.categoryAntiTamper,
            score: score,
            evidence: evidence,
            state: state,
            layer: 2,
            weightHint: score
        )
    }

    /// Signal emitted when the integrity poison flag is set.
    /// The poison source may be runtime recheck mismatch or an upper-layer
    /// hard tamper decision, and in both cases envelope signing eventually uses
    /// the wrong key and server verification fails.
    private static func integrityRecheckPoisonedSignal() -> RiskSignal {
        RiskSignal(
            id: ObfuscatedConstants.signalIntegrityRuntimeTampered,
            category: "integrity",
            score: 85,
            evidence: ["reason": "integrity_poison_flag_set"],
            state: .tampered,
            layer: 2,
            weightHint: 85
        )
    }

    private static func mprotectTamperedSignal() -> RiskSignal {
        RiskSignal(
            id: ObfuscatedConstants.signalMemoryProtectionTampered,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 85,
            evidence: ["detail": "mprotect_syscall_blocked"],
            state: .tampered,
            layer: 1,
            weightHint: 90
        )
    }

    /// Trims whitespace; invalid pins are ignored when building ``PinnedCertificatePinMaterial``.
    private static func normalizedPinnedCertificateHashes(from hashes: [String]) -> Set<String> {
        Set(
            hashes
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        )
    }

    private static func currentPinnedPinMaterial() -> PinnedCertificatePinMaterial {
        remoteTrustLock.withLock { pinnedCertificatePinMaterial }
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

    // MARK: - Armor-backed Envelope Signing

    private static func clearCStringBuffer(_ buffer: inout [CChar]) {
        for index in buffer.indices {
            buffer[index] = 0
        }
    }

    private static func requestBindingDigest(for signatureInput: Data) -> Data {
        Data(SHA256.hash(data: signatureInput))
    }

    private static func signWithArmorDerivedKey(baseKey: String, signatureInput: Data) -> String? {
        guard var keyData = baseKey.data(using: .utf8) else {
            Logger.log("armor_sign: UTF-8 encoding failed for baseKey")
            return nil
        }
        defer { secureZeroData(&keyData) }
        var bindingDigest = requestBindingDigest(for: signatureInput)
        defer { secureZeroData(&bindingDigest) }

        var signatureBuffer = [CChar](
            repeating: 0,
            count: Int(CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE) + 1
        )
        defer { clearCStringBuffer(&signatureBuffer) }

        let rc = signatureBuffer.withUnsafeMutableBufferPointer { signaturePtr in
            keyData.withUnsafeBytes { keyRaw in
                bindingDigest.withUnsafeBytes { digestRaw in
                    signatureInput.withUnsafeBytes { inputRaw in
                        guard let keyPtr = keyRaw.bindMemory(to: UInt8.self).baseAddress,
                              let digestPtr = digestRaw.bindMemory(to: UInt8.self).baseAddress,
                              let inputPtr = inputRaw.bindMemory(to: UInt8.self).baseAddress,
                              let sigPtr = signaturePtr.baseAddress else {
                            return Int32(-1)
                        }
                        return cprisk_sign_with_derived_key_and_request_binding_digest(
                            keyPtr,
                            keyData.count,
                            inputPtr,
                            signatureInput.count,
                            digestPtr,
                            sigPtr
                        )
                    }
                }
            }
        }
        guard rc == 0 else {
            Logger.log("armor_sign: bound cprisk_sign_with_derived_key failed rc=\(rc)")
            return nil
        }
        return String(cString: signatureBuffer)
    }

    private static func verifyWithArmorDerivedKey(
        baseKey: String,
        signatureInput: Data,
        expectedSignature: String
    ) -> Bool {
        guard var keyData = baseKey.data(using: .utf8) else {
            Logger.log("armor_verify: UTF-8 encoding failed for baseKey")
            return false
        }
        defer { secureZeroData(&keyData) }
        var bindingDigest = requestBindingDigest(for: signatureInput)
        defer { secureZeroData(&bindingDigest) }

        var expectedCString = Array(expectedSignature.utf8CString)
        defer { clearCStringBuffer(&expectedCString) }

        let rc = expectedCString.withUnsafeBufferPointer { signaturePtr in
            keyData.withUnsafeBytes { keyRaw in
                bindingDigest.withUnsafeBytes { digestRaw in
                    signatureInput.withUnsafeBytes { inputRaw in
                        guard let keyPtr = keyRaw.bindMemory(to: UInt8.self).baseAddress,
                              let digestPtr = digestRaw.bindMemory(to: UInt8.self).baseAddress,
                              let inputPtr = inputRaw.bindMemory(to: UInt8.self).baseAddress,
                              let sigPtr = signaturePtr.baseAddress else {
                            return Int32(-1)
                        }
                        return cprisk_verify_with_derived_key_and_request_binding_digest(
                            keyPtr,
                            keyData.count,
                            inputPtr,
                            signatureInput.count,
                            digestPtr,
                            sigPtr
                        )
                    }
                }
            }
        }
        return rc == 0
    }

    /// v2a 本地验签走 C helper，Swift 不再直接持有 runtime material 或派生后的 effective key。
    func validateEnvelopeWithArmorDerivedSignature(
        _ envelope: ReportEnvelope,
        baseKey: String,
        nonceStore: NonceReplayProtecting? = nil,
        config: ReportEnvelope.Config = ReportEnvelope.Config()
    ) -> Result<Void, ReportEnvelope.ReportEnvelopeError> {
        let snapshot = ensureArmorRuntimeStarted(trigger: "validate_envelope")
        guard snapshot.status == .active else { return .failure(.signingFailed) }
        guard cprisk_is_integrity_poisoned() == 0 else { return .failure(.signingFailed) }

        return envelope.validate(
            signatureValidator: { signatureInput, signatureHex in
                Self.verifyWithArmorDerivedKey(
                    baseKey: baseKey,
                    signatureInput: signatureInput,
                    expectedSignature: signatureHex
                )
            },
            nonceStore: nonceStore,
            config: config
        )
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
