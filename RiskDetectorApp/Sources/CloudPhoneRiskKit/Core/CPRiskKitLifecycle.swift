// MARK: - CPRiskKit+Lifecycle
//
// 从 CloudPhoneRiskKit.swift 拆分：start(), stop(), deinit,
// graph feedback observer, watchdog heartbeat, provider registration。

import CRiskCore
import Foundation
#if canImport(UIKit)
import UIKit
#endif

extension CPRiskKit {

    // MARK: - Start

    internal func startImpl() {
        if Self.isRunningUnderXCTest {
            start(config: CPRiskConfig())
        } else {
            start(config: .default)
        }
    }

    internal func startImpl(config: CPRiskConfig) {
        if Self.isRunningUnderXCTest {
            ProtectionStabilityStore.shared.resetForTesting()
            stateLock.withLock {
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

    // MARK: - Stop

    internal func stopImpl() {
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

    // MARK: - Graph Feedback Observer

    internal func installGraphFeedbackReEvaluateObserver() {
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

    internal func removeGraphFeedbackReEvaluateObserver() {
        if let obs = graphFeedbackObserver {
            NotificationCenter.default.removeObserver(obs)
            graphFeedbackObserver = nil
        }
    }

    // MARK: - Watchdog Heartbeat

    internal func scheduleMainThreadWatchdogHeartbeat() {
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

    internal func invalidateMainThreadWatchdogHeartbeat() {
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

    // MARK: - Provider Registration

    internal func registerProviders(for config: CPRiskConfig) {
        BuiltInProviderBootstrap.apply(to: RiskSignalProviderRegistry.shared, config: config)
    }

    // MARK: - Config Duplication

    internal static func duplicatingRiskConfig(_ config: CPRiskConfig, forceAppStoreSafe: Bool) -> CPRiskConfig {
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
}
