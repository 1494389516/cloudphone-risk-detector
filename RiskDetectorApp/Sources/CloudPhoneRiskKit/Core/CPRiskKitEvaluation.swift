// MARK: - CPRiskKit+Evaluation
//
// 从 CloudPhoneRiskKit.swift 拆分：evaluate() 核心管线、信号采集、
// adaptive throttle、runtime config 解析、engine policy 构建。

import CryptoKit
import CRiskCore
import Foundation
#if canImport(UIKit)
import UIKit
#endif

extension CPRiskKit {

    // MARK: - Core Evaluation Pipeline

    internal func evaluateImpl(config: CPRiskConfig, scenario: RiskScenario) -> CPRiskReport {
        var runtimeConfig = resolveRuntimeConfig(from: config)
        enforceSecurityFloor(&runtimeConfig)
        let remoteConfig = config.enableRemoteConfig ? currentRemoteConfig() : nil
        let realtimeAdaptiveProfile = resolveRealtimeAdaptiveProfile(remoteConfig: remoteConfig)

        if let cached = maybeReturnAdaptiveCachedReport(
            profile: realtimeAdaptiveProfile,
            scenario: scenario,
            runtimeConfig: runtimeConfig,
            remoteConfig: remoteConfig
        ) {
            return cached
        }

        Logger.log(
            "evaluate(config,scenario): scenario=\(scenario.identifier) threshold=\(runtimeConfig.threshold) " +
            "behavior=\(runtimeConfig.enableBehaviorDetect) network=\(runtimeConfig.enableNetworkSignals) " +
            "remote=\(remoteConfig != nil) temporal=\(config.enableTemporalAnalysis) antiTamper=\(config.enableAntiTamper)"
        )

        registerProviders(for: config)
        if !RiskSignalProviderRegistry.shared.isSealed {
            RiskSignalProviderRegistry.shared.seal()
            ConditionExpression.sealCustomEvaluators()
        }
        applyAntiDebugRuntimeConfigToCore(config)
        let appStoreSafeEval = stateLock.withLock { lastAppliedEffectiveAntiDebugMode == .appStoreSafe }
        if !appStoreSafeEval {
            cprisk_deny_attach()
            cprisk_register_exception_handler()
        }
        let armorRuntimeSnapshot = ensureArmorRuntimeStarted(trigger: "evaluate", config: nil)
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
            serverPolicy: serverPolicy,
            realtimeAdaptiveProfile: realtimeAdaptiveProfile
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

        updateAdaptiveCachedReport(
            out,
            profile: realtimeAdaptiveProfile,
            scenario: scenario,
            runtimeConfig: runtimeConfig,
            remoteConfig: remoteConfig
        )

        // Dispatch hostile-environment C-layer signals to the registered reporter
        // so the SDK consumer can forward them to their server for a second
        // verification layer that cannot be bypassed through binary patching.
        let reporter = stateLock.withLock { hostileEnvironmentReporter }
        dispatchHostileEnvironmentReport(to: reporter)

        return out
    }

    // MARK: - Risk Context

    internal func buildRiskContext(config: RiskConfig) -> RiskContext {
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

    // MARK: - Security Floor

    internal func enforceSecurityFloor(_ config: inout RiskConfig) {
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
#if !DEBUG
        config.enableBehaviorDetect = true
        config.enableNetworkSignals = true
        config.jailbreak.enableFileDetect = true
        config.jailbreak.enableDyldDetect = true
        config.jailbreak.enableSysctlDetect = true
        config.jailbreak.enableHookDetect = true
#endif
    }

    // MARK: - Runtime Config Resolution

    internal func resolveRuntimeConfig(from config: CPRiskConfig) -> RiskConfig {
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

    // MARK: - Engine Policy

    internal func buildEnginePolicy(
        runtimeConfig: RiskConfig,
        remoteConfig: RemoteConfig?,
        enableTemporalAnalysis: Bool,
        serverPolicy: ServerRiskPolicy?,
        realtimeAdaptiveProfile: RealtimeAdaptiveProfile?
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
            let adaptiveWeights = applyRealtimeAdaptiveWeightScale(
                effectiveWeights,
                profile: realtimeAdaptiveProfile
            )

            scenarioPolicies[scenario] = ScenarioPolicy(
                mediumThreshold: mediumThreshold,
                highThreshold: highThreshold,
                criticalThreshold: criticalThreshold,
                actionMapping: base.actionMapping,
                signalWeights: adaptiveWeights,
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

    // MARK: - Adaptive Telemetry

    internal func resolveRealtimeAdaptiveProfile(remoteConfig: RemoteConfig?) -> RealtimeAdaptiveProfile? {
        let remoteAdaptive = remoteConfig?.realtimeTelemetryAdaptive?.enforcingReleaseSecurityFloor()
        let feedback = ExternalServerAggregateProvider.shared.realtimeAdaptiveFeedbackSnapshot()
        let enabled = (remoteAdaptive?.enabled ?? false) || (feedback != nil)
        guard enabled else { return nil }

        let safeAdaptive = remoteAdaptive ?? RealtimeTelemetryAdaptiveConfig(
            enabled: true,
            baseMinEvaluationIntervalMillis: 0,
            highPressureMinEvaluationIntervalMillis: 0,
            defaultWeightScaleBps: 10_000,
            minWeightScaleBps: 7_000,
            maxWeightScaleBps: 13_000,
            feedbackTTLSeconds: 180
        )
        let minBps = safeAdaptive.minWeightScaleBps
        let maxBps = max(safeAdaptive.maxWeightScaleBps, minBps)

        let pressure = {
            guard let value = feedback?.riskPressure, value.isFinite else { return 0.0 }
            return min(max(value, 0), 1)
        }()

        let minIntervalMillis: Int
        if let direct = feedback?.minEvaluationIntervalMillis {
            minIntervalMillis = min(max(direct, 0), 60_000)
        } else {
            let base = max(0, safeAdaptive.baseMinEvaluationIntervalMillis)
            let high = max(0, min(base, safeAdaptive.highPressureMinEvaluationIntervalMillis))
            let interpolated = Double(base) - (Double(base - high) * pressure)
            minIntervalMillis = Int(interpolated.rounded())
        }

        let defaultScale = min(
            max(feedback?.defaultWeightScaleBps ?? safeAdaptive.defaultWeightScaleBps, minBps),
            maxBps
        )
        var categoryScales: [String: Int] = [:]
        let feedbackScales = feedback?.categoryWeightScaleBps ?? [:]
        for key in ["jailbreak", "network", "behavior", "device", "time"] {
            let raw = feedbackScales[key] ?? defaultScale
            categoryScales[key] = min(max(raw, minBps), maxBps)
        }

        let source = [
            remoteAdaptive != nil ? "remote_config" : "fallback",
            feedback?.source
        ]
            .compactMap { $0 }
            .joined(separator: "+")

        return RealtimeAdaptiveProfile(
            enabled: true,
            minEvaluationIntervalMillis: minIntervalMillis,
            defaultWeightScaleBps: defaultScale,
            categoryWeightScaleBps: categoryScales,
            source: source
        )
    }

    internal func applyRealtimeAdaptiveWeightScale(
        _ weights: SignalWeights,
        profile: RealtimeAdaptiveProfile?
    ) -> SignalWeights {
        guard let profile, profile.enabled else { return weights }

        func scaled(_ key: String, _ base: Double) -> Double {
            let bps = profile.categoryWeightScaleBps[key] ?? profile.defaultWeightScaleBps
            let candidate = base * (Double(bps) / 10_000.0)
            guard candidate.isFinite else { return base }
            return min(max(candidate, 0), 10)
        }

        return SignalWeights(
            jailbreak: scaled("jailbreak", weights.jailbreak),
            network: scaled("network", weights.network),
            behavior: scaled("behavior", weights.behavior),
            device: scaled("device", weights.device),
            time: scaled("time", weights.time)
        )
    }

    // MARK: - Adaptive Cache

    internal func adaptiveCacheKey(
        scenario: RiskScenario,
        runtimeConfig: RiskConfig,
        remoteConfig: RemoteConfig?,
        profile: RealtimeAdaptiveProfile?
    ) -> String {
        let threshold = String(format: "%.3f", runtimeConfig.threshold)
        let remoteVersion = remoteConfig.map { String($0.version) } ?? "none"
        let profileSignature = profile?.signature ?? "adaptive_off"
        return [
            "scn=\(scenario.identifier)",
            "thr=\(threshold)",
            "beh=\(runtimeConfig.enableBehaviorDetect ? 1 : 0)",
            "net=\(runtimeConfig.enableNetworkSignals ? 1 : 0)",
            "rv=\(remoteVersion)",
            profileSignature
        ].joined(separator: "|")
    }

    internal func maybeReturnAdaptiveCachedReport(
        profile: RealtimeAdaptiveProfile?,
        scenario: RiskScenario,
        runtimeConfig: RiskConfig,
        remoteConfig: RemoteConfig?
    ) -> CPRiskReport? {
        guard let profile,
              profile.enabled,
              profile.minEvaluationIntervalMillis > 0 else {
            return nil
        }

        let now = Date().timeIntervalSince1970
        let key = adaptiveCacheKey(
            scenario: scenario,
            runtimeConfig: runtimeConfig,
            remoteConfig: remoteConfig,
            profile: profile
        )

        let (cachedReport, cachedKey, lastEvalAt) = stateLock.withLock {
            (adaptiveCachedReport, adaptiveCachedKey, adaptiveLastEvaluationAtEpochSeconds)
        }
        guard let cachedReport, cachedKey == key else {
            return nil
        }

        let elapsedMillis = Int((now - lastEvalAt) * 1000)
        if elapsedMillis < profile.minEvaluationIntervalMillis {
            Logger.log(
                "adaptive.telemetry: reuse cached report elapsed_ms=\(elapsedMillis) " +
                    "min_interval_ms=\(profile.minEvaluationIntervalMillis) source=\(profile.source)"
            )
            return cachedReport
        }
        return nil
    }

    internal func updateAdaptiveCachedReport(
        _ report: CPRiskReport,
        profile: RealtimeAdaptiveProfile?,
        scenario: RiskScenario,
        runtimeConfig: RiskConfig,
        remoteConfig: RemoteConfig?
    ) {
        guard let profile, profile.enabled else {
            stateLock.withLock {
                adaptiveCachedReport = nil
                adaptiveCachedKey = nil
                adaptiveLastEvaluationAtEpochSeconds = 0
            }
            return
        }

        let key = adaptiveCacheKey(
            scenario: scenario,
            runtimeConfig: runtimeConfig,
            remoteConfig: remoteConfig,
            profile: profile
        )
        let now = Date().timeIntervalSince1970
        stateLock.withLock {
            adaptiveCachedReport = report
            adaptiveCachedKey = key
            adaptiveLastEvaluationAtEpochSeconds = now
        }
    }

    // MARK: - Mutation Strategy

    internal func resolveMutationStrategy(from serverPolicy: ServerRiskPolicy?) -> MutationStrategy? {
        serverPolicy?.mutation.map { mutation in
            MutationStrategy(
                seed: mutation.seed,
                shuffleChecks: mutation.shuffleChecks,
                thresholdJitterBps: mutation.thresholdJitterBps,
                scoreJitterBps: mutation.scoreJitterBps
            )
        }
    }

    // MARK: - Capability Probe

    internal func runCapabilityProbe(remoteConfig: RemoteConfig?) -> CapabilityProbeRuntimeResult {
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

    // MARK: - Challenge Binding

    internal func buildChallengeBindingIfNeeded(
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

    internal func buildBlindChallenge(
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

    internal func selectChallengeProbeIDs(
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

    internal func removingPayloadKey(_ key: String, from payloadData: Data) throws -> Data {
        guard var object = try JSONSerialization.jsonObject(with: payloadData, options: []) as? [String: Any] else {
            throw SecureUploadError.invalidPayloadShape
        }
        object.removeValue(forKey: key)
        guard JSONSerialization.isValidJSONObject(object) else {
            throw SecureUploadError.invalidPayloadShape
        }
        return try JSONSerialization.data(withJSONObject: object, options: [])
    }
}
