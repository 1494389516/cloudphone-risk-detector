// MARK: - CPRiskKit+Configuration
//
// 从 CloudPhoneRiskKit.swift 拆分：静态配置、枚举定义、嵌套类型。

import CryptoKit
import CRiskCore
import Foundation

// MARK: - SignalID (re-exported reference)

// SignalID 定义在 RiskReport.swift 中，此处不重复定义。
// ObfuscatedConstants 定义在 Util/ObfuscatedStrings.swift 中。

// MARK: - Configuration Extensions

extension CPRiskKit {

    // MARK: RealtimeAdaptiveProfile

    internal struct RealtimeAdaptiveProfile {
        let enabled: Bool
        let minEvaluationIntervalMillis: Int
        let defaultWeightScaleBps: Int
        let categoryWeightScaleBps: [String: Int]
        let source: String

        var signature: String {
            let ordered = categoryWeightScaleBps.keys.sorted().map {
                "\($0):\(categoryWeightScaleBps[$0] ?? defaultWeightScaleBps)"
            }
            return "e=\(enabled ? 1 : 0)|i=\(minEvaluationIntervalMillis)|d=\(defaultWeightScaleBps)|s=\(source)|c=\(ordered.joined(separator: ","))"
        }
    }

    // MARK: ArmorRootKeySource

    internal enum ArmorRootKeySource: String {
        case environment
        case debugFallback
        case missing
        case invalidEnvironment
    }

    // MARK: ArmorRuntimeStatus

    internal enum ArmorRuntimeStatus: String {
        case inactive
        case active
        case unavailable
        case failed
    }

    // MARK: ArmorRuntimeDebugSnapshot

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

    // MARK: AntiDebugWatchdogSnapshot

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
        public let libcFallbackUsedMask: UInt32
        public let libcFallbackEventTotal: UInt32
        public let watchdogStartPathMask: UInt32
        public let watchdogStartupLivenessOk: Bool
        public let mainThreadAliveMonotonicNs: UInt64
        public let earlyInjectionEnvMask: UInt32
        public let watchdogExtendedAnomalyFlags: UInt32
        public let mainThreadHeartbeatSeq: UInt64
        public let mainThreadHeartbeatStallCount: UInt64
        public let lastMainThreadHeartbeatStalled: Bool

        public var hasAnyAnomaly: Bool {
            anomalyFlags != 0 || watchdogExtendedAnomalyFlags != 0
        }
    }

    // MARK: AntiDebugPlanSnapshot

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

    // MARK: ArmorRootKeyResolution

    internal struct ArmorRootKeyResolution {
        let keyData: Data?
        let source: ArmorRootKeySource
        let debugFallbackUsed: Bool
        let failureReason: String?
    }

    // MARK: ArmorRuntimeSnapshot

    internal struct ArmorRuntimeSnapshot {
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

    // MARK: CapabilityProbeRuntimeResult

    internal struct CapabilityProbeRuntimeResult {
        let score: CapabilityScore
        let probes: [ProbeResult]
    }
}
