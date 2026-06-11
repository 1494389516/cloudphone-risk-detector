import Foundation

// MARK: - Phase & models

/// SDK 启动保护链路的阶段标记，用于崩溃归因。
public enum ProtectionStartupPhase: String, Codable, Sendable, CaseIterable {
    case startInvoked = "start_invoked"
    case antiDebugPrepare = "anti_debug_prepare"
    case armorRuntimeInit = "armor_runtime_init"
    case antiDumpPrepare = "anti_dump_prepare"
    case providerRegistration = "provider_registration"
    case startupCompleted = "startup_completed"
}

extension ProtectionStartupPhase {
    /// `armor_runtime_init` 及更早阶段（含 anti_debug_prepare）。
    var isEarlyStartupPhase: Bool {
        switch self {
        case .startInvoked, .antiDebugPrepare, .armorRuntimeInit:
            return true
        case .antiDumpPrepare, .providerRegistration, .startupCompleted:
            return false
        }
    }
}

/// 上次 session 未正常完成启动时的归因结果。
public struct ProtectionAttributionResult: Sendable {
    public let previousSessionId: String
    public let phase: ProtectionStartupPhase
    public let remoteConfigVersion: Int?
    public let antiDebugModeLabel: String
    public let localSafeProfileActive: Bool
    public let armorRuntimeSummary: String
    public let watchdogStartFailed: Bool
    public let antiDumpStartFailed: Bool
    public let lastWatchdogAnomalyFlags: UInt32?
}

/// 供线上/测试读取的保护稳定性快照。
public struct ProtectionStabilitySnapshot: Sendable {
    public let isDegraded: Bool
    public let isLocalSafeProfileActive: Bool
    public let isLocalStabilityKillSwitchActive: Bool
    public let lastAttributionPhase: ProtectionStartupPhase?
    public let lastFailedConfigVersion: Int?
    public let consecutiveFailuresSameVersion: Int
    public let consecutiveEarlyPhaseFailures: Int
    public let pinnedRollbackVersion: Int?
    public let lastHealthyStartupAt: TimeInterval?
    public let currentSessionId: String?
    public let currentPhase: ProtectionStartupPhase
    public let successfulStartsWhileDegraded: Int
    public let safeProfileEnteredAtConfigVersion: Int?
}

/// `beginSession` 返回：归因、是否自动回滚/降级。
public struct ProtectionStabilityBootstrapResult: Sendable {
    public let attribution: ProtectionAttributionResult?
    public let didRollbackRemoteConfig: Bool
    public let rolledBackToVersion: Int?
    public let didEnterLocalSafeProfile: Bool
    public let didActivateLocalStabilityKillSwitch: Bool
}

// MARK: - Store

/// 保护链路的稳定性与崩溃归因持久化（SecureFileStore + HMAC + 新鲜度锚点）。
public final class ProtectionStabilityStore: @unchecked Sendable {
    public static let shared = ProtectionStabilityStore(fileStore: .shared, configCache: ConfigCache.shared)

    private struct StoredEnvelope: Codable {
        var schemaVersion: Int
        var sessionId: String?
        var phase: ProtectionStartupPhase
        var startupCompleted: Bool
        var remoteConfigVersion: Int?
        var antiDebugModeLabel: String
        var localSafeProfileActive: Bool
        var localStabilityKillSwitchActive: Bool
        var armorRuntimeStatus: String
        var armorRuntimeReason: String
        var watchdogStartResult: Int32
        var antiDumpStartResult: Int32
        var lastWatchdogAnomalyFlags: UInt32?
        var startupBeganAt: TimeInterval
        var startupCompletedAt: TimeInterval?
        var phaseConsecutiveCrashCounts: [String: Int]
        var consecutiveFailuresSameVersion: Int
        var lastFailedConfigVersion: Int?
        var consecutiveEarlyPhaseFailures: Int
        var pinnedRollbackVersion: Int?
        var lastHealthyStartupAt: TimeInterval?
        var successfulStartsWhileDegraded: Int
        var safeProfileEnteredAtConfigVersion: Int?
        var lastWatchdogFailed: Bool
        var lastAntiDumpFailed: Bool
        var lastSessionIdForAttribution: String?
        var lastAttributedPhase: ProtectionStartupPhase?
        var lastAttributedConfigVersion: Int?
        var freshness: FreshnessState

        private enum CodingKeys: String, CodingKey {
            case schemaVersion = "sv"
            case sessionId = "sid"
            case phase = "ph"
            case startupCompleted = "sc"
            case remoteConfigVersion = "rcv"
            case antiDebugModeLabel = "adm"
            case localSafeProfileActive = "lsp"
            case localStabilityKillSwitchActive = "lsk"
            case armorRuntimeStatus = "ars"
            case armorRuntimeReason = "arr"
            case watchdogStartResult = "wsr"
            case antiDumpStartResult = "adsr"
            case lastWatchdogAnomalyFlags = "waf"
            case startupBeganAt = "sba"
            case startupCompletedAt = "sca"
            case phaseConsecutiveCrashCounts = "pcc"
            case consecutiveFailuresSameVersion = "cfsv"
            case lastFailedConfigVersion = "lfcv"
            case consecutiveEarlyPhaseFailures = "cepf"
            case pinnedRollbackVersion = "prv"
            case lastHealthyStartupAt = "lhs"
            case successfulStartsWhileDegraded = "sswd"
            case safeProfileEnteredAtConfigVersion = "spev"
            case lastWatchdogFailed = "lwf"
            case lastAntiDumpFailed = "ladf"
            case lastSessionIdForAttribution = "lsida"
            case lastAttributedPhase = "lap"
            case lastAttributedConfigVersion = "lacv"
            case freshness = "fr"
        }

        init(
            schemaVersion: Int,
            sessionId: String?,
            phase: ProtectionStartupPhase,
            startupCompleted: Bool,
            remoteConfigVersion: Int?,
            antiDebugModeLabel: String,
            localSafeProfileActive: Bool,
            localStabilityKillSwitchActive: Bool,
            armorRuntimeStatus: String,
            armorRuntimeReason: String,
            watchdogStartResult: Int32,
            antiDumpStartResult: Int32,
            lastWatchdogAnomalyFlags: UInt32?,
            startupBeganAt: TimeInterval,
            startupCompletedAt: TimeInterval?,
            phaseConsecutiveCrashCounts: [String: Int],
            consecutiveFailuresSameVersion: Int,
            lastFailedConfigVersion: Int?,
            consecutiveEarlyPhaseFailures: Int,
            pinnedRollbackVersion: Int?,
            lastHealthyStartupAt: TimeInterval?,
            successfulStartsWhileDegraded: Int,
            safeProfileEnteredAtConfigVersion: Int?,
            lastWatchdogFailed: Bool,
            lastAntiDumpFailed: Bool,
            lastSessionIdForAttribution: String?,
            lastAttributedPhase: ProtectionStartupPhase?,
            lastAttributedConfigVersion: Int?,
            freshness: FreshnessState
        ) {
            self.schemaVersion = schemaVersion
            self.sessionId = sessionId
            self.phase = phase
            self.startupCompleted = startupCompleted
            self.remoteConfigVersion = remoteConfigVersion
            self.antiDebugModeLabel = antiDebugModeLabel
            self.localSafeProfileActive = localSafeProfileActive
            self.localStabilityKillSwitchActive = localStabilityKillSwitchActive
            self.armorRuntimeStatus = armorRuntimeStatus
            self.armorRuntimeReason = armorRuntimeReason
            self.watchdogStartResult = watchdogStartResult
            self.antiDumpStartResult = antiDumpStartResult
            self.lastWatchdogAnomalyFlags = lastWatchdogAnomalyFlags
            self.startupBeganAt = startupBeganAt
            self.startupCompletedAt = startupCompletedAt
            self.phaseConsecutiveCrashCounts = phaseConsecutiveCrashCounts
            self.consecutiveFailuresSameVersion = consecutiveFailuresSameVersion
            self.lastFailedConfigVersion = lastFailedConfigVersion
            self.consecutiveEarlyPhaseFailures = consecutiveEarlyPhaseFailures
            self.pinnedRollbackVersion = pinnedRollbackVersion
            self.lastHealthyStartupAt = lastHealthyStartupAt
            self.successfulStartsWhileDegraded = successfulStartsWhileDegraded
            self.safeProfileEnteredAtConfigVersion = safeProfileEnteredAtConfigVersion
            self.lastWatchdogFailed = lastWatchdogFailed
            self.lastAntiDumpFailed = lastAntiDumpFailed
            self.lastSessionIdForAttribution = lastSessionIdForAttribution
            self.lastAttributedPhase = lastAttributedPhase
            self.lastAttributedConfigVersion = lastAttributedConfigVersion
            self.freshness = freshness
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            schemaVersion = try c.decodeIfPresent(Int.self, forKey: .schemaVersion) ?? 1
            sessionId = try c.decodeIfPresent(String.self, forKey: .sessionId)
            phase = try c.decodeIfPresent(ProtectionStartupPhase.self, forKey: .phase) ?? .startInvoked
            startupCompleted = try c.decodeIfPresent(Bool.self, forKey: .startupCompleted) ?? true
            remoteConfigVersion = try c.decodeIfPresent(Int.self, forKey: .remoteConfigVersion)
            antiDebugModeLabel = try c.decodeIfPresent(String.self, forKey: .antiDebugModeLabel) ?? "production"
            localSafeProfileActive = try c.decodeIfPresent(Bool.self, forKey: .localSafeProfileActive) ?? false
            localStabilityKillSwitchActive = try c.decodeIfPresent(Bool.self, forKey: .localStabilityKillSwitchActive) ?? false
            armorRuntimeStatus = try c.decodeIfPresent(String.self, forKey: .armorRuntimeStatus) ?? "n/a"
            armorRuntimeReason = try c.decodeIfPresent(String.self, forKey: .armorRuntimeReason) ?? "n/a"
            watchdogStartResult = try c.decodeIfPresent(Int32.self, forKey: .watchdogStartResult) ?? 0
            antiDumpStartResult = try c.decodeIfPresent(Int32.self, forKey: .antiDumpStartResult) ?? 0
            lastWatchdogAnomalyFlags = try c.decodeIfPresent(UInt32.self, forKey: .lastWatchdogAnomalyFlags)
            startupBeganAt = try c.decodeIfPresent(TimeInterval.self, forKey: .startupBeganAt) ?? 0
            startupCompletedAt = try c.decodeIfPresent(TimeInterval.self, forKey: .startupCompletedAt)
            phaseConsecutiveCrashCounts = try c.decodeIfPresent([String: Int].self, forKey: .phaseConsecutiveCrashCounts) ?? [:]
            consecutiveFailuresSameVersion = try c.decodeIfPresent(Int.self, forKey: .consecutiveFailuresSameVersion) ?? 0
            lastFailedConfigVersion = try c.decodeIfPresent(Int.self, forKey: .lastFailedConfigVersion)
            consecutiveEarlyPhaseFailures = try c.decodeIfPresent(Int.self, forKey: .consecutiveEarlyPhaseFailures) ?? 0
            pinnedRollbackVersion = try c.decodeIfPresent(Int.self, forKey: .pinnedRollbackVersion)
            lastHealthyStartupAt = try c.decodeIfPresent(TimeInterval.self, forKey: .lastHealthyStartupAt)
            successfulStartsWhileDegraded = try c.decodeIfPresent(Int.self, forKey: .successfulStartsWhileDegraded) ?? 0
            safeProfileEnteredAtConfigVersion = try c.decodeIfPresent(Int.self, forKey: .safeProfileEnteredAtConfigVersion)
            lastWatchdogFailed = try c.decodeIfPresent(Bool.self, forKey: .lastWatchdogFailed) ?? false
            lastAntiDumpFailed = try c.decodeIfPresent(Bool.self, forKey: .lastAntiDumpFailed) ?? false
            lastSessionIdForAttribution = try c.decodeIfPresent(String.self, forKey: .lastSessionIdForAttribution)
            lastAttributedPhase = try c.decodeIfPresent(ProtectionStartupPhase.self, forKey: .lastAttributedPhase)
            lastAttributedConfigVersion = try c.decodeIfPresent(Int.self, forKey: .lastAttributedConfigVersion)
            freshness = try c.decodeIfPresent(FreshnessState.self, forKey: .freshness) ?? .zero
        }
    }

    private let lock = UnfairLock()
    private let fileStore: SecureFileStore
    private let key = "cloudphone_protection_stability_v1"
    private let hmacKey = "cloudphone_protection_stability_v1_hmac"
    private let hmacPurpose = "protection_stability"
    private let freshnessAnchor = FreshnessAnchor(account: "protection_stability_v1_freshness")
    private let configCache: ConfigCaching

    /// 进入 safe profile 后至少成功启动次数才允许解除（与更高版本条件组合）。
    private let minimumSuccessfulStartsToExitSafeProfile = 3

    public convenience init() {
        self.init(fileStore: .shared, configCache: ConfigCache.shared)
    }

    init(fileStore: SecureFileStore, configCache: ConfigCaching) {
        self.fileStore = fileStore
        self.configCache = configCache
    }

    // MARK: - Public API

    /// 新进程启动时调用：检测上次异常、累计计数、触发自动回滚/降级，并开启新 session。
    public func beginSession(
        remoteConfigVersion: Int?,
        antiDebugMode: CPRiskAntiDebugRuntimeMode,
        safeProfileAlreadyActive: Bool
    ) -> ProtectionStabilityBootstrapResult {
        lock.withLock {
            let previous = loadStateLocked()
            let attribution = detectPreviousAbnormalTerminationLocked(previous: previous)

            var working = previous
            var didRollback = false
            var rolledBackVersion: Int?
            var didEnterSafe = false
            var didKillSwitch = false

            if let attr = attribution {
                Self.logAttribution(attr)
                working.lastAttributedPhase = attr.phase
                working.lastAttributedConfigVersion = attr.remoteConfigVersion
                applyCountersAfterAbnormalLocked(attr: attr, state: &working)

                let decision = evaluateAutoRollbackLocked(
                    attribution: attr,
                    state: &working
                )

                switch decision {
                case .rollback(let version):
                    if let cfg = rollbackVerifiedConfigLocked(below: version) {
                        didRollback = true
                        rolledBackVersion = cfg.version
                        working.pinnedRollbackVersion = cfg.version
                        resetFailureCountersLocked(&working)
                    } else {
                        enterDegradedModeLocked(state: &working, remoteVersion: remoteConfigVersion)
                        didEnterSafe = working.localSafeProfileActive
                        didKillSwitch = working.localStabilityKillSwitchActive
                    }
                case .degradedOnly:
                    enterDegradedModeLocked(state: &working, remoteVersion: remoteConfigVersion)
                    didEnterSafe = working.localSafeProfileActive
                    didKillSwitch = working.localStabilityKillSwitchActive
                case .none:
                    break
                }
            }

            let newSession = UUID().uuidString
            working.sessionId = newSession
            working.phase = .startInvoked
            working.startupCompleted = false
            working.remoteConfigVersion = remoteConfigVersion
            working.antiDebugModeLabel = Self.label(for: antiDebugMode)
            working.localSafeProfileActive = working.localSafeProfileActive || safeProfileAlreadyActive
            working.armorRuntimeStatus = "pending"
            working.armorRuntimeReason = "pending"
            working.watchdogStartResult = 0
            working.antiDumpStartResult = 0
            working.lastWatchdogAnomalyFlags = nil
            working.startupBeganAt = Date().timeIntervalSince1970
            working.startupCompletedAt = nil
            working.lastWatchdogFailed = false
            working.lastAntiDumpFailed = false
            working.lastSessionIdForAttribution = newSession

            saveLocked(working)
            return ProtectionStabilityBootstrapResult(
                attribution: attribution,
                didRollbackRemoteConfig: didRollback,
                rolledBackToVersion: rolledBackVersion,
                didEnterLocalSafeProfile: didEnterSafe,
                didActivateLocalStabilityKillSwitch: didKillSwitch
            )
        }
    }

    public func markPhase(_ phase: ProtectionStartupPhase) {
        lock.withLock {
            var state = loadStateLocked()
            state.phase = phase
            saveLocked(state)
        }
    }

    public func markStartupCompleted(remoteConfigVersion: Int?) {
        lock.withLock {
            var state = loadStateLocked()
            state.phase = .startupCompleted
            state.startupCompleted = true
            state.startupCompletedAt = Date().timeIntervalSince1970
            state.lastHealthyStartupAt = state.startupCompletedAt
            state.remoteConfigVersion = remoteConfigVersion ?? state.remoteConfigVersion
            resetFailureCountersLocked(&state)
            state.consecutiveEarlyPhaseFailures = 0

            if state.localSafeProfileActive {
                state.successfulStartsWhileDegraded += 1
                maybeExitSafeProfileLocked(remoteVersion: remoteConfigVersion, state: &state)
            } else {
                state.successfulStartsWhileDegraded = 0
            }

            saveLocked(state)
        }
    }

    public func recordRuntimeHealth(
        armorStatus: String,
        armorReason: String,
        watchdogStartResult: Int32,
        antiDumpStartResult: Int32,
        watchdogAnomalyFlags: UInt32?
    ) {
        lock.withLock {
            var state = loadStateLocked()
            state.armorRuntimeStatus = armorStatus
            state.armorRuntimeReason = armorReason
            state.watchdogStartResult = watchdogStartResult
            state.antiDumpStartResult = antiDumpStartResult
            state.lastWatchdogAnomalyFlags = watchdogAnomalyFlags
            state.lastWatchdogFailed = watchdogStartResult != 0
            state.lastAntiDumpFailed = antiDumpStartResult != 0
            saveLocked(state)
        }
    }

    public func detectPreviousAbnormalTermination() -> ProtectionAttributionResult? {
        lock.withLock {
            let state = loadStateLocked()
            return detectPreviousAbnormalTerminationLocked(previous: state)
        }
    }

    public func currentSnapshot() -> ProtectionStabilitySnapshot {
        lock.withLock {
            let s = loadStateLocked()
            let degraded = s.localSafeProfileActive || s.localStabilityKillSwitchActive
            return ProtectionStabilitySnapshot(
                isDegraded: degraded,
                isLocalSafeProfileActive: s.localSafeProfileActive,
                isLocalStabilityKillSwitchActive: s.localStabilityKillSwitchActive,
                lastAttributionPhase: s.lastAttributedPhase,
                lastFailedConfigVersion: s.lastFailedConfigVersion,
                consecutiveFailuresSameVersion: s.consecutiveFailuresSameVersion,
                consecutiveEarlyPhaseFailures: s.consecutiveEarlyPhaseFailures,
                pinnedRollbackVersion: s.pinnedRollbackVersion,
                lastHealthyStartupAt: s.lastHealthyStartupAt,
                currentSessionId: s.sessionId,
                currentPhase: s.phase,
                successfulStartsWhileDegraded: s.successfulStartsWhileDegraded,
                safeProfileEnteredAtConfigVersion: s.safeProfileEnteredAtConfigVersion
            )
        }
    }

    /// 供决策引擎与测试读取：本地稳定性 kill-switch（allow/log，不拦截）。
    public func isLocalStabilityKillSwitchEnabled() -> Bool {
        lock.withLock { loadStateLocked().localStabilityKillSwitchActive }
    }

    /// 是否应强制宽松 anti-debug（safe profile）。
    public func isLocalSafeProfileActive() -> Bool {
        lock.withLock { loadStateLocked().localSafeProfileActive }
    }

    // MARK: - Internal helpers for tests

    internal func resetForTesting() {
        lock.withLock {
            fileStore.remove(key: key)
            fileStore.remove(key: hmacKey)
            freshnessAnchor.remove()
        }
    }

    // MARK: - Rollback decision

    private enum AutoRollbackDecision {
        case rollback(ceilingVersion: Int)
        case degradedOnly
        case none
    }

    private func evaluateAutoRollbackLocked(
        attribution: ProtectionAttributionResult,
        state: inout StoredEnvelope
    ) -> AutoRollbackDecision {
        let v = attribution.remoteConfigVersion ?? -1
        guard v >= 0 else {
            return .degradedOnly
        }

        let sameVersionTwice = state.consecutiveFailuresSameVersion >= 2
        let earlyTwice = state.consecutiveEarlyPhaseFailures >= 2
        let watchdogDumpPairFailure = attribution.watchdogStartFailed && attribution.antiDumpStartFailed
            && state.consecutiveFailuresSameVersion >= 2

        if sameVersionTwice || earlyTwice || watchdogDumpPairFailure {
            return .rollback(ceilingVersion: v)
        }

        return .none
    }

    private func rollbackVerifiedConfigLocked(below ceilingVersion: Int) -> RemoteConfig? {
        configCache.rollbackToNewestVerifiedVersion(below: ceilingVersion)
    }

    private func enterDegradedModeLocked(state: inout StoredEnvelope, remoteVersion: Int?) {
        state.localSafeProfileActive = true
        state.localStabilityKillSwitchActive = true
        if state.safeProfileEnteredAtConfigVersion == nil {
            state.safeProfileEnteredAtConfigVersion = remoteVersion ?? state.remoteConfigVersion
        }
        state.successfulStartsWhileDegraded = 0
        Logger.log("protection_stability: entered local safe profile + stability kill-switch (no verified rollback)")
    }

    private func maybeExitSafeProfileLocked(remoteVersion: Int?, state: inout StoredEnvelope) {
        guard state.localSafeProfileActive else { return }
        let rv = remoteVersion ?? state.remoteConfigVersion ?? -1
        let enteredAt = state.safeProfileEnteredAtConfigVersion ?? -1
        let versionOk = rv > enteredAt
        let successOk = state.successfulStartsWhileDegraded >= minimumSuccessfulStartsToExitSafeProfile
        guard successOk && versionOk else { return }

        state.localSafeProfileActive = false
        state.localStabilityKillSwitchActive = false
        state.safeProfileEnteredAtConfigVersion = nil
        state.successfulStartsWhileDegraded = 0
        Logger.log("protection_stability: exited safe profile after \(minimumSuccessfulStartsToExitSafeProfile) healthy starts and newer config version")
    }

    private func resetFailureCountersLocked(_ state: inout StoredEnvelope) {
        state.consecutiveFailuresSameVersion = 0
        state.phaseConsecutiveCrashCounts = [:]
        state.lastFailedConfigVersion = nil
    }

    private func applyCountersAfterAbnormalLocked(attr: ProtectionAttributionResult, state: inout StoredEnvelope) {
        let v = attr.remoteConfigVersion
        if let v {
            if state.lastFailedConfigVersion == v {
                state.consecutiveFailuresSameVersion += 1
            } else {
                state.consecutiveFailuresSameVersion = 1
                state.lastFailedConfigVersion = v
            }
        } else {
            state.consecutiveFailuresSameVersion += 1
        }

        if attr.phase.isEarlyStartupPhase {
            state.consecutiveEarlyPhaseFailures += 1
        } else {
            state.consecutiveEarlyPhaseFailures = 0
        }

        let key = attr.phase.rawValue
        state.phaseConsecutiveCrashCounts[key] = (state.phaseConsecutiveCrashCounts[key] ?? 0) + 1
    }

    private func detectPreviousAbnormalTerminationLocked(previous: StoredEnvelope) -> ProtectionAttributionResult? {
        guard let sid = previous.sessionId, !previous.startupCompleted else {
            return nil
        }
        guard previous.startupBeganAt > 0 else {
            return nil
        }
        guard previous.phase != .startupCompleted else {
            return nil
        }

        return ProtectionAttributionResult(
            previousSessionId: sid,
            phase: previous.phase,
            remoteConfigVersion: previous.remoteConfigVersion,
            antiDebugModeLabel: previous.antiDebugModeLabel,
            localSafeProfileActive: previous.localSafeProfileActive,
            armorRuntimeSummary: "\(previous.armorRuntimeStatus)/\(previous.armorRuntimeReason)",
            watchdogStartFailed: previous.watchdogStartResult != 0,
            antiDumpStartFailed: previous.antiDumpStartResult != 0,
            lastWatchdogAnomalyFlags: previous.lastWatchdogAnomalyFlags
        )
    }

    // MARK: - Persistence

    private func loadStateLocked() -> StoredEnvelope {
        let anchor = freshnessAnchor.read() ?? .zero
        guard let stored = fileStore.read(key: key) else {
            return Self.emptyState(freshness: anchor)
        }
        guard let signature = fileStore.read(key: hmacKey),
              StorageIntegrityGuard.verify(stored, signature: signature, purpose: hmacPurpose) else {
            clearPersistedLocked(resetAnchor: false)
            return Self.emptyState(freshness: anchor)
        }
        #if DEBUG
        let data: Data
        if let decrypted = try? PayloadCrypto.decrypt(stored) {
            data = decrypted
        } else {
            data = stored
        }
        #else
        guard let data = try? PayloadCrypto.decrypt(stored) else {
            Logger.log("ProtectionStabilityStore: decrypt failed, clearing")
            clearPersistedLocked(resetAnchor: false)
            return Self.emptyState(freshness: anchor)
        }
        #endif

        guard var env = try? JSONDecoder().decode(StoredEnvelope.self, from: data) else {
            clearPersistedLocked(resetAnchor: false)
            return Self.emptyState(freshness: anchor)
        }

        if env.freshness.sequence < anchor.sequence || env.freshness.latestTimestamp < anchor.latestTimestamp {
            Logger.log("ProtectionStabilityStore: freshness rollback detected, resetting")
            clearPersistedLocked(resetAnchor: false)
            return Self.emptyState(freshness: anchor)
        }

        let merged = maxFreshness(anchor, env.freshness)
        if merged.sequence > anchor.sequence || merged.latestTimestamp > anchor.latestTimestamp {
            _ = freshnessAnchor.write(merged)
        }
        env.freshness = merged
        return env
    }

    private func saveLocked(_ state: StoredEnvelope) {
        var toSave = state
        let anchor = freshnessAnchor.read() ?? .zero
        let maxTs = max(toSave.startupCompletedAt ?? 0, toSave.startupBeganAt, toSave.lastHealthyStartupAt ?? 0, anchor.latestTimestamp)
        toSave.freshness = FreshnessState(
            latestTimestamp: max(maxTs, anchor.latestTimestamp),
            sequence: anchor.sequence + 1
        )

        guard let encoded = try? JSONEncoder().encode(toSave) else {
            Logger.log("ProtectionStabilityStore: encode failed")
            return
        }
        #if DEBUG
        let stored = (try? PayloadCrypto.encrypt(encoded)) ?? encoded
        #else
        guard let stored = try? PayloadCrypto.encrypt(encoded) else {
            Logger.log("ProtectionStabilityStore: encrypt failed")
            return
        }
        #endif
        let signature = StorageIntegrityGuard.sign(stored, purpose: hmacPurpose)
        let didWritePayload = fileStore.write(key: key, data: stored)
        let didWriteSignature = fileStore.write(key: hmacKey, data: signature)
        guard didWritePayload && didWriteSignature else {
            Logger.log("ProtectionStabilityStore: failed to persist state atomically")
            clearPersistedLocked(resetAnchor: false)
            return
        }
        if !freshnessAnchor.write(toSave.freshness) {
            Logger.log("ProtectionStabilityStore: freshness write failed")
        }
    }

    private func clearPersistedLocked(resetAnchor: Bool) {
        fileStore.remove(key: key)
        fileStore.remove(key: hmacKey)
        if resetAnchor {
            freshnessAnchor.remove()
        }
    }

    private func maxFreshness(_ lhs: FreshnessState, _ rhs: FreshnessState) -> FreshnessState {
        FreshnessState(
            latestTimestamp: max(lhs.latestTimestamp, rhs.latestTimestamp),
            sequence: max(lhs.sequence, rhs.sequence)
        )
    }

    private static func emptyState(freshness: FreshnessState) -> StoredEnvelope {
        StoredEnvelope(
            schemaVersion: 1,
            sessionId: nil,
            phase: .startInvoked,
            startupCompleted: true,
            remoteConfigVersion: nil,
            antiDebugModeLabel: "production",
            localSafeProfileActive: false,
            localStabilityKillSwitchActive: false,
            armorRuntimeStatus: "n/a",
            armorRuntimeReason: "n/a",
            watchdogStartResult: 0,
            antiDumpStartResult: 0,
            lastWatchdogAnomalyFlags: nil,
            startupBeganAt: 0,
            startupCompletedAt: nil,
            phaseConsecutiveCrashCounts: [:],
            consecutiveFailuresSameVersion: 0,
            lastFailedConfigVersion: nil,
            consecutiveEarlyPhaseFailures: 0,
            pinnedRollbackVersion: nil,
            lastHealthyStartupAt: nil,
            successfulStartsWhileDegraded: 0,
            safeProfileEnteredAtConfigVersion: nil,
            lastWatchdogFailed: false,
            lastAntiDumpFailed: false,
            lastSessionIdForAttribution: nil,
            lastAttributedPhase: nil,
            lastAttributedConfigVersion: nil,
            freshness: freshness
        )
    }

    private static func label(for mode: CPRiskAntiDebugRuntimeMode) -> String {
        switch mode {
        case .production: return "production"
        case .relaxedDevelopmentQA: return "relaxed"
        case .appStoreSafe: return "app_store_safe"
        @unknown default: return "unknown"
        }
    }

    private static func logAttribution(_ attr: ProtectionAttributionResult) {
        let ver = attr.remoteConfigVersion.map { String($0) } ?? "nil"
        Logger.log(
            "protection_stability: ABNORMAL previous session=\(attr.previousSessionId) phase=\(attr.phase.rawValue) " +
            "remoteConfigVersion=\(ver) antiDebug=\(attr.antiDebugModeLabel) armor=\(attr.armorRuntimeSummary) " +
            "watchdogFail=\(attr.watchdogStartFailed) antiDumpFail=\(attr.antiDumpStartFailed)"
        )
    }
}
