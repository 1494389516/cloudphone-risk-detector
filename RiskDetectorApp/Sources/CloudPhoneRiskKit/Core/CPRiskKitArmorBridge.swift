// MARK: - CPRiskKit+ArmorBridge
//
// 从 CloudPhoneRiskKit.swift 拆分：Armor runtime init、material derivation、
// signing key bridge、anti-debug runtime mode 管理。

import CryptoKit
import CRiskCore
import Foundation

extension CPRiskKit {

    // MARK: - Anti-Debug Runtime Mode

    internal func applyAntiDebugRuntimeModeToCore(_ mode: CPRiskAntiDebugRuntimeMode) {
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

    internal static func effectiveAntiDebugRuntimeMode(
        localMode: CPRiskAntiDebugRuntimeMode,
        remoteRequestsAppStoreSafeProfile: Bool
    ) -> CPRiskAntiDebugRuntimeMode {
        if localMode == .appStoreSafe { return .appStoreSafe }
        if remoteRequestsAppStoreSafeProfile { return .appStoreSafe }
        return localMode
    }

    internal func applyAntiDebugRuntimeConfigToCore(_ config: CPRiskConfig) {
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

    internal func reapplyAntiDebugRuntimeModeAfterRemoteConfigChange() {
        let local = stateLock.withLock { lastLocalAntiDebugMode }
        let remote = stateLock.withLock { lastEnableRemoteConfig && lastRemoteAppStoreSafeProfileFlag }
        let effective = Self.effectiveAntiDebugRuntimeMode(
            localMode: local,
            remoteRequestsAppStoreSafeProfile: remote
        )
        stateLock.withLock { lastAppliedEffectiveAntiDebugMode = effective }
        applyAntiDebugRuntimeModeToCore(effective)
    }

    // MARK: - Armor Runtime

    @discardableResult
    internal func ensureArmorRuntimeStarted(trigger: String, config: CPRiskConfig? = nil) -> ArmorRuntimeSnapshot {
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

    internal func resetArmorRuntime() {
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

    // MARK: - Armor Root Key

    internal static func resolveArmorRootKey() -> ArmorRootKeyResolution {
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

    internal static func hasArmorAnchor() -> Bool {
        var anchor = [UInt8](repeating: 0, count: 32)
        return cprisk_read_full_anchor_hash(&anchor) == 0
    }

    internal static func makeArmorRuntimeSnapshot(
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

    internal static func logArmorRuntimeSnapshot(_ snapshot: ArmorRuntimeSnapshot) {
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

    internal static func armorRuntimeSignal(from snapshot: ArmorRuntimeSnapshot) -> RiskSignal? {
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

    // MARK: - Exception Handler Verification

    internal static func maybeVerifyExceptionHandler() {
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
}
