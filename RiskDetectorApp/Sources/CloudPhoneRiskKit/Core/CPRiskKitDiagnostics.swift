// MARK: - CPRiskKit+Diagnostics
//
// 从 CloudPhoneRiskKit.swift 拆分：Debug snapshots、watchdog snapshot、
// anti-debug plan snapshot、diagnostics 及 async/await APIs。

import CRiskCore
import Foundation

extension CPRiskKit {

    // MARK: - Debug Armor Snapshot

    internal func debugArmorRuntimeSnapshotImpl() -> ArmorRuntimeDebugSnapshot {
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

    // MARK: - Watchdog Snapshot

    internal func antiDebugWatchdogSnapshotImpl() -> AntiDebugWatchdogSnapshot {
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

    // MARK: - Anti-Debug Plan Snapshot

    internal func antiDebugPlanSnapshotImpl() -> AntiDebugPlanSnapshot {
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
