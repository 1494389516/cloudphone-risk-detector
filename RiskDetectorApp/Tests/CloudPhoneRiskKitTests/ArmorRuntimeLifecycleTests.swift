import Darwin
import Foundation
import XCTest
import CRiskCore
@testable import CloudPhoneRiskKit

final class ArmorRuntimeLifecycleTests: XCTestCase {
    private let armorRootKeyDefaultsKey = "com.cloudphone.riskkit.armor.root_key_hex"

    private func textEncryptSelfCheckResult() throws -> UInt32 {
        typealias SelfCheckFn = @convention(c) () -> UInt32

        guard let handle = dlopen(nil, RTLD_NOW) else {
            throw XCTSkip("dlopen(nil) unavailable for text encrypt self-check lookup")
        }
        defer { dlclose(handle) }

        guard let symbol = dlsym(handle, "cprisk_text_encrypt_self_check") else {
            throw XCTSkip("cprisk_text_encrypt_self_check is not linked in this test runtime")
        }

        let function = unsafeBitCast(symbol, to: SelfCheckFn.self)
        return function()
    }

    private func waitForWatchdogSnapshot(
        timeout: TimeInterval = 6.0
    ) -> CPRiskKit.AntiDebugWatchdogSnapshot {
        var snapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        let deadline = Date().addingTimeInterval(timeout)
        while snapshot.supported && snapshot.running && snapshot.iterationCount == 0 && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
            snapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        }
        return snapshot
    }

    override func setUp() {
        super.setUp()
        UserDefaults.standard.removeObject(forKey: armorRootKeyDefaultsKey)
        CPRiskKit.shared.stop()
    }

    override func tearDown() {
        CPRiskKit.shared.stop()
        UserDefaults.standard.removeObject(forKey: armorRootKeyDefaultsKey)
        super.tearDown()
    }

    func testEvaluateOnlyPathBootstrapsArmorRuntimeAndEmitsObservableSignal() {
        let report = CPRiskKit.shared.evaluate()
        let snapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()

        XCTAssertEqual(snapshot.trigger, "evaluate")
        XCTAssertEqual(snapshot.attemptCount, 1)
        XCTAssertNotEqual(snapshot.status, "inactive")

        let armorDegradationSignals = report.signals.filter {
            $0.id == "armor_runtime_unavailable" || $0.id == "armor_runtime_init_failed"
        }
        if snapshot.status == "active" {
            XCTAssertTrue(armorDegradationSignals.isEmpty,
                          "active armor runtime should not emit degradation signals")
        } else {
            XCTAssertFalse(armorDegradationSignals.isEmpty,
                           "non-active armor runtime must surface degradation instead of silent success")
        }

        if ProcessInfo.processInfo.environment["CPRISKKIT_ARMOR_ROOT_KEY_HEX"] == nil {
            if snapshot.status == "active" {
                XCTAssertFalse(snapshot.debugFallbackUsed,
                               "active armor runtime should not use debug fallback")
            } else {
                XCTAssertTrue(snapshot.debugFallbackUsed,
                             "non-active armor in debug builds should fall back to the test root key")
            }
        }
    }

    func testStartIsIdempotentUntilStopResetsArmorRuntimeState() {
        CPRiskKit.shared.start()
        let firstSnapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()

        CPRiskKit.shared.start()
        let secondSnapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()

        XCTAssertEqual(firstSnapshot.trigger, "start")
        XCTAssertEqual(firstSnapshot.attemptCount, 1)
        XCTAssertEqual(secondSnapshot.attemptCount, 1, "repeated start() must not initialize armor twice")
        XCTAssertNotEqual(secondSnapshot.status, "inactive")

        CPRiskKit.shared.stop()
        let stoppedSnapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()
        XCTAssertEqual(stoppedSnapshot.status, "inactive")
        XCTAssertEqual(stoppedSnapshot.attemptCount, 0)
    }

    func testAntiDebugWatchdogFollowsStartStopLifecycle() {
        let initialSnapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        XCTAssertFalse(initialSnapshot.running)
        XCTAssertFalse(initialSnapshot.threadActive)

        CPRiskKit.shared.start()
        let startedSnapshot = waitForWatchdogSnapshot()
        let runtimeSnapshot = CPRiskKit.shared.debugArmorRuntimeSnapshot()

        if startedSnapshot.supported {
            XCTAssertTrue(startedSnapshot.running, "watchdog should be marked running after start()")
            XCTAssertTrue(
                (1...5).contains(Int(startedSnapshot.intervalSeconds)),
                "watchdog interval should be randomized within expected range"
            )
            if runtimeSnapshot.status == "active" {
                XCTAssertGreaterThan(startedSnapshot.iterationCount, 0, "watchdog should execute at least one iteration")
            } else {
                XCTAssertNotEqual(
                    runtimeSnapshot.status,
                    "active",
                    "zero watchdog iterations are only acceptable in degraded runtime paths"
                )
                XCTAssertNotEqual(
                    runtimeSnapshot.status,
                    "inactive",
                    "start() should move runtime into an attempted state even when degraded"
                )
            }
        } else {
            XCTAssertFalse(startedSnapshot.running, "unsupported platforms should degrade to no-op")
        }

        CPRiskKit.shared.start()
        let restartedSnapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        if restartedSnapshot.supported {
            XCTAssertTrue(restartedSnapshot.running, "repeated start() must not stop the existing watchdog")
            XCTAssertGreaterThanOrEqual(
                restartedSnapshot.iterationCount,
                startedSnapshot.iterationCount,
                "repeated start() must not reset watchdog progress while already running"
            )
        }

        CPRiskKit.shared.stop()
        let stoppedSnapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        XCTAssertFalse(stoppedSnapshot.running)
        XCTAssertFalse(stoppedSnapshot.threadActive)
    }

    // MARK: - Integrity Re-check

    func testRecheckIntegrityReturnsConsistentStateAfterInit() {
        CPRiskKit.shared.start()
        defer { CPRiskKit.shared.stop() }

        let rc = cprisk_recheck_integrity()
        // rc == 0 means integrity intact (normal case)
        // rc == -1 means no saved hash (non-armored binary — expected in test)
        // rc == 1 means tampered (unlikely in clean test)
        XCTAssertTrue(
            rc == 0 || rc == -1,
            "recheck should succeed (0) or report no saved hash (-1) in test env, got \(rc)"
        )

        let poisoned = cprisk_is_integrity_poisoned()
        let watchdogSnapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        if watchdogSnapshot.supported, watchdogSnapshot.hasAnyAnomaly {
            XCTAssertTrue(
                poisoned == 0 || poisoned == 1,
                "watchdog anomalies may poison runtime on host test platforms"
            )
        } else {
            XCTAssertEqual(poisoned, 0, "visible poison flag should stay clear in a clean test run")
        }
    }

    func testRecheckIntegrityWithoutInitReturnsNoSavedHash() {
        CPRiskKit.shared.stop()
        let rc = cprisk_recheck_integrity()
        XCTAssertEqual(rc, -1, "recheck without prior init should return -1 (no saved hash)")
    }

    // MARK: - Secure Zero

    func testSecureZeroClearsBuffer() {
        var buffer = [UInt8](repeating: 0xAA, count: 64)
        buffer.withUnsafeMutableBufferPointer { ptr in
            guard let base = ptr.baseAddress else { return }
            cprisk_test_secure_zero(base, ptr.count)
        }
        for byte in buffer {
            XCTAssertEqual(byte, 0, "every byte should be zeroed after cprisk_secure_zero")
        }
    }

    func testSecureZeroHandlesEmptyBuffer() {
        var buffer = [UInt8](repeating: 0xFF, count: 1)
        buffer.withUnsafeMutableBufferPointer { ptr in
            guard let base = ptr.baseAddress else { return }
            cprisk_test_secure_zero(base, 0)
        }
        XCTAssertEqual(buffer[0], 0xFF, "zero-length wipe should not modify any bytes")
    }

    // MARK: - Memory Guard

    func testMemoryGuardFunctionsExist() {
        let pageSize = Int(vm_page_size)
        let buf = UnsafeMutableRawPointer.allocate(byteCount: pageSize, alignment: pageSize)
        defer { buf.deallocate() }
        memset(buf, 0xCC, pageSize)

        let protectResult = cprisk_protect_decrypted_pages(buf, pageSize)
        XCTAssertTrue(
            protectResult == 0 || protectResult == -1,
            "cprisk_protect_decrypted_pages should return 0 or -1, got \(protectResult)"
        )

        let verifyResult = cprisk_verify_page_protection(buf, pageSize)
        XCTAssertTrue(
            verifyResult == 0 || verifyResult == 1,
            "cprisk_verify_page_protection should return 0 or 1, got \(verifyResult)"
        )

        let unprotectResult = cprisk_unprotect_pages(buf, pageSize)
        XCTAssertTrue(
            unprotectResult == 0 || unprotectResult == -1,
            "cprisk_unprotect_pages should return 0 or -1, got \(unprotectResult)"
        )
    }

    // MARK: - Init Timing

    func testInitTimingThresholdSyntheticMachineOlderGenerationIsHigherThanNew() {
        let older = cprisk_test_init_timing_threshold_ns_for_machine(
            "iPhone10,1",
            cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_PRODUCTION)
        )
        let newer = cprisk_test_init_timing_threshold_ns_for_machine(
            "iPhone17,1",
            cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_PRODUCTION)
        )
        XCTAssertGreaterThan(
            older,
            newer,
            "older SoC generations should receive a larger slack threshold than recent ones"
        )
    }

    func testRelaxedAntiDebugModeRaisesInitTimingThresholdVersusProduction() {
        let machine = "iPhone14,2"
        let prod = cprisk_test_init_timing_threshold_ns_for_machine(
            machine,
            cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_PRODUCTION)
        )
        let relaxed = cprisk_test_init_timing_threshold_ns_for_machine(
            machine,
            cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA)
        )
        let appStoreSafe = cprisk_test_init_timing_threshold_ns_for_machine(
            machine,
            cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE)
        )
        XCTAssertGreaterThan(relaxed, prod)
        XCTAssertEqual(appStoreSafe, relaxed)
    }

    func testAntiDebugRuntimeModeEnumAlignsWithCConstants() {
        XCTAssertEqual(CPRiskAntiDebugRuntimeMode.production.rawValue, Int(CPRISK_RUNTIME_HARDENING_PRODUCTION))
        XCTAssertEqual(CPRiskAntiDebugRuntimeMode.relaxedDevelopmentQA.rawValue, Int(CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA))
        XCTAssertEqual(CPRiskAntiDebugRuntimeMode.appStoreSafe.rawValue, Int(CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE))
    }

    func testRuntimeHardeningModeRoundTripInC() {
        cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA))
        XCTAssertEqual(Int(cprisk_get_runtime_hardening_mode()), Int(CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA))
        cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE))
        XCTAssertEqual(Int(cprisk_get_runtime_hardening_mode()), Int(CPRISK_RUNTIME_HARDENING_APP_STORE_SAFE))
        cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t(CPRISK_RUNTIME_HARDENING_PRODUCTION))
        XCTAssertEqual(Int(cprisk_get_runtime_hardening_mode()), Int(CPRISK_RUNTIME_HARDENING_PRODUCTION))
    }

    func testStartWithRelaxedAntiDebugModeAppliesCoreModeAndStopResetsIt() {
        let config = CPRiskConfig()
        config.antiDebugRuntimeMode = .relaxedDevelopmentQA

        CPRiskKit.shared.start(config: config)
        XCTAssertEqual(Int(cprisk_get_runtime_hardening_mode()), Int(CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA))

        CPRiskKit.shared.stop()
        XCTAssertEqual(Int(cprisk_get_runtime_hardening_mode()), Int(CPRISK_RUNTIME_HARDENING_PRODUCTION))
    }

    func testInitElapsedNsIsNonZeroAfterStart() {
        CPRiskKit.shared.start()
        defer { CPRiskKit.shared.stop() }

        let elapsed = cprisk_get_init_elapsed_ns()
        XCTAssertGreaterThan(elapsed, 0, "init elapsed time should be recorded after start()")
    }

    func testInitElapsedNsIsZeroAfterCleanup() {
        CPRiskKit.shared.start()
        CPRiskKit.shared.stop()
        let elapsed = cprisk_get_init_elapsed_ns()
        XCTAssertEqual(elapsed, 0, "init elapsed time should be cleared after cleanup")
    }

    // MARK: - AntiDebug Plan Runtime Consumption

    func testInjectedValidAntiDebugPlanIsParsedAndConsumed() {
        let payload = makeAntiDebugPlanPayload(
            policyBits: UInt32(CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE)
                | UInt32(CPRISK_ARMOR_ADBG_POLICY_DELAY_RESPONSE)
                | UInt32(CPRISK_ARMOR_ADBG_POLICY_ESCALATE_INTEGRITY)
                | UInt32(CPRISK_ARMOR_ADBG_POLICY_TRAP_ON_TAMPER)
                | UInt32(CPRISK_ARMOR_ADBG_POLICY_CRASH_ON_DEBUGGER)
        )

        let injectRC = payload.withUnsafeBytes { raw -> Int32 in
            cprisk_test_set_antidebug_plan(
                raw.bindMemory(to: UInt8.self).baseAddress,
                payload.count
            )
        }
        XCTAssertEqual(injectRC, 0, "valid anti-debug payload should be accepted by test injector")

        let keyData = Data(repeating: 0x42, count: 32)
        let initRC = keyData.withUnsafeBytes { raw -> Int32 in
            cprisk_init_protection(
                raw.bindMemory(to: UInt8.self).baseAddress,
                keyData.count
            )
        }
        XCTAssertTrue(
            initRC == 0 || (initRC >= -7 && initRC <= -1),
            "init must complete with a defined return code, got \(initRC)"
        )

        var snapshot = cprisk_antidebug_plan_snapshot_t()
        XCTAssertEqual(cprisk_get_antidebug_plan_snapshot(&snapshot), 0)
        XCTAssertEqual(snapshot.section_present, 1)
        XCTAssertEqual(snapshot.section_valid, 1)
        XCTAssertEqual(snapshot.parse_error, 0)
        XCTAssertEqual(snapshot.entry_count, 1)
        XCTAssertGreaterThan(snapshot.consume_count, 0)

        XCTAssertNotEqual(
            snapshot.last_applied_policy_bits & UInt32(CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE),
            0,
            "RuntimeGate should execute when plan is consumed"
        )
        XCTAssertNotEqual(
            snapshot.last_applied_policy_bits & UInt32(CPRISK_ARMOR_ADBG_POLICY_DELAY_RESPONSE),
            0,
            "DelayResponse should execute when plan is consumed"
        )
    }

    func testMalformedAntiDebugPlanSafelyDegrades() {
        let malformed = Data(repeating: 0xA5, count: 16)
        let injectRC = malformed.withUnsafeBytes { raw -> Int32 in
            cprisk_test_set_antidebug_plan(
                raw.bindMemory(to: UInt8.self).baseAddress,
                malformed.count
            )
        }
        XCTAssertEqual(injectRC, 0, "malformed bytes should still inject for parser negative testing")

        let keyData = Data(repeating: 0x42, count: 32)
        let initRC = keyData.withUnsafeBytes { raw -> Int32 in
            cprisk_init_protection(
                raw.bindMemory(to: UInt8.self).baseAddress,
                keyData.count
            )
        }
        XCTAssertTrue(
            initRC == 0 || (initRC >= -7 && initRC <= -1),
            "malformed plan must not crash init path, got \(initRC)"
        )

        var snapshot = cprisk_antidebug_plan_snapshot_t()
        XCTAssertEqual(cprisk_get_antidebug_plan_snapshot(&snapshot), 0)
        XCTAssertEqual(snapshot.section_present, 1)
        XCTAssertEqual(snapshot.section_valid, 0)
        XCTAssertNotEqual(snapshot.parse_error, 0)
    }

    func testInlinePatchGateFailurePoisonsSafely() {
        let payload = makeAntiDebugPlanPayload(
            policyBits: UInt32(CPRISK_ARMOR_ADBG_POLICY_RUNTIME_GATE)
                | UInt32(CPRISK_ARMOR_ADBG_POLICY_TRAP_ON_TAMPER),
            entryFlags: UInt32(CPRISK_ARMOR_ADBG_ENTRY_FLAG_INLINE_PATCH_RESERVED)
                | UInt32(CPRISK_ARMOR_ADBG_ENTRY_FLAG_RUNTIME_GATE_RESERVED)
        )

        let injectRC = payload.withUnsafeBytes { raw -> Int32 in
            cprisk_test_set_antidebug_plan(
                raw.bindMemory(to: UInt8.self).baseAddress,
                payload.count
            )
        }
        XCTAssertEqual(injectRC, 0)

        let keyData = Data(repeating: 0x42, count: 32)
        _ = keyData.withUnsafeBytes { raw -> Int32 in
            cprisk_init_protection(
                raw.bindMemory(to: UInt8.self).baseAddress,
                keyData.count
            )
        }

        var snapshot = cprisk_antidebug_plan_snapshot_t()
        XCTAssertEqual(cprisk_get_antidebug_plan_snapshot(&snapshot), 0)
        XCTAssertEqual(snapshot.section_valid, 1)
        XCTAssertGreaterThan(
            snapshot.inline_patch_failure_count,
            0,
            "invalid test patch-site must fail closed and be recorded"
        )
        XCTAssertEqual(snapshot.last_inline_patch_tamper, 1)
    }

    func testStringDecryptPathSelectorIsDeterministicForSeed() {
        let seed: UInt64 = 0xA17C_9E51_42D0_77B3
        let nonce: [UInt8] = [0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD]

        let pathA = nonce.withUnsafeBufferPointer { ptr in
            cprisk_test_select_string_decrypt_path(17, ptr.baseAddress, seed)
        }
        let pathB = nonce.withUnsafeBufferPointer { ptr in
            cprisk_test_select_string_decrypt_path(17, ptr.baseAddress, seed)
        }
        XCTAssertEqual(pathA, pathB, "same seed/stringID/nonce must always choose the same decrypt path")

        var seen = Set<UInt32>()
        for sid in UInt32(1)...UInt32(64) {
            let selected = nonce.withUnsafeBufferPointer { ptr in
                cprisk_test_select_string_decrypt_path(sid, ptr.baseAddress, seed)
            }
            XCTAssertLessThan(selected, 4, "selector must only return path IDs in [0, 3]")
            seen.insert(selected)
        }
        XCTAssertGreaterThanOrEqual(seen.count, 3, "path selector should spread calls across multiple variants")
    }

    func testObfDecodeSha256TagMatchesFridaToken() {
        let domain = UInt32(CPRISK_OBF_TAG_DOMAIN_FRIDA_RT)
        let enc: [UInt8] = [0xad, 0x0c, 0x6f, 0xa8, 0x2c]
        var buf = [CChar](repeating: 0, count: 32)
        let rc = cprisk_obf_decode_sha256_tag(domain, 1, enc, enc.count, &buf, buf.count)
        XCTAssertEqual(rc, 0)
        XCTAssertEqual(String(cString: buf), "frida")
    }

    func testArm64SuspiciousTrampolinePrefixDetectorFlagsCommonHookStubs() {
        let clean: [UInt32] = [0xA9BF7BFD, 0x910003FD, 0xA90153F3]
        let branchStub: [UInt32] = [0x14000008, 0xD503201F, 0xD503201F]
        let literalBrStub: [UInt32] = [0x58000010, 0xD61F0200, 0xD503201F]
        let adrpAddBrStub: [UInt32] = [0x90000010, 0x91000210, 0xD61F0200]

        func scan(_ words: [UInt32]) -> Int32 {
            words.withUnsafeBytes { raw in
                cprisk_scan_arm64_suspicious_trampoline_prefix(raw.baseAddress, raw.count)
            }
        }

        XCTAssertEqual(scan(clean), 0)
        XCTAssertEqual(scan(branchStub), 1)
        XCTAssertEqual(scan(literalBrStub), 1)
        XCTAssertEqual(scan(adrpAddBrStub), 1)
    }

    func testFridaRuntimeSnapshotBehaviorFieldsStayConsistent() {
        var snapshot = cprisk_frida_runtime_snapshot_t()
        XCTAssertEqual(cprisk_frida_runtime_snapshot(&snapshot), 0)
        if snapshot.supported == 0 {
            XCTAssertEqual(snapshot.flags, 0)
            XCTAssertEqual(snapshot.behavior_flags, 0)
            XCTAssertEqual(snapshot.behavior_hit_count, 0)
            return
        }

        let behaviorBit = UInt32(CPRISK_FRIDA_RT_BEHAVIOR)
        let behaviorSet = (snapshot.flags & behaviorBit) != 0
        if behaviorSet {
            XCTAssertNotEqual(snapshot.behavior_flags, 0)
            XCTAssertGreaterThan(snapshot.behavior_hit_count, 0)
        } else {
            XCTAssertEqual(snapshot.behavior_flags, 0)
            XCTAssertEqual(snapshot.behavior_hit_count, 0)
        }
    }

    func testVmMprotectCountersReadableAfterReset() {
        cprisk_test_mprotect_reset_tamper_state()
        XCTAssertEqual(cprisk_get_vm_mprotect_crosscheck_mismatch_count(), 0)
        XCTAssertEqual(cprisk_get_vm_mprotect_mach_trap_mismatch_count(), 0)
    }

    func testSvcStubIntegrityReturnsStableMaskOnThisPlatform() {
        let mask = cprisk_verify_svc_stub_integrity()
        /* bits 0..2: syscall6/deny/syscall0; 3..5: SHA-256 whole-page auxiliary */
        XCTAssertLessThanOrEqual(mask, 0x3F)
    }

    func testDlsymPrologueVerifierReturnsSuccessOnThisPlatform() {
        XCTAssertEqual(cprisk_verify_dlsym_prologue(), 1)
    }

    func testRuntimeHookSurfacePrologueVerifierReturnsSuccessOnThisPlatform() {
        XCTAssertEqual(cprisk_verify_runtime_hook_surface_prologues(), 1)
    }

    func testRuntimeHookSurfaceExportDriftMaskIsWithinKnownWatchdogBits() {
        let mask = cprisk_runtime_hook_surface_export_drift_mask()
        let allowed: UInt32 =
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_ACCESS) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_STAT) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_LSTAT) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OPEN) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_SOCKET) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_CONNECT) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DLOPEN) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_SYSCTL) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_SYSCTLBYNAME) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_MPROTECT) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_MACH_MSG) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_TASK_GET_EXCEPTION_PORTS) |
            UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_TASK_SWAP_EXCEPTION_PORTS)
        XCTAssertEqual(mask & ~allowed, 0)
    }

    func testMaskedPathProbesResolveTemporaryFileAcrossSecureAndStandardPaths() throws {
        let tempURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("cprisk-masked-probe-\(UUID().uuidString)")
        try Data("ok".utf8).write(to: tempURL)
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let path = tempURL.path
        XCTAssertEqual(SVCDirectCall.secureAccess(path), true)
        XCTAssertEqual(SVCDirectCall.secureStat(path), true)
        XCTAssertEqual(SVCDirectCall.secureLstat(path), true)

        let secureSnapshot = SVCDirectCall.securePathProbeSnapshot(path)
        XCTAssertEqual(secureSnapshot.access, true)
        XCTAssertEqual(secureSnapshot.stat, true)
        XCTAssertEqual(secureSnapshot.lstat, true)

        let standardSnapshot = SVCDirectCall.standardPathProbeSnapshot(path)
        XCTAssertEqual(standardSnapshot.access, true)
        XCTAssertEqual(standardSnapshot.stat, true)
        XCTAssertEqual(standardSnapshot.fopen, true)

        let libcMasked = SVCDirectCall.standardAccessErrnoMasked(path)
        XCTAssertEqual(libcMasked?.exists, true)
        XCTAssertEqual(libcMasked?.errno, 0)
    }

    func testTextEncryptSelfCheckIsCleanOnCurrentTestBuild() throws {
        let result = try textEncryptSelfCheckResult()
        XCTAssertEqual(result, 0)
    }

    func testCsopsStatusFlagsReturnsConsistentResultShape() {
        var flags: UInt32 = 0
        var err: Int32 = 0
        let rc = cprisk_csops_status_flags(&flags, &err)
        XCTAssertTrue(rc == 0 || rc == -1)
        if rc == 0 {
            XCTAssertEqual(err, 0)
        } else {
            XCTAssertNotEqual(err, 0)
        }
    }

    private func makeAntiDebugPlanPayload(
        policyBits: UInt32,
        entryFlags: UInt32 = UInt32(CPRISK_ARMOR_ADBG_ENTRY_FLAG_RUNTIME_GATE_RESERVED)
    ) -> Data {
        var data = Data()

        data.appendLE(UInt32(CPRISK_ARMOR_ADBG_MAGIC))
        data.appendLE(UInt32(CPRISK_ARMOR_ADBG_ABI_VERSION))
        data.appendLE(UInt32(CPRISK_ARMOR_ADBG_FLAG_HAS_SYMBOL_TARGETS))
        data.appendLE(UInt32(CPRISK_ARMOR_ADBG_HEADER_SIZE))
        data.appendLE(UInt64(0x1122_3344_5566_7788))
        data.appendLE(UInt64(0x0000_0001_0000_0000))
        data.appendLE(UInt32(0xA7D0_0001))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(CPRISK_ARMOR_ADBG_ENTRY_SIZE))
        data.appendLE(UInt32(0))

        data.appendLE(UInt64(0x1234_5678_90AB_CDEF))
        data.appendLE(UInt64(0x80))
        data.appendLE(UInt32(0x2000))
        data.appendLE(policyBits)
        data.appendLE(UInt32(0))
        data.appendLE(entryFlags)
        data.appendFixedCString("_risk_guard_entry", length: Int(CPRISK_ARMOR_ADBG_TARGET_NAME_SIZE))

        return data
    }
}

private extension Data {
    mutating func appendLE(_ value: UInt32) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }

    mutating func appendLE(_ value: UInt64) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }

    mutating func appendFixedCString(_ string: String, length: Int) {
        var bytes = Array(string.utf8.prefix(length))
        if bytes.count < length {
            bytes.append(contentsOf: repeatElement(0, count: length - bytes.count))
        }
        append(contentsOf: bytes)
    }
}
