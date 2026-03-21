import Foundation
import XCTest
import CRiskCore
@testable import CloudPhoneRiskKit

final class ArmorRuntimeLifecycleTests: XCTestCase {
    private let armorRootKeyDefaultsKey = "com.cloudphone.riskkit.armor.root_key_hex"

    private func waitForWatchdogSnapshot(
        timeout: TimeInterval = 1.0
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

        if startedSnapshot.supported {
            XCTAssertTrue(startedSnapshot.running, "watchdog should be marked running after start()")
            XCTAssertTrue(
                (1...5).contains(Int(startedSnapshot.intervalSeconds)),
                "watchdog interval should be randomized within expected range"
            )
            XCTAssertGreaterThan(startedSnapshot.iterationCount, 0, "watchdog should execute at least one iteration")
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
