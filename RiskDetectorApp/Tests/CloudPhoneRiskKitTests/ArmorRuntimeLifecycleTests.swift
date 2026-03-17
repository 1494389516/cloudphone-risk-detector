import Foundation
import XCTest
import CRiskCore
@testable import CloudPhoneRiskKit

final class ArmorRuntimeLifecycleTests: XCTestCase {
    private let armorRootKeyDefaultsKey = "com.cloudphone.riskkit.armor.root_key_hex"

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
        XCTAssertEqual(poisoned, 0, "visible poison flag should stay clear in a clean test run")
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
}
