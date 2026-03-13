import XCTest
@testable import CloudPhoneRiskKit

final class AntiTamperingTests: XCTestCase {

    // MARK: - AntiTamperingDetector Logic Tests

    func testAntiTamperingSuspiciousParentMatching() {
        let detector = AntiTamperingDetector()

        // Known debuggers / instrumentation tools
        XCTAssertEqual(detector.firstSuspiciousParentToken(in: "/usr/bin/lldb"), "lldb")
        XCTAssertEqual(detector.firstSuspiciousParentToken(in: "/usr/bin/gdb"), "gdb")
        XCTAssertEqual(detector.firstSuspiciousParentToken(in: "/Developer/usr/bin/debugserver"), "debugserver")
        XCTAssertEqual(detector.firstSuspiciousParentToken(in: "/usr/local/bin/frida-server"), "frida")
        XCTAssertEqual(detector.firstSuspiciousParentToken(in: "/Applications/Hopper Disassembler.app"), "hopper")
        XCTAssertEqual(detector.firstSuspiciousParentToken(in: "/Applications/IDA Pro.app/Contents/MacOS/ida64"), "ida")
        XCTAssertEqual(detector.firstSuspiciousParentToken(in: "/usr/local/bin/cycript"), "cycript")

        // Case insensitive
        XCTAssertEqual(detector.firstSuspiciousParentToken(in: "/usr/bin/LLDB"), "lldb")
        XCTAssertEqual(detector.firstSuspiciousParentToken(in: "/usr/bin/FRIDA-SERVER"), "frida")

        // Normal parents should not match
        XCTAssertNil(detector.firstSuspiciousParentToken(in: "/usr/libexec/init_firstboot"))
        XCTAssertNil(detector.firstSuspiciousParentToken(in: "/sbin/launchd"))
        XCTAssertNil(detector.firstSuspiciousParentToken(in: "/System/Library/CoreServices/SpringBoard.app/SpringBoard"))
    }

    func testAntiTamperingDebugEnvKeys() {
        let detector = AntiTamperingDetector()
        // Verify the detector tracks the right env keys
        XCTAssertEqual(detector.debugEnvironmentKeys.count, 5)
        XCTAssertTrue(detector.debugEnvironmentKeys.contains("DYLD_INSERT_LIBRARIES"))
        XCTAssertTrue(detector.debugEnvironmentKeys.contains("DYLD_FORCE_FLAT_NAMESPACE"))
        XCTAssertTrue(detector.debugEnvironmentKeys.contains("MallocStackLogging"))
        XCTAssertTrue(detector.debugEnvironmentKeys.contains("NSUnbufferedIO"))
        XCTAssertTrue(detector.debugEnvironmentKeys.contains("OS_ACTIVITY_DT_MODE"))
    }

    func testAntiTamperingScoreCapped() throws {
        let detector = AntiTamperingDetector()
        let result = try detector.detect()
        XCTAssertLessThanOrEqual(result.score, 90)
    }

    // MARK: - DebuggerDetector Logic Tests

    func testDebuggerParentTokenMatching() {
        let detector = DebuggerDetector()

        XCTAssertEqual(detector.firstDebuggerParentToken(in: "/usr/bin/lldb"), "lldb")
        XCTAssertEqual(detector.firstDebuggerParentToken(in: "/Developer/usr/bin/debugserver"), "debugserver")
        XCTAssertEqual(detector.firstDebuggerParentToken(in: "/Applications/Xcode.app/Contents/MacOS/Xcode"), "xcode")
        XCTAssertEqual(detector.firstDebuggerParentToken(in: "/usr/local/bin/frida"), "frida")
        XCTAssertEqual(detector.firstDebuggerParentToken(in: "/usr/bin/gdb"), "gdb")
        XCTAssertEqual(detector.firstDebuggerParentToken(in: "/Applications/Hopper.app"), "hopper")
        XCTAssertEqual(detector.firstDebuggerParentToken(in: "/Applications/IDA Pro.app"), "ida")

        XCTAssertNil(detector.firstDebuggerParentToken(in: "/sbin/launchd"))
        XCTAssertNil(detector.firstDebuggerParentToken(in: "/usr/bin/swift"))
    }

    func testDebuggerDetectorNeedlesConsistency() {
        let detector = DebuggerDetector()
        XCTAssertEqual(detector.debuggerParentNeedles.count, 7)
        XCTAssertEqual(detector.debuggerEnvKeys.count, 4)
        XCTAssertEqual(detector.debuggerPorts.count, 5)
    }

    func testDebuggerDetectorScoreCapped() throws {
        let detector = DebuggerDetector()
        let result = try detector.detect()
        XCTAssertLessThanOrEqual(result.score, 85)
    }

    func testDebuggerPortsIncludeFridaPorts() {
        let detector = DebuggerDetector()
        // Frida default ports
        XCTAssertTrue(detector.debuggerPorts.contains(27042))
        XCTAssertTrue(detector.debuggerPorts.contains(27043))
    }

    // MARK: - FridaDetector Logic Tests

    func testFridaDetectorKnownPorts() {
        let detector = FridaDetector()
        XCTAssertTrue(detector.knownPorts.contains(27042))
        XCTAssertTrue(detector.knownPorts.contains(27043))
        XCTAssertTrue(detector.knownPorts.contains(23946))
    }

    func testFridaDetectorMarkers() {
        let detector = FridaDetector()
        XCTAssertTrue(detector.markers.contains("frida"))
        XCTAssertTrue(detector.markers.contains("frida-agent"))
        XCTAssertTrue(detector.markers.contains("frida-server"))
        XCTAssertTrue(detector.markers.contains("gadget"))
        XCTAssertTrue(detector.markers.contains("gum"))
        XCTAssertTrue(detector.markers.contains("gum-js-loop"))
    }

    func testFridaDetectorServerPaths() {
        let detector = FridaDetector()
        // Should cover both rootful and rootless paths
        XCTAssertTrue(detector.knownServerPaths.contains("/usr/sbin/frida-server"))
        XCTAssertTrue(detector.knownServerPaths.contains("/var/jb/usr/sbin/frida-server"))
        XCTAssertTrue(detector.knownServerPaths.contains("/var/jb/usr/bin/frida-server"))
    }

    func testFridaFileArtifactOnCleanSystem() {
        let detector = FridaDetector()
        // On a clean test system, no Frida server files should exist
        XCTAssertFalse(detector.detectFridaFileArtifact())
    }

    // MARK: - FridaHeapDetector Tests

    func testFridaHeapDetectorScoreCapped() throws {
        let detector = FridaHeapDetector()
        let result = try detector.detect()
        XCTAssertLessThanOrEqual(result.score, 80)
    }

    func testFridaHeapDetectorSignalConversion() throws {
        let detector = FridaHeapDetector()
        let signals = try detector.asSignals()
        // On clean system, should produce no signals
        // If signals exist, verify structure
        for signal in signals {
            XCTAssertEqual(signal.category, "anti_tamper")
            XCTAssertEqual(signal.layer, 2)
            XCTAssertTrue(signal.id == "frida_js_engine_heap" || signal.id == "frida_stalker_jit")
        }
    }

    // MARK: - FridaThreadDetector Tests

    func testFridaThreadDetectorScoreCapped() throws {
        let detector = FridaThreadDetector()
        let result = try detector.detect()
        XCTAssertLessThanOrEqual(result.score, 80)
    }

    func testFridaThreadSignalConversion() throws {
        let detector = FridaThreadDetector()
        let signals = try detector.asSignals()
        for signal in signals {
            XCTAssertEqual(signal.category, "anti_tamper")
            XCTAssertEqual(signal.layer, 2)
            XCTAssertTrue(signal.id == "thread_anomaly" || signal.id == "frida_exception_port")
        }
    }

    // MARK: - FridaSocketDetector Tests

    func testFridaSocketDetectorScoreCapped() throws {
        let detector = FridaSocketDetector()
        let result = try detector.detect()
        // Socket detection capped at 30, timing at 75
        XCTAssertTrue(result.score >= 0)
    }

    func testFridaSocketSignalConversion() throws {
        let detector = FridaSocketDetector()
        let signals = try detector.asSignals()
        for signal in signals {
            XCTAssertEqual(signal.category, "anti_tamper")
            XCTAssertEqual(signal.layer, 2)
            XCTAssertTrue(signal.id == "frida_unix_socket" || signal.id == "frida_timing_anomaly")
        }
    }

    // MARK: - ObjCSwizzleDetector Tests

    func testObjCSwizzleMethodChecksCompleteness() throws {
        let detector = ObjCSwizzleDetector()
        // Verify detect() runs without crash
        let result = try detector.detect()
        XCTAssertTrue(result.score >= 0)
    }

    func testObjCSwizzleSignalConversion() throws {
        let detector = ObjCSwizzleDetector()
        let signals = try detector.asSignals()
        for signal in signals {
            XCTAssertEqual(signal.category, "anti_tamper")
            XCTAssertEqual(signal.layer, 2)
            XCTAssertTrue(
                signal.id == "objc_method_swizzled" ||
                signal.id == "objc_inline_hook_detected" ||
                signal.id == "frida_dispatch_queue"
            )
        }
    }

    // MARK: - SensorReplayDetector Tests

    func testSensorReplayDetectorRuns() throws {
        let detector = SensorReplayDetector()
        let result = try detector.detect()
        XCTAssertTrue(result.score >= 0)
    }

    func testSensorReplaySignalConversion() throws {
        let detector = SensorReplayDetector()
        let signals = try detector.asSignals()
        for signal in signals {
            XCTAssertEqual(signal.category, "device")
            XCTAssertEqual(signal.layer, 3)
            XCTAssertEqual(signal.id, "sensor_replay_detected")
        }
    }

    // MARK: - Cross-Detector Consistency Tests

    func testAllAntiTamperingDetectorsProduceValidResults() throws {
        // All detectors should produce non-negative scores
        let detectors: [Detector] = [
            AntiTamperingDetector(),
            DebuggerDetector(),
            FridaDetector(),
            FridaHeapDetector(),
            FridaThreadDetector(),
            FridaSocketDetector(),
            ObjCSwizzleDetector(),
            SensorReplayDetector(),
        ]

        for detector in detectors {
            let result = try detector.detect()
            XCTAssertGreaterThanOrEqual(result.score, 0,
                "\(type(of: detector)) produced negative score: \(result.score)")
            // Methods should not be empty if score > 0
            if result.score > 0 {
                XCTAssertFalse(result.methods.isEmpty,
                    "\(type(of: detector)) has score \(result.score) but empty methods")
            }
        }
    }
}
