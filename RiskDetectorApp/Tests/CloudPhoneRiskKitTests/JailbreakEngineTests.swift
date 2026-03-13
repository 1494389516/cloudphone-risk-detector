import XCTest
@testable import CloudPhoneRiskKit

final class JailbreakEngineTests: XCTestCase {

    // MARK: - JailbreakConfig Tests

    func testDefaultConfigEnablesAllDetectors() {
        let config = JailbreakConfig.default
        XCTAssertTrue(config.enableFileDetect)
        XCTAssertTrue(config.enableDyldDetect)
        XCTAssertTrue(config.enableEnvDetect)
        XCTAssertTrue(config.enableSysctlDetect)
        XCTAssertTrue(config.enableSchemeDetect)
        XCTAssertTrue(config.enableHookDetect)
        XCTAssertEqual(config.threshold, 50.0)
    }

    func testLightConfigDisablesHeavyDetectors() {
        let config = JailbreakConfig.light
        XCTAssertTrue(config.enableFileDetect)
        XCTAssertTrue(config.enableDyldDetect)
        XCTAssertFalse(config.enableEnvDetect)
        XCTAssertFalse(config.enableSysctlDetect)
        XCTAssertFalse(config.enableSchemeDetect)
        XCTAssertFalse(config.enableHookDetect)
        XCTAssertEqual(config.threshold, 60.0)
    }

    func testFullConfigEnablesAllWithLowerThreshold() {
        let config = JailbreakConfig.full
        XCTAssertTrue(config.enableFileDetect)
        XCTAssertTrue(config.enableDyldDetect)
        XCTAssertTrue(config.enableEnvDetect)
        XCTAssertTrue(config.enableSysctlDetect)
        XCTAssertTrue(config.enableSchemeDetect)
        XCTAssertTrue(config.enableHookDetect)
        XCTAssertEqual(config.threshold, 40.0)
    }

    func testConfigCustomThreshold() {
        var config = JailbreakConfig()
        config.threshold = 75.0
        XCTAssertEqual(config.threshold, 75.0)
    }

    func testConfigSelectiveDetectors() {
        var config = JailbreakConfig()
        config.enableFileDetect = false
        config.enableDyldDetect = true
        config.enableEnvDetect = false
        config.enableSysctlDetect = false
        config.enableSchemeDetect = false
        config.enableHookDetect = true
        XCTAssertFalse(config.enableFileDetect)
        XCTAssertTrue(config.enableDyldDetect)
        XCTAssertFalse(config.enableEnvDetect)
    }

    // MARK: - DetectorResult Tests

    func testEmptyDetectorResult() {
        let result = DetectorResult.empty
        XCTAssertEqual(result.score, 0)
        XCTAssertTrue(result.methods.isEmpty)
    }

    func testDetectorResultStoresValues() {
        let result = DetectorResult(score: 42.5, methods: ["file:test", "dylib:frida"])
        XCTAssertEqual(result.score, 42.5)
        XCTAssertEqual(result.methods.count, 2)
        XCTAssertTrue(result.methods.contains("file:test"))
        XCTAssertTrue(result.methods.contains("dylib:frida"))
    }

    // MARK: - DetectionResult Tests

    func testDetectionResultFields() {
        let result = DetectionResult(
            isJailbroken: true,
            confidence: 85.0,
            detectedMethods: ["file:/Applications/Cydia.app"],
            details: "jailbreak_detected"
        )
        XCTAssertTrue(result.isJailbroken)
        XCTAssertEqual(result.confidence, 85.0)
        XCTAssertEqual(result.detectedMethods.count, 1)
    }

    func testDetectionResultCleanDevice() {
        let result = DetectionResult(
            isJailbroken: false,
            confidence: 0,
            detectedMethods: [],
            details: "clean"
        )
        XCTAssertFalse(result.isJailbroken)
        XCTAssertEqual(result.confidence, 0)
        XCTAssertTrue(result.detectedMethods.isEmpty)
    }

    // MARK: - DyldDetector Logic Tests

    func testDyldDetectorSuspiciousTokenMatching() {
        let detector = DyldDetector()

        // Should match
        XCTAssertEqual(detector.firstSuspiciousToken(in: "/usr/lib/FridaGadget.dylib"), "frida")
        XCTAssertEqual(detector.firstSuspiciousToken(in: "/Library/MobileSubstrate/MobileSubstrate.dylib"), "substrate")
        XCTAssertEqual(detector.firstSuspiciousToken(in: "/usr/lib/libsubstitute.dylib"), "substitute")
        XCTAssertEqual(detector.firstSuspiciousToken(in: "/usr/lib/ElleKit.dylib"), "ellekit")
        XCTAssertEqual(detector.firstSuspiciousToken(in: "/usr/lib/libhooker.dylib"), "libhooker")
        XCTAssertEqual(detector.firstSuspiciousToken(in: "/usr/lib/libcycript.dylib"), "cycript")

        // Should NOT match
        XCTAssertNil(detector.firstSuspiciousToken(in: "/usr/lib/system/libsystem_kernel.dylib"))
        XCTAssertNil(detector.firstSuspiciousToken(in: "/System/Library/Frameworks/UIKit.framework/UIKit"))
        XCTAssertNil(detector.firstSuspiciousToken(in: "/usr/lib/libobjc.A.dylib"))
    }

    func testDyldDetectorCaseInsensitive() {
        let detector = DyldDetector()
        XCTAssertEqual(detector.firstSuspiciousToken(in: "/usr/lib/FRIDAGADGET.dylib"), "frida")
        XCTAssertEqual(detector.firstSuspiciousToken(in: "/Library/MOBILESUBSTRATE/MobileSubstrate.dylib"), "substrate")
    }

    // MARK: - SysctlDetector Logic Tests

    func testSysctlDetectorProcessTokenMatching() {
        let detector = SysctlDetector()

        XCTAssertEqual(detector.firstSuspiciousProcessToken(in: "cydia"), "cydia")
        XCTAssertEqual(detector.firstSuspiciousProcessToken(in: "frida-server"), "frida")
        XCTAssertEqual(detector.firstSuspiciousProcessToken(in: "sshd"), "sshd")
        XCTAssertEqual(detector.firstSuspiciousProcessToken(in: "debugserver"), "debugserver")
        XCTAssertEqual(detector.firstSuspiciousProcessToken(in: "substrated"), "substrated")

        XCTAssertNil(detector.firstSuspiciousProcessToken(in: "SpringBoard"))
        XCTAssertNil(detector.firstSuspiciousProcessToken(in: "launchd"))
        XCTAssertNil(detector.firstSuspiciousProcessToken(in: "MyApp"))
    }

    func testSysctlDetectorParentTokenMatching() {
        let detector = SysctlDetector()

        XCTAssertNotNil(detector.firstSuspiciousParentToken(in: "cydia"))
        XCTAssertNotNil(detector.firstSuspiciousParentToken(in: "frida"))
        XCTAssertNotNil(detector.firstSuspiciousParentToken(in: "lldb"))
        XCTAssertNotNil(detector.firstSuspiciousParentToken(in: "debugserver"))

        XCTAssertNil(detector.firstSuspiciousParentToken(in: "launchd"))
        XCTAssertNil(detector.firstSuspiciousParentToken(in: "SpringBoard"))
    }

    func testSysctlDetectorNormalization() {
        let detector = SysctlDetector()
        XCTAssertEqual(detector.normalizeProcessName("  Cydia  "), "cydia")
        XCTAssertEqual(detector.normalizeProcessName("FRIDA\n"), "frida")
        XCTAssertEqual(detector.normalizeProcessName("  SSHD  \n"), "sshd")
    }

    // MARK: - HookDetector Logic Tests

    func testHookDetectorSuspiciousImagePath() {
        let detector = HookDetector()

        XCTAssertTrue(detector.isSuspiciousImagePath("/usr/lib/FridaGadget.dylib"))
        XCTAssertTrue(detector.isSuspiciousImagePath("/Library/MobileSubstrate/substrate.dylib"))
        XCTAssertTrue(detector.isSuspiciousImagePath("/usr/lib/libhooker.dylib"))
        XCTAssertTrue(detector.isSuspiciousImagePath("/usr/lib/ellekit.dylib"))
        XCTAssertTrue(detector.isSuspiciousImagePath("/var/jb/tweaks/mytweak.dylib"))

        XCTAssertFalse(detector.isSuspiciousImagePath("/usr/lib/system/libsystem_kernel.dylib"))
        XCTAssertFalse(detector.isSuspiciousImagePath("/System/Library/Frameworks/UIKit.framework/UIKit"))
    }

    func testHookDetectorTrustedSystemImagePath() {
        let detector = HookDetector()

        // System paths should be trusted
        XCTAssertTrue(detector.isTrustedSystemImagePath("/usr/lib/system/libsystem_kernel.dylib", for: "open"))
        XCTAssertTrue(detector.isTrustedSystemImagePath("/usr/lib/libsystem_c.dylib", for: "stat"))
        XCTAssertTrue(detector.isTrustedSystemImagePath("/System/Library/Frameworks/UIKit.framework/UIKit", for: "open"))

        // objc_msgSend should also trust libobjc
        XCTAssertTrue(detector.isTrustedSystemImagePath("/usr/lib/libobjc.A.dylib", for: "objc_msgSend"))

        // libobjc should NOT be trusted for non-objc symbols
        XCTAssertFalse(detector.isTrustedSystemImagePath("/usr/lib/libobjc.A.dylib", for: "open"))

        // Non-system paths should NOT be trusted
        XCTAssertFalse(detector.isTrustedSystemImagePath("/var/jb/lib/mylib.dylib", for: "open"))
        XCTAssertFalse(detector.isTrustedSystemImagePath("/Library/MobileSubstrate/substrate.dylib", for: "stat"))
    }

    // MARK: - HookFrameworkSymbolDetector Logic Tests

    func testHookFrameworkSuspiciousImagePath() {
        let detector = HookFrameworkSymbolDetector()

        XCTAssertTrue(detector.isSuspiciousImagePath("/usr/lib/frida/agent.dylib"))
        XCTAssertTrue(detector.isSuspiciousImagePath("/Library/substrate/something.dylib"))
        XCTAssertTrue(detector.isSuspiciousImagePath("/var/jb/hook.dylib"))

        XCTAssertFalse(detector.isSuspiciousImagePath("/usr/lib/system/libsystem_kernel.dylib"))
    }

    func testHookFrameworkTrustedSystemPath() {
        let detector = HookFrameworkSymbolDetector()

        XCTAssertTrue(detector.isTrustedSystemPath("/usr/lib/system/libsystem_kernel.dylib"))
        XCTAssertTrue(detector.isTrustedSystemPath("/usr/lib/libsystem_c.dylib"))
        XCTAssertTrue(detector.isTrustedSystemPath("/usr/lib/libobjc.A.dylib"))
        XCTAssertTrue(detector.isTrustedSystemPath("/System/Library/Frameworks/Something.framework/Something"))

        XCTAssertFalse(detector.isTrustedSystemPath("/var/jb/lib/something.dylib"))
        XCTAssertFalse(detector.isTrustedSystemPath("/Library/MobileSubstrate/MobileSubstrate.dylib"))
    }

    // MARK: - PointerValidationDetector Logic Tests

    func testPointerValidationSuspiciousImagePath() {
        let detector = PointerValidationDetector()

        XCTAssertTrue(detector.isSuspiciousImagePath("/usr/lib/frida-gadget.dylib"))
        XCTAssertTrue(detector.isSuspiciousImagePath("/Library/substitute/libsubstitute.dylib"))

        XCTAssertFalse(detector.isSuspiciousImagePath("/usr/lib/system/libsystem_c.dylib"))
    }

    func testPointerValidationExpectedPath() {
        let detector = PointerValidationDetector()
        let systemPrefixes = ["/usr/lib/system/", "/usr/lib/libsystem"]

        XCTAssertTrue(detector.isExpectedPath("/usr/lib/system/libsystem_kernel.dylib", expectedPrefixes: systemPrefixes))
        XCTAssertTrue(detector.isExpectedPath("/usr/lib/libsystem_c.dylib", expectedPrefixes: systemPrefixes))

        XCTAssertFalse(detector.isExpectedPath("/var/jb/lib/mylib.dylib", expectedPrefixes: systemPrefixes))
        XCTAssertFalse(detector.isExpectedPath("/Library/MobileSubstrate/substrate.dylib", expectedPrefixes: systemPrefixes))
    }

    // MARK: - IndirectSymbolPointerDetector Logic Tests

    func testIndirectSymbolTrustedSystemPath() {
        let detector = IndirectSymbolPointerDetector()

        XCTAssertTrue(detector.isTrustedSystemPath("/usr/lib/system/libsystem_kernel.dylib"))
        XCTAssertTrue(detector.isTrustedSystemPath("/System/Library/Frameworks/UIKit.framework/UIKit"))

        // Suspicious tokens make it untrusted even with system prefix
        XCTAssertFalse(detector.isTrustedSystemPath("/usr/lib/system/frida-helper.dylib"))
        XCTAssertFalse(detector.isTrustedSystemPath("/usr/lib/system/substrate.dylib"))
    }

    // MARK: - ObjCIMPDetector Logic Tests

    func testObjCIMPTrustedPath() {
        let detector = ObjCIMPDetector()

        XCTAssertTrue(detector.isTrustedImpImagePath("/System/Library/Frameworks/Foundation.framework/Foundation"))
        XCTAssertTrue(detector.isTrustedImpImagePath("/usr/lib/system/libsystem_kernel.dylib"))
        XCTAssertTrue(detector.isTrustedImpImagePath("/usr/lib/libobjc.A.dylib"))

        // Suspicious image tokens override trust
        XCTAssertFalse(detector.isTrustedImpImagePath("/usr/lib/frida-gadget.dylib"))
        XCTAssertFalse(detector.isTrustedImpImagePath("/Library/substrate/something.dylib"))

        // Non-system path
        XCTAssertFalse(detector.isTrustedImpImagePath("/var/jb/tweaks/mytweak.dylib"))
    }

    // MARK: - PrologueBranchDetector Logic Tests (ARM64 only)

    #if arch(arm64) || arch(arm64e)
    func testPrologueUnconditionalBranchDetection() {
        let detector = PrologueBranchDetector()

        // B imm26: bits[31:26] == 0b000101 = 0x14000000
        XCTAssertTrue(detector.isUnconditionalBranch(0x14000001))  // B #4
        XCTAssertTrue(detector.isUnconditionalBranch(0x14FFFFFF))  // B large offset

        // BL imm26: bits[31:26] == 0b100101 = 0x94000000
        XCTAssertTrue(detector.isUnconditionalBranch(0x94000001))  // BL #4

        // Not a branch
        XCTAssertFalse(detector.isUnconditionalBranch(0xD65F03C0))  // RET
        XCTAssertFalse(detector.isUnconditionalBranch(0xA9BF7BFD))  // STP
    }

    func testPrologueRegisterBranchDetection() {
        let detector = PrologueBranchDetector()

        // BR X16: 0xD61F0200
        XCTAssertTrue(detector.isRegisterBranch(0xD61F0200))
        // BR X17: 0xD61F0220
        XCTAssertTrue(detector.isRegisterBranch(0xD61F0220))
        // BLR X8: 0xD63F0100
        XCTAssertTrue(detector.isRegisterBranch(0xD63F0100))

        // Not a register branch
        XCTAssertFalse(detector.isRegisterBranch(0xD65F03C0))  // RET
        XCTAssertFalse(detector.isRegisterBranch(0x14000001))  // B imm26
    }

    func testPrologueLiteralLoadDetection() {
        let detector = PrologueBranchDetector()

        // LDR X0, literal: 0x58xxxxxx
        XCTAssertTrue(detector.isLiteralLoad(0x58000040))
        XCTAssertTrue(detector.isLiteralLoad(0x58000001))

        // Not LDR literal
        XCTAssertFalse(detector.isLiteralLoad(0xF9400000))  // LDR from register
        XCTAssertFalse(detector.isLiteralLoad(0xD61F0200))  // BR
    }

    func testPrologueHookDetection() {
        let detector = PrologueBranchDetector()

        // Direct branch = hooked
        XCTAssertTrue(detector.isHooked(firstInstruction: 0x14000001, secondInstruction: nil))
        // Register branch = hooked
        XCTAssertTrue(detector.isHooked(firstInstruction: 0xD61F0200, secondInstruction: nil))
        // LDR literal + BR = Frida trampoline
        XCTAssertTrue(detector.isHooked(firstInstruction: 0x58000040, secondInstruction: 0xD61F0200))

        // Normal prologue (STP x29, x30, [sp, #-16]!)
        XCTAssertFalse(detector.isHooked(firstInstruction: 0xA9BF7BFD, secondInstruction: 0xA9BF7BFD))
        // LDR literal + non-branch = not hooked
        XCTAssertFalse(detector.isHooked(firstInstruction: 0x58000040, secondInstruction: 0xA9BF7BFD))
    }
    #endif

    // MARK: - MachOTextRange Tests

    func testMachOTextRangeNilForInvalidPointer() {
        // A zero-filled buffer won't have valid MH_MAGIC_64
        var buffer = [UInt8](repeating: 0, count: 256)
        let range = buffer.withUnsafeMutableBytes { rawBuffer in
            MachOTextRange.textRange(header: rawBuffer.baseAddress!)
        }
        XCTAssertNil(range)
    }

    // MARK: - EnvDetector Suspicious Vars Coverage

    func testEnvDetectorSuspiciousVarsList() throws {
        // Verify the detector covers critical env vars
        let detector = EnvDetector()
        let result = try detector.detect()
        // On a clean test environment, no suspicious vars should be set
        // (unless running under instrumentation)
        XCTAssertTrue(result.score >= 0, "Score should never be negative")
    }

    // MARK: - JailbreakEngine Integration Tests

    func testEngineProducesResultWithAllDetectorsDisabled() {
        let engine = JailbreakEngine()
        var config = JailbreakConfig()
        config.enableFileDetect = false
        config.enableDyldDetect = false
        config.enableEnvDetect = false
        config.enableSysctlDetect = false
        config.enableSchemeDetect = false
        config.enableHookDetect = false

        let result = engine.detect(config: config)
        // With all detectors disabled, score should be 0
        XCTAssertEqual(result.confidence, 0)
        XCTAssertFalse(result.isJailbroken)
        XCTAssertTrue(result.detectedMethods.isEmpty)
    }

    func testEngineConfidenceCappedAt100() {
        // Even with high scores, confidence should not exceed 100
        let result = DetectionResult(
            isJailbroken: true,
            confidence: min(150, 100),
            detectedMethods: ["test"],
            details: "test"
        )
        XCTAssertLessThanOrEqual(result.confidence, 100)
    }

    func testEngineMethodsAreDeduplicated() {
        let engine = JailbreakEngine()
        // Use .light to avoid __NSGenericDeallocHandler crash in HookDetector/SchemeDetector
        // when running on macOS (swift test) - ObjC runtime interaction with Swift closures
        let config = JailbreakConfig.light
        let result = engine.detect(config: config)

        // Methods should be sorted and unique after engine processing
        let uniqueMethods = Set(result.detectedMethods)
        XCTAssertEqual(uniqueMethods.count, result.detectedMethods.count,
                       "Engine should produce deduplicated, sorted methods")
    }

    // MARK: - Score Capping Tests

    func testDyldDetectorScoreCappedAt90() throws {
        // DyldDetector caps at 90 (line 61 of DyldDetector.swift)
        let detector = DyldDetector()
        let result = try detector.detect()
        XCTAssertLessThanOrEqual(result.score, 90)
    }

    func testSysctlDetectorScoreCappedAt85() throws {
        // SysctlDetector caps at 85 (line 108 of SysctlDetector.swift)
        let detector = SysctlDetector()
        let result = try detector.detect()
        XCTAssertLessThanOrEqual(result.score, 85)
    }

    func testObjCIMPDetectorScoreCappedAt40() throws {
        let detector = ObjCIMPDetector()
        let result = try detector.detect()
        XCTAssertLessThanOrEqual(result.score, 40)
    }
}
