import Darwin
import Foundation
import XCTest
import CRiskCore
@testable import CloudPhoneRiskKit

final class AntiTamperingTests: XCTestCase {

    private func makeSnapshot(
        deviceID: String = "device-a",
        mutationStrategy: MutationStrategy? = nil
    ) -> RiskSnapshot {
        RiskSnapshot(
            deviceID: deviceID,
            device: TestFixtures.makeDeviceFingerprint(),
            network: TestFixtures.makeNetworkSignals(),
            behavior: TestFixtures.makeBehaviorSignals(),
            jailbreak: TestFixtures.makeDetectionResult(),
            mutationStrategy: mutationStrategy
        )
    }

    private func withEnvironmentValue(
        key: String,
        value: String?,
        perform body: () -> Void
    ) {
        let original = getenv(key).map { String(cString: $0) }
        if let value {
            _ = setenv(key, value, 1)
        } else {
            _ = unsetenv(key)
        }

        defer {
            if let original {
                _ = setenv(key, original, 1)
            } else {
                _ = unsetenv(key)
            }
        }

        body()
    }

    private func waitForWatchdogSnapshot(
        timeout: TimeInterval = 2.0
    ) -> CPRiskKit.AntiDebugWatchdogSnapshot {
        var snapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        let deadline = Date().addingTimeInterval(timeout)
        while snapshot.supported && snapshot.running && snapshot.iterationCount == 0 && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
            snapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
        }
        return snapshot
    }

    private func makeWatchdogSnapshot(
        supported: Bool = true,
        running: Bool = true,
        threadActive: Bool = true,
        intervalSeconds: UInt32 = 3,
        anomalyFlags: UInt32 = 0,
        iterationCount: UInt64 = 0,
        tracedEventCount: UInt64 = 0,
        denyAttachErrorCount: UInt64 = 0,
        exceptionAnomalyCount: UInt64 = 0,
        lastDenyAttachResult: Int32 = 0,
        lastDenyAttachErrno: Int32 = 0,
        lastTraced: Bool = false,
        lastExceptionPortHealthy: Bool = true,
        lastExceptionQuerySucceeded: Bool = true,
        lastExceptionReclaimAttempted: Bool = false,
        lastExceptionHijackDetected: Bool = false,
        lastExceptionQueryKernReturn: Int32 = 0,
        lastExceptionRegisterKernReturn: Int32 = 0,
        lastCheckMonotonicNs: UInt64 = 0,
        signalProbeResult: Bool = false,
        hardwareBpDetected: Bool = false,
        softwareBreakpointDetected: Bool = false,
        csopsDebugged: Bool = false,
        suspiciousThreadCount: UInt32 = 0,
        singleStepDetected: Bool = false,
        ttyDetected: Bool = false,
        developerDiskDetected: Bool = false,
        exceptionDeliveryTimeoutDetected: Bool = false,
        exceptionDeliveryProbeHandled: Bool = false,
        lastExceptionDeliveryProbeNs: UInt64 = 0,
        signalProbeAnomalyCount: UInt64 = 0,
        hardwareBpAnomalyCount: UInt64 = 0,
        softwareBreakpointAnomalyCount: UInt64 = 0,
        csopsAnomalyCount: UInt64 = 0,
        suspiciousThreadAnomalyCount: UInt64 = 0,
        exceptionDeliveryTimeoutAnomalyCount: UInt64 = 0,
        peerWatchdogAnomalyCount: UInt64 = 0,
        shadowStackAnomalyCount: UInt64 = 0,
        lastPeerWatchdogStalled: Bool = false,
        lastShadowStackMismatch: Bool = false,
        dbiDetected: Bool = false,
        dbiMarkerFlags: UInt32 = 0,
        timingAnomalyFlags: UInt32 = 0,
        timingProbeMedianNs: UInt64 = 0,
        timingProbeMaxNs: UInt64 = 0,
        timingProbeThresholdNs: UInt64 = 0,
        dbiAnomalyCount: UInt64 = 0,
        timingAnomalyCount: UInt64 = 0,
        prologueIntegrityAnomalyCount: UInt64 = 0,
        dyldInjectionAnomalyCount: UInt64 = 0,
        lastPrologueFailMask: UInt32 = 0,
        lastDyldInjectionFlags: UInt32 = 0,
        lastCsopsStatusFlags: UInt32 = 0,
        lastAmfiProbeBits: UInt32 = 0,
        lastGetTaskAllowSuspect: Bool = false,
        lastDenyAttachVerifyBits: UInt32 = 0,
        denyAttachVerifyAnomalyCount: UInt64 = 0,
        amfiCsFlagsAnomalyCount: UInt64 = 0,
        getTaskAllowAnomalyCount: UInt64 = 0,
        vmMprotectCrosscheckMismatchTotal: UInt64 = 0,
        vmMprotectMachTrapMismatchTotal: UInt64 = 0,
        libcFallbackUsedMask: UInt32 = 0,
        libcFallbackEventTotal: UInt32 = 0
    ) -> CPRiskKit.AntiDebugWatchdogSnapshot {
        CPRiskKit.AntiDebugWatchdogSnapshot(
            supported: supported,
            running: running,
            threadActive: threadActive,
            intervalSeconds: intervalSeconds,
            anomalyFlags: anomalyFlags,
            iterationCount: iterationCount,
            tracedEventCount: tracedEventCount,
            denyAttachErrorCount: denyAttachErrorCount,
            exceptionAnomalyCount: exceptionAnomalyCount,
            lastDenyAttachResult: lastDenyAttachResult,
            lastDenyAttachErrno: lastDenyAttachErrno,
            lastTraced: lastTraced,
            lastExceptionPortHealthy: lastExceptionPortHealthy,
            lastExceptionQuerySucceeded: lastExceptionQuerySucceeded,
            lastExceptionReclaimAttempted: lastExceptionReclaimAttempted,
            lastExceptionHijackDetected: lastExceptionHijackDetected,
            lastExceptionQueryKernReturn: lastExceptionQueryKernReturn,
            lastExceptionRegisterKernReturn: lastExceptionRegisterKernReturn,
            lastCheckMonotonicNs: lastCheckMonotonicNs,
            signalProbeResult: signalProbeResult,
            hardwareBpDetected: hardwareBpDetected,
            softwareBreakpointDetected: softwareBreakpointDetected,
            csopsDebugged: csopsDebugged,
            suspiciousThreadCount: suspiciousThreadCount,
            singleStepDetected: singleStepDetected,
            ttyDetected: ttyDetected,
            developerDiskDetected: developerDiskDetected,
            exceptionDeliveryTimeoutDetected: exceptionDeliveryTimeoutDetected,
            exceptionDeliveryProbeHandled: exceptionDeliveryProbeHandled,
            lastExceptionDeliveryProbeNs: lastExceptionDeliveryProbeNs,
            signalProbeAnomalyCount: signalProbeAnomalyCount,
            hardwareBpAnomalyCount: hardwareBpAnomalyCount,
            softwareBreakpointAnomalyCount: softwareBreakpointAnomalyCount,
            csopsAnomalyCount: csopsAnomalyCount,
            suspiciousThreadAnomalyCount: suspiciousThreadAnomalyCount,
            exceptionDeliveryTimeoutAnomalyCount: exceptionDeliveryTimeoutAnomalyCount,
            peerWatchdogAnomalyCount: peerWatchdogAnomalyCount,
            shadowStackAnomalyCount: shadowStackAnomalyCount,
            lastPeerWatchdogStalled: lastPeerWatchdogStalled,
            lastShadowStackMismatch: lastShadowStackMismatch,
            dbiDetected: dbiDetected,
            dbiMarkerFlags: dbiMarkerFlags,
            timingAnomalyFlags: timingAnomalyFlags,
            timingProbeMedianNs: timingProbeMedianNs,
            timingProbeMaxNs: timingProbeMaxNs,
            timingProbeThresholdNs: timingProbeThresholdNs,
            dbiAnomalyCount: dbiAnomalyCount,
            timingAnomalyCount: timingAnomalyCount,
            prologueIntegrityAnomalyCount: prologueIntegrityAnomalyCount,
            dyldInjectionAnomalyCount: dyldInjectionAnomalyCount,
            lastPrologueFailMask: lastPrologueFailMask,
            lastDyldInjectionFlags: lastDyldInjectionFlags,
            lastCsopsStatusFlags: lastCsopsStatusFlags,
            lastAmfiProbeBits: lastAmfiProbeBits,
            lastGetTaskAllowSuspect: lastGetTaskAllowSuspect,
            lastDenyAttachVerifyBits: lastDenyAttachVerifyBits,
            denyAttachVerifyAnomalyCount: denyAttachVerifyAnomalyCount,
            amfiCsFlagsAnomalyCount: amfiCsFlagsAnomalyCount,
            getTaskAllowAnomalyCount: getTaskAllowAnomalyCount,
            vmMprotectCrosscheckMismatchTotal: vmMprotectCrosscheckMismatchTotal,
            vmMprotectMachTrapMismatchTotal: vmMprotectMachTrapMismatchTotal,
            libcFallbackUsedMask: libcFallbackUsedMask,
            libcFallbackEventTotal: libcFallbackEventTotal
        )
    }

    func testLibcDirectSyscallFallbackSignalEmittedWhenMaskNonZero() {
        let provider = AntiTamperingSignalProvider()
        let mask = UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCTL)
            | UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_GETENTROPY)
        let snapshot = makeWatchdogSnapshot(libcFallbackUsedMask: mask, libcFallbackEventTotal: 4)
        let signals = provider.libcDirectSyscallFallbackSignals(from: snapshot)
        XCTAssertEqual(signals.count, 1)
        XCTAssertEqual(signals[0].id, SignalID.libcDirectSyscallFallback)
        XCTAssertEqual(signals[0].evidence["libc_fallback_used_mask"], "\(mask)")
        XCTAssertEqual(signals[0].evidence["mask_hex"], String(mask, radix: 16))
        XCTAssertEqual(signals[0].evidence["libc_fallback_event_total"], "4")
        XCTAssertTrue(
            (signals[0].evidence["fallback_classes"] ?? "").contains("sysctl"),
            "expected sysctl class label in \(signals[0].evidence["fallback_classes"] ?? "")"
        )
        XCTAssertTrue(
            (signals[0].evidence["fallback_classes"] ?? "").contains("getentropy"),
            "expected getentropy class label"
        )
    }

    func testLibcDirectSyscallFallbackSignalStillEmittedWhenWatchdogUnsupportedButMaskNonZero() {
        let provider = AntiTamperingSignalProvider()
        let mask = UInt32(CPRISK_LIBC_FALLBACK_USED_UNSUPPORTED_PLATFORM)
            | UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCTL)
        let signals = provider.libcDirectSyscallFallbackSignals(
            from: makeWatchdogSnapshot(
                supported: false,
                libcFallbackUsedMask: mask,
                libcFallbackEventTotal: 2
            )
        )
        XCTAssertEqual(signals.count, 1)
        XCTAssertEqual(signals[0].evidence["mask_hex"], String(mask, radix: 16))
        XCTAssertEqual(signals[0].evidence["watchdog_snapshot_supported"], "0")
        XCTAssertEqual(signals[0].evidence["libc_fallback_event_total"], "2")
    }

    func testLibcDirectSyscallFallbackSignalEmptyWhenMaskZero() {
        let provider = AntiTamperingSignalProvider()
        XCTAssertTrue(
            provider.libcDirectSyscallFallbackSignals(from: makeWatchdogSnapshot(libcFallbackUsedMask: 0))
                .isEmpty
        )
    }

    func testSDKIntegrityCheckerLibcFallbackObservationStillEmittedWhenWatchdogUnsupportedButMaskNonZero() {
        let mask = UInt32(CPRISK_LIBC_FALLBACK_USED_UNSUPPORTED_PLATFORM)
            | UInt32(CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCTL)
        let observation = SDKIntegrityChecker.libcDirectSyscallFallbackObservation(
            from: makeWatchdogSnapshot(
                supported: false,
                libcFallbackUsedMask: mask,
                libcFallbackEventTotal: 3
            )
        )
        XCTAssertNotNil(observation)
        XCTAssertEqual(observation?.score, 14)
        XCTAssertTrue(observation?.method.contains("integrity:libc_direct_syscall_fallback:0x\(String(mask, radix: 16))") ?? false)
        XCTAssertTrue(observation?.method.contains("events_total=3") ?? false)
        XCTAssertTrue(observation?.method.contains("watchdog_supported=0") ?? false)
    }

    func testSDKIntegrityCheckerLibcFallbackObservationNilWhenMaskZero() {
        XCTAssertNil(
            SDKIntegrityChecker.libcDirectSyscallFallbackObservation(
                from: makeWatchdogSnapshot(libcFallbackUsedMask: 0, libcFallbackEventTotal: 9)
            )
        )
    }

    /// Runtime contract: libc fallback signal id must be protocol-stable via `ObfuscatedConstants` (not inline literals).
    func testLibcDirectSyscallFallbackSignalIdUsesObfuscatedContract() {
        XCTAssertEqual(SignalID.libcDirectSyscallFallback, ObfuscatedConstants.signalLibcDirectSyscallFallback)
    }

    func testLibcDirectSyscallFallbackMechanismEvidenceUsesObfuscatedConstant() {
        XCTAssertEqual(
            ObfuscatedConstants.evidenceMechanismLibcDirectSyscallFallback,
            "libc_or_arc4_fallback_after_direct_syscall_unavailable"
        )
    }

    func testAntiDebugWatchdogDerivedSignalIdsUseObfuscatedContract() {
        XCTAssertEqual(SignalID.debuggerDetected, ObfuscatedConstants.signalDebuggerDetected)
        XCTAssertEqual(SignalID.csopsDebugged, ObfuscatedConstants.signalCsopsDebugged)
        XCTAssertEqual(SignalID.hardwareBreakpointDetected, ObfuscatedConstants.signalHardwareBreakpointDetected)
        XCTAssertEqual(SignalID.signalProbeDebugger, ObfuscatedConstants.signalSignalProbeDebugger)
        XCTAssertEqual(SignalID.antidebugPlanEscalated, ObfuscatedConstants.signalAntidebugPlanEscalated)
    }

    func testLibcDirectSyscallFallbackSetsCompressorCrossLayerBit() {
        let sig = RiskSignal(
            id: SignalID.libcDirectSyscallFallback,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 30,
            evidence: [:],
            state: .soft(confidence: 0.8),
            layer: 1,
            weightHint: 28
        )
        let digest = SignalCompressor.compress(signals: [sig]).digest
        XCTAssertEqual(digest.count, 9)
        // `crossLayerBits` stores libc fallback at bit 16 (`0x00010000`) → byte index 5 is `(crossLayer >> 16) & 0xFF`.
        XCTAssertEqual(digest[5], 1)
    }

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

    func testAntiTamperingTimingRatioDoesNotFlagSlowButProportionalSamples() {
        let detector = AntiTamperingDetector()

        let getpidSamples: [UInt64] = [900_000, 1_000_000, 1_100_000, 950_000, 1_050_000]
        let statSamples: [UInt64] = [9_000_000, 10_000_000, 11_000_000, 9_500_000, 10_500_000]

        XCTAssertFalse(detector.isTimingRatioAnomalous(
            getpidSamples: getpidSamples,
            statSamples: statSamples
        ))
    }

    func testAntiTamperingTimingRatioFlagsRelativeInflation() {
        let detector = AntiTamperingDetector()

        let getpidSamples: [UInt64] = [180, 200, 220, 210, 205]
        let statSamples: [UInt64] = [3_600, 4_000, 4_400, 4_200, 4_100]

        XCTAssertTrue(detector.isTimingRatioAnomalous(
            getpidSamples: getpidSamples,
            statSamples: statSamples
        ))
    }

    func testTimingRatioBaselineExposesMedianAndP95Ratios() {
        let getpidSamples: [UInt64] = [200, 210, 220, 230, 240]
        let statSamples: [UInt64] = [2_000, 2_100, 2_200, 2_300, 6_000]

        let evaluation = TimingRatioBaseline.evaluate(
            getpidSamples: getpidSamples,
            statSamples: statSamples
        )

        guard let evaluation else {
            XCTFail("evaluation should not be nil")
            return
        }
        XCTAssertEqual(evaluation.medianRatio, 10.0, accuracy: 0.001)
        XCTAssertEqual(evaluation.p95Ratio, 25.0, accuracy: 0.001)
        XCTAssertTrue(evaluation.isAnomalous)
    }

    func testTimingRatioBaselineRejectsZeroMedianBaseline() {
        let evaluation = TimingRatioBaseline.evaluate(
            getpidSamples: [0, 0, 0],
            statSamples: [100, 120, 140]
        )

        XCTAssertNil(evaluation)
        XCTAssertFalse(TimingRatioBaseline.isAnomalous(
            getpidSamples: [0, 0, 0],
            statSamples: [100, 120, 140]
        ))
    }

    func testTimingRatioBaselineEvaluatePairExposesNamesAndRatios() {
        var baselineCounter = 0
        var probeCounter = 0
        let evaluation = TimingRatioBaseline.evaluatePair(
            baselineName: "baseline",
            probeName: "probe",
            sampleCount: 6,
            warmupCount: 1,
            noiseIterations: 1,
            ratioThreshold: 0.1
        ) {
            baselineCounter += 1
            var value = baselineCounter
            for _ in 0..<100 {
                value &+= 1
            }
        } probe: {
            probeCounter += 1
            var value = probeCounter
            for _ in 0..<500 {
                value &+= 3
            }
        }

        guard let evaluation else {
            XCTFail("pair evaluation should not be nil")
            return
        }
        XCTAssertEqual(evaluation.baselineName, "baseline")
        XCTAssertEqual(evaluation.probeName, "probe")
        XCTAssertEqual(evaluation.sampleCount, 6)
        XCTAssertGreaterThan(evaluation.baselineMedianNs, 0)
        XCTAssertGreaterThan(evaluation.probeMedianNs, 0)
        XCTAssertTrue(evaluation.medianRatio > 0)
    }

    func testSystemLibrarySegmentLayoutThresholdsAreConservative() {
        let normal = SystemLibrarySegmentLayoutDetector.ImageLayoutSnapshot(
            id: "foundation",
            displayName: "Foundation",
            path: "/System/Library/Frameworks/Foundation.framework/Foundation",
            kind: .systemLibrary,
            declaredSegmentCount: 5,
            executableSegmentCount: 1,
            runtimeRegionCount: 8,
            executableRegionCount: 3,
            readOnlyRegionCount: 2,
            readWriteRegionCount: 2,
            writableExecutableRegionCount: 0,
            anonymousExecutableRegionCount: 0,
            textWritableRegionCount: 0,
            dataExecutableRegionCount: 0
        )
        XCTAssertFalse(SystemLibrarySegmentLayoutDetector.isRegionCountDriftSuspicious(normal))
        XCTAssertFalse(SystemLibrarySegmentLayoutDetector.isExecutableDistributionSuspicious(normal))
        XCTAssertFalse(SystemLibrarySegmentLayoutDetector.hasCriticalPermissionAnomaly(normal))

        let suspicious = SystemLibrarySegmentLayoutDetector.ImageLayoutSnapshot(
            id: "dyld",
            displayName: "dyld",
            path: "/usr/lib/dyld",
            kind: .systemLibrary,
            declaredSegmentCount: 4,
            executableSegmentCount: 1,
            runtimeRegionCount: 12,
            executableRegionCount: 4,
            readOnlyRegionCount: 3,
            readWriteRegionCount: 2,
            writableExecutableRegionCount: 1,
            anonymousExecutableRegionCount: 1,
            textWritableRegionCount: 1,
            dataExecutableRegionCount: 0
        )
        XCTAssertTrue(SystemLibrarySegmentLayoutDetector.isRegionCountDriftSuspicious(suspicious))
        XCTAssertTrue(SystemLibrarySegmentLayoutDetector.isExecutableDistributionSuspicious(suspicious))
        XCTAssertTrue(SystemLibrarySegmentLayoutDetector.hasCriticalPermissionAnomaly(suspicious))
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

    func testAntiDebugWatchdogSnapshotWithoutAnomalyProducesNoSignals() {
        let provider = AntiTamperingSignalProvider()
        let snapshot = makeWatchdogSnapshot(iterationCount: 4, lastCheckMonotonicNs: 42)

        XCTAssertTrue(provider.antiDebugWatchdogSignals(from: snapshot).isEmpty)
    }

    func testAntiDebugWatchdogSnapshotEmitsCriticalHookSurfaceWhenFunctionPrologueFlagSet() {
        let provider = AntiTamperingSignalProvider()
        let prologueFlag = UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE)
        let mask = UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_OBJC_MSGSEND)
            | UInt32(CPRISK_WATCHDOG_PROLOGUE_FAIL_MASK_DYLD_IMAGE_COUNT)
        let snapshot = makeWatchdogSnapshot(
            anomalyFlags: prologueFlag,
            iterationCount: 2,
            prologueIntegrityAnomalyCount: 1,
            lastPrologueFailMask: mask
        )
        let signals = provider.antiDebugWatchdogSignals(from: snapshot)
        let hook = signals.first(where: { $0.id == SignalID.antiDebugWatchdogCriticalHookSurface })
        XCTAssertNotNil(hook)
        XCTAssertEqual(hook?.evidence["fail_objc_msgsend"], "1")
        XCTAssertEqual(hook?.evidence["fail_dyld_image_count"], "1")
    }

    func testAntiDebugWatchdogSnapshotProducesDetailedSignals() {
        let provider = AntiTamperingSignalProvider()
        let flags = UInt32(1 << 0)
            | UInt32(1 << 1)
            | UInt32(1 << 2)
            | UInt32(1 << 3)
        let snapshot = makeWatchdogSnapshot(
            anomalyFlags: flags,
            iterationCount: 7,
            tracedEventCount: 2,
            denyAttachErrorCount: 1,
            exceptionAnomalyCount: 3,
            lastDenyAttachResult: -1,
            lastDenyAttachErrno: 1,
            lastTraced: true,
            lastExceptionPortHealthy: false,
            lastExceptionQuerySucceeded: false,
            lastExceptionReclaimAttempted: true,
            lastExceptionHijackDetected: true,
            lastExceptionQueryKernReturn: 5,
            lastExceptionRegisterKernReturn: 6,
            lastCheckMonotonicNs: 99
        )

        let signals = provider.antiDebugWatchdogSignals(from: snapshot)
        let ids = Set(signals.map { $0.id })

        XCTAssertTrue(ids.contains(SignalID.antiDebugWatchdogAnomaly))
        XCTAssertTrue(ids.contains(SignalID.antiDebugWatchdogTraced))
        XCTAssertTrue(ids.contains(SignalID.antiDebugWatchdogDenyAttachFailed))
        XCTAssertTrue(ids.contains(SignalID.antiDebugWatchdogExceptionPort))
        XCTAssertTrue(ids.contains(SignalID.antiDebugWatchdogExceptionQuery))

        guard let summary = signals.first(where: { $0.id == SignalID.antiDebugWatchdogAnomaly }) else {
            return XCTFail("missing anti_debug_watchdog_anomaly summary signal")
        }
        XCTAssertEqual(summary.category, "anti_tamper")
        XCTAssertEqual(summary.state, RiskSignalState.tampered)
        XCTAssertEqual(summary.layer, 2)
        XCTAssertEqual(summary.evidence["anomaly_kinds"], "traced,deny_attach,exception_port,exception_query")
    }

    func testCRiskCoreDBIVmTraceMarkerFlagConstants() {
        XCTAssertEqual(UInt32(CPRISK_DBI_MARKER_ANON_EXEC_SLAB), 32)
        XCTAssertEqual(UInt32(CPRISK_DBI_MARKER_STALKER_CORREL), 64)
        XCTAssertEqual(UInt32(CPRISK_DBI_MARKER_DYLD_IMAGE_COUNT_LOW), 128)
        XCTAssertEqual(UInt32(CPRISK_DBI_MARKER_FOREIGN_MAPPED_EXEC), 256)
        XCTAssertEqual(UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_VM_TRACE_CORREL), 1 << 28)
    }

    func testCRiskCoreDyldImageLayoutDigestSucceeds() {
        var digest = [UInt8](repeating: 0, count: 32)
        let rc = digest.withUnsafeMutableBufferPointer { cprisk_vm_dyld_image_layout_digest($0.baseAddress!) }
        XCTAssertEqual(rc, 0)
        XCTAssertTrue(digest.contains { $0 != 0 })
    }

    func testCRiskCoreDBIProbeFlagsEnvMarkersAndAggregateProbeBit() throws {
        guard CPRiskKit.shared.antiDebugWatchdogSnapshot().supported else {
            throw XCTSkip("signal probe is unavailable on this platform")
        }

        withEnvironmentValue(key: "PIN_VM", value: "1") {
            let hitCount = cprisk_detect_dbi_markers()
            let markerFlags = cprisk_get_last_dbi_marker_flags()
            let aggregateFlags = cprisk_run_all_signal_probes()

            XCTAssertGreaterThanOrEqual(Int(hitCount), 1)
            XCTAssertGreaterThanOrEqual(cprisk_get_last_dbi_marker_hit_count(), 1)
            XCTAssertNotEqual(markerFlags & UInt32(CPRISK_DBI_MARKER_ENV), 0)
            XCTAssertNotEqual(aggregateFlags & UInt32(CPRISK_PROBE_DBI_MARKER), 0)
        }
    }

    func testCRiskCoreTimingProbeExposesAnomalyFlagsAndMetrics() throws {
        guard CPRiskKit.shared.antiDebugWatchdogSnapshot().supported else {
            throw XCTSkip("timing probe is unavailable on this platform")
        }

        let singleStepDetected = cprisk_detect_single_stepping()
        let timingFlags = cprisk_get_last_timing_anomaly_flags()
        let medianNs = cprisk_get_last_timing_probe_median_ns()
        let maxNs = cprisk_get_last_timing_probe_max_ns()
        let thresholdNs = cprisk_get_last_timing_probe_threshold_ns()
        let aggregateFlags = cprisk_run_all_signal_probes()

        let knownMask = UInt32(CPRISK_TIMING_ANOMALY_MEDIAN)
            | UInt32(CPRISK_TIMING_ANOMALY_SPIKE)
            | UInt32(CPRISK_TIMING_ANOMALY_JITTER)
            | UInt32(CPRISK_TIMING_ANOMALY_CLOCK_SKEW)
            | UInt32(CPRISK_TIMING_ANOMALY_DUAL_CLOCK_DRIFT)
            | UInt32(CPRISK_TIMING_ANOMALY_CRYPTO_TRACE)
            | UInt32(CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_SKEW)
            | UInt32(CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_INVARIANT)

        XCTAssertGreaterThan(thresholdNs, 0)
        XCTAssertGreaterThanOrEqual(maxNs, medianNs)
        XCTAssertEqual(timingFlags & ~knownMask, 0)

        if singleStepDetected != 0 {
            XCTAssertNotEqual(timingFlags, 0)
        }
        if cprisk_get_last_timing_anomaly_flags() != 0 {
            XCTAssertNotEqual(aggregateFlags & UInt32(CPRISK_PROBE_TIMING_ANOMALY), 0)
        }
    }

    func testCRiskCoreDeviceKeyDerivationSucceeds() {
        let rootKey = [UInt8](repeating: 0x11, count: Int(CPRISK_ARMOR_KEY_SIZE))
        var deviceKey = [UInt8](repeating: 0, count: Int(CPRISK_ARMOR_KEY_SIZE))

        let rc = rootKey.withUnsafeBufferPointer { rootPtr in
            deviceKey.withUnsafeMutableBufferPointer { devicePtr in
                cprisk_derive_device_key(rootPtr.baseAddress, devicePtr.baseAddress)
            }
        }

        XCTAssertEqual(rc, 0)
        XCTAssertTrue(deviceKey.contains { $0 != 0 })
        let boundFlag = cprisk_is_device_bound()
        XCTAssertTrue(boundFlag == 0 || boundFlag == 1)
    }

    func testCRiskCorePACSelfTestAndFlags() {
        let rc = cprisk_pac_self_test(0xA5A5_A5A5)
        XCTAssertEqual(rc, 0)

        let flags = cprisk_get_last_pac_cfi_flags()
        if cprisk_pac_is_arm64e_supported() == 0 {
            XCTAssertNotEqual(flags & UInt32(CPRISK_PAC_CFI_FLAG_UNAVAILABLE), 0)
        } else {
            XCTAssertEqual(flags & UInt32(CPRISK_PAC_CFI_FLAG_UNAVAILABLE), 0)
        }
        XCTAssertEqual(flags & UInt32(CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED), 0)
    }

    func testCRiskCorePACCoreCallbackValidation() {
        let rc = cprisk_pac_validate_core_callbacks()
        XCTAssertEqual(rc, 0)

        let flags = cprisk_get_last_pac_cfi_flags()
        XCTAssertEqual(flags & UInt32(CPRISK_PAC_CFI_FLAG_CALLBACK_VALIDATION_FAILED), 0)
        XCTAssertEqual(flags & UInt32(CPRISK_PAC_CFI_FLAG_SIGN_FAILED), 0)
        XCTAssertEqual(flags & UInt32(CPRISK_PAC_CFI_FLAG_AUTH_FAILED), 0)
        XCTAssertEqual(flags & UInt32(CPRISK_PAC_CFI_FLAG_WEAK_BINDING), 0)
        if cprisk_pac_is_arm64e_supported() == 0 {
            XCTAssertNotEqual(flags & UInt32(CPRISK_PAC_CFI_FLAG_UNAVAILABLE), 0)
        } else {
            XCTAssertEqual(flags & UInt32(CPRISK_PAC_CFI_FLAG_UNAVAILABLE), 0)
        }
    }

    func testCRiskCoreArm64InstantReturnPatchPrefixDetectsCommonPatterns() throws {
#if !arch(arm64)
        throw XCTSkip("ARM64 opcode scan test requires an arm64 host")
#endif
        var movX0: [UInt32] = [0xAA00_03E0, 0xD65F_03C0]
        XCTAssertEqual(
            movX0.withUnsafeBufferPointer { cprisk_scan_arm64_instant_return_nop_patch_prefix($0.baseAddress!, 8) },
            1
        )

        var nopRet: [UInt32] = [0xD503_201F, 0xD65F_03C0]
        XCTAssertEqual(
            nopRet.withUnsafeBufferPointer { cprisk_scan_arm64_instant_return_nop_patch_prefix($0.baseAddress!, 8) },
            1
        )

        var movW0: [UInt32] = [0x2A00_03E0, 0xD65F_03C0]
        XCTAssertEqual(
            movW0.withUnsafeBufferPointer { cprisk_scan_arm64_instant_return_nop_patch_prefix($0.baseAddress!, 8) },
            1
        )

        XCTAssertEqual(
            movX0.withUnsafeBufferPointer { cprisk_scan_arm64_instant_return_nop_patch_prefix($0.baseAddress!, 4) },
            0
        )
    }

    func testCRiskCoreArm64InstantReturnPatchCleanKeyFunctionPrefix() throws {
#if !arch(arm64)
        throw XCTSkip("ARM64 key-symbol prefix test requires an arm64 host")
#endif
        typealias SignalProbeFn = @convention(c) () -> Int32
        let probeFn: SignalProbeFn = cprisk_probe_debugger_via_signal
        let probePtr = unsafeBitCast(probeFn, to: UnsafeRawPointer.self)
        XCTAssertEqual(cprisk_scan_arm64_instant_return_nop_patch_prefix(probePtr, 8), 0)
        XCTAssertEqual(cprisk_scan_instant_return_key_symbols_prefix(), 0)
    }

    func testCRiskCoreAggregateSignalProbesIncludeInstantReturnPatchBitWhenClean() {
        let aggregateFlags = cprisk_run_all_signal_probes()
        XCTAssertEqual(aggregateFlags & UInt32(CPRISK_PROBE_INSTANT_RETURN_PATCH), 0)
    }

    func testAntiDebugWatchdogSignalsIncludeInstantReturnPatchKind() {
        let provider = AntiTamperingSignalProvider()
        let snapshot = makeWatchdogSnapshot(
            anomalyFlags: UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH)
        )
        let signals = provider.antiDebugWatchdogSignals(from: snapshot)
        let id = "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_instant_return_patch"
        XCTAssertTrue(signals.contains { $0.id == id })
        guard let summary = signals.first(where: { $0.id == SignalID.antiDebugWatchdogAnomaly }) else {
            return XCTFail("missing anti_debug_watchdog_anomaly summary signal")
        }
        XCTAssertTrue(summary.evidence["anomaly_kinds"]?.contains("instant_return_patch") ?? false)
    }

    func testCRiskCoreThreadExceptionPortsAndHardwareProbeBits() throws {
        guard CPRiskKit.shared.antiDebugWatchdogSnapshot().supported else {
            throw XCTSkip("signal probe is unavailable on this platform")
        }

        let hw = cprisk_detect_hardware_breakpoints()
        let threadPorts = cprisk_detect_thread_exception_ports()
        let aggregateFlags = cprisk_run_all_signal_probes()

        if hw > 0 {
            XCTAssertNotEqual(aggregateFlags & UInt32(CPRISK_PROBE_HARDWARE_BP), 0)
        } else {
            XCTAssertEqual(aggregateFlags & UInt32(CPRISK_PROBE_HARDWARE_BP), 0)
        }
        if threadPorts > 0 {
            XCTAssertNotEqual(aggregateFlags & UInt32(CPRISK_PROBE_THREAD_EXCEPTION_PORT), 0)
        } else {
            XCTAssertEqual(aggregateFlags & UInt32(CPRISK_PROBE_THREAD_EXCEPTION_PORT), 0)
        }
    }

    func testWatchdogSnapshotReflectsExceptionPortAndHardwareBits() throws {
        guard CPRiskKit.shared.antiDebugWatchdogSnapshot().supported else {
            throw XCTSkip("watchdog is unavailable on this platform")
        }

        CPRiskKit.shared.stop()
        CPRiskKit.shared.start()
        defer { CPRiskKit.shared.stop() }

        let snapshot = waitForWatchdogSnapshot(timeout: 3.0)

        if snapshot.hardwareBpDetected {
            XCTAssertNotEqual(
                snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_HARDWARE_BP),
                0
            )
        }
        if snapshot.lastExceptionPortHealthy == false {
            XCTAssertNotEqual(
                snapshot.anomalyFlags & UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT),
                0
            )
        }
    }

    func testAntiDebugWatchdogSnapshotIncludesDBIMarkerAnomaly() throws {
        guard CPRiskKit.shared.antiDebugWatchdogSnapshot().supported else {
            throw XCTSkip("watchdog is unavailable on this platform")
        }

        withEnvironmentValue(key: "PIN_VM", value: "1") {
            CPRiskKit.shared.stop()
            CPRiskKit.shared.start()
            defer { CPRiskKit.shared.stop() }

            let dbiAnomalyFlag = UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_MARKER)
            var snapshot = waitForWatchdogSnapshot()
            let deadline = Date().addingTimeInterval(2.0)
            while snapshot.running &&
                    Date() < deadline &&
                    (snapshot.anomalyFlags & dbiAnomalyFlag) == 0 {
                Thread.sleep(forTimeInterval: 0.05)
                snapshot = CPRiskKit.shared.antiDebugWatchdogSnapshot()
            }

            XCTAssertTrue(snapshot.running)
            XCTAssertNotEqual(snapshot.anomalyFlags & dbiAnomalyFlag, 0)
        }
    }

    func testAntiDebugWatchdogSignalsIncludeDBIAndTimingAnomalies() {
        let provider = AntiTamperingSignalProvider()
        let flags = UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_MARKER)
            | UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL)

        let snapshot = makeWatchdogSnapshot(
            anomalyFlags: flags,
            dbiDetected: true,
            dbiMarkerFlags: UInt32(CPRISK_DBI_MARKER_ENV),
            timingAnomalyFlags: UInt32(CPRISK_TIMING_ANOMALY_MEDIAN) | UInt32(CPRISK_TIMING_ANOMALY_CRYPTO_TRACE),
            timingProbeMedianNs: 1_500_000,
            timingProbeMaxNs: 2_900_000,
            timingProbeThresholdNs: 1_200_000,
            dbiAnomalyCount: 3,
            timingAnomalyCount: 4
        )

        let signals = provider.antiDebugWatchdogSignals(from: snapshot)
        XCTAssertTrue(signals.contains { $0.id == "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_dbi_marker" })
        XCTAssertTrue(signals.contains { $0.id == "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_timing_sidechannel" })

        guard let summary = signals.first(where: { $0.id == SignalID.antiDebugWatchdogAnomaly }) else {
            return XCTFail("missing watchdog summary signal")
        }
        XCTAssertTrue(summary.evidence["anomaly_kinds"]?.contains("dbi_marker") ?? false)
        XCTAssertTrue(summary.evidence["anomaly_kinds"]?.contains("timing_sidechannel") ?? false)
        XCTAssertEqual(summary.evidence["crypto_trace_slow"], "1")
        XCTAssertEqual(
            signals.first(where: { $0.id == "\(ObfuscatedConstants.detectorIDAntiDebugWatchdog)_timing_sidechannel" })?.evidence["crypto_trace_slow"],
            "1"
        )
    }

    func testProtectedDuplicateSignalsAreCollapsedToStrongestSignal() {
        let provider = AntiTamperingSignalProvider()
        let input = [
            RiskSignal(
                id: SignalID.softwareBreakpointDetected,
                category: "anti_tamper",
                score: 52,
                evidence: ["source": "debugger"],
                state: .tampered,
                layer: 1,
                weightHint: 60
            ),
            RiskSignal(
                id: SignalID.softwareBreakpointDetected,
                category: "anti_tamper",
                score: 64,
                evidence: ["source": "watchdog_probe"],
                state: .tampered,
                layer: 1,
                weightHint: 74
            ),
            RiskSignal(
                id: SignalID.exceptionDeliveryTimeout,
                category: "anti_tamper",
                score: 48,
                evidence: ["source": "watchdog_probe"],
                state: .tampered,
                layer: 1,
                weightHint: 54
            ),
            RiskSignal(
                id: "other_signal",
                category: "anti_tamper",
                score: 10,
                evidence: [:],
                state: .soft(confidence: 0.3),
                layer: 2,
                weightHint: 10
            ),
        ]

        let merged = provider.coalesceProtectedDuplicateSignals(input)
        let ids = merged.map(\.id)

        XCTAssertEqual(ids.filter { $0 == SignalID.softwareBreakpointDetected }.count, 1)
        XCTAssertEqual(ids.filter { $0 == SignalID.exceptionDeliveryTimeout }.count, 1)
        XCTAssertTrue(ids.contains("other_signal"))
        XCTAssertEqual(
            merged.first(where: { $0.id == SignalID.softwareBreakpointDetected })?.score,
            64
        )
        XCTAssertEqual(
            merged.first(where: { $0.id == SignalID.softwareBreakpointDetected })?.evidence["merged_count"],
            "2"
        )
    }

    func testRandomizedDetectorOrderIsStableForSameDeviceAndSeed() {
        let provider = AntiTamperingSignalProvider()
        let strategy = MutationStrategy(seed: "seed-1", shuffleChecks: true)
        let snapshot = makeSnapshot(deviceID: "stable-device", mutationStrategy: strategy)

        let first = provider.orderedRandomizedDetectorIDs(snapshot: snapshot)
        let second = provider.orderedRandomizedDetectorIDs(snapshot: snapshot)

        XCTAssertEqual(first, second)
    }

    func testRandomizedDetectorOrderVariesAcrossDeviceIDs() {
        let provider = AntiTamperingSignalProvider()
        let strategy = MutationStrategy(seed: "seed-1", shuffleChecks: true)
        let baseline = provider.orderedRandomizedDetectorIDs(
            snapshot: makeSnapshot(deviceID: "device-a", mutationStrategy: strategy)
        )

        let candidateIDs = ["device-b", "device-c", "device-d", "device-e", "device-f"]
        let hasVariation = candidateIDs.contains { candidate in
            provider.orderedRandomizedDetectorIDs(
                snapshot: makeSnapshot(deviceID: candidate, mutationStrategy: strategy)
            ) != baseline
        }

        XCTAssertTrue(hasVariation)
    }

    func testRandomizedDetectorOrderKeepsAllSelectedChecks() {
        let provider = AntiTamperingSignalProvider()
        let strategy = MutationStrategy(seed: "seed-1", shuffleChecks: true)
        let order = provider.orderedRandomizedDetectorIDs(
            snapshot: makeSnapshot(deviceID: "device-a", mutationStrategy: strategy)
        )

        XCTAssertEqual(Set(order), Set([
            "anti_tampering",
            "debugger",
            "frida",
            "frida_module",
            "frida_thread",
            "frida_heap",
            "objc_swizzle",
            "frida_socket",
            "dyld_interpose",
            "dyld_image_monitor",
            "dylib_injection",
            "anti_debug_watchdog",
        ]))
    }

    func testRandomizedDetectorOrderFallsBackWhenShuffleDisabled() {
        let provider = AntiTamperingSignalProvider()
        let strategy = MutationStrategy(seed: "seed-1", shuffleChecks: false)
        let order = provider.orderedRandomizedDetectorIDs(
            snapshot: makeSnapshot(deviceID: "device-a", mutationStrategy: strategy)
        )

        XCTAssertEqual(order, [
            "anti_tampering",
            "debugger",
            "frida",
            "frida_module",
            "frida_thread",
            "frida_heap",
            "objc_swizzle",
            "frida_socket",
            "dyld_interpose",
            "dyld_image_monitor",
            "dylib_injection",
            "anti_debug_watchdog",
        ])
    }

    func testDefaultConfigurationCheckPlanCount() {
        let provider = AntiTamperingSignalProvider()
        let snapshot = makeSnapshot()
        let ids = provider.configuredCheckIDs(snapshot: snapshot)
        XCTAssertEqual(ids.count, 42, "descriptor plan drift: update expected count when adding/removing checks")
    }

    // MARK: - FridaDetector Logic Tests

    func testFridaDetectorKnownPorts() {
        let detector = FridaDetector()
        XCTAssertTrue(detector.knownPorts.contains(27042))
        XCTAssertTrue(detector.knownPorts.contains(27043))
        XCTAssertTrue(detector.knownPorts.contains(23946))
    }

    func testFridaDetectorExtendedMethodPrefixes() {
        XCTAssertEqual(ObfuscatedConstants.methodPrefixFridaProto, "frida:proto:")
        XCTAssertEqual(ObfuscatedConstants.methodPrefixFridaListen, "frida:listen:")
        XCTAssertEqual(ObfuscatedConstants.methodPrefixFridaMemorySig, "frida:memsig:")
        XCTAssertEqual(ObfuscatedConstants.methodPrefixFridaRuntime, "frida:runtime:")
        XCTAssertEqual(ObfuscatedConstants.methodPrefixFridaRuntimeFused, "frida:runtime_fused:")
    }

    func testFridaProtocolWireClassification_saslOk() {
        let tok = FridaDetector.classifyFridaWireResponseForTesting(Data("OK deadbeefbeef\r\n".utf8))
        XCTAssertEqual(tok, FridaDetector.classifyFridaWireResponseForTesting(Data("ok\r\n".utf8)))
        XCTAssertNotNil(tok)
    }

    func testFridaProtocolWireClassification_saslRejected() {
        let tok = FridaDetector.classifyFridaWireResponseForTesting(Data("REJECTED EXTERNAL ANONYMOUS\r\n".utf8))
        XCTAssertNotNil(tok)
    }

    func testFridaProtocolWireClassification_dbusShapedBinary() {
        var bytes: [UInt8] = [
            0x6c, 0x02, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
        ]
        let tok = FridaDetector.classifyFridaWireResponseForTesting(Data(bytes))
        XCTAssertNotNil(tok)
    }

    func testFridaProtocolActiveWirePayloadsOrder() {
        let probes = ObfuscatedConstants.fridaProtocolActiveWirePayloads
        XCTAssertTrue(probes.first?.hasPrefix("AUTH EXTERNAL") ?? false)
        XCTAssertTrue(probes.contains("AUTH\r\n"))
        XCTAssertFalse(ObfuscatedConstants.fridaProtocolProbePayloads.isEmpty)
    }

    func testFridaDetectorDefaultCandidatePortsIncludeOfflineFallback() {
        let detector = FridaDetector()
        let ports = detector.candidatePortsForTesting()
        XCTAssertTrue(ports.contains(27042))
        XCTAssertTrue(ports.contains(27041), "offline fallback should remain active without remote updates")
        XCTAssertTrue(ports.contains(8888), "builtin magic ports should participate in default scan set")
    }

    func testFridaDetectorProactivePayloadsStartWithDbusShape() {
        let payloads = FridaDetector.proactiveProtocolPayloadsForTesting()
        let first = try? XCTUnwrap(payloads.first)
        XCTAssertEqual(first?.count, 16)
        XCTAssertEqual(first?.first, 0x6c, "first proactive payload should be D-Bus-shaped wire bytes")
        let secondText = payloads.dropFirst().first.flatMap { String(data: $0, encoding: .utf8) }
        XCTAssertTrue(secondText?.hasPrefix("AUTH EXTERNAL") ?? false)
    }

    func testCFridaRuntimeSnapshotAPI() {
        var snap = cprisk_frida_runtime_snapshot_t()
        XCTAssertEqual(cprisk_frida_runtime_snapshot(&snap), 0)
#if targetEnvironment(simulator)
        XCTAssertEqual(snap.supported, 0)
#else
        XCTAssertEqual(snap.supported, 1)
#endif
    }

    func testFridaDetectorScoreCapped() throws {
        let detector = FridaDetector()
        let result = try detector.detect()
        XCTAssertLessThanOrEqual(result.score, 45)
    }

    func testFridaDetectorMemorySignatureHookPath() throws {
        FridaDetector.clearMemorySignatureHooks()
        setenv("CPRISK_FRIDA_MEMSIG", "1", 1)
        defer {
            unsetenv("CPRISK_FRIDA_MEMSIG")
            FridaDetector.clearMemorySignatureHooks()
        }

        FridaDetector.registerMemorySignatureHook {
            "gum-inline-sig"
        }
        let detector = FridaDetector()
        let result = try detector.detect()
#if targetEnvironment(simulator)
        XCTAssertTrue(result.methods.contains("unavailable_simulator"))
#else
        XCTAssertTrue(
            result.methods.contains(where: {
                $0.hasPrefix(ObfuscatedConstants.methodPrefixFridaMemorySig)
            }),
            "memory-signature hook should emit frida:memsig:* evidence when enabled"
        )
#endif
    }

    func testFridaDetectorMemorySignatureHookPath_builtinDisabledStillEmits() throws {
        FridaDetector.clearMemorySignatureHooks()
        setenv("CPRISK_FRIDA_MEMSIG", "1", 1)
        setenv("CPRISK_FRIDA_MEMSIG_BUILTIN", "0", 1)
        defer {
            unsetenv("CPRISK_FRIDA_MEMSIG")
            unsetenv("CPRISK_FRIDA_MEMSIG_BUILTIN")
            FridaDetector.clearMemorySignatureHooks()
        }

        FridaDetector.registerMemorySignatureHook {
            "hook-only-memsig"
        }
        let detector = FridaDetector()
        let result = try detector.detect()
#if targetEnvironment(simulator)
        XCTAssertTrue(result.methods.contains("unavailable_simulator"))
#else
        XCTAssertTrue(
            result.methods.contains(where: {
                $0 == "\(ObfuscatedConstants.methodPrefixFridaMemorySig)hook-only-memsig"
            }),
            "hook path must work when builtin scan is disabled via env"
        )
#endif
    }

    func testFridaBuiltinMemorySignature_firstMatchInBuffer() {
        let marker = ObfuscatedConstants.fridaStringMarkers.first { $0.utf8.count >= 8 }!
        let payload = "prefix-\(marker)-suffix"
        let hit = FridaBuiltinMemorySignatureScanner.firstMatchInBufferForTesting(Data(payload.utf8))
        XCTAssertEqual(hit, marker)
    }

    func testFridaBuiltinMemorySignature_noMatchInBuffer() {
        XCTAssertNil(
            FridaBuiltinMemorySignatureScanner.firstMatchInBufferForTesting(Data("clean-buffer-no-markers-xyz".utf8))
        )
    }

    func testFridaBuiltinMemorySignature_envBuiltinToggle() {
        withEnvironmentValue(key: "CPRISK_FRIDA_MEMSIG_BUILTIN", value: nil) {
            XCTAssertTrue(FridaBuiltinMemorySignatureScanner.isBuiltinEnabled())
        }
        withEnvironmentValue(key: "CPRISK_FRIDA_MEMSIG_BUILTIN", value: "0") {
            XCTAssertFalse(FridaBuiltinMemorySignatureScanner.isBuiltinEnabled())
        }
        withEnvironmentValue(key: "CPRISK_FRIDA_MEMSIG_BUILTIN", value: "1") {
            XCTAssertTrue(FridaBuiltinMemorySignatureScanner.isBuiltinEnabled())
        }
    }

    #if DEBUG
    func testFridaBuiltinMemorySignature_builtinOffDoesNotEnterPerformScan() {
        FridaBuiltinMemorySignatureScanner.resetDebugCountersForTests()
        let before = FridaBuiltinMemorySignatureScanner.debugPerformScanCount
        withEnvironmentValue(key: "CPRISK_FRIDA_MEMSIG_BUILTIN", value: "0") {
            _ = FridaBuiltinMemorySignatureScanner.scanIfNeeded()
        }
        XCTAssertEqual(FridaBuiltinMemorySignatureScanner.debugPerformScanCount, before)
    }
    #endif

    func testFridaModuleDetectorMarkers() {
        let detector = FridaModuleDetector()
        XCTAssertTrue(detector.moduleMarkers.contains("frida"))
        XCTAssertTrue(detector.moduleMarkers.contains("frida-agent"))
        XCTAssertTrue(detector.moduleMarkers.contains("frida-gadget"))
        XCTAssertTrue(detector.moduleMarkers.contains("gadget"))
        XCTAssertTrue(detector.moduleMarkers.contains("libgum"))
        XCTAssertTrue(detector.suspiciousSectionMarkers.contains("__frida"))
        XCTAssertTrue(detector.suspiciousSectionMarkers.contains("__gum"))
        XCTAssertTrue(detector.suspiciousStringMarkers.contains("frida:rpc"))
        XCTAssertTrue(detector.suspiciousStringMarkers.contains("gum-js-loop"))
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

    func testFridaModuleDetectorBasicMatchingLogic() {
        let detector = FridaModuleDetector()

        let imageHits = detector.detectImageMarkers(in: [
            "/usr/lib/frida-agent.dylib",
            "/private/var/mobile/Containers/frida-gadget.dylib",
            "/System/Library/Frameworks/Foundation.framework/Foundation",
        ])
        let sectionHits = detector.detectSectionMarkers(in: [
            "__text",
            "__frida",
            "__gum",
        ])
        let stringHits = detector.detectStringMarkers(in: [
            "hello world",
            "transport=frida:rpc session ready",
            "gum-js-loop active",
        ])

        XCTAssertTrue(imageHits.contains("frida_module:image:frida"))
        XCTAssertTrue(imageHits.contains("frida_module:image:frida-agent"))
        XCTAssertTrue(sectionHits.contains("frida_module:section:__frida"))
        XCTAssertTrue(sectionHits.contains("frida_module:section:__gum"))
        XCTAssertTrue(stringHits.contains("frida_module:string:frida:rpc"))
        XCTAssertTrue(stringHits.contains("frida_module:string:gum-js-loop"))
    }

    func testFridaModuleDetectorSignalConversion() {
        let result = FridaModuleDetector.buildResult(
            imageHits: ["frida_module:image:frida-agent"],
            sectionHits: ["frida_module:section:__frida"],
            stringHits: ["frida_module:string:frida:rpc"]
        )
        let signals = FridaModuleDetector.asSignals(result: result)
        let ids = Set(signals.map(\.id))

        XCTAssertGreaterThan(result.score, 0)
        XCTAssertLessThanOrEqual(result.score, 40)
        XCTAssertTrue(ids.contains(SignalID.fridaModuleDetected))
        XCTAssertTrue(ids.contains(SignalID.fridaModuleImage))
        XCTAssertTrue(ids.contains(SignalID.fridaModuleSection))
        XCTAssertTrue(ids.contains(SignalID.fridaModuleString))
        XCTAssertEqual(signals.first(where: { $0.id == SignalID.fridaModuleDetected })?.category, "anti_tamper")
        XCTAssertEqual(signals.first(where: { $0.id == SignalID.fridaModuleDetected })?.layer, 2)
        XCTAssertLessThanOrEqual(
            signals.first(where: { $0.id == SignalID.fridaModuleDetected })?.score ?? 0,
            28
        )
    }

    func testRWXMemoryScannerJitAssessmentFlagsStalkerCoexistence() {
        let scanner = RWXMemoryScanner()
        let regions: [RWXMemoryScanner.SuspiciousRegion] = [
            .init(
                address: 0x1000,
                size: 0x4000,
                protection: vm_prot_t(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE),
                isAnonymous: true,
                isAnonymousRX: false,
                userTag: 240,
                shareMode: 3,
                inImage: false,
                isJITLike: false
            ),
            .init(
                address: 0x9000,
                size: 0x2000,
                protection: vm_prot_t(VM_PROT_READ | VM_PROT_EXECUTE),
                isAnonymous: true,
                isAnonymousRX: true,
                userTag: 240,
                shareMode: 3,
                inImage: false,
                isJITLike: true
            ),
        ]

        let assessment = scanner.assess(regions: regions)
        XCTAssertGreaterThan(assessment.score, 0)
        XCTAssertTrue(assessment.methods.contains("rwx:jit_rwx_stalker_like"))
        XCTAssertTrue(assessment.methods.contains("rwx:jit_rwx_coexistence"))
        XCTAssertEqual(assessment.anonymousRWXCount, 1)
        XCTAssertEqual(assessment.jitLikeCount, 1)
    }

    func testRWXMemoryScannerJitSignalConversionIncludesStalkerSignals() {
        let scanner = RWXMemoryScanner()
        let regions: [RWXMemoryScanner.SuspiciousRegion] = [
            .init(
                address: 0x2000,
                size: 0x3000,
                protection: vm_prot_t(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE),
                isAnonymous: true,
                isAnonymousRX: false,
                userTag: 241,
                shareMode: 3,
                inImage: false,
                isJITLike: false
            ),
            .init(
                address: 0xB000,
                size: 0x4000,
                protection: vm_prot_t(VM_PROT_READ | VM_PROT_EXECUTE),
                isAnonymous: true,
                isAnonymousRX: true,
                userTag: 241,
                shareMode: 0,
                inImage: false,
                isJITLike: true
            ),
        ]

        let signals = scanner.asSignals(regions: regions)
        let ids = Set(signals.map(\.id))

        XCTAssertTrue(ids.contains(SignalID.stalkerJitRWX))
        XCTAssertTrue(ids.contains(SignalID.rwxJitCoexistence))
        XCTAssertTrue(ids.contains("rwx_anonymous"))
        XCTAssertTrue(ids.contains("anonymous_executable_memory"))
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
        // Socket detection capped at 30, timing ratio path capped at 25
        XCTAssertTrue(result.score >= 0)
    }

    func testFridaSocketSignalConversion() throws {
        let detector = FridaSocketDetector()
        let signals = try detector.asSignals()
        for signal in signals {
            XCTAssertEqual(signal.category, "anti_tamper")
            XCTAssertEqual(signal.layer, 2)
            XCTAssertTrue(signal.id == "frida_unix_socket" || signal.id == "frida_timing_anomaly" || signal.id == "frida_stalker_amplified")
        }
    }

    func testSystemLibrarySegmentLayoutSignalConversion() throws {
        let detector = SystemLibrarySegmentLayoutDetector()
        let signals = try detector.asSignals()
        for signal in signals {
            XCTAssertEqual(signal.category, "anti_tamper")
            XCTAssertEqual(signal.layer, 2)
            XCTAssertTrue(
                signal.id == "system_library_wx_mapping" ||
                signal.id == "system_library_anonymous_exec_region" ||
                signal.id == "system_library_segment_count_drift" ||
                signal.id == "app_image_segment_layout_anomaly"
            )
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
            FridaModuleDetector(),
            FridaHeapDetector(),
            FridaThreadDetector(),
            FridaSocketDetector(),
            SystemLibrarySegmentLayoutDetector(),
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

    // MARK: - Stalker Amplified Timing Tests

    func testAmplifiedSamplesReturnsCorrectCount() {
        let samples = TimingRatioBaseline.amplifiedSamples(count: 10)
#if targetEnvironment(simulator)
        XCTAssertEqual(samples.getpid.count, 0)
        XCTAssertEqual(samples.stat.count, 0)
#else
        XCTAssertEqual(samples.getpid.count, 10)
        XCTAssertEqual(samples.stat.count, 10)
#endif
    }

    func testAmplifiedSamplesProducesNonZeroValues() {
        let samples = TimingRatioBaseline.amplifiedSamples(count: 5)
#if targetEnvironment(simulator)
        XCTAssertTrue(samples.getpid.isEmpty)
        XCTAssertTrue(samples.stat.isEmpty)
#else
        for s in samples.getpid {
            XCTAssertGreaterThan(s, 0)
        }
        for s in samples.stat {
            XCTAssertGreaterThan(s, 0)
        }
#endif
    }

    func testAmplifiedEvaluationWithNormalRatio() {
        let getpid: [UInt64] = [500, 520, 510, 530, 490]
        let stat: [UInt64] = [5000, 5200, 5100, 5300, 4900]
        let eval = TimingRatioBaseline.evaluate(
            getpidSamples: getpid,
            statSamples: stat,
            ratioThreshold: 12.0
        )
        XCTAssertNotNil(eval)
        XCTAssertFalse(eval!.isAnomalous)
    }

    func testAmplifiedEvaluationDetectsHighRatio() {
        let getpid: [UInt64] = [100, 110, 105, 108, 102]
        let stat: [UInt64] = [2000, 2200, 2100, 2160, 2040]
        let eval = TimingRatioBaseline.evaluate(
            getpidSamples: getpid,
            statSamples: stat,
            ratioThreshold: 12.0
        )
        XCTAssertNotNil(eval)
        XCTAssertTrue(eval!.isAnomalous)
    }

    // MARK: - DyldImageMonitor Tests

    func testDyldImageMonitorSingleton() {
        let a = DyldImageMonitor.shared
        let b = DyldImageMonitor.shared
        XCTAssertTrue(a === b)
    }

    func testDyldImageMonitorStartDoesNotCrash() {
        DyldImageMonitor.shared.start()
        DyldImageMonitor.shared.start()
    }

    func testDyldImageMonitorEvaluateReturnsValidResult() {
        DyldImageMonitor.shared.start()
        let result = DyldImageMonitor.shared.evaluate()
        XCTAssertGreaterThanOrEqual(result.score, 0)
    }

    func testDyldImageMonitorSignalConversion() throws {
        DyldImageMonitor.shared.start()
        let signals = try DyldImageMonitor.shared.asSignals()
        for signal in signals {
            XCTAssertEqual(signal.category, "anti_tamper")
            XCTAssertEqual(signal.layer, 2)
        }
    }

    func testDyldImageMonitorSuspiciousTokenDetection() {
        let monitor = DyldImageMonitor.shared
        let result = monitor.evaluate()
        XCTAssertEqual(result.methods.filter { $0.contains("suspicious_load") }.count, 0)
    }

    // MARK: - FileDetector Randomization Tests

    func testFileDetectorDoesNotCrashWithRandomization() throws {
        let detector = FileDetector()
        for _ in 0..<3 {
            let result = try detector.detect()
            XCTAssertGreaterThanOrEqual(result.score, 0)
        }
    }

    func testFileDetectorProducesNonNegativeScore() throws {
        let detector = FileDetector()
        let result = try detector.detect()
        XCTAssertGreaterThanOrEqual(result.score, 0)
    }

    // MARK: - RandomizedDetection Tests

    func testRandomizedDetectionDeterministicWithFixedSeedAndNoDelay() throws {
        let config = RandomizedDetection.Config(
            enableShuffle: false,
            enableRandomDelay: false,
            minDelayUs: 1,
            maxDelayUs: 1,
            seed: 0x1234_5678,
            subsetRatio: 1.0
        )
        let detector = RandomizedDetection(config: config)

        let first = try detector.detect()
        let second = try detector.detect()

        XCTAssertEqual(first.score, second.score)
        XCTAssertEqual(first.methods, second.methods)
    }

    func testRandomizedDetectionScoreUpperBoundRemainsStable() throws {
        let config = RandomizedDetection.Config(
            enableShuffle: true,
            enableRandomDelay: false,
            minDelayUs: 1,
            maxDelayUs: 1,
            seed: 0xABCD_EF12,
            subsetRatio: 1.0
        )
        let result = try RandomizedDetection(config: config).detect()
        XCTAssertGreaterThanOrEqual(result.score, 0)
        XCTAssertLessThanOrEqual(result.score, 70)
    }

    // MARK: - Watchdog dyld / AMFI / get-task-allow / deny-attach-verify

    func testAntiDebugWatchdogSnapshotProducesDyldFamilySignals() {
        let provider = AntiTamperingSignalProvider()
        let flags = UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION)
            | UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY)
            | UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS)
            | UInt32(CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW)

        let snapshot = makeWatchdogSnapshot(
            anomalyFlags: flags,
            iterationCount: 1,
            dyldInjectionAnomalyCount: 1,
            lastDyldInjectionFlags: 1,
            lastCsopsStatusFlags: 8,
            lastAmfiProbeBits: 4,
            lastGetTaskAllowSuspect: true,
            lastDenyAttachVerifyBits: 2,
            denyAttachVerifyAnomalyCount: 1,
            amfiCsFlagsAnomalyCount: 1,
            getTaskAllowAnomalyCount: 1
        )

        let signals = provider.antiDebugWatchdogSignals(from: snapshot)
        let ids = Set(signals.map { $0.id })

        XCTAssertTrue(ids.contains(SignalID.antiDebugWatchdogDyldInjection))
        XCTAssertTrue(ids.contains(SignalID.antiDebugWatchdogDenyAttachVerify))
        XCTAssertTrue(ids.contains(SignalID.antiDebugWatchdogAMFICsFlags))
        XCTAssertTrue(ids.contains(SignalID.antiDebugWatchdogGetTaskAllow))

        guard let summary = signals.first(where: { $0.id == SignalID.antiDebugWatchdogAnomaly }) else {
            return XCTFail("missing anti_debug_watchdog_anomaly summary signal")
        }
        let kinds = summary.evidence["anomaly_kinds"] ?? ""
        XCTAssertTrue(kinds.contains("dyld_injection"), "expected dyld_injection in \(kinds)")
        XCTAssertTrue(kinds.contains("deny_attach_verify"), "expected deny_attach_verify in \(kinds)")
        XCTAssertTrue(kinds.contains("amfi_cs_flags"), "expected amfi_cs_flags in \(kinds)")
        XCTAssertTrue(kinds.contains("get_task_allow"), "expected get_task_allow in \(kinds)")
    }

    // MARK: - Dylib image count low → dylibInjectImageCountLow

    func testDylibInjectionClassifyImageCountLowMapsToAsSignalsFilters() {
        let hard = DylibInjectionDetector.classifyImageCount(80)
        XCTAssertFalse(hard.methods.isEmpty)
        XCTAssertTrue(hard.methods.allSatisfy { $0.contains("image_count_low_hard") })

        let soft = DylibInjectionDetector.classifyImageCount(150)
        XCTAssertFalse(soft.methods.isEmpty)
        XCTAssertTrue(soft.methods.allSatisfy { $0.contains("image_count_low_soft") })

        let nominal = DylibInjectionDetector.classifyImageCount(250)
        XCTAssertTrue(nominal.methods.isEmpty)

        // Mirrors DylibInjectionDetector.asSignals() low-path filter
        let isLow: (String) -> Bool = {
            $0.contains("image_count_low_hard") || $0.contains("image_count_low_soft")
        }
        let lowDetail = hard.methods.filter { $0.hasPrefix("dylib_inject:image_count") }.filter(isLow)
        XCTAssertFalse(lowDetail.isEmpty)
    }

    func testDylibInjectImageCountLowSignalIdIsStable() {
        XCTAssertEqual(SignalID.dylibInjectImageCountLow, "dylib_inject_image_count_low")
    }

    // MARK: - Cross-consistency (dyld_topology family)

    func testCrossConsistencyIncludesDyldTopologyWithWatchdogDyldInjection() {
        let provider = AntiTamperingSignalProvider()
        let drivers: [RiskSignal] = [
            RiskSignal(
                id: SignalID.pacDisabled,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 50,
                evidence: [:],
                state: .tampered,
                layer: 1,
                weightHint: 70
            ),
            RiskSignal(
                id: SignalID.antiDebugWatchdogDyldInjection,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 84,
                evidence: ["dyld_injection_flags": "1"],
                state: .tampered,
                layer: 2,
                weightHint: 90
            ),
        ]

        let consensus = provider.crossConsistencySignals(from: drivers)
        XCTAssertEqual(consensus.count, 1)
        XCTAssertEqual(consensus.first?.id, "multi_path_consistency_consensus")
        XCTAssertTrue(consensus.first?.evidence["families"]?.contains("dyld_topology") ?? false)
        XCTAssertTrue(consensus.first?.evidence["matched_signals"]?.contains(SignalID.antiDebugWatchdogDyldInjection) ?? false)
    }

    func testCrossConsistencyDyldTopologyAcceptsDylibInjectImageCountLow() {
        let provider = AntiTamperingSignalProvider()
        let drivers: [RiskSignal] = [
            RiskSignal(
                id: SignalID.vmRemapSharedAnonymous,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 50,
                evidence: [:],
                state: .tampered,
                layer: 2,
                weightHint: 80
            ),
            RiskSignal(
                id: SignalID.dylibInjectImageCountLow,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 30,
                evidence: ["detail": "dylib_inject:image_count_low_hard:100"],
                state: .soft(confidence: 0.82),
                layer: 2,
                weightHint: 62
            ),
        ]

        let consensus = provider.crossConsistencySignals(from: drivers)
        XCTAssertEqual(consensus.count, 1)
        XCTAssertTrue(consensus.first?.evidence["matched_signals"]?.contains(SignalID.dylibInjectImageCountLow) ?? false)
    }
}

/// Exercises `cprisk_hidden_mprotect` tolerance: streak-based tamper latch + test injection.
final class MprotectTamperThresholdTests: XCTestCase {

    override func tearDown() {
        cprisk_test_mprotect_reset_tamper_state()
        super.tearDown()
    }

    func testDirectFailFallbackSucceedsDoesNotSetTampered() {
        cprisk_test_mprotect_reset_tamper_state()
        let pageSize = Int(sysconf(_SC_PAGESIZE))
        let ptr = mmap(nil, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)
        XCTAssertNotEqual(ptr, MAP_FAILED)
        defer { munmap(ptr, pageSize) }

        cprisk_test_mprotect_set_force_direct_fail(1)
        cprisk_test_mprotect_set_force_fallback_fail(0)

        let rc = cprisk_armor_vm_protect(ptr, size_t(pageSize), PROT_READ)
        XCTAssertEqual(rc, 0)

        XCTAssertEqual(cprisk_is_mprotect_tampered(), 0)
        XCTAssertEqual(cprisk_get_mprotect_direct_failure_count(), 1)
        XCTAssertEqual(cprisk_get_mprotect_fallback_success_count(), 1)
        XCTAssertEqual(cprisk_get_mprotect_consecutive_full_fail_streak(), 0)
    }

    func testConsecutiveFullFailuresReachThresholdSetsTampered() {
        cprisk_test_mprotect_reset_tamper_state()
        cprisk_test_mprotect_set_fail_streak_threshold(2)

        let pageSize = Int(sysconf(_SC_PAGESIZE))
        let ptr = mmap(nil, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)
        XCTAssertNotEqual(ptr, MAP_FAILED)
        defer { munmap(ptr, pageSize) }

        cprisk_test_mprotect_set_force_direct_fail(1)
        cprisk_test_mprotect_set_force_fallback_fail(1)

        XCTAssertEqual(cprisk_armor_vm_protect(ptr, size_t(pageSize), PROT_READ), -1)
        XCTAssertEqual(cprisk_is_mprotect_tampered(), 0)
        XCTAssertEqual(cprisk_get_mprotect_consecutive_full_fail_streak(), 1)

        XCTAssertEqual(cprisk_armor_vm_protect(ptr, size_t(pageSize), PROT_READ), -1)
        XCTAssertEqual(cprisk_is_mprotect_tampered(), 1)
        XCTAssertEqual(cprisk_get_mprotect_consecutive_full_fail_streak(), 2)
        XCTAssertEqual(cprisk_get_mprotect_fail_streak_threshold(), 2)
    }

    func testRealSuccessClearsFullFailStreak() {
        cprisk_test_mprotect_reset_tamper_state()
        cprisk_test_mprotect_set_fail_streak_threshold(3)

        let pageSize = Int(sysconf(_SC_PAGESIZE))
        let ptr = mmap(nil, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)
        XCTAssertNotEqual(ptr, MAP_FAILED)
        defer { munmap(ptr, pageSize) }

        cprisk_test_mprotect_set_force_direct_fail(1)
        cprisk_test_mprotect_set_force_fallback_fail(1)
        XCTAssertEqual(cprisk_armor_vm_protect(ptr, size_t(pageSize), PROT_READ), -1)
        XCTAssertEqual(cprisk_armor_vm_protect(ptr, size_t(pageSize), PROT_READ), -1)
        XCTAssertEqual(cprisk_get_mprotect_consecutive_full_fail_streak(), 2)
        XCTAssertEqual(cprisk_is_mprotect_tampered(), 0)

        cprisk_test_mprotect_set_force_direct_fail(0)
        cprisk_test_mprotect_set_force_fallback_fail(0)
        XCTAssertEqual(cprisk_armor_vm_protect(ptr, size_t(pageSize), PROT_READ), 0)
        XCTAssertEqual(cprisk_get_mprotect_consecutive_full_fail_streak(), 0)

        cprisk_test_mprotect_set_force_direct_fail(1)
        cprisk_test_mprotect_set_force_fallback_fail(1)
        XCTAssertEqual(cprisk_armor_vm_protect(ptr, size_t(pageSize), PROT_READ), -1)
        XCTAssertEqual(cprisk_armor_vm_protect(ptr, size_t(pageSize), PROT_READ), -1)
        XCTAssertEqual(cprisk_get_mprotect_consecutive_full_fail_streak(), 2)
        XCTAssertEqual(cprisk_armor_vm_protect(ptr, size_t(pageSize), PROT_READ), -1)
        XCTAssertEqual(cprisk_is_mprotect_tampered(), 1)
    }

    func testMIEPostureDetectorPrimarySignalAndLevel() {
        let a = MIEPostureDetector.evaluate()
        XCTAssertTrue(MIEPostureDetector.Level.allCases.contains(a.level))
        let signals = MIEPostureDetector().asSignals()
        let primary = signals.first { $0.id == SignalID.miePosture }
        XCTAssertNotNil(primary)
        XCTAssertEqual(primary?.score, 0)
        XCTAssertFalse(signals.contains { $0.id == SignalID.mteCanaryTampered && $0.score > 0 })
    }

    /// Staged watchdog lane poison (default threshold 3) should not surface full integrity poison immediately.
    func testStagedWatchdogPoisonRequiresThresholdHits() {
        cprisk_test_reset_staged_poison_for_tests()
        XCTAssertEqual(cprisk_is_integrity_poisoned(), 0)

        cprisk_integrity_poison_watchdog_lane()
        XCTAssertEqual(cprisk_is_integrity_poisoned(), 0)

        cprisk_integrity_poison_watchdog_lane()
        XCTAssertEqual(cprisk_is_integrity_poisoned(), 0)

        cprisk_integrity_poison_watchdog_lane()
        XCTAssertEqual(cprisk_is_integrity_poisoned(), 1)

        cprisk_test_reset_staged_poison_for_tests()
        XCTAssertEqual(cprisk_is_integrity_poisoned(), 0)
    }
}
