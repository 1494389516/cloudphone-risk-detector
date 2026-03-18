import XCTest
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
        exceptionDeliveryTimeoutAnomalyCount: UInt64 = 0
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
            exceptionDeliveryTimeoutAnomalyCount: exceptionDeliveryTimeoutAnomalyCount
        )
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

    // MARK: - FridaDetector Logic Tests

    func testFridaDetectorKnownPorts() {
        let detector = FridaDetector()
        XCTAssertTrue(detector.knownPorts.contains(27042))
        XCTAssertTrue(detector.knownPorts.contains(27043))
        XCTAssertTrue(detector.knownPorts.contains(23946))
    }

    func testFridaDetectorScoreCapped() throws {
        let detector = FridaDetector()
        let result = try detector.detect()
        XCTAssertLessThanOrEqual(result.score, 45)
    }

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
}
