import Darwin
import XCTest
@testable import CloudPhoneRiskKit

final class DetectionEnhancementTests: XCTestCase {
    func testNewDetectorsProduceNonNegativeScores() throws {
        let detectors: [Detector] = [
            MultiPathConsistencyCrossValidator(),
            VMRemapDetector(),
            PACValidationDetector(),
            TaskPortAuditDetector(),
            DTraceKDebugDetector(),
            LLDBJITDetector(),
            DyldSharedCacheIntegrityDetector(),
        ]

        for detector in detectors {
            let result = try detector.detect()
            XCTAssertGreaterThanOrEqual(result.score, 0, "\(type(of: detector)) score should be non-negative")
        }
    }

    func testMultiPathCrossValidationReportsHighRiskOnInconsistency() {
        let detector = MultiPathConsistencyCrossValidator()
        let finding = MultiPathConsistencyCrossValidator.PathFinding(
            path: "/Applications/Cydia.app",
            results: [
                .coreAccess: true,
                .coreStat: false,
                .coreFopen: false,
                .secureAccess: true,
                .secureStat: true,
                .secureLstat: true,
            ]
        )

        let assessment = detector.assess(findings: [finding])

        XCTAssertGreaterThanOrEqual(assessment.score, 72)
        XCTAssertEqual(assessment.inconsistentFindings.count, 1)
        XCTAssertTrue(assessment.methods.contains(where: { $0.contains("multipath_consistency:inconsistent") }))
    }

    func testVMRemapAssessmentFlagsSharedAnonymousAndImageAliasCoexistence() {
        let detector = VMRemapDetector()
        let executable = vm_prot_t(VM_PROT_READ | VM_PROT_EXECUTE)
        let findings: [VMRemapDetector.RegionFinding] = [
            .init(
                address: 0x1000,
                size: 0x8000,
                protection: executable,
                userTag: 240,
                shareMode: 2,
                isAnonymous: true,
                inImage: false
            ),
            .init(
                address: 0x9000,
                size: 0x8000,
                protection: executable,
                userTag: 241,
                shareMode: 2,
                isAnonymous: true,
                inImage: false
            ),
            .init(
                address: 0x11000,
                size: 0x6000,
                protection: executable,
                userTag: 242,
                shareMode: 3,
                isAnonymous: true,
                inImage: true
            ),
        ]

        let assessment = detector.assess(findings: findings)

        XCTAssertGreaterThan(assessment.score, 60)
        XCTAssertEqual(assessment.sharedAnonymousExecutableCount, 2)
        XCTAssertEqual(assessment.imageAnonymousAliasCount, 1)
        XCTAssertTrue(assessment.methods.contains("vm_remap:coexistence"))
    }

    func testPACValidationDetectsFeatureDisabledOnCapableDevice() {
        let detector = PACValidationDetector()
        let snapshot = PACValidationDetector.Snapshot(
            machine: "iPhone14,2",
            pacCapable: true,
            arm64eFlag: 0,
            pAuthFlag: 1,
            unreadablePointers: [],
            unexpectedImages: []
        )

        let assessment = detector.assess(snapshot: snapshot)

        XCTAssertTrue(assessment.pacReportedDisabled)
        XCTAssertGreaterThanOrEqual(assessment.score, 70)
        XCTAssertTrue(assessment.methods.contains("pac:feature_disabled"))
    }

    func testTaskPortAuditHighlightsSendOnlyExceptionPorts() {
        let detector = TaskPortAuditDetector()
        let snapshot = TaskPortAuditDetector.Snapshot(
            totalPortNames: 900,
            sendRightCount: 600,
            receiveRightCount: 120,
            sendOnceRightCount: 80,
            deadNameCount: 200,
            sendOnlyExceptionPortCount: 1,
            unknownExceptionPortCount: 0,
            taskForPidUnexpectedSuccess: false
        )

        let assessment = detector.assess(snapshot: snapshot)

        XCTAssertGreaterThanOrEqual(assessment.score, 40)
        XCTAssertEqual(assessment.sendOnlyExceptionPortCount, 1)
        XCTAssertTrue(assessment.methods.contains("task_port:exception_send_only:1"))
    }

    func testDTraceKDebugAssessmentUsesConservativeGating() {
        let detector = DTraceKDebugDetector()
        let singleSurface = DTraceKDebugDetector.Snapshot(
            envHits: ["DYLD_PRINT_APIS=1"],
            imageHits: [],
            toolPathHits: [],
            kdebugValues: [:]
        )
        let multiSurface = DTraceKDebugDetector.Snapshot(
            envHits: ["DYLD_PRINT_APIS=1"],
            imageHits: ["dtrace@/usr/lib/libdtrace.dylib"],
            toolPathHits: [],
            kdebugValues: [:]
        )

        let singleAssessment = detector.assess(snapshot: singleSurface)
        let multiAssessment = detector.assess(snapshot: multiSurface)

        XCTAssertEqual(singleAssessment.indicatorCount, 1)
        XCTAssertEqual(singleAssessment.score, 12)
        XCTAssertEqual(multiAssessment.indicatorCount, 2)
        XCTAssertGreaterThanOrEqual(multiAssessment.score, 38)
        XCTAssertTrue(multiAssessment.methods.contains("dtrace_kdebug:multi_surface"))
    }

    func testLLDBJITAssessmentEscalatesAfterSmallRWXBurst() {
        let detector = LLDBJITDetector()
        let twoRegions = [
            LLDBJITDetector.RegionObservation(address: 0x1000, size: 0x4000, userTag: 240, shareMode: 3, inImage: false),
            LLDBJITDetector.RegionObservation(address: 0x6000, size: 0x4000, userTag: 241, shareMode: 3, inImage: false),
        ]
        let threeRegions = twoRegions + [
            LLDBJITDetector.RegionObservation(address: 0xB000, size: 0x6000, userTag: 242, shareMode: 3, inImage: false),
        ]

        let softAssessment = detector.assess(observations: twoRegions)
        let strongAssessment = detector.assess(observations: threeRegions)

        XCTAssertLessThan(softAssessment.score, 30)
        XCTAssertGreaterThanOrEqual(strongAssessment.score, 30)
        XCTAssertTrue(strongAssessment.methods.contains(where: { $0.hasPrefix("lldb_jit:small_rwx_count") }))
    }

    func testDyldSharedCacheIntegrityCorrelatedAnomaliesIncreaseScore() {
        let detector = DyldSharedCacheIntegrityDetector()
        let snapshot = DyldSharedCacheIntegrityDetector.Snapshot(
            criticalImages: [
                .init(id: "libsystem_kernel", path: "/usr/lib/system/libsystem_kernel.dylib", uuidHex: nil, slide: 100),
                .init(id: "libobjc", path: "/usr/lib/libobjc.A.dylib", uuidHex: "abcd", slide: 200),
            ],
            slideMismatchCount: 1,
            missingUUIDCount: 1,
            symbolMismatches: ["open:unexpected_image:/tmp/x.dylib", "objc_msgSend:out_of_text"]
        )

        let assessment = detector.assess(snapshot: snapshot)

        XCTAssertGreaterThan(assessment.score, 50)
        XCTAssertEqual(assessment.slideMismatchCount, 1)
        XCTAssertEqual(assessment.missingUUIDCount, 1)
        XCTAssertEqual(assessment.symbolMismatchCount, 2)
        XCTAssertTrue(assessment.methods.contains("dyld_shared_cache:correlated_anomaly"))
    }
}
