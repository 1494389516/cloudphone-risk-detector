import XCTest
@testable import CloudPhoneRiskKit

final class AppSigningIdentityDetectorTests: XCTestCase {
    func testDetectsApplicationIdentifierBundleMismatch() {
        let detector = makeDetector()
        let inspection = detector.inspect(
            snapshot: makeSnapshot(applicationIdentifier: "ABCDE12345.com.example.other"),
            isDebugBuild: false
        )

        XCTAssertTrue(inspection.shouldPoison)
        XCTAssertTrue(inspection.findings.contains(where: { $0.signalID == "app_identifier_bundle_mismatch" }))
        XCTAssertEqual(inspection.signals.first?.id, "app_signing_identity_tampered")
        XCTAssertEqual(inspection.signals.first?.state, .tampered)
    }

    func testDetectsTeamIdentifierMismatchBetweenEntitlementAndApplicationIdentifier() {
        let detector = makeDetector()
        let inspection = detector.inspect(
            snapshot: makeSnapshot(
                teamIdentifierEntitlement: "ABCDE12345",
                applicationIdentifier: "ZZZZZ99999.com.example.app"
            ),
            isDebugBuild: false
        )

        XCTAssertTrue(inspection.shouldPoison)
        XCTAssertTrue(inspection.findings.contains(where: { $0.signalID == "app_team_identifier_mismatch" }))
    }

    func testDetectsMalformedApplicationIdentifier() {
        let detector = makeDetector()
        let inspection = detector.inspect(
            snapshot: makeSnapshot(applicationIdentifier: "ABCDE12345"),
            isDebugBuild: false
        )

        XCTAssertFalse(inspection.shouldPoison)
        XCTAssertTrue(inspection.findings.contains(where: { $0.signalID == "app_identifier_malformed" }))
    }

    func testDerivesTeamIdentifierFromApplicationIdentifierPrefix() {
        let detector = makeDetector()
        let inspection = detector.inspect(
            snapshot: makeSnapshot(teamIdentifierEntitlement: nil),
            isDebugBuild: false
        )

        XCTAssertEqual(inspection.snapshot.derivedTeamIdentifier, "ABCDE12345")
        XCTAssertEqual(inspection.snapshot.effectiveTeamIdentifier, "ABCDE12345")
        XCTAssertFalse(inspection.findings.contains(where: { $0.signalID == "app_team_identifier_missing" }))
    }

    func testFlagsReleaseGetTaskAllow() {
        let detector = makeDetector()
        let inspection = detector.inspect(
            snapshot: makeSnapshot(getTaskAllow: true),
            isDebugBuild: false
        )

        XCTAssertTrue(inspection.shouldPoison)
        XCTAssertTrue(inspection.findings.contains(where: { $0.signalID == "app_get_task_allow_enabled" }))
    }

    func testBaselineDetectsSigningIdentityChange() {
        let suiteName = "AppSigningIdentityDetectorTests.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            XCTFail("failed to create isolated user defaults")
            return
        }
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let detector = AppSigningIdentityDetector(userDefaults: defaults)
        let firstInspection = detector.inspect(snapshot: makeSnapshot(), isDebugBuild: false)
        XCTAssertTrue(firstInspection.baselineStored)
        XCTAssertFalse(firstInspection.shouldPoison)

        let secondInspection = detector.inspect(
            snapshot: makeSnapshot(
                teamIdentifierEntitlement: "ZZZZZ99999",
                applicationIdentifier: "ZZZZZ99999.com.example.app"
            ),
            isDebugBuild: false
        )
        XCTAssertTrue(secondInspection.shouldPoison)
        XCTAssertTrue(secondInspection.findings.contains(where: { $0.signalID == "app_signing_baseline_changed" }))
    }

    func testAggregateSignalCarriesReasonCodesAndCoverageEvidence() {
        let detector = makeDetector()
        let inspection = detector.inspect(
            snapshot: makeSnapshot(
                teamIdentifierEntitlement: "ABCDE12345",
                applicationIdentifier: "ZZZZZ99999.com.example.other",
                bundleIdentifier: "com.example.app",
                infoPlistBundleIdentifier: "com.example.mismatch",
                getTaskAllow: true
            ),
            isDebugBuild: false
        )

        let aggregate = inspection.signals.first { $0.id == ObfuscatedConstants.signalAppSigningIdentityTampered }
        XCTAssertNotNil(aggregate)
        XCTAssertTrue(aggregate?.evidence["reason_codes"]?.contains("app_bundle_identifier_mismatch") ?? false)
        XCTAssertTrue(aggregate?.evidence["poison_finding_ids"]?.contains("app_get_task_allow_enabled") ?? false)
        XCTAssertEqual(aggregate?.evidence["team_identifier_source"], "entitlement")
        XCTAssertEqual(aggregate?.evidence["bundle_container"], "app")
        XCTAssertEqual(aggregate?.evidence["soft_count"], "0")
    }

    func testTelemetryCarriesBindingFingerprintAndEligibility() {
        let detector = makeDetector()
        let inspection = detector.inspect(
            snapshot: makeSnapshot(
                teamIdentifierEntitlement: nil,
                applicationIdentifier: "ABCDE12345",
                bundleIdentifier: "com.example.app"
            ),
            isDebugBuild: false
        )

        XCTAssertFalse(inspection.telemetry["signing_identity_fp"]?.isEmpty ?? true)
        XCTAssertEqual(inspection.telemetry["signing_identity_status"], "soft_anomaly")
        XCTAssertEqual(inspection.telemetry["signing_identity_baseline_eligibility"], "missing_team_identifier")
        XCTAssertTrue(inspection.telemetry["signing_identity_reason_codes"]?.contains("app_identifier_malformed") ?? false)
    }

    func testSkipsNonAppBundleContainers() {
        let detector = makeDetector()
        let inspection = detector.inspect(
            snapshot: makeSnapshot(bundleContainer: .other),
            isDebugBuild: false
        )

        XCTAssertTrue(inspection.findings.isEmpty)
        XCTAssertTrue(inspection.signals.isEmpty)
    }

    func testAggregateSignalCarriesFindingIDsAndTeamSource() {
        let detector = makeDetector()
        let inspection = detector.inspect(
            snapshot: makeSnapshot(
                teamIdentifierEntitlement: "ABCDE12345",
                applicationIdentifier: "ZZZZZ99999.com.example.app"
            ),
            isDebugBuild: false
        )

        let aggregate = inspection.signals.first(where: { $0.id == "app_signing_identity_tampered" })
        XCTAssertEqual(aggregate?.evidence["team_identifier_source"], "entitlement")
        XCTAssertEqual(aggregate?.evidence["bundle_container"], "app")
        XCTAssertTrue(aggregate?.evidence["finding_ids"]?.contains("app_team_identifier_mismatch") ?? false)
        XCTAssertTrue(aggregate?.evidence["poison_finding_ids"]?.contains("app_team_identifier_mismatch") ?? false)
    }

    private func makeDetector() -> AppSigningIdentityDetector {
        let suiteName = "AppSigningIdentityDetectorTests.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suiteName) else {
            fatalError("failed to create isolated user defaults")
        }
        defaults.removePersistentDomain(forName: suiteName)
        return AppSigningIdentityDetector(userDefaults: defaults)
    }

    private func makeSnapshot(
        teamIdentifierEntitlement: String? = "ABCDE12345",
        applicationIdentifier: String? = "ABCDE12345.com.example.app",
        bundleIdentifier: String? = "com.example.app",
        infoPlistBundleIdentifier: String? = "com.example.app",
        getTaskAllow: Bool? = false,
        bundleContainer: AppSigningIdentityDetector.BundleContainer = .app
    ) -> AppSigningIdentityDetector.IdentitySnapshot {
        AppSigningIdentityDetector.IdentitySnapshot(
            teamIdentifierEntitlement: teamIdentifierEntitlement,
            applicationIdentifier: applicationIdentifier,
            bundleIdentifier: bundleIdentifier,
            infoPlistBundleIdentifier: infoPlistBundleIdentifier,
            getTaskAllow: getTaskAllow,
            bundleContainer: bundleContainer
        )
    }
}
