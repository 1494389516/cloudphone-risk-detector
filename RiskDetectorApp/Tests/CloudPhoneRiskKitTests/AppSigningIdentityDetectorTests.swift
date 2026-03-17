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

    func testSkipsNonAppBundleContainers() {
        let detector = makeDetector()
        let inspection = detector.inspect(
            snapshot: makeSnapshot(bundleContainer: .other),
            isDebugBuild: false
        )

        XCTAssertTrue(inspection.findings.isEmpty)
        XCTAssertTrue(inspection.signals.isEmpty)
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
