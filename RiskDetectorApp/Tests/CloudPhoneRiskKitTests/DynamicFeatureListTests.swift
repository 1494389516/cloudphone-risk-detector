import XCTest
@testable import CloudPhoneRiskKit

final class DynamicFeatureListTests: XCTestCase {

    override func tearDown() {
        DynamicFeatureList.shared.resetDynamic()
        super.tearDown()
    }

    // MARK: - Default Values

    func testDefaultSuspiciousLibrariesNotEmpty() {
        let list = DynamicFeatureList.shared
        list.resetDynamic()

        let libs = list.suspiciousLibraries
        XCTAssertFalse(libs.isEmpty)
        XCTAssertTrue(libs.contains("frida"))
        XCTAssertTrue(libs.contains("substrate"))
        XCTAssertTrue(libs.contains("cycript"))
    }

    func testDefaultSuspiciousPathsNotEmpty() {
        let list = DynamicFeatureList.shared
        list.resetDynamic()

        let paths = list.suspiciousPaths
        XCTAssertFalse(paths.isEmpty)
        XCTAssertTrue(paths.contains("/tmp/frida-"))
    }

    func testDefaultSuspiciousPortsNotEmpty() {
        let list = DynamicFeatureList.shared
        list.resetDynamic()

        let ports = list.suspiciousPorts
        XCTAssertTrue(ports.contains(27042))
        XCTAssertTrue(ports.contains(27043))
    }

    // MARK: - applyRemoteConfig

    func testApplyRemoteConfigAddsLibraries() {
        let list = DynamicFeatureList.shared
        list.resetDynamic()

        list.applyRemoteConfig(
            additionalSuspiciousLibraries: ["newHookLib"],
            additionalSuspiciousPaths: nil,
            additionalSuspiciousPorts: nil
        )

        XCTAssertTrue(list.suspiciousLibraries.contains("newhooklib")) // lowercased
    }

    func testApplyRemoteConfigAddsPaths() {
        let list = DynamicFeatureList.shared
        list.resetDynamic()

        list.applyRemoteConfig(
            additionalSuspiciousLibraries: nil,
            additionalSuspiciousPaths: ["/tmp/custom-agent-"],
            additionalSuspiciousPorts: nil
        )

        XCTAssertTrue(list.suspiciousPaths.contains("/tmp/custom-agent-"))
    }

    func testApplyRemoteConfigAddsPorts() {
        let list = DynamicFeatureList.shared
        list.resetDynamic()

        list.applyRemoteConfig(
            additionalSuspiciousLibraries: nil,
            additionalSuspiciousPaths: nil,
            additionalSuspiciousPorts: [9999]
        )

        XCTAssertTrue(list.suspiciousPorts.contains(9999))
    }

    func testApplyRemoteConfigDeduplicates() {
        let list = DynamicFeatureList.shared
        list.resetDynamic()

        list.applyRemoteConfig(
            additionalSuspiciousLibraries: ["newlib", "newlib", "NEWLIB"],
            additionalSuspiciousPaths: ["/a", "/a"],
            additionalSuspiciousPorts: [5555, 5555]
        )

        let libCount = list.suspiciousLibraries.filter { $0 == "newlib" }.count
        XCTAssertEqual(libCount, 1, "Should deduplicate (case-insensitive)")

        let pathCount = list.suspiciousPaths.filter { $0 == "/a" }.count
        XCTAssertEqual(pathCount, 1, "Should deduplicate paths")

        let portCount = list.suspiciousPorts.filter { $0 == 5555 }.count
        XCTAssertEqual(portCount, 1, "Should deduplicate ports")
    }

    func testApplyRemoteConfigMultipleTimes() {
        let list = DynamicFeatureList.shared
        list.resetDynamic()

        list.applyRemoteConfig(additionalSuspiciousLibraries: ["lib_a"], additionalSuspiciousPaths: nil, additionalSuspiciousPorts: nil)
        list.applyRemoteConfig(additionalSuspiciousLibraries: ["lib_b"], additionalSuspiciousPaths: nil, additionalSuspiciousPorts: nil)

        XCTAssertTrue(list.suspiciousLibraries.contains("lib_a"))
        XCTAssertTrue(list.suspiciousLibraries.contains("lib_b"))
    }

    // MARK: - resetDynamic

    func testResetDynamicKeepsDefaults() {
        let list = DynamicFeatureList.shared

        list.applyRemoteConfig(
            additionalSuspiciousLibraries: ["custom_lib"],
            additionalSuspiciousPaths: ["/custom/path"],
            additionalSuspiciousPorts: [8888]
        )

        list.resetDynamic()

        XCTAssertFalse(list.suspiciousLibraries.contains("custom_lib"))
        XCTAssertFalse(list.suspiciousPaths.contains("/custom/path"))
        XCTAssertFalse(list.suspiciousPorts.contains(8888))

        // Defaults should still be present
        XCTAssertTrue(list.suspiciousLibraries.contains("frida"))
        XCTAssertTrue(list.suspiciousPaths.contains("/tmp/frida-"))
        XCTAssertTrue(list.suspiciousPorts.contains(27042))
    }

    // MARK: - Nil parameters

    func testApplyRemoteConfigWithAllNils() {
        let list = DynamicFeatureList.shared
        list.resetDynamic()

        let countBefore = list.suspiciousLibraries.count

        list.applyRemoteConfig(
            additionalSuspiciousLibraries: nil,
            additionalSuspiciousPaths: nil,
            additionalSuspiciousPorts: nil
        )

        XCTAssertEqual(list.suspiciousLibraries.count, countBefore)
    }
}
