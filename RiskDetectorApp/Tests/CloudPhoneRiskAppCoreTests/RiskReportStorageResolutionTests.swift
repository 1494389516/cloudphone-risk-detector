import XCTest
@testable import CloudPhoneRiskAppCore

final class RiskReportStorageResolutionTests: XCTestCase {

    func testResolveBaseDirectoryPrefersApplicationSupport() {
        let appSupport = URL(fileURLWithPath: "/tmp/app-support", isDirectory: true)
        let caches = URL(fileURLWithPath: "/tmp/caches", isDirectory: true)
        let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

        let resolved = RiskReportStorage.resolveBaseDirectory(
            applicationSupportDirectories: [appSupport],
            cachesDirectories: [caches],
            temporaryDirectory: temp
        )

        XCTAssertEqual(
            resolved,
            appSupport.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
        )
    }

    func testResolveBaseDirectoryFallsBackToCaches() {
        let caches = URL(fileURLWithPath: "/tmp/caches", isDirectory: true)
        let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

        let resolved = RiskReportStorage.resolveBaseDirectory(
            applicationSupportDirectories: [],
            cachesDirectories: [caches],
            temporaryDirectory: temp
        )

        XCTAssertEqual(
            resolved,
            caches.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
        )
    }

    func testResolveBaseDirectoryFallsBackToTemporaryDirectory() {
        let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

        let resolved = RiskReportStorage.resolveBaseDirectory(
            applicationSupportDirectories: [],
            cachesDirectories: [],
            temporaryDirectory: temp
        )

        XCTAssertEqual(
            resolved,
            temp.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true)
        )
    }
}
