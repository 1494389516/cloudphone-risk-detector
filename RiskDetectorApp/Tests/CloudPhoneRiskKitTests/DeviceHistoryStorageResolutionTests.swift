import XCTest

@testable import CloudPhoneRiskKit

final class DeviceHistoryStorageResolutionTests: XCTestCase {

  func testResolveStorageDirectoryPrefersApplicationSupport() {
    let appSupport = URL(fileURLWithPath: "/tmp/app-support", isDirectory: true)
    let caches = URL(fileURLWithPath: "/tmp/caches", isDirectory: true)
    let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

    let resolved = DeviceHistory.resolveStorageDirectory(
      applicationSupportDirectories: [appSupport],
      cachesDirectories: [caches],
      temporaryDirectory: temp
    )

    XCTAssertEqual(resolved, appSupport)
  }

  func testResolveStorageDirectoryFallsBackToCaches() {
    let caches = URL(fileURLWithPath: "/tmp/caches", isDirectory: true)
    let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

    let resolved = DeviceHistory.resolveStorageDirectory(
      applicationSupportDirectories: [],
      cachesDirectories: [caches],
      temporaryDirectory: temp
    )

    XCTAssertEqual(resolved, caches.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true))
  }

  func testResolveStorageDirectoryFallsBackToTemporaryDirectory() {
    let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

    let resolved = DeviceHistory.resolveStorageDirectory(
      applicationSupportDirectories: [],
      cachesDirectories: [],
      temporaryDirectory: temp
    )

    XCTAssertEqual(resolved, temp.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true))
  }
}
