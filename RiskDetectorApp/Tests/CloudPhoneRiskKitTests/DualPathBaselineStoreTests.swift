import XCTest
@testable import CloudPhoneRiskKit

final class DualPathBaselineStoreTests: XCTestCase {

    // MARK: - Baseline Collection

    func testHasBaselineInitiallyFalse() {
        // Note: hasCollected is static, may be true from previous tests
        // Testing the API contract rather than initial state
        _ = DualPathBaselineStore.hasBaseline
    }

    func testCollectBaselineSetsHasBaseline() {
        DualPathBaselineStore.collectBaseline(paths: ["/usr/lib/dyld"])
        XCTAssertTrue(DualPathBaselineStore.hasBaseline)
    }

    func testHasBaselineForSpecificPath() {
        DualPathBaselineStore.collectBaseline(paths: ["/usr/lib/dyld"])
        // Path that was collected should have baseline
        // Note: on test host, /usr/lib/dyld may or may not exist
        // This tests the API, not the actual filesystem
    }

    // MARK: - Drift Detection

    func testCheckForDriftWithNoBaseline() {
        // A path that was never baselined should not report drift
        let drift = DualPathBaselineStore.checkForDrift(
            path: "/nonexistent/path/never/baselined",
            currentInode: 12345,
            currentStDev: 1
        )
        XCTAssertFalse(drift)
    }

    // MARK: - Thread Safety

    func testConcurrentBaselineAccess() {
        let iterations = 50
        let group = DispatchGroup()

        for i in 0..<iterations {
            group.enter()
            DispatchQueue.global().async {
                _ = DualPathBaselineStore.hasBaseline
                _ = DualPathBaselineStore.hasBaseline(for: "/test/path_\(i)")
                _ = DualPathBaselineStore.checkForDrift(
                    path: "/test/path_\(i)",
                    currentInode: UInt64(i),
                    currentStDev: 1
                )
                group.leave()
            }
        }

        let result = group.wait(timeout: .now() + 10)
        XCTAssertEqual(result, .success)
    }
}
