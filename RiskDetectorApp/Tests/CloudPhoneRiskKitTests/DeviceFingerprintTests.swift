import XCTest
@testable import CloudPhoneRiskKit

final class DeviceFingerprintTests: XCTestCase {

    func testExtractKernelBuildPrefersExplicitOSVersion() {
        let build = DeviceFingerprint.extractKernelBuild(
            from: "Darwin Kernel Version 23.0.0.0: Thu Oct 26 15:18:41 PDT 2023; root:xnu-10002.1.13.100.1~1/RELEASE_ARM64_T8101",
            osVersion: "23F79"
        )

        XCTAssertEqual(build, "23F79")
    }

    func testExtractKernelBuildDoesNotTreatReleaseSuffixAsBuild() {
        let build = DeviceFingerprint.extractKernelBuild(
            from: "Darwin Kernel Version 23.0.0.0: Thu Oct 26 15:18:41 PDT 2023; root:xnu-10002.1.13.100.1~1/RELEASE_ARM64_T8101",
            osVersion: ""
        )

        XCTAssertNil(build)
    }

    func testLooksLikeKernelBuildAcceptsAppleStyleBuildIdentifiers() {
        XCTAssertTrue(DeviceFingerprint.looksLikeKernelBuild("21A360"))
        XCTAssertTrue(DeviceFingerprint.looksLikeKernelBuild("24A5264n"))
        XCTAssertFalse(DeviceFingerprint.looksLikeKernelBuild("RELEASE_ARM64_T8101"))
        XCTAssertFalse(DeviceFingerprint.looksLikeKernelBuild("xnu-10002"))
    }
}
