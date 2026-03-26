import CRiskCore
import XCTest

final class VMBranchIndRuntimeTests: XCTestCase {

    func testIdentityModeBranchIndFallsThroughOneInstruction() {
        var encodedPC: UInt64 = 0
        var steps: UInt64 = 0

        let rc = cprisk_test_vm_branch_ind_identity(
            0,
            &encodedPC,
            &steps
        )

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(steps, 1)
        XCTAssertEqual(encodedPC, 81)
    }

    func testIdentityModePreservesLowImmediateBits() {
        var encodedPC: UInt64 = 0
        var steps: UInt64 = 0
        let identityWithPayload: UInt64 = 0x0055_AA11_2233_44

        let rc = cprisk_test_vm_branch_ind_identity(
            identityWithPayload,
            &encodedPC,
            &steps
        )

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(steps, 1)
        XCTAssertEqual(encodedPC, 81)
    }
}
