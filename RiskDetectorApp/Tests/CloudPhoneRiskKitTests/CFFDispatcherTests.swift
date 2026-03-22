import XCTest
@testable import CloudPhoneRiskKit

final class CFFDispatcherTests: XCTestCase {

    func testPrefersPrimaryBranchIsDeterministic() {
        let encodedState: UInt32 = 0x1234_5678
        let salt: UInt32 = 0x9ABC_DEF0

        let first = CFFDispatcher.prefersPrimaryBranch(encodedState: encodedState, salt: salt)
        let second = CFFDispatcher.prefersPrimaryBranch(encodedState: encodedState, salt: salt)

        XCTAssertEqual(first, second)
    }

    func testPrefersPrimaryBranchCanSelectBothRails() {
        let salt: UInt32 = 0x7F4A_7C15

        let first = CFFDispatcher.prefersPrimaryBranch(encodedState: 0, salt: salt)
        let second = CFFDispatcher.prefersPrimaryBranch(encodedState: 1, salt: salt)

        XCTAssertNotEqual(first, second, "adjacent states should not collapse to one fixed rail")
    }

    func testBranchKeyIsBoundedToTwoBits() {
        let salt: UInt32 = 0xCAFEBABE
        let samples: [UInt32] = [0, 1, 2, 3, 0x11, 0x1234_5678, 0xFFFF_FFFF]

        for sample in samples {
            let key = CFFDispatcher.branchKey(sample, salt: salt)
            XCTAssertLessThanOrEqual(key, 3, "branch key should stay within two bits")
        }
    }

    func testBranchKeyCoversFourBucketsForSequentialStates() {
        let salt: UInt32 = 0xA24B_AED5
        let values = Set((0..<4).map { CFFDispatcher.branchKey(UInt32($0), salt: salt) })

        XCTAssertEqual(values, Set<UInt32>([0, 1, 2, 3]))
    }

    func testSplitIndirectDispatcherProducesStableStyle() {
        let config = CFFConfig.debug(
            functionSeed: 0x1234_5678,
            protectionTier: .heavy,
            dispatcherStyle: .splitIndirect,
            codecStyle: .xorRotate
        )
        let planA = CFFDispatcher.plan(encodedState: 0x77AA_22CC, salt: 0x9ABC_DEF0, config: config)
        let planB = CFFDispatcher.plan(encodedState: 0x77AA_22CC, salt: 0x9ABC_DEF0, config: config)
        XCTAssertEqual(planA.style, planB.style)
        XCTAssertTrue(planA.style == .switchLoop || planA.style == .ifElseChain)
    }

    func testFunctionPointerTableDispatcherProducesStableStyle() {
        let config = CFFConfig.debug(
            functionSeed: 0x2233_4455,
            protectionTier: .heavy,
            dispatcherStyle: .functionPointerTable,
            codecStyle: .feistelSpn
        )
        let planA = CFFDispatcher.plan(encodedState: 0x55AA_00FF, salt: 0xA5A5_5A5A, config: config)
        let planB = CFFDispatcher.plan(encodedState: 0x55AA_00FF, salt: 0xA5A5_5A5A, config: config)
        XCTAssertEqual(planA.style, planB.style)
        XCTAssertTrue(planA.style == .switchLoop || planA.style == .ifElseChain)
    }
}

#if !DEBUG
final class CFFReleaseDefaultPolicyTests: XCTestCase {
    func testReleaseDefaultsUseFunctionPointerTableAndFeistelCodec() {
        let cfg = CFFConfig.release(functionSeed: 0xA11C_E551_BEE5)
        XCTAssertEqual(cfg.dispatcherStyle, .functionPointerTable)
        XCTAssertEqual(cfg.codecStyle, .feistelSpn)
        XCTAssertEqual(cfg.protectionTier, .heavy)
    }
}
#endif
