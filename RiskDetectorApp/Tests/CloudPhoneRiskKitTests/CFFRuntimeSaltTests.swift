import XCTest
@testable import CloudPhoneRiskKit

final class CFFRuntimeSaltTests: XCTestCase {

    func testCombineIsDeterministic() {
        let first = CFFRuntimeSalt.combine(
            words: [1, 2, 3],
            strings: ["device", "policy", "challenge"],
            flags: [true, false, true]
        )
        let second = CFFRuntimeSalt.combine(
            words: [1, 2, 3],
            strings: ["device", "policy", "challenge"],
            flags: [true, false, true]
        )

        XCTAssertEqual(first, second)
    }

    func testCombineChangesWhenAnyInputDomainChanges() {
        let base = CFFRuntimeSalt.combine(
            words: [11, 22],
            strings: ["ctx", "score"],
            flags: [true, false]
        )
        let changedWord = CFFRuntimeSalt.combine(
            words: [11, 23],
            strings: ["ctx", "score"],
            flags: [true, false]
        )
        let changedString = CFFRuntimeSalt.combine(
            words: [11, 22],
            strings: ["ctx", "state"],
            flags: [true, false]
        )
        let changedFlag = CFFRuntimeSalt.combine(
            words: [11, 22],
            strings: ["ctx", "score"],
            flags: [false, false]
        )

        XCTAssertNotEqual(base, changedWord)
        XCTAssertNotEqual(base, changedString)
        XCTAssertNotEqual(base, changedFlag)
    }

    func testCombinePreservesStringBoundaries() {
        let joinedAsTwoFields = CFFRuntimeSalt.combine(strings: ["ab", "c"])
        let joinedAsDifferentSplit = CFFRuntimeSalt.combine(strings: ["a", "bc"])

        XCTAssertNotEqual(
            joinedAsTwoFields,
            joinedAsDifferentSplit,
            "string separator should prevent accidental boundary collisions"
        )
    }

    func testCombineIsOrderSensitive() {
        let ordered = CFFRuntimeSalt.combine(
            words: [1, 2, 3],
            strings: ["alpha", "beta"],
            flags: [true, false]
        )
        let reversed = CFFRuntimeSalt.combine(
            words: [3, 2, 1],
            strings: ["beta", "alpha"],
            flags: [false, true]
        )

        XCTAssertNotEqual(ordered, reversed)
    }

    func testCombineBuildContextTogglePerturbsOutput() {
        let withBuildContext = CFFRuntimeSalt.combine(
            words: [0x1234_5678, 0x9ABC_DEF0],
            strings: ["ctx", "blend"],
            flags: [true],
            includeBuildContext: true
        )
        let withoutBuildContext = CFFRuntimeSalt.combine(
            words: [0x1234_5678, 0x9ABC_DEF0],
            strings: ["ctx", "blend"],
            flags: [true],
            includeBuildContext: false
        )

        XCTAssertNotEqual(withBuildContext, withoutBuildContext)
    }
}
