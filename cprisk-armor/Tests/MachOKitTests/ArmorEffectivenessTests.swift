import MachOKit
import XCTest

final class ArmorEffectivenessTests: XCTestCase {
    func testPartialMetadataIsNotNativeProtection() {
        let result = PassResult(
            passName: "VM Protector", itemsProcessed: 1, bytesModified: 256,
            details: [], metrics: ["vmp.partial_emitted": 1]
        )
        XCTAssertThrowsError(try validateEffectiveArmorPasses(
            enabledPasses: [13], resultsByPass: [13: [result]]
        ))
    }

    func testSelectedCodeTransformCannotSucceedWithZeroEffect() {
        let result = PassResult(
            passName: "InstructionSubstitution",
            itemsProcessed: 0,
            bytesModified: 0,
            details: ["Applied no substitutions"]
        )

        XCTAssertThrowsError(
            try validateEffectiveArmorPasses(
                enabledPasses: [8],
                resultsByPass: [8: [result]]
            )
        )
    }

    func testVMPFullTierRequiresAtLeastOneInstalledTrampoline() {
        let result = PassResult(
            passName: "VM Protector",
            itemsProcessed: 2,
            bytesModified: 256,
            details: [],
            metrics: [
                "vmp.full_targets": 3,
                "vmp.full_patched": 0,
                "vmp.partial_emitted": 2,
            ]
        )

        XCTAssertThrowsError(
            try validateEffectiveArmorPasses(
                enabledPasses: [13],
                resultsByPass: [13: [result]]
            )
        )
    }

    func testVMPAcceptsEffectiveBytecodeAndFullPatch() throws {
        let result = PassResult(
            passName: "VM Protector",
            itemsProcessed: 2,
            bytesModified: 256,
            details: [],
            metrics: [
                "vmp.full_targets": 1,
                "vmp.full_patched": 1,
                "vmp.partial_emitted": 1,
            ]
        )

        XCTAssertNoThrow(
            try validateEffectiveArmorPasses(
                enabledPasses: [13],
                resultsByPass: [13: [result]]
            )
        )
    }
}
