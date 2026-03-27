import CRiskCore
import XCTest
import VMProtector

final class VMBranchIndRuntimeTests: XCTestCase {

    func testSemiSemanticBranchIndControlledTargetSelection() {
        var encodedPC: UInt64 = 0
        var steps: UInt64 = 0
        let structured = VMBranchIndImmediateContract.synthetic(vregIndex: 3, accBase: 11)
        let entropy: UInt64 = 0x00AA_BBCC_DDEE_FF00 | (structured & 0xFF)
        let forwardSpan: UInt8 = 2
        let semiSemanticImm = VMBranchIndImmediateContract.semiSemantic(
            entropy: entropy,
            forwardSpan: forwardSpan
        )

        XCTAssertTrue(VMBranchIndImmediateContract.isSemiSemantic(semiSemanticImm))

        let rc = cprisk_test_vm_branch_ind_identity(
            semiSemanticImm,
            &encodedPC,
            &steps
        )

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(steps, 1)
        let insnWidth: UInt64 = 9
        let minPC = insnWidth * insnWidth
        let maxPC = UInt64(1 + forwardSpan) * insnWidth * insnWidth
        XCTAssertGreaterThanOrEqual(encodedPC, minPC)
        XCTAssertLessThanOrEqual(encodedPC, maxPC)
    }

    func testSemiSemanticBranchIndZeroSpanFallsThrough() {
        var encodedPC: UInt64 = 0
        var steps: UInt64 = 0
        let semiSemanticImm = VMBranchIndImmediateContract.semiSemantic(
            entropy: 0x00FF_1122_3344_5500,
            forwardSpan: 0
        )

        let rc = cprisk_test_vm_branch_ind_identity(
            semiSemanticImm,
            &encodedPC,
            &steps
        )

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(steps, 1)
        XCTAssertEqual(encodedPC, 81, "forward_span=0 should always advance by exactly 1 instruction")
    }

    func testSemiSemanticBranchIndDedicatedSmokeHelper() {
        var encodedPC: UInt64 = 0
        var steps: UInt64 = 0
        let forwardSpan: UInt8 = 4
        let semiSemanticImm = VMBranchIndImmediateContract.semiSemantic(
            entropy: 0x00DE_ADBE_EF00_FF00,
            forwardSpan: forwardSpan
        )

        let rc = cprisk_test_vm_branch_ind_semi_semantic(
            semiSemanticImm,
            &encodedPC,
            &steps
        )

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(steps, 1)
        let insnWidth: UInt64 = 9
        let minPC = insnWidth * insnWidth
        let maxPC = UInt64(1 + forwardSpan) * insnWidth * insnWidth
        XCTAssertGreaterThanOrEqual(encodedPC, minPC)
        XCTAssertLessThanOrEqual(encodedPC, maxPC)
    }

    func testSemiIdentityBranchIndFallsThroughOneInstruction() {
        var encodedPC: UInt64 = 0
        var steps: UInt64 = 0
        let semiIdentityTag: UInt64 = 0xA100_0000_0000_0000

        let rc = cprisk_test_vm_branch_ind_identity(
            semiIdentityTag,
            &encodedPC,
            &steps
        )

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(steps, 1)
        XCTAssertEqual(encodedPC, 81)
    }

    func testProducerSemiIdentityBranchIndImmediateRunsThroughRuntime() {
        let instructions = [VMInstruction(op: .nop), VMInstruction(op: .halt)]
        let hardening = VMPolicyHardeningM3(
            syntheticBranchIndBudget: 1,
            syntheticBranchIndRate: 1,
            syntheticBranchIndMaxPerFunction: 1,
            syntheticBranchIndMode: .semiIdentity
        )
        let rewritten = VMProtectorPass.rewriteProducerInstructions(
            instructions,
            functionId: 0x444,
            seed: 0x555,
            tier: .full,
            hardening: hardening
        )

        guard let branchIndex = rewritten.instructions.firstIndex(where: { $0.op == .branchInd }) else {
            XCTFail("expected semi-identity branchInd insertion")
            return
        }

        let branchImmediate = rewritten.instructions[branchIndex].immediate
        XCTAssertTrue(VMBranchIndImmediateContract.isSemiIdentity(branchImmediate))

        var encodedPC: UInt64 = 0
        var steps: UInt64 = 0

        let rc = cprisk_test_vm_branch_ind_identity(
            branchImmediate,
            &encodedPC,
            &steps
        )

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(steps, 1)
        XCTAssertEqual(encodedPC, 81)
    }

    /// Exercises the same path as Pass 13 (`rewriteProducerInstructions` → `VMBytecodeEmitter.emit`) and feeds the **on-disk**
    /// decoded immediate into the CRiskCore identity probe — closing encoding ↔ runtime without hand-constructed immediates.
    func testEmittedBytecodeSemiIdentityBranchIndImmediateRunsThroughRuntime() {
        let instructions = [VMInstruction(op: .nop), VMInstruction(op: .halt)]
        let hardening = VMPolicyHardeningM3(
            syntheticBranchIndBudget: 1,
            syntheticBranchIndRate: 1,
            syntheticBranchIndMaxPerFunction: 1,
            syntheticBranchIndMode: .semiIdentity
        )
        let functionId: UInt64 = 0x444
        let seed: UInt64 = 0x555
        let rewritten = VMProtectorPass.rewriteProducerInstructions(
            instructions,
            functionId: functionId,
            seed: seed,
            tier: .full,
            hardening: hardening
        )
        let emitOpts = VMM2EmitOptions(handlerVariantSeed: 0x99, perEntryVpcEnabled: false)
        let table = VMOpcodeTable(seed: 0x5151)
        let emitter = VMBytecodeEmitter()
        let payloads = emitter.emit(
            programs: [
                (functionId: functionId, entryVMA: 0x2000, tier: .full, instructions: rewritten.instructions)
            ],
            opcodeTable: table,
            options: emitOpts
        )
        let ops = VMBytecodeEmitter.decodeEntryLogicalOps(
            bytecodePayload: payloads.bytecode,
            dispatchPayload: payloads.dispatch,
            entryIndex: 0
        )
        XCTAssertEqual(ops, [.nop, .branchInd, .halt])

        let imms = VMProtectorPass.decodeEntryWireImmediates(
            bytecodePayload: payloads.bytecode,
            dispatchPayload: payloads.dispatch,
            entryIndex: 0,
            functionId: functionId,
            options: emitOpts
        )
        guard let imms, imms.count == 3 else {
            XCTFail("expected decoded wire immediates")
            return
        }

        guard let branchIdx = ops?.firstIndex(of: .branchInd) else {
            XCTFail("expected branchInd in decoded logical op stream")
            return
        }
        let wireImmediate = imms[branchIdx]
        XCTAssertEqual(wireImmediate, rewritten.instructions[branchIdx].immediate)

        var encodedPC: UInt64 = 0
        var steps: UInt64 = 0
        let rc = cprisk_test_vm_branch_ind_identity(wireImmediate, &encodedPC, &steps)

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(steps, 1)
        XCTAssertEqual(encodedPC, 81)
    }

    func testSemiIdentityPayloadPreservesFallthroughBehavior() {
        var encodedPC: UInt64 = 0
        var steps: UInt64 = 0
        let identityWithPayload: UInt64 = 0xA155_AA11_2233_4455

        let rc = cprisk_test_vm_branch_ind_identity(
            identityWithPayload,
            &encodedPC,
            &steps
        )

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(steps, 1)
        XCTAssertEqual(encodedPC, 81)
    }

    func testRuntimeAcceptsProducerSemiIdentityImmediate() {
        var encodedPC: UInt64 = 0
        var steps: UInt64 = 0
        let entropy: UInt64 = 0xDEAD_BEEF_CAFE_F00D
        let semiIdentityImmediate = 0xA100_0000_0000_0000 | (entropy & 0x00FF_FFFF_FFFF_FFFF)

        let rc = cprisk_test_vm_branch_ind_identity(
            semiIdentityImmediate,
            &encodedPC,
            &steps
        )

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(steps, 1)
        XCTAssertEqual(encodedPC, 81)
    }

    func testEmittedBytecodeSemiSemanticBranchIndImmediateRunsThroughRuntime() {
        let instructions = [VMInstruction(op: .nop), VMInstruction(op: .halt)]
        let hardening = VMPolicyHardeningM3(
            syntheticBranchIndBudget: 1,
            syntheticBranchIndRate: 1,
            syntheticBranchIndMaxPerFunction: 1,
            syntheticBranchIndMode: .semiSemantic
        )
        let functionId: UInt64 = 0xA200
        let seed: UInt64 = 0xB300
        let rewritten = VMProtectorPass.rewriteProducerInstructions(
            instructions,
            functionId: functionId,
            seed: seed,
            tier: .full,
            hardening: hardening
        )
        let defaultSpan = Int(VMProtectorPass.semiSemanticDefaultForwardSpan)
        let actualOps = rewritten.instructions.map(\.op)
        XCTAssertEqual(actualOps.first, .nop)
        XCTAssertEqual(actualOps[1], .branchInd)
        XCTAssertEqual(actualOps.last, .halt)
        let sledOps = Array(actualOps[2..<(2 + defaultSpan)])
        XCTAssertEqual(sledOps.count, defaultSpan)
        for op in sledOps {
            XCTAssertTrue(op == .nop || op == .rolAcc, "sled must contain nop or rolAcc, got \(op)")
        }

        let emitOpts = VMM2EmitOptions(handlerVariantSeed: 0x77, perEntryVpcEnabled: false)
        let table = VMOpcodeTable(seed: 0x6162)
        let emitter = VMBytecodeEmitter()
        let payloads = emitter.emit(
            programs: [
                (functionId: functionId, entryVMA: 0x3000, tier: .full, instructions: rewritten.instructions)
            ],
            opcodeTable: table,
            options: emitOpts
        )
        let ops = VMBytecodeEmitter.decodeEntryLogicalOps(
            bytecodePayload: payloads.bytecode,
            dispatchPayload: payloads.dispatch,
            entryIndex: 0
        )
        XCTAssertEqual(ops, actualOps)

        let imms = VMProtectorPass.decodeEntryWireImmediates(
            bytecodePayload: payloads.bytecode,
            dispatchPayload: payloads.dispatch,
            entryIndex: 0,
            functionId: functionId,
            options: emitOpts
        )
        let expectedImmCount = actualOps.count
        guard let imms, imms.count == expectedImmCount else {
            XCTFail("expected \(expectedImmCount) decoded wire immediates, got \(imms?.count ?? 0)")
            return
        }
        let wireImmediate = imms[1]
        XCTAssertTrue(VMBranchIndImmediateContract.isSemiSemantic(wireImmediate))
        XCTAssertEqual(wireImmediate, rewritten.instructions[1].immediate)

        let rc = cprisk_test_vm_branch_ind_semi_semantic(wireImmediate, nil, nil)
        XCTAssertEqual(rc, 0)
    }

    func testLegacySyntheticImmediatePathStillResolvesAsBefore() {
        var encodedPC: UInt64 = 0
        var steps: UInt64 = 0

        let rc = cprisk_test_vm_branch_ind_identity(
            0,
            &encodedPC,
            &steps
        )

        XCTAssertEqual(rc, 0)
        XCTAssertEqual(steps, 1)
        XCTAssertEqual(encodedPC, 0)
    }
}
