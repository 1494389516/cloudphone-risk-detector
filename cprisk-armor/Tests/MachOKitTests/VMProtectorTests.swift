import XCTest
import VMProtector

final class VMProtectorTests: XCTestCase {
    func testVMPolicyParsesTiersAndNeverWins() {
        let yaml = """
        version: 2
        functions:
          full:
            - _foo
            - bar
          partial:
            - baz
          never:
            - bar
            - qux
        """
        let p = VMPolicyConfig.parse(yaml)
        XCTAssertEqual(p.version, 2)
        XCTAssertEqual(Set(p.full), ["_foo", "bar"])
        XCTAssertEqual(p.partial, ["baz"])
        XCTAssertEqual(Set(p.never), ["bar", "qux"])
        XCTAssertEqual(p.tier(for: "_foo"), .full)
        XCTAssertEqual(p.tier(for: "baz"), .partial)
        XCTAssertNil(p.tier(for: "bar"))
        XCTAssertNil(p.tier(for: "qux"))
        XCTAssertFalse(p.antiAnalysis.handlerDuplication)
        XCTAssertFalse(p.opaqueVpcEncoding.enabled)
        XCTAssertFalse(p.hardening.protectVmInterpreterWithCff)
        XCTAssertFalse(p.hardening.enableDeadHandlerInjection)
        XCTAssertFalse(p.hardening.opaqueVpcPredicateChain)
        XCTAssertFalse(p.hardening.interpreterSelfIntegrityCheck)
        XCTAssertEqual(p.hardening.interpreterCffTier, .medium)
    }

    func testVMPolicyParsesM2OptionalSections() {
        let yaml = """
        version: 3
        anti_analysis:
          handler_duplication: true
        opaque_vpc_encoding:
          enabled: true
        functions:
          full:
            - _x
        """
        let p = VMPolicyConfig.parse(yaml)
        XCTAssertEqual(p.version, 3)
        XCTAssertTrue(p.antiAnalysis.handlerDuplication)
        XCTAssertTrue(p.opaqueVpcEncoding.enabled)
    }

    func testVMPolicyParsesM3Hardening() {
        let yaml = """
        version: 4
        hardening:
          protect_vm_interpreter_with_cff: true
          enable_dead_handler_injection: true
          opaque_vpc_predicate_chain: true
          interpreter_self_integrity_check: true
          interpreter_cff_tier: heavy
        functions:
          full:
            - _x
        """
        let p = VMPolicyConfig.parse(yaml)
        XCTAssertTrue(p.hardening.protectVmInterpreterWithCff)
        XCTAssertTrue(p.hardening.enableDeadHandlerInjection)
        XCTAssertTrue(p.hardening.opaqueVpcPredicateChain)
        XCTAssertTrue(p.hardening.interpreterSelfIntegrityCheck)
        XCTAssertEqual(p.hardening.interpreterCffTier, .heavy)
    }

    func testOpcodeTablePolymorphismIsDeterministicPerSeed() {
        let a = VMOpcodeTable(seed: 0x1111_AAAA_BBBB_CCCC)
        let b = VMOpcodeTable(seed: 0x1111_AAAA_BBBB_CCCC)
        let c = VMOpcodeTable(seed: 0x2222_DEAD_BEEF_CAFE)

        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a.wireByte(for: VMLogicalOp.nop), a.wireByte(for: VMLogicalOp.ret))
        var mappingA = Set<UInt8>()
        for op in VMLogicalOp.allCases {
            mappingA.insert(a.wireByte(for: op))
        }
        XCTAssertEqual(mappingA.count, VMLogicalOp.allCases.count, "seeded table should assign distinct primary raw bytes")
        XCTAssertNotEqual(a, c)
        XCTAssertFalse(a.hasRawMappingConflict())
    }

    func testOpcodeTableHandlerDuplicationExpandsPools() {
        let t = VMOpcodeTable(seed: 0xC0FFEE, enableHandlerDuplication: true)
        XCTAssertTrue(t.handlerDuplicationEnabled)
        XCTAssertFalse(t.hasRawMappingConflict())
        XCTAssertEqual(t.assignedRawBytes().count, VMLogicalOp.allCases.count * 4)
        for op in VMLogicalOp.allCases {
            var s = Set<UInt8>()
            for k in 0..<64 {
                s.insert(t.wireByte(for: op, selector: UInt64(k)))
            }
            XCTAssertGreaterThanOrEqual(s.count, 2, "handler duplication should rotate among aliases for \(op)")
        }
    }

    func testRawToLogicalDispatchTableCoversAliases() {
        let t = VMOpcodeTable(seed: 0xBEEF, enableHandlerDuplication: true)
        let table = t.rawToLogicalTable()
        XCTAssertEqual(table.count, 256)
        for op in VMLogicalOp.allCases {
            for k in 0..<8 {
                let raw = t.wireByte(for: op, selector: UInt64(k))
                XCTAssertEqual(table[Int(raw)], op.rawValue, "selector \(k) op \(op)")
            }
        }
    }

    func testDeadHandlerInjectionFillsDecoySlotsWithoutPoolConflict() {
        let spec = VMDeadHandlerSpec(seed: 0xACE0FACE, budget: 32)
        let t = VMOpcodeTable(seed: 0xBEEF, enableHandlerDuplication: false, deadHandler: spec)
        XCTAssertNotNil(t.deadHandlerInjection)
        XCTAssertEqual(t.deadHandlerInjection?.budget, 32)
        XCTAssertFalse(t.hasRawMappingConflict())
        let table = t.rawToLogicalTable()
        for m in t.deadHandlerInjection!.mappings {
            XCTAssertEqual(table[Int(m.raw)], m.logical)
        }
    }

    func testM3DispatchTailRoundTripForDeadAndPredicates() {
        let table = VMOpcodeTable(
            seed: 99,
            enableHandlerDuplication: false,
            deadHandler: VMDeadHandlerSpec(seed: 0x1111, budget: 12)
        )
        let preds: [UInt64] = [7, 8, 9]
        let emitter = VMBytecodeEmitter()
        let programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (1, 0x1000, .full, [VMInstruction(op: .nop)])
        ]
        let payloads = emitter.emit(
            programs: programs,
            opcodeTable: table,
            options: VMM2EmitOptions(
                opaqueVpcCategoryHigh32: false,
                handlerVariantSeed: 1,
                perEntryVpcEnabled: false,
                m3: VMM3EmitOptions(
                    vpcPredicateConstants: preds,
                    enableDeadHandlers: true,
                    enableOpaquePredicateChain: true
                )
            )
        )
        XCTAssertGreaterThan(payloads.dispatch.count, 16 + VMBytecodeFormat.dispatchTableSize)
        let parsed = VMBytecodeEmitter.parseM3DispatchTail(fromDispatchPayload: payloads.dispatch)
        XCTAssertNotNil(parsed)
        XCTAssertEqual(parsed?.predicates, preds)
        XCTAssertGreaterThan(parsed?.deadBudget ?? 0, 0)
        let dh = VMBytecodeFormat.readUInt32LE(payloads.dispatch, offset: 12)
        XCTAssertNotEqual(dh & VMBytecodeFormat.DispatchHeaderFlags.deadHandlerMetadata, 0)
        XCTAssertNotEqual(dh & VMBytecodeFormat.DispatchHeaderFlags.vpcPredicateChainMetadata, 0)
    }

    func testGenerateVpcPredicateChainIsDeterministic() {
        let a = VMBytecodeEmitter.generateVpcPredicateChain(seed: 0x55, count: 8)
        let b = VMBytecodeEmitter.generateVpcPredicateChain(seed: 0x55, count: 8)
        XCTAssertEqual(a, b)
        XCTAssertEqual(a.count, 8)
    }

    func testBytecodeEmitterProducesHeaderEntriesAndVpcAffineMetadata() {
        let table = VMOpcodeTable(seed: 42)
        let emitter = VMBytecodeEmitter()
        let programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (1, 0x1000, .full, [VMInstruction(op: .nop), VMInstruction(op: .halt)])
        ]
        let payloads = emitter.emit(
            programs: programs,
            opcodeTable: table,
            options: VMM2EmitOptions(opaqueVpcCategoryHigh32: false, handlerVariantSeed: 0xABCD, perEntryVpcEnabled: true)
        )
        XCTAssertGreaterThan(payloads.bytecode.count, 48)
        XCTAssertEqual(payloads.dispatch.count, 16 + VMBytecodeFormat.dispatchTableSize)
        let magic = payloads.bytecode.withUnsafeBytes { $0.load(as: UInt32.self) }
        XCTAssertEqual(magic, VMBytecodeFormat.bytecodeMagic)
        let version = payloads.bytecode.withUnsafeBytes { buf in
            buf.load(fromByteOffset: 4, as: UInt32.self)
        }
        XCTAssertEqual(version, VMBytecodeFormat.bytecodeABIVersionV2)
        let flags = payloads.bytecode.withUnsafeBytes { buf in
            buf.load(fromByteOffset: 12, as: UInt32.self)
        }
        XCTAssertNotEqual(flags & VMBytecodeFormat.BytecodeFlags.perEntryVpc, 0)
        XCTAssertNotEqual(flags & VMBytecodeFormat.BytecodeFlags.handlerVariantSeed, 0)
        let a = VMBytecodeEmitter.deriveVpcAffine(functionId: 1, seed: 0xABCD).0
        XCTAssertEqual(a & 1, 1)
    }

    func testOpaqueVpcEncodingChangesRawImmediateHighBits() {
        let table = VMOpcodeTable(seed: 9)
        let emitter = VMBytecodeEmitter()
        let ins = VMInstruction(op: .rawRegion, immediate: 0xD280_0000, rawCategory: .movWide)
        let programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (functionId: 3, entryVMA: 0x2000, tier: .partial, instructions: [ins, VMInstruction(op: .halt)])
        ]
        let plain = emitter.emit(programs: programs, opcodeTable: table, options: VMM2EmitOptions(opaqueVpcCategoryHigh32: false))
        let opaque = emitter.emit(programs: programs, opcodeTable: table, options: VMM2EmitOptions(opaqueVpcCategoryHigh32: true))
        XCTAssertNotEqual(plain.bytecode, opaque.bytecode)
    }

    func testTrampolineEncodingRoundTripSize() throws {
        let stub = try VMPatchRewriter.buildTrampoline(
            functionId: 0x0123_4567_89AB_CDEF,
            functionEntryVMA: 0x1000_0400,
            vmEntryVMA: 0x1000_0800
        )
        XCTAssertEqual(stub.count, VMPatchRewriter.trampolineByteLength)
    }

    func testLifterRecognizesMovWideAndBranchPatterns() {
        let movz = Data([0x00, 0x00, 0x80, 0xD2]) // MOVZ X0, #0
        let lifter = ARM64Lifter()
        let m = lifter.liftPrologue(bytes: movz, maxInstructions: 8)
        XCTAssertEqual(m.first?.op, VMLogicalOp.rawRegion)
        XCTAssertEqual(m.first?.rawCategory, VMRawRegionCategory.movWide)

        let cbz = Data([0x00, 0x00, 0x00, 0xB4]) // CBZ X0, +0 (imm14=0)
        let c = lifter.liftPrologue(bytes: cbz, maxInstructions: 8)
        XCTAssertEqual(c.first?.rawCategory, VMRawRegionCategory.branchTest)

        let bCond = Data([0x00, 0x00, 0x00, 0x54]) // B.EQ +0
        let b = lifter.liftPrologue(bytes: bCond, maxInstructions: 8)
        XCTAssertEqual(b.first?.rawCategory, VMRawRegionCategory.branchCond)
    }

    func testLifterLoadStoreAndConditionalSelectCategories() {
        let lifter = ARM64Lifter()
        let ldr = Data([0x20, 0x00, 0x40, 0xF9]) // LDR X0, [X1, #0]
        let ld = lifter.liftPrologue(bytes: ldr, maxInstructions: 4)
        XCTAssertEqual(ld.first?.rawCategory, VMRawRegionCategory.loadStore)

        let csel = Data([0x20, 0x0C, 0x82, 0x9A]) // CSEL X0, X1, X2, EQ
        let cs = lifter.liftPrologue(bytes: csel, maxInstructions: 4)
        XCTAssertEqual(cs.first?.rawCategory, VMRawRegionCategory.condSelect)
    }

    func testLifterFusesAdrpAdd() {
        let adrp = Data([0x00, 0x00, 0x00, 0x90]) // ADRP X0, #0
        let add = Data([0x00, 0x00, 0x00, 0x91]) // ADD X0, X0, #0
        var bytes = Data()
        bytes.append(adrp)
        bytes.append(add)
        let lifter = ARM64Lifter()
        let p = lifter.liftPrologue(bytes: bytes, maxInstructions: 8)
        XCTAssertEqual(p.count, 2)
        XCTAssertEqual(p[0].op, .rawRegion)
        XCTAssertEqual(p[0].rawCategory, .adrAdd)
        XCTAssertEqual(p[0].immediate, 0x9100_0000_9000_0000)
    }
}
