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
        XCTAssertFalse(p.hardening.antiSymbolicHeavy)
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
        XCTAssertNotEqual(flags & VMBytecodeFormat.BytecodeFlags.nonLinearVpc, 0)
        let a = VMBytecodeEmitter.deriveVpcAffine(functionId: 1, seed: 0xABCD).0
        XCTAssertEqual(a & 1, 1)
    }

    func testHandlerSeedOnlyCanDisableNonLinearVpcWhenOptedOut() {
        let table = VMOpcodeTable(seed: 123)
        let emitter = VMBytecodeEmitter()
        let programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (1, 0x1000, .partial, [VMInstruction(op: .nop), VMInstruction(op: .halt)])
        ]
        let payloads = emitter.emit(
            programs: programs,
            opcodeTable: table,
            options: VMM2EmitOptions(handlerVariantSeed: 0x44, perEntryVpcEnabled: false, vpcNonlinearEncoding: false)
        )
        let flags = payloads.bytecode.withUnsafeBytes { buf in
            buf.load(fromByteOffset: 12, as: UInt32.self)
        }
        XCTAssertNotEqual(flags & VMBytecodeFormat.BytecodeFlags.handlerVariantSeed, 0)
        XCTAssertEqual(flags & VMBytecodeFormat.BytecodeFlags.nonLinearVpc, 0)
    }

    func testVpcNonlinearEncodingOptInSetsFlag() {
        let table = VMOpcodeTable(seed: 123)
        let emitter = VMBytecodeEmitter()
        let programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (1, 0x1000, .partial, [VMInstruction(op: .nop), VMInstruction(op: .halt)])
        ]
        let payloads = emitter.emit(
            programs: programs,
            opcodeTable: table,
            options: VMM2EmitOptions(handlerVariantSeed: 0x44, perEntryVpcEnabled: false, vpcNonlinearEncoding: true)
        )
        let flags = payloads.bytecode.withUnsafeBytes { buf in
            buf.load(fromByteOffset: 12, as: UInt32.self)
        }
        XCTAssertNotEqual(flags & VMBytecodeFormat.BytecodeFlags.nonLinearVpc, 0)
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
        let fid = UInt64(0x0123_4567_89AB_CDEF)
        let entry = UInt64(0x1000_0400)
        let vm = UInt64(0x1000_0800)
        for tpl in VMTrampolineTemplate.allCases {
            let stub = try VMPatchRewriter.buildTrampoline(
                functionId: fid,
                functionEntryVMA: entry,
                vmEntryVMA: vm,
                template: tpl
            )
            XCTAssertEqual(stub.count, VMPatchRewriter.trampolineByteLength, "template \(tpl)")
        }
    }

    func testTrampolineTemplateSelectionIsDeterministicBySeedAndFunctionId() {
        let a = VMPatchRewriter.selectTrampolineTemplate(functionId: 0xAAA, buildSeed: 0x111)
        let b = VMPatchRewriter.selectTrampolineTemplate(functionId: 0xAAA, buildSeed: 0x111)
        XCTAssertEqual(a, b)
        XCTAssertTrue(VMTrampolineTemplate.allCases.contains(a))
        var variants = Set<VMTrampolineTemplate>()
        for u in UInt64(0)..<256 {
            variants.insert(VMPatchRewriter.selectTrampolineTemplate(functionId: u, buildSeed: 0x111))
        }
        XCTAssertGreaterThanOrEqual(variants.count, 2, "seed mix should surface multiple templates across ids")
    }

    func testVmEntrySymbolSelectionIsDeterministicAndVaried() {
        let a = VMPatchRewriter.selectVmEntrySymbolName(functionId: 0xAAA, buildSeed: 0x111)
        let b = VMPatchRewriter.selectVmEntrySymbolName(functionId: 0xAAA, buildSeed: 0x111)
        XCTAssertEqual(a, b)
        var names = Set<String>()
        for u in UInt64(0)..<512 {
            names.insert(VMPatchRewriter.selectVmEntrySymbolName(functionId: u, buildSeed: 0x222))
        }
        XCTAssertGreaterThanOrEqual(names.count, 2)
    }

    func testOpcodeWireObfuscationV3MatchesMix() {
        let table = VMOpcodeTable(seed: 0xC0DE)
        let emitter = VMBytecodeEmitter()
        let programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (functionId: 0x22, entryVMA: 0x3000, tier: .full, [VMInstruction(op: .nop), VMInstruction(op: .halt)])
        ]
        let encOpts = VMM2EmitOptions(
            handlerVariantSeed: 0,
            perEntryVpcEnabled: false,
            opcodeWireObfuscation: true,
            opcodeKeystreamMaterial: 0xABCD_EF01_2345_6789
        )
        let enc = emitter.emit(programs: programs, opcodeTable: table, options: encOpts)
        let vEnc = VMBytecodeFormat.readUInt32LE(enc.bytecode, offset: 4)
        XCTAssertEqual(vEnc, VMBytecodeFormat.bytecodeABIVersionV3)
        let f = VMBytecodeFormat.readUInt32LE(enc.bytecode, offset: 12)
        XCTAssertNotEqual(f & VMBytecodeFormat.BytecodeFlags.opcodeWireObfuscation, 0)
        let hdrTotal = VMBytecodeEmitter.bytecodeHeaderTotalBytes(version: vEnc, flags: f)
        XCTAssertEqual(hdrTotal, 16 + VMBytecodeFormat.vpcAffineBytes + 8)
        let root = VMBytecodeFormat.readUInt64LE(enc.bytecode, offset: hdrTotal - 8)
        XCTAssertEqual(root, encOpts.opcodeKeystreamMaterial)
        let entryBase = hdrTotal
        let bcOff = Int(VMBytecodeFormat.readUInt32LE(enc.bytecode, offset: entryBase + 20))
        let raw0 = enc.bytecode[bcOff]
        let sel = UInt64(0) ^ UInt64(0) ^ (0 & 0xFFFF)
        let rawWire = table.wireByte(for: .nop, selector: sel)
        let m = VMBytecodeEmitter.opcodeMixByte(functionId: 0x22, pcIndex: 0, seed: root)
        XCTAssertEqual(raw0, rawWire ^ UInt8(truncatingIfNeeded: m))
    }

    func testTrampolineTemplatesAreNotAllIdenticalBytes() throws {
        let fid = UInt64(0xF00D_BEEF_DEAD_BEEF)
        let entry = UInt64(0x1_0000_2000)
        let vm = UInt64(0x1_0000_2800)
        var sigs = Set<Data>()
        for tpl in VMTrampolineTemplate.allCases {
        let stub = try VMPatchRewriter.buildTrampoline(
                functionId: fid,
                functionEntryVMA: entry,
                vmEntryVMA: vm,
                template: tpl
            )
            sigs.insert(stub)
        }
        XCTAssertEqual(sigs.count, VMTrampolineTemplate.allCases.count, "each template should yield a distinct encoding")
    }

    func testDispatchKeystreamObfuscatesClassTableOnDisk() {
        let table = VMOpcodeTable(seed: 0xC001_D00D)
        let emitter = VMBytecodeEmitter()
        let programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (1, 0x1000, .full, [VMInstruction(op: .nop)])
        ]
        let plain = emitter.emit(programs: programs, opcodeTable: table, options: VMM2EmitOptions(dispatchTableKeystream: false))
        let enc = emitter.emit(programs: programs, opcodeTable: table, options: VMM2EmitOptions(dispatchTableKeystream: true))
        let plainVersion = VMBytecodeFormat.readUInt32LE(plain.dispatch, offset: 4)
        let encVersion = VMBytecodeFormat.readUInt32LE(enc.dispatch, offset: 4)
        let plainClassOffset = plainVersion >= VMBytecodeFormat.dispatchABIVersionV2 ? (16 + VMBytecodeFormat.dispatchSeedBytes) : 16
        let encClassOffset = encVersion >= VMBytecodeFormat.dispatchABIVersionV2 ? (16 + VMBytecodeFormat.dispatchSeedBytes) : 16
        let slicePlain = plain.dispatch[plainClassOffset..<(plainClassOffset + VMBytecodeFormat.dispatchTableSize)]
        let sliceEnc = enc.dispatch[encClassOffset..<(encClassOffset + VMBytecodeFormat.dispatchTableSize)]
        XCTAssertNotEqual(Data(slicePlain), Data(sliceEnc))
        XCTAssertEqual(encVersion, VMBytecodeFormat.dispatchABIVersionV2)
        let flags = VMBytecodeFormat.readUInt32LE(enc.dispatch, offset: 12)
        XCTAssertNotEqual(flags & VMBytecodeFormat.DispatchHeaderFlags.classTableKeystream, 0)
        let recovered = VMBytecodeEmitter.decryptDispatchClassTable(
            payload: enc.dispatch,
            opcodeTableSeed: table.seed,
            material: 0
        )
        XCTAssertEqual(recovered, [UInt8](slicePlain))
    }

    func testImmediateKeystreamV3EncodesNonPlainImmediates() {
        let table = VMOpcodeTable(seed: 7)
        let emitter = VMBytecodeEmitter()
        let ins = VMInstruction(op: .addLane, immediate: 0x1111_2222_3333_4444)
        let programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (functionId: 0x99, entryVMA: 0x2000, tier: .partial, instructions: [ins, VMInstruction(op: .halt)])
        ]
        let baseOpts = VMM2EmitOptions(handlerVariantSeed: 0, perEntryVpcEnabled: false)
        let plain = emitter.emit(programs: programs, opcodeTable: table, options: baseOpts)
        let encOpts = VMM2EmitOptions(
            handlerVariantSeed: 0,
            perEntryVpcEnabled: false,
            immediateKeystream: true,
            immediateKeystreamMaterial: 0x1234_5678_ABCD_EF00
        )
        let enc = emitter.emit(programs: programs, opcodeTable: table, options: encOpts)
        let vPlain = VMBytecodeFormat.readUInt32LE(plain.bytecode, offset: 4)
        let vEnc = VMBytecodeFormat.readUInt32LE(enc.bytecode, offset: 4)
        XCTAssertEqual(vPlain, VMBytecodeFormat.bytecodeABIVersionV2)
        XCTAssertEqual(vEnc, VMBytecodeFormat.bytecodeABIVersionV3)
        let fEnc = VMBytecodeFormat.readUInt32LE(enc.bytecode, offset: 12)
        XCTAssertNotEqual(fEnc & VMBytecodeFormat.BytecodeFlags.immediateKeystream, 0)
        let hdrTotal = VMBytecodeEmitter.bytecodeHeaderTotalBytes(version: vEnc, flags: fEnc)
        XCTAssertEqual(hdrTotal, 16 + VMBytecodeFormat.vpcAffineBytes + 8)
        let root = VMBytecodeFormat.readUInt64LE(enc.bytecode, offset: hdrTotal - 8)
        XCTAssertEqual(root, encOpts.immediateKeystreamMaterial)
        let entryBase = hdrTotal
        let bcOff = Int(VMBytecodeFormat.readUInt32LE(enc.bytecode, offset: entryBase + 20))
        let immOff = bcOff + 1
        let wEnc = VMBytecodeFormat.readUInt64LE(enc.bytecode, offset: immOff)
        XCTAssertNotEqual(wEnc, ins.immediate)
        let dec = VMBytecodeEmitter.decodeWireImmediate(
            encoded: wEnc,
            functionId: 0x99,
            pcIndex: 0,
            keystreamRoot: root
        )
        XCTAssertEqual(dec, ins.immediate)
    }

    func testVMPolicyParsesDispatchAndImmediateKeystreamFlags() {
        let yaml = """
        version: 5
        hardening:
          dispatch_table_keystream: true
          bytecode_immediate_keystream: true
        functions:
          full:
            - _x
        """
        let p = VMPolicyConfig.parse(yaml)
        XCTAssertTrue(p.hardening.dispatchTableKeystream)
        XCTAssertTrue(p.hardening.bytecodeImmediateKeystream)
    }

    func testEntryExecutionProfileEncodedAndDeterministicPerSeed() {
        let table = VMOpcodeTable(seed: 0x3333_4444)
        let emitter = VMBytecodeEmitter()
        let programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (functionId: 0x101, entryVMA: 0x2000, tier: .full, instructions: [VMInstruction(op: .rawRegion, immediate: 0xAA55), VMInstruction(op: .halt)])
        ]
        let opts = VMM2EmitOptions(handlerVariantSeed: 0x5566_7788, perEntryVpcEnabled: false)
        let p1 = emitter.emit(programs: programs, opcodeTable: table, options: opts)
        let p2 = emitter.emit(programs: programs, opcodeTable: table, options: opts)
        XCTAssertEqual(p1.bytecode, p2.bytecode, "same seed/options should be reproducible")

        let e1 = parsedEntry(in: p1.bytecode, index: 0)
        let profile = VMBytecodeEmitter.unpackEntryExecutionProfile(e1.reserved)
        XCTAssertNotNil(profile, "extended execution profile marker should be present")
        XCTAssertGreaterThanOrEqual(profile?.maxSubcallDepth ?? 0, 2)
        XCTAssertLessThanOrEqual(profile?.maxSubcallDepth ?? 100, 16)
    }

    func testEntryExecutionProfileChangesAcrossSeed() {
        let table = VMOpcodeTable(seed: 77)
        let emitter = VMBytecodeEmitter()
        let program: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (functionId: 0xABCD_EF01, entryVMA: 0x1200, tier: .partial, instructions: [VMInstruction(op: .nop), VMInstruction(op: .halt)])
        ]
        let a = emitter.emit(
            programs: program,
            opcodeTable: table,
            options: VMM2EmitOptions(handlerVariantSeed: 0x1111, perEntryVpcEnabled: false)
        )
        let b = emitter.emit(
            programs: program,
            opcodeTable: table,
            options: VMM2EmitOptions(handlerVariantSeed: 0x2222, perEntryVpcEnabled: false)
        )
        let pa = VMBytecodeEmitter.unpackEntryExecutionProfile(parsedEntry(in: a.bytecode, index: 0).reserved)
        let pb = VMBytecodeEmitter.unpackEntryExecutionProfile(parsedEntry(in: b.bytecode, index: 0).reserved)
        XCTAssertNotNil(pa)
        XCTAssertNotNil(pb)
        XCTAssertNotEqual(pa, pb, "seed should drive profile polymorphism")
    }

    func testSubcallDepthAndMixedPredicateProfilesVaryAcrossFunctions() {
        let table = VMOpcodeTable(seed: 19)
        let emitter = VMBytecodeEmitter()
        var programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = []
        for i in 0..<12 {
            programs.append((functionId: UInt64(0x9000 + i), entryVMA: UInt64(0x4000 + i * 0x20), tier: .partial, instructions: [VMInstruction(op: .nop), VMInstruction(op: .halt)]))
        }
        let payload = emitter.emit(
            programs: programs,
            opcodeTable: table,
            options: VMM2EmitOptions(handlerVariantSeed: 0xFEED_BEEF, perEntryVpcEnabled: false)
        )
        var depths = Set<UInt8>()
        var mixes = Set<UInt8>()
        for i in 0..<programs.count {
            let entry = parsedEntry(in: payload.bytecode, index: i)
            let profile = VMBytecodeEmitter.unpackEntryExecutionProfile(entry.reserved)
            XCTAssertNotNil(profile)
            depths.insert(profile?.maxSubcallDepth ?? 0)
            mixes.insert(profile?.mixedPredicateProfile ?? 0)
        }
        XCTAssertGreaterThan(depths.count, 1, "subcall depth should not be a fixed shallow constant")
        XCTAssertGreaterThan(mixes.count, 1, "mixed predicate profiles should vary across functions")
    }

    func testBranchAndCallOpsEncodeIntoRecoverableLogicalClasses() {
        let table = VMOpcodeTable(seed: 0x1234_5678)
        let emitter = VMBytecodeEmitter()
        let condWord = UInt64(0x5400_0020) // B.EQ +1 insn (imm19=1)
        let program: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (
                functionId: 0xB1,
                entryVMA: 0x3000,
                tier: .full,
                instructions: [
                    VMInstruction(op: .branchRel, immediate: 18),
                    VMInstruction(op: .call, immediate: UInt64(bitPattern: Int64(-9))),
                    VMInstruction(op: .branchCond, immediate: condWord),
                    VMInstruction(op: .halt),
                ]
            )
        ]
        let payload = emitter.emit(
            programs: program,
            opcodeTable: table,
            options: VMM2EmitOptions(handlerVariantSeed: 0x66, perEntryVpcEnabled: false)
        )
        let dispatchTable = dispatchClassTable(from: payload.dispatch)
        let entry = parsedEntry(in: payload.bytecode, index: 0)
        let ops: [UInt8] = (0..<4).map { i in
            let raw = payload.bytecode[entry.bytecodeOffset + i * 9]
            return dispatchTable[Int(raw)]
        }
        XCTAssertEqual(ops, [VMLogicalOp.branchRel.rawValue, VMLogicalOp.call.rawValue, VMLogicalOp.branchCond.rawValue, VMLogicalOp.halt.rawValue])
        XCTAssertNotNil(VMBytecodeEmitter.unpackEntryExecutionProfile(entry.reserved))
    }

    func testLifterRecognizesMovWideAndBranchPatterns() {
        let movz = Data([0x00, 0x00, 0x80, 0xD2]) // MOVZ X0, #0
        let lifter = ARM64Lifter()
        let m = lifter.liftPrologue(bytes: movz, maxInstructions: 8)
        XCTAssertEqual(m.first?.op, VMLogicalOp.movWide)

        let cbz = Data([0x00, 0x00, 0x00, 0xB4]) // CBZ X0, +0 (imm14=0)
        let c = lifter.liftPrologue(bytes: cbz, maxInstructions: 8)
        XCTAssertEqual(c.first?.op, VMLogicalOp.branchCond)

        let bCond = Data([0x00, 0x00, 0x00, 0x54]) // B.EQ +0
        let b = lifter.liftPrologue(bytes: bCond, maxInstructions: 8)
        XCTAssertEqual(b.first?.op, VMLogicalOp.branchCond)
    }

    func testLifterLoadStoreAndConditionalSelectCategories() {
        let lifter = ARM64Lifter()
        let ldr = Data([0x20, 0x00, 0x40, 0xF9]) // LDR X0, [X1, #0]
        let ld = lifter.liftPrologue(bytes: ldr, maxInstructions: 4)
        XCTAssertEqual(ld.first?.op, VMLogicalOp.loadStore)

        let csel = Data([0x20, 0x0C, 0x82, 0x9A]) // CSEL X0, X1, X2, EQ
        let cs = lifter.liftPrologue(bytes: csel, maxInstructions: 4)
        XCTAssertEqual(cs.first?.op, VMLogicalOp.condSelect)
    }

    func testLifterRecognizesAdrLogicalImmAndIndirectBranch() {
        let lifter = ARM64Lifter()
        let adr = Data([0x00, 0x00, 0x00, 0x10]) // ADR X0, #0
        let a = lifter.liftPrologue(bytes: adr, maxInstructions: 4)
        XCTAssertEqual(a.first?.op, VMLogicalOp.adrAdd)

        let andImm = Data([0x20, 0x88, 0x03, 0x92]) // AND X0, X1, #0xFF (typical mask)
        let ai = lifter.liftPrologue(bytes: andImm, maxInstructions: 4)
        XCTAssertEqual(ai.first?.op, VMLogicalOp.andLane)

        let blr = Data([0x00, 0x00, 0x3F, 0xD6]) // BLR X0
        let br = lifter.liftPrologue(bytes: blr, maxInstructions: 4)
        XCTAssertEqual(br.first?.op, VMLogicalOp.rawRegion)
        XCTAssertEqual(br.first?.rawCategory, VMRawRegionCategory.branchTest)
    }

    func testBytecodePayloadAppendsProducerChunkManifest() {
        let table = VMOpcodeTable(seed: 0xBEEF)
        let emitter = VMBytecodeEmitter()
        let programs: [(UInt64, UInt64, VMBytecodeFormat.TierCode, [VMInstruction])] = [
            (1, 0x1000, .full, [VMInstruction(op: .nop), VMInstruction(op: .halt)])
        ]
        let payload = emitter.emit(programs: programs, opcodeTable: table)
        let tailLen = 4 + 4 + 4 + 8 + 4
        XCTAssertGreaterThanOrEqual(payload.bytecode.count, tailLen)
        let m = VMBytecodeFormat.readUInt32LE(payload.bytecode, offset: payload.bytecode.count - tailLen)
        XCTAssertEqual(m, VMBytecodeEmitter.producerChunkManifestMagic)
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
        XCTAssertEqual(p[0].op, .adrAdd)
        XCTAssertEqual(p[0].immediate, 0x9100_0000_9000_0000)
    }

    private func parsedEntry(in bytecode: Data, index: Int) -> (reserved: UInt32, bytecodeOffset: Int, bytecodeLength: Int) {
        let version = VMBytecodeFormat.readUInt32LE(bytecode, offset: 4)
        let flags = VMBytecodeFormat.readUInt32LE(bytecode, offset: 12)
        let headerTotal = VMBytecodeEmitter.bytecodeHeaderTotalBytes(version: version, flags: flags)
        let stride = VMBytecodeFormat.entryCoreSize
            + (((flags & VMBytecodeFormat.BytecodeFlags.perEntryVpc) != 0) ? VMBytecodeFormat.vpcAffineBytes : 0)
        let base = headerTotal + index * stride
        let reserved = VMBytecodeFormat.readUInt32LE(bytecode, offset: base + 28)
        let offset = Int(VMBytecodeFormat.readUInt32LE(bytecode, offset: base + 20))
        let length = Int(VMBytecodeFormat.readUInt32LE(bytecode, offset: base + 24))
        return (reserved, offset, length)
    }

    private func dispatchClassTable(from dispatch: Data) -> [UInt8] {
        let version = VMBytecodeFormat.readUInt32LE(dispatch, offset: 4)
        let classOffset = version >= VMBytecodeFormat.dispatchABIVersionV2 ? (16 + VMBytecodeFormat.dispatchSeedBytes) : 16
        return [UInt8](dispatch[classOffset..<(classOffset + VMBytecodeFormat.dispatchTableSize)])
    }

    func testBytecodeSegmentRuntimeSha256FlagEmitted() {
        let table = VMOpcodeTable(seed: 77)
        let emitter = VMBytecodeEmitter()
        let programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = [
            (1, 0x1000, .full, [VMInstruction(op: .nop), VMInstruction(op: .halt)])
        ]
        let payloads = emitter.emit(
            programs: programs,
            opcodeTable: table,
            options: VMM2EmitOptions(
                handlerVariantSeed: 1,
                perEntryVpcEnabled: false,
                m3: VMM3EmitOptions(bytecodeSegmentRuntimeSha256: true)
            )
        )
        let flags = payloads.bytecode.withUnsafeBytes { buf in
            buf.load(fromByteOffset: 12, as: UInt32.self)
        }
        XCTAssertNotEqual(flags & VMBytecodeFormat.BytecodeFlags.bcSegmentRuntimeSha256, 0)
    }

    func testVMPolicyParsesBytecodeSegmentRuntimeSha256() {
        let yaml = """
        version: 6
        hardening:
          bytecode_segment_runtime_sha256: true
        functions:
          full:
            - _x
        """
        let p = VMPolicyConfig.parse(yaml)
        XCTAssertTrue(p.hardening.bytecodeSegmentRuntimeSha256)
    }

    func testVMPolicyParsesAntiSymbolicHeavy() {
        let yaml = """
        version: 7
        hardening:
          anti_symbolic_heavy: true
        functions:
          full:
            - _x
        """
        let p = VMPolicyConfig.parse(yaml)
        XCTAssertTrue(p.hardening.antiSymbolicHeavy)
    }

    func testDiophantineMathTrapCountExpanded() {
        let yaml = """
        version: 7
        hardening:
          anti_symbolic_heavy: true
        functions:
          full:
            - _x
        """
        let p = VMPolicyConfig.parse(yaml)
        XCTAssertTrue(p.hardening.antiSymbolicHeavy, "anti_symbolic_heavy must enable expanded math traps")
    }

    func testBytecodeEmitterSetsAntiSymbolicHeavyFlag() {
        let table = VMOpcodeTable(seed: 123)
        let emitter = VMBytecodeEmitter()
        let payloads = emitter.emit(
            programs: [
                (functionId: 1, entryVMA: 0x1000, tier: .full, instructions: [VMInstruction(op: .nop), VMInstruction(op: .halt)])
            ],
            opcodeTable: table,
            options: VMM2EmitOptions(handlerVariantSeed: 1, perEntryVpcEnabled: false, antiSymbolicHeavy: true)
        )
        let flags = payloads.bytecode.withUnsafeBytes { buf in
            buf.load(fromByteOffset: 12, as: UInt32.self)
        }
        XCTAssertNotEqual(flags & VMBytecodeFormat.BytecodeFlags.antiSymbolicHeavy, 0)
    }

    func testArmorSafetyProfileCLITokens() {
        XCTAssertEqual(ArmorSafetyProfile(cliToken: "standard"), .standard)
        XCTAssertEqual(ArmorSafetyProfile(cliToken: "appstore-safe"), .appStoreSafe)
        XCTAssertNil(ArmorSafetyProfile(cliToken: "nope"))
    }

    func testAppStoreSafeBundledPolicyYAMLsExistAndParse() throws {
        let repoRoot = URL(fileURLWithPath: #file)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let vmpURL = repoRoot.appendingPathComponent("RiskDetectorApp/vmp_policy_appstore_safe.yaml")
        XCTAssertTrue(FileManager.default.fileExists(atPath: vmpURL.path))
        let vmpText = try String(contentsOf: vmpURL, encoding: .utf8)
        let vmp = VMPolicyConfig.parse(vmpText)
        XCTAssertFalse(vmp.hardening.protectVmInterpreterWithCff)
        XCTAssertFalse(vmp.hardening.interpreterSelfIntegrityCheck)
        XCTAssertFalse(vmp.hardening.antiSymbolicHeavy)
        XCTAssertFalse(vmp.hardening.bytecodeSegmentRuntimeSha256)

        let cffPath = ArmorPolicyPathResolver.resolveDefaultCffPolicyPath(profile: .appStoreSafe)
        XCTAssertNotNil(cffPath)
        XCTAssertTrue(cffPath!.contains("cff_policy_appstore_safe.yaml"))
    }
}
