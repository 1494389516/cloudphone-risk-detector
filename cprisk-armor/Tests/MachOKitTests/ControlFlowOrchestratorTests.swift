import ControlFlowOrchestrator
import MachOKit
import XCTest

final class ControlFlowOrchestratorTests: XCTestCase {
    func testFunctionCFFPolicyParsesTiersAndFlags() throws {
        let raw = """
        version: 2
        functions:
          heavy:
            - RiskDetectionEngine.collectAndAugmentSignals
            - anti_debug_watchdog.cprisk_watchdog_run_iteration
          medium:
            - ConditionNode.evaluate
          light:
            - MutationPlanner.maybeShuffle
          never:
            - direct_syscall.cprisk_direct_syscall0
          regionOnly:
            - RiskDetectionEngine.evaluate
        anti_deobfuscation:
          enable_runtime_salt: true
          enable_fake_state_release_only: true
          enable_multi_dispatcher: true
          enable_default_poison_for_heavy: true
          enable_pass8_cff_awareness: true
        """

        let policy = try FunctionCFFPolicy.parse(raw)

        XCTAssertEqual(policy.version, 2)
        XCTAssertEqual(policy.tier(for: "RiskDetectionEngine.collectAndAugmentSignals"), .heavy)
        XCTAssertEqual(policy.tier(for: "ConditionNode.evaluate"), .medium)
        XCTAssertEqual(policy.tier(for: "MutationPlanner.maybeShuffle"), .light)
        XCTAssertEqual(policy.tier(for: "direct_syscall.cprisk_direct_syscall0"), .never)
        XCTAssertEqual(policy.tier(for: "RiskDetectionEngine.evaluate"), .regionOnly)
        XCTAssertTrue(policy.antiDeobfuscation.enableRuntimeSalt)
        XCTAssertTrue(policy.antiDeobfuscation.enablePass8CFFAwareness)
    }

    func testOrchestratorBuildPlansReflectTierSpecificDefaults() throws {
        let policy = FunctionCFFPolicy(
            version: 2,
            heavy: ["DecisionTree.decide"],
            medium: ["ConditionNode.evaluate"],
            light: ["MutationPlanner.maybeShuffle"],
            never: ["direct_syscall.cprisk_direct_syscall0"],
            regionOnly: ["RiskDetectionEngine.evaluate"],
            antiDeobfuscation: AntiDeobfuscationOptions()
        )

        let orchestrator = ControlFlowOrchestrator(policy: policy)
        let plans = orchestrator.buildPlans()

        let heavyPlan = try XCTUnwrap(plans.first { $0.symbol == "DecisionTree.decide" })
        let mediumPlan = try XCTUnwrap(plans.first { $0.symbol == "ConditionNode.evaluate" })
        let lightPlan = try XCTUnwrap(plans.first { $0.symbol == "MutationPlanner.maybeShuffle" })
        let neverPlan = try XCTUnwrap(plans.first { $0.symbol == "direct_syscall.cprisk_direct_syscall0" })
        let regionPlan = try XCTUnwrap(plans.first { $0.symbol == "RiskDetectionEngine.evaluate" })

        XCTAssertEqual(heavyPlan.tier, .heavy)
        XCTAssertTrue(heavyPlan.stateEncodingPlan.usesRuntimeSalt)
        XCTAssertTrue(heavyPlan.runtimeDependencyPlan.pass8Aware)
        XCTAssertEqual(heavyPlan.antiDeobfuscationPlan.runtimeSaltMode, .coupled)
        XCTAssertTrue(heavyPlan.antiDeobfuscationPlan.fakeStateReleaseOnlyEnabled)
        XCTAssertTrue(heavyPlan.antiDeobfuscationPlan.multiDispatcherEnabled)
        XCTAssertTrue(heavyPlan.antiDeobfuscationPlan.pass8CFFAwarenessEnabled)

        XCTAssertEqual(mediumPlan.tier, .medium)
        XCTAssertEqual(mediumPlan.antiDeobfuscationPlan.runtimeSaltMode, .advisory)
        XCTAssertFalse(mediumPlan.antiDeobfuscationPlan.multiDispatcherEnabled)

        XCTAssertEqual(lightPlan.tier, .light)
        XCTAssertEqual(lightPlan.antiDeobfuscationPlan.runtimeSaltMode, .advisory)
        XCTAssertFalse(lightPlan.antiDeobfuscationPlan.fakeStateReleaseOnlyEnabled)
        XCTAssertFalse(lightPlan.antiDeobfuscationPlan.multiDispatcherEnabled)
        XCTAssertFalse(lightPlan.antiDeobfuscationPlan.pass8CFFAwarenessEnabled)

        XCTAssertEqual(neverPlan.tier, .never)
        XCTAssertFalse(neverPlan.antiDeobfuscationPlan.runtimeSaltEnabled)
        XCTAssertEqual(neverPlan.antiDeobfuscationPlan.runtimeSaltMode, .disabled)

        XCTAssertEqual(regionPlan.tier, .regionOnly)
        XCTAssertTrue(regionPlan.antiDeobfuscationPlan.runtimeSaltEnabled)
        XCTAssertEqual(regionPlan.antiDeobfuscationPlan.runtimeSaltMode, .coupled)
        XCTAssertTrue(regionPlan.antiDeobfuscationPlan.fakeStateReleaseOnlyEnabled)
        XCTAssertFalse(regionPlan.antiDeobfuscationPlan.multiDispatcherEnabled)
        XCTAssertTrue(regionPlan.antiDeobfuscationPlan.pass8CFFAwarenessEnabled)
    }

    func testHeavyTierStateEncodingSupportsAffineOrAddRotateXor() {
        let policy = FunctionCFFPolicy(
            version: 2,
            heavy: ["DecisionTree.decide"],
            medium: [],
            light: [],
            never: [],
            regionOnly: [],
            antiDeobfuscation: AntiDeobfuscationOptions()
        )
        let plan = ControlFlowOrchestrator(policy: policy, seedMaterial: 0x2026).buildPlans().first
        XCTAssertNotNil(plan)
        XCTAssertTrue(
            plan?.stateEncodingPlan.style == .addRotateXor || plan?.stateEncodingPlan.style == .affine,
            "heavy tier should use a stronger codec style"
        )
    }

    func testRepositoryPolicyLightTierMatchesCurrentFunctionNames() throws {
        let policyURL = try ControlFlowOrchestrator.resolvePolicyURL()
        let policy = try FunctionCFFPolicy.load(from: policyURL)

        let expectedLight: Set<String> = [
            "RandomizedDetection.detect",
            "AntiTamperingDetector.detect",
            "DetectorRegistry.detectAll",
            "ChallengeTrigger.shouldTriggerBlindChallenge",
            "AntiTamperingSignalProvider.signals",
            "MutationPlanner.maybeShuffle"
        ]
        let legacyNames: Set<String> = [
            "DetectorRegistry.dispatchSensitiveDetectors",
            "ChallengeTrigger.dispatch",
            "AntiTamperingSignalProvider.collect",
            "MutationStrategy.shuffleChecks"
        ]

        XCTAssertEqual(Set(policy.light), expectedLight)
        XCTAssertTrue(Set(policy.light).isDisjoint(with: legacyNames))
        for symbol in expectedLight {
            XCTAssertEqual(policy.tier(for: symbol), .light)
        }
    }

    func testPass9RewritesManagedFunctionsAndKeepsNeverTierUntouched() throws {
        let fixtureURL = try Self.writePass9Fixture(
            named: "pass9_binary_rewrite",
            symbols: [
                ("_DecisionTree.decide", 0x1800),
                ("_MutationPlanner.maybeShuffle", 0x1820),
                ("_RiskDetectionEngine.evaluate", 0x1840),
                ("_direct_syscall.cprisk_direct_syscall0", 0x1860)
            ],
            functionBlocks: [
                [0xAA0A03E9, 0x9100018B, 0xD10001CD, 0x8A10020F, 0xAA120251, 0xD503201F, 0xAA1403F4, 0x910002B5],
                [0xAA0803E8, 0x91000129, 0xD100014A, 0x8A0B016B, 0xAA0C018C, 0xD503201F, 0xAA0D01AD, 0x910001CE],
                [0xAA0203E1, 0x91000062, 0xD1000083, 0x8A040084, 0xAA0500A5, 0xD503201F, 0xAA0600C6, 0x910000E7],
                [0xAA1603F6, 0x910002D6, 0xD10002D6, 0x8A1702F7, 0xAA180318, 0xD503201F, 0xAA1A03FA, 0x9100039B]
            ]
        )
        let policyURL = try Self.writePass9Policy(
            named: "pass9_binary_rewrite",
            heavy: ["DecisionTree.decide"],
            light: ["MutationPlanner.maybeShuffle"],
            never: ["direct_syscall.cprisk_direct_syscall0"],
            regionOnly: ["RiskDetectionEngine.evaluate"]
        )
        defer {
            try? FileManager.default.removeItem(at: fixtureURL)
            try? FileManager.default.removeItem(at: policyURL)
        }

        let file = try MachOFile(url: fixtureURL)
        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let before = try textSection.readContent(from: file.data)

        let result = try ControlFlowOrchestratorPass(policyFilePath: policyURL.path).execute(
            on: file,
            config: PassConfig(verbose: true)
        )

        let after = try textSection.readContent(from: file.data)
        XCTAssertGreaterThan(result.itemsProcessed, 0)
        XCTAssertGreaterThan(result.bytesModified, 0)
        XCTAssertEqual(result.bytesModified % 4, 0, "Pass9 should patch whole ARM64 instructions")
        XCTAssertNotEqual(before, after, "Pass9 should modify __TEXT.__text bytes")
        XCTAssertEqual(before.count, after.count, "Pass9 should keep __text size unchanged")

        let changedOffsets = Self.changedByteOffsets(before: before, after: after)
        XCTAssertFalse(changedOffsets.isEmpty)
        XCTAssertTrue(changedOffsets.allSatisfy { $0 >= 0 && $0 < Int(textSection.size) })

        let neverRange = 0x60..<0x80
        XCTAssertEqual(
            before.subdata(in: neverRange),
            after.subdata(in: neverRange),
            "never-tier function bytes must stay untouched"
        )

        XCTAssertTrue(result.details.contains(where: { $0.contains("modified functions:") }))
        XCTAssertTrue(result.details.contains(where: { $0.contains("DecisionTree.decide") }))
        XCTAssertTrue(result.details.contains(where: { $0.contains("__text+0x") }))
        XCTAssertNoThrow(try file.validateStructure())
    }

    func testPass9SkipsUnsafeFunctionAndReportsReason() throws {
        let fixtureURL = try Self.writePass9Fixture(
            named: "pass9_skip_reason",
            symbols: [
                ("_UnsafeTarget.block", 0x1800)
            ],
            functionBlocks: [
                [0xA9BF7BFD, 0x910003FD, 0xF9000BF3, 0xD63F0260, 0xA8C17BFD, 0xD65F03C0, 0x14000000, 0xB9400008]
            ]
        )
        let policyURL = try Self.writePass9Policy(
            named: "pass9_skip_reason",
            heavy: ["UnsafeTarget.block"],
            light: [],
            never: [],
            regionOnly: []
        )
        defer {
            try? FileManager.default.removeItem(at: fixtureURL)
            try? FileManager.default.removeItem(at: policyURL)
        }

        let file = try MachOFile(url: fixtureURL)
        let result = try ControlFlowOrchestratorPass(policyFilePath: policyURL.path).execute(
            on: file,
            config: PassConfig(verbose: true)
        )

        XCTAssertEqual(result.itemsProcessed, 0)
        XCTAssertEqual(result.bytesModified, 0)
        XCTAssertTrue(result.details.contains(where: { $0.contains("skipped functions: 1") }))
        XCTAssertTrue(result.details.contains(where: { $0.contains("insufficient rewritable entry instructions") }))
        XCTAssertNoThrow(try file.validateStructure())
    }

    /// When the switch-style dispatcher lands in a trailing NOP island, structural patches can fully
    /// satisfy the per-function budget even if the prologue contains no neutral-decodable slots.
    func testPass9StructuralPathOutsidePrologueCountsTowardBudget() throws {
        let nop: UInt32 = 0xD503_201F
        let filler: UInt32 = 0xFFFF_FFFF
        var block = [UInt32](repeating: filler, count: 36)
        block.append(contentsOf: [nop, nop, nop, nop])

        let fixtureURL = try Self.writePass9Fixture(
            named: "pass9_structural_only_deep",
            symbols: [
                ("_HeavyTarget.structuralDeep", 0x1800)
            ],
            functionBlocks: [block]
        )
        let policyURL = try Self.writePass9Policy(
            named: "pass9_structural_only_deep",
            heavy: ["HeavyTarget.structuralDeep"],
            light: [],
            never: [],
            regionOnly: []
        )
        defer {
            try? FileManager.default.removeItem(at: fixtureURL)
            try? FileManager.default.removeItem(at: policyURL)
        }

        let file = try MachOFile(url: fixtureURL)
        let result = try ControlFlowOrchestratorPass(policyFilePath: policyURL.path).execute(
            on: file,
            config: PassConfig(verbose: false)
        )

        XCTAssertGreaterThan(result.itemsProcessed, 0)
        XCTAssertGreaterThan(result.bytesModified, 0)
        XCTAssertNoThrow(try file.validateStructure())
    }

    /// Three unconditional blocks forming an in-function cycle (B→+4, B→+8, B→entry).
    /// A trailing symbol bounds VM range so `functionSizeBytes` is exactly 12 (no padding inside the function).
    func testPass9MultiBasicBlockReorderShufflesThreeBlockCycleAndPreservesBranchSemantics() throws {
        let bForward4 = Self.encodeARM64UnconditionalB(deltaBytes: 4)
        let bBack8 = Self.encodeARM64UnconditionalB(deltaBytes: -8)
        let fixtureURL = try Self.writePass9Fixture(
            named: "pass9_multi_bb_cycle",
            symbols: [
                ("_MultiBB.cycle3", 0x1800),
                ("_MultiBB.boundary", 0x180C)
            ],
            functionBlocks: [
                [bForward4, bForward4, bBack8],
                [0xD503_201F]
            ]
        )
        // Light tier: requiredPatchSlots == 1 so a 2–3 instruction structural rewrite is not rolled back
        // when there are no neutral-eligible slots (function is all unconditional branches).
        // The boundary symbol must be a managed tier (not `never`) so it appears in `matchedCandidates`
        // and caps the VM range of `MultiBB.cycle3` at 12 bytes.
        let policyURL = try Self.writePass9Policy(
            named: "pass9_multi_bb_cycle",
            heavy: [],
            light: ["MultiBB.cycle3", "MultiBB.boundary"],
            never: [],
            regionOnly: []
        )
        defer {
            try? FileManager.default.removeItem(at: fixtureURL)
            try? FileManager.default.removeItem(at: policyURL)
        }

        let file = try MachOFile(url: fixtureURL)
        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let textStart = Int(textSection.offset)
        let fnFileOffset = textStart + 0x0 // symbol at __text base
        let functionSpan = 12

        let before = try textSection.readContent(from: file.data)
        let targetsBefore = Self.unconditionalBranchTargets(
            in: before,
            baseFileOffset: fnFileOffset,
            fromSectionOffset: 0,
            byteCount: functionSpan
        )

        let result = try ControlFlowOrchestratorPass(policyFilePath: policyURL.path).execute(
            on: file,
            config: PassConfig(verbose: true)
        )

        let after = try textSection.readContent(from: file.data)
        let targetsAfter = Self.unconditionalBranchTargets(
            in: after,
            baseFileOffset: fnFileOffset,
            fromSectionOffset: 0,
            byteCount: functionSpan
        )

        XCTAssertGreaterThan(result.itemsProcessed, 0)
        XCTAssertTrue(
            result.details.contains(where: { $0.contains("CFG multi-bb reorder") }),
            "expected multi-basic-block reorder to win over branch-stub shuffle; details=\(result.details)"
        )

        let multiPatches = result.details.filter { $0.contains("CFG multi-bb reorder") }
        XCTAssertGreaterThanOrEqual(multiPatches.count, 1)

        let structuralChangeLines = result.details.filter { line in
            line.contains("patch __text+") && line.contains("CFG multi-bb reorder")
        }
        XCTAssertGreaterThanOrEqual(
            structuralChangeLines.count,
            2,
            "multi-bb reorder should move more than one instruction slot; got \(structuralChangeLines.count)"
        )

        XCTAssertEqual(
            targetsBefore.sorted(),
            targetsAfter.sorted(),
            "PC-relative branch fixup must preserve the multiset of jump targets"
        )
        for t in targetsAfter {
            XCTAssertTrue(
                [fnFileOffset, fnFileOffset + 4, fnFileOffset + 8].contains(t),
                "rewritten branches should still target only original block entry PCs"
            )
        }

        XCTAssertNoThrow(try file.validateStructure())
    }

    /// Unconditional branch to an address that is not a block leader makes multi-bb reorder bail out.
    /// With only B instructions, neutral substitution cannot run → Pass9 skips and reports the reason.
    func testPass9MultiBasicBlockReorderAbortsOnExternalBranchTargetAndSkipsWithReason() throws {
        let bForward4 = Self.encodeARM64UnconditionalB(deltaBytes: 4)
        let bToExternal = Self.encodeARM64UnconditionalB(deltaBytes: 0x4000)
        let fixtureURL = try Self.writePass9Fixture(
            named: "pass9_multi_bb_external_target",
            symbols: [
                ("_MultiBB.badExit", 0x1800),
                ("_MultiBB.boundary2", 0x180C)
            ],
            functionBlocks: [
                [bForward4, bForward4, bToExternal],
                [0xD503_201F]
            ]
        )
        let policyURL = try Self.writePass9Policy(
            named: "pass9_multi_bb_external_target",
            heavy: ["MultiBB.badExit"],
            light: ["MultiBB.boundary2"],
            never: [],
            regionOnly: []
        )
        defer {
            try? FileManager.default.removeItem(at: fixtureURL)
            try? FileManager.default.removeItem(at: policyURL)
        }

        let file = try MachOFile(url: fixtureURL)
        let result = try ControlFlowOrchestratorPass(policyFilePath: policyURL.path).execute(
            on: file,
            config: PassConfig(verbose: true)
        )

        XCTAssertTrue(
            result.details.contains(where: { line in
                line.contains("[skipped]") && line.contains("MultiBB.badExit")
            }),
            "expected badExit to be skipped; details=\(result.details)"
        )
        XCTAssertFalse(result.details.contains(where: { $0.contains("CFG multi-bb reorder") }))
        XCTAssertTrue(result.details.contains(where: { $0.contains("skipped functions: 1") }))
        XCTAssertTrue(
            result.details.contains(where: { $0.contains("insufficient rewritable entry instructions") }),
            "details=\(result.details)"
        )
        XCTAssertNoThrow(try file.validateStructure())
    }

    /// NOP padding run (≥3 words) enables switch-style TBZ/TBNZ-on-WZR dispatcher + dead bogus NOPs; semantics match NOP slide.
    func testPass9SwitchDispatcherInjectedWithBogusAndPreservesLayout() throws {
        let eightData: [UInt32] = [
            0xAA0A03E9, 0x9100018B, 0xD10001CD, 0x8A10020F,
            0xAA120251, 0xD503201F, 0xAA1403F4, 0x910002B5
        ]
        let nopRun = [UInt32](repeating: 0xD503_201F, count: 4)
        let ret: UInt32 = 0xD65F03C0
        let body = eightData + nopRun + [ret]
        let fnBytes = body.count * 4
        let fixtureURL = try Self.writePass9Fixture(
            named: "pass9_switch_dispatcher",
            symbols: [
                ("_Switch.dispatch", 0x1800),
                ("_Switch.boundary", 0x1800 + UInt64(fnBytes))
            ],
            functionBlocks: [
                body,
                [0xD503_201F]
            ]
        )
        let policyURL = try Self.writePass9Policy(
            named: "pass9_switch_dispatcher",
            heavy: ["Switch.dispatch"],
            light: ["Switch.boundary"],
            never: [],
            regionOnly: [],
            enableMultiDispatcher: true
        )
        defer {
            try? FileManager.default.removeItem(at: fixtureURL)
            try? FileManager.default.removeItem(at: policyURL)
        }

        let file = try MachOFile(url: fixtureURL)
        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let textStart = Int(textSection.offset)
        let before = try textSection.readContent(from: file.data)

        let result = try ControlFlowOrchestratorPass(policyFilePath: policyURL.path).execute(
            on: file,
            config: PassConfig(verbose: true)
        )

        let after = try textSection.readContent(from: file.data)
        XCTAssertGreaterThan(result.itemsProcessed, 0)
        XCTAssertNotEqual(before, after)

        XCTAssertTrue(
            result.details.contains(where: { $0.contains("CFG switch dispatcher") }),
            "expected switch dispatcher; details=\(result.details)"
        )
        XCTAssertTrue(result.details.contains(where: { $0.contains("bogus block") }))

        let nopRunSectionOffset = eightData.count * 4
        let head = Self.readWordLE(after, at: nopRunSectionOffset)
        XCTAssertNotEqual(head, 0xD503_201F, "first NOP should become TBZ dispatcher")
        XCTAssertEqual((head >> 24) & 0xFF, 0x36, "live dispatcher should be TBZ (WZR)")

        let dead1 = Self.readWordLE(after, at: nopRunSectionOffset + 4)
        let dead2 = Self.readWordLE(after, at: nopRunSectionOffset + 8)
        XCTAssertNotEqual(dead1, 0xD503_201F, "second slot is unreachable TBZ/TBNZ (dead arm), not NOP")
        XCTAssertNotEqual(dead2, 0xD503_201F, "third slot is unreachable TBZ/TBNZ (dead arm), not NOP")
        XCTAssertEqual((dead1 >> 24) & 0xFF, 0x36, "dead arm[1] is TBZ")
        XCTAssertEqual((dead2 >> 24) & 0xFF, 0x37, "dead arm[2] is TBNZ")

        XCTAssertEqual(Self.readWordLE(after, at: nopRunSectionOffset + 12), 0xD503_201F, "join slot stays NOP")

        let retOffset = nopRunSectionOffset + 16
        XCTAssertEqual(Self.readWordLE(before, at: retOffset), Self.readWordLE(after, at: retOffset), "RET after NOP run unchanged")

        let uBefore = Self.unconditionalBranchTargets(
            in: before,
            baseFileOffset: textStart,
            fromSectionOffset: 0,
            byteCount: body.count * 4
        )
        let uAfter = Self.unconditionalBranchTargets(
            in: after,
            baseFileOffset: textStart,
            fromSectionOffset: 0,
            byteCount: body.count * 4
        )
        XCTAssertEqual(uBefore.sorted(), uAfter.sorted(), "B/BL targets multiset unchanged in function span")

        XCTAssertNoThrow(try file.validateStructure())
    }

    /// Fewer than three consecutive NOPs cannot host the switch dispatcher; Pass9 must fall back without "switch dispatcher" lines.
    func testPass9SwitchDispatcherNotUsedWhenNopRunTooShort() throws {
        let eightData: [UInt32] = [
            0xAA0A03E9, 0x9100018B, 0xD10001CD, 0x8A10020F,
            0xAA120251, 0xD503201F, 0xAA1403F4, 0x910002B5
        ]
        let shortNops = [UInt32](repeating: 0xD503_201F, count: 2)
        let ret: UInt32 = 0xD65F03C0
        let body = eightData + shortNops + [ret]
        let fnBytes = body.count * 4
        let fixtureURL = try Self.writePass9Fixture(
            named: "pass9_switch_short_nop",
            symbols: [
                ("_Switch.shortNop", 0x1800),
                ("_Switch.boundaryShort", 0x1800 + UInt64(fnBytes))
            ],
            functionBlocks: [
                body,
                [0xD503_201F]
            ]
        )
        let policyURL = try Self.writePass9Policy(
            named: "pass9_switch_short_nop",
            heavy: ["Switch.shortNop"],
            light: ["Switch.boundaryShort"],
            never: [],
            regionOnly: [],
            enableMultiDispatcher: true
        )
        defer {
            try? FileManager.default.removeItem(at: fixtureURL)
            try? FileManager.default.removeItem(at: policyURL)
        }

        let file = try MachOFile(url: fixtureURL)
        let result = try ControlFlowOrchestratorPass(policyFilePath: policyURL.path).execute(
            on: file,
            config: PassConfig(verbose: true)
        )

        XCTAssertGreaterThan(result.itemsProcessed, 0)
        XCTAssertFalse(result.details.contains(where: { $0.contains("CFG switch dispatcher") }))
        XCTAssertNoThrow(try file.validateStructure())
    }

    /// With multi-dispatcher off, the same fixture must not apply switch injection (fail-safe path uses other rewrites or neutral only).
    func testPass9SwitchDispatcherSkippedWhenMultiDispatcherDisabled() throws {
        let eightData: [UInt32] = [
            0xAA0A03E9, 0x9100018B, 0xD10001CD, 0x8A10020F,
            0xAA120251, 0xD503201F, 0xAA1403F4, 0x910002B5
        ]
        let nopRun = [UInt32](repeating: 0xD503_201F, count: 4)
        let ret: UInt32 = 0xD65F03C0
        let body = eightData + nopRun + [ret]
        let fnBytes = body.count * 4
        let fixtureURL = try Self.writePass9Fixture(
            named: "pass9_switch_off",
            symbols: [
                ("_Switch.dispatchOff", 0x1800),
                ("_Switch.boundaryOff", 0x1800 + UInt64(fnBytes))
            ],
            functionBlocks: [
                body,
                [0xD503_201F]
            ]
        )
        let policyURL = try Self.writePass9Policy(
            named: "pass9_switch_off",
            heavy: ["Switch.dispatchOff"],
            light: ["Switch.boundaryOff"],
            never: [],
            regionOnly: [],
            enableMultiDispatcher: false
        )
        defer {
            try? FileManager.default.removeItem(at: fixtureURL)
            try? FileManager.default.removeItem(at: policyURL)
        }

        let file = try MachOFile(url: fixtureURL)
        let result = try ControlFlowOrchestratorPass(policyFilePath: policyURL.path).execute(
            on: file,
            config: PassConfig(verbose: true)
        )

        XCTAssertGreaterThan(result.itemsProcessed, 0)
        XCTAssertFalse(result.details.contains(where: { $0.contains("CFG switch dispatcher") }))
        XCTAssertNoThrow(try file.validateStructure())
    }

    func testPass9PerformsBranchStubCFGReorderWithRelocationFixup() throws {
        let fixtureURL = try Self.writePass9Fixture(
            named: "pass9_cfg_reorder_branch_stubs",
            symbols: [
                ("_DecisionTree.decide", 0x1800),
            ],
            functionBlocks: [
                [
                    0xB4000040, // CBZ X0, +8
                    0x14000005, // B +20 (from +4 -> +24)
                    0x14000002, // B +8  (from +8 -> +16)
                    0xAA0A03E9,
                    0x9100018B,
                    0x8A10020F,
                    0xAA120251,
                    0xD503201F,
                ],
            ]
        )
        let policyURL = try Self.writePass9Policy(
            named: "pass9_cfg_reorder_branch_stubs",
            heavy: ["DecisionTree.decide"],
            light: [],
            never: [],
            regionOnly: []
        )
        defer {
            try? FileManager.default.removeItem(at: fixtureURL)
            try? FileManager.default.removeItem(at: policyURL)
        }

        let file = try MachOFile(url: fixtureURL)
        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let before = try textSection.readContent(from: file.data)

        let result = try ControlFlowOrchestratorPass(policyFilePath: policyURL.path).execute(
            on: file,
            config: PassConfig(verbose: true)
        )

        let after = try textSection.readContent(from: file.data)
        XCTAssertGreaterThan(result.itemsProcessed, 0)
        XCTAssertNotEqual(before, after)

        // Head predicate is inverted (CBZ -> CBNZ), and branch stubs are reordered
        // with PC-relative fixup so absolute targets remain stable.
        XCTAssertEqual(Self.readWordLE(after, at: 0x00), 0xB5000040)
        XCTAssertEqual(Self.readWordLE(after, at: 0x04), 0x14000003)
        XCTAssertEqual(Self.readWordLE(after, at: 0x08), 0x14000004)
        XCTAssertTrue(result.details.contains(where: { $0.contains("CFG branch-stub reorder") }))
        XCTAssertNoThrow(try file.validateStructure())
    }

    func testCoverageAdvisorSuggestsSafeDefaults() {
        let policy = FunctionCFFPolicy(
            version: 2,
            heavy: ["DecisionTree.decide"],
            medium: [],
            light: ["DetectorRegistry.detectAll"],
            never: ["direct_syscall.cprisk_direct_syscall0"],
            regionOnly: [],
            antiDeobfuscation: AntiDeobfuscationOptions()
        )

        let suggestion = CFFPolicyCoverageAdvisor.suggestExpansions(
            policy: policy,
            availableSymbols: [
                "_RiskDetectionEngine.collectAndAugmentSignals",
                "_AntiTamperingDetector.detect",
                "_direct_syscall.cprisk_direct_syscall6",
                "_CloudPhoneRiskKitTests.testFoo"
            ]
        )

        XCTAssertTrue(suggestion.heavy.contains("RiskDetectionEngine.collectAndAugmentSignals"))
        XCTAssertTrue(suggestion.light.contains("AntiTamperingDetector.detect"))
        XCTAssertTrue(suggestion.never.contains("direct_syscall.cprisk_direct_syscall6"))
        XCTAssertTrue(suggestion.skipped.contains("CloudPhoneRiskKitTests.testFoo"))
    }

    private static func writePass9Policy(
        named name: String,
        heavy: [String],
        medium: [String] = [],
        light: [String],
        never: [String],
        regionOnly: [String],
        enableMultiDispatcher: Bool = true
    ) throws -> URL {
        let url = temporaryURL(named: "\(name)_policy", ext: "yaml")
        let md = enableMultiDispatcher ? "true" : "false"
        let contents = """
        version: 2
        functions:
          heavy:
        \(yamlList(heavy))
          medium:
        \(yamlList(medium))
          light:
        \(yamlList(light))
          never:
        \(yamlList(never))
          regionOnly:
        \(yamlList(regionOnly))
        anti_deobfuscation:
          enable_runtime_salt: true
          enable_fake_state_release_only: true
          enable_multi_dispatcher: \(md)
          enable_default_poison_for_heavy: true
          enable_pass8_cff_awareness: true
        """
        try contents.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    private static func writePass9Fixture(
        named name: String,
        symbols: [(name: String, vmAddress: UInt64)],
        functionBlocks: [[UInt32]]
    ) throws -> URL {
        let url = temporaryURL(named: name, ext: "macho")
        try makePass9Fixture(symbols: symbols, functionBlocks: functionBlocks).write(to: url)
        return url
    }

    private static func makePass9Fixture(
        symbols: [(name: String, vmAddress: UInt64)],
        functionBlocks: [[UInt32]]
    ) -> Data {
        precondition(symbols.count == functionBlocks.count, "symbol count must equal function block count")
        precondition(!symbols.isEmpty, "fixture requires at least one symbol")

        let textVMBase: UInt64 = 0x1800
        let textFileOffset: UInt32 = 2048
        let symoff: UInt32 = 8192

        var textSectionSize = 0
        for (index, symbol) in symbols.enumerated() {
            precondition(symbol.vmAddress >= textVMBase, "symbol vmAddress must be inside __text")
            let relative = Int(symbol.vmAddress - textVMBase)
            let blockSize = functionBlocks[index].count * 4
            textSectionSize = max(textSectionSize, relative + blockSize)
        }

        var textBytes = Data(repeating: 0x1F, count: textSectionSize)
        for (index, symbol) in symbols.enumerated() {
            let base = Int(symbol.vmAddress - textVMBase)
            for (slotIndex, raw) in functionBlocks[index].enumerated() {
                let offset = base + slotIndex * 4
                textBytes.replaceSubrange(offset..<(offset + 4), with: leBytes(raw))
            }
        }

        var stringTable = Data([0])
        var stringOffsets = [UInt32]()
        for symbol in symbols {
            stringOffsets.append(UInt32(stringTable.count))
            stringTable.append(contentsOf: symbol.name.utf8)
            stringTable.append(0)
        }

        let nsyms = UInt32(symbols.count)
        let stroff = symoff + nsyms * UInt32(Nlist64Entry.entrySize)

        var d = Data()
        d.appendLE(UInt32(0xFEEDFACF))
        d.appendLE(UInt32(0x0100000C))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(2))
        d.appendLE(UInt32(2))
        d.appendLE(UInt32(176))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

        d.appendLE(UInt32(0x19))
        d.appendLE(UInt32(152))
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(0x1000))
        d.appendLE(UInt64(0x4000))
        d.appendLE(UInt64(0))
        d.appendLE(UInt64(0x4000))
        d.appendLE(UInt32(5))
        d.appendLE(UInt32(5))
        d.appendLE(UInt32(1))
        d.appendLE(UInt32(0))

        d.appendFixedCString("__text", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(textVMBase)
        d.appendLE(UInt64(textSectionSize))
        d.appendLE(textFileOffset)
        d.appendLE(UInt32(2))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0x80000400))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

        d.appendLE(UInt32(0x02))
        d.appendLE(UInt32(24))
        d.appendLE(symoff)
        d.appendLE(nsyms)
        d.appendLE(stroff)
        d.appendLE(UInt32(stringTable.count))

        precondition(d.count == 208)

        d.append(Data(count: Int(textFileOffset) - d.count))
        d.append(textBytes)
        d.append(Data(count: Int(symoff) - d.count))

        for (index, symbol) in symbols.enumerated() {
            d.appendLE(stringOffsets[index])
            d.append(0x0E)
            d.append(0x01)
            d.appendLE(Int16(0))
            d.appendLE(symbol.vmAddress)
        }

        d.append(stringTable)
        return d
    }

    private static func changedByteOffsets(before: Data, after: Data) -> [Int] {
        precondition(before.count == after.count, "buffers must have equal length")
        var changed = [Int]()
        for index in 0..<before.count where before[index] != after[index] {
            changed.append(index)
        }
        return changed
    }

    private static func yamlList(_ values: [String]) -> String {
        if values.isEmpty {
            return "    # empty"
        }
        return values.map { "    - \($0)" }.joined(separator: "\n")
    }

    private static func temporaryURL(named name: String, ext: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).\(ext)")
    }

    private static func leBytes(_ value: UInt32) -> Data {
        var le = value.littleEndian
        return withUnsafeBytes(of: &le) { Data($0) }
    }

    private static func readWordLE(_ data: Data, at offset: Int) -> UInt32 {
        precondition(offset >= 0 && offset + 4 <= data.count)
        return UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
    }

    private static func encodeARM64UnconditionalB(deltaBytes: Int) -> UInt32 {
        precondition(deltaBytes % 4 == 0)
        let words = deltaBytes / 4
        precondition(words >= -(1 << 25) && words < (1 << 25))
        let imm26 = UInt32(bitPattern: Int32(words)) & 0x03FF_FFFF
        return 0x1400_0000 | imm26
    }

    private static func arm64UnconditionalBranchTargetPC(fileOffset: Int, raw: UInt32) -> Int? {
        guard (raw & 0xFC00_0000) == 0x1400_0000 else { return nil }
        var immBits = raw & 0x03FF_FFFF
        if (immBits & 0x0200_0000) != 0 {
            immBits |= 0xFC00_0000
        }
        let signed = Int32(bitPattern: immBits)
        return fileOffset + Int(signed) * 4
    }

    private static func unconditionalBranchTargets(
        in data: Data,
        baseFileOffset: Int,
        fromSectionOffset: Int,
        byteCount: Int
    ) -> [Int] {
        var targets = [Int]()
        var offset = fromSectionOffset
        let end = fromSectionOffset + byteCount
        while offset + 4 <= end {
            let raw = readWordLE(data, at: offset)
            let pc = baseFileOffset + (offset - fromSectionOffset)
            if let target = arm64UnconditionalBranchTargetPC(fileOffset: pc, raw: raw) {
                targets.append(target)
            }
            offset += 4
        }
        return targets
    }
}

private extension Data {
    mutating func appendLE(_ value: UInt32) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 4))
    }

    mutating func appendLE(_ value: UInt64) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 8))
    }

    mutating func appendLE(_ value: Int16) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 2))
    }

    mutating func appendFixedCString(_ string: String, length: Int) {
        var bytes = Array(string.utf8.prefix(length))
        while bytes.count < length {
            bytes.append(0)
        }
        append(contentsOf: bytes)
    }
}
