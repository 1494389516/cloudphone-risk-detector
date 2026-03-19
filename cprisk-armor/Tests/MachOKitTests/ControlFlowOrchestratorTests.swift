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
            light: ["MutationPlanner.maybeShuffle"],
            never: ["direct_syscall.cprisk_direct_syscall0"],
            regionOnly: ["RiskDetectionEngine.evaluate"],
            antiDeobfuscation: AntiDeobfuscationOptions()
        )

        let orchestrator = ControlFlowOrchestrator(policy: policy)
        let plans = orchestrator.buildPlans()

        let heavyPlan = try XCTUnwrap(plans.first { $0.symbol == "DecisionTree.decide" })
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

    private static func writePass9Policy(
        named name: String,
        heavy: [String],
        light: [String],
        never: [String],
        regionOnly: [String]
    ) throws -> URL {
        let url = temporaryURL(named: "\(name)_policy", ext: "yaml")
        let contents = """
        version: 2
        functions:
          heavy:
        \(yamlList(heavy))
          light:
        \(yamlList(light))
          never:
        \(yamlList(never))
          regionOnly:
        \(yamlList(regionOnly))
        anti_deobfuscation:
          enable_runtime_salt: true
          enable_fake_state_release_only: true
          enable_multi_dispatcher: true
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
