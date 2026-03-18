import ControlFlowOrchestrator
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
            - MutationStrategy.shuffleChecks
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
        XCTAssertEqual(policy.tier(for: "MutationStrategy.shuffleChecks"), .light)
        XCTAssertEqual(policy.tier(for: "direct_syscall.cprisk_direct_syscall0"), .never)
        XCTAssertEqual(policy.tier(for: "RiskDetectionEngine.evaluate"), .regionOnly)
        XCTAssertTrue(policy.antiDeobfuscation.enableRuntimeSalt)
        XCTAssertTrue(policy.antiDeobfuscation.enablePass8CFFAwareness)
    }

    func testOrchestratorBuildPlansReflectTierSpecificDefaults() throws {
        let policy = FunctionCFFPolicy(
            version: 2,
            heavy: ["DecisionTree.decide"],
            light: ["MutationStrategy.shuffleChecks"],
            never: ["direct_syscall.cprisk_direct_syscall0"],
            regionOnly: ["RiskDetectionEngine.evaluate"],
            antiDeobfuscation: AntiDeobfuscationOptions()
        )

        let orchestrator = ControlFlowOrchestrator(policy: policy)
        let plans = orchestrator.buildPlans()

        let heavyPlan = try XCTUnwrap(plans.first { $0.symbol == "DecisionTree.decide" })
        let lightPlan = try XCTUnwrap(plans.first { $0.symbol == "MutationStrategy.shuffleChecks" })
        let neverPlan = try XCTUnwrap(plans.first { $0.symbol == "direct_syscall.cprisk_direct_syscall0" })
        let regionPlan = try XCTUnwrap(plans.first { $0.symbol == "RiskDetectionEngine.evaluate" })

        XCTAssertEqual(heavyPlan.tier, .heavy)
        XCTAssertTrue(heavyPlan.stateEncodingPlan.usesRuntimeSalt)
        XCTAssertTrue(heavyPlan.runtimeDependencyPlan.pass8Aware)

        XCTAssertEqual(lightPlan.tier, .light)
        XCTAssertEqual(neverPlan.tier, .never)
        XCTAssertEqual(regionPlan.tier, .regionOnly)
    }
}
