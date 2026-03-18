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
}
