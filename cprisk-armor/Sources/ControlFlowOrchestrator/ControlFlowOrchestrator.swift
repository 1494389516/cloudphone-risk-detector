import Foundation
import MachOKit

public struct OrchestratedFunctionPlan: Equatable, Sendable {
    public let symbol: String
    public let tier: FunctionCFFTier
    public let dispatcherStyle: DispatcherStyle
    public let stateEncodingPlan: StateEncodingPlan
    public let runtimeDependencyPlan: RuntimeDependencyPlan
    public let antiDeobfuscationPlan: AntiDeobfuscationFunctionPlan
    public let notes: [String]

    public var summaryLine: String {
        [
            symbol,
            "tier=\(tier.rawValue)",
            "dispatcher=\(dispatcherStyle.rawValue)",
            "codec=\(stateEncodingPlan.style.rawValue)",
            "runtimeSalt=\(stateEncodingPlan.usesRuntimeSalt)",
            "runtimeSaltMode=\(antiDeobfuscationPlan.runtimeSaltMode.rawValue)",
            "fakeStates=\(stateEncodingPlan.releaseFakeStateCount)",
            "fakeStateReleaseOnly=\(antiDeobfuscationPlan.fakeStateReleaseOnlyEnabled)",
            "multiDispatcher=\(antiDeobfuscationPlan.multiDispatcherEnabled)",
            "pass8Aware=\(runtimeDependencyPlan.pass8Aware)",
            "pass8CFFAware=\(antiDeobfuscationPlan.pass8CFFAwarenessEnabled)"
        ].joined(separator: " ")
    }
}

public final class ControlFlowOrchestrator {
    public let policy: FunctionCFFPolicy

    public init(policy: FunctionCFFPolicy) {
        self.policy = policy
    }

    public func buildPlans() -> [OrchestratedFunctionPlan] {
        policy.allManagedFunctions
            .map { makePlan(for: $0) }
            .sorted { $0.symbol < $1.symbol }
    }

    public func makePlan(for symbol: String) -> OrchestratedFunctionPlan {
        let tier = policy.tier(for: symbol) ?? .never
        let dispatcher = DispatcherStyle.choose(
            for: symbol,
            tier: tier,
            enableMultiDispatcher: policy.antiDeobfuscation.enableMultiDispatcher
        )
        let stateEncodingPlan = StateEncodingPlan.recommended(
            for: symbol,
            tier: tier,
            options: policy.antiDeobfuscation
        )
        let runtimeDependencyPlan = RuntimeDependencyPlan.recommended(
            for: tier,
            options: policy.antiDeobfuscation
        )
        let antiDeobfuscationPlan = AntiDeobfuscationFunctionPlan.recommended(
            for: tier,
            options: policy.antiDeobfuscation,
            stateEncodingPlan: stateEncodingPlan,
            runtimeDependencyPlan: runtimeDependencyPlan
        )

        var notes: [String] = []
        if tier == .heavy {
            notes.append("heavy tier is eligible for dual-dispatcher and poison defaults")
        }
        if tier == .regionOnly {
            notes.append("region-only tier should orchestrate connectors without whole-function flattening")
        }
        if runtimeDependencyPlan.enabled {
            notes.append("runtime salt inputs should remain advisory, not semantic")
        }
        notes.append(
            "antiDeobf(runtimeSalt=\(antiDeobfuscationPlan.runtimeSaltEnabled), mode=\(antiDeobfuscationPlan.runtimeSaltMode.rawValue), fakeStateReleaseOnly=\(antiDeobfuscationPlan.fakeStateReleaseOnlyEnabled), multiDispatcher=\(antiDeobfuscationPlan.multiDispatcherEnabled), pass8Aware=\(antiDeobfuscationPlan.pass8CFFAwarenessEnabled))"
        )

        return OrchestratedFunctionPlan(
            symbol: symbol,
            tier: tier,
            dispatcherStyle: dispatcher,
            stateEncodingPlan: stateEncodingPlan,
            runtimeDependencyPlan: runtimeDependencyPlan,
            antiDeobfuscationPlan: antiDeobfuscationPlan,
            notes: notes
        )
    }

    public static func resolvePolicyURL(explicitPath: String? = nil) throws -> URL {
        let fileManager = FileManager.default

        if let explicitPath, !explicitPath.isEmpty {
            let url = URL(fileURLWithPath: explicitPath)
            guard fileManager.fileExists(atPath: url.path) else {
                throw NSError(
                    domain: "ControlFlowOrchestrator",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "cff policy file not found at \(url.path)"]
                )
            }
            return url
        }

        let cwd = URL(fileURLWithPath: fileManager.currentDirectoryPath)
        let parent = cwd.deletingLastPathComponent()
        let grandParent = parent.deletingLastPathComponent()
        let candidates = [
            cwd.appendingPathComponent("cff_policy.yaml"),
            cwd.appendingPathComponent("RiskDetectorApp/cff_policy.yaml"),
            parent.appendingPathComponent("cff_policy.yaml"),
            parent.appendingPathComponent("RiskDetectorApp/cff_policy.yaml"),
            grandParent.appendingPathComponent("cff_policy.yaml"),
            grandParent.appendingPathComponent("RiskDetectorApp/cff_policy.yaml")
        ]

        if let matched = candidates.first(where: { fileManager.fileExists(atPath: $0.path) }) {
            return matched
        }

        throw NSError(
            domain: "ControlFlowOrchestrator",
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: "unable to locate cff_policy.yaml from \(cwd.path)"]
        )
    }
}

public struct ControlFlowOrchestratorPass: ArmorPass {
    public let name = "Control Flow Orchestrator"
    private let policyFilePath: String?

    public init(policyFilePath: String? = nil) {
        self.policyFilePath = policyFilePath
    }

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        _ = file.header.numberOfCommands

        let policyURL = try ControlFlowOrchestrator.resolvePolicyURL(explicitPath: policyFilePath)
        let policy = try FunctionCFFPolicy.load(from: policyURL)
        let plans = ControlFlowOrchestrator(policy: policy).buildPlans()

        var details = [
            "policy: \(policyURL.path)",
            "version: \(policy.version)",
            "heavy=\(policy.heavy.count) light=\(policy.light.count) regionOnly=\(policy.regionOnly.count) never=\(policy.never.count)",
            "runtimeSalt=\(policy.antiDeobfuscation.enableRuntimeSalt) fakeStateReleaseOnly=\(policy.antiDeobfuscation.enableFakeStateReleaseOnly) multiDispatcher=\(policy.antiDeobfuscation.enableMultiDispatcher)",
            "pass8Aware=\(policy.antiDeobfuscation.enablePass8CFFAwareness)"
        ]

        if config.verbose {
            details.append(contentsOf: plans.map(\.summaryLine))
        }

        return PassResult(
            passName: name,
            itemsProcessed: plans.count,
            bytesModified: 0,
            details: details
        )
    }
}
