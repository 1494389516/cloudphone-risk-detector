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
    private let seedMaterial: UInt64

    public init(policy: FunctionCFFPolicy, seedMaterial: UInt64 = 0) {
        self.policy = policy
        self.seedMaterial = seedMaterial
    }

    public func buildPlans() -> [OrchestratedFunctionPlan] {
        var symbols = policy.allManagedFunctions
        if seedMaterial != 0 {
            var rng = CFFPlanSplitMix64(seed: seedMaterial ^ 0xA5A5A5A55A5A5A5A)
            symbols.shuffle(using: &rng)
        } else {
            symbols.sort()
        }
        return symbols.map { makePlan(for: $0) }
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
            options: policy.antiDeobfuscation,
            buildSeed: seedMaterial
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
        if tier == .medium {
            notes.append("medium tier uses widened binary rewrite admission (between light and heavy)")
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
        let buildSeed = try deriveBuildSeed(
            file: file,
            key: config.encryptionKey,
            explicitSeed: config.randomSeed
        )
        let availableSymbols = (try? file.readSymbols().map(\.name)) ?? []
        let plans = ControlFlowOrchestrator(policy: policy, seedMaterial: buildSeed).buildPlans()
        let rewriteReport = try ControlFlowBinaryRewriter(policy: policy, plans: plans).apply(
            to: file,
            verbose: config.verbose
        )
        let coverageSuggestion = CFFPolicyCoverageAdvisor.suggestExpansions(
            policy: policy,
            availableSymbols: availableSymbols
        )

        var details = [
            "policy: \(policyURL.path)",
            "version: \(policy.version)",
            "heavy=\(policy.heavy.count) medium=\(policy.medium.count) light=\(policy.light.count) regionOnly=\(policy.regionOnly.count) never=\(policy.never.count)",
            "runtimeSalt=\(policy.antiDeobfuscation.enableRuntimeSalt) fakeStateReleaseOnly=\(policy.antiDeobfuscation.enableFakeStateReleaseOnly) multiDispatcher=\(policy.antiDeobfuscation.enableMultiDispatcher)",
            "pass8Aware=\(policy.antiDeobfuscation.enablePass8CFFAwareness)",
            String(format: "stateSeedMaterial=0x%016llX", buildSeed)
        ]

        details.append(contentsOf: rewriteReport.details)

        if !coverageSuggestion.isEmpty {
            details.append(
                "coverage suggestions: heavy=\(coverageSuggestion.heavy.count) medium=\(coverageSuggestion.medium.count) light=\(coverageSuggestion.light.count) never=\(coverageSuggestion.never.count)"
            )
            if config.verbose {
                if !coverageSuggestion.heavy.isEmpty {
                    details.append("suggest heavy: \(coverageSuggestion.heavy.joined(separator: ", "))")
                }
                if !coverageSuggestion.medium.isEmpty {
                    details.append("suggest medium: \(coverageSuggestion.medium.joined(separator: ", "))")
                }
                if !coverageSuggestion.light.isEmpty {
                    details.append("suggest light: \(coverageSuggestion.light.joined(separator: ", "))")
                }
                if !coverageSuggestion.never.isEmpty {
                    details.append("suggest never: \(coverageSuggestion.never.joined(separator: ", "))")
                }
            }
        }

        if config.verbose {
            details.append(contentsOf: plans.map(\.summaryLine))
        }

        return PassResult(
            passName: name,
            itemsProcessed: rewriteReport.modifiedFunctionCount,
            bytesModified: rewriteReport.bytesModified,
            details: details
        )
    }

    private func deriveBuildSeed(
        file: MachOFile,
        key: Data?,
        explicitSeed: UInt64?
    ) throws -> UInt64 {
        if let explicitSeed {
            var seeded = CFFSeedFNV.offsetBasis
            seeded = fnvMix(seeded, string: "ControlFlowOrchestratorPass")
            seeded = fnvMix(seeded, value: explicitSeed == 0 ? 1 : explicitSeed)
            return seeded == 0 ? 1 : seeded
        }

        var hash = CFFSeedFNV.offsetBasis

        hash = fnvMix(hash, value: UInt64(file.header.numberOfCommands))
        hash = fnvMix(hash, value: UInt64(file.header.sizeOfCommands))
        hash = fnvMix(hash, value: UInt64(file.header.fileType))

        let segments = try file.segments()
        for segment in segments {
            hash = fnvMix(hash, string: segment.name)
            hash = fnvMix(hash, value: segment.vmAddress)
            hash = fnvMix(hash, value: segment.vmSize)
            hash = fnvMix(hash, value: segment.fileOffset)
            hash = fnvMix(hash, value: segment.fileSize)

            for section in segment.sections {
                hash = fnvMix(hash, string: section.sectionName)
                hash = fnvMix(hash, value: section.address)
                hash = fnvMix(hash, value: section.size)
                hash = fnvMix(hash, value: UInt64(section.offset))
            }
        }

        if let key {
            for byte in key {
                hash = fnvMix(hash, byte: byte)
            }
        }

        return hash == 0 ? 1 : hash
    }
}

private struct CFFPlanSplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed == 0 ? 1 : seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }
}

private enum CFFSeedFNV {
    static let offsetBasis: UInt64 = 0xCBF29CE484222325
    static let prime: UInt64 = 0x00000100000001B3
}

private func fnvMix(_ hash: UInt64, byte: UInt8) -> UInt64 {
    var mixed = hash
    mixed ^= UInt64(byte)
    mixed &*= CFFSeedFNV.prime
    return mixed
}

private func fnvMix(_ hash: UInt64, value: UInt64) -> UInt64 {
    var littleEndian = value.littleEndian
    return withUnsafeBytes(of: &littleEndian) { bytes in
        var mixed = hash
        for byte in bytes {
            mixed = fnvMix(mixed, byte: byte)
        }
        return mixed
    }
}

private func fnvMix(_ hash: UInt64, string: String) -> UInt64 {
    var mixed = hash
    for byte in string.utf8 {
        mixed = fnvMix(mixed, byte: byte)
    }
    return mixed
}
