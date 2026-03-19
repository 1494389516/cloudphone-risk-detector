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
        let buildSeed = try deriveBuildSeed(file: file, key: config.encryptionKey)
        let plans = ControlFlowOrchestrator(policy: policy, seedMaterial: buildSeed).buildPlans()
        let rewriteReport = try ControlFlowBinaryRewriter(policy: policy, plans: plans).apply(
            to: file,
            verbose: config.verbose
        )

        var details = [
            "policy: \(policyURL.path)",
            "version: \(policy.version)",
            "heavy=\(policy.heavy.count) light=\(policy.light.count) regionOnly=\(policy.regionOnly.count) never=\(policy.never.count)",
            "runtimeSalt=\(policy.antiDeobfuscation.enableRuntimeSalt) fakeStateReleaseOnly=\(policy.antiDeobfuscation.enableFakeStateReleaseOnly) multiDispatcher=\(policy.antiDeobfuscation.enableMultiDispatcher)",
            "pass8Aware=\(policy.antiDeobfuscation.enablePass8CFFAwareness)",
            String(format: "stateSeedMaterial=0x%016llX", buildSeed)
        ]

        details.append(contentsOf: rewriteReport.details)

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

    private func deriveBuildSeed(file: MachOFile, key: Data?) throws -> UInt64 {
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
