import Foundation

public enum RuntimeDependency: String, CaseIterable, Codable, Sendable {
    case processEntropy
    case integritySignals
    case challengeState
    case trustLevel
    case watchdogSummary
}

public struct RuntimeDependencyPlan: Codable, Equatable, Sendable {
    public let enabled: Bool
    public let dependencies: [RuntimeDependency]
    public let releaseOnlyFakeStates: Bool
    public let pass7Aware: Bool
    public let pass8Aware: Bool
    public let notes: [String]

    public static func recommended(
        for tier: FunctionCFFTier,
        options: AntiDeobfuscationOptions
    ) -> RuntimeDependencyPlan {
        let enabled = options.enableRuntimeSalt && tier != .never
        let dependencies: [RuntimeDependency]
        let notes: [String]

        switch tier {
        case .heavy:
            dependencies = enabled ? [.integritySignals, .challengeState, .trustLevel, .watchdogSummary] : []
            notes = [
                "heavy functions prefer runtime-coupled state material",
                "default branch should stay fail-closed or poison"
            ]
        case .regionOnly:
            dependencies = enabled ? [.challengeState, .trustLevel, .processEntropy] : []
            notes = [
                "region flattening can bias state selection from challenge/trust context"
            ]
        case .light:
            dependencies = enabled ? [.integritySignals, .processEntropy] : []
            notes = [
                "light tier keeps runtime inputs shallow to limit codegen churn"
            ]
        case .never:
            dependencies = []
            notes = [
                "never tier should remain outside source-level CFF orchestration"
            ]
        }

        return RuntimeDependencyPlan(
            enabled: enabled,
            dependencies: dependencies,
            releaseOnlyFakeStates: options.enableFakeStateReleaseOnly && (tier == .heavy || tier == .regionOnly),
            pass7Aware: tier == .heavy,
            pass8Aware: options.enablePass8CFFAwareness && (tier == .heavy || tier == .regionOnly),
            notes: notes
        )
    }
}
