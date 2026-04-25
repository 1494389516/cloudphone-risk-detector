import Foundation

public enum RuntimeSaltMode: String, Codable, CaseIterable, Sendable {
    case disabled
    case advisory
    case coupled
}

public struct AntiDeobfuscationFunctionPlan: Codable, Equatable, Sendable {
    public let runtimeSaltEnabled: Bool
    public let runtimeSaltMode: RuntimeSaltMode
    public let fakeStateReleaseOnlyEnabled: Bool
    public let multiDispatcherEnabled: Bool
    public let pass8CFFAwarenessEnabled: Bool

    public static func recommended(
        for tier: FunctionCFFTier,
        options: AntiDeobfuscationOptions,
        stateEncodingPlan: StateEncodingPlan,
        runtimeDependencyPlan: RuntimeDependencyPlan
    ) -> AntiDeobfuscationFunctionPlan {
        let runtimeSaltEnabled = options.enableRuntimeSalt && tier != .never
        let runtimeSaltMode: RuntimeSaltMode
        switch tier {
        case .heavy, .regionOnly:
            runtimeSaltMode = runtimeSaltEnabled ? .coupled : .disabled
        case .light, .medium:
            runtimeSaltMode = runtimeSaltEnabled ? .advisory : .disabled
        case .never:
            runtimeSaltMode = .disabled
        }

        let fakeStateReleaseOnlyEnabled = options.enableFakeStateReleaseOnly
            && (tier == .heavy || tier == .regionOnly)
            && stateEncodingPlan.releaseFakeStateCount > 0

        let multiDispatcherEnabled = options.enableMultiDispatcher && tier == .heavy
        let pass8CFFAwarenessEnabled = options.enablePass8CFFAwareness && runtimeDependencyPlan.pass8Aware

        let plan = AntiDeobfuscationFunctionPlan(
            runtimeSaltEnabled: runtimeSaltEnabled,
            runtimeSaltMode: runtimeSaltMode,
            fakeStateReleaseOnlyEnabled: fakeStateReleaseOnlyEnabled,
            multiDispatcherEnabled: multiDispatcherEnabled,
            pass8CFFAwarenessEnabled: pass8CFFAwarenessEnabled
        )

        // Cross-field consistency: catch state combinations that are
        // semantically incompatible BEFORE they reach the runtime, where
        // they would silently produce wrong-tier behavior or panic.
        //
        // Rule 1: tier=never must keep every protective flag off — a
        //   "never tier" function is explicitly excluded from CFF, so a
        //   true `runtimeSaltEnabled` would arm the runtime salt path
        //   for a function the runtime expects to be plain.
        // Rule 2: `runtimeSaltMode == .coupled` requires a tier whose
        //   codec actually uses a coupled salt (heavy / regionOnly). The
        //   audit flagged a possible mismatch when a builder forces a
        //   non-heavy tier to use coupled salt mode.
        precondition(
            !(tier == .never && (runtimeSaltEnabled || fakeStateReleaseOnlyEnabled || multiDispatcherEnabled)),
            "AntiDeobfuscationFunctionPlan: tier=.never cannot coexist with any active hardening flag"
        )
        precondition(
            !(runtimeSaltMode == .coupled && tier != .heavy && tier != .regionOnly),
            "AntiDeobfuscationFunctionPlan: runtimeSaltMode=.coupled requires tier=heavy or regionOnly"
        )
        return plan
    }
}
