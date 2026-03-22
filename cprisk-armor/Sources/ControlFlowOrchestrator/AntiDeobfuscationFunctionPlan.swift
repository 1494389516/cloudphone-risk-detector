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

        return AntiDeobfuscationFunctionPlan(
            runtimeSaltEnabled: runtimeSaltEnabled,
            runtimeSaltMode: runtimeSaltMode,
            fakeStateReleaseOnlyEnabled: fakeStateReleaseOnlyEnabled,
            multiDispatcherEnabled: multiDispatcherEnabled,
            pass8CFFAwarenessEnabled: pass8CFFAwarenessEnabled
        )
    }
}
