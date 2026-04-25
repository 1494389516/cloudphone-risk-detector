import Foundation

public enum StateEncodingStyle: String, CaseIterable, Codable, Sendable {
    case xorRotate
    case addRotateXor
    case affine
    case feistelSpn
}

public enum UnexpectedStateBehavior: String, Codable, Sendable {
    case benign
    case failClosed
    case poison
    case trap
}

public struct StateEncodingPlan: Codable, Equatable, Sendable {
    public let style: StateEncodingStyle
    public let perFunctionSeed: UInt64
    public let usesPerFunctionSeed: Bool
    public let usesRuntimeSalt: Bool
    public let debugFakeStateCount: Int
    public let releaseFakeStateCount: Int
    public let allowConnectorStates: Bool
    public let unexpectedStateBehavior: UnexpectedStateBehavior

    public static func recommended(
        for symbol: String,
        tier: FunctionCFFTier,
        options: AntiDeobfuscationOptions,
        buildSeed: UInt64 = 0
    ) -> StateEncodingPlan {
        let seed = makePerFunctionSeed(
            symbol: symbol,
            tier: tier,
            options: options,
            buildSeed: buildSeed
        )
        let style: StateEncodingStyle
        let releaseFakeStateCount: Int
        let unexpectedStateBehavior: UnexpectedStateBehavior

        // `makePerFunctionSeed` guarantees `seed != 0`, so the `(seed & 3)`
        // and `(seed & 1)` style selectors below cannot all evaluate to 0
        // for the same function. Defensively assert to catch any future
        // change to seed derivation that loses the non-zero invariant.
        precondition(seed != 0, "StateEncodingPlan: per-function seed must be non-zero")
        switch tier {
        case .heavy:
            style = (seed & 3) != 0 ? .feistelSpn : ((seed & 1) == 0 ? .addRotateXor : .affine)
            releaseFakeStateCount = options.enableFakeStateReleaseOnly ? 2 : 0
            unexpectedStateBehavior = options.enableDefaultPoisonForHeavy ? .poison : .failClosed
        case .regionOnly:
            style = (seed & 3) != 0 ? .feistelSpn : ((seed & 2) == 0 ? .addRotateXor : .affine)
            releaseFakeStateCount = options.enableFakeStateReleaseOnly ? 1 : 0
            unexpectedStateBehavior = .failClosed
        case .medium:
            style = (seed & 3) == 0 ? .xorRotate : .addRotateXor
            releaseFakeStateCount = 0
            unexpectedStateBehavior = .failClosed
        case .light:
            style = .xorRotate
            releaseFakeStateCount = 0
            unexpectedStateBehavior = .failClosed
        case .never:
            style = .xorRotate
            releaseFakeStateCount = 0
            unexpectedStateBehavior = .benign
        }

        return StateEncodingPlan(
            style: style,
            perFunctionSeed: seed,
            usesPerFunctionSeed: tier != .never,
            usesRuntimeSalt: options.enableRuntimeSalt && tier != .never,
            debugFakeStateCount: 0,
            releaseFakeStateCount: releaseFakeStateCount,
            allowConnectorStates: tier == .heavy || tier == .regionOnly,
            unexpectedStateBehavior: unexpectedStateBehavior
        )
    }
}

private func makePerFunctionSeed(
    symbol: String,
    tier: FunctionCFFTier,
    options: AntiDeobfuscationOptions,
    buildSeed: UInt64
) -> UInt64 {
    var hash = cffStableHash64(symbol)
    hash ^= cffStableHash64("tier:\(tier.rawValue)")
    hash ^= cffStableHash64(optionsSeedLabel(options))
    hash ^= rotatedLeft(buildSeed == 0 ? cffStableHash64("seed:fallback") : buildSeed, by: 17)
    return hash == 0 ? 1 : hash
}

private func optionsSeedLabel(_ options: AntiDeobfuscationOptions) -> String {
    "runtimeSalt=\(options.enableRuntimeSalt);" +
        "fakeStateReleaseOnly=\(options.enableFakeStateReleaseOnly);" +
        "multiDispatcher=\(options.enableMultiDispatcher);" +
        "defaultPoisonHeavy=\(options.enableDefaultPoisonForHeavy);" +
        "pass8Aware=\(options.enablePass8CFFAwareness)"
}

private func rotatedLeft(_ value: UInt64, by shift: UInt64) -> UInt64 {
    let amount = shift & 63
    if amount == 0 { return value }
    return (value << amount) | (value >> (64 - amount))
}
