import Foundation

public enum StateEncodingStyle: String, CaseIterable, Codable, Sendable {
    case xorRotate
    case addRotateXor
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
        options: AntiDeobfuscationOptions
    ) -> StateEncodingPlan {
        let seed = cffStableHash64(symbol) ^ 0xCFF0_C0DE_51A7_9000
        let style: StateEncodingStyle
        let releaseFakeStateCount: Int
        let unexpectedStateBehavior: UnexpectedStateBehavior

        switch tier {
        case .heavy:
            style = .addRotateXor
            releaseFakeStateCount = options.enableFakeStateReleaseOnly ? 2 : 0
            unexpectedStateBehavior = options.enableDefaultPoisonForHeavy ? .poison : .failClosed
        case .regionOnly:
            style = .addRotateXor
            releaseFakeStateCount = options.enableFakeStateReleaseOnly ? 1 : 0
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
