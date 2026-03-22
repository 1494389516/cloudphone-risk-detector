import Foundation

internal struct CFFDispatchPlan: Sendable, Equatable {
    let style: CFFDispatcherStyle
    let branchSelector: UInt32
    let prefersPrimaryRail: Bool
    let usesSecondaryDispatcher: Bool
}

internal enum CFFDispatcher {
    @inline(__always)
    static func prefersPrimaryBranch(encodedState: UInt32, salt: UInt32) -> Bool {
        prefersPrimaryRail(encodedState: encodedState, salt: salt, blend: .legacy)
    }

    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32) -> UInt32 {
        branchKey(encodedState, salt: salt, modulo: 4, blend: .legacy)
    }

    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32, blend: CFFContextBlend) -> UInt32 {
        branchKey(encodedState, salt: salt, modulo: 4, blend: blend)
    }

    @inline(__always)
    static func plan(encodedState: UInt32, salt: UInt32, config: CFFConfig) -> CFFDispatchPlan {
        let blend = config.contextBlend
        let selector = branchKey(encodedState, salt: salt, modulo: 4, blend: blend)
        let prefersPrimary = prefersPrimaryRail(encodedState: encodedState, salt: salt, blend: blend)
        let resolvedStyle: CFFDispatcherStyle

        switch config.dispatcherStyle {
        case .switchLoop:
            resolvedStyle = selector == blend.switchConnectorSelector && config.allowConnectorStates ? .ifElseChain : .switchLoop
        case .ifElseChain:
            resolvedStyle = selector == blend.ifElseConnectorSelector && config.allowConnectorStates ? .switchLoop : .ifElseChain
        case .dualRail:
            resolvedStyle = prefersPrimary ? .switchLoop : .ifElseChain
        case .functionPointerTable:
            let table = blend.fpTable
            let seed32 = UInt32(truncatingIfNeeded: config.functionSeed)
            let ix = Int(CFFOpaquePredicates.boundedSelector(
                encodedState ^ seed32,
                salt: salt,
                modulo: UInt32(table.count),
                blend: blend
            ))
            resolvedStyle = table[ix]
        case .splitIndirect:
            resolvedStyle = splitIndirectStyle(
                encodedState: encodedState,
                salt: salt,
                selector: selector,
                prefersPrimary: prefersPrimary,
                config: config,
                blend: blend
            )
        }

        return CFFDispatchPlan(
            style: resolvedStyle,
            branchSelector: selector,
            prefersPrimaryRail: prefersPrimary,
            usesSecondaryDispatcher: config.dispatcherStyle == .dualRail
        )
    }

    @inline(__always)
    static func prefersPrimaryRail(encodedState: UInt32, salt: UInt32, blend: CFFContextBlend) -> Bool {
        ((encodedState ^ (salt &* blend.railSaltMultiplier)) & 1) == 0
    }

    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32, modulo: UInt32) -> UInt32 {
        branchKey(encodedState, salt: salt, modulo: modulo, blend: .legacy)
    }

    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32, modulo: UInt32, blend: CFFContextBlend) -> UInt32 {
        let boundedModulo = max(1, modulo)
        return (encodedState ^ salt ^ blend.dispatchXor32) % boundedModulo
    }

    @inline(__always)
    static func shouldVisitFakeState(
        encodedState: UInt32,
        salt: UInt32,
        config: CFFConfig
    ) -> Bool {
        guard config.enableFakeStates, config.normalizedFakeStateCount > 0, config.buildFlavor == .release else {
            return false
        }

        let blend = config.contextBlend
        return branchKey(
            encodedState &+ blend.fakeEncodedTweak,
            salt: salt ^ blend.fakeSaltXor,
            modulo: UInt32(config.normalizedFakeStateCount + 2),
            blend: blend
        ) == 0
    }

    @inline(__always)
    private static func splitIndirectStyle(
        encodedState: UInt32,
        salt: UInt32,
        selector: UInt32,
        prefersPrimary: Bool,
        config: CFFConfig,
        blend: CFFContextBlend
    ) -> CFFDispatcherStyle {
        let table = blend.fpTable
        let token = CFFOpaquePredicates.boundedSelector(
            encodedState ^ (selector &* blend.splitSelectorPrime),
            salt: salt ^ blend.splitSaltXor,
            modulo: UInt32(table.count),
            blend: blend
        )

        let gate = CFFOpaquePredicates.parityFence(encodedState ^ selector, salt: salt, blend: blend)
        let base = table[Int(token)]
        if config.allowConnectorStates && gate && prefersPrimary {
            return base == .switchLoop ? .ifElseChain : .switchLoop
        }
        return base
    }
}
