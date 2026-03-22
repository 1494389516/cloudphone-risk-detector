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
        prefersPrimaryRail(encodedState: encodedState, salt: salt)
    }

    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32) -> UInt32 {
        branchKey(encodedState, salt: salt, modulo: 4)
    }

    @inline(__always)
    static func plan(encodedState: UInt32, salt: UInt32, config: CFFConfig) -> CFFDispatchPlan {
        let selector = branchKey(encodedState, salt: salt, modulo: 4)
        let prefersPrimary = prefersPrimaryRail(encodedState: encodedState, salt: salt)
        let resolvedStyle: CFFDispatcherStyle

        switch config.dispatcherStyle {
        case .switchLoop:
            resolvedStyle = selector == 3 && config.allowConnectorStates ? .ifElseChain : .switchLoop
        case .ifElseChain:
            resolvedStyle = selector == 0 && config.allowConnectorStates ? .switchLoop : .ifElseChain
        case .dualRail:
            resolvedStyle = prefersPrimary ? .switchLoop : .ifElseChain
        case .splitIndirect:
            resolvedStyle = splitIndirectStyle(
                encodedState: encodedState,
                salt: salt,
                selector: selector,
                prefersPrimary: prefersPrimary,
                config: config
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
    static func prefersPrimaryRail(encodedState: UInt32, salt: UInt32) -> Bool {
        ((encodedState ^ (salt &* 0xA24BAED5)) & 1) == 0
    }

    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32, modulo: UInt32) -> UInt32 {
        let boundedModulo = max(1, modulo)
        return (encodedState ^ salt ^ 0x6C8E9CF5) % boundedModulo
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

        return branchKey(encodedState &+ 0x13579BDF, salt: salt ^ 0x2468ACE0, modulo: UInt32(config.normalizedFakeStateCount + 2)) == 0
    }

    @inline(__always)
    private static func splitIndirectStyle(
        encodedState: UInt32,
        salt: UInt32,
        selector: UInt32,
        prefersPrimary: Bool,
        config: CFFConfig
    ) -> CFFDispatcherStyle {
        let table: [CFFDispatcherStyle] = [.switchLoop, .ifElseChain, .switchLoop, .ifElseChain]
        let token = CFFOpaquePredicates.boundedSelector(
            encodedState ^ (selector &* 0x9E3779B1),
            salt: salt ^ 0xA24BAED5,
            modulo: UInt32(table.count)
        )

        // Opaque gate keeps rails semantically equivalent while changing control shape.
        let gate = CFFOpaquePredicates.parityFence(encodedState ^ selector, salt: salt)
        let base = table[Int(token)]
        if config.allowConnectorStates && gate && prefersPrimary {
            return base == .switchLoop ? .ifElseChain : .switchLoop
        }
        return base
    }
}
