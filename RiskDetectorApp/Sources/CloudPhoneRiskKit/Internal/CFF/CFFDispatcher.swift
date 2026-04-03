import Foundation

internal struct CFFDispatchPlan: Sendable, Equatable {
    let style: CFFDispatcherStyle
    let branchSelector: UInt32
    let prefersPrimaryRail: Bool
    let usesSecondaryDispatcher: Bool
    /// Per-invocation epoch used to rotate dispatcher style across loop iterations.
    /// Downstream state-machine callers should pass this back as `invocationCounter`
    /// on the next call to `planRotating` to advance the rotation chain.
    let invocationEpoch: UInt32
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
            usesSecondaryDispatcher: config.dispatcherStyle == .dualRail,
            invocationEpoch: 0
        )
    }

    /// Returns a dispatch plan whose style rotates on each invocation of the same
    /// function by mixing `invocationCounter` into the salt.  Pass
    /// `plan.invocationEpoch` back as `invocationCounter` on the next call to
    /// advance the rotation chain without external state.
    ///
    /// Counter-measure: defeats Capstone L1/L2 dispatch-path caching — the same
    /// state-machine basic-block entry produces a different ARM64 branch target on
    /// each pass through the loop because the resolved `CFFDispatcherStyle` changes.
    @inline(__always)
    static func planRotating(
        encodedState: UInt32,
        salt: UInt32,
        config: CFFConfig,
        invocationCounter: UInt32
    ) -> CFFDispatchPlan {
        let rotNonce = CFFRuntimeSalt.deriveRotationNonce(
            counter: invocationCounter,
            functionSeed: config.functionSeed
        )
        let rotatedSalt = salt ^ rotNonce
        let blend = config.contextBlend
        let selector = branchKey(encodedState, salt: rotatedSalt, modulo: 4, blend: blend)
        let prefersPrimary = prefersPrimaryRail(
            encodedState: encodedState,
            salt: rotatedSalt,
            blend: blend
        )

        let resolvedStyle: CFFDispatcherStyle
        switch config.dispatcherStyle {
        case .switchLoop:
            resolvedStyle = selector == blend.switchConnectorSelector && config.allowConnectorStates
                ? .ifElseChain : .switchLoop
        case .ifElseChain:
            resolvedStyle = selector == blend.ifElseConnectorSelector && config.allowConnectorStates
                ? .switchLoop : .ifElseChain
        case .dualRail:
            resolvedStyle = prefersPrimary ? .switchLoop : .ifElseChain
        case .functionPointerTable:
            let table = blend.fpTable
            let seed32 = UInt32(truncatingIfNeeded: config.functionSeed)
            let ix = Int(CFFOpaquePredicates.boundedSelector(
                encodedState ^ seed32 ^ rotNonce,
                salt: rotatedSalt,
                modulo: UInt32(table.count),
                blend: blend
            ))
            resolvedStyle = table[ix]
        case .splitIndirect:
            resolvedStyle = splitIndirectStyle(
                encodedState: encodedState,
                salt: rotatedSalt,
                selector: selector,
                prefersPrimary: prefersPrimary,
                config: config,
                blend: blend
            )
        }

        // Next epoch: advance the rotation chain by hashing the current nonce
        // with the resolved selector so the chain is coupled to actual execution.
        let nextEpoch = invocationCounter &+ 1 &+ (selector ^ rotNonce)

        return CFFDispatchPlan(
            style: resolvedStyle,
            branchSelector: selector,
            prefersPrimaryRail: prefersPrimary,
            usesSecondaryDispatcher: config.dispatcherStyle == .dualRail,
            invocationEpoch: nextEpoch
        )
    }

    @inline(__always)
    static func prefersPrimaryRail(encodedState: UInt32, salt: UInt32, blend: CFFContextBlend) -> Bool {
        let mask = runtimeBlendMask(salt: salt, blend: blend, lane: 0x4346_465F_5241_494C)
        let multiplier = (blend.railSaltMultiplier ^ mask) | 1
        return ((encodedState ^ (salt &* multiplier)) & 1) == 0
    }

    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32, modulo: UInt32) -> UInt32 {
        branchKey(encodedState, salt: salt, modulo: modulo, blend: .legacy)
    }

    @inline(__always)
    static func branchKey(_ encodedState: UInt32, salt: UInt32, modulo: UInt32, blend: CFFContextBlend) -> UInt32 {
        let boundedModulo = max(1, modulo)
        let mask = runtimeBlendMask(salt: salt, blend: blend, lane: 0x4346_465F_4252_414E)
        return (encodedState ^ salt ^ blend.dispatchXor32 ^ mask) % boundedModulo
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

    @inline(__always)
    private static func runtimeBlendMask(salt: UInt32, blend: CFFContextBlend, lane: UInt64) -> UInt32 {
        CFFRuntimeSalt.combine(
            words: [UInt64(salt), UInt64(blend.dispatchXor32), lane],
            strings: [blend.rawValue],
            flags: [(lane & 1) == 1]
        )
    }
}
