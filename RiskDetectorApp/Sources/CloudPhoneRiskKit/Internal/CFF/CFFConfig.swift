import Foundation

enum CFFProtectionTier: String, Codable, Sendable {
    case heavy
    case light
    case regionOnly
    case never
}

enum CFFDispatcherStyle: String, CaseIterable, Codable, Sendable {
    case switchLoop
    case ifElseChain
    case dualRail
}

enum CFFStateCodecStyle: String, CaseIterable, Codable, Sendable {
    case xorRotate
    case addRotateXor
}

enum CFFBuildFlavor: String, Codable, Sendable {
    case debug
    case release
}

enum CFFUnexpectedStatePolicy: String, Codable, Sendable {
    case benign
    case failClosed
    case poison
    case debugAssert
}

struct CFFConfig: Sendable, Codable, Equatable {
    let functionSeed: UInt64
    let protectionTier: CFFProtectionTier
    let dispatcherStyle: CFFDispatcherStyle
    let codecStyle: CFFStateCodecStyle
    let buildFlavor: CFFBuildFlavor
    let enableRuntimeSalt: Bool
    let enableFakeStates: Bool
    let fakeStateCount: Int
    let allowConnectorStates: Bool
    let unexpectedStatePolicy: CFFUnexpectedStatePolicy

    var failClosedOnUnexpectedState: Bool {
        unexpectedStatePolicy == .failClosed || unexpectedStatePolicy == .poison
    }

    var normalizedFakeStateCount: Int {
        enableFakeStates ? max(0, min(fakeStateCount, 16)) : 0
    }

    static func debug(
        functionSeed: UInt64,
        protectionTier: CFFProtectionTier = .light,
        dispatcherStyle: CFFDispatcherStyle = .switchLoop,
        codecStyle: CFFStateCodecStyle = .xorRotate
    ) -> CFFConfig {
        CFFConfig(
            functionSeed: functionSeed,
            protectionTier: protectionTier,
            dispatcherStyle: dispatcherStyle,
            codecStyle: codecStyle,
            buildFlavor: .debug,
            enableRuntimeSalt: false,
            enableFakeStates: false,
            fakeStateCount: 0,
            allowConnectorStates: protectionTier == .heavy || protectionTier == .regionOnly,
            unexpectedStatePolicy: .failClosed
        )
    }

    static func release(
        functionSeed: UInt64,
        protectionTier: CFFProtectionTier = .heavy,
        dispatcherStyle: CFFDispatcherStyle = .dualRail,
        codecStyle: CFFStateCodecStyle = .addRotateXor
    ) -> CFFConfig {
        CFFConfig(
            functionSeed: functionSeed,
            protectionTier: protectionTier,
            dispatcherStyle: dispatcherStyle,
            codecStyle: codecStyle,
            buildFlavor: .release,
            enableRuntimeSalt: true,
            enableFakeStates: protectionTier == .heavy || protectionTier == .regionOnly,
            fakeStateCount: protectionTier == .heavy ? 2 : (protectionTier == .regionOnly ? 1 : 0),
            allowConnectorStates: protectionTier != .never,
            unexpectedStatePolicy: protectionTier == .heavy ? .poison : .failClosed
        )
    }

    static func adaptive(
        functionSeed: UInt64,
        protectionTier: CFFProtectionTier,
        dispatcherStyle: CFFDispatcherStyle,
        codecStyle: CFFStateCodecStyle
    ) -> CFFConfig {
        #if DEBUG
        return .debug(
            functionSeed: functionSeed,
            protectionTier: protectionTier,
            dispatcherStyle: dispatcherStyle,
            codecStyle: codecStyle
        )
        #else
        return .release(
            functionSeed: functionSeed,
            protectionTier: protectionTier,
            dispatcherStyle: dispatcherStyle,
            codecStyle: codecStyle
        )
        #endif
    }
}
