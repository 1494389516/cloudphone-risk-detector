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
    case splitIndirect
    /// C-side style: decode via per-codec function pointer table (`cprisk_cff_current_state_table`).
    case functionPointerTable
}

enum CFFStateCodecStyle: String, CaseIterable, Codable, Sendable {
    case xorRotate
    case addRotateXor
    case affine
    case feistelSpn
}

enum CFFBuildFlavor: String, Codable, Sendable {
    case debug
    case release
}

enum CFFContextBlend: String, CaseIterable, Codable, Sendable {
    case legacy
    case debugExtended
    case releaseBalanced
    case releasePointerTable
    case releaseSplitIndirect

    var dispatchXor32: UInt32 {
        switch self {
        case .legacy:
            return 0xA24B_AED5
        case .debugExtended:
            return 0x7F4A_7C15
        case .releaseBalanced:
            return 0x51ED_270B
        case .releasePointerTable:
            return 0xD1B5_4A35
        case .releaseSplitIndirect:
            return 0x94D0_49BB
        }
    }

    var railSaltMultiplier: UInt32 {
        switch self {
        case .legacy:
            return 0x45D9_F3B
        case .debugExtended:
            return 0x27D4_EB2D
        case .releaseBalanced:
            return 0x119D_E1F3
        case .releasePointerTable:
            return 0x9E37_79B1
        case .releaseSplitIndirect:
            return 0x1656_67B1
        }
    }

    var switchConnectorSelector: UInt32 {
        switch self {
        case .legacy, .releasePointerTable:
            return 1
        case .debugExtended, .releaseSplitIndirect:
            return 2
        case .releaseBalanced:
            return 3
        }
    }

    var ifElseConnectorSelector: UInt32 {
        switch self {
        case .legacy, .releaseBalanced:
            return 2
        case .debugExtended:
            return 3
        case .releasePointerTable:
            return 0
        case .releaseSplitIndirect:
            return 1
        }
    }

    var fakeEncodedTweak: UInt32 {
        switch self {
        case .legacy:
            return 0x1357_9BDF
        case .debugExtended:
            return 0x6C8E_9CF5
        case .releaseBalanced:
            return 0x517C_C1B7
        case .releasePointerTable:
            return 0xC2B2_AE3D
        case .releaseSplitIndirect:
            return 0x85EB_CA6B
        }
    }

    var fakeSaltXor: UInt32 {
        switch self {
        case .legacy:
            return 0x517C_C1B7
        case .debugExtended:
            return 0x1B56_C4E9
        case .releaseBalanced:
            return 0x9E37_79B9
        case .releasePointerTable:
            return 0x7F4A_7C15
        case .releaseSplitIndirect:
            return 0xA5A5_5A5A
        }
    }

    var splitSelectorPrime: UInt32 {
        switch self {
        case .legacy:
            return 65_521
        case .debugExtended:
            return 65_497
        case .releaseBalanced:
            return 65_479
        case .releasePointerTable:
            return 65_449
        case .releaseSplitIndirect:
            return 65_447
        }
    }

    var splitSaltXor: UInt32 {
        switch self {
        case .legacy:
            return 0xDEAD_BEEF
        case .debugExtended:
            return 0xBADC_0FFE
        case .releaseBalanced:
            return 0xC001_D00D
        case .releasePointerTable:
            return 0xF00D_CAFE
        case .releaseSplitIndirect:
            return 0x0F10_55A1
        }
    }

    var residueLayoutTag: UInt8 {
        switch self {
        case .legacy:
            return 0
        case .debugExtended, .releasePointerTable:
            return 1
        case .releaseBalanced:
            return 2
        case .releaseSplitIndirect:
            return 3
        }
    }

    var parityLayoutTag: UInt8 {
        switch self {
        case .legacy, .releaseSplitIndirect:
            return 1
        case .debugExtended:
            return 2
        case .releaseBalanced:
            return 3
        case .releasePointerTable:
            return 0
        }
    }

    var connectorLayoutTag: UInt8 {
        switch self {
        case .legacy:
            return 2
        case .debugExtended:
            return 0
        case .releaseBalanced:
            return 1
        case .releasePointerTable:
            return 3
        case .releaseSplitIndirect:
            return 2
        }
    }

    var fpTable: [CFFDispatcherStyle] {
        switch self {
        case .legacy:
            return [.switchLoop, .ifElseChain]
        case .debugExtended:
            return [.ifElseChain, .switchLoop, .ifElseChain, .switchLoop]
        case .releaseBalanced:
            return [.switchLoop, .ifElseChain, .switchLoop, .ifElseChain]
        case .releasePointerTable:
            return [.ifElseChain, .switchLoop, .switchLoop, .ifElseChain]
        case .releaseSplitIndirect:
            return [.switchLoop, .switchLoop, .ifElseChain, .ifElseChain]
        }
    }
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

    var contextBlend: CFFContextBlend {
        switch (buildFlavor, dispatcherStyle, protectionTier) {
        case (.debug, .functionPointerTable, _),
             (.debug, .splitIndirect, _),
             (.debug, _, .heavy),
             (.debug, _, .regionOnly):
            return .debugExtended
        case (.release, .functionPointerTable, .heavy):
            return .releasePointerTable
        case (.release, .splitIndirect, _):
            return .releaseSplitIndirect
        case (.release, _, .heavy),
             (.release, _, .regionOnly):
            return .releaseBalanced
        default:
            return .legacy
        }
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
        dispatcherStyle: CFFDispatcherStyle = .functionPointerTable,
        codecStyle: CFFStateCodecStyle = .feistelSpn
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
