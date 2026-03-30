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

    @inline(__always)
    private static func fnv1a64(_ value: String) -> UInt64 {
        var hash: UInt64 = 0xCBF29CE484222325
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x100000001B3
        }
        return hash
    }

    @inline(__always)
    private func derivedWord32(domain: UInt64, base: UInt32, runtimeSalt: UInt32 = 0) -> UInt32 {
        let contextWord = Self.fnv1a64(rawValue) ^ (UInt64(base) << 16) ^ domain
        let tweak = CFFSBoxRuntime.derivedWord32(domain: domain, runtimeSalt: runtimeSalt, contextWord: contextWord)
        return base ^ ((tweak << 7) | (tweak >> 25))
    }

    @inline(__always)
    private func derivedTag(base: UInt8, domain: UInt64) -> UInt8 {
        let tweak = derivedWord32(domain: domain, base: UInt32(base))
        return UInt8((Int(base) + Int(tweak & 0x3)) & 0x3)
    }

    private var baseDispatchXor32: UInt32 {
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

    var dispatchXor32: UInt32 {
        derivedWord32(domain: 0x4346_4644_4953_5058, base: baseDispatchXor32)
    }

    private var baseRailSaltMultiplier: UInt32 {
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

    var railSaltMultiplier: UInt32 {
        derivedWord32(domain: 0x4346_4652_4149_4C4D, base: baseRailSaltMultiplier) | 1
    }

    private var baseSwitchConnectorSelector: UInt32 {
        switch self {
        case .legacy, .releasePointerTable:
            return 1
        case .debugExtended, .releaseSplitIndirect:
            return 2
        case .releaseBalanced:
            return 3
        }
    }

    var switchConnectorSelector: UInt32 {
        UInt32((Int(baseSwitchConnectorSelector) + Int(derivedWord32(domain: 0x4346_4653_5743_4843, base: baseSwitchConnectorSelector) & 0x3)) & 0x3)
    }

    private var baseIfElseConnectorSelector: UInt32 {
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

    var ifElseConnectorSelector: UInt32 {
        UInt32((Int(baseIfElseConnectorSelector) + Int(derivedWord32(domain: 0x4346_4649_4645_4C53, base: baseIfElseConnectorSelector) & 0x3)) & 0x3)
    }

    private var baseFakeEncodedTweak: UInt32 {
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

    var fakeEncodedTweak: UInt32 {
        derivedWord32(domain: 0x4346_4646_414B_4554, base: baseFakeEncodedTweak)
    }

    private var baseFakeSaltXor: UInt32 {
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

    var fakeSaltXor: UInt32 {
        derivedWord32(domain: 0x4346_4646_5341_4C54, base: baseFakeSaltXor)
    }

    private var baseSplitSelectorPrime: UInt32 {
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

    var splitSelectorPrime: UInt32 {
        let primePool: [UInt32] = [65_521, 65_519, 65_497, 65_479, 65_449, 65_447]
        let baseIndex = primePool.firstIndex(of: baseSplitSelectorPrime) ?? 0
        let offset = Int(derivedWord32(domain: 0x4346_4653_5052_494D, base: baseSplitSelectorPrime) % UInt32(primePool.count))
        return primePool[(baseIndex + offset) % primePool.count]
    }

    private var baseSplitSaltXor: UInt32 {
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

    var splitSaltXor: UInt32 {
        derivedWord32(domain: 0x4346_4653_4C54_584F, base: baseSplitSaltXor)
    }

    private var baseResidueLayoutTag: UInt8 {
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

    var residueLayoutTag: UInt8 {
        derivedTag(base: baseResidueLayoutTag, domain: 0x4346_4652_5344_5447)
    }

    private var baseParityLayoutTag: UInt8 {
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

    var parityLayoutTag: UInt8 {
        derivedTag(base: baseParityLayoutTag, domain: 0x4346_4650_5254_5947)
    }

    private var baseConnectorLayoutTag: UInt8 {
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

    var connectorLayoutTag: UInt8 {
        derivedTag(base: baseConnectorLayoutTag, domain: 0x4346_4643_4F4E_4E54)
    }

    private var baseFpTable: [CFFDispatcherStyle] {
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

    var fpTable: [CFFDispatcherStyle] {
        var table = baseFpTable
        guard table.count > 1 else { return table }
        let rotation = Int(derivedWord32(domain: 0x4346_4646_5054_4142, base: UInt32(table.count)) % UInt32(table.count))
        if rotation > 0 {
            table = Array(table[rotation...] + table[..<rotation])
        }
        if (derivedWord32(domain: 0x4346_4646_5053_5750, base: UInt32(table.count)) & 1) == 1, table.count >= 2 {
            table.swapAt(0, table.count - 1)
        }
        return table
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
