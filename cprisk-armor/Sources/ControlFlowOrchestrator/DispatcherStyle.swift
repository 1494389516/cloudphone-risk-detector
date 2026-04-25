import Foundation

internal func cffStableHash64(_ value: String) -> UInt64 {
    var hash: UInt64 = 0xCBF29CE484222325
    for byte in value.utf8 {
        hash ^= UInt64(byte)
        hash &*= 0x100000001B3
    }
    return hash
}

public enum DispatcherStyle: String, CaseIterable, Codable, Sendable {
    case disabled
    case switchLoop
    case ifElseChain
    case dualRail
    case splitIndirect
    case regionCascade

    public static func choose(
        for symbol: String,
        tier: FunctionCFFTier,
        enableMultiDispatcher: Bool,
        buildSeed: UInt64 = 0
    ) -> DispatcherStyle {
        var hash = cffStableHash64(symbol)
        if buildSeed != 0 {
            hash ^= cffStableHash64(String(buildSeed))
            hash = (hash &* 0x9E37_79B9_7F4A_7C15) ^ (hash >> 33)
        }

        switch tier {
        case .never:
            return .disabled
        case .regionOnly:
            return .regionCascade
        case .light, .medium:
            return (hash & 1) == 0 ? .switchLoop : .ifElseChain
        case .heavy:
            guard enableMultiDispatcher else {
                return .switchLoop
            }

            // Bitwise AND instead of `% 4` to avoid the residual modulo bias
            // when reducing a 64-bit avalanche output to 4 buckets. The C
            // runtime uses the same pattern (`& 3u`) in
            // `cprisk_cff_normalize_mba_layers`; matching it keeps the
            // distribution exactly uniform across 4 dispatcher styles.
            switch hash & 3 {
            case 0:
                return .switchLoop
            case 1:
                return .ifElseChain
            case 2:
                return .splitIndirect
            default:
                return .dualRail
            }
        }
    }
}
