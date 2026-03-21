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
        enableMultiDispatcher: Bool
    ) -> DispatcherStyle {
        let hash = cffStableHash64(symbol)

        switch tier {
        case .never:
            return .disabled
        case .regionOnly:
            return .regionCascade
        case .light:
            return (hash & 1) == 0 ? .switchLoop : .ifElseChain
        case .heavy:
            guard enableMultiDispatcher else {
                return .switchLoop
            }

            switch hash % 4 {
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
