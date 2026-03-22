import Foundation

internal enum CFFOpaquePredicates {
    /// FNV-1a + small prime mod — harder than a single xor fold; branch outcome unchanged for fixed inputs.
    @inline(__always)
    static func fnvPrimeResidue32(_ value: UInt32, salt: UInt32) -> UInt32 {
        var h = UInt32(2166136261)
        h ^= value &+ salt
        h &*= 16777619
        h ^= salt &+ (value &>> 11)
        h &*= 709607
        return h % 65521
    }

    @inline(__always)
    static func parityFence(_ value: UInt32, salt: UInt32) -> Bool {
        let r = fnvPrimeResidue32(value, salt: salt)
        let mixed = (value &* 0x45D9F3B) ^ (salt &* 0x119DE1F3) ^ (r &* 0x9E37_79B1)
        return ((mixed ^ (mixed >> 16)) & 1) == (value & 1)
    }

    @inline(__always)
    static func connectorGate(encodedState: UInt32, salt: UInt32) -> Bool {
        let folded = (encodedState ^ salt).nonzeroBitCount
        return (folded & 1) == Int((salt >> 3) & 1)
    }

    @inline(__always)
    static func maskedEquals(_ lhs: UInt32, _ rhs: UInt32, salt: UInt32) -> Bool {
        let mask = (salt | 1) &* 0x9E3779B1
        return (lhs ^ mask) == (rhs ^ mask)
    }

    @inline(__always)
    static func boundedSelector(_ value: UInt32, salt: UInt32, modulo: UInt32) -> UInt32 {
        let boundedModulo = max(1, modulo)
        let mixed = fnvPrimeResidue32(value, salt: salt) ^ (value &+ (salt &* 0x27D4EB2D)) ^ 0x7F4A7C15
        return mixed % boundedModulo
    }
}
