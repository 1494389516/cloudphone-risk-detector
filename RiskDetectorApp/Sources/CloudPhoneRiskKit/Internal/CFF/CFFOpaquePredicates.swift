import Foundation

internal enum CFFOpaquePredicates {
    // MARK: - SPN byte substitution (masked custom permutation)

    /// XOR masks for `spnSboxEnc`; runtime decode matches the custom Feistel SPN lane in CRiskCore.
    private static let spnSboxMask: [UInt8] = [0xA7, 0x38, 0xC2, 0x91]
    /// Encoded bytes — avoids embedding a contiguous plaintext permutation fingerprint in rodata.
    private static let spnSboxEnc: [UInt8] = [
        0x4a, 0x45, 0x34, 0xc5, 0xa9, 0xec, 0x69, 0xa0, 0x26, 0x52, 0xbe, 0x48, 0xa3, 0x76, 0x9e, 0xe9,
        0x7b, 0x2d, 0xd9, 0x5b, 0x9b, 0x46, 0xb1, 0x7b, 0x6a, 0xe8, 0xea, 0x0f, 0x54, 0x41, 0xb5, 0xe3,
        0x25, 0x07, 0x00, 0x30, 0x3e, 0x6e, 0x45, 0x19, 0x24, 0xdd, 0x3c, 0xbb, 0xb1, 0xb4, 0xdb, 0x73,
        0x40, 0x0e, 0xe1, 0x70, 0x71, 0xca, 0xc3, 0x96, 0x8c, 0x37, 0x9c, 0xee, 0x6e, 0xd6, 0x89, 0xf5,
        0xff, 0x78, 0xc0, 0xbe, 0x87, 0x63, 0xd3, 0xb6, 0x12, 0x0f, 0xf9, 0x75, 0x4e, 0xf4, 0xf2, 0x8c,
        0xe6, 0x5b, 0x6f, 0xac, 0xc2, 0x11, 0x1d, 0xab, 0x50, 0x27, 0x11, 0x6c, 0x36, 0xbe, 0xa2, 0x5e,
        0x92, 0x42, 0x62, 0x06, 0xe1, 0x8b, 0x60, 0x7a, 0x48, 0x8c, 0x7a, 0xd9, 0xf4, 0xab, 0xcf, 0x7d,
        0x32, 0x2c, 0x2a, 0x0c, 0xf5, 0xc8, 0x9d, 0x27, 0x2a, 0x91, 0xec, 0x07, 0xe5, 0x7d, 0x4d, 0x60,
        0x08, 0x5e, 0x46, 0xa8, 0xd6, 0x43, 0x86, 0x36, 0x17, 0xc7, 0xde, 0x6b, 0x60, 0x77, 0x07, 0xcb,
        0xa1, 0x0a, 0xce, 0x98, 0x19, 0xc0, 0x58, 0x8b, 0x0f, 0x2b, 0x95, 0x5f, 0x02, 0x32, 0x73, 0xb0,
        0xc9, 0x82, 0x03, 0x4b, 0xf7, 0xfc, 0x7d, 0x14, 0x1a, 0x9c, 0x70, 0xf0, 0x9f, 0x15, 0xd2, 0x1f,
        0xb5, 0x48, 0x49, 0xf3, 0xd1, 0xc4, 0xca, 0x8f, 0x27, 0xb2, 0xe0, 0x91, 0x37, 0xcd, 0x61, 0x46,
        0xa4, 0x0b, 0xb7, 0x18, 0x44, 0xaa, 0xc7, 0xfa, 0x7f, 0x14, 0xaf, 0x5a, 0x67, 0x8f, 0xe4, 0xa5,
        0xe4, 0x92, 0x97, 0x3d, 0x1e, 0x71, 0xa5, 0xb4, 0xce, 0x1c, 0x59, 0x71, 0xbf, 0x7f, 0x10, 0x4c,
        0xc8, 0xcc, 0x6c, 0xdb, 0x79, 0xe3, 0x56, 0x0d, 0x1c, 0xde, 0x5a, 0x9a, 0xb0, 0x9e, 0x8f, 0x2d,
        0xcb, 0x65, 0x3b, 0x52, 0xeb, 0xc3, 0x04, 0xaf, 0x76, 0x69, 0x9b, 0x44, 0xcf, 0x4c, 0x0a, 0x0e
    ]

    @inline(__always)
    private static func spnSboxByte(_ idx: UInt8) -> UInt8 {
        let i = Int(idx)
        return spnSboxEnc[i] ^ spnSboxMask[i & 3]
    }
    private static let residuePrimes: [UInt32] = [65_521, 65_519, 65_497, 65_479, 65_449, 65_447]

    @inline(__always)
    private static func subWord32(_ x: UInt32) -> UInt32 {
        let b0 = UInt32(spnSboxByte(UInt8(truncatingIfNeeded: x)))
        let b1 = UInt32(spnSboxByte(UInt8(truncatingIfNeeded: x &>> 8))) &<< 8
        let b2 = UInt32(spnSboxByte(UInt8(truncatingIfNeeded: x &>> 16))) &<< 16
        let b3 = UInt32(spnSboxByte(UInt8(truncatingIfNeeded: x &>> 24))) &<< 24
        return b0 | b1 | b2 | b3
    }

    @inline(__always)
    private static func byteSwap32(_ x: UInt32) -> UInt32 {
        ((x & 0x0000_00ff) &<< 24)
            | ((x & 0x0000_ff00) &<< 8)
            | ((x & 0x00ff_0000) &>> 8)
            | ((x & 0xff00_0000) &>> 24)
    }

    @inline(__always)
    private static func residuePrime(for blend: CFFContextBlend) -> UInt32 {
        let selector = UInt32(blend.residueLayoutTag)
            ^ (UInt32(blend.parityLayoutTag) &<< 1)
            ^ (UInt32(blend.connectorLayoutTag) &<< 2)
        return residuePrimes[Int(selector % UInt32(residuePrimes.count))]
    }

    /// One SPN round: SubWord → add round key → rotate (diffusion / avalanche).
    @inline(__always)
    private static func spnRound(_ x: UInt32, roundKey: UInt32, rot: UInt32) -> UInt32 {
        let y = subWord32(x) ^ roundKey
        return (y &<< rot) | (y &>> (32 &- rot))
    }

    @inline(__always)
    private static func spnRotations(for blend: CFFContextBlend) -> (UInt32, UInt32, UInt32, UInt32) {
        let r0 = 5 &+ UInt32(blend.residueLayoutTag)
        let r1 = 9 &+ UInt32(blend.parityLayoutTag)
        let r2 = 13 &+ UInt32(blend.connectorLayoutTag)
        let r3 = 17 &+ UInt32((blend.residueLayoutTag ^ blend.parityLayoutTag ^ blend.connectorLayoutTag) & 3)
        return (r0, r1, r2, r3)
    }

    /// Multi-round SPN mixing (substitution + P-layer via rotations / XOR of round keys).
    @inline(__always)
    private static func spnMix32(_ value: UInt32, salt: UInt32, blend: CFFContextBlend = .legacy) -> UInt32 {
        let rk0 = salt &* 0x9e37_79b1
        let rk1 = salt ^ 0x1357_9bdf
        let rk2 = salt &* 0x27d4_eb2d
        let rk3 = rk0 ^ rk2 ^ 0x517c_c1b7
        let (r0, r1, r2, r3) = spnRotations(for: blend)

        var x = value ^ salt
        x = spnRound(x, roundKey: rk0, rot: r0)
        x = spnRound(x, roundKey: rk1, rot: r1)
        x = spnRound(x, roundKey: rk2, rot: r2)
        x = spnRound(x, roundKey: rk3, rot: r3)
        return x
    }

    /// Semantic residue: SPN avalanche folded into prime field (replaces legacy FNV chain).
    @inline(__always)
    private static func spnPrimeResidue32(_ value: UInt32, salt: UInt32, blend: CFFContextBlend = .legacy) -> UInt32 {
        let prime = residuePrime(for: blend)
        let mixed = spnMix32(
            value ^ (UInt32(blend.connectorLayoutTag) &<< 24),
            salt: salt ^ UInt32(blend.parityLayoutTag),
            blend: blend
        )
        return mixed % prime
    }

    /// Ghost lanes: alternate round-key schedule / rotation schedule — masked to zero against semantic core.
    @inline(__always)
    private static func ghostSpnLane(_ value: UInt32, salt: UInt32, ghostTag: UInt8, blend: CFFContextBlend = .legacy) -> UInt32 {
        let gSalt = salt ^ (UInt32(ghostTag) &* 0x1111_1111)
        let rk0 = gSalt &+ UInt32(ghostTag) &* 0xa5a5_a5a5
        let rk1 = gSalt ^ (~UInt32(ghostTag) &<< 5)
        let (r0, _, r2, r3) = spnRotations(for: blend)
        var x = value ^ gSalt ^ (UInt32(ghostTag) &<< 24)
        x = spnRound(x, roundKey: rk0, rot: r0)
        x = spnRound(x, roundKey: rk1, rot: r2 &+ 4)
        x = spnRound(x, roundKey: rk0 ^ rk1, rot: r3 &+ 4)
        return x % residuePrime(for: blend)
    }

    @inline(__always)
    private static func opaqueZero32(_ a: UInt32, _ b: UInt32) -> UInt32 {
        (a ^ a) & (b | ~b)
    }

    /// Legacy entry point name — semantic lane now uses SPN + prime mod (not FNV).
    @inline(__always)
    static func fnvPrimeResidue32(_ value: UInt32, salt: UInt32) -> UInt32 {
        spnPrimeResidue32(value, salt: salt, blend: .legacy)
    }

    @inline(__always)
    static func parityFence(_ value: UInt32, salt: UInt32, blend: CFFContextBlend = .legacy) -> Bool {
        let z = opaqueZero32(value, salt)
        let rCore: UInt32 = spnPrimeResidue32(value, salt: salt, blend: blend)
        let ghostLane: UInt32 = ghostSpnLane(value, salt: salt, ghostTag: blend.residueLayoutTag, blend: blend)
        let ghost: UInt32 = ghostLane & z
        let mirrorSeed = byteSwap32(value) ^ subWord32(salt ^ blend.dispatchXor32)
        let mirrorResidue: UInt32 = spnPrimeResidue32(mirrorSeed, salt: salt ^ blend.splitSaltXor, blend: blend)
        let mirrorMask = mirrorResidue & UInt32(blend.switchConnectorSelector | 1)
        let r: UInt32 = rCore ^ ghost ^ mirrorMask
        let mixA = value &* UInt32(0x45d9_f3b)
        let mixB = salt &* UInt32(0x119d_e1f3)
        let mixC = r &* UInt32(0x9e37_79b1)
        let mixD = mirrorResidue &* (blend.dispatchXor32 | 1)
        let mixed0: UInt32 = mixA ^ mixB ^ mixC ^ mixD
        let z0 = opaqueZero32(value, salt)
        let z1 = opaqueZero32(salt, value)
        let mixed1 = mixed0 ^ (z0 &* 0x517c_c1b7)
        let mixed2 = mixed1 ^ (z1 &* 0x1656_67b1)
        let mixed: UInt32
        switch blend.parityLayoutTag {
        case 0:
            mixed = mixed2
        case 1:
            mixed = mixed2 ^ (z0 >> 1)
        case 2:
            mixed = mixed2 ^ (z1 << 1)
        default:
            mixed = mixed2 ^ (z0 | z1)
        }
        return ((mixed ^ (mixed >> 16)) & 1) == (value & 1)
    }

    /// Connector gate: S-box byte avalanche replaces raw popcount on XOR (same blend-driven branch shapes).
    @inline(__always)
    static func connectorGate(encodedState: UInt32, salt: UInt32, blend: CFFContextBlend = .legacy) -> Bool {
        let diff = encodedState ^ salt
        let h = spnMix32(
            diff ^ blend.dispatchXor32,
            salt: (salt &+ 0xdead_beef) ^ blend.splitSaltXor,
            blend: blend
        )
        let b0 = spnSboxByte(UInt8(truncatingIfNeeded: h))
        let b1 = spnSboxByte(UInt8(truncatingIfNeeded: h >> 8))
        let b2 = spnSboxByte(UInt8(truncatingIfNeeded: h >> 16))
        let b3 = spnSboxByte(UInt8(truncatingIfNeeded: h >> 24))
        let mirror = byteSwap32(h ^ blend.dispatchXor32)
        let folded = Int(b0 ^ b1 ^ b2 ^ b3 ^ UInt8(truncatingIfNeeded: mirror))
        let z = opaqueZero32(encodedState, salt)
        let t = Int(z & 0xFF)
        switch blend.connectorLayoutTag {
        case 0:
            return (folded & 1) == Int((salt >> 3) & 1)
        case 1:
            return ((folded ^ t) & 1) == Int((salt >> 3) & 1)
        case 2:
            return ((folded & 1) ^ (t & 1)) == Int((salt >> 3) & 1)
        default:
            return (folded & 1) == Int(((salt ^ UInt32(t)) >> 3) & 1)
        }
    }

    @inline(__always)
    static func maskedEquals(_ lhs: UInt32, _ rhs: UInt32, salt: UInt32) -> Bool {
        let mask = (salt | 1) &* 0x9e37_79b1
        return (lhs ^ mask) == (rhs ^ mask)
    }

    @inline(__always)
    static func boundedSelector(_ value: UInt32, salt: UInt32, modulo: UInt32, blend: CFFContextBlend = .legacy) -> UInt32 {
        let boundedModulo = max(1, modulo)
        let z = opaqueZero32(value, salt)
        let rCore: UInt32 = spnPrimeResidue32(value, salt: salt, blend: blend)
        let ghostLane: UInt32 = ghostSpnLane(value, salt: salt, ghostTag: blend.residueLayoutTag, blend: blend)
        let ghost: UInt32 = ghostLane & z
        let mirrorResidue: UInt32 = spnPrimeResidue32(byteSwap32(value), salt: salt ^ blend.dispatchXor32, blend: blend)
        let r: UInt32 = rCore ^ ghost
        let folded = value &+ (salt &* UInt32(0x27d4_eb2d))
        let mixed0: UInt32 = r ^ mirrorResidue ^ folded ^ UInt32(0x7f4a_7c15)
        let mixed1: UInt32
        switch blend.residueLayoutTag {
        case 0:
            mixed1 = mixed0
        case 1:
            mixed1 = mixed0 ^ (z &* 0x9e37_79b1)
        case 2:
            mixed1 = mixed0 &+ (z & (value ^ value))
        default:
            mixed1 = mixed0 | (z & 0)
        }
        return mixed1 % boundedModulo
    }
}
