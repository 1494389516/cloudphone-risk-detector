import Foundation

internal enum CFFOpaquePredicates {
    // MARK: - SPN byte substitution (per-build permutation via CFFSBoxRuntime)

    @inline(__always)
    private static func spnSboxByte(_ idx: UInt8) -> UInt8 {
        CFFSBoxRuntime.spnSboxByte(idx)
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

    @inline(__always)
    private static func derivedBlendConst32(
        domain: UInt64,
        salt: UInt32,
        blend: CFFContextBlend,
        base: UInt32
    ) -> UInt32 {
        let seed = blend.dispatchXor32 ^ blend.splitSelectorPrime
        let layoutWord = UInt32(blend.residueLayoutTag)
            | (UInt32(blend.parityLayoutTag) &<< 8)
            | (UInt32(blend.connectorLayoutTag) &<< 16)
        let runtimeSalt = salt ^ blend.splitSaltXor ^ layoutWord
        let contextWord = (UInt64(seed) &<< 32) ^ UInt64(layoutWord ^ base)
        let derived = CFFSBoxRuntime.derivedWord32(
            domain: domain ^ UInt64(base),
            runtimeSalt: runtimeSalt,
            contextWord: contextWord
        )
        return derived ^ base
    }

    @inline(__always)
    private static func derivedBlendOddConst32(
        domain: UInt64,
        salt: UInt32,
        blend: CFFContextBlend,
        base: UInt32
    ) -> UInt32 {
        derivedBlendConst32(domain: domain, salt: salt, blend: blend, base: base) | 1
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
        let rk0Mul = derivedBlendOddConst32(
            domain: 0x4346_465F_5350_4E30,
            salt: salt,
            blend: blend,
            base: 0x9E37_79B1
        )
        let rk1Xor = derivedBlendConst32(
            domain: 0x4346_465F_5350_4E31,
            salt: salt,
            blend: blend,
            base: 0x1357_9BDF
        )
        let rk2Mul = derivedBlendOddConst32(
            domain: 0x4346_465F_5350_4E32,
            salt: salt,
            blend: blend,
            base: 0x27D4_EB2D
        )
        let rk3Xor = derivedBlendConst32(
            domain: 0x4346_465F_5350_4E33,
            salt: salt,
            blend: blend,
            base: 0x517C_C1B7
        )
        let rk0 = salt &* rk0Mul
        let rk1 = salt ^ rk1Xor
        let rk2 = salt &* rk2Mul
        let rk3 = rk0 ^ rk2 ^ rk3Xor
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
        let gSaltMul = derivedBlendOddConst32(
            domain: 0x4346_465F_4748_5330,
            salt: salt,
            blend: blend,
            base: 0x1111_1111
        )
        let rk0Mul = derivedBlendOddConst32(
            domain: 0x4346_465F_4748_5331,
            salt: salt ^ UInt32(ghostTag),
            blend: blend,
            base: 0xA5A5_A5A5
        )
        let rk1Xor = derivedBlendConst32(
            domain: 0x4346_465F_4748_5332,
            salt: salt,
            blend: blend,
            base: 0xA24B_AED5
        )
        let gSalt = salt ^ (UInt32(ghostTag) &* gSaltMul)
        let rk0 = gSalt &+ (UInt32(ghostTag) &* rk0Mul)
        let rk1 = gSalt ^ (~UInt32(ghostTag) &<< 5) ^ rk1Xor
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
        let mixA = value &* derivedBlendOddConst32(
            domain: 0x4346_465F_5052_5441,
            salt: salt,
            blend: blend,
            base: 0x045D_9F3B
        )
        let mixB = salt &* derivedBlendOddConst32(
            domain: 0x4346_465F_5052_5442,
            salt: salt,
            blend: blend,
            base: 0x119D_E1F3
        )
        let mixC = r &* derivedBlendOddConst32(
            domain: 0x4346_465F_5052_5443,
            salt: salt,
            blend: blend,
            base: 0x9E37_79B1
        )
        let mixD = mirrorResidue &* (blend.dispatchXor32 | 1)
        let mixed0: UInt32 = mixA ^ mixB ^ mixC ^ mixD
        let z0 = opaqueZero32(value, salt)
        let z1 = opaqueZero32(salt, value)
        let mixed1 = mixed0 ^ (z0 &* derivedBlendOddConst32(
            domain: 0x4346_465F_5052_5444,
            salt: salt,
            blend: blend,
            base: 0x517C_C1B7
        ))
        let mixed2 = mixed1 ^ (z1 &* derivedBlendOddConst32(
            domain: 0x4346_465F_5052_5445,
            salt: salt,
            blend: blend,
            base: 0x1656_67B1
        ))
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
            salt: (salt &+ derivedBlendConst32(
                domain: 0x4346_465F_4347_5431,
                salt: salt,
                blend: blend,
                base: 0xDEAD_BEEF
            )) ^ blend.splitSaltXor,
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
        let mask = (salt | 1) &* derivedBlendOddConst32(
            domain: 0x4346_465F_4D45_5131,
            salt: salt,
            blend: .legacy,
            base: 0x9E37_79B1
        )
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
        let folded = value &+ (salt &* derivedBlendOddConst32(
            domain: 0x4346_465F_424E_4431,
            salt: salt,
            blend: blend,
            base: 0x27D4_EB2D
        ))
        let mixed0: UInt32 = r ^ mirrorResidue ^ folded ^ derivedBlendConst32(
            domain: 0x4346_465F_424E_4432,
            salt: salt,
            blend: blend,
            base: 0x7F4A_7C15
        )
        let mixed1: UInt32
        switch blend.residueLayoutTag {
        case 0:
            mixed1 = mixed0
        case 1:
            mixed1 = mixed0 ^ (z &* derivedBlendOddConst32(
                domain: 0x4346_465F_424E_4433,
                salt: salt,
                blend: blend,
                base: 0x9E37_79B1
            ))
        case 2:
            mixed1 = mixed0 &+ (z & (value ^ value))
        default:
            mixed1 = mixed0 | (z & 0)
        }
        return mixed1 % boundedModulo
    }
}
