import Foundation

internal enum CFFStateCodec {
    @inline(__always)
    static func encode(_ state: UInt32, seed: UInt32, salt: UInt32) -> UInt32 {
        encode(state: state, key: seed, salt: salt, style: .feistelSpn)
    }

    @inline(__always)
    static func decode(_ encoded: UInt32, seed: UInt32, salt: UInt32) -> UInt32 {
        decode(state: encoded, key: seed, salt: salt, style: .feistelSpn)
    }

    @inline(__always)
    static func encode(
        state: UInt32,
        key: UInt32,
        salt: UInt32,
        style: CFFStateCodecStyle = .feistelSpn
    ) -> UInt32 {
        switch style {
        case .feistelSpn:
            return feistel32EncodeCore(state: state, key: key, salt: salt)
        case .xorRotate:
            let mix = avalanche32(key ^ salt ^ codecConst32(
                domain: 0x4346_465F_5354_5831,
                key: key,
                salt: salt,
                base: 0x9E37_79B9
            ))
            let shift = Int((mix & 0x1F) | 1)
            let masked = state ^ mix ^ (salt &* codecOddConst32(
                domain: 0x4346_465F_5354_5832,
                key: key,
                salt: salt,
                base: 0x045D_9F3B
            ))
            return masked.rotatedLeft(by: shift) &+ (key &* codecOddConst32(
                domain: 0x4346_465F_5354_5833,
                key: key,
                salt: salt,
                base: 0x27D4_EB2D
            ))
        case .addRotateXor:
            let addend = avalanche32(key &+ salt &+ codecConst32(
                domain: 0x4346_465F_5354_4131,
                key: key,
                salt: salt,
                base: 0x7F4A_7C15
            ))
            let shift = Int((((key &>> 3) ^ salt) & 0x1F) | 1)
            let mixed = (state &+ addend).rotatedLeft(by: shift)
            return mixed ^ avalanche32(key ^ codecConst32(
                domain: 0x4346_465F_5354_4132,
                key: key,
                salt: salt,
                base: 0xA24B_AED5
            )) ^ (salt &* codecOddConst32(
                domain: 0x4346_465F_5354_4133,
                key: key,
                salt: salt,
                base: 0x1656_67B1
            ))
        case .affine:
            let mask = avalanche32(key &+ salt &+ codecConst32(
                domain: 0x4346_465F_5354_4631,
                key: key,
                salt: salt,
                base: 0x51ED_270B
            ))
            let multiplier = avalanche32(
                key ^ salt.rotatedLeft(by: 7) ^ codecConst32(
                    domain: 0x4346_465F_5354_4632,
                    key: key,
                    salt: salt,
                    base: 0xD1B5_4A35
                )
            ) | 1
            let addend = avalanche32(
                (key &* codecOddConst32(
                    domain: 0x4346_465F_5354_4633,
                    key: key,
                    salt: salt,
                    base: 0x9E37_79B1
                )) ^ salt ^ codecConst32(
                    domain: 0x4346_465F_5354_4634,
                    key: key,
                    salt: salt,
                    base: 0x94D0_49BB
                )
            )
            let masked = state ^ mask
            return (masked &* multiplier &+ addend) ^ key.rotatedLeft(by: Int((salt & 0x1F) | 1))
        }
    }

    @inline(__always)
    static func decode(
        state: UInt32,
        key: UInt32,
        salt: UInt32,
        style: CFFStateCodecStyle = .feistelSpn
    ) -> UInt32 {
        switch style {
        case .feistelSpn:
            return feistel32DecodeCore(encodedState: state, key: key, salt: salt)
        case .xorRotate:
            let mix = avalanche32(key ^ salt ^ codecConst32(
                domain: 0x4346_465F_5354_5831,
                key: key,
                salt: salt,
                base: 0x9E37_79B9
            ))
            let shift = Int((mix & 0x1F) | 1)
            let unshifted = (state &- (key &* codecOddConst32(
                domain: 0x4346_465F_5354_5833,
                key: key,
                salt: salt,
                base: 0x27D4_EB2D
            ))).rotatedRight(by: shift)
            return unshifted ^ mix ^ (salt &* codecOddConst32(
                domain: 0x4346_465F_5354_5832,
                key: key,
                salt: salt,
                base: 0x045D_9F3B
            ))
        case .addRotateXor:
            let addend = avalanche32(key &+ salt &+ codecConst32(
                domain: 0x4346_465F_5354_4131,
                key: key,
                salt: salt,
                base: 0x7F4A_7C15
            ))
            let shift = Int((((key &>> 3) ^ salt) & 0x1F) | 1)
            let unmasked = state ^ avalanche32(key ^ codecConst32(
                domain: 0x4346_465F_5354_4132,
                key: key,
                salt: salt,
                base: 0xA24B_AED5
            )) ^ (salt &* codecOddConst32(
                domain: 0x4346_465F_5354_4133,
                key: key,
                salt: salt,
                base: 0x1656_67B1
            ))
            return unmasked.rotatedRight(by: shift) &- addend
        case .affine:
            let mask = avalanche32(key &+ salt &+ codecConst32(
                domain: 0x4346_465F_5354_4631,
                key: key,
                salt: salt,
                base: 0x51ED_270B
            ))
            let multiplier = avalanche32(
                key ^ salt.rotatedLeft(by: 7) ^ codecConst32(
                    domain: 0x4346_465F_5354_4632,
                    key: key,
                    salt: salt,
                    base: 0xD1B5_4A35
                )
            ) | 1
            let inverse = modularInverse32(multiplier)
            let addend = avalanche32(
                (key &* codecOddConst32(
                    domain: 0x4346_465F_5354_4633,
                    key: key,
                    salt: salt,
                    base: 0x9E37_79B1
                )) ^ salt ^ codecConst32(
                    domain: 0x4346_465F_5354_4634,
                    key: key,
                    salt: salt,
                    base: 0x94D0_49BB
                )
            )
            let unxored = state ^ key.rotatedLeft(by: Int((salt & 0x1F) | 1))
            let unscaled = (unxored &- addend) &* inverse
            return unscaled ^ mask
        }
    }

    @inline(__always)
    static func deriveSeed(
        function: String,
        namespace: String? = nil,
        config: CFFConfig
    ) -> UInt32 {
        let flavorSeed = stableHash64(config.buildFlavor == .release ? "rel" : "dbg")
        let functionLo = UInt32(truncatingIfNeeded: config.functionSeed)
        let functionHi = UInt32(truncatingIfNeeded: config.functionSeed >> 32)
        let flavorConstHi = UInt64(codecConst32(
            domain: 0x4346_465F_5354_4448,
            key: functionLo,
            salt: functionHi,
            base: 0x9E37_79B9
        ))
        let flavorConstLo = UInt64(codecConst32(
            domain: 0x4346_465F_5354_444C,
            key: functionLo,
            salt: functionHi,
            base: 0x7F4A_7C15
        ))
        let flavorMarkerConst = (flavorConstHi << 32) | flavorConstLo
        let flavorMarker = avalanche64(flavorSeed ^ config.functionSeed ^ flavorMarkerConst)
        let namespaceHash = stableHash64(namespace ?? "CloudPhoneRiskKit")
        let functionHash = stableHash64(function)
        let tierBits = config.protectionTier.rawValue.utf8.reduce(UInt64(0)) { partialResult, byte in
            (partialResult &* 16_777_619) ^ UInt64(byte)
        }
        let mixed = functionHash ^ namespaceHash.rotatedLeft64(by: 11) ^ config.functionSeed ^ tierBits ^ flavorMarker
        return UInt32(truncatingIfNeeded: avalanche64(mixed) ^ mixed)
    }

    @inline(__always)
    static func fakeState(
        ordinal: Int,
        key: UInt32,
        salt: UInt32,
        config: CFFConfig
    ) -> UInt32? {
        guard config.enableFakeStates, config.buildFlavor == .release, ordinal >= 0 else {
            return nil
        }

        let raw = avalanche32(UInt32(ordinal) &+ key &+ (salt &* codecOddConst32(
            domain: 0x4346_465F_4641_4B31,
            key: key,
            salt: salt,
            base: 0x9E37_79B1
        ))) | 1
        return encode(
            state: raw,
            key: key ^ codecConst32(
                domain: 0x4346_465F_4641_4B32,
                key: key,
                salt: salt,
                base: 0x6C8E_9CF5
            ),
            salt: salt,
            style: config.codecStyle
        )
    }

    @inline(__always)
    static func encodedEntryState(
        rawState: UInt32,
        function: String,
        salt: UInt32,
        config: CFFConfig
    ) -> UInt32 {
        let key = deriveSeed(function: function, config: config)
        let fallbackSaltXor = codecConst32(
            domain: 0x4346_465F_454E_5331,
            key: key,
            salt: salt,
            base: 0x1357_9BDF
        )
        let effectiveSalt = config.enableRuntimeSalt ? salt : salt ^ fallbackSaltXor
        return encode(state: rawState, key: key, salt: effectiveSalt, style: config.codecStyle)
    }

    @inline(__always)
    static func decodedState(
        encodedState: UInt32,
        function: String,
        salt: UInt32,
        config: CFFConfig
    ) -> UInt32 {
        let key = deriveSeed(function: function, config: config)
        let fallbackSaltXor = codecConst32(
            domain: 0x4346_465F_4445_5331,
            key: key,
            salt: salt,
            base: 0x1357_9BDF
        )
        let effectiveSalt = config.enableRuntimeSalt ? salt : salt ^ fallbackSaltXor
        return decode(state: encodedState, key: key, salt: effectiveSalt, style: config.codecStyle)
    }

    @inline(__always)
    private static func avalanche32(_ value: UInt32) -> UInt32 {
        var mixed = value
        mixed ^= mixed >> 16
        mixed &*= 0x7FEB352D
        mixed ^= mixed >> 15
        mixed &*= 0x846CA68B
        mixed ^= mixed >> 16
        return mixed
    }

    @inline(__always)
    private static func avalanche64(_ value: UInt64) -> UInt64 {
        var mixed = value
        mixed ^= mixed >> 33
        mixed &*= 0xFF51AFD7ED558CCD
        mixed ^= mixed >> 33
        mixed &*= 0xC4CEB9FE1A85EC53
        mixed ^= mixed >> 33
        return mixed
    }

    private static func stableHash64(_ string: String) -> UInt64 {
        var hash: UInt64 = 0xCBF29CE484222325
        for byte in string.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x100000001B3
        }
        return hash
    }

    @inline(__always)
    private static func modularInverse32(_ oddValue: UInt32) -> UInt32 {
        var inverse = oddValue
        inverse &*= (UInt32(2) &- (oddValue &* inverse))
        inverse &*= (UInt32(2) &- (oddValue &* inverse))
        inverse &*= (UInt32(2) &- (oddValue &* inverse))
        inverse &*= (UInt32(2) &- (oddValue &* inverse))
        inverse &*= (UInt32(2) &- (oddValue &* inverse))
        return inverse
    }

    @inline(__always)
    private static func codecConst32(domain: UInt64, key: UInt32, salt: UInt32, base: UInt32) -> UInt32 {
        let lo = UInt32(truncatingIfNeeded: domain)
        let hi = UInt32(truncatingIfNeeded: domain >> 32)
        let spin = Int(((key ^ hi ^ (salt >> 1)) & 31) | 1)
        let lane = (key ^ base ^ lo).rotatedLeft(by: spin)
        let mixed0 = avalanche32(key ^ salt ^ lo ^ base)
        let mixed1 = avalanche32(lane ^ salt ^ hi ^ (base &* (key | 1)))
        return avalanche32(mixed0 ^ mixed1 ^ lo ^ hi) ^ base
    }

    @inline(__always)
    private static func codecOddConst32(domain: UInt64, key: UInt32, salt: UInt32, base: UInt32) -> UInt32 {
        codecConst32(domain: domain, key: key, salt: salt, base: base) | 1
    }

    @inline(__always)
    private static func spnSboxByte(_ idx: UInt8) -> UInt8 {
        CFFSBoxRuntime.spnSboxByte(idx)
    }

    private static let feistelRounds: UInt32 = 8

    @inline(__always)
    private static func buildSeed32() -> UInt32 {
        let buildSeed = CFFSBoxRuntime.runtimeSeed()
        let lo = UInt32(truncatingIfNeeded: buildSeed)
        let hi = UInt32(truncatingIfNeeded: buildSeed >> 32)
        return avalanche32(lo ^ hi)
    }

    @inline(__always)
    private static func deriveTag32(
        key: UInt32,
        salt: UInt32,
        chainMix: UInt32,
        lane: UInt32
    ) -> UInt32 {
        let buildSeed = CFFSBoxRuntime.runtimeSeed()
        let lo = UInt32(truncatingIfNeeded: buildSeed)
        let hi = UInt32(truncatingIfNeeded: buildSeed >> 32)
        let buildSeed32 = avalanche32(lo ^ hi)
        let buildFold = lo ^ hi
        let rotated = (chainMix ^ buildSeed32).rotatedLeft(by: Int((lane & 15) + 1))
        let laneMul = codecOddConst32(
            domain: 0x4346_465F_5441_4731,
            key: key ^ lane,
            salt: salt ^ chainMix,
            base: 0x9E37_79B1
        )
        return avalanche32(buildSeed32 ^ buildFold ^ key ^ salt ^ rotated ^ (lane &* laneMul))
    }

    @inline(__always)
    private static func codecChainMix(key: UInt32, salt: UInt32) -> UInt32 {
        avalanche32(key ^ salt.rotatedLeft(by: 7) ^ buildSeed32())
    }

    @inline(__always)
    private static func codecTag32(key: UInt32, salt: UInt32, lane: UInt32) -> UInt32 {
        deriveTag32(key: key, salt: salt, chainMix: codecChainMix(key: key, salt: salt), lane: lane)
    }

    @inline(__always)
    private static func feistelRoundF(_ r: UInt16, key: UInt32, salt: UInt32, round: UInt32) -> UInt16 {
        let roundMul = codecOddConst32(
            domain: 0x4346_465F_4653_5231,
            key: key,
            salt: salt,
            base: 0x9E37_79B9
        )
        let roundKey = avalanche32(key ^ salt ^ (round &* roundMul) ^ codecTag32(key: key, salt: salt, lane: 1))
        let b0 = UInt8(truncatingIfNeeded: r)
        let b1 = UInt8(truncatingIfNeeded: r >> 8)
        let s0 = UInt32(spnSboxByte(b0 ^ UInt8(truncatingIfNeeded: roundKey)))
        let s1 = UInt32(spnSboxByte(b1 ^ UInt8(truncatingIfNeeded: roundKey >> 8))) << 8
        var piece = s0 ^ s1
        piece ^= roundKey ^ (roundKey >> 16)
        piece = avalanche32(piece)
        return UInt16(truncatingIfNeeded: piece ^ (piece >> 16))
    }

    @inline(__always)
    private static func feistel32EncodeCore(state: UInt32, key: UInt32, salt: UInt32) -> UInt32 {
        let prewhiten = avalanche32(key ^ salt ^ codecTag32(key: key, salt: salt, lane: 2))
        let postwhiten = avalanche32(key ^ salt ^ codecTag32(key: key, salt: salt, lane: 3))
        var value = state ^ prewhiten
        var left = UInt16(truncatingIfNeeded: value >> 16)
        var right = UInt16(truncatingIfNeeded: value)
        for round in 0..<feistelRounds {
            let nextLeft = right
            let nextRight = left ^ feistelRoundF(right, key: key, salt: salt, round: round)
            left = nextLeft
            right = nextRight
        }
        value = (UInt32(left) << 16) | UInt32(right)
        return value ^ postwhiten
    }

    @inline(__always)
    private static func feistel32DecodeCore(encodedState: UInt32, key: UInt32, salt: UInt32) -> UInt32 {
        let prewhiten = avalanche32(key ^ salt ^ codecTag32(key: key, salt: salt, lane: 2))
        let postwhiten = avalanche32(key ^ salt ^ codecTag32(key: key, salt: salt, lane: 3))
        var value = encodedState ^ postwhiten
        var left = UInt16(truncatingIfNeeded: value >> 16)
        var right = UInt16(truncatingIfNeeded: value)
        var round = feistelRounds
        while round > 0 {
            round &-= 1
            let prevRight = left
            let prevLeft = right ^ feistelRoundF(left, key: key, salt: salt, round: round)
            left = prevLeft
            right = prevRight
        }
        value = (UInt32(left) << 16) | UInt32(right)
        return value ^ prewhiten
    }
}

private extension UInt32 {
    @inline(__always)
    func rotatedLeft(by shift: Int) -> UInt32 {
        let amount = shift & 31
        guard amount != 0 else { return self }
        return (self << amount) | (self >> (32 - amount))
    }

    @inline(__always)
    func rotatedRight(by shift: Int) -> UInt32 {
        let amount = shift & 31
        guard amount != 0 else { return self }
        return (self >> amount) | (self << (32 - amount))
    }
}

private extension UInt64 {
    @inline(__always)
    func rotatedLeft64(by shift: Int) -> UInt64 {
        let amount = shift & 63
        guard amount != 0 else { return self }
        return (self << amount) | (self >> (64 - amount))
    }
}
