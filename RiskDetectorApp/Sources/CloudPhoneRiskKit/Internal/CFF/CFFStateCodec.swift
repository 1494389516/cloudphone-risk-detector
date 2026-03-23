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
            let mix = avalanche32(key ^ salt ^ 0x9E3779B9)
            let shift = Int((mix & 0x1F) | 1)
            let masked = state ^ mix ^ (salt &* 0x45D9F3B)
            return masked.rotatedLeft(by: shift) &+ (key &* 0x27D4EB2D)
        case .addRotateXor:
            let addend = avalanche32(key &+ salt &+ 0x7F4A7C15)
            let shift = Int((((key &>> 3) ^ salt) & 0x1F) | 1)
            let mixed = (state &+ addend).rotatedLeft(by: shift)
            return mixed ^ avalanche32(key ^ 0xA24BAED5) ^ (salt &* 0x165667B1)
        case .affine:
            let mask = avalanche32(key &+ salt &+ 0x51ED270B)
            let multiplier = (avalanche32(key ^ salt.rotatedLeft(by: 7) ^ 0xD1B54A35) | 1)
            let addend = avalanche32((key &* 0x9E3779B1) ^ salt ^ 0x94D049BB)
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
            let mix = avalanche32(key ^ salt ^ 0x9E3779B9)
            let shift = Int((mix & 0x1F) | 1)
            let unshifted = (state &- (key &* 0x27D4EB2D)).rotatedRight(by: shift)
            return unshifted ^ mix ^ (salt &* 0x45D9F3B)
        case .addRotateXor:
            let addend = avalanche32(key &+ salt &+ 0x7F4A7C15)
            let shift = Int((((key &>> 3) ^ salt) & 0x1F) | 1)
            let unmasked = state ^ avalanche32(key ^ 0xA24BAED5) ^ (salt &* 0x165667B1)
            return unmasked.rotatedRight(by: shift) &- addend
        case .affine:
            let mask = avalanche32(key &+ salt &+ 0x51ED270B)
            let multiplier = (avalanche32(key ^ salt.rotatedLeft(by: 7) ^ 0xD1B54A35) | 1)
            let inverse = modularInverse32(multiplier)
            let addend = avalanche32((key &* 0x9E3779B1) ^ salt ^ 0x94D049BB)
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
        let flavorMarker = avalanche64(flavorSeed ^ config.functionSeed ^ 0x9E37_79B9_7F4A_7C15)
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

        let raw = avalanche32(UInt32(ordinal) &+ key &+ (salt &* 0x9E3779B1)) | 1
        return encode(state: raw, key: key ^ 0x6C8E9CF5, salt: salt, style: config.codecStyle)
    }

    @inline(__always)
    static func encodedEntryState(
        rawState: UInt32,
        function: String,
        salt: UInt32,
        config: CFFConfig
    ) -> UInt32 {
        let key = deriveSeed(function: function, config: config)
        let effectiveSalt = config.enableRuntimeSalt ? salt : salt ^ 0x13579BDF
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
        let effectiveSalt = config.enableRuntimeSalt ? salt : salt ^ 0x13579BDF
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

    private static let spnSboxMask: [UInt8] = [0xA7, 0x38, 0xC2, 0x91]
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

    private static let feistelRounds: UInt32 = 8

    @inline(__always)
    private static func feistelRoundF(_ r: UInt16, key: UInt32, salt: UInt32, round: UInt32) -> UInt16 {
        let roundKey = avalanche32(key ^ salt ^ (round &* 0x9E3779B9) ^ 0xDEADBEEF)
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
        let prewhiten = avalanche32(key ^ salt ^ 0x0F1055A1)
        let postwhiten = avalanche32(key ^ salt ^ 0x0ACC0DEC)
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
        let prewhiten = avalanche32(key ^ salt ^ 0x0F1055A1)
        let postwhiten = avalanche32(key ^ salt ^ 0x0ACC0DEC)
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
