import Foundation

internal enum CFFStateCodec {
    @inline(__always)
    static func encode(_ state: UInt32, seed: UInt32, salt: UInt32) -> UInt32 {
        encode(state: state, key: seed, salt: salt, style: .xorRotate)
    }

    @inline(__always)
    static func decode(_ encoded: UInt32, seed: UInt32, salt: UInt32) -> UInt32 {
        decode(state: encoded, key: seed, salt: salt, style: .xorRotate)
    }

    @inline(__always)
    static func encode(
        state: UInt32,
        key: UInt32,
        salt: UInt32,
        style: CFFStateCodecStyle = .xorRotate
    ) -> UInt32 {
        switch style {
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
        style: CFFStateCodecStyle = .xorRotate
    ) -> UInt32 {
        switch style {
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
