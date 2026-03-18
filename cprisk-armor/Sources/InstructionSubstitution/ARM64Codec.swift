import Foundation

public enum ARM64RegisterWidth: UInt32, Equatable {
    case w32 = 32
    case x64 = 64

    public static let zeroRegisterIndex: UInt32 = 31

    public var is64Bit: Bool { self == .x64 }
    public var bitWidth: Int { Int(rawValue) }
    public var valueMask: UInt64 { is64Bit ? UInt64.max : UInt64(UInt32.max) }
}

public struct ARM64BitmaskImmediateEncoding: Equatable {
    public let n: UInt32
    public let immr: UInt32
    public let imms: UInt32

    public init(n: UInt32, immr: UInt32, imms: UInt32) {
        self.n = n
        self.immr = immr
        self.imms = imms
    }
}

public enum ARM64RegisterCopyForm: Equatable {
    case movAlias
    case addZero
    case subZero
    case andSelf
    case orrSelf

    public var description: String {
        switch self {
        case .movAlias: return "mov alias (ORR with ZR)"
        case .addZero: return "ADD #0"
        case .subZero: return "SUB #0"
        case .andSelf: return "AND self"
        case .orrSelf: return "ORR self"
        }
    }
}

public struct ARM64RegisterCopy: Equatable {
    public let form: ARM64RegisterCopyForm
    public let destinationRegister: UInt32
    public let sourceRegister: UInt32
    public let width: ARM64RegisterWidth

    public init(
        form: ARM64RegisterCopyForm,
        destinationRegister: UInt32,
        sourceRegister: UInt32,
        width: ARM64RegisterWidth
    ) {
        self.form = form
        self.destinationRegister = destinationRegister
        self.sourceRegister = sourceRegister
        self.width = width
    }
}

public enum ARM64NoEffectForm: Equatable {
    case nop
    case discardViaMove
    case discardViaAddZero
    case discardViaSubZero
    case discardViaAndSelf
    case discardViaOrrSelf

    public var description: String {
        switch self {
        case .nop: return "NOP"
        case .discardViaMove: return "discard via mov alias"
        case .discardViaAddZero: return "discard via ADD #0"
        case .discardViaSubZero: return "discard via SUB #0"
        case .discardViaAndSelf: return "discard via AND self"
        case .discardViaOrrSelf: return "discard via ORR self"
        }
    }
}

public struct ARM64NoEffect: Equatable {
    public let form: ARM64NoEffectForm
    public let sourceRegister: UInt32?
    public let width: ARM64RegisterWidth

    public init(form: ARM64NoEffectForm, sourceRegister: UInt32?, width: ARM64RegisterWidth) {
        self.form = form
        self.sourceRegister = sourceRegister
        self.width = width
    }
}

public enum ARM64ImmediateLoadForm: Equatable {
    case movzZeroShift
    case orrLogicalImmediate(ARM64BitmaskImmediateEncoding)

    public var description: String {
        switch self {
        case .movzZeroShift:
            return "MOVZ #imm16, LSL #0"
        case .orrLogicalImmediate:
            return "ORR logical immediate"
        }
    }
}

public struct ARM64ImmediateLoad: Equatable {
    public let form: ARM64ImmediateLoadForm
    public let destinationRegister: UInt32
    public let immediate: UInt64
    public let width: ARM64RegisterWidth

    public init(
        form: ARM64ImmediateLoadForm,
        destinationRegister: UInt32,
        immediate: UInt64,
        width: ARM64RegisterWidth
    ) {
        self.form = form
        self.destinationRegister = destinationRegister
        self.immediate = immediate
        self.width = width
    }
}

public enum ARM64InstructionKind: Equatable {
    case registerCopy(ARM64RegisterCopy)
    case noEffect(ARM64NoEffect)
    case immediateLoad(ARM64ImmediateLoad)
}

public struct ARM64DecodedInstruction: Equatable {
    public let rawValue: UInt32
    public let kind: ARM64InstructionKind

    public init(rawValue: UInt32, kind: ARM64InstructionKind) {
        self.rawValue = rawValue
        self.kind = kind
    }
}

public enum ARM64Codec {
    public static let nopRawValue: UInt32 = 0xD503_201F

    public static func decode(_ rawValue: UInt32) -> ARM64DecodedInstruction? {
        if rawValue == nopRawValue {
            return ARM64DecodedInstruction(
                rawValue: rawValue,
                kind: .noEffect(ARM64NoEffect(form: .nop, sourceRegister: nil, width: .x64))
            )
        }

        if let decoded = decodeLogicalShiftedRegister(rawValue) {
            return decoded
        }
        if let decoded = decodeAddSubImmediate(rawValue) {
            return decoded
        }
        if let decoded = decodeMoveWideImmediate(rawValue) {
            return decoded
        }
        if let decoded = decodeLogicalImmediate(rawValue) {
            return decoded
        }
        return nil
    }

    public static func encode(_ decoded: ARM64DecodedInstruction?) -> UInt32 {
        guard let decoded else {
            preconditionFailure("ARM64Codec.encode requires a decoded instruction")
        }

        switch decoded.kind {
        case .registerCopy(let copy):
            switch copy.form {
            case .movAlias:
                return encodeMoveAlias(
                    destinationRegister: copy.destinationRegister,
                    sourceRegister: copy.sourceRegister,
                    width: copy.width
                )
            case .addZero:
                return encodeAddImmediateZero(
                    destinationRegister: copy.destinationRegister,
                    sourceRegister: copy.sourceRegister,
                    width: copy.width
                )
            case .subZero:
                return encodeSubImmediateZero(
                    destinationRegister: copy.destinationRegister,
                    sourceRegister: copy.sourceRegister,
                    width: copy.width
                )
            case .andSelf:
                return encodeAndSelf(
                    destinationRegister: copy.destinationRegister,
                    sourceRegister: copy.sourceRegister,
                    width: copy.width
                )
            case .orrSelf:
                return encodeOrrSelf(
                    destinationRegister: copy.destinationRegister,
                    sourceRegister: copy.sourceRegister,
                    width: copy.width
                )
            }

        case .noEffect(let noEffect):
            let source = noEffect.sourceRegister ?? ARM64RegisterWidth.zeroRegisterIndex
            switch noEffect.form {
            case .nop:
                return encodeNOP()
            case .discardViaMove:
                return encodeMoveAlias(
                    destinationRegister: ARM64RegisterWidth.zeroRegisterIndex,
                    sourceRegister: source,
                    width: noEffect.width
                )
            case .discardViaAddZero:
                return encodeAddImmediateZero(
                    destinationRegister: ARM64RegisterWidth.zeroRegisterIndex,
                    sourceRegister: source,
                    width: noEffect.width
                )
            case .discardViaSubZero:
                return encodeSubImmediateZero(
                    destinationRegister: ARM64RegisterWidth.zeroRegisterIndex,
                    sourceRegister: source,
                    width: noEffect.width
                )
            case .discardViaAndSelf:
                return encodeAndSelf(
                    destinationRegister: ARM64RegisterWidth.zeroRegisterIndex,
                    sourceRegister: source,
                    width: noEffect.width
                )
            case .discardViaOrrSelf:
                return encodeOrrSelf(
                    destinationRegister: ARM64RegisterWidth.zeroRegisterIndex,
                    sourceRegister: source,
                    width: noEffect.width
                )
            }

        case .immediateLoad(let load):
            switch load.form {
            case .movzZeroShift:
                return encodeMoveWideImmediate(
                    destinationRegister: load.destinationRegister,
                    immediate: UInt16(load.immediate),
                    width: load.width
                )
            case .orrLogicalImmediate:
                guard let raw = encodeORRLogicalImmediate(
                    destinationRegister: load.destinationRegister,
                    immediate: load.immediate,
                    width: load.width
                ) else {
                    preconditionFailure("Immediate \(load.immediate) is not encodable as ORR logical immediate")
                }
                return raw
            }
        }
    }

    public static func encodeMoveAlias(
        destinationRegister: UInt32,
        sourceRegister: UInt32,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0xAA00_0000 : 0x2A00_0000
        return base
            | ((sourceRegister & 0x1F) << 16)
            | ((ARM64RegisterWidth.zeroRegisterIndex & 0x1F) << 5)
            | (destinationRegister & 0x1F)
    }

    public static func encodeAddImmediateZero(
        destinationRegister: UInt32,
        sourceRegister: UInt32,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0x9100_0000 : 0x1100_0000
        return base
            | ((sourceRegister & 0x1F) << 5)
            | (destinationRegister & 0x1F)
    }

    public static func encodeSubImmediateZero(
        destinationRegister: UInt32,
        sourceRegister: UInt32,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0xD100_0000 : 0x5100_0000
        return base
            | ((sourceRegister & 0x1F) << 5)
            | (destinationRegister & 0x1F)
    }

    public static func encodeAndSelf(
        destinationRegister: UInt32,
        sourceRegister: UInt32,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0x8A00_0000 : 0x0A00_0000
        return base
            | ((sourceRegister & 0x1F) << 16)
            | ((sourceRegister & 0x1F) << 5)
            | (destinationRegister & 0x1F)
    }

    public static func encodeOrrSelf(
        destinationRegister: UInt32,
        sourceRegister: UInt32,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0xAA00_0000 : 0x2A00_0000
        return base
            | ((sourceRegister & 0x1F) << 16)
            | ((sourceRegister & 0x1F) << 5)
            | (destinationRegister & 0x1F)
    }

    public static func encodeNOP() -> UInt32 {
        nopRawValue
    }

    public static func encodeMoveWideImmediate(
        destinationRegister: UInt32,
        immediate: UInt16,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0xD280_0000 : 0x5280_0000
        return base
            | (UInt32(immediate) << 5)
            | (destinationRegister & 0x1F)
    }

    public static func encodeORRLogicalImmediate(
        destinationRegister: UInt32,
        immediate: UInt64,
        width: ARM64RegisterWidth
    ) -> UInt32? {
        guard let encoding = encodeBitmaskImmediate(immediate, width: width) else {
            return nil
        }

        let base: UInt32 = width.is64Bit ? 0xB200_0000 : 0x3200_0000
        return base
            | ((encoding.n & 0x1) << 22)
            | ((encoding.immr & 0x3F) << 16)
            | ((encoding.imms & 0x3F) << 10)
            | ((ARM64RegisterWidth.zeroRegisterIndex & 0x1F) << 5)
            | (destinationRegister & 0x1F)
    }

    public static func encodeBitmaskImmediate(
        _ immediate: UInt64,
        width: ARM64RegisterWidth
    ) -> ARM64BitmaskImmediateEncoding? {
        let target = immediate & width.valueMask
        guard target != 0, target != width.valueMask else { return nil }

        let maxElementWidth = width.is64Bit ? 64 : 32
        for elementWidth in stride(from: 2, through: maxElementWidth, by: 2) where elementWidth.isPowerOfTwo {
            for oneBitCount in 1..<elementWidth {
                for rotation in 0..<elementWidth {
                    let pattern = makeBitmaskPattern(
                        elementWidth: elementWidth,
                        oneBitCount: oneBitCount,
                        rotation: rotation,
                        totalWidth: width.bitWidth
                    )
                    if pattern != target {
                        continue
                    }
                    return ARM64BitmaskImmediateEncoding(
                        n: elementWidth == 64 ? 1 : 0,
                        immr: UInt32(rotation),
                        imms: makeLogicalImmediateImms(elementWidth: elementWidth, oneBitCount: oneBitCount)
                    )
                }
            }
        }

        return nil
    }

    public static func decodeBitmaskImmediate(
        n: UInt32,
        immr: UInt32,
        imms: UInt32,
        width: ARM64RegisterWidth
    ) -> UInt64? {
        let maxElementWidth = width.is64Bit ? 64 : 32
        for elementWidth in stride(from: 2, through: maxElementWidth, by: 2) where elementWidth.isPowerOfTwo {
            for oneBitCount in 1..<elementWidth {
                for rotation in 0..<elementWidth {
                    let encoding = ARM64BitmaskImmediateEncoding(
                        n: elementWidth == 64 ? 1 : 0,
                        immr: UInt32(rotation),
                        imms: makeLogicalImmediateImms(elementWidth: elementWidth, oneBitCount: oneBitCount)
                    )
                    if encoding.n == n, encoding.immr == immr, encoding.imms == imms {
                        return makeBitmaskPattern(
                            elementWidth: elementWidth,
                            oneBitCount: oneBitCount,
                            rotation: rotation,
                            totalWidth: width.bitWidth
                        ) & width.valueMask
                    }
                }
            }
        }
        return nil
    }

    public static func data(for rawValue: UInt32) -> Data {
        var littleEndian = rawValue.littleEndian
        return Swift.withUnsafeBytes(of: &littleEndian) { Data($0) }
    }

    private static func decodeLogicalShiftedRegister(_ rawValue: UInt32) -> ARM64DecodedInstruction? {
        guard (rawValue & 0x1F20_0000) == 0x0A00_0000 else { return nil }

        let width = registerWidth(from: rawValue)
        let opc = (rawValue >> 29) & 0x3
        let shift = (rawValue >> 22) & 0x3
        let rm = (rawValue >> 16) & 0x1F
        let imm6 = (rawValue >> 10) & 0x3F
        let rn = (rawValue >> 5) & 0x1F
        let rd = rawValue & 0x1F

        guard shift == 0, imm6 == 0 else { return nil }

        if opc == 0b01, rn == ARM64RegisterWidth.zeroRegisterIndex {
            let kind: ARM64InstructionKind = rd == ARM64RegisterWidth.zeroRegisterIndex
                ? .noEffect(ARM64NoEffect(form: .discardViaMove, sourceRegister: rm, width: width))
                : .registerCopy(ARM64RegisterCopy(
                    form: .movAlias,
                    destinationRegister: rd,
                    sourceRegister: rm,
                    width: width
                ))
            return ARM64DecodedInstruction(rawValue: rawValue, kind: kind)
        }

        if opc == 0b00, rn == rm {
            let kind: ARM64InstructionKind = rd == ARM64RegisterWidth.zeroRegisterIndex
                ? .noEffect(ARM64NoEffect(form: .discardViaAndSelf, sourceRegister: rn, width: width))
                : .registerCopy(ARM64RegisterCopy(
                    form: .andSelf,
                    destinationRegister: rd,
                    sourceRegister: rn,
                    width: width
                ))
            return ARM64DecodedInstruction(rawValue: rawValue, kind: kind)
        }

        if opc == 0b01, rn == rm {
            let kind: ARM64InstructionKind = rd == ARM64RegisterWidth.zeroRegisterIndex
                ? .noEffect(ARM64NoEffect(form: .discardViaOrrSelf, sourceRegister: rn, width: width))
                : .registerCopy(ARM64RegisterCopy(
                    form: .orrSelf,
                    destinationRegister: rd,
                    sourceRegister: rn,
                    width: width
                ))
            return ARM64DecodedInstruction(rawValue: rawValue, kind: kind)
        }

        return nil
    }

    private static func decodeAddSubImmediate(_ rawValue: UInt32) -> ARM64DecodedInstruction? {
        guard (rawValue & 0x1F00_0000) == 0x1100_0000 else { return nil }

        let setFlags = (rawValue >> 29) & 0x1
        let isSub = ((rawValue >> 30) & 0x1) == 1
        let imm12 = (rawValue >> 10) & 0xFFF
        let rn = (rawValue >> 5) & 0x1F
        let rd = rawValue & 0x1F

        guard setFlags == 0, imm12 == 0 else { return nil }

        // In ADD/SUB immediate, register 31 encodes SP (not XZR).
        // We must exclude any instruction that reads or writes SP, because
        // logical-register replacements treat register 31 as XZR.
        guard rn != ARM64RegisterWidth.zeroRegisterIndex,
              rd != ARM64RegisterWidth.zeroRegisterIndex else {
            return nil
        }

        let width = registerWidth(from: rawValue)
        let form: ARM64RegisterCopyForm = isSub ? .subZero : .addZero
        return ARM64DecodedInstruction(
            rawValue: rawValue,
            kind: .registerCopy(ARM64RegisterCopy(
                form: form,
                destinationRegister: rd,
                sourceRegister: rn,
                width: width
            ))
        )
    }

    private static func decodeMoveWideImmediate(_ rawValue: UInt32) -> ARM64DecodedInstruction? {
        let moveWideMask: UInt32 = 0x7F80_0000
        let opcode = rawValue & moveWideMask
        // The mask clears bit 31 (sf), so both W-form (0x5280_0000) and
        // X-form produce the same masked value.  A single check suffices.
        guard opcode == 0x5280_0000 else { return nil }

        let width = registerWidth(from: rawValue)
        let halfwordShift = (rawValue >> 21) & 0x3
        guard halfwordShift == 0 else { return nil }

        let immediate = UInt64((rawValue >> 5) & 0xFFFF)
        let destinationRegister = rawValue & 0x1F
        return ARM64DecodedInstruction(
            rawValue: rawValue,
            kind: .immediateLoad(ARM64ImmediateLoad(
                form: .movzZeroShift,
                destinationRegister: destinationRegister,
                immediate: immediate,
                width: width
            ))
        )
    }

    private static func decodeLogicalImmediate(_ rawValue: UInt32) -> ARM64DecodedInstruction? {
        let width = registerWidth(from: rawValue)
        let opc = (rawValue >> 29) & 0x3
        let fixed = (rawValue >> 23) & 0x3F
        let n = (rawValue >> 22) & 0x1
        let immr = (rawValue >> 16) & 0x3F
        let imms = (rawValue >> 10) & 0x3F
        let rn = (rawValue >> 5) & 0x1F
        let rd = rawValue & 0x1F

        guard opc == 0b01, fixed == 0b100100, rn == ARM64RegisterWidth.zeroRegisterIndex else {
            return nil
        }
        guard let immediate = decodeBitmaskImmediate(n: n, immr: immr, imms: imms, width: width) else {
            return nil
        }
        guard immediate <= UInt64(UInt16.max) else { return nil }

        return ARM64DecodedInstruction(
            rawValue: rawValue,
            kind: .immediateLoad(ARM64ImmediateLoad(
                form: .orrLogicalImmediate(ARM64BitmaskImmediateEncoding(n: n, immr: immr, imms: imms)),
                destinationRegister: rd,
                immediate: immediate,
                width: width
            ))
        )
    }

    private static func registerWidth(from rawValue: UInt32) -> ARM64RegisterWidth {
        ((rawValue >> 31) & 0x1) == 1 ? .x64 : .w32
    }

    private static func makeLogicalImmediateImms(elementWidth: Int, oneBitCount: Int) -> UInt32 {
        let s = UInt32(oneBitCount - 1)
        if elementWidth == 64 {
            return s
        }
        let prefix = UInt32((~((elementWidth << 1) - 1)) & 0x3F)
        return prefix | s
    }

    private static func makeBitmaskPattern(
        elementWidth: Int,
        oneBitCount: Int,
        rotation: Int,
        totalWidth: Int
    ) -> UInt64 {
        let elementMask = widthMask(bitWidth: elementWidth)
        let onesMask = widthMask(bitWidth: oneBitCount)
        let rotated = rotateRight(onesMask, by: rotation, bitWidth: elementWidth) & elementMask

        var pattern: UInt64 = 0
        var bitOffset = 0
        while bitOffset < totalWidth {
            pattern |= rotated << bitOffset
            bitOffset += elementWidth
        }
        return pattern & widthMask(bitWidth: totalWidth)
    }

    private static func rotateRight(_ value: UInt64, by amount: Int, bitWidth: Int) -> UInt64 {
        let mask = widthMask(bitWidth: bitWidth)
        let normalized = amount % bitWidth
        guard normalized != 0 else { return value & mask }

        let truncated = value & mask
        let lower = truncated >> normalized
        let upper = (truncated << (bitWidth - normalized)) & mask
        return (lower | upper) & mask
    }

    private static func widthMask(bitWidth: Int) -> UInt64 {
        if bitWidth >= 64 {
            return UInt64.max
        }
        return (UInt64(1) << UInt64(bitWidth)) - 1
    }
}

public enum ARM64Decoder {
    public static func decode(_ rawValue: UInt32) -> ARM64DecodedInstruction? {
        ARM64Codec.decode(rawValue)
    }
}

public enum ARM64Encoder {
    public static func encode(_ decoded: ARM64DecodedInstruction?) -> UInt32 {
        ARM64Codec.encode(decoded)
    }
}

private extension Int {
    var isPowerOfTwo: Bool {
        self > 0 && (self & (self - 1)) == 0
    }
}
