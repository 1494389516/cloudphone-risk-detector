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

// MARK: - Group F: ConditionalBranch (CBZ/CBNZ <-> CSEL)

public enum ARM64ConditionalBranchForm: Equatable {
    case cbz
    case cbnz
    case cselZero
    case csincZero

    public var description: String {
        switch self {
        case .cbz: return "CBZ"
        case .cbnz: return "CBNZ"
        case .cselZero: return "CSEL Xd, Xn, XZR, EQ"
        case .csincZero: return "CSINC Xd, XZR, Xn, NE"
        }
    }
}

public struct ARM64ConditionalBranch: Equatable {
    public let form: ARM64ConditionalBranchForm
    public let register: UInt32
    public let immediate: Int32

    public init(form: ARM64ConditionalBranchForm, register: UInt32, immediate: Int32) {
        self.form = form
        self.register = register
        self.immediate = immediate
    }
}

// MARK: - Group G: CompareBranch (B.cond patterns)

public enum ARM64CompareBranchForm: Equatable {
    case cbz
    case cbnz
    case csincCond
    /// PC-relative `B.<cond>` (condition code stored in `ARM64CompareBranch.register` for encoding round-trips).
    case bConditional

    public var description: String {
        switch self {
        case .cbz: return "CBZ pattern"
        case .cbnz: return "CBNZ pattern"
        case .csincCond: return "CSINC conditional"
        case .bConditional: return "B.cond"
        }
    }
}

public struct ARM64CompareBranch: Equatable {
    public let form: ARM64CompareBranchForm
    public let register: UInt32
    public let immediate: Int32

    public init(form: ARM64CompareBranchForm, register: UInt32, immediate: Int32) {
        self.form = form
        self.register = register
        self.immediate = immediate
    }
}

// MARK: - Group H: LogicalShiftedRegister (shifted register variants)

public enum ARM64LogicalShiftedForm: Equatable {
    case addShifted
    case subShifted
    case eorShifted
    case bicShifted

    public var description: String {
        switch self {
        case .addShifted: return "ADD shifted register"
        case .subShifted: return "SUB shifted register"
        case .eorShifted: return "EOR shifted register"
        case .bicShifted: return "BIC shifted register"
        }
    }
}

public struct ARM64LogicalShifted: Equatable {
    public let form: ARM64LogicalShiftedForm
    public let destinationRegister: UInt32
    public let sourceRegister1: UInt32
    public let sourceRegister2: UInt32
    public let shiftType: UInt32
    public let shiftAmount: UInt32
    public let width: ARM64RegisterWidth

    public init(
        form: ARM64LogicalShiftedForm,
        destinationRegister: UInt32,
        sourceRegister1: UInt32,
        sourceRegister2: UInt32,
        shiftType: UInt32,
        shiftAmount: UInt32,
        width: ARM64RegisterWidth
    ) {
        self.form = form
        self.destinationRegister = destinationRegister
        self.sourceRegister1 = sourceRegister1
        self.sourceRegister2 = sourceRegister2
        self.shiftType = shiftType
        self.shiftAmount = shiftAmount
        self.width = width
    }
}

// MARK: - Group I: MultiplyAccumulate (MADD/MSUB <-> MUL variants)

public enum ARM64MultiplyAccumulateForm: Equatable {
    case madd
    case msub
    case mul

    public var description: String {
        switch self {
        case .madd: return "MADD"
        case .msub: return "MSUB"
        case .mul: return "MUL (MADD with XZR)"
        }
    }
}

public struct ARM64MultiplyAccumulate: Equatable {
    public let form: ARM64MultiplyAccumulateForm
    public let destinationRegister: UInt32
    public let multiplicand: UInt32
    public let multiplier: UInt32
    public let accumulator: UInt32

    public init(
        form: ARM64MultiplyAccumulateForm,
        destinationRegister: UInt32,
        multiplicand: UInt32,
        multiplier: UInt32,
        accumulator: UInt32
    ) {
        self.form = form
        self.destinationRegister = destinationRegister
        self.multiplicand = multiplicand
        self.multiplier = multiplier
        self.accumulator = accumulator
    }
}

// MARK: - Group J: LoadLiteral

public enum ARM64LoadLiteralForm: Equatable {
    case ldrLiteral
    case adrpAdd

    public var description: String {
        switch self {
        case .ldrLiteral: return "LDR literal"
        case .adrpAdd: return "ADRP+ADD :lo12:"
        }
    }
}

public struct ARM64LoadLiteral: Equatable {
    public let form: ARM64LoadLiteralForm
    public let destinationRegister: UInt32
    public let immediate: Int64
    public let width: ARM64RegisterWidth

    public init(
        form: ARM64LoadLiteralForm,
        destinationRegister: UInt32,
        immediate: Int64,
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
    case conditionalBranch(ARM64ConditionalBranch)
    case compareBranch(ARM64CompareBranch)
    case logicalShifted(ARM64LogicalShifted)
    case multiplyAccumulate(ARM64MultiplyAccumulate)
    case loadLiteral(ARM64LoadLiteral)
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
        if let decoded = decodeCompareBranch(rawValue) {
            return decoded
        }
        if let decoded = decodeCSEL(rawValue) {
            return decoded
        }
        if let decoded = decodeCSINC(rawValue) {
            return decoded
        }
        if let decoded = decodeMultiplyAccumulate(rawValue) {
            return decoded
        }
        if let decoded = decodeLoadLiteral(rawValue) {
            return decoded
        }
        if let decoded = decodeLogicalShiftedRegisterVariant(rawValue) {
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

        case .conditionalBranch(let cb):
            switch cb.form {
            case .cbz:
                return encodeCBZ(destinationRegister: cb.register, immediateWords: Int(cb.immediate >> 2))
            case .cbnz:
                return encodeCBNZ(destinationRegister: cb.register, immediateWords: Int(cb.immediate >> 2))
            case .cselZero:
                return encodeCSEL(
                    destination: cb.register,
                    sourceTrue: 0,
                    sourceFalse: 31,
                    condition: 0
                )
            case .csincZero:
                return encodeCSINC(
                    destination: cb.register,
                    sourceTrue: 31,
                    sourceFalse: 31,
                    condition: 1
                )
            }

        case .compareBranch(let cb):
            switch cb.form {
            case .cbz:
                return encodeCBZ(destinationRegister: cb.register, immediateWords: Int(cb.immediate >> 2))
            case .cbnz:
                return encodeCBNZ(destinationRegister: cb.register, immediateWords: Int(cb.immediate >> 2))
            case .csincCond:
                return encodeCSINC(
                    destination: cb.register,
                    sourceTrue: 31,
                    sourceFalse: 31,
                    condition: 1
                )
            case .bConditional:
                return encodeBCond(
                    conditionCode: cb.register,
                    immediateBytes: Int(cb.immediate)
                )
            }

        case .logicalShifted(let ls):
            switch ls.form {
            case .addShifted:
                return encodeAddShiftedRegister(
                    destination: ls.destinationRegister,
                    source1: ls.sourceRegister1,
                    source2: ls.sourceRegister2,
                    shiftType: ls.shiftType,
                    shiftAmount: ls.shiftAmount,
                    width: ls.width
                )
            case .subShifted:
                return encodeSubShiftedRegister(
                    destination: ls.destinationRegister,
                    source1: ls.sourceRegister1,
                    source2: ls.sourceRegister2,
                    shiftType: ls.shiftType,
                    shiftAmount: ls.shiftAmount,
                    width: ls.width
                )
            case .eorShifted:
                return encodeLogicalShiftedRegister(
                    destination: ls.destinationRegister,
                    source1: ls.sourceRegister1,
                    source2: ls.sourceRegister2,
                    shiftType: ls.shiftType,
                    shiftAmount: ls.shiftAmount,
                    opc: 2,
                    width: ls.width
                )
            case .bicShifted:
                return encodeLogicalShiftedRegister(
                    destination: ls.destinationRegister,
                    source1: ls.sourceRegister1,
                    source2: ls.sourceRegister2,
                    shiftType: ls.shiftType,
                    shiftAmount: ls.shiftAmount,
                    opc: 0,
                    width: ls.width
                )
            }

        case .multiplyAccumulate(let ma):
            switch ma.form {
            case .madd:
                return encodeMADD(
                    destination: ma.destinationRegister,
                    multiplicand: ma.multiplicand,
                    multiplier: ma.multiplier,
                    accumulator: ma.accumulator
                )
            case .msub:
                return encodeMSUB(
                    destination: ma.destinationRegister,
                    multiplicand: ma.multiplicand,
                    multiplier: ma.multiplier,
                    accumulator: ma.accumulator
                )
            case .mul:
                return encodeMADD(
                    destination: ma.destinationRegister,
                    multiplicand: ma.multiplicand,
                    multiplier: ma.multiplier,
                    accumulator: 31
                )
            }

        case .loadLiteral(let ll):
            switch ll.form {
            case .ldrLiteral:
                return encodeLoadLiteral(
                    destinationRegister: ll.destinationRegister,
                    immediate: ll.immediate,
                    width: ll.width
                )
            case .adrpAdd:
                return encodeLoadLiteral(
                    destinationRegister: ll.destinationRegister,
                    immediate: ll.immediate,
                    width: ll.width
                )
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
        return encodeORRLogicalImmediate(
            destinationRegister: destinationRegister,
            encoding: encoding,
            width: width
        )
    }

    public static func encodeORRLogicalImmediateVariants(
        destinationRegister: UInt32,
        immediate: UInt64,
        width: ARM64RegisterWidth
    ) -> [UInt32] {
        let target = immediate & width.valueMask
        guard target != 0, target != width.valueMask else { return [] }

        var variants: [UInt32] = []
        variants.reserveCapacity(8)
        var seen = Set<UInt32>()
        let maxElementWidth = width.is64Bit ? 64 : 32

        for elementWidth in stride(from: 2, through: maxElementWidth, by: 2) where elementWidth.isPowerOfTwo {
            for oneBitCount in 1..<elementWidth {
                for rotation in 0..<elementWidth {
                    let pattern = makeBitmaskPattern(
                        elementWidth: elementWidth,
                        oneBitCount: oneBitCount,
                        rotation: rotation,
                        totalWidth: width.bitWidth
                    ) & width.valueMask
                    guard pattern == target else { continue }

                    let encoding = ARM64BitmaskImmediateEncoding(
                        n: elementWidth == 64 ? 1 : 0,
                        immr: UInt32(rotation),
                        imms: makeLogicalImmediateImms(elementWidth: elementWidth, oneBitCount: oneBitCount)
                    )
                    let raw = encodeORRLogicalImmediate(
                        destinationRegister: destinationRegister,
                        encoding: encoding,
                        width: width
                    )
                    if seen.insert(raw).inserted {
                        variants.append(raw)
                    }
                }
            }
        }
        return variants
    }

    private static func encodeORRLogicalImmediate(
        destinationRegister: UInt32,
        encoding: ARM64BitmaskImmediateEncoding,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0xB200_0000 : 0x3200_0000
        return base
            | ((encoding.n & 0x1) << 22)
            | ((encoding.immr & 0x3F) << 16)
            | ((encoding.imms & 0x3F) << 10)
            | ((ARM64RegisterWidth.zeroRegisterIndex & 0x1F) << 5)
            | (destinationRegister & 0x1F)
    }

    // MARK: - Group F Encode Functions

    public static func encodeCSEL(
        destination: UInt32,
        sourceTrue: UInt32,
        sourceFalse: UInt32,
        condition: UInt32
    ) -> UInt32 {
        return 0x9A80_0000
            | ((condition & 0xF) << 12)
            | ((sourceFalse & 0x1F) << 16)
            | ((sourceTrue & 0x1F) << 5)
            | (destination & 0x1F)
    }

    public static func encodeCSINC(
        destination: UInt32,
        sourceTrue: UInt32,
        sourceFalse: UInt32,
        condition: UInt32
    ) -> UInt32 {
        return 0x9A80_0000
            | (1 << 20)
            | ((condition & 0xF) << 12)
            | ((sourceFalse & 0x1F) << 16)
            | ((sourceTrue & 0x1F) << 5)
            | (destination & 0x1F)
    }

    /// imm19 is a SIGNED 19-bit word offset, valid range [-2^18, 2^18). Clamp in the signed
    /// domain so CBZ/CBNZ can emit backward branches; a plain `[0, 0x7FFFF]` clamp both drops
    /// negatives to zero and lets the top half (262144…524287) wrap to negative by truncation.
    private static func clampImm19Words(_ words: Int) -> Int {
        let maxPos = (1 << 18) - 1
        let minNeg = -(1 << 18)
        return max(min(words, maxPos), minNeg)
    }

    public static func encodeCBZ(destinationRegister: UInt32, immediateWords: Int) -> UInt32 {
        let clamped = clampImm19Words(immediateWords)
        let imm19 = UInt32(bitPattern: Int32(clamped)) & 0x7FFFF
        return 0xB400_0000 | (imm19 << 5) | (destinationRegister & 0x1F)
    }

    public static func encodeCBNZ(destinationRegister: UInt32, immediateWords: Int) -> UInt32 {
        let clamped = clampImm19Words(immediateWords)
        let imm19 = UInt32(bitPattern: Int32(clamped)) & 0x7FFFF
        return 0xB500_0000 | (imm19 << 5) | (destinationRegister & 0x1F)
    }

    /// `B.<cond>` PC-relative branch (offset must be a multiple of 4; encoded as signed imm19 words).
    public static func encodeBCond(conditionCode: UInt32, immediateBytes: Int) -> UInt32 {
        precondition(immediateBytes % 4 == 0, "B.cond offset must be 4-byte aligned")
        let wordOffset = clampImm19Words(immediateBytes / 4)
        let imm19 = UInt32(bitPattern: Int32(wordOffset)) & 0x7FFFF
        return 0x5400_0000 | (imm19 << 5) | (conditionCode & 0xF)
    }

    /// `SUBS` with shifted register form, shift = LSL #0 (sets flags for `B.cond` veneers).
    public static func encodeSUBSShiftedRegister(
        destination: UInt32,
        source1: UInt32,
        source2: UInt32,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let high: UInt32 = width.is64Bit ? 0xEB00_0000 : 0x6B00_0000
        return high
            | ((source2 & 0x1F) << 16)
            | ((source1 & 0x1F) << 5)
            | (destination & 0x1F)
    }

    // MARK: - Group I Encode Functions

    public static func encodeMADD(
        destination: UInt32,
        multiplicand: UInt32,
        multiplier: UInt32,
        accumulator: UInt32
    ) -> UInt32 {
        return 0x9B00_0000
            | ((multiplier & 0x1F) << 16)
            | ((accumulator & 0x1F) << 10)
            | ((multiplicand & 0x1F) << 5)
            | (destination & 0x1F)
    }

    public static func encodeMSUB(
        destination: UInt32,
        multiplicand: UInt32,
        multiplier: UInt32,
        accumulator: UInt32
    ) -> UInt32 {
        return 0x9B00_8000
            | ((multiplier & 0x1F) << 16)
            | ((accumulator & 0x1F) << 10)
            | ((multiplicand & 0x1F) << 5)
            | (destination & 0x1F)
    }

    // MARK: - Group H Encode Functions

    public static func encodeAddShiftedRegister(
        destination: UInt32,
        source1: UInt32,
        source2: UInt32,
        shiftType: UInt32,
        shiftAmount: UInt32,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0x0B20_0000 : 0x0B00_0000
        return base
            | ((shiftType & 0x3) << 22)
            | ((source2 & 0x1F) << 16)
            | ((shiftAmount & 0x3F) << 10)
            | ((source1 & 0x1F) << 5)
            | (destination & 0x1F)
    }

    public static func encodeSubShiftedRegister(
        destination: UInt32,
        source1: UInt32,
        source2: UInt32,
        shiftType: UInt32,
        shiftAmount: UInt32,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0xCB20_0000 : 0xCB00_0000
        return base
            | ((shiftType & 0x3) << 22)
            | ((source2 & 0x1F) << 16)
            | ((shiftAmount & 0x3F) << 10)
            | ((source1 & 0x1F) << 5)
            | (destination & 0x1F)
    }

    public static func encodeLogicalShiftedRegister(
        destination: UInt32,
        source1: UInt32,
        source2: UInt32,
        shiftType: UInt32,
        shiftAmount: UInt32,
        opc: UInt32,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let sf: UInt32 = width.is64Bit ? 0 : (1 << 31)
        let base: UInt32 = width.is64Bit ? 0x8A00_0000 : 0x0A00_0000
        return base
            | sf
            | ((opc & 0x3) << 29)
            | ((shiftType & 0x3) << 22)
            | ((source2 & 0x1F) << 16)
            | ((shiftAmount & 0x3F) << 10)
            | ((source1 & 0x1F) << 5)
            | (destination & 0x1F)
    }

    // MARK: - Group J Encode Function

    public static func encodeLoadLiteral(
        destinationRegister: UInt32,
        immediate: Int64,
        width: ARM64RegisterWidth
    ) -> UInt32 {
        let imm19 = UInt32((immediate >> 2) & 0x7FFFF)
        let base: UInt32 = width.is64Bit ? 0x5C00_0000 : 0x5800_0000
        return base | (imm19 << 5) | (destinationRegister & 0x1F)
    }

    // MARK: - Group F Decode Functions

    private static func decodeCSEL(_ raw: UInt32) -> ARM64DecodedInstruction? {
        guard (raw & 0xFF800000) == 0x9A800000 else { return nil }
        guard (raw & (1 << 20)) == 0 else { return nil }
        let rm = (raw >> 16) & 0x1F
        let rd = raw & 0x1F
        guard rm == ARM64RegisterWidth.zeroRegisterIndex else { return nil }
        return ARM64DecodedInstruction(
            rawValue: raw,
            kind: .conditionalBranch(ARM64ConditionalBranch(form: .cselZero, register: rd, immediate: 0))
        )
    }

    private static func decodeCSINC(_ raw: UInt32) -> ARM64DecodedInstruction? {
        guard (raw & 0xFFF80000) == 0x9A800000 else { return nil }
        guard (raw & (1 << 20)) != 0 else { return nil }
        let rm = (raw >> 16) & 0x1F
        let rn = (raw >> 5) & 0x1F
        let rd = raw & 0x1F
        guard rm == ARM64RegisterWidth.zeroRegisterIndex,
              rn == ARM64RegisterWidth.zeroRegisterIndex else { return nil }
        return ARM64DecodedInstruction(
            rawValue: raw,
            kind: .conditionalBranch(ARM64ConditionalBranch(form: .csincZero, register: rd, immediate: 0))
        )
    }

    // MARK: - Group G Decode Functions

    /// CBZ/CBNZ and `B.<cond>` share compare/branch-like semantics for substitution passes.
    /// `B.<cond>` stores the condition code in `register` (0...15) and the PC-relative byte offset in `immediate`.
    private static func decodeCompareBranch(_ raw: UInt32) -> ARM64DecodedInstruction? {
        if let bCond = decodeBCondInstruction(raw) {
            return bCond
        }

        let high = (raw >> 24) & 0x7F
        guard high == 0x34 || high == 0x35 else { return nil }
        let isCbnz = high == 0x35
        let imm19 = (raw >> 5) & 0x7FFFF
        let rt = raw & 0x1F
        let imm = expandPCRelativeOffset(Int32(imm19 << 2))
        let form: ARM64CompareBranchForm = isCbnz ? .cbnz : .cbz
        return ARM64DecodedInstruction(
            rawValue: raw,
            kind: .compareBranch(ARM64CompareBranch(form: form, register: rt, immediate: imm))
        )
    }

    /// `B.<cond>`: top byte 0x54, imm19 in bits [23:5], condition in bits [3:0].
    private static func decodeBCondInstruction(_ raw: UInt32) -> ARM64DecodedInstruction? {
        guard (raw & 0xFF00_0010) == 0x5400_0000 else { return nil }
        let imm19 = (raw >> 5) & 0x7FFFF
        let cond = raw & 0xF
        let imm = expandPCRelativeOffset(Int32(imm19 << 2))
        return ARM64DecodedInstruction(
            rawValue: raw,
            kind: .compareBranch(ARM64CompareBranch(
                form: .bConditional,
                register: cond,
                immediate: imm
            ))
        )
    }

    // MARK: - Group H Decode Functions

    private static func decodeLogicalShiftedRegisterVariant(_ raw: UInt32) -> ARM64DecodedInstruction? {
        // Restrict to the logical shifted-register major opcode class.
        // Without this gate, unrelated encodings (e.g. RET/SVC/BRK) can
        // accidentally satisfy opc/shift predicates and be misclassified.
        guard (raw & 0x1F20_0000) == 0x0A00_0000 else { return nil }

        let width = registerWidth(from: raw)
        let opc = (raw >> 29) & 0x3
        let shift = (raw >> 22) & 0x3
        let rm = (raw >> 16) & 0x1F
        let imm6 = (raw >> 10) & 0x3F
        let rn = (raw >> 5) & 0x1F
        let rd = raw & 0x1F

        // Exclude the patterns already handled by decodeLogicalShiftedRegister (shift==0)
        guard shift != 0 || imm6 != 0 else { return nil }

        // ADD shifted register: opc=00, shift=01(LSR)
        if opc == 0b00, shift == 0b01 {
            return ARM64DecodedInstruction(
                rawValue: raw,
                kind: .logicalShifted(ARM64LogicalShifted(
                    form: .addShifted,
                    destinationRegister: rd,
                    sourceRegister1: rn,
                    sourceRegister2: rm,
                    shiftType: shift,
                    shiftAmount: imm6,
                    width: width
                ))
            )
        }

        // SUB shifted register: opc=10, shift=01(LSR)
        if opc == 0b10, shift == 0b01 {
            return ARM64DecodedInstruction(
                rawValue: raw,
                kind: .logicalShifted(ARM64LogicalShifted(
                    form: .subShifted,
                    destinationRegister: rd,
                    sourceRegister1: rn,
                    sourceRegister2: rm,
                    shiftType: shift,
                    shiftAmount: imm6,
                    width: width
                ))
            )
        }

        // EOR shifted register: opc=10, shift!=0 (opc bits [30:29] = 0b10, we use opc field differently here)
        // Actually EOR shifted: opcode bits 29-30 = 0b10, opc field is bits 29:30 combined with shift
        // Let me reconsider: logical shifted register encoding:
        // Bits [30:29] opc: 00=AND, 01=ORR, 10=EOR, 11=BIC
        // When shift != 0, these are shifted variants
        if opc == 0b10, shift != 0 {
            return ARM64DecodedInstruction(
                rawValue: raw,
                kind: .logicalShifted(ARM64LogicalShifted(
                    form: .eorShifted,
                    destinationRegister: rd,
                    sourceRegister1: rn,
                    sourceRegister2: rm,
                    shiftType: shift,
                    shiftAmount: imm6,
                    width: width
                ))
            )
        }

        if opc == 0b11, shift != 0 {
            return ARM64DecodedInstruction(
                rawValue: raw,
                kind: .logicalShifted(ARM64LogicalShifted(
                    form: .bicShifted,
                    destinationRegister: rd,
                    sourceRegister1: rn,
                    sourceRegister2: rm,
                    shiftType: shift,
                    shiftAmount: imm6,
                    width: width
                ))
            )
        }

        return nil
    }

    // MARK: - Group I Decode Functions

    private static func decodeMultiplyAccumulate(_ raw: UInt32) -> ARM64DecodedInstruction? {
        guard (raw & 0xFF200000) == 0x9B000000 else { return nil }
        let op = (raw >> 21) & 0x3
        guard op <= 1 else { return nil }
        let rm = (raw >> 16) & 0x1F
        let ra = (raw >> 10) & 0x1F
        let rn = (raw >> 5) & 0x1F
        let rd = raw & 0x1F
        let form: ARM64MultiplyAccumulateForm = op == 0 ? .madd : .msub
        return ARM64DecodedInstruction(
            rawValue: raw,
            kind: .multiplyAccumulate(ARM64MultiplyAccumulate(
                form: form,
                destinationRegister: rd,
                multiplicand: rn,
                multiplier: rm,
                accumulator: ra
            ))
        )
    }

    // MARK: - Group J Decode Functions

    private static func decodeLoadLiteral(_ raw: UInt32) -> ARM64DecodedInstruction? {
        let high = (raw >> 24) & 0xFF
        guard high == 0x18 || high == 0x58 || high == 0x5C else { return nil }
        let isXReg = ((raw >> 30) & 1) != 0
        let imm19 = (raw >> 5) & 0x7FFFF
        let rt = raw & 0x1F
        let imm = Int64(imm19 << 2)
        return ARM64DecodedInstruction(
            rawValue: raw,
            kind: .loadLiteral(ARM64LoadLiteral(
                form: .ldrLiteral,
                destinationRegister: rt,
                immediate: imm,
                width: isXReg ? .x64 : .w32
            ))
        )
    }

    // MARK: - Helper Functions

    private static func expandPCRelativeOffset(_ value: Int32) -> Int32 {
        if (UInt32(bitPattern: value) & 0x00080000) != 0 {
            return Int32(bitPattern: UInt32(bitPattern: value) | 0xFFF00000)
        }
        return value
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
