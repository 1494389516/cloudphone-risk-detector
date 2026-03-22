import Foundation
import MachOKit

public struct VMSectionPayloads {
    public let dispatch: Data
    public let bytecode: Data

    public init(dispatch: Data, bytecode: Data) {
        self.dispatch = dispatch
        self.bytecode = bytecode
    }
}

/// M3 optional metadata appended after the 256-byte dispatch class table (CRiskCore reads only the prefix; tail is forward-compatible).
public struct VMM3EmitOptions: Equatable, Sendable {
    /// Opaque VPC predicate-chain constants for build-time / future runtime consumers.
    public var vpcPredicateConstants: [UInt64]
    public var enableDeadHandlers: Bool
    public var enableOpaquePredicateChain: Bool
    public var enableSelfIntegrityCheck: Bool

    public init(
        vpcPredicateConstants: [UInt64] = [],
        enableDeadHandlers: Bool = false,
        enableOpaquePredicateChain: Bool = false,
        enableSelfIntegrityCheck: Bool = false
    ) {
        self.vpcPredicateConstants = vpcPredicateConstants
        self.enableDeadHandlers = enableDeadHandlers
        self.enableOpaquePredicateChain = enableOpaquePredicateChain
        self.enableSelfIntegrityCheck = enableSelfIntegrityCheck
    }
}

/// Build-time options for M2 metadata and wire encoding (consumable by future runtime; v1 interpreter ignores M2 blob).
public struct VMM2EmitOptions: Equatable, Sendable {
    /// When true, pack `VMRawRegionCategory` into the high 32 bits of `rawRegion` immediates (changes accumulator mix vs plain insn word).
    public var opaqueVpcCategoryHigh32: Bool
    public var handlerVariantSeed: UInt64
    /// Emit per-entry VPC affine metadata (runtime reads A/B after each entry when enabled).
    public var perEntryVpcEnabled: Bool
    public var m3: VMM3EmitOptions

    public init(
        opaqueVpcCategoryHigh32: Bool = false,
        handlerVariantSeed: UInt64 = 0,
        perEntryVpcEnabled: Bool = true,
        m3: VMM3EmitOptions = VMM3EmitOptions()
    ) {
        self.opaqueVpcCategoryHigh32 = opaqueVpcCategoryHigh32
        self.handlerVariantSeed = handlerVariantSeed
        self.perEntryVpcEnabled = perEntryVpcEnabled
        self.m3 = m3
    }
}

/// On-disk layout for Pass 13 VM payloads.
public enum VMBytecodeFormat {
    /// Bytes `C P V D` on disk (little-endian word 0x4456_5043).
    public static let dispatchMagic: UInt32 = 0x4456_5043
    /// Bytes `C P V M` on disk (little-endian word 0x4D56_5043).
    public static let bytecodeMagic: UInt32 = 0x4D56_5043
    public static let dispatchABIVersion: UInt32 = 1
    public static let bytecodeABIVersionV1: UInt32 = 1
    public static let bytecodeABIVersionV2: UInt32 = 2
    public static let sectionSegment = ArmorABI.dataSegmentName
    public static let dispatchSection = ArmorABI.Sections.vmpDispatch
    public static let bytecodeSection = ArmorABI.Sections.vmpBytecode
    public static let dispatchTableSize = 256
    public static let entryCoreSize = 32
    public static let vpcAffineBytes = 16

    public enum BytecodeFlags {
        public static let none: UInt32 = 0
        /// Runtime: include a 2-bit handler variant seed in header reserved high bits.
        public static let handlerVariantSeed: UInt32 = 1 << 0
        /// Runtime: each entry is followed by 16 bytes `vpc_a(8) + vpc_b(8)`.
        public static let perEntryVpc: UInt32 = 1 << 1
        /// Runtime M3: opaque predicate-chain enabled in interpreter dispatch.
        public static let m3OpaqueChain: UInt32 = 1 << 2
        /// Runtime M3: dead-handler bait paths enabled.
        public static let m3DeadHandlers: UInt32 = 1 << 3
        /// Runtime M3: interpreter self-integrity check enabled.
        public static let m3SelfIntegrity: UInt32 = 1 << 4
    }

    /// Dispatch header `flags` (M2 + M3 producer hints). CRiskCore does not branch on these today; safe to extend.
    public enum DispatchHeaderFlags {
        public static let handlerDuplicationPools: UInt32 = 1 << 0
        public static let opaqueVpcCategoryHigh32: UInt32 = 1 << 1
        public static let deadHandlerMetadata: UInt32 = 1 << 2
        public static let vpcPredicateChainMetadata: UInt32 = 1 << 3
    }

    /// Little-endian tail after the 256-byte class table (`HV3M`).
    public static let m3DispatchTailMagic: UInt32 = 0x4D335648
    public static let m3DispatchTailVersion: UInt32 = 1

    /// Unaligned-safe little-endian readers for on-disk payloads.
    public static func readUInt32LE(_ data: Data, offset: Int) -> UInt32 {
        precondition(offset + 4 <= data.count)
        return UInt32(data[offset])
            | UInt32(data[offset + 1]) << 8
            | UInt32(data[offset + 2]) << 16
            | UInt32(data[offset + 3]) << 24
    }

    public static func readUInt64LE(_ data: Data, offset: Int) -> UInt64 {
        precondition(offset + 8 <= data.count)
        let lo = readUInt32LE(data, offset: offset)
        let hi = readUInt32LE(data, offset: offset + 4)
        return UInt64(lo) | (UInt64(hi) << 32)
    }

    public enum TierCode: UInt32 {
        case full = 1
        case partial = 2
    }

    public struct DispatchHeader {
        public let tableSize: UInt32
        /// Bit 0: handler duplication pools enabled. Bit 1: opaque VPC category high-32 in immediates.
        public let flags: UInt32

        public func serialize() -> Data {
            var d = Data()
            d.appendUInt32(VMBytecodeFormat.dispatchMagic)
            d.appendUInt32(VMBytecodeFormat.dispatchABIVersion)
            d.appendUInt32(tableSize)
            d.appendUInt32(flags)
            return d
        }
    }

    public struct BytecodeHeader {
        public let version: UInt32
        public let entryCount: UInt32
        /// Runtime flags (see `CPRISK_VMP_BC_FLAG_*`).
        public let reservedFlags: UInt32

        public func serialize() -> Data {
            var d = Data()
            d.appendUInt32(VMBytecodeFormat.bytecodeMagic)
            d.appendUInt32(version)
            d.appendUInt32(entryCount)
            d.appendUInt32(reservedFlags)
            return d
        }
    }

    public struct Entry {
        public let functionId: UInt64
        public let originalEntryVMA: UInt64
        public let tier: TierCode
        public let bytecodeOffset: UInt32
        public let bytecodeLength: UInt32
        public let reserved: UInt32

        public func serialize() -> Data {
            var d = Data()
            d.appendUInt64(functionId)
            d.appendUInt64(originalEntryVMA)
            d.appendUInt32(tier.rawValue)
            d.appendUInt32(bytecodeOffset)
            d.appendUInt32(bytecodeLength)
            d.appendUInt32(reserved)
            return d
        }
    }
}

private extension Data {
    mutating func appendUInt32(_ v: UInt32) {
        var le = v.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }

    mutating func appendUInt64(_ v: UInt64) {
        var le = v.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }
}

/// Encodes VMIR + opcode table into a single section payload.
public struct VMBytecodeEmitter: Sendable {
    public init() {}

    public func emit(
        programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])],
        opcodeTable: VMOpcodeTable,
        options: VMM2EmitOptions = VMM2EmitOptions()
    ) -> VMSectionPayloads {
        let dispatch = emitDispatchTable(opcodeTable: opcodeTable, options: options)
        let bytecode = emitBytecode(programs: programs, opcodeTable: opcodeTable, options: options)
        return VMSectionPayloads(dispatch: dispatch, bytecode: bytecode)
    }

    private func emitDispatchTable(opcodeTable: VMOpcodeTable, options: VMM2EmitOptions) -> Data {
        var flags: UInt32 = 0
        if opcodeTable.handlerDuplicationEnabled { flags |= VMBytecodeFormat.DispatchHeaderFlags.handlerDuplicationPools }
        if options.opaqueVpcCategoryHigh32 { flags |= VMBytecodeFormat.DispatchHeaderFlags.opaqueVpcCategoryHigh32 }
        let dead = opcodeTable.deadHandlerInjection
        let preds = options.m3.vpcPredicateConstants
        let emitM3Tail = (options.m3.enableDeadHandlers && dead != nil) || (options.m3.enableOpaquePredicateChain && !preds.isEmpty)
        if options.m3.enableDeadHandlers, dead != nil { flags |= VMBytecodeFormat.DispatchHeaderFlags.deadHandlerMetadata }
        if options.m3.enableOpaquePredicateChain, !preds.isEmpty { flags |= VMBytecodeFormat.DispatchHeaderFlags.vpcPredicateChainMetadata }
        var out = VMBytecodeFormat.DispatchHeader(tableSize: UInt32(VMBytecodeFormat.dispatchTableSize), flags: flags).serialize()
        out.append(contentsOf: opcodeTable.rawToLogicalTable())
        if emitM3Tail {
            out.append(
                Self.serializeM3DispatchTail(
                    dead: options.m3.enableDeadHandlers ? dead : nil,
                    predicateConstants: options.m3.enableOpaquePredicateChain ? preds : []
                )
            )
        }
        return out
    }

    /// Deterministic opaque predicate chain for M3 metadata (build-time; independent of opcode pools).
    public static func generateVpcPredicateChain(seed: UInt64, count: Int = 8) -> [UInt64] {
        var rng = VMProtectorSplitMix64(seed: seed ^ 0x5650_4350_5244_4D33) // "VPRDM3"
        return (0..<count).map { _ in rng.next() }
    }

    /// Serialized M3 tail: magic, version, dead budget/seed, predicate constants.
    public static func serializeM3DispatchTail(dead: VMDeadHandlerInjection?, predicateConstants: [UInt64]) -> Data {
        var d = Data()
        d.appendUInt32(VMBytecodeFormat.m3DispatchTailMagic)
        d.appendUInt32(VMBytecodeFormat.m3DispatchTailVersion)
        let budget = dead.map { UInt32($0.budget) } ?? 0
        let deadSeed = dead?.seed ?? 0
        d.appendUInt32(budget)
        d.appendUInt64(deadSeed)
        d.appendUInt32(UInt32(predicateConstants.count))
        for p in predicateConstants {
            d.appendUInt64(p)
        }
        return d
    }

    /// Parses M3 tail from a full `__swift5_mdvrt` payload (returns nil if no tail).
    public static func parseM3DispatchTail(fromDispatchPayload dispatch: Data) -> (deadBudget: UInt32, deadSeed: UInt64, predicates: [UInt64])? {
        let prefix = 16 + VMBytecodeFormat.dispatchTableSize
        guard dispatch.count >= prefix + 24 else { return nil }
        let tailStart = prefix
        let magic = VMBytecodeFormat.readUInt32LE(dispatch, offset: tailStart)
        guard magic == VMBytecodeFormat.m3DispatchTailMagic else { return nil }
        var o = tailStart + 4
        _ = VMBytecodeFormat.readUInt32LE(dispatch, offset: o) // version
        o += 4
        let deadBudget = VMBytecodeFormat.readUInt32LE(dispatch, offset: o)
        o += 4
        let deadSeed = VMBytecodeFormat.readUInt64LE(dispatch, offset: o)
        o += 8
        let predCount = Int(VMBytecodeFormat.readUInt32LE(dispatch, offset: o))
        o += 4
        guard predCount >= 0, o + predCount * 8 <= dispatch.count else { return nil }
        var preds: [UInt64] = []
        preds.reserveCapacity(predCount)
        for _ in 0..<predCount {
            let p = VMBytecodeFormat.readUInt64LE(dispatch, offset: o)
            preds.append(p)
            o += 8
        }
        return (deadBudget, deadSeed, preds)
    }

    private func emitBytecode(
        programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])],
        opcodeTable: VMOpcodeTable,
        options: VMM2EmitOptions
    ) -> Data {
        let useM2 = options.perEntryVpcEnabled || options.handlerVariantSeed != 0
        let perEntryVpc = useM2 && options.perEntryVpcEnabled
        let bytecodeVersion = useM2 ? VMBytecodeFormat.bytecodeABIVersionV2 : VMBytecodeFormat.bytecodeABIVersionV1
        let headerSize = 16 + (useM2 ? VMBytecodeFormat.vpcAffineBytes : 0)
        let entryStride = VMBytecodeFormat.entryCoreSize + (perEntryVpc ? VMBytecodeFormat.vpcAffineBytes : 0)
        let bodies: [Data] = programs.map { encode(program: $0.instructions, opcodeTable: opcodeTable, options: options) }
        let tableBytes = headerSize + programs.count * entryStride
        var cursor = UInt32(tableBytes)
        var entriesData = Data()
        for (index, program) in programs.enumerated() {
            let body = bodies[index]
            let hv = Self.handlerVariant(functionId: program.functionId, seed: options.handlerVariantSeed)
            let reserved = Self.packEntryReserved(
                handlerVariant: hv,
                vpcA: Self.deriveVpcAffine(functionId: program.functionId, seed: options.handlerVariantSeed).0
            )
            let entry = VMBytecodeFormat.Entry(
                functionId: program.functionId,
                originalEntryVMA: program.entryVMA,
                tier: program.tier,
                bytecodeOffset: cursor,
                bytecodeLength: UInt32(body.count),
                reserved: reserved
            )
            entriesData.append(entry.serialize())
            if perEntryVpc {
                let (a, b) = Self.deriveVpcAffine(functionId: program.functionId, seed: options.handlerVariantSeed)
                entriesData.append(serializeVpcAffine(a: a, b: b))
            }
            cursor += UInt32(body.count)
        }
        var flags: UInt32 = VMBytecodeFormat.BytecodeFlags.none
        if options.handlerVariantSeed != 0 {
            flags |= VMBytecodeFormat.BytecodeFlags.handlerVariantSeed
            flags |= (UInt32(options.handlerVariantSeed & 0x3) << 8)
        }
        if perEntryVpc {
            flags |= VMBytecodeFormat.BytecodeFlags.perEntryVpc
        }
        if options.m3.enableOpaquePredicateChain {
            flags |= VMBytecodeFormat.BytecodeFlags.m3OpaqueChain
        }
        if options.m3.enableDeadHandlers {
            flags |= VMBytecodeFormat.BytecodeFlags.m3DeadHandlers
        }
        if options.m3.enableSelfIntegrityCheck {
            flags |= VMBytecodeFormat.BytecodeFlags.m3SelfIntegrity
        }
        var out = VMBytecodeFormat.BytecodeHeader(
            version: bytecodeVersion,
            entryCount: UInt32(programs.count),
            reservedFlags: flags
        ).serialize()
        if useM2 {
            let (globalA, globalB) = Self.deriveVpcAffine(functionId: 0x4350564D, seed: options.handlerVariantSeed)
            out.append(serializeVpcAffine(a: globalA, b: globalB))
        }
        out.append(entriesData)
        for body in bodies {
            out.append(body)
        }
        return out
    }

    private func encode(program: [VMInstruction], opcodeTable: VMOpcodeTable, options: VMM2EmitOptions) -> Data {
        var d = Data()
        for (idx, ins) in program.enumerated() {
            let sel = options.handlerVariantSeed ^ UInt64(idx) ^ (ins.immediate & 0xFFFF)
            d.append(opcodeTable.wireByte(for: ins.op, selector: sel))
            var imm = Self.wireImmediate(ins, options: options).littleEndian
            Swift.withUnsafeBytes(of: &imm) { d.append(contentsOf: $0) }
        }
        return d
    }

    /// Affine VPC parameters for M2: `vpc' = (vpc * A + B) mod 2^64` with **A odd** (build-time metadata).
    public static func deriveVpcAffine(functionId: UInt64, seed: UInt64) -> (UInt64, UInt64) {
        var rng = VMProtectorSplitMix64(seed: functionId ^ seed ^ 0x564D_5043_5632_4D32) // "VMPV2M2"
        var a = rng.next() | 1
        if a == 0 { a = 1 }
        let b = rng.next()
        return (a, b)
    }

    public static func handlerVariant(functionId: UInt64, seed: UInt64) -> UInt32 {
        var rng = VMProtectorSplitMix64(seed: functionId ^ seed ^ 0x48_6E_64_6C_56_72) // "HndlVr"
        return UInt32(truncatingIfNeeded: rng.next())
    }

    private static func packEntryReserved(handlerVariant: UInt32, vpcA: UInt64) -> UInt32 {
        let hv8 = handlerVariant & 0xFF
        let tag = UInt32(truncatingIfNeeded: vpcA ^ (vpcA >> 32)) & 0xFFFF_FFFF
        return hv8 | ((tag & 0x00FF_FFFF) << 8)
    }

    private func serializeVpcAffine(a: UInt64, b: UInt64) -> Data {
        precondition(a & 1 == 1)
        var d = Data()
        d.appendUInt64(a)
        d.appendUInt64(b)
        return d
    }

    private static func wireImmediate(_ ins: VMInstruction, options: VMM2EmitOptions) -> UInt64 {
        guard ins.op == .rawRegion else {
            return ins.immediate
        }
        if ins.immediate > UInt64(UInt32.max) {
            return ins.immediate
        }
        let word = UInt32(truncatingIfNeeded: ins.immediate)
        if options.opaqueVpcCategoryHigh32, let cat = ins.rawCategory {
            return VMImmediateLayout.packRaw(insnWord: word, category: cat, opaqueHigh32: true)
        }
        return UInt64(word)
    }
}

/// Stable 64-bit id for a symbol (FNV-1a 64).
public enum VMFunctionId {
    public static func fnv1a64(symbol: String) -> UInt64 {
        let prime: UInt64 = 0x100000001B3
        var hash: UInt64 = 0xCBF29CE484222325
        for byte in symbol.utf8 {
            hash ^= UInt64(byte)
            hash &*= prime
        }
        return hash == 0 ? 1 : hash
    }
}
