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

/// Encoded in `VMBytecodeFormat.Entry.reserved` (producer hint field).
/// Layout v1 (when magic byte `0xA5` is present in bits 24...31):
/// - bits 0...7: low 8 bits of handler variant selector
/// - bits 8...11: semantic family id (runtime polymorphic-equivalent handlers)
/// - bits 12...15: mixed-predicate profile id (branchCond path expansion)
/// - bits 16...19: max subcall depth minus 1 (stored range 0...15)
/// - bits 20...23: entropy tag (producer-only, runtime optional)
/// - bits 24...31: marker `0xA5`
public struct VMEntryExecutionProfile: Equatable, Sendable {
    public let handlerVariantLow8: UInt8
    public let semanticFamily: UInt8
    public let mixedPredicateProfile: UInt8
    public let maxSubcallDepth: UInt8
    public let entropyTag: UInt8
    public let usesExtendedLayout: Bool

    public init(
        handlerVariantLow8: UInt8,
        semanticFamily: UInt8,
        mixedPredicateProfile: UInt8,
        maxSubcallDepth: UInt8,
        entropyTag: UInt8,
        usesExtendedLayout: Bool
    ) {
        self.handlerVariantLow8 = handlerVariantLow8
        self.semanticFamily = semanticFamily
        self.mixedPredicateProfile = mixedPredicateProfile
        self.maxSubcallDepth = Swift.max(UInt8(1), maxSubcallDepth)
        self.entropyTag = entropyTag
        self.usesExtendedLayout = usesExtendedLayout
    }
}

/// M3 optional metadata appended after the 256-byte dispatch class table (CRiskCore reads only the prefix; tail is forward-compatible).
public struct VMM3EmitOptions: Equatable, Sendable {
    /// Opaque VPC predicate-chain constants for build-time / future runtime consumers.
    public var vpcPredicateConstants: [UInt64]
    public var enableDeadHandlers: Bool
    public var enableOpaquePredicateChain: Bool
    public var enableSelfIntegrityCheck: Bool
    /// When `enableSelfIntegrityCheck` is true, use HMAC-SHA256 (truncated) vs CPSH blob instead of FNV/CPSF.
    public var enableSelfIntegrityHmac: Bool
    /// Runtime SHA256 baseline + periodic re-check of each function bytecode blob (`CPRISK_VMP_BC_FLAG_BC_SEG_RUNTIME_SHA256`).
    public var bytecodeSegmentRuntimeSha256: Bool

    public init(
        vpcPredicateConstants: [UInt64] = [],
        enableDeadHandlers: Bool = false,
        enableOpaquePredicateChain: Bool = false,
        enableSelfIntegrityCheck: Bool = false,
        enableSelfIntegrityHmac: Bool = false,
        bytecodeSegmentRuntimeSha256: Bool = false
    ) {
        self.vpcPredicateConstants = vpcPredicateConstants
        self.enableDeadHandlers = enableDeadHandlers
        self.enableOpaquePredicateChain = enableOpaquePredicateChain
        self.enableSelfIntegrityCheck = enableSelfIntegrityCheck
        self.enableSelfIntegrityHmac = enableSelfIntegrityHmac
        self.bytecodeSegmentRuntimeSha256 = bytecodeSegmentRuntimeSha256
    }
}

/// Build-time options for M2 metadata and wire encoding (consumable by future runtime; v1 interpreter ignores M2 blob).
public struct VMM2EmitOptions: Equatable, Sendable {
    /// When true, pack `VMRawRegionCategory` into the high 32 bits of `rawRegion` immediates (changes accumulator mix vs plain insn word).
    public var opaqueVpcCategoryHigh32: Bool
    public var handlerVariantSeed: UInt64
    /// Emit per-entry VPC metadata (runtime reads two UInt64 words after each entry when enabled).
    /// Current runtime interprets the pair as non-linear VPC codec material when the corresponding flag is set.
    public var perEntryVpcEnabled: Bool
    public var m3: VMM3EmitOptions
    /// XOR the 256-byte raw→logical class table with a deterministic keystream (dispatch header flag). **Requires matching CRiskCore support when enabled.**
    public var dispatchTableKeystream: Bool
    /// Mixed into dispatch keystream seed (`opcodeTable.seed` is always part of the mix).
    public var dispatchKeystreamMaterial: UInt64
    /// v3 bytecode: XOR each 8-byte immediate with a per-`functionId`/`pc` mask; appends an 8-byte seed after the header. **Requires matching CRiskCore support when enabled.**
    public var immediateKeystream: Bool
    /// Extra entropy for immediate XOR; when zero, derived from `handlerVariantSeed`.
    public var immediateKeystreamMaterial: UInt64
    /// v3: XOR each wire opcode byte (per-insn); appends an 8-byte opcode seed after optional immediate seed.
    public var opcodeWireObfuscation: Bool
    /// Extra entropy for opcode XOR; when zero, derived from `handlerVariantSeed`.
    public var opcodeKeystreamMaterial: UInt64
    /// When true, set `BytecodeFlags.nonLinearVpc` and use the same 16-byte VPC slot as non-linear codec material (CRiskCore `CPRISK_VMP_BC_FLAG_VPC_NONLINEAR`).
    public var vpcNonlinearEncoding: Bool
    /// Emit `CPRISK_VMP_BC_FLAG_ANTI_SYMBOLIC_HEAVY` (runtime anti-symbolic bait; CRiskCore interpreter).
    public var antiSymbolicHeavy: Bool

    public init(
        opaqueVpcCategoryHigh32: Bool = false,
        handlerVariantSeed: UInt64 = 0,
        perEntryVpcEnabled: Bool = true,
        m3: VMM3EmitOptions = VMM3EmitOptions(),
        dispatchTableKeystream: Bool = false,
        dispatchKeystreamMaterial: UInt64 = 0,
        immediateKeystream: Bool = false,
        immediateKeystreamMaterial: UInt64 = 0,
        opcodeWireObfuscation: Bool = false,
        opcodeKeystreamMaterial: UInt64 = 0,
        vpcNonlinearEncoding: Bool = true,
        antiSymbolicHeavy: Bool = false
    ) {
        self.opaqueVpcCategoryHigh32 = opaqueVpcCategoryHigh32
        self.handlerVariantSeed = handlerVariantSeed
        self.perEntryVpcEnabled = perEntryVpcEnabled
        self.m3 = m3
        self.dispatchTableKeystream = dispatchTableKeystream
        self.dispatchKeystreamMaterial = dispatchKeystreamMaterial
        self.immediateKeystream = immediateKeystream
        self.immediateKeystreamMaterial = immediateKeystreamMaterial
        self.opcodeWireObfuscation = opcodeWireObfuscation
        self.opcodeKeystreamMaterial = opcodeKeystreamMaterial
        self.vpcNonlinearEncoding = vpcNonlinearEncoding
        self.antiSymbolicHeavy = antiSymbolicHeavy
    }
}

/// On-disk layout for Pass 13 VM payloads.
public enum VMBytecodeFormat {
    /// Bytes `C P V D` on disk (little-endian word 0x4456_5043).
    public static let dispatchMagic: UInt32 = 0x4456_5043
    /// Bytes `C P V M` on disk (little-endian word 0x4D56_5043).
    public static let bytecodeMagic: UInt32 = 0x4D56_5043
    public static let dispatchABIVersionV1: UInt32 = 1
    public static let dispatchABIVersionV2: UInt32 = 2
    public static let bytecodeABIVersionV1: UInt32 = 1
    public static let bytecodeABIVersionV2: UInt32 = 2
    /// Extended producer format: optional 8-byte immediate keystream seed after the M2 VPC block (or after the core header when M2 fields are absent).
    public static let bytecodeABIVersionV3: UInt32 = 3
    public static let sectionSegment = ArmorABI.dataSegmentName
    public static let dispatchSection = ArmorABI.Sections.vmpDispatch
    public static let bytecodeSection = ArmorABI.Sections.vmpBytecode
    public static let dispatchTableSize = 256
    public static let dispatchSeedBytes = 8
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
        /// Runtime M3: HMAC-SHA256 (truncated) self-check vs CPSH blob (requires \c m3SelfIntegrity).
        public static let m3SelfIntegrityHmac: UInt32 = 1 << 8
        /// Runtime: interpret the 16-byte VPC metadata block as non-linear Feistel/SPN material.
        public static let nonLinearVpc: UInt32 = 1 << 10
        /// v3: immediates XOR’d with a per-insn mask (see on-disk seed field).
        public static let immediateKeystream: UInt32 = 1 << 5
        /// v3: wire opcode bytes XOR’d per insn (see on-disk opcode seed field).
        public static let opcodeWireObfuscation: UInt32 = 1 << 6
        /// Runtime: SHA256 baseline + periodic bytecode segment integrity checks (CRiskCore `CPRISK_VMP_BC_FLAG_BC_SEG_RUNTIME_SHA256`).
        public static let bcSegmentRuntimeSha256: UInt32 = 1 << 11
        /// Runtime: heavy anti-symbolic bait (CRiskCore `CPRISK_VMP_BC_FLAG_ANTI_SYMBOLIC_HEAVY`).
        public static let antiSymbolicHeavy: UInt32 = 1 << 7
    }

    /// Dispatch header `flags` (M2 + M3 producer hints). CRiskCore does not branch on these today; safe to extend.
    public enum DispatchHeaderFlags {
        public static let handlerDuplicationPools: UInt32 = 1 << 0
        public static let opaqueVpcCategoryHigh32: UInt32 = 1 << 1
        public static let deadHandlerMetadata: UInt32 = 1 << 2
        public static let vpcPredicateChainMetadata: UInt32 = 1 << 3
        /// 256-byte class table XOR’d with `dispatchKeystreamBytes(seed:)` (seed mixes `opcodeTable.seed` + emit options).
        public static let classTableKeystream: UInt32 = 1 << 4
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
        public let version: UInt32
        public let tableSize: UInt32
        /// Bit 0: handler duplication pools enabled. Bit 1: opaque VPC category high-32 in immediates.
        public let flags: UInt32

        public init(version: UInt32 = VMBytecodeFormat.dispatchABIVersionV1, tableSize: UInt32, flags: UInt32) {
            self.version = version
            self.tableSize = tableSize
            self.flags = flags
        }

        public func serialize() -> Data {
            var d = Data()
            d.appendUInt32(VMBytecodeFormat.dispatchMagic)
            d.appendUInt32(version)
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
    private static let entryProfileMagic: UInt32 = 0xA5

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
        let dispatchKsEnabled = options.dispatchTableKeystream
        let dispatchVersion: UInt32 = dispatchKsEnabled ? VMBytecodeFormat.dispatchABIVersionV2 : VMBytecodeFormat.dispatchABIVersionV1
        let dispatchSeed = Self.dispatchKeystreamSeed(opcodeTableSeed: opcodeTable.seed, material: options.dispatchKeystreamMaterial)
        if opcodeTable.handlerDuplicationEnabled { flags |= VMBytecodeFormat.DispatchHeaderFlags.handlerDuplicationPools }
        if options.opaqueVpcCategoryHigh32 { flags |= VMBytecodeFormat.DispatchHeaderFlags.opaqueVpcCategoryHigh32 }
        let dead = opcodeTable.deadHandlerInjection
        let preds = options.m3.vpcPredicateConstants
        let emitM3Tail = (options.m3.enableDeadHandlers && dead != nil) || (options.m3.enableOpaquePredicateChain && !preds.isEmpty)
        if options.m3.enableDeadHandlers, dead != nil { flags |= VMBytecodeFormat.DispatchHeaderFlags.deadHandlerMetadata }
        if options.m3.enableOpaquePredicateChain, !preds.isEmpty { flags |= VMBytecodeFormat.DispatchHeaderFlags.vpcPredicateChainMetadata }
        if dispatchKsEnabled { flags |= VMBytecodeFormat.DispatchHeaderFlags.classTableKeystream }
        var out = VMBytecodeFormat.DispatchHeader(
            version: dispatchVersion,
            tableSize: UInt32(VMBytecodeFormat.dispatchTableSize),
            flags: flags
        ).serialize()
        if dispatchKsEnabled {
            out.appendUInt64(dispatchSeed)
        }
        var classTable = opcodeTable.rawToLogicalTable()
        if dispatchKsEnabled {
            let ks = Self.dispatchKeystreamBytes(seed: dispatchSeed)
            for i in 0..<classTable.count {
                classTable[i] ^= ks[i]
            }
        }
        out.append(contentsOf: classTable)
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
        guard dispatch.count >= 16 else { return nil }
        let version = VMBytecodeFormat.readUInt32LE(dispatch, offset: 4)
        let classOffset = version >= VMBytecodeFormat.dispatchABIVersionV2 ? (16 + VMBytecodeFormat.dispatchSeedBytes) : 16
        let prefix = classOffset + VMBytecodeFormat.dispatchTableSize
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
        let opcodeEnc = options.opcodeWireObfuscation
        let immKs = options.immediateKeystream
        let useM2 = options.perEntryVpcEnabled || options.handlerVariantSeed != 0 || options.vpcNonlinearEncoding
        let perEntryVpc = useM2 && options.perEntryVpcEnabled
        let bytecodeVersion: UInt32
        if immKs || opcodeEnc {
            bytecodeVersion = VMBytecodeFormat.bytecodeABIVersionV3
        } else if useM2 {
            bytecodeVersion = VMBytecodeFormat.bytecodeABIVersionV2
        } else {
            bytecodeVersion = VMBytecodeFormat.bytecodeABIVersionV1
        }
        let headerSize = 16 + (useM2 ? VMBytecodeFormat.vpcAffineBytes : 0) + (immKs ? 8 : 0) + (opcodeEnc ? 8 : 0)
        let entryStride = VMBytecodeFormat.entryCoreSize + (perEntryVpc ? VMBytecodeFormat.vpcAffineBytes : 0)
        let bodies: [Data] = programs.map {
            encode(program: $0.instructions, functionId: $0.functionId, opcodeTable: opcodeTable, options: options)
        }
        let tableBytes = headerSize + programs.count * entryStride
        var cursor = UInt32(tableBytes)
        var entriesData = Data()
        for (index, program) in programs.enumerated() {
            let body = bodies[index]
            let hv = Self.handlerVariant(functionId: program.functionId, seed: options.handlerVariantSeed)
            let affine = Self.deriveVpcAffine(functionId: program.functionId, seed: options.handlerVariantSeed)
            let execProfile = Self.deriveEntryExecutionProfile(
                functionId: program.functionId,
                seed: options.handlerVariantSeed,
                handlerVariant: hv,
                vpcA: affine.0
            )
            let reserved = Self.packEntryReserved(
                profile: execProfile
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
                entriesData.append(serializeVpcAffine(a: affine.0, b: affine.1))
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
        if options.vpcNonlinearEncoding {
            flags |= VMBytecodeFormat.BytecodeFlags.nonLinearVpc
        }
        if options.m3.enableOpaquePredicateChain {
            flags |= VMBytecodeFormat.BytecodeFlags.m3OpaqueChain
        }
        if options.m3.enableDeadHandlers {
            flags |= VMBytecodeFormat.BytecodeFlags.m3DeadHandlers
        }
        if options.m3.enableSelfIntegrityCheck {
            flags |= VMBytecodeFormat.BytecodeFlags.m3SelfIntegrity
            if options.m3.enableSelfIntegrityHmac {
                flags |= VMBytecodeFormat.BytecodeFlags.m3SelfIntegrityHmac
            }
        }
        if options.m3.bytecodeSegmentRuntimeSha256 {
            flags |= VMBytecodeFormat.BytecodeFlags.bcSegmentRuntimeSha256
        }
        if options.antiSymbolicHeavy {
            flags |= VMBytecodeFormat.BytecodeFlags.antiSymbolicHeavy
        }
        if immKs {
            flags |= VMBytecodeFormat.BytecodeFlags.immediateKeystream
        }
        if opcodeEnc {
            flags |= VMBytecodeFormat.BytecodeFlags.opcodeWireObfuscation
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
        if immKs {
            out.appendUInt64(Self.immediateKeystreamRoot(options: options))
        }
        if opcodeEnc {
            out.appendUInt64(Self.opcodeKeystreamRoot(options: options))
        }
        out.append(entriesData)
        for body in bodies {
            out.append(body)
        }
        /* Producer-only chunk manifest: documents per-entry bytecode placement (offset/length); CRiskCore ignores. */
        out.append(Self.serializeProducerChunkManifest(programs: programs))
        return out
    }

    /// Little-endian magic `'CPVX'` (on-disk bytes `43 50 56 58`) — optional trailer after bytecode bodies.
    public static let producerChunkManifestMagic: UInt32 = 0x5856_5043
    public static let producerChunkManifestVersion: UInt32 = 1

    /// Redundant indirection metadata: stable substitute when Mach-O `__TEXT` scatter is unsafe.
    public static func serializeProducerChunkManifest(
        programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])]
    ) -> Data {
        var d = Data()
        d.appendUInt32(producerChunkManifestMagic)
        d.appendUInt32(producerChunkManifestVersion)
        d.appendUInt32(UInt32(programs.count))
        for p in programs {
            d.appendUInt64(p.functionId)
            d.appendUInt32(UInt32(p.instructions.count))
        }
        return d
    }

    private func encode(program: [VMInstruction], functionId: UInt64, opcodeTable: VMOpcodeTable, options: VMM2EmitOptions) -> Data {
        let opcodeEnc = options.opcodeWireObfuscation
        let immKs = options.immediateKeystream
        let immRoot = Self.immediateKeystreamRoot(options: options)
        let opRoot = Self.opcodeKeystreamRoot(options: options)
        var d = Data()
        for (idx, ins) in program.enumerated() {
            let sel = options.handlerVariantSeed ^ UInt64(idx) ^ (ins.immediate & 0xFFFF)
            var rawOp = opcodeTable.wireByte(for: ins.op, selector: sel)
            if opcodeEnc {
                rawOp ^= UInt8(truncatingIfNeeded: Self.opcodeMixByte(functionId: functionId, pcIndex: UInt32(idx), seed: opRoot))
            }
            d.append(rawOp)
            var plain = Self.wireImmediate(ins, options: options)
            if ins.op == .rawRegion, options.opaqueVpcCategoryHigh32 {
                let bindRoot = immKs ? immRoot : opRoot
                plain ^= Self.rawRegionOpaqueBindMask(functionId: functionId, pcIndex: UInt32(idx), seed: bindRoot)
            }
            if immKs {
                plain ^= Self.immediateXorMask(functionId: functionId, pcIndex: UInt32(idx), seed: immRoot)
            }
            var imm = plain.littleEndian
            Swift.withUnsafeBytes(of: &imm) { d.append(contentsOf: $0) }
        }
        return d
    }

    /// Stable 16-byte VPC metadata pair for M2/M4. Legacy consumers may treat it as affine A/B;
    /// current runtime uses the same pair as non-linear VPC codec material when `nonLinearVpc` is set.
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

    /// Build producer-side branch/runtime execution profile (deterministic for `(functionId, seed)`).
    public static func deriveEntryExecutionProfile(
        functionId: UInt64,
        seed: UInt64,
        handlerVariant: UInt32,
        vpcA: UInt64
    ) -> VMEntryExecutionProfile {
        let mixSeed = seed == 0 ? 0x56_4D_50_52_4F_46_49_4C : seed
        var rng = VMProtectorSplitMix64(seed: functionId ^ mixSeed ^ 0x4558_4350_524F_4631) // "EXCPROF1"
        /* 0...15 (runtime clamps 0 → 1); expands semantic polymorphism surface for poly16 lanes. */
        let semanticFamily = UInt8(truncatingIfNeeded: rng.next() % 16)
        let mixedPredicate = UInt8(truncatingIfNeeded: rng.next() % 8) // 0...7
        let subcallDepth = UInt8(truncatingIfNeeded: (rng.next() % 8) + 2) // 2...9
        let entropyTag = UInt8(truncatingIfNeeded: (vpcA ^ (vpcA >> 32) ^ UInt64(rng.next())) & 0xF)
        return VMEntryExecutionProfile(
            handlerVariantLow8: UInt8(truncatingIfNeeded: handlerVariant),
            semanticFamily: semanticFamily,
            mixedPredicateProfile: mixedPredicate,
            maxSubcallDepth: subcallDepth,
            entropyTag: entropyTag,
            usesExtendedLayout: true
        )
    }

    /// Decode `Entry.reserved` produced by this emitter.
    /// Returns `nil` for legacy layouts that do not contain the `0xA5` marker.
    public static func unpackEntryExecutionProfile(_ reserved: UInt32) -> VMEntryExecutionProfile? {
        let marker = (reserved >> 24) & 0xFF
        guard marker == entryProfileMagic else { return nil }
        let hv = UInt8(truncatingIfNeeded: reserved & 0xFF)
        let semantic = UInt8(truncatingIfNeeded: (reserved >> 8) & 0xF)
        let mixed = UInt8(truncatingIfNeeded: (reserved >> 12) & 0xF)
        let subDepthEncoded = UInt8(truncatingIfNeeded: (reserved >> 16) & 0xF)
        let entropyTag = UInt8(truncatingIfNeeded: (reserved >> 20) & 0xF)
        return VMEntryExecutionProfile(
            handlerVariantLow8: hv,
            semanticFamily: semantic,
            mixedPredicateProfile: mixed,
            maxSubcallDepth: Swift.max(UInt8(1), subDepthEncoded &+ 1),
            entropyTag: entropyTag,
            usesExtendedLayout: true
        )
    }

    private static func packEntryReserved(profile: VMEntryExecutionProfile) -> UInt32 {
        let hv = UInt32(profile.handlerVariantLow8)
        let semantic = UInt32(profile.semanticFamily & 0xF) << 8
        let mixed = UInt32(profile.mixedPredicateProfile & 0xF) << 12
        let subDepth = UInt32((Swift.max(UInt8(1), profile.maxSubcallDepth) &- 1) & 0xF) << 16
        let entropyTag = UInt32(profile.entropyTag & 0xF) << 20
        let marker = entryProfileMagic << 24
        return hv | semantic | mixed | subDepth | entropyTag | marker
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

    // MARK: - Optional dispatch / immediate protection (forward-compatible; default off)

    public static func dispatchKeystreamSeed(opcodeTableSeed: UInt64, material: UInt64) -> UInt64 {
        opcodeTableSeed ^ material ^ 0x4453_5042_4D50_3300 // "DSPMP3\0" domain tag
    }

    public static func dispatchKeystreamBytes(seed: UInt64) -> [UInt8] {
        var r = VMProtectorSplitMix64(seed: seed ^ 0x4D44_5654_4B45_5953) // "MDVTKEYS"
        return (0..<VMBytecodeFormat.dispatchTableSize).map { _ in UInt8(truncatingIfNeeded: r.next()) }
    }

    /// XOR / XOR⁻¹ (symmetric) for the 256-byte class table using the same seed material as the emitter.
    public static func xorDispatchClassTableBytes(_ table: [UInt8], opcodeTableSeed: UInt64, material: UInt64) -> [UInt8] {
        precondition(table.count == VMBytecodeFormat.dispatchTableSize)
        let seed = dispatchKeystreamSeed(opcodeTableSeed: opcodeTableSeed, material: material)
        let ks = dispatchKeystreamBytes(seed: seed)
        return zip(table, ks).map { a, k in a ^ k }
    }

    /// When the dispatch header has `classTableKeystream`, recover the logical class table (tools / unit tests).
    public static func decryptDispatchClassTable(payload: Data, opcodeTableSeed: UInt64, material: UInt64) -> [UInt8]? {
        guard payload.count >= 16 + VMBytecodeFormat.dispatchTableSize else { return nil }
        let version = VMBytecodeFormat.readUInt32LE(payload, offset: 4)
        let classOffset = version >= VMBytecodeFormat.dispatchABIVersionV2 ? (16 + VMBytecodeFormat.dispatchSeedBytes) : 16
        guard payload.count >= classOffset + VMBytecodeFormat.dispatchTableSize else { return nil }
        let flags = VMBytecodeFormat.readUInt32LE(payload, offset: 12)
        guard (flags & VMBytecodeFormat.DispatchHeaderFlags.classTableKeystream) != 0 else { return nil }
        let seed: UInt64
        if version >= VMBytecodeFormat.dispatchABIVersionV2 {
            seed = VMBytecodeFormat.readUInt64LE(payload, offset: 16)
        } else {
            seed = dispatchKeystreamSeed(opcodeTableSeed: opcodeTableSeed, material: material)
        }
        let slice = payload[classOffset..<(classOffset + VMBytecodeFormat.dispatchTableSize)]
        let ks = dispatchKeystreamBytes(seed: seed)
        return zip([UInt8](slice), ks).map { $0 ^ $1 }
    }

    public static func immediateKeystreamRoot(options: VMM2EmitOptions) -> UInt64 {
        if options.immediateKeystreamMaterial != 0 {
            return options.immediateKeystreamMaterial
        }
        return options.handlerVariantSeed ^ 0x564D_5049_4D4D_5331 // "VMPIMMS1"
    }

    public static func opcodeKeystreamRoot(options: VMM2EmitOptions) -> UInt64 {
        if options.opcodeKeystreamMaterial != 0 {
            return options.opcodeKeystreamMaterial
        }
        return options.handlerVariantSeed ^ 0x564D_504F5043324B // "VMPOPC3K"
    }

    public static func opcodeMixByte(functionId: UInt64, pcIndex: UInt32, seed: UInt64) -> UInt64 {
        var r = VMProtectorSplitMix64(seed: functionId ^ UInt64(pcIndex) ^ seed ^ 0x4F50434D49583152) // "OPCMIX1R"
        return r.next()
    }

    public static func rawRegionOpaqueBindMask(functionId: UInt64, pcIndex: UInt32, seed: UInt64) -> UInt64 {
        var r = VMProtectorSplitMix64(seed: functionId ^ UInt64(pcIndex) ^ seed ^ 0x5241574C4E4D3130) // "RAWLNM10"
        return r.next()
    }

    public static func immediateXorMask(functionId: UInt64, pcIndex: UInt32, seed: UInt64) -> UInt64 {
        var r = VMProtectorSplitMix64(seed: functionId ^ UInt64(pcIndex) ^ seed ^ 0x49_4D_4D_58_4F_52_31_52) // "IMMXOR1R"
        return r.next()
    }

    public static func decodeWireImmediate(encoded: UInt64, functionId: UInt64, pcIndex: UInt32, keystreamRoot: UInt64) -> UInt64 {
        encoded ^ immediateXorMask(functionId: functionId, pcIndex: pcIndex, seed: keystreamRoot)
    }

    /// Total bytes before the bytecode entry table (core header + optional M2 VPC block + optional v3 immediate seed).
    public static func bytecodeHeaderTotalBytes(version: UInt32, flags: UInt32) -> Int {
        let useM2 = (flags & VMBytecodeFormat.BytecodeFlags.perEntryVpc) != 0
            || (flags & VMBytecodeFormat.BytecodeFlags.handlerVariantSeed) != 0
            || (flags & VMBytecodeFormat.BytecodeFlags.nonLinearVpc) != 0
        var n = 16
        if useM2 { n += VMBytecodeFormat.vpcAffineBytes }
        if version >= VMBytecodeFormat.bytecodeABIVersionV3,
           (flags & VMBytecodeFormat.BytecodeFlags.immediateKeystream) != 0 {
            n += 8
        }
        if version >= VMBytecodeFormat.bytecodeABIVersionV3,
           (flags & VMBytecodeFormat.BytecodeFlags.opcodeWireObfuscation) != 0 {
            n += 8
        }
        return n
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
