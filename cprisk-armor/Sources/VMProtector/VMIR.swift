import Foundation

/// Logical VM operations emitted by the ARM64 lifter before wire-byte encoding.
///
/// Wire logical IDs 0–4 match `CRiskCore` `CPRISK_VM_OP_*` core layout; 5+ extend the interpreter ABI (`CPRISK_VM_OP_BRANCH_*`, `CALL`, …).
public enum VMLogicalOp: UInt8, CaseIterable, Sendable {
    case nop = 0
    case ret = 1
    /// Unclassified or unknown AArch64 word (passthrough / semantic loss).
    case rawRegion = 2
    case halt = 3
    /// Byte-lane add into accumulator (matches `CPRISK_VM_OP_ADD`).
    case addLane = 4
    /// Unconditional `B` (PC-relative; immediate = signed VM bytecode byte delta, AArch64 imm26×9).
    case branchRel = 5
    /// `B.cond` / `CBZ` / `CBNZ` — immediate carries the AArch64 instruction word; runtime evaluates predicate on `acc`.
    case branchCond = 6
    /// `BL` — push return PC then branch like `branchRel`.
    case call = 7
    case movWide = 8
    case adrAdd = 9
    case condSelect = 10
    case loadStore = 11
    /// Bitwise-style mixing lane (EOR family and similar; accumulator XOR semantics).
    case xorMix = 12
    /// Byte-lane OR into accumulator (polymorphic with ADD/XOR families).
    case orLane = 13
    /// Byte-lane AND into accumulator.
    case andLane = 14
    /// Rotate 32-byte accumulator left by `(imm & 31)`.
    case rolAcc = 15
    /// Nested VM: immediate = callee `function_id` (inter-function bytecode call).
    case vmCallFunc = 16
    /// Virtual GPR move / immediate / acc slice (see CRiskCore immediate layout).
    case vregMov = 17
    /// Virtual GPR 64-bit ALU between registers.
    case vregAlu = 18
    /// Load/store between vreg and 8-byte acc window.
    case vregMem = 19
    /// Byte-lane subtract (wrapping uint8) — AArch64 SUB imm / similar surrogate.
    case subLane = 20
    /// Byte-lane multiply mod 256 — AArch64 MADD-as-MUL surrogate.
    case mulLane = 21
    /// Fused add-lane + rol-acc (see CRiskCore `CPRISK_VM_OP_ADD_ROL_ACC`).
    case addRolAcc = 22
    /// Indirect branch via vreg + acc mix (see CRiskCore `CPRISK_VM_OP_BRANCH_IND`).
    case branchInd = 23
}

/// Classifies a lifted machine instruction when emitted as `rawRegion` (legacy / fallback).
public enum VMRawRegionCategory: UInt8, Sendable, Equatable {
    case unknown = 0
    case movWide = 1
    case adrAdd = 2
    case condSelect = 3
    case branchCond = 4
    case branchTest = 5
    case loadStore = 6
    case other = 0xFF
}

/// One VMIR instruction with optional immediate payload (little-endian when multi-byte).
public struct VMInstruction: Equatable, Sendable {
    public let op: VMLogicalOp
    public let immediate: UInt64
    /// When `op == .rawRegion`, describes the AArch64 pattern; ignored on wire unless opaque encoding is enabled.
    public let rawCategory: VMRawRegionCategory?

    public init(op: VMLogicalOp, immediate: UInt64 = 0, rawCategory: VMRawRegionCategory? = nil) {
        self.op = op
        self.immediate = immediate
        self.rawCategory = rawCategory
    }
}

/// Packs a 32-bit instruction word with an optional category tag in the high 32 bits (build-time / opaque mode).
public enum VMImmediateLayout: Sendable {
    public static let categoryShift: UInt64 = 32

    public static func packRaw(insnWord: UInt32, category: VMRawRegionCategory, opaqueHigh32: Bool) -> UInt64 {
        let base = UInt64(insnWord)
        guard opaqueHigh32 else { return base }
        return base | (UInt64(category.rawValue) << categoryShift)
    }
}

/// Producer contract for `branchInd` immediate materialization.
///
/// Runtime today consumes:
/// - low 3 bits as `vreg` index
/// - bits 3...7 as `acc` start byte
///
/// Producer uses three wire shapes:
/// - `synthetic`: unreachable block branch noise (safe-by-default)
/// - `semiIdentity`: reserved high-byte tag for runtime-verified fallthrough/no-op semantics;
///   producer may inject tagged instructions directly into reachable bytecode without behavior drift
/// - `semiSemantic`: reserved high-byte `0xA2`; runtime runs the same mix path as full `branchInd` then
///   forces the same single-instruction advance as `semiIdentity` (low 8 bits still materialize vreg/acc).
public enum VMBranchIndImmediateContract: Sendable {
    public static let vregMask: UInt64 = 0x7
    public static let accBaseMask: UInt64 = 0x1F
    public static let accBaseShift: UInt64 = 3

    /// `0xA1` in high byte reserves the immediate for semi-identity mode.
    public static let semiIdentityTag: UInt64 = 0xA100_0000_0000_0000
    /// `0xA2` in high byte: semi-semantic (compute + controlled target selection within nop sled).
    public static let semiSemanticTag: UInt64 = 0xA200_0000_0000_0000
    public static let semiIdentityPayloadMask: UInt64 = 0x00FF_FFFF_FFFF_FFFF

    /// Bits 8..15 of the immediate encode `forward_span` (0..255) for `0xA2` semi-semantic mode.
    /// Runtime computes `skip = q % (forward_span + 1)` and jumps `(1 + skip) * INSN_WIDTH` forward.
    public static let semiSemanticForwardSpanShift: UInt64 = 8
    public static let semiSemanticForwardSpanMask: UInt64 = 0xFF

    public static func synthetic(vregIndex: UInt64, accBase: UInt64) -> UInt64 {
        let vreg = vregIndex & vregMask
        let acc = accBase & accBaseMask
        return vreg | (acc << accBaseShift)
    }

    public static func semiIdentity(entropy: UInt64) -> UInt64 {
        semiIdentityTag | (entropy & semiIdentityPayloadMask)
    }

    /// Low 8 bits mirror `synthetic` (vreg/acc); bits 8..15 encode `forwardSpan` for nop-sled targeting.
    public static func semiSemantic(entropy: UInt64, forwardSpan: UInt8 = 0) -> UInt64 {
        var payload = entropy & semiIdentityPayloadMask
        payload = (payload & ~(semiSemanticForwardSpanMask << semiSemanticForwardSpanShift))
            | (UInt64(forwardSpan) << semiSemanticForwardSpanShift)
        return semiSemanticTag | payload
    }

    public static func isSemiIdentity(_ immediate: UInt64) -> Bool {
        (immediate & ~semiIdentityPayloadMask) == semiIdentityTag
    }

    public static func isSemiSemantic(_ immediate: UInt64) -> Bool {
        (immediate & ~semiIdentityPayloadMask) == semiSemanticTag
    }
}
