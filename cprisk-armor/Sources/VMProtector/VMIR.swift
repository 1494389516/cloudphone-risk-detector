import Foundation

/// Logical VM operations emitted by the ARM64 lifter before wire-byte encoding.
/// Wire IDs 0–3 are shared with `CRiskCore` `CPRISK_VM_OP_*` (do not reorder).
public enum VMLogicalOp: UInt8, CaseIterable, Sendable {
    case nop = 0
    case ret = 1
    case rawRegion = 2
    case halt = 3
}

/// Classifies a lifted machine instruction that is emitted as `rawRegion` (semantic loss / passthrough).
public enum VMRawRegionCategory: UInt8, Sendable, Equatable {
    /// Unclassified raw word (legacy behavior).
    case unknown = 0
    case movWide = 1
    /// ADRP+ADD fused materialization or a single ADRP/ADD contributing to a PC-relative address.
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
