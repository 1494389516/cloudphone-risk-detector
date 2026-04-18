import Foundation

public enum VMPatchRewriterError: Error, CustomStringConvertible {
    case blOffsetNotAligned(Int64)
    case blOutOfRange(offsetBytes: Int64, fromVMA: UInt64, toVMA: UInt64)
    case sourceVMANotAligned(UInt64)
    case targetVMANotAligned(UInt64)

    public var description: String {
        switch self {
        case .blOffsetNotAligned(let o):
            return "BL offset not 4-byte aligned (\(o))"
        case .blOutOfRange(let offset, let from, let to):
            return String(
                format: "BL out of ±128MB range: offset=%lld bytes (0x%016llX → 0x%016llX)",
                offset, from, to
            )
        case .sourceVMANotAligned(let vma):
            return String(format: "Trampoline source VMA not 4-byte aligned (0x%016llX)", vma)
        case .targetVMANotAligned(let vma):
            return String(format: "VM entry target VMA not 4-byte aligned (0x%016llX)", vma)
        }
    }
}

/// Polymorphic AArch64 trampoline shapes (all `trampolineByteLength`; ABI: `x0 = functionId`, then `bl` → VM entry).
public enum VMTrampolineTemplate: UInt32, CaseIterable, Sendable, Equatable {
    /// `MOVZ/MOVK*3` on `x0`, `BL`, `RET`, `NOP`.
    case movkClassic = 0
    /// Same immediates on `x1`, `MOV X0,X1`, `BL`, `RET`, `NOP`.
    case movkViaX1 = 1
    /// `LDR X0` of an embedded `.quad`, `BL`, `RET`, `NOP`, literal, trailing `NOP`.
    case pcRelativeLiteral = 2
}

/// Builds AArch64 trampoline: load `functionId` into `x0`, then `bl` to `_cprisk_vm_entry`.
public enum VMPatchRewriter {
    public static let trampolineByteLength = 28

    /// Deterministic template pick for a protected function (use build seed + FNV id).
    public static func selectTrampolineTemplate(functionId: UInt64, buildSeed: UInt64) -> VMTrampolineTemplate {
        var g = VMProtectorSplitMix64(seed: functionId ^ buildSeed ^ 0x5452_4D50_4C5F_5633) // "TRMPL_V3"
        let idx = g.next() % UInt64(VMTrampolineTemplate.allCases.count)
        return VMTrampolineTemplate(rawValue: UInt32(idx)) ?? .movkClassic
    }

    /// Which Mach-O VM entry symbol the trampoline should `bl` (distinct from template shape; spreads hook surface).
    public static func selectVmEntrySymbolName(functionId: UInt64, buildSeed: UInt64) -> String {
        var g = VMProtectorSplitMix64(seed: functionId ^ buildSeed ^ 0x564D454E54525900) // "VMENTY\0"
        switch g.next() % 3 {
        case 0: return "_cprisk_vm_entry"
        case 1: return "_cprisk_vm_entry_alt1"
        default: return "_cprisk_vm_entry_alt2"
        }
    }

    /// - Parameters:
    ///   - functionId: Passed in `x0` to the VM entry helper.
    ///   - functionEntryVMA: Virtual address of the patched function entry (first MOVZ).
    ///   - vmEntryVMA: Virtual address of `_cprisk_vm_entry`.
    public static func buildTrampoline(
        functionId: UInt64,
        functionEntryVMA: UInt64,
        vmEntryVMA: UInt64
    ) throws -> Data {
        try buildTrampoline(
            functionId: functionId,
            functionEntryVMA: functionEntryVMA,
            vmEntryVMA: vmEntryVMA,
            template: .movkClassic
        )
    }

    /// - Parameters:
    ///   - template: Machine shape; all variants preserve `x0` / `BL` ABI to `_cprisk_vm_entry`.
    public static func buildTrampoline(
        functionId: UInt64,
        functionEntryVMA: UInt64,
        vmEntryVMA: UInt64,
        template: VMTrampolineTemplate
    ) throws -> Data {
        guard functionEntryVMA % 4 == 0 else {
            throw VMPatchRewriterError.sourceVMANotAligned(functionEntryVMA)
        }
        guard vmEntryVMA % 4 == 0 else {
            throw VMPatchRewriterError.targetVMANotAligned(vmEntryVMA)
        }
        switch template {
        case .movkClassic:
            return try buildMovkClassic(functionId: functionId, functionEntryVMA: functionEntryVMA, vmEntryVMA: vmEntryVMA, rd: 0)
        case .movkViaX1:
            return try buildMovkViaX1(functionId: functionId, functionEntryVMA: functionEntryVMA, vmEntryVMA: vmEntryVMA)
        case .pcRelativeLiteral:
            return try buildPcRelativeLiteral(functionId: functionId, functionEntryVMA: functionEntryVMA, vmEntryVMA: vmEntryVMA)
        }
    }

    private static func buildMovkClassic(
        functionId: UInt64,
        functionEntryVMA: UInt64,
        vmEntryVMA: UInt64,
        rd: UInt32
    ) throws -> Data {
        let imm0 = UInt16(truncatingIfNeeded: functionId)
        let imm1 = UInt16(truncatingIfNeeded: functionId >> 16)
        let imm2 = UInt16(truncatingIfNeeded: functionId >> 32)
        let imm3 = UInt16(truncatingIfNeeded: functionId >> 48)

        var words: [UInt32] = []
        words.append(encodeMOVZ64(rd: rd, imm16: imm0, hw: 0))
        words.append(encodeMOVK64(rd: rd, imm16: imm1, hw: 1))
        words.append(encodeMOVK64(rd: rd, imm16: imm2, hw: 2))
        words.append(encodeMOVK64(rd: rd, imm16: imm3, hw: 3))

        let blPC = functionEntryVMA + 16
        let blOffset = Int64(vmEntryVMA) - Int64(blPC)
        words.append(try encodeBL(offsetBytes: blOffset, fromVMA: blPC, toVMA: vmEntryVMA))
        words.append(0xD65F_03C0) // ret
        words.append(0xD503_201F) // nop padding

        return packWords(words)
    }

    private static func buildMovkViaX1(
        functionId: UInt64,
        functionEntryVMA: UInt64,
        vmEntryVMA: UInt64
    ) throws -> Data {
        let imm0 = UInt16(truncatingIfNeeded: functionId)
        let imm1 = UInt16(truncatingIfNeeded: functionId >> 16)
        let imm2 = UInt16(truncatingIfNeeded: functionId >> 32)
        let imm3 = UInt16(truncatingIfNeeded: functionId >> 48)

        var words: [UInt32] = []
        words.append(encodeMOVZ64(rd: 1, imm16: imm0, hw: 0))
        words.append(encodeMOVK64(rd: 1, imm16: imm1, hw: 1))
        words.append(encodeMOVK64(rd: 1, imm16: imm2, hw: 2))
        words.append(encodeMOVK64(rd: 1, imm16: imm3, hw: 3))
        words.append(0xAA01_03E0) // mov x0, x1
        let blPC = functionEntryVMA + 20
        let blOffset = Int64(vmEntryVMA) - Int64(blPC)
        words.append(try encodeBL(offsetBytes: blOffset, fromVMA: blPC, toVMA: vmEntryVMA))
        words.append(0xD65F_03C0) // ret
        // Exactly 7 words (28 B): no trailing NOP — padding slot is folded into fixed patch size.

        return packWords(words)
    }

    /// Literal sits at `functionEntryVMA + 16`; first insn is `LDR X0, #4` (PC+16).
    private static func buildPcRelativeLiteral(
        functionId: UInt64,
        functionEntryVMA: UInt64,
        vmEntryVMA: UInt64
    ) throws -> Data {
        var words: [UInt32] = []
        words.append(encodeLDRXLiteral(rt: 0, imm19: 4))
        let blPC = functionEntryVMA + 4
        let blOffset = Int64(vmEntryVMA) - Int64(blPC)
        words.append(try encodeBL(offsetBytes: blOffset, fromVMA: blPC, toVMA: vmEntryVMA))
        words.append(0xD65F_03C0) // ret
        words.append(0xD503_201F) // nop
        words.append(UInt32(truncatingIfNeeded: functionId))
        words.append(UInt32(truncatingIfNeeded: functionId >> 32))
        words.append(0xD503_201F) // trailing nop

        return packWords(words)
    }

    private static func packWords(_ words: [UInt32]) -> Data {
        precondition(words.count * 4 == trampolineByteLength)
        var data = Data(capacity: words.count * 4)
        for w in words {
            var le = w.littleEndian
            Swift.withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }
        }
        return data
    }

    /// `MOVZ Xd,#imm16` with optional `LSL # (hw*16)` (64-bit).
    private static func encodeMOVZ64(rd: UInt32, imm16: UInt16, hw: UInt32) -> UInt32 {
        0xD280_0000 | ((hw & 3) << 21) | (UInt32(imm16) << 5) | (rd & 31)
    }

    /// `MOVK Xd,#imm16` with optional `LSL # (hw*16)` (64-bit).
    private static func encodeMOVK64(rd: UInt32, imm16: UInt16, hw: UInt32) -> UInt32 {
        0xF280_0000 | ((hw & 3) << 21) | (UInt32(imm16) << 5) | (rd & 31)
    }

    private static func encodeBL(offsetBytes: Int64, fromVMA: UInt64, toVMA: UInt64) throws -> UInt32 {
        guard offsetBytes % 4 == 0 else {
            throw VMPatchRewriterError.blOffsetNotAligned(offsetBytes)
        }
        let imm = offsetBytes >> 2
        let min26: Int64 = -(1 << 25)
        let max26: Int64 = (1 << 25) - 1
        guard imm >= min26 && imm <= max26 else {
            throw VMPatchRewriterError.blOutOfRange(
                offsetBytes: offsetBytes,
                fromVMA: fromVMA,
                toVMA: toVMA
            )
        }
        let encoded = UInt32(bitPattern: Int32(imm))
        return 0x9400_0000 | (encoded & 0x03FF_FFFF)
    }

    /// `LDR Xt, label` PC-relative (64-bit). `imm19` is signed offset in instructions from the LDR PC to the literal.
    private static func encodeLDRXLiteral(rt: UInt32, imm19: Int32) -> UInt32 {
        let encImm = UInt32(bitPattern: imm19) & 0x7FFFF
        return 0x5800_0000 | (encImm << 5) | (rt & 31)
    }
}
