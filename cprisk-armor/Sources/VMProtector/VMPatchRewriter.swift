import Foundation

public enum VMPatchRewriterError: Error, CustomStringConvertible {
    case blOffsetNotAligned(Int64)
    case blOutOfRange(Int64)

    public var description: String {
        switch self {
        case .blOffsetNotAligned(let o): return "BL offset not 4-byte aligned (\(o))"
        case .blOutOfRange(let imm): return "BL out of ±128MB range (imm26=\(imm))"
        }
    }
}

/// Builds AArch64 trampoline: load `functionId` into `x0`, then `bl` to `_cprisk_vm_entry`.
public enum VMPatchRewriter {
    public static let trampolineByteLength = 28

    /// - Parameters:
    ///   - functionId: Passed in `x0` to the VM entry helper.
    ///   - functionEntryVMA: Virtual address of the patched function entry (first MOVZ).
    ///   - vmEntryVMA: Virtual address of `_cprisk_vm_entry`.
    public static func buildTrampoline(
        functionId: UInt64,
        functionEntryVMA: UInt64,
        vmEntryVMA: UInt64
    ) throws -> Data {
        let imm0 = UInt16(truncatingIfNeeded: functionId)
        let imm1 = UInt16(truncatingIfNeeded: functionId >> 16)
        let imm2 = UInt16(truncatingIfNeeded: functionId >> 32)
        let imm3 = UInt16(truncatingIfNeeded: functionId >> 48)

        var words: [UInt32] = []
        words.append(encodeMOVZ64(rd: 0, imm16: imm0, hw: 0))
        words.append(encodeMOVK64(rd: 0, imm16: imm1, hw: 1))
        words.append(encodeMOVK64(rd: 0, imm16: imm2, hw: 2))
        words.append(encodeMOVK64(rd: 0, imm16: imm3, hw: 3))

        let blPC = functionEntryVMA + 16
        let blOffset = Int64(vmEntryVMA) - Int64(blPC)
        words.append(try encodeBL(offsetBytes: blOffset))
        words.append(0xD65F_03C0) // ret
        words.append(0xD503_201F) // nop padding

        var data = Data(capacity: words.count * 4)
        for w in words {
            var le = w.littleEndian
            Swift.withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }
        }
        precondition(data.count == trampolineByteLength)
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

    private static func encodeBL(offsetBytes: Int64) throws -> UInt32 {
        guard offsetBytes % 4 == 0 else {
            throw VMPatchRewriterError.blOffsetNotAligned(offsetBytes)
        }
        let imm = offsetBytes >> 2
        let min26 = -(1 << 25)
        let max26 = (1 << 25) - 1
        guard imm >= min26 && imm <= max26 else {
            throw VMPatchRewriterError.blOutOfRange(imm)
        }
        let encoded = UInt32(bitPattern: Int32(imm))
        return 0x9400_0000 | (encoded & 0x03FF_FFFF)
    }
}
