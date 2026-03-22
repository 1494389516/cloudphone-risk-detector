import Foundation

/// AArch64 → VMIR lifter (build-time). Unrecognized or partially modeled patterns become categorized `rawRegion`.
public struct ARM64Lifter: Sendable {
    public init() {}

    /// Lift up to `maxInstructions` 4-byte instructions from the start of `bytes`.
    public func liftPrologue(bytes: Data, maxInstructions: Int = 24) -> [VMInstruction] {
        var out: [VMInstruction] = []
        var offset = 0
        var count = 0
        while offset + 4 <= bytes.count, count < maxInstructions {
            let insn = readU32LE(bytes, offset)

            if insn == 0xD503_201F {
                out.append(VMInstruction(op: .nop))
                offset += 4
                count += 1
                continue
            }

            if isRET(insn) {
                out.append(VMInstruction(op: .ret))
                break
            }

            if offset + 8 <= bytes.count, let fused = tryFuseAdrpAdd(bytes: bytes, offset: offset) {
                out.append(
                    VMInstruction(
                        op: .rawRegion,
                        immediate: fused,
                        rawCategory: .adrAdd
                    )
                )
                offset += 8
                count += 2
                continue
            }

            let category = classifyRaw(insn)
            out.append(
                VMInstruction(
                    op: .rawRegion,
                    immediate: UInt64(insn),
                    rawCategory: category
                )
            )
            offset += 4
            count += 1
        }
        if out.last?.op != .ret {
            out.append(VMInstruction(op: .halt))
        }
        return out
    }

    private func readU32LE(_ data: Data, _ offset: Int) -> UInt32 {
        UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
    }

    private func isRET(_ insn: UInt32) -> Bool {
        (insn & 0xFFFF_FC1F) == 0xD65F_0000 || insn == 0xD65F_03C0
    }

    private func tryFuseAdrpAdd(bytes: Data, offset: Int) -> UInt64? {
        let adrp = readU32LE(bytes, offset)
        let add = readU32LE(bytes, offset + 4)
        guard isADRP(adrp), isADDImm64(add) else { return nil }
        let adrpRd = adrp & 31
        let addRn = (add >> 5) & 31
        let addRd = add & 31
        guard adrpRd == addRn, adrpRd == addRd else { return nil }
        return UInt64(adrp) | (UInt64(add) << 32)
    }

    // MARK: - Decoders (masks are conservative; overlap falls through to `.other`)

    private func classifyRaw(_ insn: UInt32) -> VMRawRegionCategory {
        if isMoveWide(insn) { return .movWide }
        if isADRP(insn) { return .adrAdd }
        if isADDImm64(insn) { return .adrAdd }
        if isCSEL(insn) || isCSETAlias(insn) { return .condSelect }
        if isCBZCBNZ(insn) { return .branchTest }
        if isBCond(insn) { return .branchCond }
        if isLoadStoreBasic(insn) { return .loadStore }
        return .other
    }

    /// Move wide immediate (64-bit): MOVN/MOVZ/MOVK.
    private func isMoveWide(_ insn: UInt32) -> Bool {
        (insn >> 23) & 0x1FF == 0x1A5
    }

    /// ADRP (page address of 4KB page).
    private func isADRP(_ insn: UInt32) -> Bool {
        (insn & 0x9F00_0000) == 0x9000_0000
    }

    /// ADD Xd, Xn, #imm12 (64-bit add immediate only; SUB uses a different opcode family).
    private func isADDImm64(_ insn: UInt32) -> Bool {
        (insn & 0xFF80_0000) == 0x9100_0000
    }

    /// CSEL / CSINC / CSINV / CSNEG (conditional select family).
    private func isCSEL(_ insn: UInt32) -> Bool {
        (insn & 0xFF80_0000) == 0x9A80_0000
    }

    /// CSINC Xd, XZR, XZR, invert(cond) — common CSET pattern; also CSINC-based CSET.
    private func isCSETAlias(_ insn: UInt32) -> Bool {
        let masked = insn & 0xFFFE_FC00
        if masked == 0x9A9F_2000 || masked == 0x9A9F_3000 { return true }
        let rn = (insn >> 5) & 31
        let rm = (insn >> 16) & 31
        let rd = insn & 31
        guard (insn & 0xFFE0_FC00) == 0x9A80_0400 else { return false }
        return rn == 31 && rm == 31 && rd != 31
    }

    private func isCBZCBNZ(_ insn: UInt32) -> Bool {
        (insn & 0x7F00_0000) == 0x3400_0000
    }

    private func isBCond(_ insn: UInt32) -> Bool {
        (insn & 0xFF00_0010) == 0x5400_0000
    }

    /// Basic LDR/STR with unsigned scaled immediate (common leaf forms).
    private func isLoadStoreBasic(_ insn: UInt32) -> Bool {
        let op = (insn >> 22) & 0x3F
        if op == 0x28 || op == 0x29 { return true }
        let top = insn & 0xFFC0_0000
        if top == 0xF940_0000 || top == 0xF900_0000 { return true }
        if top == 0xB940_0000 || top == 0xB900_0000 { return true }
        if (insn & 0x3B00_0000) == 0x3900_0000 { return true }
        return false
    }
}
