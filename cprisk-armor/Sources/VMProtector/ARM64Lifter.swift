import Foundation

/// How far to scan within the provided instruction buffer.
public enum LiftTermination: Sendable, Equatable {
    /// Stop after lifting the first `RET` (included) or when `maxInstructions` is reached.
    case atFirstRet
    /// Linear sweep until buffer end or `maxInstructions` (does not stop at `RET`).
    case atBufferEnd
}

public struct ARMLiftConfig: Sendable, Equatable {
    public var maxInstructions: Int
    public var termination: LiftTermination

    public init(maxInstructions: Int = 256, termination: LiftTermination = .atFirstRet) {
        self.maxInstructions = max(1, maxInstructions)
        self.termination = termination
    }
}

/// AArch64 → VMIR lifter (build-time). Unrecognized patterns become `rawRegion`.
public struct ARM64Lifter: Sendable {
    public init() {}

    /// Legacy entry: lift until first RET (or max instructions), append `halt` if no RET.
    public func liftPrologue(bytes: Data, maxInstructions: Int = 24) -> [VMInstruction] {
        lift(bytes: bytes, config: ARMLiftConfig(maxInstructions: maxInstructions, termination: .atFirstRet))
    }

    /// Lift AArch64 words from `bytes` according to `config`.
    public func lift(bytes: Data, config: ARMLiftConfig = ARMLiftConfig()) -> [VMInstruction] {
        var out: [VMInstruction] = []
        var offset = 0
        var insnCount = 0

        while offset + 4 <= bytes.count, insnCount < config.maxInstructions {
            let insn = readU32LE(bytes, offset)

            if insn == 0xD503_201F {
                out.append(VMInstruction(op: .nop))
                offset += 4
                insnCount += 1
                continue
            }

            if isRET(insn) {
                out.append(VMInstruction(op: .ret))
                offset += 4
                insnCount += 1
                if config.termination == .atFirstRet {
                    break
                }
                continue
            }

            if offset + 8 <= bytes.count, let fused = tryFuseAdrpAdd(bytes: bytes, offset: offset) {
                out.append(
                    VMInstruction(
                        op: .adrAdd,
                        immediate: fused
                    )
                )
                offset += 8
                insnCount += 2
                continue
            }

            if let lifted = liftSingleWord(insn) {
                out.append(lifted)
                offset += 4
                insnCount += 1
                continue
            }

            out.append(
                VMInstruction(
                    op: .rawRegion,
                    immediate: UInt64(insn),
                    rawCategory: .unknown
                )
            )
            offset += 4
            insnCount += 1
        }

        if terminationNeedsHalt(last: out.last) {
            out.append(VMInstruction(op: .halt))
        }
        return out
    }

    private func terminationNeedsHalt(last: VMInstruction?) -> Bool {
        guard let last else { return true }
        return last.op != .ret
    }

    private func liftSingleWord(_ insn: UInt32) -> VMInstruction? {
        if isBL(insn) {
            return VMInstruction(op: .call, immediate: Self.vmByteDeltaFromUnconditionalBranch(insn))
        }
        if isBUnconditional(insn) {
            return VMInstruction(op: .branchRel, immediate: Self.vmByteDeltaFromUnconditionalBranch(insn))
        }
        if isMoveWide(insn) {
            return VMInstruction(op: .movWide, immediate: UInt64(insn))
        }
        if isEOR64(insn) {
            return VMInstruction(op: .xorMix, immediate: UInt64(insn))
        }
        if isADRP(insn) {
            return VMInstruction(op: .adrAdd, immediate: UInt64(insn))
        }
        if isADDImm64(insn) {
            return VMInstruction(op: .addLane, immediate: UInt64(insn))
        }
        if isCSEL(insn) || isCSETAlias(insn) {
            return VMInstruction(op: .condSelect, immediate: UInt64(insn))
        }
        if isCBZCBNZ(insn) || isBCond(insn) {
            return VMInstruction(op: .branchCond, immediate: UInt64(insn))
        }
        if isLoadStoreBasic(insn) {
            return VMInstruction(op: .loadStore, immediate: UInt64(insn))
        }
        return nil
    }

    /// AArch64 unconditional `B` / `BL`: signed imm26 counts 32-bit words; VM mirrors one AArch64 word per VM instruction → ×9 bytes.
    private static func vmByteDeltaFromUnconditionalBranch(_ insn: UInt32) -> UInt64 {
        let imm26 = insn & 0x03FF_FFFF
        let sext = Int32(bitPattern: (imm26 << 6) >> 6)
        let delta = Int64(sext) * 9
        return UInt64(bitPattern: delta)
    }

    private func isBL(_ insn: UInt32) -> Bool {
        (insn & 0xFC00_0000) == 0x9400_0000
    }

    private func isBUnconditional(_ insn: UInt32) -> Bool {
        (insn & 0xFC00_0000) == 0x1400_0000
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

    private func isMoveWide(_ insn: UInt32) -> Bool {
        (insn >> 23) & 0x1FF == 0x1A5
    }

    private func isADRP(_ insn: UInt32) -> Bool {
        (insn & 0x9F00_0000) == 0x9000_0000
    }

    private func isADDImm64(_ insn: UInt32) -> Bool {
        (insn & 0xFF80_0000) == 0x9100_0000
    }

    /// EOR Xd, Xn, Xm (shifted) — 64-bit.
    private func isEOR64(_ insn: UInt32) -> Bool {
        (insn & 0xFF20_0000) == 0xCA00_0000
    }

    private func isCSEL(_ insn: UInt32) -> Bool {
        (insn & 0xFF80_0000) == 0x9A80_0000
    }

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
