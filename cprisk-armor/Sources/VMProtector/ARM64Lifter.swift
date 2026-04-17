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
    public var fuseAddRolAcc: Bool

    public init(
        maxInstructions: Int = 256,
        termination: LiftTermination = .atFirstRet,
        fuseAddRolAcc: Bool = true
    ) {
        self.maxInstructions = max(1, maxInstructions)
        self.termination = termination
        self.fuseAddRolAcc = fuseAddRolAcc
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

        var optimized = fuseSuperInstructions(out, enableAddRolAccFusion: config.fuseAddRolAcc)
        if terminationNeedsHalt(last: optimized.last) {
            optimized.append(VMInstruction(op: .halt))
        }
        return optimized
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
        if isMOVRegisterAlias(insn) {
            return VMInstruction(op: .movWide, immediate: UInt64(insn))
        }
        if isADRP(insn) {
            return VMInstruction(op: .adrAdd, immediate: UInt64(insn))
        }
        if isADR(insn) {
            return VMInstruction(op: .adrAdd, immediate: UInt64(insn))
        }
        if let logImm = classifyLogicalImm64(insn) {
            return VMInstruction(op: logImm, immediate: UInt64(insn))
        }
        if isCompareLike(insn) {
            return VMInstruction(op: .branchCond, immediate: UInt64(insn))
        }
        if isADDImm64(insn) {
            return VMInstruction(op: .addLane, immediate: UInt64(insn))
        }
        if isSUBImm64(insn) {
            return VMInstruction(op: .subLane, immediate: UInt64(insn))
        }
        if let addSub = classifyAddSubShiftedReg64(insn) {
            return VMInstruction(op: addSub, immediate: UInt64(insn))
        }
        if isMADD64AsMul(insn) {
            return VMInstruction(op: .mulLane, immediate: UInt64(insn))
        }
        if let bitwise = classifyBitwiseLogical64(insn) {
            return VMInstruction(op: bitwise, immediate: UInt64(insn))
        }
        if isShiftByRegister64(insn) {
            return VMInstruction(op: .rolAcc, immediate: UInt64(insn))
        }
        if isCSEL(insn) || isCSETAlias(insn) {
            return VMInstruction(op: .condSelect, immediate: UInt64(insn))
        }
        if isCBZCBNZ(insn) || isBCond(insn) || isTBZTBNZ(insn) {
            return VMInstruction(op: .branchCond, immediate: UInt64(insn))
        }
        if isLoadStoreBasic(insn) {
            return VMInstruction(op: .loadStore, immediate: UInt64(insn))
        }
        if isBLR(insn) || isBR(insn) {
            let rn = UInt64((insn >> 5) & 0x1F)
            return VMInstruction(op: .branchInd, immediate: VMBranchIndImmediateContract.synthetic(vregIndex: rn, accBase: 0))
        }
        if isPACInstruction(insn) {
            return VMInstruction(op: .rawRegion, immediate: UInt64(insn), rawCategory: .other)
        }
        if isMADD64(insn) {
            return VMInstruction(op: .mulLane, immediate: UInt64(insn))
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
        let addShift = (add >> 22) & 0x3
        guard addShift == 0 || addShift == 1 else { return nil }
        let adrpRd = adrp & 31
        let addRn = (add >> 5) & 31
        let addRd = add & 31
        guard adrpRd == addRn, adrpRd == addRd else { return nil }
        return UInt64(adrp) | (UInt64(add) << 32)
    }

    private func fuseSuperInstructions(
        _ instructions: [VMInstruction],
        enableAddRolAccFusion: Bool
    ) -> [VMInstruction] {
        guard enableAddRolAccFusion else { return instructions }
        guard instructions.count >= 2 else { return instructions }
        var fused: [VMInstruction] = []
        fused.reserveCapacity(instructions.count)
        var index = 0
        while index < instructions.count {
            if index + 1 < instructions.count,
               let merged = tryFuseAddRolAcc(first: instructions[index], second: instructions[index + 1]) {
                fused.append(merged)
                index += 2
                continue
            }
            fused.append(instructions[index])
            index += 1
        }
        return fused
    }

    private func tryFuseAddRolAcc(first: VMInstruction, second: VMInstruction) -> VMInstruction? {
        guard first.op == .addLane, second.op == .rolAcc else { return nil }
        guard first.rawCategory == nil, second.rawCategory == nil else { return nil }
        guard first.immediate <= UInt64(UInt32.max), second.immediate <= UInt64(UInt32.max) else { return nil }
        let packed = first.immediate | (second.immediate << 32)
        return VMInstruction(op: .addRolAcc, immediate: packed)
    }

    private func isMoveWide(_ insn: UInt32) -> Bool {
        (insn >> 23) & 0x1FF == 0x1A5
    }

    private func isADRP(_ insn: UInt32) -> Bool {
        (insn & 0x9F00_0000) == 0x9000_0000
    }

    /// PC-relative ADR (page-off); same VM surrogate bucket as ADRP / fused ADRP+ADD.
    private func isADR(_ insn: UInt32) -> Bool {
        (insn & 0x9F00_0000) == 0x1000_0000
    }

    /// Logical (immediate) 64-bit — bitmask immediates routed to bitwise VMIR lanes.
    private func classifyLogicalImm64(_ insn: UInt32) -> VMLogicalOp? {
        let masked = insn & 0xFF80_0000
        if masked == 0x9200_0000 { return .andLane }
        if masked == 0xB200_0000 { return .orLane }
        if masked == 0xD200_0000 { return .xorMix }
        return nil
    }

    private func isBLR(_ insn: UInt32) -> Bool {
        (insn & 0xFFFF_FC1F) == 0xD63F_0000
    }

    private func isBR(_ insn: UInt32) -> Bool {
        (insn & 0xFFFF_FC1F) == 0xD61F_0000
    }

    /// Full MADD (not only Xm=XZR mul idiom).
    private func isMADD64(_ insn: UInt32) -> Bool {
        (insn & 0xFF80_0000) == 0x9B00_0000
    }

    private func isADDImm64(_ insn: UInt32) -> Bool {
        guard (insn & 0xFF80_0000) == 0x9100_0000 else { return false }
        let shift = (insn >> 22) & 0x3
        return shift == 0 || shift == 1
    }

    private func isSUBImm64(_ insn: UInt32) -> Bool {
        (insn & 0xFF80_0000) == 0xD100_0000
    }

    /// 64-bit ADD/SUB (register, shifted) — map SUB family to `subLane`.
    private func classifyAddSubShiftedReg64(_ insn: UInt32) -> VMLogicalOp? {
        guard (insn & 0x8000_0000) != 0 else { return nil }
        let top = insn & 0xFF20_0000
        if top == 0x8B00_0000 || top == 0xAB00_0000 { return .addLane }
        if top == 0xCB00_0000 || top == 0xEB00_0000 { return .subLane }
        return nil
    }

    /// MADD Xd, Xn, Xm, XZR — multiply idiom.
    private func isMADD64AsMul(_ insn: UInt32) -> Bool {
        (insn & 0xFF80_0000) == 0x9B00_0000 && ((insn >> 10) & 31) == 31
    }

    /// ORR Xd, XZR, Xm alias of MOV Xd, Xm (shift == LSL #0).
    private func isMOVRegisterAlias(_ insn: UInt32) -> Bool {
        guard (insn & 0xFF20_0000) == 0xAA00_0000 else { return false }
        let rn = (insn >> 5) & 31
        let shift = (insn >> 22) & 0x3
        let imm6 = (insn >> 10) & 0x3F
        return rn == 31 && shift == 0 && imm6 == 0
    }

    /// 64-bit logical shifted-register forms mapped to VM bit-lane families.
    private func classifyBitwiseLogical64(_ insn: UInt32) -> VMLogicalOp? {
        guard (insn & 0x8000_0000) != 0 else { return nil }
        let top = insn & 0xFF20_0000
        switch top {
        case 0x8A00_0000, 0xEA00_0000: // AND / ANDS
            return .andLane
        case 0xAA00_0000, 0xAA20_0000: // ORR / ORN (MOV alias handled earlier)
            return .orLane
        case 0xCA00_0000: // EOR
            return .xorMix
        default:
            return nil
        }
    }

    /// LSLV/LSRV/ASRV 64-bit (register shifts).
    private func isShiftByRegister64(_ insn: UInt32) -> Bool {
        guard (insn & 0x8000_0000) != 0 else { return false }
        let masked = insn & 0xFFE0_FC00
        return masked == 0x9AC0_2000
            || masked == 0x9AC0_2400
            || masked == 0x9AC0_2800
    }

    /// CMP/CMN/TST aliases (SUBS/ADDS/ANDS with Rd==XZR).
    private func isCompareLike(_ insn: UInt32) -> Bool {
        let rd = insn & 31
        guard rd == 31 else { return false }
        if (insn & 0xFF80_001F) == 0xF100_001F { return true } // CMP (imm)
        if (insn & 0xFF80_001F) == 0xB100_001F { return true } // CMN (imm)
        if (insn & 0xFF20_001F) == 0xEB00_001F { return true } // CMP (shifted reg)
        if (insn & 0xFF20_001F) == 0xAB00_001F { return true } // CMN (shifted reg)
        if (insn & 0xFF20_001F) == 0xEA00_001F { return true } // TST (shifted reg)
        return false
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

    private func isTBZTBNZ(_ insn: UInt32) -> Bool {
        (insn & 0x7E00_0000) == 0x3600_0000
    }

    private func isLoadStoreBasic(_ insn: UInt32) -> Bool {
        let op = (insn >> 22) & 0x3F
        if op == 0x28 || op == 0x29 || op == 0x2A || op == 0x2C { return true }
        let top = insn & 0xFFC0_0000
        if top == 0xF940_0000 || top == 0xF900_0000 { return true }
        if top == 0xB940_0000 || top == 0xB900_0000 { return true }
        if top == 0xF840_0000 || top == 0xF800_0000 { return true }
        if top == 0xB840_0000 || top == 0xB800_0000 { return true }
        if top == 0xB980_0000 || top == 0xB880_0000 { return true } // LDRSW/LDURSW
        if (insn & 0x3B00_0000) == 0x3900_0000 { return true }
        if (insn & 0x3B00_0000) == 0x3800_0000 { return true }
        if (insn & 0x3FE0_0C00) == 0x3820_0400 { return true } // pre/post-index family
        return false
    }

    private func isPACInstruction(_ insn: UInt32) -> Bool {
        // PAC/AUT/XPAC live in system-hint and data-processing classes.
        if (insn & 0xFFFF_FF1F) == 0xD503_211F { return true } // XPACLRI
        if (insn & 0xFFFF_FC1F) == 0xDAC1_0000 { return true } // PACIA/PACIZA variants
        if (insn & 0xFFFF_FC1F) == 0xDAC1_0400 { return true } // PACIB/PACIZB variants
        if (insn & 0xFFFF_FC1F) == 0xDAC1_0800 { return true } // AUTIA/AUTIZA variants
        if (insn & 0xFFFF_FC1F) == 0xDAC1_0C00 { return true } // AUTIB/AUTIZB variants
        if (insn & 0xFFFF_FC1F) == 0xDAC1_1000 { return true } // XPACI/XPACD class
        return false
    }
}
