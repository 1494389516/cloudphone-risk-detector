import Foundation
import MachOKit

struct ControlFlowBinaryRewriteReport {
    let modifiedFunctionCount: Int
    let bytesModified: Int
    let details: [String]
}

final class ControlFlowBinaryRewriter {
    private let policy: FunctionCFFPolicy
    private let plansBySymbol: [String: OrchestratedFunctionPlan]
    private let symbolIndex: CFFPolicySymbolIndex

    init(policy: FunctionCFFPolicy, plans: [OrchestratedFunctionPlan]) {
        self.policy = policy
        self.plansBySymbol = Dictionary(uniqueKeysWithValues: plans.map { ($0.symbol, $0) })
        self.symbolIndex = CFFPolicySymbolIndex(policy: policy)
    }

    func apply(to file: MachOFile, verbose: Bool) throws -> ControlFlowBinaryRewriteReport {
        guard let textSection = try file.section(segment: "__TEXT", section: "__text") else {
            return ControlFlowBinaryRewriteReport(
                modifiedFunctionCount: 0,
                bytesModified: 0,
                details: ["Skipped: __TEXT.__text not found"]
            )
        }
        guard textSection.size <= UInt64(Int.max) else {
            return ControlFlowBinaryRewriteReport(
                modifiedFunctionCount: 0,
                bytesModified: 0,
                details: ["Skipped: __TEXT.__text exceeds supported size"]
            )
        }

        let textStart = Int(textSection.offset)
        let textSize = Int(textSection.size)
        let textEnd = textStart + textSize
        let textVMStart = textSection.address
        let textVMEnd = textSection.address + textSection.size

        let symbols = try file.readSymbols()
        guard !symbols.isEmpty else {
            return ControlFlowBinaryRewriteReport(
                modifiedFunctionCount: 0,
                bytesModified: 0,
                details: ["Skipped: no symbol table entries found for Pass9 targeting"]
            )
        }

        let matchedCandidates = collectManagedCandidates(
            from: symbols,
            textStart: textStart,
            textEnd: textEnd,
            textVMStart: textVMStart,
            textVMEnd: textVMEnd
        )
        guard !matchedCandidates.isEmpty else {
            return ControlFlowBinaryRewriteReport(
                modifiedFunctionCount: 0,
                bytesModified: 0,
                details: [
                    "No managed functions matched __TEXT.__text symbols",
                    "Managed symbols in policy: \(policy.allManagedFunctions.count)"
                ]
            )
        }

        var modified = [CFFModifiedFunctionRecord]()
        var skipped = [CFFSkippedFunctionRecord]()
        modified.reserveCapacity(matchedCandidates.count)
        skipped.reserveCapacity(matchedCandidates.count)

        for (index, candidate) in matchedCandidates.enumerated() {
            let functionVMEnd = (index + 1 < matchedCandidates.count)
                ? matchedCandidates[index + 1].entryVMAddress
                : textVMEnd

            guard functionVMEnd > candidate.entryVMAddress else {
                skipped.append(CFFSkippedFunctionRecord(
                    policySymbol: candidate.policySymbol,
                    binarySymbol: candidate.binarySymbol,
                    tier: candidate.tier,
                    reason: "invalid function bounds (next symbol address <= current address)"
                ))
                continue
            }

            let functionSizeBytes = Int(functionVMEnd - candidate.entryVMAddress)
            let outcome = rewriteFunction(
                candidate,
                functionSizeBytes: functionSizeBytes,
                textStart: textStart,
                file: file
            )
            switch outcome {
            case .modified(let record):
                modified.append(record)
            case .skipped(let record):
                skipped.append(record)
            }
        }

        let bytesModified = modified.reduce(0) { $0 + $1.bytesModified }
        var details: [String] = [
            "Pass9 binary rewrite mode: active",
            "managed policy symbols: \(policy.allManagedFunctions.count)",
            "policy-matched __text functions: \(matchedCandidates.count)",
            "modified functions: \(modified.count)",
            "bytes modified in __text: \(bytesModified)"
        ]

        if !modified.isEmpty {
            let maxFunctionLines = verbose ? modified.count : min(12, modified.count)
            for record in modified.prefix(maxFunctionLines) {
                let symbolLabel: String
                if record.policySymbol == record.binarySymbol {
                    symbolLabel = record.policySymbol
                } else {
                    symbolLabel = "\(record.policySymbol) <= \(record.binarySymbol)"
                }

                let offsetList = record.patches
                    .map { String(format: "__text+0x%X", $0.fileOffset - textStart) }
                    .joined(separator: ", ")
                details.append(
                    "[modified][\(record.tier.rawValue)] \(symbolLabel) patches=\(record.patches.count) bytes=\(record.bytesModified) offsets=[\(offsetList)]"
                )

                if verbose {
                    for patch in record.patches {
                        details.append(String(
                            format: "  patch __text+0x%X: 0x%08X -> 0x%08X (%@)",
                            patch.fileOffset - textStart,
                            patch.originalRawValue,
                            patch.replacementRawValue,
                            patch.replacementDescription
                        ))
                    }
                }
            }
        }

        if !skipped.isEmpty {
            details.append("skipped functions: \(skipped.count)")
            let maxSkippedLines = verbose ? skipped.count : min(16, skipped.count)
            for record in skipped.prefix(maxSkippedLines) {
                let symbolLabel: String
                if record.policySymbol == record.binarySymbol {
                    symbolLabel = record.policySymbol
                } else {
                    symbolLabel = "\(record.policySymbol) <= \(record.binarySymbol)"
                }
                details.append("[skipped][\(record.tier.rawValue)] \(symbolLabel): \(record.reason)")
            }
        }

        return ControlFlowBinaryRewriteReport(
            modifiedFunctionCount: modified.count,
            bytesModified: bytesModified,
            details: details
        )
    }

    private func collectManagedCandidates(
        from symbols: [SymbolEntry],
        textStart: Int,
        textEnd: Int,
        textVMStart: UInt64,
        textVMEnd: UInt64
    ) -> [CFFManagedFunctionCandidate] {
        var bestByEntryAddress = [UInt64: CFFManagedFunctionCandidate]()

        for symbol in symbols {
            guard symbol.nlist.typeField == Nlist64Entry.N_SECT else { continue }
            let vmAddress = symbol.nlist.n_value
            guard vmAddress >= textVMStart, vmAddress < textVMEnd else { continue }
            guard let resolved = symbolIndex.resolve(symbol.name) else { continue }
            guard let plan = plansBySymbol[resolved.policySymbol] else { continue }
            guard let profile = resolved.tier.rewriteProfile else { continue }

            let relative = vmAddress - textVMStart
            let fileOffset64 = UInt64(textStart) + relative
            guard fileOffset64 <= UInt64(Int.max) else { continue }
            let fileOffset = Int(fileOffset64)
            guard fileOffset >= textStart, fileOffset < textEnd else { continue }

            let candidate = CFFManagedFunctionCandidate(
                policySymbol: resolved.policySymbol,
                binarySymbol: symbol.name,
                tier: resolved.tier,
                plan: plan,
                entryVMAddress: vmAddress,
                entryFileOffset: fileOffset,
                requiredPatchSlots: profile.requiredPatchSlots,
                scanSlots: profile.scanSlots
            )

            if let existing = bestByEntryAddress[vmAddress] {
                if candidate.priorityScore > existing.priorityScore
                    || (candidate.priorityScore == existing.priorityScore
                        && candidate.policySymbol < existing.policySymbol) {
                    bestByEntryAddress[vmAddress] = candidate
                }
            } else {
                bestByEntryAddress[vmAddress] = candidate
            }
        }

        return bestByEntryAddress.values.sorted { lhs, rhs in
            lhs.entryVMAddress < rhs.entryVMAddress
        }
    }

    private func rewriteFunction(
        _ candidate: CFFManagedFunctionCandidate,
        functionSizeBytes: Int,
        textStart: Int,
        file: MachOFile
    ) -> CFFFunctionRewriteOutcome {
        let minBytes = candidate.requiredPatchSlots * 4
        guard functionSizeBytes >= minBytes else {
            return .skipped(CFFSkippedFunctionRecord(
                policySymbol: candidate.policySymbol,
                binarySymbol: candidate.binarySymbol,
                tier: candidate.tier,
                reason: "function too small (\(functionSizeBytes) bytes < required \(minBytes) bytes)"
            ))
        }
        guard candidate.entryFileOffset % 4 == 0 else {
            return .skipped(CFFSkippedFunctionRecord(
                policySymbol: candidate.policySymbol,
                binarySymbol: candidate.binarySymbol,
                tier: candidate.tier,
                reason: "entry offset 0x\(String(candidate.entryFileOffset, radix: 16)) is not 4-byte aligned"
            ))
        }

        let availableSlots = functionSizeBytes / 4
        let scanSlots = min(candidate.scanSlots, availableSlots)
        guard scanSlots >= candidate.requiredPatchSlots else {
            return .skipped(CFFSkippedFunctionRecord(
                policySymbol: candidate.policySymbol,
                binarySymbol: candidate.binarySymbol,
                tier: candidate.tier,
                reason: "insufficient scan window (\(scanSlots) slots < required \(candidate.requiredPatchSlots) slots)"
            ))
        }

        var patchable = [CFFPatchableSlot]()
        patchable.reserveCapacity(scanSlots)

        for slotIndex in 0..<scanSlots {
            let fileOffset = candidate.entryFileOffset + slotIndex * 4
            guard let rawValue = try? file.data.readUInt32LE(at: fileOffset) else { continue }
            guard let decoded = CFFNeutralInstructionCodec.decode(rawValue) else { continue }
            let options = CFFNeutralInstructionCodec.replacementOptions(
                for: decoded,
                excluding: rawValue
            )
            guard !options.isEmpty else { continue }

            patchable.append(CFFPatchableSlot(
                fileOffset: fileOffset,
                originalRawValue: rawValue,
                options: options
            ))
        }

        guard patchable.count >= candidate.requiredPatchSlots else {
            return .skipped(CFFSkippedFunctionRecord(
                policySymbol: candidate.policySymbol,
                binarySymbol: candidate.binarySymbol,
                tier: candidate.tier,
                reason: "insufficient rewritable entry instructions (\(patchable.count) < \(candidate.requiredPatchSlots))"
            ))
        }

        var rng = CFFSplitMix64(seed: candidate.rewriteSeed)
        patchable.shuffle(using: &rng)
        let selectedSlots = Array(patchable.prefix(candidate.requiredPatchSlots)).sorted {
            $0.fileOffset < $1.fileOffset
        }

        var mutations = [CFFPatchMutation]()
        mutations.reserveCapacity(selectedSlots.count)
        for slot in selectedSlots {
            let optionIndex = Int(rng.next() % UInt64(slot.options.count))
            let replacement = slot.options[optionIndex]
            mutations.append(CFFPatchMutation(
                fileOffset: slot.fileOffset,
                originalRawValue: slot.originalRawValue,
                replacementRawValue: replacement.rawValue,
                replacementDescription: replacement.description
            ))
        }

        let rollbackBytes = mutations.map { mutation -> (offset: UInt64, bytes: Data) in
            (
                offset: UInt64(mutation.fileOffset),
                bytes: CFFNeutralInstructionCodec.data(for: mutation.originalRawValue)
            )
        }

        do {
            for mutation in mutations {
                try file.replaceBytes(
                    at: UInt64(mutation.fileOffset),
                    with: CFFNeutralInstructionCodec.data(for: mutation.replacementRawValue)
                )
            }

            for mutation in mutations {
                guard let patched = try? file.data.readUInt32LE(at: mutation.fileOffset),
                      patched == mutation.replacementRawValue else {
                    for rollback in rollbackBytes {
                        try? file.replaceBytes(at: rollback.offset, with: rollback.bytes)
                    }
                    return .skipped(CFFSkippedFunctionRecord(
                        policySymbol: candidate.policySymbol,
                        binarySymbol: candidate.binarySymbol,
                        tier: candidate.tier,
                        reason: "post-write verification failed, reverted"
                    ))
                }
            }
        } catch {
            for rollback in rollbackBytes {
                try? file.replaceBytes(at: rollback.offset, with: rollback.bytes)
            }
            return .skipped(CFFSkippedFunctionRecord(
                policySymbol: candidate.policySymbol,
                binarySymbol: candidate.binarySymbol,
                tier: candidate.tier,
                reason: "write failure: \(error), reverted"
            ))
        }

        return .modified(CFFModifiedFunctionRecord(
            policySymbol: candidate.policySymbol,
            binarySymbol: candidate.binarySymbol,
            tier: candidate.tier,
            bytesModified: mutations.count * 4,
            patches: mutations
        ))
    }
}

private struct CFFManagedFunctionCandidate {
    let policySymbol: String
    let binarySymbol: String
    let tier: FunctionCFFTier
    let plan: OrchestratedFunctionPlan
    let entryVMAddress: UInt64
    let entryFileOffset: Int
    let requiredPatchSlots: Int
    let scanSlots: Int

    var priorityScore: Int {
        tier.priorityWeight
    }

    var rewriteSeed: UInt64 {
        let base = plan.stateEncodingPlan.perFunctionSeed
        let tierSalt = UInt64(tier.priorityWeight) << 48
        return base ^ UInt64(entryFileOffset) ^ tierSalt
    }
}

private struct CFFModifiedFunctionRecord {
    let policySymbol: String
    let binarySymbol: String
    let tier: FunctionCFFTier
    let bytesModified: Int
    let patches: [CFFPatchMutation]
}

private struct CFFSkippedFunctionRecord {
    let policySymbol: String
    let binarySymbol: String
    let tier: FunctionCFFTier
    let reason: String
}

private enum CFFFunctionRewriteOutcome {
    case modified(CFFModifiedFunctionRecord)
    case skipped(CFFSkippedFunctionRecord)
}

private struct CFFPatchableSlot {
    let fileOffset: Int
    let originalRawValue: UInt32
    let options: [CFFReplacementOption]
}

private struct CFFPatchMutation {
    let fileOffset: Int
    let originalRawValue: UInt32
    let replacementRawValue: UInt32
    let replacementDescription: String
}

private struct CFFPolicySymbolIndex {
    private struct Entry {
        let policySymbol: String
        let tier: FunctionCFFTier
    }

    private let exact: [String: Entry]
    private let normalized: [String: Entry]
    private let uniqueTail: [String: Entry]

    init(policy: FunctionCFFPolicy) {
        var exact = [String: Entry]()
        var normalized = [String: Entry]()
        var tailCandidates = [String: Entry]()
        var duplicatedTail = Set<String>()

        for tier in FunctionCFFTier.allCases {
            for symbol in policy.functions(for: tier) {
                let entry = Entry(policySymbol: symbol, tier: tier)
                exact[symbol] = entry
                normalized[Self.normalize(symbol)] = entry

                if let tail = Self.tailComponent(of: symbol) {
                    if tailCandidates[tail] == nil {
                        tailCandidates[tail] = entry
                    } else {
                        duplicatedTail.insert(tail)
                    }
                }
            }
        }

        for tail in duplicatedTail {
            tailCandidates.removeValue(forKey: tail)
        }

        self.exact = exact
        self.normalized = normalized
        self.uniqueTail = tailCandidates
    }

    func resolve(_ binarySymbol: String) -> (policySymbol: String, tier: FunctionCFFTier)? {
        if let exactMatch = exact[binarySymbol] {
            return (exactMatch.policySymbol, exactMatch.tier)
        }

        let normalizedSymbol = Self.normalize(binarySymbol)
        if let normalizedMatch = normalized[normalizedSymbol] {
            return (normalizedMatch.policySymbol, normalizedMatch.tier)
        }

        for (tail, entry) in uniqueTail where tail.count >= 8 {
            if normalizedSymbol == tail || normalizedSymbol.hasSuffix(tail) {
                return (entry.policySymbol, entry.tier)
            }
        }

        return nil
    }

    private static func normalize(_ symbol: String) -> String {
        var normalized = symbol.trimmingCharacters(in: .whitespacesAndNewlines)
        while normalized.hasPrefix("_") {
            normalized.removeFirst()
        }
        return normalized
    }

    private static func tailComponent(of symbol: String) -> String? {
        guard let tail = symbol.split(separator: ".").last else {
            return nil
        }
        let trimmed = String(tail).trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

private extension FunctionCFFTier {
    var rewriteProfile: (requiredPatchSlots: Int, scanSlots: Int)? {
        switch self {
        case .heavy:
            return (requiredPatchSlots: 3, scanSlots: 8)
        case .regionOnly:
            return (requiredPatchSlots: 2, scanSlots: 6)
        case .light:
            return (requiredPatchSlots: 1, scanSlots: 4)
        case .never:
            return nil
        }
    }

    var priorityWeight: Int {
        switch self {
        case .heavy:
            return 30
        case .regionOnly:
            return 20
        case .light:
            return 10
        case .never:
            return 0
        }
    }
}

private enum CFFWidth {
    case w32
    case x64

    var is64Bit: Bool { self == .x64 }
}

private enum CFFDecodedInstruction {
    case registerCopy(destination: UInt32, source: UInt32, width: CFFWidth)
    case noEffect(source: UInt32?, width: CFFWidth)
}

private struct CFFReplacementOption {
    let rawValue: UInt32
    let description: String
}

private enum CFFNeutralInstructionCodec {
    private static let zeroRegister: UInt32 = 31
    private static let nopRawValue: UInt32 = 0xD503_201F

    static func decode(_ rawValue: UInt32) -> CFFDecodedInstruction? {
        if rawValue == nopRawValue {
            return .noEffect(source: nil, width: .x64)
        }
        if let decoded = decodeLogicalShiftedRegister(rawValue) {
            return decoded
        }
        if let decoded = decodeAddSubImmediate(rawValue) {
            return decoded
        }
        return nil
    }

    static func replacementOptions(
        for decoded: CFFDecodedInstruction,
        excluding originalRawValue: UInt32
    ) -> [CFFReplacementOption] {
        switch decoded {
        case .registerCopy(let destination, let source, let width):
            let allowAddSub = source != zeroRegister && destination != zeroRegister
            var candidates: [CFFReplacementOption] = [
                CFFReplacementOption(
                    rawValue: encodeMoveAlias(destination: destination, source: source, width: width),
                    description: "mov alias"
                ),
                CFFReplacementOption(
                    rawValue: encodeAndSelf(destination: destination, source: source, width: width),
                    description: "and self"
                ),
                CFFReplacementOption(
                    rawValue: encodeOrrSelf(destination: destination, source: source, width: width),
                    description: "orr self"
                )
            ]

            if allowAddSub {
                candidates.append(CFFReplacementOption(
                    rawValue: encodeAddImmediateZero(destination: destination, source: source, width: width),
                    description: "add #0"
                ))
                candidates.append(CFFReplacementOption(
                    rawValue: encodeSubImmediateZero(destination: destination, source: source, width: width),
                    description: "sub #0"
                ))
            }

            return orderedUnique(candidates, excluding: originalRawValue)

        case .noEffect(let source, let width):
            let sourceRegister = source ?? zeroRegister
            var candidates: [CFFReplacementOption] = []
            if sourceRegister == zeroRegister {
                candidates.append(CFFReplacementOption(rawValue: encodeNOP(), description: "nop"))
            }
            candidates.append(contentsOf: [
                CFFReplacementOption(
                    rawValue: encodeMoveAlias(destination: zeroRegister, source: sourceRegister, width: width),
                    description: "discard via mov"
                ),
                CFFReplacementOption(
                    rawValue: encodeAndSelf(destination: zeroRegister, source: sourceRegister, width: width),
                    description: "discard via and"
                ),
                CFFReplacementOption(
                    rawValue: encodeOrrSelf(destination: zeroRegister, source: sourceRegister, width: width),
                    description: "discard via orr"
                )
            ])
            return orderedUnique(candidates, excluding: originalRawValue)
        }
    }

    static func data(for rawValue: UInt32) -> Data {
        var littleEndian = rawValue.littleEndian
        return Swift.withUnsafeBytes(of: &littleEndian) { Data($0) }
    }

    private static func orderedUnique(
        _ options: [CFFReplacementOption],
        excluding originalRawValue: UInt32
    ) -> [CFFReplacementOption] {
        var seen = Set<UInt32>()
        var unique = [CFFReplacementOption]()
        unique.reserveCapacity(options.count)

        for option in options where option.rawValue != originalRawValue {
            if seen.insert(option.rawValue).inserted {
                unique.append(option)
            }
        }
        return unique
    }

    private static func decodeLogicalShiftedRegister(_ rawValue: UInt32) -> CFFDecodedInstruction? {
        guard (rawValue & 0x1F20_0000) == 0x0A00_0000 else { return nil }

        let width = width(from: rawValue)
        let opc = (rawValue >> 29) & 0x3
        let shift = (rawValue >> 22) & 0x3
        let rm = (rawValue >> 16) & 0x1F
        let imm6 = (rawValue >> 10) & 0x3F
        let rn = (rawValue >> 5) & 0x1F
        let rd = rawValue & 0x1F

        guard shift == 0, imm6 == 0 else { return nil }

        if opc == 0b01, rn == zeroRegister {
            if rd == zeroRegister {
                return .noEffect(source: rm, width: width)
            }
            return .registerCopy(destination: rd, source: rm, width: width)
        }

        if (opc == 0b00 || opc == 0b01), rn == rm {
            if rd == zeroRegister {
                return .noEffect(source: rn, width: width)
            }
            return .registerCopy(destination: rd, source: rn, width: width)
        }

        return nil
    }

    private static func decodeAddSubImmediate(_ rawValue: UInt32) -> CFFDecodedInstruction? {
        guard (rawValue & 0x1F00_0000) == 0x1100_0000 else { return nil }

        let setFlags = (rawValue >> 29) & 0x1
        let imm12 = (rawValue >> 10) & 0xFFF
        let rn = (rawValue >> 5) & 0x1F
        let rd = rawValue & 0x1F
        guard setFlags == 0, imm12 == 0 else { return nil }
        guard rn != zeroRegister, rd != zeroRegister else { return nil }

        return .registerCopy(destination: rd, source: rn, width: width(from: rawValue))
    }

    private static func encodeMoveAlias(destination: UInt32, source: UInt32, width: CFFWidth) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0xAA00_0000 : 0x2A00_0000
        return base
            | ((source & 0x1F) << 16)
            | ((zeroRegister & 0x1F) << 5)
            | (destination & 0x1F)
    }

    private static func encodeAddImmediateZero(destination: UInt32, source: UInt32, width: CFFWidth) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0x9100_0000 : 0x1100_0000
        return base
            | ((source & 0x1F) << 5)
            | (destination & 0x1F)
    }

    private static func encodeSubImmediateZero(destination: UInt32, source: UInt32, width: CFFWidth) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0xD100_0000 : 0x5100_0000
        return base
            | ((source & 0x1F) << 5)
            | (destination & 0x1F)
    }

    private static func encodeAndSelf(destination: UInt32, source: UInt32, width: CFFWidth) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0x8A00_0000 : 0x0A00_0000
        return base
            | ((source & 0x1F) << 16)
            | ((source & 0x1F) << 5)
            | (destination & 0x1F)
    }

    private static func encodeOrrSelf(destination: UInt32, source: UInt32, width: CFFWidth) -> UInt32 {
        let base: UInt32 = width.is64Bit ? 0xAA00_0000 : 0x2A00_0000
        return base
            | ((source & 0x1F) << 16)
            | ((source & 0x1F) << 5)
            | (destination & 0x1F)
    }

    private static func encodeNOP() -> UInt32 {
        nopRawValue
    }

    private static func width(from rawValue: UInt32) -> CFFWidth {
        ((rawValue >> 31) & 0x1) == 1 ? .x64 : .w32
    }
}

private struct CFFSplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed == 0 ? 1 : seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

private extension Data {
    func readUInt32LE(at offset: Int) throws -> UInt32 {
        guard offset >= 0, offset + 4 <= count else {
            throw MachOError.outOfBoundsRead(offset: offset, size: 4, dataSize: count)
        }

        let bytes = [UInt8](self[offset..<(offset + 4)])
        return UInt32(bytes[0])
            | (UInt32(bytes[1]) << 8)
            | (UInt32(bytes[2]) << 16)
            | (UInt32(bytes[3]) << 24)
    }
}
