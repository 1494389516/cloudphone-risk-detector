import Foundation
import MachOKit

public enum InstructionSubstitutionGroup: String, CaseIterable, Hashable {
    case groupA
    case groupB
    case groupC
    case groupD
    case groupE

    var summaryLabel: String {
        switch self {
        case .groupA: return "Group A"
        case .groupB: return "Group B"
        case .groupC: return "Group C"
        case .groupD: return "Group D"
        case .groupE: return "Group E"
        }
    }

    var detailLabel: String {
        switch self {
        case .groupA:
            return "mov register alias"
        case .groupB:
            return "ADD/SUB #0"
        case .groupC:
            return "AND-self / ORR-self"
        case .groupD:
            return "NOP / XZR no-effect"
        case .groupE:
            return "MOVZ / ORR logical immediate"
        }
    }
}

public struct AppliedInstructionSubstitution: Equatable {
    public let fileOffset: UInt64
    public let originalRawValue: UInt32
    public let replacementRawValue: UInt32
    public let group: InstructionSubstitutionGroup
    public let description: String

    public init(
        fileOffset: UInt64,
        originalRawValue: UInt32,
        replacementRawValue: UInt32,
        group: InstructionSubstitutionGroup,
        description: String
    ) {
        self.fileOffset = fileOffset
        self.originalRawValue = originalRawValue
        self.replacementRawValue = replacementRawValue
        self.group = group
        self.description = description
    }
}

public struct SubstitutionEngineReport {
    public let scannedInstructionCount: Int
    public let eligibleCandidateCount: Int
    public let appliedCount: Int
    public let bytesModified: Int
    public let replacementRate: Double
    public let skippedDataInCodeRangeCount: Int
    public let appliedGroupCounts: [InstructionSubstitutionGroup: Int]
    public let appliedSubstitutions: [AppliedInstructionSubstitution]

    public init(
        scannedInstructionCount: Int,
        eligibleCandidateCount: Int,
        appliedCount: Int,
        bytesModified: Int,
        replacementRate: Double,
        skippedDataInCodeRangeCount: Int,
        appliedGroupCounts: [InstructionSubstitutionGroup: Int],
        appliedSubstitutions: [AppliedInstructionSubstitution]
    ) {
        self.scannedInstructionCount = scannedInstructionCount
        self.eligibleCandidateCount = eligibleCandidateCount
        self.appliedCount = appliedCount
        self.bytesModified = bytesModified
        self.replacementRate = replacementRate
        self.skippedDataInCodeRangeCount = skippedDataInCodeRangeCount
        self.appliedGroupCounts = appliedGroupCounts
        self.appliedSubstitutions = appliedSubstitutions
    }
}

public final class SubstitutionEngine {
    public struct Configuration {
        public let replacementRate: Double
        public let seed: UInt64

        public init(replacementRate: Double = 0.40, seed: UInt64) {
            self.replacementRate = min(max(replacementRate, 0), 1)
            self.seed = seed == 0 ? 1 : seed
        }
    }

    public init() {}

    public func substitute<R: RandomNumberGenerator>(
        for rawValue: UInt32,
        ratio: Double = 1.0,
        using rng: inout R
    ) -> UInt32? {
        let clampedRatio = min(max(ratio, 0), 1)
        guard clampedRatio > 0 else { return nil }
        guard let decoded = ARM64Codec.decode(rawValue) else { return nil }
        let replacementOptions = buildReplacementOptions(for: decoded)
        guard !replacementOptions.isEmpty else { return nil }

        if clampedRatio < 1 {
            let threshold = UInt64(Double(UInt64.max) * clampedRatio)
            guard rng.next() <= threshold else { return nil }
        }

        let optionIndex = Int(rng.next() % UInt64(replacementOptions.count))
        return replacementOptions[optionIndex].rawValue
    }

    public func apply(to file: MachOFile, configuration: Configuration) throws -> SubstitutionEngineReport {
        guard let textSection = try file.section(segment: "__TEXT", section: "__text") else {
            return SubstitutionEngineReport(
                scannedInstructionCount: 0,
                eligibleCandidateCount: 0,
                appliedCount: 0,
                bytesModified: 0,
                replacementRate: configuration.replacementRate,
                skippedDataInCodeRangeCount: 0,
                appliedGroupCounts: [:],
                appliedSubstitutions: []
            )
        }

        let textContent = try textSection.readContent(from: file.data)
        let scanBytes = textContent.count - (textContent.count % 4)
        let dataInCodeRanges = loadDataInCodeRanges(from: file, textSection: textSection)
        var candidates = [Candidate]()
        candidates.reserveCapacity(scanBytes / 8)

        guard textSection.offset <= UInt64(Int.max) else {
            throw MachOError.invalidData("Text section offset \(textSection.offset) exceeds addressable range")
        }
        let textBaseFileOffset = Int(textSection.offset)
        for byteOffset in stride(from: 0, to: scanBytes, by: 4) {
            let fileOffset = textBaseFileOffset + byteOffset
            if isMarkedAsData(fileOffset: fileOffset, ranges: dataInCodeRanges) {
                continue
            }

            let rawValue = try textContent.readUInt32LE(at: byteOffset)
            guard let decoded = ARM64Codec.decode(rawValue) else {
                continue
            }

            let replacementOptions = buildReplacementOptions(for: decoded)
            guard !replacementOptions.isEmpty else {
                continue
            }

            candidates.append(Candidate(
                fileOffset: UInt64(fileOffset),
                originalRawValue: rawValue,
                group: candidateGroup(for: decoded.kind),
                sourceDescription: currentFormDescription(for: decoded.kind),
                replacementOptions: replacementOptions
            ))
        }

        let targetCount = desiredReplacementCount(
            candidateCount: candidates.count,
            replacementRate: configuration.replacementRate
        )
        guard targetCount > 0 else {
            return SubstitutionEngineReport(
                scannedInstructionCount: scanBytes / 4,
                eligibleCandidateCount: candidates.count,
                appliedCount: 0,
                bytesModified: 0,
                replacementRate: configuration.replacementRate,
                skippedDataInCodeRangeCount: dataInCodeRanges.count,
                appliedGroupCounts: [:],
                appliedSubstitutions: []
            )
        }

        var rng = SplitMix64(seed: configuration.seed)
        candidates.shuffle(using: &rng)

        let selected = Array(candidates.prefix(targetCount)).sorted { lhs, rhs in
            lhs.fileOffset < rhs.fileOffset
        }

        var appliedGroupCounts = [InstructionSubstitutionGroup: Int]()
        var appliedSubstitutions = [AppliedInstructionSubstitution]()
        appliedSubstitutions.reserveCapacity(selected.count)

        for candidate in selected {
            let optionIndex = Int(rng.next() % UInt64(candidate.replacementOptions.count))
            let chosen = candidate.replacementOptions[optionIndex]
            try file.replaceBytes(at: candidate.fileOffset, with: ARM64Codec.data(for: chosen.rawValue))

            appliedGroupCounts[candidate.group, default: 0] += 1
            appliedSubstitutions.append(AppliedInstructionSubstitution(
                fileOffset: candidate.fileOffset,
                originalRawValue: candidate.originalRawValue,
                replacementRawValue: chosen.rawValue,
                group: candidate.group,
                description: "\(candidate.sourceDescription) -> \(chosen.description)"
            ))
        }

        return SubstitutionEngineReport(
            scannedInstructionCount: scanBytes / 4,
            eligibleCandidateCount: candidates.count,
            appliedCount: appliedSubstitutions.count,
            bytesModified: appliedSubstitutions.count * 4,
            replacementRate: configuration.replacementRate,
            skippedDataInCodeRangeCount: dataInCodeRanges.count,
            appliedGroupCounts: appliedGroupCounts,
            appliedSubstitutions: appliedSubstitutions
        )
    }

    private func buildReplacementOptions(for decoded: ARM64DecodedInstruction) -> [ReplacementOption] {
        let options: [ReplacementOption]

        switch decoded.kind {
        case .registerCopy(let copy):
            // In ADD/SUB immediate, register 31 encodes SP (not XZR).
            // Only offer ADD/SUB alternatives when neither operand is register 31,
            // to avoid accidentally reading SP or writing SP.
            let canUseAddSub = copy.sourceRegister != ARM64RegisterWidth.zeroRegisterIndex
                && copy.destinationRegister != ARM64RegisterWidth.zeroRegisterIndex

            var copyOptions = [
                ReplacementOption(
                    rawValue: ARM64Codec.encodeMoveAlias(
                        destinationRegister: copy.destinationRegister,
                        sourceRegister: copy.sourceRegister,
                        width: copy.width
                    ),
                    description: ARM64RegisterCopyForm.movAlias.description
                ),
                ReplacementOption(
                    rawValue: ARM64Codec.encodeAndSelf(
                        destinationRegister: copy.destinationRegister,
                        sourceRegister: copy.sourceRegister,
                        width: copy.width
                    ),
                    description: ARM64RegisterCopyForm.andSelf.description
                ),
                ReplacementOption(
                    rawValue: ARM64Codec.encodeOrrSelf(
                        destinationRegister: copy.destinationRegister,
                        sourceRegister: copy.sourceRegister,
                        width: copy.width
                    ),
                    description: ARM64RegisterCopyForm.orrSelf.description
                ),
            ]

            if canUseAddSub {
                copyOptions.append(contentsOf: [
                    ReplacementOption(
                        rawValue: ARM64Codec.encodeAddImmediateZero(
                            destinationRegister: copy.destinationRegister,
                            sourceRegister: copy.sourceRegister,
                            width: copy.width
                        ),
                        description: ARM64RegisterCopyForm.addZero.description
                    ),
                    ReplacementOption(
                        rawValue: ARM64Codec.encodeSubImmediateZero(
                            destinationRegister: copy.destinationRegister,
                            sourceRegister: copy.sourceRegister,
                            width: copy.width
                        ),
                        description: ARM64RegisterCopyForm.subZero.description
                    ),
                ])
            }

            options = orderedUniqueOptions(excluding: decoded.rawValue, options: copyOptions)

        case .noEffect(let noEffect):
            let width = noEffect.width
            let source = noEffect.sourceRegister ?? ARM64RegisterWidth.zeroRegisterIndex
            var candidates = [ReplacementOption]()
            candidates.reserveCapacity(4)

            if source == ARM64RegisterWidth.zeroRegisterIndex {
                candidates.append(ReplacementOption(
                    rawValue: ARM64Codec.encodeNOP(),
                    description: ARM64NoEffectForm.nop.description
                ))
            }

            // No-effect destination is always register 31 (XZR in logical
            // context). ADD/SUB immediate treats register 31 as SP, so
            // generating ADD/SUB XZR replacements would corrupt the stack
            // pointer.  Only use logical-register forms here.
            candidates.append(contentsOf: [
                ReplacementOption(
                    rawValue: ARM64Codec.encodeMoveAlias(
                        destinationRegister: ARM64RegisterWidth.zeroRegisterIndex,
                        sourceRegister: source,
                        width: width
                    ),
                    description: ARM64NoEffectForm.discardViaMove.description
                ),
                ReplacementOption(
                    rawValue: ARM64Codec.encodeAndSelf(
                        destinationRegister: ARM64RegisterWidth.zeroRegisterIndex,
                        sourceRegister: source,
                        width: width
                    ),
                    description: ARM64NoEffectForm.discardViaAndSelf.description
                ),
                ReplacementOption(
                    rawValue: ARM64Codec.encodeOrrSelf(
                        destinationRegister: ARM64RegisterWidth.zeroRegisterIndex,
                        sourceRegister: source,
                        width: width
                    ),
                    description: ARM64NoEffectForm.discardViaOrrSelf.description
                ),
            ])

            options = orderedUniqueOptions(excluding: decoded.rawValue, options: candidates)

        case .immediateLoad(let load):
            guard load.immediate <= UInt64(UInt16.max) else {
                return []
            }

            var candidates = [ReplacementOption(
                rawValue: ARM64Codec.encodeMoveWideImmediate(
                    destinationRegister: load.destinationRegister,
                    immediate: UInt16(load.immediate),
                    width: load.width
                ),
                description: ARM64ImmediateLoadForm.movzZeroShift.description
            )]

            if let orrRawValue = ARM64Codec.encodeORRLogicalImmediate(
                destinationRegister: load.destinationRegister,
                immediate: load.immediate,
                width: load.width
            ) {
                candidates.append(ReplacementOption(
                    rawValue: orrRawValue,
                    description: ARM64ImmediateLoadForm
                        .orrLogicalImmediate(ARM64BitmaskImmediateEncoding(n: 0, immr: 0, imms: 0))
                        .description
                ))
            }

            options = orderedUniqueOptions(excluding: decoded.rawValue, options: candidates)
        }

        return options
    }

    private func currentFormDescription(for kind: ARM64InstructionKind) -> String {
        switch kind {
        case .registerCopy(let copy):
            return copy.form.description
        case .noEffect(let noEffect):
            return noEffect.form.description
        case .immediateLoad(let load):
            return load.form.description
        }
    }

    private func candidateGroup(for kind: ARM64InstructionKind) -> InstructionSubstitutionGroup {
        switch kind {
        case .registerCopy(let copy):
            switch copy.form {
            case .movAlias:
                return .groupA
            case .addZero, .subZero:
                return .groupB
            case .andSelf, .orrSelf:
                return .groupC
            }
        case .noEffect:
            return .groupD
        case .immediateLoad:
            return .groupE
        }
    }

    private func orderedUniqueOptions(
        excluding originalRawValue: UInt32,
        options: [ReplacementOption]
    ) -> [ReplacementOption] {
        var seen = Set<UInt32>()
        var unique = [ReplacementOption]()
        unique.reserveCapacity(options.count)

        for option in options where option.rawValue != originalRawValue {
            if seen.insert(option.rawValue).inserted {
                unique.append(option)
            }
        }
        return unique
    }

    private func desiredReplacementCount(candidateCount: Int, replacementRate: Double) -> Int {
        guard candidateCount > 0, replacementRate > 0 else { return 0 }
        if replacementRate >= 1 { return candidateCount }

        let scaled = Int(Double(candidateCount) * replacementRate)
        return min(candidateCount, max(1, scaled))
    }

    private func loadDataInCodeRanges(from file: MachOFile, textSection: Section) -> [DataInCodeRange] {
        guard textSection.size <= UInt64(Int.max) else { return [] }

        let textStart = Int(textSection.offset)
        let textEnd = textStart + Int(textSection.size)
        var ranges = [DataInCodeRange]()

        for command in file.loadCommands where command.cmd == LoadCommand.LC_DATA_IN_CODE {
            guard command.rawData.count >= 16 else { continue }
            guard let dataOffset = try? command.rawData.readUInt32LE(at: 8),
                  let dataSize = try? command.rawData.readUInt32LE(at: 12) else {
                continue
            }

            let blobOffset = Int(dataOffset)
            let blobSize = Int(dataSize)
            guard blobOffset >= 0,
                  blobSize >= 0,
                  blobOffset + blobSize <= file.data.count else {
                continue
            }

            let blob = file.data.subdata(in: blobOffset..<(blobOffset + blobSize))
            let entryCount = blob.count / 8
            for entryIndex in 0..<entryCount {
                let entryOffset = entryIndex * 8
                guard let rawOffset = try? blob.readUInt32LE(at: entryOffset),
                      let rawLength = try? blob.readUInt16LE(at: entryOffset + 4) else {
                    continue
                }
                let fileStart = Int(rawOffset)
                let fileEnd = fileStart + Int(rawLength)
                guard rawLength > 0, fileStart < textEnd, fileEnd > textStart else {
                    continue
                }
                ranges.append(DataInCodeRange(
                    start: max(fileStart, textStart),
                    end: min(fileEnd, textEnd)
                ))
            }
        }

        return merge(ranges: ranges)
    }

    private func isMarkedAsData(fileOffset: Int, ranges: [DataInCodeRange]) -> Bool {
        for range in ranges where fileOffset >= range.start && fileOffset < range.end {
            return true
        }
        return false
    }

    private func merge(ranges: [DataInCodeRange]) -> [DataInCodeRange] {
        let sorted = ranges.sorted { lhs, rhs in
            if lhs.start != rhs.start {
                return lhs.start < rhs.start
            }
            return lhs.end < rhs.end
        }
        guard var current = sorted.first else { return [] }

        var merged = [DataInCodeRange]()
        for range in sorted.dropFirst() {
            if range.start <= current.end {
                current = DataInCodeRange(start: current.start, end: max(current.end, range.end))
            } else {
                merged.append(current)
                current = range
            }
        }
        merged.append(current)
        return merged
    }
}

private struct Candidate {
    let fileOffset: UInt64
    let originalRawValue: UInt32
    let group: InstructionSubstitutionGroup
    let sourceDescription: String
    let replacementOptions: [ReplacementOption]
}

private struct ReplacementOption {
    let rawValue: UInt32
    let description: String
}

private struct DataInCodeRange {
    let start: Int
    let end: Int
}

public struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64

    public init(seed: UInt64) {
        state = seed == 0 ? 1 : seed
    }

    public mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

private extension Data {
    func readUInt16LE(at offset: Int) throws -> UInt16 {
        guard offset >= 0, offset + 2 <= count else {
            throw MachOError.outOfBoundsRead(offset: offset, size: 2, dataSize: count)
        }
        let bytes = [UInt8](self[offset..<(offset + 2)])
        return UInt16(bytes[0]) | (UInt16(bytes[1]) << 8)
    }

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
