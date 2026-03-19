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

public struct AppliedOpaquePredicateInjection: Equatable {
    public let fileOffset: UInt64
    public let originalRawValue: UInt32
    public let replacementRawValue: UInt32
    public let description: String

    public init(
        fileOffset: UInt64,
        originalRawValue: UInt32,
        replacementRawValue: UInt32,
        description: String
    ) {
        self.fileOffset = fileOffset
        self.originalRawValue = originalRawValue
        self.replacementRawValue = replacementRawValue
        self.description = description
    }
}

public struct AppliedDeadCodeIsland: Equatable {
    public let branchFileOffset: UInt64
    public let deadInstructionFileOffset: UInt64
    public let originalBranchRawValue: UInt32
    public let originalDeadRawValue: UInt32
    public let replacementBranchRawValue: UInt32
    public let replacementDeadRawValue: UInt32
    public let description: String

    public init(
        branchFileOffset: UInt64,
        deadInstructionFileOffset: UInt64,
        originalBranchRawValue: UInt32,
        originalDeadRawValue: UInt32,
        replacementBranchRawValue: UInt32,
        replacementDeadRawValue: UInt32,
        description: String
    ) {
        self.branchFileOffset = branchFileOffset
        self.deadInstructionFileOffset = deadInstructionFileOffset
        self.originalBranchRawValue = originalBranchRawValue
        self.originalDeadRawValue = originalDeadRawValue
        self.replacementBranchRawValue = replacementBranchRawValue
        self.replacementDeadRawValue = replacementDeadRawValue
        self.description = description
    }
}

public struct SubstitutionEngineReport {
    public let scannedInstructionCount: Int
    public let eligibleCandidateCount: Int
    public let appliedCount: Int
    public let bytesModified: Int
    public let replacementRate: Double
    public let opaquePredicateRate: Double
    public let deadCodeIslandRate: Double
    public let skippedDataInCodeRangeCount: Int
    public let appliedGroupCounts: [InstructionSubstitutionGroup: Int]
    public let appliedSubstitutions: [AppliedInstructionSubstitution]
    public let injectedOpaquePredicates: [AppliedOpaquePredicateInjection]
    public let injectedDeadCodeIslands: [AppliedDeadCodeIsland]

    public init(
        scannedInstructionCount: Int,
        eligibleCandidateCount: Int,
        appliedCount: Int,
        bytesModified: Int,
        replacementRate: Double,
        opaquePredicateRate: Double,
        deadCodeIslandRate: Double,
        skippedDataInCodeRangeCount: Int,
        appliedGroupCounts: [InstructionSubstitutionGroup: Int],
        appliedSubstitutions: [AppliedInstructionSubstitution],
        injectedOpaquePredicates: [AppliedOpaquePredicateInjection],
        injectedDeadCodeIslands: [AppliedDeadCodeIsland]
    ) {
        self.scannedInstructionCount = scannedInstructionCount
        self.eligibleCandidateCount = eligibleCandidateCount
        self.appliedCount = appliedCount
        self.bytesModified = bytesModified
        self.replacementRate = replacementRate
        self.opaquePredicateRate = opaquePredicateRate
        self.deadCodeIslandRate = deadCodeIslandRate
        self.skippedDataInCodeRangeCount = skippedDataInCodeRangeCount
        self.appliedGroupCounts = appliedGroupCounts
        self.appliedSubstitutions = appliedSubstitutions
        self.injectedOpaquePredicates = injectedOpaquePredicates
        self.injectedDeadCodeIslands = injectedDeadCodeIslands
    }
}

public final class SubstitutionEngine {
    public struct Configuration {
        public let replacementRate: Double
        public let opaquePredicateRate: Double
        public let deadCodeIslandRate: Double
        public let seed: UInt64

        public init(
            replacementRate: Double = 0.40,
            opaquePredicateRate: Double = 0.15,
            deadCodeIslandRate: Double = 0.08,
            seed: UInt64
        ) {
            self.replacementRate = min(max(replacementRate, 0), 1)
            self.opaquePredicateRate = min(max(opaquePredicateRate, 0), 1)
            self.deadCodeIslandRate = min(max(deadCodeIslandRate, 0), 1)
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
                opaquePredicateRate: configuration.opaquePredicateRate,
                deadCodeIslandRate: configuration.deadCodeIslandRate,
                skippedDataInCodeRangeCount: 0,
                appliedGroupCounts: [:],
                appliedSubstitutions: [],
                injectedOpaquePredicates: [],
                injectedDeadCodeIslands: []
            )
        }

        let textContent = try textSection.readContent(from: file.data)
        let scanBytes = textContent.count - (textContent.count % 4)
        let dataInCodeRanges = loadDataInCodeRanges(from: file, textSection: textSection)
        var candidates = [Candidate]()
        var noEffectCandidates = [NoEffectCandidate]()
        candidates.reserveCapacity(scanBytes / 8)
        noEffectCandidates.reserveCapacity(scanBytes / 12)

        let textBaseFileOffset = Int(textSection.offset)
        let textEndFileOffset = textBaseFileOffset + scanBytes
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

            if case .noEffect = decoded.kind {
                noEffectCandidates.append(NoEffectCandidate(
                    fileOffset: UInt64(fileOffset),
                    originalRawValue: rawValue
                ))
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

        var rng = SplitMix64(seed: configuration.seed)
        let selected: [Candidate]
        if targetCount > 0 {
            candidates.shuffle(using: &rng)
            selected = Array(candidates.prefix(targetCount)).sorted { lhs, rhs in
                lhs.fileOffset < rhs.fileOffset
            }
        } else {
            selected = []
        }

        var appliedGroupCounts = [InstructionSubstitutionGroup: Int]()
        var appliedSubstitutions = [AppliedInstructionSubstitution]()
        appliedSubstitutions.reserveCapacity(selected.count)
        var injectedOpaquePredicates = [AppliedOpaquePredicateInjection]()
        var injectedDeadCodeIslands = [AppliedDeadCodeIsland]()
        var mutatedOffsets = Set<UInt64>()
        mutatedOffsets.reserveCapacity(selected.count * 3)
        var bytesModified = 0

        for candidate in selected {
            let optionIndex = Int(rng.next() % UInt64(candidate.replacementOptions.count))
            let chosen = candidate.replacementOptions[optionIndex]
            if chosen.rawValue != candidate.originalRawValue {
                try file.replaceBytes(at: candidate.fileOffset, with: ARM64Codec.data(for: chosen.rawValue))
                bytesModified += 4
            }
            mutatedOffsets.insert(candidate.fileOffset)

            appliedGroupCounts[candidate.group, default: 0] += 1
            appliedSubstitutions.append(AppliedInstructionSubstitution(
                fileOffset: candidate.fileOffset,
                originalRawValue: candidate.originalRawValue,
                replacementRawValue: chosen.rawValue,
                group: candidate.group,
                description: "\(candidate.sourceDescription) -> \(chosen.description)"
            ))
        }

        // Dead-code islands: [CBZ XZR, +8] [dead op]. Branch always skips dead op.
        let remainingNoEffect = noEffectCandidates
            .filter { !mutatedOffsets.contains($0.fileOffset) }
            .sorted { $0.fileOffset < $1.fileOffset }
        var islandCandidates = [DeadCodeIslandCandidate]()
        islandCandidates.reserveCapacity(remainingNoEffect.count / 2)

        if remainingNoEffect.count >= 2 {
            for index in 0..<(remainingNoEffect.count - 1) {
                let branchSlot = remainingNoEffect[index]
                let deadSlot = remainingNoEffect[index + 1]
                guard deadSlot.fileOffset == branchSlot.fileOffset + 4 else { continue }
                let branchTarget = Int(branchSlot.fileOffset) + 8
                guard branchTarget < textEndFileOffset else { continue }
                guard !isMarkedAsData(fileOffset: branchTarget, ranges: dataInCodeRanges) else { continue }
                islandCandidates.append(DeadCodeIslandCandidate(branchSlot: branchSlot, deadSlot: deadSlot))
            }
        }

        let islandTarget = desiredReplacementCount(
            candidateCount: islandCandidates.count,
            replacementRate: configuration.deadCodeIslandRate
        )
        if islandTarget > 0 {
            islandCandidates.shuffle(using: &rng)
            var usedIslandOffsets = Set<UInt64>()
            let branchReplacement = encodeCompareAndBranchZero(
                branchIfZero: true,
                immediateWords: 2
            )

            for candidate in islandCandidates {
                guard injectedDeadCodeIslands.count < islandTarget else { break }
                let branchOffset = candidate.branchSlot.fileOffset
                let deadOffset = candidate.deadSlot.fileOffset
                guard !mutatedOffsets.contains(branchOffset),
                      !mutatedOffsets.contains(deadOffset),
                      !usedIslandOffsets.contains(branchOffset),
                      !usedIslandOffsets.contains(deadOffset) else {
                    continue
                }

                let deadReplacement = chooseDeadInstructionRawValue(
                    avoiding: candidate.deadSlot.originalRawValue,
                    using: &rng
                )

                if branchReplacement != candidate.branchSlot.originalRawValue {
                    try file.replaceBytes(at: branchOffset, with: ARM64Codec.data(for: branchReplacement))
                    bytesModified += 4
                }
                if deadReplacement != candidate.deadSlot.originalRawValue {
                    try file.replaceBytes(at: deadOffset, with: ARM64Codec.data(for: deadReplacement))
                    bytesModified += 4
                }

                mutatedOffsets.insert(branchOffset)
                mutatedOffsets.insert(deadOffset)
                usedIslandOffsets.insert(branchOffset)
                usedIslandOffsets.insert(deadOffset)
                injectedDeadCodeIslands.append(AppliedDeadCodeIsland(
                    branchFileOffset: branchOffset,
                    deadInstructionFileOffset: deadOffset,
                    originalBranchRawValue: candidate.branchSlot.originalRawValue,
                    originalDeadRawValue: candidate.deadSlot.originalRawValue,
                    replacementBranchRawValue: branchReplacement,
                    replacementDeadRawValue: deadReplacement,
                    description: "CBZ XZR, +8 island gate + unreachable dead op"
                ))
            }
        }

        // Opaque predicate injection: CBNZ XZR, +4 (branch target equals fallthrough).
        let opaqueEligible = noEffectCandidates
            .filter { !mutatedOffsets.contains($0.fileOffset) }
        let opaqueTarget = desiredReplacementCount(
            candidateCount: opaqueEligible.count,
            replacementRate: configuration.opaquePredicateRate
        )
        if opaqueTarget > 0 {
            var shuffledOpaque = opaqueEligible
            shuffledOpaque.shuffle(using: &rng)
            let opaqueReplacement = encodeCompareAndBranchZero(
                branchIfZero: false,
                immediateWords: 1
            )

            for candidate in shuffledOpaque.prefix(opaqueTarget) {
                if opaqueReplacement != candidate.originalRawValue {
                    try file.replaceBytes(at: candidate.fileOffset, with: ARM64Codec.data(for: opaqueReplacement))
                    bytesModified += 4
                }
                mutatedOffsets.insert(candidate.fileOffset)
                injectedOpaquePredicates.append(AppliedOpaquePredicateInjection(
                    fileOffset: candidate.fileOffset,
                    originalRawValue: candidate.originalRawValue,
                    replacementRawValue: opaqueReplacement,
                    description: "CBNZ XZR, +4 opaque predicate (same-target edge)"
                ))
            }
        }

        return SubstitutionEngineReport(
            scannedInstructionCount: scanBytes / 4,
            eligibleCandidateCount: candidates.count,
            appliedCount: appliedSubstitutions.count
                + injectedOpaquePredicates.count
                + injectedDeadCodeIslands.count,
            bytesModified: bytesModified,
            replacementRate: configuration.replacementRate,
            opaquePredicateRate: configuration.opaquePredicateRate,
            deadCodeIslandRate: configuration.deadCodeIslandRate,
            skippedDataInCodeRangeCount: dataInCodeRanges.count,
            appliedGroupCounts: appliedGroupCounts,
            appliedSubstitutions: appliedSubstitutions,
            injectedOpaquePredicates: injectedOpaquePredicates,
            injectedDeadCodeIslands: injectedDeadCodeIslands
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

    private func encodeCompareAndBranchZero(branchIfZero: Bool, immediateWords: Int) -> UInt32 {
        let clamped = max(min(immediateWords, 0x3FFFF), 0)
        let base: UInt32 = branchIfZero ? 0xB400_0000 : 0xB500_0000
        let imm19 = UInt32(clamped) & 0x7FFFF
        return base
            | (imm19 << 5)
            | ARM64RegisterWidth.zeroRegisterIndex
    }

    private func chooseDeadInstructionRawValue<R: RandomNumberGenerator>(
        avoiding originalRawValue: UInt32,
        using rng: inout R
    ) -> UInt32 {
        let options = [
            ARM64Codec.encodeMoveAlias(
                destinationRegister: ARM64RegisterWidth.zeroRegisterIndex,
                sourceRegister: ARM64RegisterWidth.zeroRegisterIndex,
                width: .x64
            ),
            ARM64Codec.encodeAndSelf(
                destinationRegister: ARM64RegisterWidth.zeroRegisterIndex,
                sourceRegister: ARM64RegisterWidth.zeroRegisterIndex,
                width: .x64
            ),
            ARM64Codec.encodeNOP(),
        ]
        var seen = Set<UInt32>()
        let uniqueOptions = options.filter { seen.insert($0).inserted }
        guard !uniqueOptions.isEmpty else { return ARM64Codec.encodeNOP() }
        let filtered = uniqueOptions.filter { $0 != originalRawValue }
        let pool = filtered.isEmpty ? uniqueOptions : filtered
        let index = Int(rng.next() % UInt64(pool.count))
        return pool[index]
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

private struct NoEffectCandidate {
    let fileOffset: UInt64
    let originalRawValue: UInt32
}

private struct DeadCodeIslandCandidate {
    let branchSlot: NoEffectCandidate
    let deadSlot: NoEffectCandidate
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
