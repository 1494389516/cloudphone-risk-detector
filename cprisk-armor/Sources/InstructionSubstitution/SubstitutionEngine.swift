import Foundation
import MachOKit

public enum InstructionSubstitutionGroup: String, CaseIterable, Hashable {
    case groupA
    case groupB
    case groupC
    case groupD
    case groupE
    case groupF
    case groupG
    case groupH
    case groupI
    case groupJ
    case groupK

    var summaryLabel: String {
        switch self {
        case .groupA: return "Group A"
        case .groupB: return "Group B"
        case .groupC: return "Group C"
        case .groupD: return "Group D"
        case .groupE: return "Group E"
        case .groupF: return "Group F"
        case .groupG: return "Group G"
        case .groupH: return "Group H"
        case .groupI: return "Group I"
        case .groupJ: return "Group J"
        case .groupK: return "Group K"
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
            return "MOVZ / ORR logical immediate (const-unfold)"
        case .groupF:
            return "CSEL/CSINC compare-select patterns"
        case .groupG:
            return "CBZ/CBNZ/B.cond compare-and-branch"
        case .groupH:
            return "ADD/SUB/EOR/BIC shifted register"
        case .groupI:
            return "MADD/MSUB/MUL multiply-accumulate"
        case .groupJ:
            return "LDR literal / ADRP+ADD"
        case .groupK:
            return "8-byte branch veneers (SUBS + B.cond)"
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

        var textContent = try textSection.readContent(from: file.data)
        let scanBytes = textContent.count - (textContent.count % 4)
        let dataInCodeRanges = loadDataInCodeRanges(from: file, textSection: textSection)
        guard textSection.offset <= UInt64(Int.max) else {
            throw MachOError.invalidData("Text section offset \(textSection.offset) exceeds addressable range")
        }
        let textBaseFileOffset = Int(textSection.offset)

        var rng = SplitMix64(seed: configuration.seed)
        var veneerSubstitutions = [AppliedInstructionSubstitution]()
        var veneerBytes = 0
        var veneerMutated = Set<UInt64>()
        let veneerOutcome = try applyCompareBranchVeneers(
            to: file,
            textBaseFileOffset: textBaseFileOffset,
            scanBytes: scanBytes,
            dataInCodeRanges: dataInCodeRanges,
            configuration: configuration,
            rng: &rng
        )
        veneerSubstitutions = veneerOutcome.substitutions
        veneerBytes = veneerOutcome.bytesModified
        veneerMutated = veneerOutcome.mutatedOffsets
        if veneerBytes > 0 {
            textContent = try textSection.readContent(from: file.data)
        }

        var candidates = [Candidate]()
        var noEffectCandidates = [NoEffectCandidate]()
        candidates.reserveCapacity(scanBytes / 8)
        noEffectCandidates.reserveCapacity(scanBytes / 12)

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

        let selected: [Candidate]
        if targetCount > 0 {
            candidates.shuffle(using: &rng)
            selected = Array(candidates.prefix(targetCount)).sorted { lhs, rhs in
                lhs.fileOffset < rhs.fileOffset
            }
        } else {
            selected = []
        }

        let selectedForMain = selected.filter { !veneerMutated.contains($0.fileOffset) }

        var appliedGroupCounts = [InstructionSubstitutionGroup: Int]()
        if !veneerSubstitutions.isEmpty {
            appliedGroupCounts[.groupK] = veneerSubstitutions.count
        }
        var appliedSubstitutions = veneerSubstitutions
        appliedSubstitutions.reserveCapacity(veneerSubstitutions.count + selectedForMain.count)
        var injectedOpaquePredicates = [AppliedOpaquePredicateInjection]()
        var injectedDeadCodeIslands = [AppliedDeadCodeIsland]()
        var mutatedOffsets = veneerMutated
        mutatedOffsets.reserveCapacity(veneerMutated.count + selectedForMain.count * 3)
        var bytesModified = veneerBytes

        for candidate in selectedForMain {
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

        // Dead-code islands: blend classic 2-word bait with longer __text mimic blocks so
        // disassemblers / LLMs see fake helper routines inside real code pages.
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
            var usedIslandOffsets = Set<UInt64>()
            let textMimicCandidates = buildTextMimicIslandCandidates(
                from: remainingNoEffect,
                textEndFileOffset: textEndFileOffset,
                dataInCodeRanges: dataInCodeRanges
            )
            let textMimicTarget = textMimicCandidates.isEmpty ? 0 : min(textMimicCandidates.count, max(1, islandTarget / 2))

            if textMimicTarget > 0 {
                var shuffledMimics = textMimicCandidates
                shuffledMimics.shuffle(using: &rng)

                for candidate in shuffledMimics {
                    guard injectedDeadCodeIslands.count < textMimicTarget else { break }
                    let branchOffset = candidate.branchSlot.fileOffset
                    let deadOffsets = candidate.deadSlots.map(\.fileOffset)
                    guard !mutatedOffsets.contains(branchOffset),
                          !usedIslandOffsets.contains(branchOffset),
                          deadOffsets.allSatisfy({ !mutatedOffsets.contains($0) && !usedIslandOffsets.contains($0) }) else {
                        continue
                    }

                    let branchReplacement = encodeCompareAndBranchZero(
                        branchIfZero: true,
                        immediateWords: candidate.template.instructions.count + 1
                    )
                    if branchReplacement != candidate.branchSlot.originalRawValue {
                        try file.replaceBytes(at: branchOffset, with: ARM64Codec.data(for: branchReplacement))
                        bytesModified += 4
                    }
                    mutatedOffsets.insert(branchOffset)
                    usedIslandOffsets.insert(branchOffset)

                    for (slot, replacementRawValue) in zip(candidate.deadSlots, candidate.template.instructions) {
                        if replacementRawValue != slot.originalRawValue {
                            try file.replaceBytes(at: slot.fileOffset, with: ARM64Codec.data(for: replacementRawValue))
                            bytesModified += 4
                        }
                        mutatedOffsets.insert(slot.fileOffset)
                        usedIslandOffsets.insert(slot.fileOffset)
                    }

                    injectedDeadCodeIslands.append(AppliedDeadCodeIsland(
                        branchFileOffset: branchOffset,
                        deadInstructionFileOffset: candidate.deadSlots[0].fileOffset,
                        originalBranchRawValue: candidate.branchSlot.originalRawValue,
                        originalDeadRawValue: candidate.deadSlots[0].originalRawValue,
                        replacementBranchRawValue: branchReplacement,
                        replacementDeadRawValue: candidate.template.instructions[0],
                        description: candidate.template.description
                    ))
                }
            }

            islandCandidates.shuffle(using: &rng)
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
                ReplacementOption(
                    rawValue: ARM64Codec.encodeLogicalShiftedRegister(
                        destination: copy.destinationRegister,
                        source1: copy.sourceRegister,
                        source2: ARM64RegisterWidth.zeroRegisterIndex,
                        shiftType: 0,
                        shiftAmount: 0,
                        opc: 2,
                        width: copy.width
                    ),
                    description: "EOR with XZR (arith-equivalent copy)"
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
                ReplacementOption(
                    rawValue: ARM64Codec.encodeLogicalShiftedRegister(
                        destination: ARM64RegisterWidth.zeroRegisterIndex,
                        source1: source,
                        source2: ARM64RegisterWidth.zeroRegisterIndex,
                        shiftType: 0,
                        shiftAmount: 0,
                        opc: 2,
                        width: width
                    ),
                    description: "discard via EOR with XZR"
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

            let orrVariants = ARM64Codec.encodeORRLogicalImmediateVariants(
                destinationRegister: load.destinationRegister,
                immediate: load.immediate,
                width: load.width
            )
            if !orrVariants.isEmpty {
                for (idx, variantRawValue) in orrVariants.enumerated() {
                    candidates.append(ReplacementOption(
                        rawValue: variantRawValue,
                        description: idx == 0
                            ? ARM64ImmediateLoadForm
                                .orrLogicalImmediate(ARM64BitmaskImmediateEncoding(n: 0, immr: 0, imms: 0))
                                .description
                            : "ORR logical immediate alt#\(idx + 1)"
                    ))
                }
            }

            options = orderedUniqueOptions(excluding: decoded.rawValue, options: candidates)

        case .conditionalBranch:
            // CSEL/CSINC patterns are flag/data-flow sensitive; CBZ/CBNZ are classified as `compareBranch`.
            options = []

        case .compareBranch:
            // CBZ/CBNZ/B.cond single-word polymorphism is unsafe without context; 8-byte SUBS + B.cond veneers
            // are applied separately in `applyCompareBranchVeneers` (Group K).
            options = []

        case .logicalShifted(let ls):
            var candidates = [ReplacementOption]()

            let isEquivalentCopyCandidate =
                ls.sourceRegister2 == ARM64RegisterWidth.zeroRegisterIndex
                && ls.shiftType == 0
                && ls.shiftAmount == 0

            if isEquivalentCopyCandidate {
                candidates.append(contentsOf: [
                    ReplacementOption(
                        rawValue: ARM64Codec.encodeAddShiftedRegister(
                            destination: ls.destinationRegister,
                            source1: ls.sourceRegister1,
                            source2: ls.sourceRegister2,
                            shiftType: ls.shiftType,
                            shiftAmount: ls.shiftAmount,
                            width: ls.width
                        ),
                        description: "ADD shifted zero (arith-equivalent)"
                    ),
                    ReplacementOption(
                        rawValue: ARM64Codec.encodeSubShiftedRegister(
                            destination: ls.destinationRegister,
                            source1: ls.sourceRegister1,
                            source2: ls.sourceRegister2,
                            shiftType: ls.shiftType,
                            shiftAmount: ls.shiftAmount,
                            width: ls.width
                        ),
                        description: "SUB shifted zero (arith-equivalent)"
                    ),
                    ReplacementOption(
                        rawValue: ARM64Codec.encodeLogicalShiftedRegister(
                            destination: ls.destinationRegister,
                            source1: ls.sourceRegister1,
                            source2: ls.sourceRegister2,
                            shiftType: ls.shiftType,
                            shiftAmount: ls.shiftAmount,
                            opc: 2,
                            width: ls.width
                        ),
                        description: "EOR shifted zero (arith-equivalent)"
                    ),
                    ReplacementOption(
                        rawValue: ARM64Codec.encodeLogicalShiftedRegister(
                            destination: ls.destinationRegister,
                            source1: ls.sourceRegister1,
                            source2: ls.sourceRegister2,
                            shiftType: ls.shiftType,
                            shiftAmount: ls.shiftAmount,
                            opc: 3,
                            width: ls.width
                        ),
                        description: "BIC shifted zero (arith-equivalent)"
                    ),
                ])
            }

            options = orderedUniqueOptions(excluding: decoded.rawValue, options: candidates)

        case .multiplyAccumulate(let ma):
            var candidates = [ReplacementOption]()

            switch ma.form {
            case .madd:
                if ma.accumulator == ARM64RegisterWidth.zeroRegisterIndex {
                    candidates.append(ReplacementOption(
                        rawValue: ARM64Codec.encodeMSUB(
                            destination: ma.destinationRegister,
                            multiplicand: ma.multiplicand,
                            multiplier: ma.multiplier,
                            accumulator: ma.accumulator
                        ),
                        description: "MSUB with XZR acc (arith-equivalent MUL)"
                    ))
                    candidates.append(ReplacementOption(
                        rawValue: ARM64Codec.encodeMADD(
                            destination: ma.destinationRegister,
                            multiplicand: ma.multiplicand,
                            multiplier: ma.multiplier,
                            accumulator: ARM64RegisterWidth.zeroRegisterIndex
                        ),
                        description: ARM64MultiplyAccumulateForm.mul.description
                    ))
                }
            case .msub:
                if ma.accumulator == ARM64RegisterWidth.zeroRegisterIndex {
                    candidates.append(ReplacementOption(
                        rawValue: ARM64Codec.encodeMADD(
                            destination: ma.destinationRegister,
                            multiplicand: ma.multiplicand,
                            multiplier: ma.multiplier,
                            accumulator: ma.accumulator
                        ),
                        description: "MADD with XZR acc (arith-equivalent MUL)"
                    ))
                }
            case .mul:
                // MUL -> MADD with XZR accumulator
                candidates.append(ReplacementOption(
                    rawValue: ARM64Codec.encodeMADD(
                        destination: ma.destinationRegister,
                        multiplicand: ma.multiplicand,
                        multiplier: ma.multiplier,
                        accumulator: ARM64RegisterWidth.zeroRegisterIndex
                    ),
                    description: ARM64MultiplyAccumulateForm.madd.description
                ))
            }

            options = orderedUniqueOptions(excluding: decoded.rawValue, options: candidates)

        case .loadLiteral(let ll):
            var candidates = [ReplacementOption]()

            // LDR literal can be kept but represented differently
            candidates.append(ReplacementOption(
                rawValue: ARM64Codec.encodeLoadLiteral(
                    destinationRegister: ll.destinationRegister,
                    immediate: ll.immediate,
                    width: ll.width
                ),
                description: ARM64LoadLiteralForm.ldrLiteral.description
            ))

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
        case .conditionalBranch(let cb):
            return cb.form.description
        case .compareBranch(let cb):
            return cb.form.description
        case .logicalShifted(let ls):
            return ls.form.description
        case .multiplyAccumulate(let ma):
            return ma.form.description
        case .loadLiteral(let ll):
            return ll.form.description
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
        case .conditionalBranch:
            return .groupF
        case .compareBranch:
            return .groupG
        case .logicalShifted:
            return .groupH
        case .multiplyAccumulate:
            return .groupI
        case .loadLiteral:
            return .groupJ
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

    /// 8-byte template: `SUBS XZR/WZR, Rt, Rt` + `B.EQ/B.NE +4` replaces `CBZ/CBNZ, +8` + `NOP` + `NOP`
    /// with identical control-flow semantics (flags from SUBS match the zero / non-zero test).
    private func applyCompareBranchVeneers(
        to file: MachOFile,
        textBaseFileOffset: Int,
        scanBytes: Int,
        dataInCodeRanges: [DataInCodeRange],
        configuration: Configuration,
        rng: inout SplitMix64
    ) throws -> (substitutions: [AppliedInstructionSubstitution], bytesModified: Int, mutatedOffsets: Set<UInt64>) {
        var pool = [UInt64]()
        let textEnd = textBaseFileOffset + scanBytes
        for byteOffset in stride(from: 0, to: scanBytes - 8, by: 4) {
            let i0 = textBaseFileOffset + byteOffset
            let i1 = i0 + 4
            let i2 = i0 + 8
            if i2 >= textEnd { continue }
            if isMarkedAsData(fileOffset: i0, ranges: dataInCodeRanges) { continue }
            if isMarkedAsData(fileOffset: i1, ranges: dataInCodeRanges) { continue }
            if isMarkedAsData(fileOffset: i2, ranges: dataInCodeRanges) { continue }

            guard let head = try? file.data.readUInt32LE(at: i0),
                  let tail = try? file.data.readUInt32LE(at: i1),
                  let tail2 = try? file.data.readUInt32LE(at: i2) else { continue }

            guard let decoded = ARM64Codec.decode(head),
                  case .compareBranch(let cb) = decoded.kind else { continue }
            guard cb.immediate == 8 else { continue }
            guard tail == ARM64Codec.nopRawValue, tail2 == ARM64Codec.nopRawValue else { continue }

            switch cb.form {
            case .cbz, .cbnz:
                pool.append(UInt64(i0))
            default:
                continue
            }
        }

        let target = desiredReplacementCount(candidateCount: pool.count, replacementRate: configuration.replacementRate)
        guard target > 0, !pool.isEmpty else {
            return ([], 0, [])
        }

        pool.shuffle(using: &rng)
        let chosen = Array(pool.prefix(target)).sorted()

        var substitutions = [AppliedInstructionSubstitution]()
        var mutated = Set<UInt64>()
        var bytes = 0
        var occupied = Set<Int>()

        for fileOffsetU in chosen {
            let i0 = Int(fileOffsetU)
            let range = stride(from: i0, to: i0 + 8, by: 4)
            if range.contains(where: { occupied.contains($0) }) {
                continue
            }

            guard let head = try? file.data.readUInt32LE(at: i0) else { continue }
            guard let decoded = ARM64Codec.decode(head),
                  case .compareBranch(let cb) = decoded.kind else { continue }
            guard cb.immediate == 8 else { continue }

            let width: ARM64RegisterWidth = ((head >> 31) & 1) == 1 ? .x64 : .w32
            let cond: UInt32
            switch cb.form {
            case .cbz:
                cond = 0 // EQ / matches CBZ zero test
            case .cbnz:
                cond = 1 // NE / matches CBNZ non-zero test
            default:
                continue
            }

            let subs = ARM64Codec.encodeSUBSShiftedRegister(
                destination: ARM64RegisterWidth.zeroRegisterIndex,
                source1: cb.register,
                source2: cb.register,
                width: width
            )
            let bcond = ARM64Codec.encodeBCond(conditionCode: cond, immediateBytes: 4)

            try file.replaceBytes(at: UInt64(i0), with: ARM64Codec.data(for: subs))
            try file.replaceBytes(at: UInt64(i0 + 4), with: ARM64Codec.data(for: bcond))

            bytes += 8
            for o in range {
                occupied.insert(o)
                mutated.insert(UInt64(o))
            }

            substitutions.append(AppliedInstructionSubstitution(
                fileOffset: UInt64(i0),
                originalRawValue: head,
                replacementRawValue: subs,
                group: .groupK,
                description: "compare-branch + NOP x2 -> SUBS + B.cond veneer (second insn at +0x4)"
            ))
        }

        return (substitutions, bytes, mutated)
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

    private func buildTextMimicIslandCandidates(
        from candidates: [NoEffectCandidate],
        textEndFileOffset: Int,
        dataInCodeRanges: [DataInCodeRange]
    ) -> [TextMimicIslandCandidate] {
        guard !candidates.isEmpty else { return [] }

        let templates = TextMimicTemplate.allCases
        var result = [TextMimicIslandCandidate]()
        result.reserveCapacity(max(1, candidates.count / 3))

        for startIndex in candidates.indices {
            let branchSlot = candidates[startIndex]
            for template in templates {
                let deadCount = template.instructions.count
                guard deadCount > 0 else { continue }
                guard startIndex + deadCount < candidates.count else { continue }

                var deadSlots = [NoEffectCandidate]()
                deadSlots.reserveCapacity(deadCount)
                var contiguous = true
                for delta in 1...deadCount {
                    let slot = candidates[startIndex + delta]
                    guard slot.fileOffset == branchSlot.fileOffset + UInt64(delta * 4) else {
                        contiguous = false
                        break
                    }
                    deadSlots.append(slot)
                }
                guard contiguous else { continue }

                let branchTarget = Int(branchSlot.fileOffset) + ((deadCount + 1) * 4)
                guard branchTarget < textEndFileOffset else { continue }
                guard !isMarkedAsData(fileOffset: branchTarget, ranges: dataInCodeRanges) else { continue }

                result.append(TextMimicIslandCandidate(
                    branchSlot: branchSlot,
                    deadSlots: deadSlots,
                    template: template
                ))
            }
        }

        return result
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

private struct TextMimicIslandCandidate {
    let branchSlot: NoEffectCandidate
    let deadSlots: [NoEffectCandidate]
    let template: TextMimicTemplate
}

private enum TextMimicTemplate: CaseIterable {
    case jailbreakProbe
    case compareStub
    case frameCallStub
    case megamorphicDataflow
    case deepCallChain
    case vtableDispatch

    var instructions: [UInt32] {
        switch self {
        case .jailbreakProbe:
            return [
                0x9000_0000, // ADRP X0, #0
                ARM64Codec.encodeAddImmediateZero(
                    destinationRegister: 0,
                    sourceRegister: 0,
                    width: .x64
                ),
                0x9400_0000, // BL +0
                0x7100_001F, // CMP W0, #0
                ARM64Codec.encodeBCond(conditionCode: 0, immediateBytes: 8), // B.EQ +8
            ]
        case .compareStub:
            return [
                ARM64Codec.encodeMoveAlias(destinationRegister: 8, sourceRegister: 0, width: .x64),
                ARM64Codec.encodeMoveAlias(destinationRegister: 9, sourceRegister: 1, width: .x64),
                ARM64Codec.encodeSUBSShiftedRegister(
                    destination: ARM64RegisterWidth.zeroRegisterIndex,
                    source1: 8,
                    source2: 9,
                    width: .x64
                ),
                ARM64Codec.encodeBCond(conditionCode: 1, immediateBytes: 8), // B.NE +8
                0xD65F_03C0, // RET
            ]
        case .frameCallStub:
            return [
                0xA9BF_7BFD, // STP X29, X30, [SP,#-16]!
                0x9100_03FD, // MOV X29, SP
                0xD100_C3FF, // SUB SP, SP, #0x30
                0x9400_0000, // BL +0
                0xD65F_03C0, // RET
            ]
        case .megamorphicDataflow:
            return [
                0xCA0A_0128, // EOR  X8,  X9,  X10
                0x8B09_0D0B, // ADD  X11, X8,  X9,  LSL #3
                0xCB0A_1D6C, // SUB  X12, X11, X10
                0xCA0B_358D, // EOR  X13, X12, X11
                0x8B0C_15AE, // ADD  X14, X13, X12, LSL #5
                0xCB0D_01CF, // SUB  X15, X14, X13
                0xCA0E_01E8, // EOR  X8,  X15, X14
                0x8B0F_0109, // ADD  X9,  X8,  X15
                0xCB08_012A, // SUB  X10, X9,  X8
                0xCA09_014B, // EOR  X11, X10, X9
                0x8B0A_016C, // ADD  X12, X11, X10
                0xCB0B_018D, // SUB  X13, X12, X11
                0xCA0C_01AE, // EOR  X14, X13, X12
                0x8B0D_01CF, // ADD  X15, X14, X13
                0xCB0E_01E8, // SUB  X8,  X15, X14
                0xD65F_03C0, // RET (fake epilogue)
            ]
        case .deepCallChain:
            return [
                0xA9BF_7BFD, // STP  X29, X30, [SP, #-16]!
                0x9100_03FD, // MOV  X29, SP
                0xAA08_03E0, // MOV  X0,  X8
                0x9400_0000, // BL   +0
                0xAA00_03E8, // MOV  X8,  X0
                0xAA09_03E0, // MOV  X0,  X9
                0x9400_0000, // BL   +0
                0xEB00_011F, // CMP  X8,  X0
                0x5400_0041, // B.NE +8
                0xAA1F_03E0, // MOV  X0,  XZR
                0xA8C1_7BFD, // LDP  X29, X30, [SP], #16
                0xD65F_03C0, // RET
            ]
        case .vtableDispatch:
            return [
                0xF940_0008, // LDR  X8,  [X0]          (load vtable ptr)
                0xF940_0909, // LDR  X9,  [X8, #0x10]   (load method ptr)
                0xAA13_03E1, // MOV  X1,  X19
                0xAA14_03E2, // MOV  X2,  X20
                0xD63F_0120, // BLR  X9                  (call virtual method)
                0xF940_040A, // LDR  X10, [X0, #8]      (load 2nd vtable)
                0xF940_0D4B, // LDR  X11, [X10, #0x18]  (load 2nd method)
                0xAA15_03E1, // MOV  X1,  X21
                0xD63F_0160, // BLR  X11                 (call 2nd virtual method)
                0xD65F_03C0, // RET
            ]
        }
    }

    var description: String {
        switch self {
        case .jailbreakProbe:
            return "CBZ XZR text-mimic island + fake jailbreak probe (ADRP+ADD+BL+CMP+B.EQ)"
        case .compareStub:
            return "CBZ XZR text-mimic island + fake compare helper (MOV+MOV+SUBS+B.NE+RET)"
        case .frameCallStub:
            return "CBZ XZR text-mimic island + fake frame/call stub (STP+MOV+SUB+BL+RET)"
        case .megamorphicDataflow:
            return "CBZ XZR text-mimic island + megamorphic data-flow chain (16 EOR/ADD/SUB register dependency cascade)"
        case .deepCallChain:
            return "CBZ XZR text-mimic island + deep call chain with multiple BL (fake cross-refs for IDA call graph)"
        case .vtableDispatch:
            return "CBZ XZR text-mimic island + vtable dispatch mimic (LDR+BLR fake virtual calls)"
        }
    }
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
