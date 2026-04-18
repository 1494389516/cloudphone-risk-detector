import Foundation
import InstructionSubstitution
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
    /// Build seed forwarded to the heuristic fallback path when the binary is stripped.
    private let heuristicFallbackSeed: UInt64

    init(policy: FunctionCFFPolicy, plans: [OrchestratedFunctionPlan], heuristicFallbackSeed: UInt64 = 0) {
        self.policy = policy
        self.plansBySymbol = Dictionary(uniqueKeysWithValues: plans.map { ($0.symbol, $0) })
        self.symbolIndex = CFFPolicySymbolIndex(policy: policy)
        self.heuristicFallbackSeed = heuristicFallbackSeed
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
            // Stripped binary: no symbol table to match policy names against.
            // Fall back to ARM64 prologue heuristic scanning so Pass9 still
            // applies light-tier CFF mutations instead of silently no-op'ing.
            return applyHeuristic(
                to: file,
                textStart: textStart,
                textSize: textSize,
                textVMStart: textVMStart,
                textVMEnd: textVMEnd,
                verbose: verbose
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

        /// Every `__TEXT.__text` symbol entry VM address (including `never`-tier symbols omitted from
        /// `matchedCandidates`). Using only the managed-candidate chain for the last symbol wrongly
        /// extended the VM range to `textVMEnd`, swallowing following never-tier functions.
        let sortedTextSymbolEntries = Self.sortedTextSymbolEntryAddresses(
            symbols: symbols,
            textVMStart: textVMStart,
            textVMEnd: textVMEnd
        )

        var modified = [CFFModifiedFunctionRecord]()
        var skipped = [CFFSkippedFunctionRecord]()
        modified.reserveCapacity(matchedCandidates.count)
        skipped.reserveCapacity(matchedCandidates.count)

        for candidate in matchedCandidates {
            let functionVMEnd = Self.nextTextSymbolEntry(
                after: candidate.entryVMAddress,
                sortedEntries: sortedTextSymbolEntries,
                textVMEnd: textVMEnd
            )

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

    // MARK: - ARM64 Prologue Heuristic (stripped-binary fallback)

    /// ARM64 encoding mask/pattern for `STP x29, x30, [sp, #-N]!` (pre-indexed, N > 0).
    ///
    /// Bits 31–22: load/store pair, 64-bit, pre-index, store.
    /// Bit  21:    imm7 sign bit = 1 → negative offset (stack grows down).
    /// Bits 14–0:  fixed Rt2=x30, Rn=SP, Rt=x29.
    /// Bits 20–15: lower imm7 field — cleared in the mask (any valid frame size).
    private static let arm64StpX29X30PreindexMask:    UInt32 = 0xFFE0_7FFF
    private static let arm64StpX29X30PreindexPattern: UInt32 = 0xA9A0_7BFD

    /// Minimum distance between two heuristically detected function starts (bytes).
    private static let heuristicMinFunctionGap = 16
    /// Maximum number of functions detected via heuristic scan (guard against pathological binaries).
    private static let heuristicMaxFunctions = 256

    /// Build a light-tier `OrchestratedFunctionPlan` for a synthetic heuristic symbol.
    private func makeLightFallbackPlan(symbol: String) -> OrchestratedFunctionPlan {
        let seed = heuristicFallbackSeed == 0 ? 1 : heuristicFallbackSeed
        let stateEnc = StateEncodingPlan.recommended(
            for: symbol,
            tier: .light,
            options: policy.antiDeobfuscation,
            buildSeed: seed
        )
        let runtimeDep = RuntimeDependencyPlan.recommended(for: .light, options: policy.antiDeobfuscation)
        let antiDeobf = AntiDeobfuscationFunctionPlan.recommended(
            for: .light,
            options: policy.antiDeobfuscation,
            stateEncodingPlan: stateEnc,
            runtimeDependencyPlan: runtimeDep
        )
        return OrchestratedFunctionPlan(
            symbol: symbol,
            tier: .light,
            dispatcherStyle: DispatcherStyle.choose(for: symbol, tier: .light, enableMultiDispatcher: false),
            stateEncodingPlan: stateEnc,
            runtimeDependencyPlan: runtimeDep,
            antiDeobfuscationPlan: antiDeobf,
            notes: ["heuristic: ARM64 prologue scan (stripped binary — no symbol table)"]
        )
    }

    /// Scan `__TEXT.__text` for `STP x29, x30, [sp, #-N]!` prologues.
    /// Returns file-offset-sorted candidate structs ready for `rewriteFunction`.
    private func heuristicPrologueCandidates(
        file: MachOFile,
        textStart: Int,
        textSize: Int,
        textVMStart: UInt64,
        textVMEnd: UInt64
    ) -> [CFFManagedFunctionCandidate] {
        var candidates: [CFFManagedFunctionCandidate] = []
        var lastFileOffset = -Self.heuristicMinFunctionGap

        let slotCount = textSize / 4
        for slotIndex in 0..<slotCount {
            guard candidates.count < Self.heuristicMaxFunctions else { break }

            let fileOffset = textStart + slotIndex * 4
            guard fileOffset - lastFileOffset >= Self.heuristicMinFunctionGap else { continue }
            guard let raw = try? file.data.readUInt32LE(at: fileOffset) else { continue }

            guard (raw & Self.arm64StpX29X30PreindexMask) == Self.arm64StpX29X30PreindexPattern else {
                continue
            }

            let vmAddress = textVMStart + UInt64(slotIndex * 4)
            let syntheticName = String(format: "__heuristic_func_0x%X", fileOffset - textStart)
            let plan = makeLightFallbackPlan(symbol: syntheticName)
            let profile = FunctionCFFTier.light.rewriteProfile!

            candidates.append(CFFManagedFunctionCandidate(
                policySymbol: syntheticName,
                binarySymbol: syntheticName,
                tier: .light,
                plan: plan,
                entryVMAddress: vmAddress,
                entryFileOffset: fileOffset,
                requiredPatchSlots: profile.requiredPatchSlots,
                scanSlots: profile.scanSlots
            ))
            lastFileOffset = fileOffset
        }
        return candidates
    }

    /// Apply light-tier CFF mutations to ARM64-prologue-detected functions in a stripped binary.
    private func applyHeuristic(
        to file: MachOFile,
        textStart: Int,
        textSize: Int,
        textVMStart: UInt64,
        textVMEnd: UInt64,
        verbose: Bool
    ) -> ControlFlowBinaryRewriteReport {
        let candidates = heuristicPrologueCandidates(
            file: file,
            textStart: textStart,
            textSize: textSize,
            textVMStart: textVMStart,
            textVMEnd: textVMEnd
        )

        guard !candidates.isEmpty else {
            return ControlFlowBinaryRewriteReport(
                modifiedFunctionCount: 0,
                bytesModified: 0,
                details: [
                    "Skipped: no symbol table found and ARM64 prologue scan found no candidates",
                    "Hint: provide an unstripped binary for full policy-guided Pass9 targeting",
                ]
            )
        }

        // Build a sorted list of all detected VM addresses for boundary estimation.
        let sortedEntries = candidates.map(\.entryVMAddress).sorted()

        var modified: [CFFModifiedFunctionRecord] = []
        var skipped: [CFFSkippedFunctionRecord] = []

        for candidate in candidates {
            let functionVMEnd = Self.nextTextSymbolEntry(
                after: candidate.entryVMAddress,
                sortedEntries: sortedEntries,
                textVMEnd: textVMEnd
            )
            guard functionVMEnd > candidate.entryVMAddress else {
                skipped.append(CFFSkippedFunctionRecord(
                    policySymbol: candidate.policySymbol,
                    binarySymbol: candidate.binarySymbol,
                    tier: candidate.tier,
                    reason: "invalid heuristic function bounds"
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
            case .modified(let record): modified.append(record)
            case .skipped(let record):  skipped.append(record)
            }
        }

        let bytesModified = modified.reduce(0) { $0 + $1.bytesModified }
        var details: [String] = [
            "Pass9 heuristic mode: ARM64 prologue scan (stripped binary)",
            "prologue candidates detected: \(candidates.count)",
            "modified functions: \(modified.count)",
            "bytes modified in __text: \(bytesModified)",
        ]
        if !skipped.isEmpty {
            details.append("skipped functions: \(skipped.count)")
        }
        if verbose {
            for record in modified {
                details.append(
                    "[heuristic][light] \(record.binarySymbol) patches=\(record.patches.count) bytes=\(record.bytesModified)"
                )
            }
        }

        return ControlFlowBinaryRewriteReport(
            modifiedFunctionCount: modified.count,
            bytesModified: bytesModified,
            details: details
        )
    }

    private static func sortedTextSymbolEntryAddresses(
        symbols: [SymbolEntry],
        textVMStart: UInt64,
        textVMEnd: UInt64
    ) -> [UInt64] {
        var addresses = Set<UInt64>()
        for symbol in symbols {
            guard symbol.nlist.typeField == Nlist64Entry.N_SECT else { continue }
            let vm = symbol.nlist.n_value
            guard vm >= textVMStart, vm < textVMEnd else { continue }
            addresses.insert(vm)
        }
        return addresses.sorted()
    }

    private static func nextTextSymbolEntry(
        after entry: UInt64,
        sortedEntries: [UInt64],
        textVMEnd: UInt64
    ) -> UInt64 {
        for addr in sortedEntries where addr > entry {
            return addr
        }
        return textVMEnd
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

        let blockApprox = approximateBasicBlockCount(
            file: file,
            functionStart: candidate.entryFileOffset,
            functionEnd: candidate.entryFileOffset + functionSizeBytes
        )

        var structuralPatches = computeCFGStructuralMutations(
            candidate: candidate,
            functionSizeBytes: functionSizeBytes,
            file: file,
            blockApprox: blockApprox
        )
        var excludedStructuralOffsets = Set(structuralPatches.map(\.fileOffset))

        func buildNeutralPatchable(excluding excluded: Set<Int>) -> [CFFPatchableSlot] {
            var slots = [CFFPatchableSlot]()
            slots.reserveCapacity(scanSlots)
            for slotIndex in 0..<scanSlots {
                let fileOffset = candidate.entryFileOffset + slotIndex * 4
                if excluded.contains(fileOffset) { continue }
                guard let rawValue = try? file.data.readUInt32LE(at: fileOffset) else { continue }
                guard let decoded = CFFNeutralInstructionCodec.decode(rawValue) else { continue }
                let options = CFFNeutralInstructionCodec.replacementOptions(
                    for: decoded,
                    excluding: rawValue
                )
                guard !options.isEmpty else { continue }

                slots.append(CFFPatchableSlot(
                    fileOffset: fileOffset,
                    originalRawValue: rawValue,
                    options: options
                ))
            }
            return slots
        }

        /// Structural CFG mutations (dispatcher / reorder / opaque island) count toward the per-function
        /// rewrite budget even when their patch sites sit outside the linear neutral scan window. The
        /// previous “in-scan only” rule forced `requiredNeutralSlots` to stay high unless *both*
        /// structural patches and neutral substitutions landed in the prologue-sized window — a common
        /// cause of `itemsProcessed == 0` on real Swift/ObjC functions where padding and dispatcher
        /// islands live past the first ~32 instructions.
        let structuralCoverage = structuralPatches.count
        var patchable = buildNeutralPatchable(excluding: excludedStructuralOffsets)
        var requiredNeutralSlots = max(0, candidate.requiredPatchSlots - structuralCoverage)

        if patchable.count < requiredNeutralSlots, !structuralPatches.isEmpty {
            structuralPatches = []
            excludedStructuralOffsets = []
            patchable = buildNeutralPatchable(excluding: [])
            requiredNeutralSlots = candidate.requiredPatchSlots
        }

        guard patchable.count >= requiredNeutralSlots else {
            return .skipped(CFFSkippedFunctionRecord(
                policySymbol: candidate.policySymbol,
                binarySymbol: candidate.binarySymbol,
                tier: candidate.tier,
                reason: "insufficient rewritable entry instructions (\(patchable.count) < \(requiredNeutralSlots), structural_coverage=\(structuralCoverage))"
            ))
        }

        var rng = CFFSplitMix64(seed: candidate.rewriteSeed)
        patchable.shuffle(using: &rng)
        let selectedSlots = Array(patchable.prefix(requiredNeutralSlots)).sorted {
            $0.fileOffset < $1.fileOffset
        }

        var neutralMutations = [CFFPatchMutation]()
        neutralMutations.reserveCapacity(selectedSlots.count)
        for slot in selectedSlots {
            let optionIndex = Int(rng.next() % UInt64(slot.options.count))
            let replacement = slot.options[optionIndex]
            neutralMutations.append(CFFPatchMutation(
                fileOffset: slot.fileOffset,
                originalRawValue: slot.originalRawValue,
                replacementRawValue: replacement.rawValue,
                replacementDescription: replacement.description
            ))
        }

        var mutations = structuralPatches + neutralMutations
        mutations.sort { $0.fileOffset < $1.fileOffset }

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

    /// Conservative leader-based estimate of basic blocks (4-byte aligned scan, PC-relative targets only).
    private func approximateBasicBlockCount(file: MachOFile, functionStart: Int, functionEnd: Int) -> Int {
        var leaders = Set<Int>()
        leaders.insert(functionStart)
        var offset = functionStart
        while offset + 4 <= functionEnd {
            guard let raw = try? file.data.readUInt32LE(at: offset) else { break }

            if let decoded = ARM64Codec.decode(raw) {
                switch decoded.kind {
                case .compareBranch(let cb):
                    let target = offset + Int(cb.immediate)
                    if target >= functionStart && target < functionEnd {
                        leaders.insert(target)
                    }
                    let fallthroughPC = offset + 4
                    if fallthroughPC < functionEnd {
                        leaders.insert(fallthroughPC)
                    }
                case .loadLiteral(let ll):
                    let target = offset + Int(ll.immediate)
                    if target >= functionStart && target < functionEnd {
                        leaders.insert(target)
                    }
                default:
                    break
                }
            }

            if let bTarget = unconditionalBranchTarget(fileOffset: offset, raw: raw) {
                if bTarget >= functionStart && bTarget < functionEnd {
                    leaders.insert(bTarget)
                }
                let fallthroughPC = offset + 4
                if fallthroughPC < functionEnd {
                    leaders.insert(fallthroughPC)
                }
            }

            offset += 4
        }
        return max(1, leaders.count)
    }

    private func unconditionalBranchTarget(fileOffset: Int, raw: UInt32) -> Int? {
        guard (raw & 0xFC00_0000) == 0x1400_0000 else { return nil }
        var immBits = raw & 0x03FF_FFFF
        if (immBits & 0x0200_0000) != 0 {
            immBits |= 0xFC00_0000
        }
        let signed = Int32(bitPattern: immBits)
        return fileOffset + Int(signed) * 4
    }

    /// Build a 3-patch branch-stub shuffle for a pre-validated CBZ/CBNZ head + two `B` stubs.
    /// Returns nil when any sub-decoding fails so the caller can try another site or fall
    /// through to the opaque-island path.
    private func buildBranchStubShufflePatches(
        site: (head: Int, headRaw: UInt32, leftRaw: UInt32, rightRaw: UInt32),
        blockApprox: Int
    ) -> [CFFPatchMutation]? {
        let base = site.head
        guard let invertedHead = invertedCompareBranchRaw(raw: site.headRaw) else {
            return nil
        }
        let leftOffset = base + 4
        let rightOffset = base + 8
        guard let leftImm = decodeUnconditionalBranchImmediate(raw: site.leftRaw),
              let rightImm = decodeUnconditionalBranchImmediate(raw: site.rightRaw) else {
            return nil
        }

        let leftTarget = leftOffset + leftImm
        let rightTarget = rightOffset + rightImm

        let relocatedLeft = rightTarget - leftOffset
        let relocatedRight = leftTarget - rightOffset
        guard let leftReencoded = encodeUnconditionalBranchImmediate(immediateBytes: relocatedLeft),
              let rightReencoded = encodeUnconditionalBranchImmediate(immediateBytes: relocatedRight) else {
            return nil
        }

        let tag = "CFG branch-stub reorder (bb~\(blockApprox))"
        return [
            CFFPatchMutation(
                fileOffset: base,
                originalRawValue: site.headRaw,
                replacementRawValue: invertedHead,
                replacementDescription: "\(tag) invert head predicate"
            ),
            CFFPatchMutation(
                fileOffset: leftOffset,
                originalRawValue: site.leftRaw,
                replacementRawValue: leftReencoded,
                replacementDescription: "\(tag) reorder +0x4"
            ),
            CFFPatchMutation(
                fileOffset: rightOffset,
                originalRawValue: site.rightRaw,
                replacementRawValue: rightReencoded,
                replacementDescription: "\(tag) reorder +0x8"
            ),
        ]
    }

    /// Decode TBZ / TBNZ (C4.2.5, test-and-branch-immediate). Returns the branch target file
    /// offset (computed as `fileOffset + signExtendedImm14 * 4`) or nil if `raw` isn't a test
    /// branch. Both 32-bit (`b5 = 0`) and 64-bit (`b5 = 1`) forms share the same imm14 layout,
    /// so we don't need to distinguish operand width to resolve the branch edge.
    private func testBranchTargetOffset(fileOffset: Int, raw: UInt32) -> Int? {
        // TBZ/TBNZ share encoding `x 011011 o1 bbbbb imm14 Rt` with top bits masked as below.
        guard (raw & 0x7E00_0000) == 0x3600_0000 else { return nil }
        var immBits = (raw >> 5) & 0x3FFF
        if (immBits & 0x2000) != 0 {
            // Sign-extend from bit 13 into the upper bits of a 32-bit word.
            immBits |= 0xFFFF_C000
        }
        let signed = Int32(bitPattern: immBits)
        return fileOffset + Int(signed) * 4
    }

    /// Structural CFG mutation priority:
    /// 1) Switch-style dispatcher (TBZ/TBNZ on WZR) using NOP padding holes, with dead bogus blocks.
    /// 2) Multi-basic-block physical reorder (safe subset with explicit terminal branches).
    /// 3) Compact branch-stub shuffle fallback.
    /// 4) Opaque island fallback.
    private func computeCFGStructuralMutations(
        candidate: CFFManagedFunctionCandidate,
        functionSizeBytes: Int,
        file: MachOFile,
        blockApprox: Int
    ) -> [CFFPatchMutation] {
        let start = candidate.entryFileOffset
        let end = start + functionSizeBytes
        // Domain-tag + per-symbol/per-VM mix so two dispatchers with the same policy tier
        // don't share the same shuffle/opaque ordering. Using only `rewriteSeed ^ 0xC0FF_EE2F`
        // would degrade every function to the same handful of permutations under a single
        // build seed, making pattern-based reversal trivial.
        let dispatcherSeedMix: UInt64 =
            0xD15C_5EED_C0FF_EE2F
            ^ cffStableHash64("dispatch:\(candidate.policySymbol)")
            ^ (UInt64(functionSizeBytes) &* 0x9E37_79B9_7F4A_7C15)
            ^ (candidate.entryVMAddress &* 0xBF58_476D_1CE4_E5B9)
        var rng = CFFSplitMix64(seed: candidate.rewriteSeed ^ dispatcherSeedMix)

        let shuffleEnabled = policy.antiDeobfuscation.enableBinaryCFGShuffle
        let opaqueEnabled = policy.antiDeobfuscation.enableCFGOpaqueIslands

        if policy.antiDeobfuscation.enableMultiDispatcher {
            let switchPatches = computeSwitchDispatcherMutations(
                candidate: candidate,
                functionSizeBytes: functionSizeBytes,
                file: file,
                blockApprox: blockApprox
            )
            if !switchPatches.isEmpty {
                return switchPatches
            }
        }

        if shuffleEnabled {
            let multiPatches = computeMultiBasicBlockReorderMutations(
                candidate: candidate,
                functionSizeBytes: functionSizeBytes,
                file: file,
                rng: &rng,
                blockApprox: blockApprox
            )
            if !multiPatches.isEmpty {
                return multiPatches
            }
        }

        var shuffleSites: [(head: Int, headRaw: UInt32, leftRaw: UInt32, rightRaw: UInt32)] = []
        var opaqueSites: [Int] = []

        for off in stride(from: start, to: end - 12, by: 4) {
            guard let w0 = try? file.data.readUInt32LE(at: off),
                  let w1 = try? file.data.readUInt32LE(at: off + 4),
                  let w2 = try? file.data.readUInt32LE(at: off + 8) else { continue }
            guard let decoded = ARM64Codec.decode(w0),
                  case .compareBranch(let cb) = decoded.kind,
                  cb.immediate == 8 else { continue }
            if decodeUnconditionalBranchImmediate(raw: w1) != nil,
               decodeUnconditionalBranchImmediate(raw: w2) != nil {
                shuffleSites.append((head: off, headRaw: w0, leftRaw: w1, rightRaw: w2))
            }
            if w1 == ARM64Codec.nopRawValue {
                opaqueSites.append(off + 4)
            }
        }

        if shuffleEnabled, !shuffleSites.isEmpty {
            shuffleSites.shuffle(using: &rng)
            // Try shuffle sites in randomised order; if one fails mid-decode, keep trying
            // the next site instead of returning []. Previous code aborted the whole
            // structural path at the first decode miss, starving the opaque fallback.
            for site in shuffleSites {
                if let stubPatches = buildBranchStubShufflePatches(site: site, blockApprox: blockApprox) {
                    return stubPatches
                }
            }
        }

        if opaqueEnabled, !opaqueSites.isEmpty {
            opaqueSites.shuffle(using: &rng)
            if let opOff = opaqueSites.first {
                guard let orig = try? file.data.readUInt32LE(at: opOff), orig == ARM64Codec.nopRawValue else {
                    return []
                }
                let opaque = pass9OpaqueCBNZXZRPlus4()
                return [
                    CFFPatchMutation(
                        fileOffset: opOff,
                        originalRawValue: orig,
                        replacementRawValue: opaque,
                        replacementDescription: "CFG opaque island CBNZ XZR, +4 (bb~\(blockApprox))"
                    ),
                ]
            }
        }

        return []
    }

    /// In-place switch-style dispatcher: replace leading NOPs in a padding run with TBZ/TBNZ on `WZR`
    /// (always-zero), jumping over unreachable bogus NOPs to a join NOP. Semantics match a straight
    /// NOP slide when the run is only padding. Fails (returns `[]`) when no ≥3-word NOP run exists.
    private func computeSwitchDispatcherMutations(
        candidate: CFFManagedFunctionCandidate,
        functionSizeBytes: Int,
        file: MachOFile,
        blockApprox: Int
    ) -> [CFFPatchMutation] {
        let functionStart = candidate.entryFileOffset
        let functionEnd = functionStart + functionSizeBytes
        guard let run = findLongestContiguousNOPRun(
            file: file,
            functionStart: functionStart,
            functionEnd: functionEnd,
            minimumWords: 3
        ) else {
            return []
        }

        let runStart = run.start
        let runCount = run.count
        for off in stride(from: runStart, to: runStart + runCount * 4, by: 4) {
            guard let raw = try? file.data.readUInt32LE(at: off), raw == ARM64Codec.nopRawValue else {
                return []
            }
        }

        let bogusWords = min(2, runCount - 2)
        let joinWords = runCount - 1 - bogusWords
        guard joinWords >= 1 else { return [] }

        let firstJoinWordIndex = bogusWords + 1
        let joinOff = runStart + firstJoinWordIndex * 4

        let immHeadWords = bogusWords + 1
        guard let headTBZ = encodeTBZ_WZR(bitIndex: 0, imm14Words: immHeadWords) else {
            return []
        }

        let tagBase = "CFG switch dispatcher (TBZ/TBNZ WZR) + bogus block (bb~\(blockApprox))"

        guard let origHead = try? file.data.readUInt32LE(at: runStart) else { return [] }
        var patches: [CFFPatchMutation] = [
            CFFPatchMutation(
                fileOffset: runStart,
                originalRawValue: origHead,
                replacementRawValue: headTBZ,
                replacementDescription: "\(tagBase) live TBZ skips bogus"
            ),
        ]

        if runCount >= 4 {
            let secondOff = runStart + 4
            let deltaBytes = joinOff - secondOff
            guard deltaBytes > 0, deltaBytes % 4 == 0 else { return [] }
            let immSecondWords = deltaBytes / 4
            guard let deadTBZ = encodeTBZ_WZR(bitIndex: 1, imm14Words: immSecondWords),
                  let origSecond = try? file.data.readUInt32LE(at: secondOff) else {
                return []
            }
            patches.append(CFFPatchMutation(
                fileOffset: secondOff,
                originalRawValue: origSecond,
                replacementRawValue: deadTBZ,
                replacementDescription: "\(tagBase) unreachable TBZ (dead arm)"
            ))

            let thirdOff = runStart + 8
            if thirdOff < joinOff {
                let deltaThird = joinOff - thirdOff
                guard deltaThird > 0, deltaThird % 4 == 0 else { return [] }
                let immThirdWords = deltaThird / 4
                guard let deadTBNZ = encodeTBNZ_WZR(bitIndex: 0, imm14Words: immThirdWords),
                      let origThird = try? file.data.readUInt32LE(at: thirdOff) else {
                    return []
                }
                patches.append(CFFPatchMutation(
                    fileOffset: thirdOff,
                    originalRawValue: origThird,
                    replacementRawValue: deadTBNZ,
                    replacementDescription: "\(tagBase) unreachable TBNZ (dead arm)"
                ))
            }
        }

        return patches
    }

    private func findLongestContiguousNOPRun(
        file: MachOFile,
        functionStart: Int,
        functionEnd: Int,
        minimumWords: Int
    ) -> (start: Int, count: Int)? {
        guard functionEnd > functionStart, minimumWords > 0 else { return nil }

        var best: (start: Int, count: Int)?
        var runStart = -1
        var runCount = 0

        var offset = functionStart
        while offset + 4 <= functionEnd {
            guard let raw = try? file.data.readUInt32LE(at: offset) else { break }
            if raw == ARM64Codec.nopRawValue {
                if runStart < 0 {
                    runStart = offset
                    runCount = 0
                }
                runCount += 1
            } else {
                if runStart >= 0, runCount >= minimumWords {
                    if best == nil || runCount > best!.count {
                        best = (runStart, runCount)
                    }
                }
                runStart = -1
                runCount = 0
            }
            offset += 4
        }

        if runStart >= 0, runCount >= minimumWords {
            if best == nil || runCount > best!.count {
                best = (runStart, runCount)
            }
        }

        return best
    }

    /// TBZ `Wn`, `#bit`, `PC + imm14*4` — uses 32-bit form (`WZR` = 31) matching assembler output.
    private func encodeTBZ_WZR(bitIndex: UInt32, imm14Words: Int) -> UInt32? {
        encodeTestBranch_WZR(isTbnz: false, bitIndex: bitIndex, imm14Words: imm14Words)
    }

    private func encodeTBNZ_WZR(bitIndex: UInt32, imm14Words: Int) -> UInt32? {
        encodeTestBranch_WZR(isTbnz: true, bitIndex: bitIndex, imm14Words: imm14Words)
    }

    private func encodeTestBranch_WZR(isTbnz: Bool, bitIndex: UInt32, imm14Words: Int) -> UInt32? {
        guard bitIndex < 32 else { return nil }
        guard imm14Words >= -(1 << 13), imm14Words < (1 << 13) else { return nil }
        let imm = UInt32(bitPattern: Int32(imm14Words)) & 0x3FFF
        let b5 = (bitIndex >> 5) & 1
        let b40 = bitIndex & 0x1F
        let opcodeBase: UInt32 = isTbnz ? 0x37 : 0x36
        return (UInt32(b5) << 31) | (opcodeBase << 24) | (b40 << 19) | (imm << 5) | 31
    }

    /// Returns `true` if any instruction in `[regionStart, regionEnd)` is a PC-relative
    /// pointer (LDR-literal, LDRSW-literal, PRFM-literal, ADR, ADRP) whose target lands
    /// inside the same region. Such references are invalidated by block reorder because
    /// we don't rewrite their encoded immediates. Unconditional-branch terminators are
    /// handled separately in the reorder path and are explicitly ignored here.
    ///
    /// Conservative: unrecognised instruction shapes are treated as "no reference".
    private func regionContainsInternalPCRelativeReference(
        file: MachOFile,
        regionStart: Int,
        regionEnd: Int
    ) -> Bool {
        var offset = regionStart
        while offset + 4 <= regionEnd {
            defer { offset += 4 }
            guard let raw = try? file.data.readUInt32LE(at: offset) else { return true }

            // ADR / ADRP: `(op)(immlo)10000(immhi)Rd` — `op` in bit 31, fixed `10000` in [28:24].
            if (raw & 0x1F00_0000) == 0x1000_0000 {
                let immlo = (raw >> 29) & 0x3
                var immhi = (raw >> 5) & 0x7FFFF
                // Sign-extend 21 bits (immhi:immlo) into Int32.
                var imm21 = (immhi << 2) | immlo
                if (imm21 & (1 << 20)) != 0 {
                    imm21 |= 0xFFE0_0000
                }
                let signedImm = Int32(bitPattern: imm21)
                let isAdrp = (raw & 0x8000_0000) != 0
                // ADR: target = PC + signedImm.  ADRP: target = (PC & ~0xFFF) + signedImm << 12.
                // We only care whether the target can fall inside the region; any ADRP hit that
                // aligns into the region indicates the region is data-adjacent and reorder is unsafe.
                if isAdrp {
                    // ADRP shifts by 12 → targets a page, so region overlap is very unlikely and
                    // not a correctness risk for instruction reorder (page-aligned labels are
                    // typically outside __text regions). Skip.
                    _ = signedImm
                } else {
                    let target = offset &+ Int(signedImm)
                    if target >= regionStart, target < regionEnd {
                        return true
                    }
                }
                _ = immhi
                continue
            }

            // LDR (literal) 32-bit: 0x1800_0000 mask 0xFF00_0000
            // LDR (literal) 64-bit: 0x5800_0000 mask 0xFF00_0000
            // LDRSW (literal):      0x9800_0000 mask 0xFF00_0000
            // PRFM   (literal):     0xD800_0000 mask 0xFF00_0000
            // LDR (literal) SIMD S: 0x1C00_0000; D: 0x5C00_0000; Q: 0x9C00_0000
            let top8 = raw & 0xFF00_0000
            let isLiteral: Bool
            switch top8 {
            case 0x1800_0000, 0x5800_0000, 0x9800_0000, 0xD800_0000,
                 0x1C00_0000, 0x5C00_0000, 0x9C00_0000:
                isLiteral = true
            default:
                isLiteral = false
            }
            if isLiteral {
                var imm19 = (raw >> 5) & 0x7FFFF
                if (imm19 & (1 << 18)) != 0 {
                    imm19 |= 0xFFF8_0000
                }
                let signed = Int32(bitPattern: imm19)
                let target = offset &+ Int(signed) * 4
                if target >= regionStart, target < regionEnd {
                    return true
                }
            }
        }
        return false
    }

    private func computeMultiBasicBlockReorderMutations(
        candidate: CFFManagedFunctionCandidate,
        functionSizeBytes: Int,
        file: MachOFile,
        rng: inout CFFSplitMix64,
        blockApprox: Int
    ) -> [CFFPatchMutation] {
        let functionStart = candidate.entryFileOffset
        let functionEnd = functionStart + functionSizeBytes
        let blocks = buildReorderBasicBlocks(
            file: file,
            functionStart: functionStart,
            functionEnd: functionEnd
        )
        guard blocks.count >= 3 else { return [] }

        let maxBlocks = candidate.tier.multiBlockReorderLimit
        guard maxBlocks >= 3 else { return [] }
        let selectedCount = min(maxBlocks, blocks.count)
        guard selectedCount >= 3 else { return [] }

        let selected = Array(blocks.prefix(selectedCount))
        let regionStart = selected[0].start
        let regionEnd = selected[selected.count - 1].end
        let regionLength = regionEnd - regionStart
        guard regionLength > 0,
              regionLength % 4 == 0,
              regionLength <= 512 else {
            return []
        }

        for block in selected {
            guard case .unconditional = block.terminator else { return [] }
        }

        // Data-in-code guard: abort the reorder if any LDR-literal / ADR target (PC-relative
        // pointer) inside the region would be silently invalidated by shuffling. Ordinary B
        // terminators are patched up below, but literal pools and ADR-targeted labels that
        // land in a shuffled block have no corresponding fixup path here.
        if regionContainsInternalPCRelativeReference(
            file: file,
            regionStart: regionStart,
            regionEnd: regionEnd
        ) {
            return []
        }

        var startToBlockIndex = [Int: Int]()
        for (index, block) in blocks.enumerated() {
            startToBlockIndex[block.start] = index
        }

        var incomingByBlock = [Int: Set<Int>]()
        for (index, block) in blocks.enumerated() {
            guard case .unconditional(let target) = block.terminator else { continue }
            guard let targetIndex = startToBlockIndex[target] else { return [] }
            incomingByBlock[targetIndex, default: []].insert(index)
        }

        let selectedIndices = Set(0..<selectedCount)
        for idx in 1..<selectedCount {
            let incoming = incomingByBlock[idx] ?? []
            if incoming.contains(where: { !selectedIndices.contains($0) }) {
                return []
            }
        }

        let originalTail = Array(1..<selectedCount)
        var reorderedTail = originalTail
        reorderedTail.shuffle(using: &rng)
        // If shuffle left the identity order, force a swap. Do not swap when shuffle already
        // produced a non-identity order — swapping [2,1] back to [1,2] would incorrectly abort.
        if reorderedTail == originalTail {
            if reorderedTail.count > 1 {
                reorderedTail.swapAt(0, 1)
            }
        }
        if reorderedTail == originalTail {
            return []
        }

        let newOrder = [0] + reorderedTail
        var newStarts = Array(repeating: 0, count: selectedCount)
        var cursor = regionStart
        for blockIndex in newOrder {
            newStarts[blockIndex] = cursor
            cursor += selected[blockIndex].length
        }
        guard cursor == regionEnd else { return [] }

        func mapOffset(_ oldOffset: Int) -> Int? {
            for idx in 0..<selectedCount {
                let block = selected[idx]
                if oldOffset >= block.start, oldOffset < block.end {
                    return newStarts[idx] + (oldOffset - block.start)
                }
            }
            return nil
        }

        var reorderedRegion = Data(count: regionLength)
        for idx in 0..<selectedCount {
            let block = selected[idx]
            let newStart = newStarts[idx]
            let srcRange = block.start..<block.end
            let dstOffset = newStart - regionStart
            let dstRange = dstOffset..<(dstOffset + block.length)
            reorderedRegion.replaceSubrange(dstRange, with: file.data.subdata(in: srcRange))
        }

        for idx in 0..<selectedCount {
            let block = selected[idx]
            guard case .unconditional(let oldTarget) = block.terminator else { return [] }
            let oldTerminatorOffset = block.end - 4
            guard let newTerminatorOffset = mapOffset(oldTerminatorOffset) else { return [] }
            let newTarget = mapOffset(oldTarget) ?? oldTarget
            let newImmediateBytes = newTarget - newTerminatorOffset
            guard let encoded = encodeUnconditionalBranchImmediate(immediateBytes: newImmediateBytes) else {
                return []
            }
            let encodedData = CFFNeutralInstructionCodec.data(for: encoded)
            let localOffset = newTerminatorOffset - regionStart
            reorderedRegion.replaceSubrange(localOffset..<(localOffset + 4), with: encodedData)
        }

        var patches = [CFFPatchMutation]()
        for off in stride(from: regionStart, to: regionEnd, by: 4) {
            guard let oldRaw = try? file.data.readUInt32LE(at: off),
                  let newRaw = try? reorderedRegion.readUInt32LE(at: off - regionStart) else {
                return []
            }
            if oldRaw == newRaw { continue }
            patches.append(CFFPatchMutation(
                fileOffset: off,
                originalRawValue: oldRaw,
                replacementRawValue: newRaw,
                replacementDescription: "CFG multi-bb reorder (\(selectedCount) blocks, bb~\(blockApprox))"
            ))
        }

        return patches
    }

    private func buildReorderBasicBlocks(
        file: MachOFile,
        functionStart: Int,
        functionEnd: Int
    ) -> [CFFBasicBlock] {
        guard functionEnd > functionStart, (functionStart % 4) == 0, (functionEnd % 4) == 0 else {
            return []
        }

        var leaders = Set<Int>()
        leaders.insert(functionStart)

        var offset = functionStart
        while offset + 4 <= functionEnd {
            guard let raw = try? file.data.readUInt32LE(at: offset) else { break }

            // Keep leader discovery consistent with `approximateBasicBlockCount` so block
            // boundaries match compare-branches and literal loads, not only unconditional `B`.
            if let decoded = ARM64Codec.decode(raw) {
                switch decoded.kind {
                case .compareBranch(let cb):
                    let target = offset + Int(cb.immediate)
                    if target >= functionStart, target < functionEnd, target % 4 == 0 {
                        leaders.insert(target)
                    }
                    let fallthroughPC = offset + 4
                    if fallthroughPC < functionEnd {
                        leaders.insert(fallthroughPC)
                    }
                case .loadLiteral(let ll):
                    let target = offset + Int(ll.immediate)
                    if target >= functionStart, target < functionEnd, target % 4 == 0 {
                        leaders.insert(target)
                    }
                default:
                    break
                }
            }

            // TBZ / TBNZ are conditional branches too but aren't surfaced by ARM64Codec today.
            // Include them in leader discovery so reorder doesn't split a basic block in the
            // middle of a TBZ-guarded edge.
            if let tbzTarget = testBranchTargetOffset(fileOffset: offset, raw: raw) {
                if tbzTarget >= functionStart, tbzTarget < functionEnd, tbzTarget % 4 == 0 {
                    leaders.insert(tbzTarget)
                }
                let fallthroughPC = offset + 4
                if fallthroughPC < functionEnd {
                    leaders.insert(fallthroughPC)
                }
            }

            if let target = unconditionalBranchTarget(fileOffset: offset, raw: raw) {
                if target >= functionStart, target < functionEnd, target % 4 == 0 {
                    leaders.insert(target)
                }
                let next = offset + 4
                if next < functionEnd {
                    leaders.insert(next)
                }
            }
            offset += 4
        }

        let sortedLeaders = leaders.sorted()
        guard sortedLeaders.first == functionStart else { return [] }

        var blocks = [CFFBasicBlock]()
        blocks.reserveCapacity(sortedLeaders.count)
        for (index, start) in sortedLeaders.enumerated() {
            let end = (index + 1 < sortedLeaders.count) ? sortedLeaders[index + 1] : functionEnd
            guard end > start, ((end - start) % 4) == 0 else { return [] }
            guard let terminatorRaw = try? file.data.readUInt32LE(at: end - 4) else { return [] }
            if let target = unconditionalBranchTarget(fileOffset: end - 4, raw: terminatorRaw) {
                blocks.append(CFFBasicBlock(
                    start: start,
                    end: end,
                    terminator: .unconditional(target: target)
                ))
            } else {
                blocks.append(CFFBasicBlock(
                    start: start,
                    end: end,
                    terminator: .other
                ))
            }
        }
        return blocks
    }

    private func pass9OpaqueCBNZXZRPlus4() -> UInt32 {
        encodeCompareAndBranchZero(branchIfZero: false, immediateWords: 1)
    }

    private func invertedCompareBranchRaw(raw: UInt32) -> UInt32? {
        guard let decoded = ARM64Codec.decode(raw),
              case .compareBranch(let cb) = decoded.kind else {
            return nil
        }
        guard cb.immediate % 4 == 0 else { return nil }

        switch cb.form {
        case .cbz:
            return ARM64Codec.encodeCBNZ(
                destinationRegister: cb.register,
                immediateWords: Int(cb.immediate / 4)
            )
        case .cbnz:
            return ARM64Codec.encodeCBZ(
                destinationRegister: cb.register,
                immediateWords: Int(cb.immediate / 4)
            )
        case .bConditional:
            let cond = cb.register & 0xF
            // Skip AL/NV encodings for conservative safety.
            guard cond < 0xE else { return nil }
            let inverted = cond ^ 0x1
            return ARM64Codec.encodeBCond(
                conditionCode: inverted,
                immediateBytes: Int(cb.immediate)
            )
        case .csincCond:
            return nil
        }
    }

    private func decodeUnconditionalBranchImmediate(raw: UInt32) -> Int? {
        guard (raw & 0xFC00_0000) == 0x1400_0000 else { return nil }
        var immBits = raw & 0x03FF_FFFF
        if (immBits & 0x0200_0000) != 0 {
            immBits |= 0xFC00_0000
        }
        let signed = Int32(bitPattern: immBits)
        return Int(signed) * 4
    }

    private func encodeUnconditionalBranchImmediate(immediateBytes: Int) -> UInt32? {
        guard immediateBytes % 4 == 0 else { return nil }
        let words = immediateBytes / 4
        guard words >= -(1 << 25), words < (1 << 25) else { return nil }
        let imm26 = UInt32(bitPattern: Int32(words)) & 0x03FF_FFFF
        return 0x1400_0000 | imm26
    }

    private func encodeCompareAndBranchZero(branchIfZero: Bool, immediateWords: Int) -> UInt32 {
        // imm19 is SIGNED: valid word range is [-2^18, 2^18). Clamping to [0, 0x3FFFF] silently
        // drops backward branches (which CBZ/CBNZ must be able to emit) and also accepts the
        // inverse sign by truncation. Clamp into the signed range and encode via 2's-complement.
        let maxPos = (1 << 18) - 1
        let minNeg = -(1 << 18)
        let clamped = max(min(immediateWords, maxPos), minNeg)
        let base: UInt32 = branchIfZero ? 0xB400_0000 : 0xB500_0000
        let imm19 = UInt32(bitPattern: Int32(clamped)) & 0x7FFFF
        return base | (imm19 << 5) | ARM64RegisterWidth.zeroRegisterIndex
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

    /// VM-address stable across Mach-O layout (segment slides, LINKEDIT growth) so Pass9's
    /// per-function rewrite seed survives codesign / lipo / linker-edit re-runs. Using
    /// `entryFileOffset` (as before) let trivial re-linking silently rotate every seed.
    var rewriteSeed: UInt64 {
        let base = plan.stateEncodingPlan.perFunctionSeed
        let tierSalt = UInt64(tier.priorityWeight) << 48
        let symbolSalt = cffStableHash64(policySymbol) &* 0x100000001B3
        return base ^ entryVMAddress ^ tierSalt ^ symbolSalt
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

private struct CFFBasicBlock {
    let start: Int
    let end: Int
    let terminator: CFFBasicBlockTerminator

    var length: Int { end - start }
}

private enum CFFBasicBlockTerminator {
    case unconditional(target: Int)
    case other
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
            // Swift mangled symbols embed identifiers as length-prefixed tokens (e.g.
            // "...19RiskDetectionEngineC8evaluate..."), so policy tails rarely sit at suffix.
            // Allow substring hits for unique long tails to keep Pass9 effective on stripped
            // Release binaries while still preferring exact/normalized matches above.
            if normalizedSymbol == tail
                || normalizedSymbol.hasSuffix(tail)
                || normalizedSymbol.contains(tail) {
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
    /// Admission policy for Pass9 binary rewrite: scan the first N 4-byte instruction slots for
    /// neutral substitutions; require M successful slots (after structural mutations consume coverage).
    /// Wider scans improve hit rate on real Swift/ObjC prologues where neutral patterns appear past
    /// the first few words; heavy tier asks for fewer *neutral* slots when structural CFG mutations apply.
    var rewriteProfile: (requiredPatchSlots: Int, scanSlots: Int)? {
        switch self {
        case .heavy:
            // Structural mutations often satisfy part of the budget; keep a modest neutral requirement.
            return (requiredPatchSlots: 2, scanSlots: 56)
        case .medium:
            // Real binaries: Swift prologues may lack neutral-decodable slots early; one substitution
            // plus a wider scan hits “medium” targets without forcing risky multi-slot rewrites.
            return (requiredPatchSlots: 1, scanSlots: 72)
        case .regionOnly:
            return (requiredPatchSlots: 1, scanSlots: 44)
        case .light:
            return (requiredPatchSlots: 1, scanSlots: 44)
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
        case .medium:
            return 15
        case .light:
            return 10
        case .never:
            return 0
        }
    }

    var multiBlockReorderLimit: Int {
        switch self {
        case .heavy:
            return 6
        case .regionOnly:
            return 5
        case .medium:
            return 5
        case .light:
            return 4
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
