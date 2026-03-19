import Foundation
import MachOKit

/// SplitMix64 deterministic PRNG used to keep plan scattering reproducible.
private struct SeededRNG: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed == 0 ? 1 : seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }
}

private struct InjectionCandidate {
    let identifier: String
    let patchSiteVMAddress: UInt64
    let patchSiteFileOffset: UInt32
    let policyBits: UInt32
    let entryFlags: UInt32
    let score: Int
}

private enum SeedOrigin {
    case config
    case binary

    var description: String {
        switch self {
        case .config:
            return "config"
        case .binary:
            return "binary fingerprint"
        }
    }
}

/// Pass 7: emit a runtime-readable anti-debug injection plan section.
///
/// This pass intentionally avoids inline patching live machine code. Instead it
/// reserves a stable ABI in `__DATA,__objc_data2` so the runtime can later map
/// target identifiers, offsets, and policy bits to a stronger in-memory patcher.
public final class AntiDebugInjectorPass: ArmorPass {
    public let name = "AntiDebugInjector"

    private static let interestingKeywords = [
        "debug", "dbg", "frida", "ptrace", "sysctl", "tamper",
        "jailbreak", "hook", "trace", "integrity", "risk", "guard", "probe",
    ]

    private static let ignoredPrefixes = [
        "_objc_", "_swift_", "___swift_", "__mh_",
    ]

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        guard (try? file.segment(named: ArmorABI.dataSegmentName)) != nil else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["Skipped: __DATA segment not found"]
            )
        }

        guard let textSegment = try file.segment(named: "__TEXT"),
              let textSection = try file.section(segment: "__TEXT", section: "__text") else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["Skipped: __TEXT.__text not found"]
            )
        }

        let (seed, seedOrigin) = try resolveSeed(for: file, config: config)
        var rng = SeededRNG(seed: seed)
        let probeImmediate = makeProbeImmediate(using: &rng)

        let candidates = try collectCandidates(from: file, textSection: textSection)
        guard !candidates.isEmpty else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["Skipped: no anti-debug targets discovered"]
            )
        }

        let selectedCandidates = selectCandidates(from: candidates, using: &rng)
        let sectionFlags = buildSectionFlags(
            seedOrigin: seedOrigin,
            candidates: selectedCandidates
        )

        var payload = ArmorABI.AntiDebug.Header(
            flags: sectionFlags,
            seed: seed,
            textBaseAddress: textSegment.vmAddress,
            probeImmediate: probeImmediate,
            entryCount: UInt32(selectedCandidates.count)
        ).serialized()

        var details = [
            "Injected anti-debug plan into \(ArmorABI.dataSegmentName).\(ArmorABI.AntiDebug.sectionName)",
            "Seed: \(seed) (\(seedOrigin.description))",
            String(format: "Probe immediate: 0x%08X", probeImmediate),
            "Entries: \(selectedCandidates.count)/\(candidates.count) candidates",
        ]

        for (scatterSlot, candidate) in selectedCandidates.enumerated() {
            let entry = ArmorABI.AntiDebug.Entry(
                identifierHash: fnv1a64(candidate.identifier),
                patchSiteVMOffset: candidate.patchSiteVMAddress - textSegment.vmAddress,
                patchSiteFileOffset: candidate.patchSiteFileOffset,
                policyBits: candidate.policyBits,
                scatterSlot: UInt32(scatterSlot),
                entryFlags: candidate.entryFlags,
                targetName: candidate.identifier
            )
            payload.append(entry.serialized())

            if config.verbose {
                details.append(
                    String(
                        format: "Plan[%d] %@ vm+0x%llX file=0x%X policy=0x%08X flags=0x%08X",
                        scatterSlot,
                        candidate.identifier,
                        candidate.patchSiteVMAddress - textSegment.vmAddress,
                        candidate.patchSiteFileOffset,
                        candidate.policyBits,
                        candidate.entryFlags
                    )
                )
            }
        }

        let scrubReport = ObjCData2MangledSymbolScrubber.sanitize(
            payload: &payload,
            buildSeedHint: config.randomSeed
        )
        if scrubReport.scrubbedTargetNames > 0 {
            details.append(
                "Scrubbed \(scrubReport.scrubbedTargetNames) leaked target_name values in \(ArmorABI.dataSegmentName).\(ArmorABI.AntiDebug.sectionName)"
            )
        }
        if scrubReport.remappedIdentifierHashes > 0 {
            details.append(
                "Remapped \(scrubReport.remappedIdentifierHashes) identifier_hash values with build-scoped salt"
            )
        }

        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.AntiDebug.sectionName,
            content: payload,
            align: 3,
            flags: 0
        )

        return PassResult(
            passName: name,
            itemsProcessed: selectedCandidates.count,
            bytesModified: payload.count,
            details: details
        )
    }

    private func resolveSeed(for file: MachOFile, config: PassConfig) throws -> (UInt64, SeedOrigin) {
        if let provided = config.randomSeed {
            return (provided == 0 ? 1 : provided, .config)
        }

        var hash = FNV1A64.offsetBasis
        if let textSegment = try file.segment(named: "__TEXT") {
            hash = mix(hash, string: textSegment.name)
            hash = mix(hash, value: textSegment.vmAddress)
            hash = mix(hash, value: textSegment.fileOffset)
            hash = mix(hash, value: textSegment.fileSize)
        }

        let symbols = try file.readSymbols()
        if !symbols.isEmpty {
            for symbol in symbols.prefix(32) where !symbol.name.isEmpty {
                hash = mix(hash, string: symbol.name)
                hash = mix(hash, value: symbol.nlist.n_value)
            }
        } else {
            for segment in try file.segments() {
                hash = mix(hash, string: segment.name)
                for section in segment.sections {
                    hash = mix(hash, string: section.sectionName)
                    hash = mix(hash, value: section.address)
                    hash = mix(hash, value: section.size)
                }
            }
        }

        return (hash == 0 ? 1 : hash, .binary)
    }

    private func collectCandidates(from file: MachOFile, textSection: Section) throws -> [InjectionCandidate] {
        var candidates = [InjectionCandidate]()
        candidates.append(contentsOf: try collectSymbolCandidates(from: file))
        candidates.append(contentsOf: syntheticCandidates(from: textSection))

        var deduped = [UInt64: InjectionCandidate]()
        for candidate in candidates.sorted(by: candidateSortKey) {
            let key = (UInt64(candidate.patchSiteFileOffset) << 32) ^ fnv1a64(candidate.identifier)
            if let existing = deduped[key], existing.score >= candidate.score {
                continue
            }
            deduped[key] = candidate
        }

        return deduped.values.sorted(by: candidateSortKey)
    }

    private func collectSymbolCandidates(from file: MachOFile) throws -> [InjectionCandidate] {
        let symbols = try file.readSymbols()
        guard !symbols.isEmpty else { return [] }

        var candidates = [InjectionCandidate]()

        for symbol in symbols {
            let name = symbol.name
            guard shouldConsiderSymbol(symbol.name) else { continue }
            guard symbol.nlist.typeField == Nlist64Entry.N_SECT else { continue }
            guard symbol.nlist.n_value > 0 else { continue }

            guard let containingSection = try file.section(containingVMAddress: symbol.nlist.n_value),
                  containingSection.segmentName == "__TEXT",
                  containingSection.sectionName == "__text" else {
                continue
            }

            guard let fileOffset = try file.fileOffset(forVMAddress: symbol.nlist.n_value),
                  fileOffset <= UInt64(UInt32.max) else {
                continue
            }

            let policyBits = policyBits(for: name, isSynthetic: false)
            let entryFlags = ArmorABI.AntiDebug.entryFlagInlinePatchReserved
                | ArmorABI.AntiDebug.entryFlagRuntimeGateReserved

            candidates.append(InjectionCandidate(
                identifier: name,
                patchSiteVMAddress: symbol.nlist.n_value,
                patchSiteFileOffset: UInt32(fileOffset),
                policyBits: policyBits,
                entryFlags: entryFlags,
                score: score(for: name, isLocal: symbol.nlist.isDefinedLocal)
            ))
        }

        return candidates
    }

    private func syntheticCandidates(from textSection: Section) -> [InjectionCandidate] {
        guard textSection.size > 0 else { return [] }

        let maxSlots = min(4, max(2, Int(textSection.size / 32)))
        let stride = max(16, Int(textSection.size) / maxSlots)
        let lastValidOffset = max(0, Int(textSection.size) - 4)

        return (0..<maxSlots).map { index in
            let rawOffset = min(index * stride, lastValidOffset)
            let alignedOffset = rawOffset & ~0xF
            let patchSiteVMAddress = textSection.address + UInt64(alignedOffset)
            let patchSiteFileOffset = Int(textSection.offset) + alignedOffset
            let identifier = String(format: "__text+0x%X", alignedOffset)
            let policyBits = policyBits(for: identifier, isSynthetic: true)
            return InjectionCandidate(
                identifier: identifier,
                patchSiteVMAddress: patchSiteVMAddress,
                patchSiteFileOffset: UInt32(patchSiteFileOffset),
                policyBits: policyBits,
                entryFlags: ArmorABI.AntiDebug.entryFlagSyntheticTarget
                    | ArmorABI.AntiDebug.entryFlagInlinePatchReserved,
                score: max(1, 6 - index)
            )
        }
    }

    private func selectCandidates(
        from candidates: [InjectionCandidate],
        using rng: inout SeededRNG
    ) -> [InjectionCandidate] {
        let selectionPoolSize = min(12, candidates.count)
        var selectionPool = Array(candidates.prefix(selectionPoolSize))
        selectionPool.shuffle(using: &rng)

        let maxSelectable = min(6, selectionPool.count)
        let minSelectable = min(maxSelectable, selectionPool.count >= 3 ? 3 : selectionPool.count)
        let spread = max(1, maxSelectable - minSelectable + 1)
        let desiredCount = minSelectable + Int(rng.next() % UInt64(spread))

        return Array(selectionPool.prefix(desiredCount))
    }

    private func buildSectionFlags(seedOrigin: SeedOrigin, candidates: [InjectionCandidate]) -> UInt32 {
        var flags: UInt32 = 0

        if candidates.contains(where: { ($0.entryFlags & ArmorABI.AntiDebug.entryFlagSyntheticTarget) == 0 }) {
            flags |= ArmorABI.AntiDebug.flagHasSymbolTargets
        }
        if candidates.contains(where: { ($0.entryFlags & ArmorABI.AntiDebug.entryFlagSyntheticTarget) != 0 }) {
            flags |= ArmorABI.AntiDebug.flagHasSyntheticTargets
        }

        switch seedOrigin {
        case .config:
            flags |= ArmorABI.AntiDebug.flagSeedFromConfig
        case .binary:
            flags |= ArmorABI.AntiDebug.flagSeedFromBinary
        }

        return flags
    }

    private func makeProbeImmediate(using rng: inout SeededRNG) -> UInt32 {
        let raw = UInt32(truncatingIfNeeded: rng.next())
        return raw == 0 ? 0xA7D0_0001 : raw | 0x0000_0001
    }

    private func shouldConsiderSymbol(_ symbolName: String) -> Bool {
        guard !symbolName.isEmpty else { return false }
        guard !Self.ignoredPrefixes.contains(where: { symbolName.hasPrefix($0) }) else { return false }

        if symbolName.hasPrefix("_$s") {
            let lowered = symbolName.lowercased()
            if lowered.contains("swift") && !Self.interestingKeywords.contains(where: { lowered.contains($0) }) {
                return false
            }
        }

        return true
    }

    private func score(for name: String, isLocal: Bool) -> Int {
        let lowered = name.lowercased()
        var score = isLocal ? 12 : 8

        for keyword in Self.interestingKeywords where lowered.contains(keyword) {
            score += 10
        }
        if lowered.hasPrefix("_main") || lowered.contains("entry") {
            score += 3
        }

        return score
    }

    private func policyBits(for identifier: String, isSynthetic: Bool) -> UInt32 {
        let lowered = identifier.lowercased()
        var bits = ArmorABI.AntiDebug.policyRuntimeGate

        if lowered.contains("debug") || lowered.contains("ptrace") || lowered.contains("sysctl") {
            bits |= ArmorABI.AntiDebug.policyCrashOnDebugger
        }
        if lowered.contains("frida") || lowered.contains("hook") || lowered.contains("tamper") {
            bits |= ArmorABI.AntiDebug.policyTrapOnTamper
            bits |= ArmorABI.AntiDebug.policyEscalateIntegrity
        }
        if lowered.contains("risk") || lowered.contains("guard") || lowered.contains("probe") || isSynthetic {
            bits |= ArmorABI.AntiDebug.policyDelayResponse
        }

        return bits
    }

    private func candidateSortKey(_ lhs: InjectionCandidate, _ rhs: InjectionCandidate) -> Bool {
        if lhs.score != rhs.score {
            return lhs.score > rhs.score
        }
        if lhs.patchSiteVMAddress != rhs.patchSiteVMAddress {
            return lhs.patchSiteVMAddress < rhs.patchSiteVMAddress
        }
        return lhs.identifier < rhs.identifier
    }
}

enum ObjCData2MangledSymbolScrubber {
    private static let leakPrefixes = [
        "_$s17CloudPhoneRiskKit",
        "_$s21CloudPhoneRiskAppCore",
    ]

    private static let semanticLeakKeywords = [
        "cloudphonerisk",
        "riskdetector",
        "riskappcore",
        "criskcore",
    ]

    private static let replacementAlphabet = Array("abcdefghijklmnopqrstuvwxyz0123456789".utf8)

    struct ObjCData2ScrubReport: Equatable {
        let parsed: Bool
        let entryCount: Int
        let scrubbedTargetNames: Int
        let remappedIdentifierHashes: Int
        let bytesModified: Int
    }

    /// Backward-compatible entry point used by older tests/callers.
    @discardableResult
    static func scrub(in payload: inout Data) -> Int {
        sanitize(payload: &payload).scrubbedTargetNames
    }

    /// Unified sanitizer for `__DATA,__objc_data2`:
    /// 1) scrub semantic leaks in `target_name`;
    /// 2) remap `identifier_hash` using a build-scoped salt to remove stable identifiers.
    static func sanitize(payload: inout Data, buildSeedHint: UInt64? = nil) -> ObjCData2ScrubReport {
        guard payload.count >= ArmorABI.AntiDebug.headerSize else {
            return ObjCData2ScrubReport(parsed: false, entryCount: 0, scrubbedTargetNames: 0, remappedIdentifierHashes: 0, bytesModified: 0)
        }

        let headerSize = Int(readLE32(payload, at: ArmorABI.AntiDebug.headerHeaderSizeOffset))
        let entryCount = Int(readLE32(payload, at: ArmorABI.AntiDebug.headerEntryCountOffset))
        let entrySize = Int(readLE32(payload, at: ArmorABI.AntiDebug.headerEntrySizeOffset))
        let headerSeed = readLE64(payload, at: ArmorABI.AntiDebug.headerSeedOffset)

        guard entryCount >= 0,
              headerSize >= ArmorABI.AntiDebug.headerSize,
              entrySize >= ArmorABI.AntiDebug.entrySize else {
            return ObjCData2ScrubReport(parsed: false, entryCount: 0, scrubbedTargetNames: 0, remappedIdentifierHashes: 0, bytesModified: 0)
        }

        let (entriesBytes, overflow) = entryCount.multipliedReportingOverflow(by: entrySize)
        guard !overflow,
              headerSize <= payload.count,
              entriesBytes <= payload.count - headerSize else {
            return ObjCData2ScrubReport(parsed: false, entryCount: 0, scrubbedTargetNames: 0, remappedIdentifierHashes: 0, bytesModified: 0)
        }

        let mappingSalt = buildMappingSalt(
            headerSeed: headerSeed,
            buildSeedHint: buildSeedHint,
            entryCount: entryCount
        )

        var scrubbed = 0
        var remapped = 0
        var bytesModified = 0

        for index in 0..<entryCount {
            let entryBase = headerSize + index * entrySize

            let nameBase = entryBase + ArmorABI.AntiDebug.entryTargetNameOffset
            let nameFieldEnd = nameBase + ArmorABI.AntiDebug.targetNameFieldSize
            guard nameFieldEnd <= payload.count else { break }

            var bytes = [UInt8](payload[nameBase..<nameFieldEnd])
            let visibleLength = bytes.firstIndex(of: 0) ?? bytes.count
            if visibleLength > 0 {
                let currentName = String(decoding: bytes.prefix(visibleLength), as: UTF8.self)
                if shouldScrubTargetName(currentName) {
                    let replacement = semanticlessReplacement(
                        source: Array(bytes.prefix(visibleLength)),
                        length: visibleLength
                    )
                    for offset in 0..<visibleLength {
                        bytes[offset] = replacement[offset]
                        payload[nameBase + offset] = replacement[offset]
                    }
                    if visibleLength < bytes.count {
                        payload[nameBase + visibleLength] = 0
                    }
                    scrubbed += 1
                    bytesModified += visibleLength
                }
            }

            let patchSiteVMOffset = readLE64(payload, at: entryBase + ArmorABI.AntiDebug.entryPatchSiteVMOffset)
            let patchSiteFileOffset = readLE32(payload, at: entryBase + ArmorABI.AntiDebug.entryPatchSiteFileOffset)
            let policyBits = readLE32(payload, at: entryBase + ArmorABI.AntiDebug.entryPolicyBitsOffset)
            let scatterSlot = readLE32(payload, at: entryBase + ArmorABI.AntiDebug.entryScatterSlotOffset)
            let entryFlags = readLE32(payload, at: entryBase + ArmorABI.AntiDebug.entryFlagsOffset)
            let hashOffset = entryBase + ArmorABI.AntiDebug.entryIdentifierHashOffset
            let currentHash = readLE64(payload, at: hashOffset)
            let remappedHash = remappedIdentifierHash(
                mappingSalt: mappingSalt,
                entryIndex: index,
                patchSiteVMOffset: patchSiteVMOffset,
                patchSiteFileOffset: patchSiteFileOffset,
                policyBits: policyBits,
                scatterSlot: scatterSlot,
                entryFlags: entryFlags
            )
            if currentHash != remappedHash {
                writeLE64(&payload, at: hashOffset, value: remappedHash)
                remapped += 1
                bytesModified += MemoryLayout<UInt64>.size
            }
        }

        return ObjCData2ScrubReport(
            parsed: true,
            entryCount: entryCount,
            scrubbedTargetNames: scrubbed,
            remappedIdentifierHashes: remapped,
            bytesModified: bytesModified
        )
    }

    static func buildMappingSalt(headerSeed: UInt64, buildSeedHint: UInt64?, entryCount: Int) -> UInt64 {
        var hash = FNV1A64.offsetBasis
        hash = mix(hash, value: headerSeed)
        hash = mix(hash, value: UInt64(entryCount))
        if let buildSeedHint {
            hash = mix(hash, value: buildSeedHint)
        }
        hash = mix(hash, value: 0x4350_5249_534B_4144) // "CPRISKAD"
        return avalanche64ForScrub(hash)
    }

    static func remappedIdentifierHash(
        mappingSalt: UInt64,
        entryIndex: Int,
        patchSiteVMOffset: UInt64,
        patchSiteFileOffset: UInt32,
        policyBits: UInt32,
        scatterSlot: UInt32,
        entryFlags: UInt32
    ) -> UInt64 {
        var hash = mappingSalt
        hash = mix(hash, value: UInt64(entryIndex))
        hash = mix(hash, value: patchSiteVMOffset)
        hash = mix(hash, value: UInt64(patchSiteFileOffset))
        hash = mix(hash, value: UInt64(policyBits))
        hash = mix(hash, value: UInt64(scatterSlot))
        hash = mix(hash, value: UInt64(entryFlags))
        hash = mix(hash, value: 0xA7D0_0001)
        return avalanche64ForScrub(hash)
    }

    private static func semanticlessReplacement(source: [UInt8], length: Int) -> [UInt8] {
        guard length > 0 else { return [] }
        var state = fnv1a64(source)
        var output = [UInt8]()
        output.reserveCapacity(length)
        for _ in 0..<length {
            state = state &* 2862933555777941757 &+ 3037000493
            let idx = Int(state % UInt64(replacementAlphabet.count))
            output.append(replacementAlphabet[idx])
        }
        return output
    }

    private static func shouldScrubTargetName(_ targetName: String) -> Bool {
        if leakPrefixes.contains(where: { targetName.hasPrefix($0) }) {
            return true
        }
        let lowered = targetName.lowercased()
        return semanticLeakKeywords.contains(where: { lowered.contains($0) })
    }

    private static func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= data.count else { return 0 }
        return data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            UInt32(littleEndian: $0.load(as: UInt32.self))
        }
    }

    private static func readLE64(_ data: Data, at offset: Int) -> UInt64 {
        guard offset >= 0, offset + 8 <= data.count else { return 0 }
        return data.subdata(in: offset..<(offset + 8)).withUnsafeBytes {
            UInt64(littleEndian: $0.load(as: UInt64.self))
        }
    }

    private static func writeLE64(_ data: inout Data, at offset: Int, value: UInt64) {
        guard offset >= 0, offset + 8 <= data.count else { return }
        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { bytes in
            for index in 0..<8 {
                data[offset + index] = bytes[index]
            }
        }
    }
}

public final class ObjCData2ScrubberPass: ArmorPass {
    public let name = "ObjCData2Scrubber"

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        guard let section = try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.AntiDebug.sectionName) else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["Skipped: \(ArmorABI.dataSegmentName).\(ArmorABI.AntiDebug.sectionName) not found"]
            )
        }

        var payload = try section.readContent(from: file.data)
        guard !payload.isEmpty else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["Skipped: \(ArmorABI.dataSegmentName).\(ArmorABI.AntiDebug.sectionName) is empty"]
            )
        }

        let report = ObjCData2MangledSymbolScrubber.sanitize(
            payload: &payload,
            buildSeedHint: config.randomSeed
        )

        if report.bytesModified > 0 {
            try file.replaceBytes(at: UInt64(section.offset), with: payload)
        }

        var details = [String]()
        if !report.parsed {
            details.append("Skipped: existing section layout is not compatible with AntiDebug ABI")
        } else {
            details.append("Entries parsed: \(report.entryCount)")
            details.append("target_name scrubbed: \(report.scrubbedTargetNames)")
            details.append("identifier_hash remapped: \(report.remappedIdentifierHashes)")
        }

        return PassResult(
            passName: name,
            itemsProcessed: report.entryCount,
            bytesModified: report.bytesModified,
            details: details
        )
    }
}

private enum FNV1A64 {
    static let offsetBasis: UInt64 = 0xCBF29CE484222325
    static let prime: UInt64 = 0x00000100000001B3
}

private func fnv1a64(_ string: String) -> UInt64 {
    var hash = FNV1A64.offsetBasis
    for byte in string.utf8 {
        hash ^= UInt64(byte)
        hash &*= FNV1A64.prime
    }
    return hash
}

private func fnv1a64(_ bytes: [UInt8]) -> UInt64 {
    var hash = FNV1A64.offsetBasis
    for byte in bytes {
        hash ^= UInt64(byte)
        hash &*= FNV1A64.prime
    }
    return hash
}

private func mix(_ hash: UInt64, string: String) -> UInt64 {
    var mixed = hash
    for byte in string.utf8 {
        mixed ^= UInt64(byte)
        mixed &*= FNV1A64.prime
    }
    return mixed
}

private func mix(_ hash: UInt64, value: UInt64) -> UInt64 {
    var littleEndian = value.littleEndian
    return withUnsafeBytes(of: &littleEndian) { rawBuffer in
        var mixed = hash
        for byte in rawBuffer {
            mixed ^= UInt64(byte)
            mixed &*= FNV1A64.prime
        }
        return mixed
    }
}

private func avalanche64ForScrub(_ value: UInt64) -> UInt64 {
    var v = value
    v ^= v >> 33
    v &*= 0xFF51_AFD7_ED55_8CCD
    v ^= v >> 33
    v &*= 0xC4CE_B9FE_1A85_EC53
    v ^= v >> 33
    return v == 0 ? 1 : v
}
