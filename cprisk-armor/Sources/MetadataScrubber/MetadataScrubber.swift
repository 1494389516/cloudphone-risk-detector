import Foundation
import MachOKit

/// Pass 2: Scrub non-essential Swift / ObjC metadata to hinder reverse engineering.
///
/// Strips or obfuscates type names, protocol conformance descriptors,
/// and reflection metadata that are not required at runtime.
///
/// **Swift semantic leaks:** In addition to mangled symbols and module keywords, a curated list of
/// substrings (e.g. `riskdetection`, `isvip`, `honeypot`) triggers conservative in-place rewrites of
/// C-string bodies in `__const` and ancillary `__swift5_*` sections without touching relative-pointer
/// tables. Optional ``PassConfig.swiftSemanticLeakOptions`` enables `__TEXT.__cstring` reporting,
/// opt-in CString scrubbing, and unreferenced decoy sections — see CLI/env in `cprisk-armor` help.
public final class MetadataScrubberPass: ArmorPass {
    public let name = "MetadataScrubber"

    /// ObjC method prefixes that must be preserved for runtime correctness.
    private static let systemMethodPrefixes = [
        "init", ".cxx_destruct",
        "viewDid", "viewWill", "layout", "draw",
        "encode", "decode", "awakeFromNib",
        "application:", "scene:",
        "tableView:", "collectionView:", "scrollView:",
        "textField:", "picker:",
        "dealloc", "description", "debugDescription",
        "hash", "isEqual:", "copy", "mutableCopy",
        "responds", "performs", "class", "super", "self",
        "zone", "retain", "release", "autorelease", "forward",
        "observeValue", "setValue:forKey", "valueForKey",
    ]

    /// Deterministic RNG for scrub bytes (ties to ``PassConfig.randomSeed`` / ``PassConfig.buildSeed``).
    private struct SeededSplitMix64 {
        private var state: UInt64

        init(seed: UInt64) {
            self.state = seed == 0 ? 0xDEAD_BEEF_CAFE_0001 : seed
        }

        mutating func nextUInt64() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
            z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
            return z ^ (z >> 31)
        }
    }

    private var rng = SeededSplitMix64(seed: 1)

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        let seed = config.randomSeed ?? config.buildSeed
        rng = SeededSplitMix64(seed: seed == 0 ? 0xC0DEDA57FBADC0FE : seed)

        var itemsProcessed = 0
        var bytesModified = 0
        var details = [String]()

        let typeResult = try scrubSwiftTypeNames(in: file)
        itemsProcessed += typeResult.obfuscated
        bytesModified += typeResult.bytes
        details.append("Swift type names obfuscated: \(typeResult.obfuscated)/\(typeResult.total)")

        let reflBytes = try scrubReflectionStrings(in: file)
        if reflBytes > 0 {
            itemsProcessed += 1
            bytesModified += reflBytes
            details.append("Reflection strings scrubbed: \(reflBytes) bytes")
        }

        let extra = try scrubSwiftMetadataExtraSections(in: file, level: config.swiftMetadataScrubLevel)
        if extra.bytes > 0 {
            itemsProcessed += extra.items
            bytesModified += extra.bytes
            if let line = extra.detailLine {
                details.append(line)
            }
        }

        let methResult = try scrubObjCMethodNames(in: file)
        if methResult.total > 0 {
            itemsProcessed += methResult.obfuscated
            bytesModified += methResult.bytes
            details.append("ObjC method names obfuscated: \(methResult.obfuscated)/\(methResult.total)")
        }

        let constResult = try scrubConstSectionModuleNames(in: file)
        if constResult.total > 0 {
            itemsProcessed += constResult.scrubbed
            bytesModified += constResult.bytes
            details.append("__const module name strings scrubbed: \(constResult.scrubbed)/\(constResult.total)")
        }

        let opt = config.swiftSemanticLeakOptions
        if opt.reportCStringSemanticMatches || opt.scrubCStringSemanticMatches {
            let cScan = try scanCStringSemanticLeaks(in: file)
            if opt.reportCStringSemanticMatches, cScan.matches > 0 {
                let preview = cScan.samples.prefix(3).joined(separator: "; ")
                let line =
                    "Swift semantic CString scan: \(cScan.matches) match(es)\(preview.isEmpty ? "" : " (e.g. \(preview))")"
                details.append(line)
                if config.verbose {
                    fputs("[!] Pass 2: \(line)\n", stderr)
                }
            }
            if opt.scrubCStringSemanticMatches, cScan.matches > 0 {
                let scrubbed = try scrubCStringSemanticMatches(in: file, candidates: cScan.candidateOffsets)
                itemsProcessed += scrubbed.strings
                bytesModified += scrubbed.bytes
                if scrubbed.strings > 0 {
                    details.append(
                        "Swift semantic CString scrub (opt-in): \(scrubbed.strings) string(s), \(scrubbed.bytes) bytes"
                    )
                }
            }
        }

        if opt.injectSemanticDecoys {
            let effectiveSeed = seed == 0 ? 0xC0DEDA57FBADC0FE : seed
            switch try appendSemanticDecoySectionIfPossible(to: file, seed: effectiveSeed) {
            case .appended(let bytes):
                itemsProcessed += 1
                bytesModified += bytes
                details.append(
                    "Swift semantic decoy section \(ArmorABI.MetadataSections.swiftSemanticDecoy): \(bytes) bytes"
                )
            case .skipped(let reason):
                details.append("Swift semantic decoys skipped: \(reason)")
            }
        }

        return PassResult(
            passName: name,
            itemsProcessed: itemsProcessed,
            bytesModified: bytesModified,
            details: details
        )
    }

    // MARK: - Swift semantic CString scan / scrub (optional)

    private struct CStringSemanticScan {
        let matches: Int
        let samples: [String]
        let candidateOffsets: [UInt64]
    }

    /// Enumerate `__TEXT.__cstring` and find strings matching ``SwiftSemanticLeakCatalog``.
    private func scanCStringSemanticLeaks(in file: MachOFile) throws -> CStringSemanticScan {
        guard let section = try file.section(segment: "__TEXT", section: "__cstring") else {
            return CStringSemanticScan(matches: 0, samples: [], candidateOffsets: [])
        }
        let content = try section.readContent(from: file.data)
        guard !content.isEmpty else {
            return CStringSemanticScan(matches: 0, samples: [], candidateOffsets: [])
        }
        let base = UInt64(section.offset)
        var matches = 0
        var samples = [String]()
        var candidateOffsets = [UInt64]()
        var position = 0
        while position < content.count {
            var end = position
            while end < content.count && content[end] != 0 { end += 1 }
            let length = end - position
            if length > 0 {
                let slice = content.subdata(in: position..<end)
                let str = String(data: slice, encoding: .utf8)
                    ?? String(data: slice, encoding: .isoLatin1)
                    ?? ""
                let hit: Bool
                if !str.isEmpty {
                    hit = SwiftSemanticLeakCatalog.matchesUTF8(str)
                } else {
                    hit = SwiftSemanticLeakCatalog.rawSliceMatches(slice, length: length)
                }
                if hit {
                    matches += 1
                    candidateOffsets.append(base + UInt64(position))
                    if samples.count < 5 {
                        let preview = str.isEmpty
                            ? "<non-utf8 \(length)B>"
                            : (str.count > 48 ? String(str.prefix(45)) + "…" : str)
                        samples.append(preview)
                    }
                }
            }
            position = end + 1
        }
        return CStringSemanticScan(matches: matches, samples: samples, candidateOffsets: candidateOffsets)
    }

    private func scrubCStringSemanticMatches(in file: MachOFile, candidates: [UInt64]) throws -> (strings: Int, bytes: Int) {
        var strings = 0
        var bytes = 0
        for off in candidates {
            var end = Int(off)
            while end < file.data.count && file.data[end] != 0 { end += 1 }
            let length = end - Int(off)
            guard length > 0 else { continue }
            try file.replaceBytes(at: off, with: randomHexBytes(count: length))
            strings += 1
            bytes += length
        }
        return (strings, bytes)
    }

    private enum DecoyAppendResult {
        case appended(bytes: Int)
        case skipped(reason: String)
    }

    private func appendSemanticDecoySectionIfPossible(to file: MachOFile, seed: UInt64) throws -> DecoyAppendResult {
        let payload = SwiftSemanticLeakCatalog.decoyPayload(seed: seed)
        do {
            _ = try file.addOrUpdateSection(
                segment: "__TEXT",
                section: ArmorABI.MetadataSections.swiftSemanticDecoy,
                content: payload,
                align: 2,
                flags: 0
            )
            return .appended(bytes: payload.count)
        } catch {
            return .skipped(reason: String(describing: error))
        }
    }

    // MARK: - A. Swift Type Name Obfuscation

    private func scrubSwiftTypeNames(
        in file: MachOFile
    ) throws -> (total: Int, obfuscated: Int, bytes: Int) {
        let metadata = try file.findSwiftTypeMetadata()
        var obfuscated = 0
        var bytes = 0

        for entry in metadata {
            guard shouldObfuscateType(entry) else { continue }
            let nameLength = entry.name.utf8.count
            guard nameLength > 0 else { continue }

            try file.replaceBytes(at: entry.nameOffset, with: randomHexBytes(count: nameLength))
            obfuscated += 1
            bytes += nameLength
        }

        return (metadata.count, obfuscated, bytes)
    }

    // MARK: - B. Reflection String Scrubbing

    private func scrubReflectionStrings(in file: MachOFile) throws -> Int {
        guard let section = try file.section(
            segment: "__TEXT",
            section: ArmorABI.MetadataSections.swiftReflectionStrings
        ) else { return 0 }

        guard section.size <= UInt64(Int.max) else {
            throw MachOError.integerOverflow("section \(section.sectionName) size exceeds Int.max")
        }
        let size = Int(section.size)
        guard size > 0 else { return 0 }

        try file.replaceBytes(at: UInt64(section.offset), with: randomBytes(count: size))
        return size
    }

    // MARK: - B2. Swift metadata sections (__swift5_proto / __swift5_fieldmd / …)

    /// Extra Swift metadata sections (everything in ``ArmorABI.MetadataSections.additionalScrubSections``).
    ///
    /// **Conservative (default):** Walk embedded C strings and replace only payloads that look like
    /// Swift mangled symbols (`$s…`, `_T…`) or match the same business-keyword rules as `__const`
    /// scrubbing. Descriptor records and relative-pointer fields stay byte-stable so the Swift runtime
    /// and dyld keep a consistent view; IDA/Swift plugins lose readable names tied to those strings.
    ///
    /// **Aggressive:** Overwrite each section in full with random bytes. This breaks the linear layout
    /// tools use to follow name/typeref chains, but can break reflection, some dynamic casts, or future
    /// runtime uses of these blobs — only enable when you accept that risk.
    private func scrubSwiftMetadataExtraSections(
        in file: MachOFile,
        level: SwiftMetadataScrubLevel
    ) throws -> (items: Int, bytes: Int, detailLine: String?) {
        switch level {
        case .conservative:
            let (strings, bytes) = try scrubSwiftMetadataSectionsConservative(in: file)
            guard bytes > 0 else { return (0, 0, nil) }
            let line =
                "Swift metadata sections (conservative, string payloads): \(strings) strings, \(bytes) bytes"
            return (strings, bytes, line)
        case .aggressive:
            let bytes = try scrubAdditionalMetadataSectionsAggressive(in: file)
            guard bytes > 0 else { return (0, 0, nil) }
            let line = "Swift metadata sections (aggressive, full overwrite): \(bytes) bytes"
            return (1, bytes, line)
        }
    }

    /// Conservative: string payloads only (see ``scrubSwiftMetadataExtraSections``).
    private func scrubSwiftMetadataSectionsConservative(in file: MachOFile) throws -> (strings: Int, bytes: Int) {
        var strings = 0
        var bytes = 0

        for sectionName in ArmorABI.MetadataSections.additionalScrubSections {
            for segName in ["__TEXT", "__DATA"] {
                guard let section = try file.section(segment: segName, section: sectionName) else {
                    continue
                }
                let r = try scrubSectionCStringPayloads(section, in: file) { utf8 in
                    Self.shouldScrubSwiftMetadataCString(utf8)
                }
                strings += r.strings
                bytes += r.bytes
            }
        }

        return (strings, bytes)
    }

    /// True for Swift 5 (`$s…`) / legacy (`_T…`) mangling prefixes and module keyword matches.
    private static func shouldScrubSwiftMetadataCString(_ utf8: String) -> Bool {
        if looksLikeSwiftSymbolMangling(utf8) { return true }
        if shouldScrubConstString(utf8) { return true }
        let lower = utf8.lowercased()
        if constSectionScrubKeywords.contains(where: { lower.contains($0.lowercased()) }) { return true }
        if utf8.count > riskSubstringMinLength, lower.contains("risk") { return true }
        if SwiftSemanticLeakCatalog.matchesUTF8(utf8) { return true }
        return false
    }

    /// Swift mangled type/symbol text as emitted in metadata (Swift 5 and legacy).
    private static func looksLikeSwiftSymbolMangling(_ s: String) -> Bool {
        if s.hasPrefix("$s") || s.hasPrefix("_$s") { return true }
        if s.hasPrefix("_T") { return true }
        return false
    }

    /// When UTF-8 decode fails, detect mangling via raw bytes so we still scrub `$s` / `_T` blobs.
    private static func rawLooksLikeSwiftManglingPrefix(_ slice: Data) -> Bool {
        let b = Array(slice)
        guard b.count >= 2 else { return false }
        if b[0] == 0x24 && b[1] == 0x73 { return true }
        if b.count >= 3, b[0] == 0x5F, b[1] == 0x24, b[2] == 0x73 { return true }
        if b[0] == 0x5F && b[1] == 0x54 { return true }
        return false
    }

    /// Aggressive: full section overwrite (legacy behavior).
    private func scrubAdditionalMetadataSectionsAggressive(in file: MachOFile) throws -> Int {
        var totalBytes = 0
        let relativePointerCritical: Set<String> = [
            ArmorABI.MetadataSections.swiftProtocols,
            ArmorABI.MetadataSections.swiftFieldMetadata,
            ArmorABI.MetadataSections.swiftAssociatedTypes,
            ArmorABI.MetadataSections.swiftTypeReferences,
        ]

        for sectionName in ArmorABI.MetadataSections.additionalScrubSections {
            for segName in ["__TEXT", "__DATA"] {
                guard let section = try file.section(segment: segName, section: sectionName) else {
                    continue
                }
                if relativePointerCritical.contains(sectionName) {
                    // Keep relative-pointer metadata byte-stable even in aggressive mode.
                    let conservative = try scrubSectionCStringPayloads(section, in: file) { utf8 in
                        Self.shouldScrubSwiftMetadataCString(utf8)
                    }
                    totalBytes += conservative.bytes
                    continue
                }
                guard section.size <= UInt64(Int.max) else { continue }
                let size = Int(section.size)
                guard size > 0 else { continue }

                try file.replaceBytes(at: UInt64(section.offset), with: randomBytes(count: size))
                totalBytes += size
            }
        }

        return totalBytes
    }

    /// Scan a section as a bag of null-terminated C strings; scrub selected strings in place.
    private func scrubSectionCStringPayloads(
        _ section: Section,
        in file: MachOFile,
        shouldScrubUTF8: (String) -> Bool
    ) throws -> (strings: Int, bytes: Int) {
        let content = try section.readContent(from: file.data)
        guard !content.isEmpty else { return (0, 0) }

        let sectionFileOffset = UInt64(section.offset)
        var strings = 0
        var bytes = 0
        var position = 0

        while position < content.count {
            var end = position
            while end < content.count && content[end] != 0 { end += 1 }

            let length = end - position
            if length > 0 {
                let slice = content.subdata(in: position..<end)
                let str = String(data: slice, encoding: .utf8)
                    ?? String(data: slice, encoding: .isoLatin1)
                    ?? ""

                let scrub: Bool
                if !str.isEmpty {
                    scrub = shouldScrubUTF8(str)
                } else {
                    scrub = Self.rawSliceContainsScrubKeyword(slice, length: length)
                        || SwiftSemanticLeakCatalog.rawSliceMatches(slice, length: length)
                        || Self.rawLooksLikeSwiftManglingPrefix(slice)
                }

                if scrub {
                    try file.replaceBytes(
                        at: sectionFileOffset + UInt64(position),
                        with: randomHexBytes(count: length)
                    )
                    strings += 1
                    bytes += length
                }
            }

            position = end + 1
        }

        return (strings, bytes)
    }

    // MARK: - C. ObjC Method Name Obfuscation

    private func scrubObjCMethodNames(
        in file: MachOFile
    ) throws -> (total: Int, obfuscated: Int, bytes: Int) {
        guard let section = try file.section(
            segment: "__TEXT",
            section: ArmorABI.MetadataSections.objcMethodNames
        ) else { return (0, 0, 0) }

        let content = try section.readContent(from: file.data)
        guard !content.isEmpty else { return (0, 0, 0) }

        let sectionFileOffset = UInt64(section.offset)
        var total = 0
        var obfuscated = 0
        var bytes = 0
        var position = 0

        while position < content.count {
            var end = position
            while end < content.count && content[end] != 0 { end += 1 }

            if end > position, end <= content.count,
               let methodName = String(data: content.subdata(in: position..<end), encoding: .utf8)
            {
                total += 1
                if Self.shouldObfuscateMethod(methodName) {
                    let length = end - position
                    try file.replaceBytes(
                        at: sectionFileOffset + UInt64(position),
                        with: randomHexBytes(count: length)
                    )
                    obfuscated += 1
                    bytes += length
                }
            }

            position = end + 1
        }

        return (total, obfuscated, bytes)
    }

    // MARK: - Decision Logic

    private func shouldObfuscateType(_ metadata: SwiftTypeMetadata) -> Bool {
        let name = metadata.name
        guard name.count > 2 else { return false }
        if name.contains("cprisk_") { return false }
        return true
    }

    /// Default-obfuscate: all methods are obfuscated UNLESS they match a system prefix or are single-char.
    private static func shouldObfuscateMethod(_ name: String) -> Bool {
        guard name.count > 1 else { return false }
        for prefix in systemMethodPrefixes where name.hasPrefix(prefix) {
            return false
        }
        return true
    }

    // MARK: - D. __const Section Module Name Scrubbing

    /// Business module name keywords to scrub from Swift type descriptor C strings.
    ///
    /// These appear as `module name` fields in `__TEXT,__const` type descriptors and are
    /// directly readable in IDA/Hopper. We overwrite the content bytes with random hex
    /// while preserving the null terminator so the surrounding record layout is intact.
    private static let constSectionScrubKeywords: [String] = [
        "CloudPhoneRisk",
        "RiskDetector",
        "CRiskCore",
        "RiskAppCore",
    ]

    /// Minimum length for a generic "Risk"-containing string to be eligible for scrubbing.
    private static let riskSubstringMinLength = 5

    /// Raw byte-level keyword search for slices that failed UTF-8/Latin-1 decode.
    /// Matches keywords case-insensitively (ASCII only).
    private static func rawSliceContainsScrubKeyword(_ slice: Data, length: Int) -> Bool {
        for keyword in constSectionScrubKeywords {
            let kw = keyword.lowercased()
            let kwBytes = Array(kw.utf8)
            guard length >= kwBytes.count else { continue }
            for i in 0...(length - kwBytes.count) {
                var match = true
                for j in 0..<kwBytes.count {
                    let b = slice[i + j]
                    let kb = kwBytes[j]
                    if b == kb { continue }
                    if (65...90).contains(b) && b + 32 == kb { continue }
                    if (97...122).contains(b) && b - 32 == kb { continue }
                    match = false
                    break
                }
                if match { return true }
            }
        }
        if length > riskSubstringMinLength {
            let riskBytes = Array("risk".utf8)
            guard length >= riskBytes.count else { return false }
            for i in 0...(length - riskBytes.count) {
                var match = true
                for j in 0..<riskBytes.count {
                    let b = slice[i + j]
                    let kb = riskBytes[j]
                    if b == kb { continue }
                    if (65...90).contains(b) && b + 32 == kb { continue }
                    if (97...122).contains(b) && b - 32 == kb { continue }
                    match = false
                    break
                }
                if match { return true }
            }
        }
        return false
    }

    /// Returns true when a C string found in `__TEXT,__const` should be overwritten.
    ///
    /// Rules (evaluated in order):
    /// 1. Exact keyword prefix/substring match against `constSectionScrubKeywords`.
    /// 2. Contains "Risk" and length > `riskSubstringMinLength` (catches RiskSignal, RiskDetector, etc.).
    /// 3. Curated semantic-leak tokens (``SwiftSemanticLeakCatalog``), e.g. `isVip` / `RiskDetectionEngine` fragments.
    private static func shouldScrubConstString(_ string: String) -> Bool {
        for keyword in constSectionScrubKeywords where string.contains(keyword) {
            return true
        }
        if string.count > riskSubstringMinLength, string.contains("Risk") {
            return true
        }
        if SwiftSemanticLeakCatalog.matchesUTF8(string) {
            return true
        }
        return false
    }

    /// Scan `__TEXT,__const` and `__DATA_CONST,__const` for C strings that contain
    /// business module names and overwrite their content bytes with random hex,
    /// preserving each null terminator so surrounding record layout is intact.
    ///
    /// - Returns: `(total, scrubbed, bytes)` counts for reporting.
    private func scrubConstSectionModuleNames(
        in file: MachOFile
    ) throws -> (total: Int, scrubbed: Int, bytes: Int) {
        var total = 0
        var scrubbed = 0
        var bytes = 0

        let candidates: [(String, String)] = [
            ("__TEXT", "__const"),
            ("__DATA_CONST", "__const"),
        ]

        for (segName, sectName) in candidates {
            guard let section = try file.section(segment: segName, section: sectName) else {
                continue
            }
            let r = try scrubConstSection(section, in: file)
            total += r.total
            scrubbed += r.scrubbed
            bytes += r.bytes
        }

        return (total, scrubbed, bytes)
    }

    private func scrubConstSection(
        _ section: Section,
        in file: MachOFile
    ) throws -> (total: Int, scrubbed: Int, bytes: Int) {
        let content = try section.readContent(from: file.data)
        guard !content.isEmpty else { return (0, 0, 0) }

        let sectionFileOffset = UInt64(section.offset)
        var total = 0
        var scrubbed = 0
        var bytes = 0
        var position = 0

        while position < content.count {
            // Locate end of current C string (null terminator).
            var end = position
            while end < content.count && content[end] != 0 {
                end += 1
            }

            let length = end - position
            if length > 0 {
                total += 1
                let slice = content.subdata(in: position..<end)
                // Try UTF-8 first; fall back to Latin-1 so non-UTF8 records are still scanned.
                let str = String(data: slice, encoding: .utf8)
                    ?? String(data: slice, encoding: .isoLatin1)
                    ?? ""
                var shouldScrub = false
                if !str.isEmpty {
                    shouldScrub = Self.shouldScrubConstString(str)
                    if !shouldScrub {
                        // Raw byte-level search for business keywords in non-UTF8 records.
                        let lower = str.lowercased()
                        shouldScrub = Self.constSectionScrubKeywords.contains(where: { lower.contains($0.lowercased()) })
                            || (lower.count > Self.riskSubstringMinLength && lower.contains("risk"))
                    }
                } else {
                    // Decoding failed: raw byte-level keyword match to avoid missing hits.
                    shouldScrub = Self.rawSliceContainsScrubKeyword(slice, length: length)
                        || SwiftSemanticLeakCatalog.rawSliceMatches(slice, length: length)
                }
                if shouldScrub {
                    try file.replaceBytes(
                        at: sectionFileOffset + UInt64(position),
                        with: randomHexBytes(count: length)
                    )
                    scrubbed += 1
                    bytes += length
                }
            }

            // Advance past null terminator (or past lone null bytes used as padding).
            position = end + 1
        }

        return (total, scrubbed, bytes)
    }

    // MARK: - Random Generation

    private static let hexTable: [UInt8] = Array("0123456789abcdef".utf8)

    private func randomHexBytes(count: Int) -> Data {
        Data((0..<count).map { _ in Self.hexTable[Int(rng.nextUInt64() % 16)] })
    }

    private func randomBytes(count: Int) -> Data {
        Data((0..<count).map { _ in UInt8(truncatingIfNeeded: rng.nextUInt64()) })
    }
}
