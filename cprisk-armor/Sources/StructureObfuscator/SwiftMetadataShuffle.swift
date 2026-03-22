import Foundation
import MachOKit

/// SplitMix64 — shared with `StructureObfuscator` for deterministic builds.
struct SeededRNG: RandomNumberGenerator {
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

/// Fisher–Yates permutation of `0..<n` using `subseed` (SplitMix64 state).
func swiftShufflePermutation(entryCount n: Int, subseed: UInt64) -> [Int] {
    precondition(n >= 0)
    guard n > 1 else { return Array(0..<n) }
    var rng = SeededRNG(seed: subseed)
    var perm = Array(0..<n)
    for i in stride(from: n - 1, through: 1, by: -1) {
        let j = Int(rng.next() % UInt64(i + 1))
        perm.swapAt(i, j)
    }
    return perm
}

/// FNV-1a 64-bit — stable across Swift runs (same as documented for optional C restore).
func fnv1a64Combine(base: UInt64, string: String) -> UInt64 {
    var h = base &+ 0xCBF29CE484222325
    for b in string.utf8 {
        h ^= UInt64(b)
        h &*= 0x100000001B3
    }
    return h == 0 ? 1 : h
}

func deriveSwiftShuffleSubseed(segment: String, section: String, masterSeed: UInt64) -> UInt64 {
    var h = fnv1a64Combine(base: masterSeed, string: segment)
    h = fnv1a64Combine(base: h, string: section)
    return h == 0 ? 1 : h
}

enum SwiftMetadataShuffle {

    private static let targets: [(segment: String, section: String)] = [
        ("__TEXT", ArmorABI.MetadataSections.swiftTypes),
        ("__TEXT", ArmorABI.MetadataSections.swiftProtocols),
        ("__TEXT", ArmorABI.MetadataSections.swiftFieldMetadata),
        ("__DATA", ArmorABI.MetadataSections.swiftTypes),
        ("__DATA", ArmorABI.MetadataSections.swiftProtocols),
        ("__DATA", ArmorABI.MetadataSections.swiftFieldMetadata),
    ]

    /// Reorder Swift relative-pointer tables and re-encode offsets so each slot still resolves to
    /// the same absolute target as before (multiset of target addresses preserved).
    static func applyDescriptorTableShuffles(
        to file: MachOFile,
        buildSeed: UInt64
    ) throws -> (items: Int, bytes: Int, details: [String]) {
        var records = [ShuffleRecord]()
        var details = [String]()
        var bytes = 0

        for target in targets {
            guard let section = try file.section(segment: target.segment, section: target.section) else {
                continue
            }
            guard section.size >= 8, section.size % 4 == 0 else { continue }
            guard section.size <= UInt64(Int.max) else { continue }
            let n = Int(section.size) / 4
            guard n >= 2 else { continue }

            let sectionOffset = Int(section.offset)
            var targetAbsolutes = [Int]()
            targetAbsolutes.reserveCapacity(n)

            for i in 0..<n {
                let slotOff = sectionOffset + i * 4
                let rel = try file.readUInt32(at: slotOff)
                let relSigned = Int32(bitPattern: rel)
                let slotAbs = slotOff
                let targetAbs = slotAbs + 4 + Int(relSigned)
                targetAbsolutes.append(targetAbs)
            }

            let subseed = deriveSwiftShuffleSubseed(
                segment: target.segment,
                section: target.section,
                masterSeed: buildSeed
            )
            let perm = swiftShufflePermutation(entryCount: n, subseed: subseed)

            var newRels = [Int32]()
            newRels.reserveCapacity(n)
            var valid = true
            for i in 0..<n {
                let slotOff = sectionOffset + i * 4
                let sourceIndex = perm[i]
                let targetAbs = targetAbsolutes[sourceIndex]
                let newDelta = targetAbs - (slotOff + 4)
                guard newDelta >= Int(Int32.min), newDelta <= Int(Int32.max) else {
                    details.append(
                        "Swift shuffle skipped \(target.segment).\(target.section): relative overflow at slot \(i)"
                    )
                    valid = false
                    break
                }
                newRels.append(Int32(truncatingIfNeeded: newDelta))
            }
            guard valid, newRels.count == n else { continue }

            for i in 0..<n {
                let slotOff = sectionOffset + i * 4
                try file.writeUInt32(UInt32(bitPattern: newRels[i]), at: slotOff)
                bytes += 4
            }

            records.append(
                ShuffleRecord(
                    segment: target.segment,
                    section: target.section,
                    fileOffset: UInt32(section.offset),
                    entryCount: UInt32(n),
                    subseed: subseed
                )
            )
            details.append(
                "Swift descriptor shuffle: \(target.segment).\(target.section) (\(n) slots, rel re-encoded)"
            )
        }

        if !records.isEmpty {
            let payload = try serializeMapping(buildSeed: buildSeed, records: records)
            let label = try writeMappingBlob(to: file, payload: payload)
            bytes += payload.count
            details.append("Swift shuffle mapping: \(payload.count) bytes → \(label)")
        }

        return (records.count, bytes, details)
    }

    private struct ShuffleRecord {
        let segment: String
        let section: String
        let fileOffset: UInt32
        let entryCount: UInt32
        let subseed: UInt64
    }

    private static func serializeMapping(buildSeed: UInt64, records: [ShuffleRecord]) throws -> Data {
        let H = ArmorABI.SwiftMetadataDescriptorShuffle.headerSize
        let R = ArmorABI.SwiftMetadataDescriptorShuffle.recordSize
        let total = H + records.count * R
        guard total <= 16 * 1024 * 1024 else {
            throw MachOError.invalidData("Swift shuffle mapping payload too large")
        }

        var data = Data()
        data.reserveCapacity(total)

        func appendLE32(_ v: UInt32) {
            var le = v.littleEndian
            Swift.withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }
        }
        func appendLE64(_ v: UInt64) {
            var le = v.littleEndian
            Swift.withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }
        }

        appendLE32(ArmorABI.SwiftMetadataDescriptorShuffle.magic)
        appendLE32(ArmorABI.SwiftMetadataDescriptorShuffle.abiVersion)
        appendLE32(0) // flags
        appendLE32(UInt32(records.count))
        appendLE64(buildSeed)
        appendLE64(0) // reserved — header is 32 bytes

        for rec in records {
            var seg = Array(rec.segment.utf8.prefix(16))
            while seg.count < 16 { seg.append(0) }
            data.append(contentsOf: seg)

            var sect = Array(rec.section.utf8.prefix(16))
            while sect.count < 16 { sect.append(0) }
            data.append(contentsOf: sect)

            appendLE32(rec.fileOffset)
            appendLE32(rec.entryCount)
            appendLE64(rec.subseed)
        }

        precondition(data.count == total)
        return data
    }

    private static func writeMappingBlob(to file: MachOFile, payload: Data) throws -> String {
        let chain = ArmorABI.Sections.chainMeta
        let fallback = ArmorABI.Sections.swiftMetadataMap

        if let existing = try file.section(segment: ArmorABI.dataSegmentName, section: chain),
           Int(existing.size) >= payload.count {
            var padded = payload
            if padded.count < Int(existing.size) {
                padded.append(Data(count: Int(existing.size) - padded.count))
            }
            try file.replaceBytes(at: UInt64(existing.offset), with: padded)
            return "\(ArmorABI.dataSegmentName).\(chain)"
        }

        try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: fallback,
            content: payload,
            align: 3,
            flags: 0
        )
        return "\(ArmorABI.dataSegmentName).\(fallback)"
    }
}
