import Foundation
import MachOKit
import Security

/// SplitMix64 — deterministic PRNG for reproducible obfuscation across runs.
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

/// Pass 5: Obfuscate the Mach-O structure to frustrate static analysis tools
/// (IDA, Hopper, etc.) by injecting decoy sections with structured fake data.
///
/// This pass must preserve ArmorABI-reserved sections consumed by CRiskCore.
public final class StructureObfuscatorPass: ArmorPass {
    public let name = "StructureObfuscator"

    private static let reservedSections: Set<String> = [
        ArmorABI.Sections.stringTable,
        ArmorABI.Sections.loader,
        ArmorABI.Sections.protectedBlob,
        ArmorABI.Sections.anchorA,
        ArmorABI.Sections.anchorB,
        ArmorABI.Sections.anchorC,
        ArmorABI.Sections.anchorD,
        ArmorABI.Sections.fullAnchorHash,
    ]

    /// Decoy names that mimic Apple system / Swift runtime sections.
    /// Each must be ≤16 bytes (Mach-O section name field is char[16]).
    private static let decoySectionPool: [String] = [
        "__sw5_builtin2",
        "__sw5_capture2",
        "__sw5_typeref2",
        "__objc_imageinfo",
        "__la_resolver2",
        "__stub_helper2",
        "__auth_got2",
        "__nl_catlist",
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

        let seed: UInt64
        if let provided = config.randomSeed {
            seed = provided
        } else {
            var randomBytes: UInt64 = 0
            let status = SecRandomCopyBytes(kSecRandomDefault, MemoryLayout<UInt64>.size, &randomBytes)
            guard status == errSecSuccess else {
                throw MachOError.invalidData("SecRandomCopyBytes failed: \(status)")
            }
            seed = randomBytes == 0 ? 1 : randomBytes
        }
        if config.verbose { print("    [StructureObfuscator] seed = \(seed)") }
        var rng = SeededRNG(seed: seed)

        let count = 5 + Int(rng.next() % 4)
        var pool = Self.decoySectionPool
        pool.shuffle(using: &rng)
        let selectedNames = Array(pool.prefix(count))

        var injectedCount = 0
        var totalBytes = 0
        var details = [String]()

        for sectionName in selectedNames {
            if Self.reservedSections.contains(sectionName) { continue }
            if (try? file.section(segment: ArmorABI.dataSegmentName, section: sectionName)) != nil {
                continue
            }

            let units = 8 + Int(rng.next() % 57)
            let size = units * 8
            let content = Self.generateStructuredContent(size: size, using: &rng)

            try file.addOrUpdateSection(
                segment: ArmorABI.dataSegmentName,
                section: sectionName,
                content: content,
                align: 3,
                flags: 0
            )

            injectedCount += 1
            totalBytes += content.count
            details.append("Injected __DATA.\(sectionName) (\(content.count) bytes)")
        }

        details.append("Random seed: \(seed)")

        return PassResult(
            passName: name,
            itemsProcessed: injectedCount,
            bytesModified: totalBytes,
            details: details
        )
    }

    /// Build structured random data that mimics real section content:
    ///   [magic:4][version:4][count:4][pointer-like values:N×8]
    /// This fools tools that apply heuristics on section payloads.
    private static func generateStructuredContent(size: Int, using rng: inout SeededRNG) -> Data {
        var data = Data(capacity: size)

        let magic = UInt32(truncatingIfNeeded: rng.next())
        let version = UInt32(rng.next() % 16 + 1)
        let payloadBytes = size - 12
        let pointerCount = UInt32(max(1, payloadBytes / 8))

        appendLE32(&data, magic)
        appendLE32(&data, version)
        appendLE32(&data, pointerCount)

        while data.count + 8 <= size {
            let ptr: UInt64 = 0x0000000100000000 | (rng.next() & 0x00000000FFFFFE00)
            appendLE64(&data, ptr)
        }

        while data.count < size {
            data.append(UInt8(truncatingIfNeeded: rng.next()))
        }

        return data
    }

    private static func appendLE32(_ data: inout Data, _ value: UInt32) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }
    }

    private static func appendLE64(_ data: inout Data, _ value: UInt64) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }
    }
}
