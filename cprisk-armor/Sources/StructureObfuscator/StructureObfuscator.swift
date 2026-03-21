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
        ArmorABI.Sections.antiDebugPlan,
    ]

    /// Decoy names that mimic Apple system / Swift runtime sections.
    /// Each must be ≤16 bytes (Mach-O section name field is char[16]).
    private static let decoySectionPool: [String] = [
        "__sw5_builtin2",
        "__sw5_capture2",
        "__sw5_typeref2",
        "__cpr_objc_inf2",
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
            let content = Self.generateStructuredContent(
                size: size,
                sectionName: sectionName,
                using: &rng
            )

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

    /// Build mixed-structure payloads with pointer-like lanes, dead-code-like
    /// words, and constrained entropy shaping to avoid synthetic signatures.
    private static func generateStructuredContent(
        size: Int,
        sectionName: String,
        using rng: inout SeededRNG
    ) -> Data {
        var data = Data(capacity: size)

        let magic = UInt32(truncatingIfNeeded: rng.next() ^ 0x4350_5345)
        let version = UInt32((rng.next() % 7) + 1)
        let flavor = UInt32((rng.next() % 3) + 1)
        let payloadBytes = size - 16
        let unitCount = UInt32(max(1, payloadBytes / 8))

        appendLE32(&data, magic)
        appendLE32(&data, version)
        appendLE32(&data, unitCount)
        appendLE32(&data, flavor)

        var laneIndex = 0
        while data.count < size {
            let laneType = Int((rng.next() ^ UInt64(laneIndex)) % 4)
            switch laneType {
            case 0:
                if data.count + 8 <= size {
                    // Pointer-like lane near canonical image ranges.
                    let base: UInt64 = (rng.next() & 1) == 0
                        ? 0x0000000100000000
                        : 0x0000000180000000
                    let ptr = base | (rng.next() & 0x0000000000FF_FC00)
                    appendLE64(&data, ptr)
                }
            case 1:
                if data.count + 4 <= size {
                    // Dead-code-like AArch64 words (NOP/ISB/ORR XZR patterns).
                    let deadWords: [UInt32] = [
                        0xD503_201F, // NOP
                        0xD503_3FDF, // ISB
                        0xAA1F_03E0, // MOV X0, XZR
                        0x8A1F_03FF, // AND XZR, XZR, XZR
                    ]
                    let word = deadWords[Int(rng.next() % UInt64(deadWords.count))]
                        ^ UInt32(truncatingIfNeeded: (rng.next() & 0x0000_0003) << 5)
                    appendLE32(&data, word)
                }
            case 2:
                let tokenPool = [
                    "__swift5",
                    "__objc",
                    "__auth",
                    "__stubs",
                    sectionName
                ]
                let token = tokenPool[Int(rng.next() % UInt64(tokenPool.count))]
                for b in token.utf8 where data.count < size {
                    data.append(b)
                }
                if data.count < size {
                    data.append(0)
                }
            default:
                if data.count < size {
                    data.append(UInt8(truncatingIfNeeded: rng.next() ^ 0xA5A5_A5A5))
                }
            }
            laneIndex += 1
        }

        if data.count > size {
            data.removeSubrange(size..<data.count)
        }

        // Entropy shaping: avoid low-entropy synthetic lanes and stable repeats.
        let entropy = approximateEntropy(data)
        if entropy < 4.2 {
            for index in stride(from: 0, to: data.count, by: 7) {
                data[index] ^= UInt8(truncatingIfNeeded: rng.next())
            }
        } else if entropy > 7.7 {
            for index in stride(from: 3, to: data.count, by: 11) {
                data[index] ^= UInt8((index * 29) & 0xFF)
            }
        }

        return Data(data.prefix(size))
    }

    private static func approximateEntropy(_ data: Data) -> Double {
        guard !data.isEmpty else { return 0 }
        var histogram = [Int](repeating: 0, count: 256)
        for byte in data {
            histogram[Int(byte)] += 1
        }

        let length = Double(data.count)
        var entropy = 0.0
        for count in histogram where count > 0 {
            let p = Double(count) / length
            entropy -= p * log2(p)
        }
        return entropy
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
