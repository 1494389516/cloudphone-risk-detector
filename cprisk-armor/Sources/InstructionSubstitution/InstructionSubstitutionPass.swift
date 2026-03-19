import Foundation
import MachOKit

private enum InstructionSubstitutionSeedOrigin {
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

public final class InstructionSubstitutionPass: ArmorPass {
    public static let defaultReplacementRate = 0.40
    public static let defaultOpaquePredicateRate = 0.15
    public static let defaultDeadCodeIslandRate = 0.08

    public let name = "InstructionSubstitution"

    private let replacementRate: Double
    private let opaquePredicateRate: Double
    private let deadCodeIslandRate: Double
    private let engine: SubstitutionEngine

    public init(
        replacementRate: Double = InstructionSubstitutionPass.defaultReplacementRate,
        opaquePredicateRate: Double = InstructionSubstitutionPass.defaultOpaquePredicateRate,
        deadCodeIslandRate: Double = InstructionSubstitutionPass.defaultDeadCodeIslandRate
    ) {
        self.replacementRate = min(max(replacementRate, 0), 1)
        self.opaquePredicateRate = min(max(opaquePredicateRate, 0), 1)
        self.deadCodeIslandRate = min(max(deadCodeIslandRate, 0), 1)
        self.engine = SubstitutionEngine()
    }

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        guard (try? file.segment(named: "__TEXT")) != nil,
              let textSection = try file.section(segment: "__TEXT", section: "__text") else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["Skipped: __TEXT.__text not found"]
            )
        }

        let (seed, seedOrigin) = try resolveSeed(for: file, config: config, textSection: textSection)
        if config.verbose {
            print("    [InstructionSubstitution] seed = \(seed)")
        }

        let report = try engine.apply(
            to: file,
            configuration: SubstitutionEngine.Configuration(
                replacementRate: replacementRate,
                opaquePredicateRate: opaquePredicateRate,
                deadCodeIslandRate: deadCodeIslandRate,
                seed: seed
            )
        )

        var details = [
            "Scanned \(report.scannedInstructionCount) 4-byte slots in __TEXT.__text",
            "Eligible substitutions: \(report.eligibleCandidateCount)",
            String(format: "Configured replacement rate: %.0f%%", replacementRate * 100),
            String(format: "Opaque predicate rate: %.0f%%", opaquePredicateRate * 100),
            String(format: "Dead-code island rate: %.0f%%", deadCodeIslandRate * 100),
            "Seed: \(seed) (\(seedOrigin.description))",
        ]

        if report.skippedDataInCodeRangeCount > 0 {
            details.append("Skipped \(report.skippedDataInCodeRangeCount) LC_DATA_IN_CODE ranges")
        }

        if report.appliedCount == 0 {
            details.append("Applied no substitutions/injections")
        } else {
            details.append("Applied \(report.appliedCount) total equal-length rewrites")
            for group in InstructionSubstitutionGroup.allCases {
                let count = report.appliedGroupCounts[group, default: 0]
                if count > 0 {
                    details.append("\(group.summaryLabel): \(count) \(group.detailLabel)")
                }
            }
            if !report.injectedOpaquePredicates.isEmpty {
                details.append("Opaque predicates injected: \(report.injectedOpaquePredicates.count)")
            }
            if !report.injectedDeadCodeIslands.isEmpty {
                details.append("Dead-code islands injected: \(report.injectedDeadCodeIslands.count)")
            }
        }

        if config.verbose {
            let textBaseOffset = UInt64(textSection.offset)
            for entry in report.appliedSubstitutions.prefix(12) {
                let relativeOffset = entry.fileOffset - textBaseOffset
                details.append(String(
                    format: "%@ @ __text+0x%llX: 0x%08X -> 0x%08X (%@)",
                    entry.group.summaryLabel,
                    relativeOffset,
                    entry.originalRawValue,
                    entry.replacementRawValue,
                    entry.description
                ))
            }
            for entry in report.injectedOpaquePredicates.prefix(6) {
                let relativeOffset = entry.fileOffset - textBaseOffset
                details.append(String(
                    format: "Opaque predicate @ __text+0x%llX: 0x%08X -> 0x%08X (%@)",
                    relativeOffset,
                    entry.originalRawValue,
                    entry.replacementRawValue,
                    entry.description
                ))
            }
            for entry in report.injectedDeadCodeIslands.prefix(6) {
                let relativeOffset = entry.branchFileOffset - textBaseOffset
                details.append(String(
                    format: "Dead-code island @ __text+0x%llX: gate 0x%08X -> 0x%08X, dead 0x%08X -> 0x%08X",
                    relativeOffset,
                    entry.originalBranchRawValue,
                    entry.replacementBranchRawValue,
                    entry.originalDeadRawValue,
                    entry.replacementDeadRawValue
                ))
            }
        }

        return PassResult(
            passName: name,
            itemsProcessed: report.appliedCount,
            bytesModified: report.bytesModified,
            details: details
        )
    }

    private func resolveSeed(
        for file: MachOFile,
        config: PassConfig,
        textSection: Section
    ) throws -> (UInt64, InstructionSubstitutionSeedOrigin) {
        if let providedSeed = config.randomSeed {
            return (derivePassSeed(from: providedSeed), .config)
        }

        var hash = FNV1A64.offsetBasis
        hash = mix(hash, string: name)
        hash = mix(hash, value: textSection.address)
        hash = mix(hash, value: textSection.size)
        hash = mix(hash, value: UInt64(textSection.offset))

        let textContent = try textSection.readContent(from: file.data)
        for byte in textContent.prefix(256) {
            hash ^= UInt64(byte)
            hash &*= FNV1A64.prime
        }

        let symbols = try file.readSymbols()
        for symbol in symbols.prefix(16) where !symbol.name.isEmpty {
            hash = mix(hash, string: symbol.name)
            hash = mix(hash, value: symbol.nlist.n_value)
        }

        let seed = hash == 0 ? 1 : hash
        return (seed, .binary)
    }

    private func derivePassSeed(from baseSeed: UInt64) -> UInt64 {
        var hash = FNV1A64.offsetBasis
        hash = mix(hash, value: baseSeed == 0 ? 1 : baseSeed)
        hash = mix(hash, string: name)
        return hash == 0 ? 1 : hash
    }
}

private enum FNV1A64 {
    static let offsetBasis: UInt64 = 0xCBF2_9CE4_8422_2325
    static let prime: UInt64 = 0x0000_0100_0000_01B3
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
    return Swift.withUnsafeBytes(of: &littleEndian) { rawBuffer in
        var mixed = hash
        for byte in rawBuffer {
            mixed ^= UInt64(byte)
            mixed &*= FNV1A64.prime
        }
        return mixed
    }
}
