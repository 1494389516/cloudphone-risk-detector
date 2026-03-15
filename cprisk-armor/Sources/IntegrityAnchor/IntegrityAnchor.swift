import CryptoKit
import Foundation
import MachOKit

/// Pass 4: emit real integrity anchors consumed by CRiskCore.
///
/// The minimal ABI keeps runtime path C alive by materializing four split lanes
/// plus the masked full-hash section. The digest itself is the SHA-256 of
/// `__TEXT.__text`, which keeps producer and runtime semantics aligned.
public final class IntegrityAnchorPass: ArmorPass {
    public let name = "IntegrityAnchor"

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        guard let textSection = try file.section(segment: "__TEXT", section: "__text") else {
            throw MachOError.sectionNotFound("__TEXT", "__text")
        }

        let textHash = sha256(try textSection.readContent(from: file.data))
        // Build-tool only — this salt does not appear in the final SDK binary.
        let mask = sha256(Data("cprisk.pass4.mask.v1".utf8) + textHash)
        let lanes = ArmorABI.Integrity.splitAnchorLanes(for: textHash)
        let fullHashSection = ArmorABI.Integrity.maskedFullHashSection(mask: mask, fullHash: textHash)

        for (name, lane) in zip(ArmorABI.Integrity.splitSectionNames, lanes) {
            _ = try file.addOrUpdateSection(
                segment: ArmorABI.dataSegmentName,
                section: name,
                content: lane,
                align: 3
            )
        }

        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Integrity.fullHashSectionName,
            content: fullHashSection,
            align: 3
        )

        return PassResult(
            passName: name,
            itemsProcessed: ArmorABI.Integrity.splitSectionCount + 1,
            bytesModified: lanes.reduce(fullHashSection.count) { $0 + $1.count },
            details: [
                "Anchored SHA-256(__TEXT.__text) into \(ArmorABI.Integrity.splitSectionNames.joined(separator: ", "))",
                "Wrote masked full hash to \(ArmorABI.dataSegmentName).\(ArmorABI.Integrity.fullHashSectionName)"
            ]
        )
    }
}

private func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}
