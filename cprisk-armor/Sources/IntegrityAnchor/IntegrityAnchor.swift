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

        guard let rootKey = config.encryptionKey else {
            throw MachOError.invalidData(
                "IntegrityAnchorPass requires an encryption key (no zero/default key fallback)"
            )
        }

        let textHash = ArmorWhiteBox.sha256(try textSection.readContent(from: file.data))
        let lanes = ArmorABI.Integrity.splitAnchorLanes(for: textHash)
        let whiteboxBundle = try ArmorWhiteBox.build(rootKey: rootKey)
        let anchorTag = whiteboxBundle.prf(domain: .anchorTag, input: textHash)

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
            section: ArmorABI.Integrity.hmacFullHashSectionName,
            content: ArmorABI.Integrity.anchorTagSection(anchorTag),
            align: 3
        )

        // White-box sections are REQUIRED placeholders: the runtime verifies
        // the white-box bundle (metadata/code/data/tag) against the anchor.
        // A missing placeholder is an explicit hard failure — never skip
        // silently, or the binary would ship with anchor lanes but no
        // white-box bundle and the runtime would reject (or silently
        // distrust) the anchor chain.
        let requiredWhiteboxSections = [
            ArmorABI.WhiteBox.Sections.metadata,
            ArmorABI.WhiteBox.Sections.code,
            ArmorABI.WhiteBox.Sections.data,
            ArmorABI.WhiteBox.Sections.tag,
        ]
        var missingWhiteboxSections: [String] = []
        for section in requiredWhiteboxSections {
            if try file.section(segment: ArmorABI.dataSegmentName, section: section) == nil {
                missingWhiteboxSections.append("\(ArmorABI.dataSegmentName).\(section)")
            }
        }
        guard missingWhiteboxSections.isEmpty else {
            throw MachOError.invalidData(
                "IntegrityAnchorPass: missing required white-box placeholder section(s): "
                + missingWhiteboxSections.joined(separator: ", ")
                + ". Link the white-box placeholders (or add them to the link) before running Pass 4."
            )
        }
        func writeIfPresent(_ section: String, _ content: Data) throws {
            _ = try file.addOrUpdateSection(
                segment: ArmorABI.dataSegmentName,
                section: section,
                content: content,
                align: 3
            )
        }
        try writeIfPresent(ArmorABI.WhiteBox.Sections.metadata, whiteboxBundle.metadataSection)
        try writeIfPresent(ArmorABI.WhiteBox.Sections.code, whiteboxBundle.whiteboxCode)
        try writeIfPresent(ArmorABI.WhiteBox.Sections.data, whiteboxBundle.whiteboxData)
        try writeIfPresent(ArmorABI.WhiteBox.Sections.tag, whiteboxBundle.whiteboxTag)

        return PassResult(
            passName: name,
            itemsProcessed: ArmorABI.Integrity.splitSectionCount + 5,
            bytesModified: lanes.reduce(
                anchorTag.count
                    + whiteboxBundle.metadataSection.count
                    + whiteboxBundle.whiteboxCode.count
                    + whiteboxBundle.whiteboxData.count
                    + whiteboxBundle.whiteboxTag.count
            ) { $0 + $1.count },
            details: [
                "Anchored SHA-256(__TEXT.__text) into \(ArmorABI.Integrity.splitSectionNames.joined(separator: ", "))",
                "Wrote white-box anchor tag to \(ArmorABI.dataSegmentName).\(ArmorABI.Integrity.hmacFullHashSectionName)",
                "Wrote white-box metadata/code/data/tag sections to \(ArmorABI.dataSegmentName)"
            ]
        )
    }
}
