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

        let textHash = ArmorWhiteBox.sha256(try textSection.readContent(from: file.data))
        let lanes = ArmorABI.Integrity.splitAnchorLanes(for: textHash)
        let whiteboxBundle = ArmorWhiteBox.build(rootKey: config.encryptionKey)
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

        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.WhiteBox.Sections.metadata,
            content: whiteboxBundle.metadataSection,
            align: 3
        )

        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.WhiteBox.Sections.code,
            content: whiteboxBundle.whiteboxCode,
            align: 3
        )

        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.WhiteBox.Sections.data,
            content: whiteboxBundle.whiteboxData,
            align: 3
        )

        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.WhiteBox.Sections.tag,
            content: whiteboxBundle.whiteboxTag,
            align: 3
        )

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
