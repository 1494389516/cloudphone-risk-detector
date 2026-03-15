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
        let rootKey = normalizedRootKey(config.encryptionKey)
        let lanes = ArmorABI.Integrity.splitAnchorLanes(for: textHash)
        let hmacSection = ArmorABI.Integrity.hmacFullHashSection(rootKey: rootKey, fullHash: textHash)

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
            content: hmacSection,
            align: 3
        )

        return PassResult(
            passName: name,
            itemsProcessed: ArmorABI.Integrity.splitSectionCount + 1,
            bytesModified: lanes.reduce(hmacSection.count) { $0 + $1.count },
            details: [
                "Anchored SHA-256(__TEXT.__text) into \(ArmorABI.Integrity.splitSectionNames.joined(separator: ", "))",
                "Wrote HMAC anchor to \(ArmorABI.dataSegmentName).\(ArmorABI.Integrity.hmacFullHashSectionName)"
            ]
        )
    }
}

private func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}

private func normalizedRootKey(_ rootKey: Data?) -> Data {
    var key = Data(repeating: 0, count: ArmorABI.keySize)
    guard let rootKey else { return key }
    let prefix = rootKey.prefix(ArmorABI.keySize)
    key.replaceSubrange(0..<prefix.count, with: prefix)
    return key
}
