import Foundation

/// Reproduces the build-stable portion of
/// `cprisk_init_protection_whitebox_i` for post-link tooling.
///
/// At initialization, the string accumulator is reset and protected data is
/// installed lazily, so both accumulators are zero when runtime material is
/// derived. The resulting material is then passed through the same mini-VM
/// bootstrap transform as CRiskCore.
public enum ArmorRuntimeMaterialDeriver {
    public static func derive(from file: MachOFile, rootKey: Data) throws -> Data {
        guard rootKey.count == ArmorABI.keySize else {
            throw MachOError.invalidData("armor root key must be exactly \(ArmorABI.keySize) bytes")
        }

        let anchorHash = try readSplitAnchor(from: file)
        let bundle = ArmorWhiteBox.build(rootKey: rootKey)

        try verifySectionPrefix(
            file: file,
            sectionName: ArmorABI.WhiteBox.Sections.metadata,
            expected: bundle.metadataSection
        )
        try verifySectionPrefix(
            file: file,
            sectionName: ArmorABI.WhiteBox.Sections.code,
            expected: bundle.whiteboxCode
        )
        try verifySectionPrefix(
            file: file,
            sectionName: ArmorABI.WhiteBox.Sections.data,
            expected: bundle.whiteboxData
        )
        try verifySectionPrefix(
            file: file,
            sectionName: ArmorABI.WhiteBox.Sections.tag,
            expected: bundle.whiteboxTag
        )
        try verifySectionPrefix(
            file: file,
            sectionName: ArmorABI.Integrity.hmacFullHashSectionName,
            expected: bundle.prf(domain: .anchorTag, input: anchorHash)
        )

        let integrityHash = ArmorWhiteBox.sha256(anchorHash + anchorHash + anchorHash)
        var runtimeInput = Data()
        runtimeInput.append(anchorHash)
        runtimeInput.append(integrityHash)
        ArmorWhiteBox.appendLittleEndian(0, to: &runtimeInput) // string accumulator
        ArmorWhiteBox.appendLittleEndian(0, to: &runtimeInput) // data accumulator
        let runtimeDigest = ArmorWhiteBox.sha256(runtimeInput)
        let material = bundle.prf(domain: .runtimeMaterial, input: runtimeDigest)
        return ArmorABI.miniVMBootstrap(material)
    }

    private static func readSplitAnchor(from file: MachOFile) throws -> Data {
        var result = Data()
        result.reserveCapacity(ArmorABI.hashSize)
        for sectionName in ArmorABI.Integrity.splitSectionNames {
            guard let section = try file.section(
                segment: ArmorABI.dataSegmentName,
                section: sectionName
            ) else {
                throw MachOError.sectionNotFound(ArmorABI.dataSegmentName, sectionName)
            }
            let content = try section.readContent(from: file.data)
            guard content.count >= ArmorABI.Integrity.splitLaneSize else {
                throw MachOError.invalidData("split anchor section \(sectionName) is truncated")
            }
            result.append(content.prefix(ArmorABI.Integrity.splitLaneSize))
        }
        guard result.count == ArmorABI.hashSize else {
            throw MachOError.invalidData("split anchor did not reconstruct a 32-byte digest")
        }
        return result
    }

    private static func verifySectionPrefix(
        file: MachOFile,
        sectionName: String,
        expected: Data
    ) throws {
        guard let section = try file.section(
            segment: ArmorABI.dataSegmentName,
            section: sectionName
        ) else {
            throw MachOError.sectionNotFound(ArmorABI.dataSegmentName, sectionName)
        }
        let actual = try section.readContent(from: file.data)
        guard actual.count >= expected.count,
              Data(actual.prefix(expected.count)) == expected else {
            throw MachOError.invalidData(
                "root key/build seed does not match \(ArmorABI.dataSegmentName).\(sectionName)"
            )
        }
    }
}
