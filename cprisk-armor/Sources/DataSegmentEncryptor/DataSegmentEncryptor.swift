import CryptoKit
import Foundation
import MachOKit
import Security

private enum DataArmorSeed {
    static let bootstrapID: UInt32 = 1
    // Build-tool only — this literal does not appear in the final SDK binary.
    static let bootstrapValue = "cprisk-bootstrap-v1"
    static let blobMagic: UInt32 = 0x43504244
}

/// Pass 3: emit a minimal real protected `__DATA` payload and loader descriptor.
///
/// To keep the closure safe, this pass encrypts a dedicated custom payload section
/// instead of mutating arbitrary live app globals. Runtime still has to parse the
/// loader descriptor, validate the target section, and decrypt the bytes in place.
public final class DataSegmentEncryptorPass: ArmorPass {
    public let name = "DataSegmentEncryptor"

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        let fullAnchorHash = try readFullAnchorHash(from: file)
        let integrityHash = sha256(fullAnchorHash + fullAnchorHash + fullAnchorHash)
        let stringAccumulator = bootstrapAccumulator()
        let loaderKey = deriveLoaderKey(
            rootKey: config.encryptionKey,
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash,
            stringAccumulator: stringAccumulator
        )

        let plaintextPayload = buildProtectedBlob(
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash,
            stringAccumulator: stringAccumulator
        )

        try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Loader.protectedSectionName,
            content: plaintextPayload,
            align: 3
        )

        guard let dataSegment = try file.segment(named: ArmorABI.dataSegmentName) else {
            throw MachOError.segmentNotFound(ArmorABI.dataSegmentName)
        }

        let targetSections = dataSegment.sections.filter { section in
            ArmorABI.DataEncryption.isEncryptable(section.sectionName)
                && section.storesDataInFile
                && section.size > 0
        }

        var entries = [ArmorABI.Loader.Entry]()
        var totalBytesEncrypted = 0
        var details = [String]()

        for section in targetSections {
            let plaintext = try section.readContent(from: file.data)
            let contentHash = sha256(plaintext)
            let keyID = stableKeyID(
                segment: section.segmentName,
                section: section.sectionName
            )
            let nonce = generateNonce()
            let encrypted = xor(
                plaintext,
                makeKeystream(key: loaderKey, keyID: keyID, nonce: nonce, length: plaintext.count)
            )
            try file.replaceBytes(at: UInt64(section.offset), with: encrypted)

            var hmacMessage = nonce
            hmacMessage.append(encrypted)
            let hmacTag = ArmorABI.hmacSHA256(key: loaderKey, message: hmacMessage)

            entries.append(ArmorABI.Loader.Entry(
                segmentName: section.segmentName,
                sectionName: section.sectionName,
                keyID: keyID,
                vmAddress: section.address,
                size: section.size,
                contentHash: contentHash,
                nonce: nonce,
                hmacTag: hmacTag
            ))

            totalBytesEncrypted += plaintext.count
            details.append(
                "Encrypted \(section.segmentName).\(section.sectionName) (\(plaintext.count) bytes)"
            )
        }

        var loaderPayload = ArmorABI.Loader.Header(count: UInt32(entries.count)).serialized()
        for entry in entries {
            loaderPayload.append(entry.serialized())
        }

        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Loader.sectionName,
            content: loaderPayload,
            align: 3
        )

        details.append(
            "Wrote loader descriptor (\(entries.count) entries) to "
                + "\(ArmorABI.dataSegmentName).\(ArmorABI.Loader.sectionName)"
        )
        details.append("Loader key is chained from pass1 bootstrap accumulator and pass4 anchor material")

        return PassResult(
            passName: name,
            itemsProcessed: entries.count,
            bytesModified: totalBytesEncrypted + loaderPayload.count,
            details: details
        )
    }

    private func readFullAnchorHash(from file: MachOFile) throws -> Data {
        var digest = Data(repeating: 0, count: ArmorABI.hashSize)
        for (i, name) in ArmorABI.Integrity.splitSectionNames.enumerated() {
            guard let section = try file.section(
                segment: ArmorABI.dataSegmentName,
                section: name
            ) else {
                throw MachOError.sectionNotFound(ArmorABI.dataSegmentName, name)
            }
            let lane = try section.readContent(from: file.data)
            guard lane.count >= ArmorABI.Integrity.splitLaneSize else {
                throw MachOError.invalidData("Split anchor lane \(name) is truncated")
            }
            let offset = i * ArmorABI.Integrity.splitLaneSize
            digest.replaceSubrange(offset..<(offset + ArmorABI.Integrity.splitLaneSize),
                                   with: lane.prefix(ArmorABI.Integrity.splitLaneSize))
        }
        return digest
    }

    private func buildProtectedBlob(
        fullAnchorHash: Data,
        integrityHash: Data,
        stringAccumulator: UInt64
    ) -> Data {
        var payload = Data()
        appendUInt32(DataArmorSeed.blobMagic, to: &payload)
        appendUInt32(ArmorABI.version, to: &payload)
        appendUInt32(DataArmorSeed.bootstrapID, to: &payload)
        appendUInt32(1, to: &payload)
        payload.append(fullAnchorHash)
        payload.append(integrityHash)
        appendUInt64(stringAccumulator, to: &payload)
        return payload
    }

    private func bootstrapAccumulator() -> UInt64 {
        let digest = sha256(Data(DataArmorSeed.bootstrapValue.utf8))
        var value: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &value) { target in
            digest.prefix(MemoryLayout<UInt64>.size).copyBytes(to: target)
        }
        return rotl64(value, by: Int(DataArmorSeed.bootstrapID % 64))
    }
}

// Build-tool only — this salt does not appear in the final SDK binary.
private func deriveLoaderKey(
    rootKey: Data?,
    fullAnchorHash: Data,
    integrityHash: Data,
    stringAccumulator: UInt64
) -> Data {
    var seed = Data("cprisk.pass3.key.v1".utf8)
    seed.append(normalizedRootKey(rootKey))
    seed.append(fullAnchorHash)
    seed.append(integrityHash)
    appendUInt64(stringAccumulator, to: &seed)
    return sha256(seed)
}

private func stableKeyID(segment: String, section: String) -> UInt32 {
    let bytes = Array("\(segment).\(section)".utf8)
    var hash: UInt32 = 2166136261
    for byte in bytes {
        hash ^= UInt32(byte)
        hash &*= 16777619
    }
    return hash
}

private func generateNonce() -> Data {
    var bytes = [UInt8](repeating: 0, count: ArmorABI.nonceSize)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
    return Data(bytes)
}

private func makeKeystream(key: Data, keyID: UInt32, nonce: Data, length: Int) -> Data {
    var seed = Data()
    seed.append(key)
    appendUInt32(keyID, to: &seed)
    seed.append(nonce)

    var block = sha256(seed)
    var output = Data()
    output.reserveCapacity(length)

    while output.count < length {
        let remaining = length - output.count
        output.append(block.prefix(remaining))
        if output.count < length {
            block = sha256(block)
        }
    }
    return output
}

private func rotl64(_ value: UInt64, by amount: Int) -> UInt64 {
    guard amount != 0 else { return value }
    return (value << amount) | (value >> (64 - amount))
}

private func xor(_ lhs: Data, _ rhs: Data) -> Data {
    Data(zip(lhs, rhs).map(^))
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

private func appendUInt32(_ value: UInt32, to data: inout Data) {
    var littleEndian = value.littleEndian
    withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
}

private func appendUInt64(_ value: UInt64, to data: inout Data) {
    var littleEndian = value.littleEndian
    withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
}
