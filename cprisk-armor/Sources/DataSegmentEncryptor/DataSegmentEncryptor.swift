import CryptoKit
import Foundation
import MachOKit

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

        let protectedSection = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Loader.protectedSectionName,
            content: plaintextPayload,
            align: 3
        )
        let protectedPlaintext = try protectedSection.readContent(from: file.data)
        let keyID = stableKeyID(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Loader.protectedSectionName
        )
        let encryptedPayload = xor(
            protectedPlaintext,
            makeKeystream(key: loaderKey, keyID: keyID, length: protectedPlaintext.count)
        )
        try file.replaceBytes(at: UInt64(protectedSection.offset), with: encryptedPayload)

        var loaderPayload = ArmorABI.Loader.Header(count: 1).serialized()
        loaderPayload.append(
            ArmorABI.Loader.Entry(
                segmentName: ArmorABI.dataSegmentName,
                sectionName: ArmorABI.Loader.protectedSectionName,
                keyID: keyID,
                vmAddress: protectedSection.address,
                size: protectedSection.size,
                contentHash: sha256(protectedPlaintext)
            ).serialized()
        )

        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Loader.sectionName,
            content: loaderPayload,
            align: 3
        )

        return PassResult(
            passName: name,
            itemsProcessed: 1,
            bytesModified: protectedPlaintext.count + loaderPayload.count,
            details: [
                "Encrypted \(ArmorABI.dataSegmentName).\(ArmorABI.Loader.protectedSectionName) in place",
                "Wrote runtime loader descriptor to \(ArmorABI.dataSegmentName).\(ArmorABI.Loader.sectionName)",
                "Loader key is chained from pass1 bootstrap accumulator and pass4 anchor material"
            ]
        )
    }

    private func readFullAnchorHash(from file: MachOFile) throws -> Data {
        guard let section = try file.section(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Integrity.fullHashSectionName
        ) else {
            throw MachOError.sectionNotFound(ArmorABI.dataSegmentName, ArmorABI.Integrity.fullHashSectionName)
        }

        let content = try section.readContent(from: file.data)
        guard content.count >= ArmorABI.Integrity.fullHashSectionSize else {
            throw MachOError.invalidData("Integrity full-hash section is truncated")
        }

        let mask = content.prefix(ArmorABI.hashSize)
        let masked = content.dropFirst(ArmorABI.hashSize).prefix(ArmorABI.hashSize)
        return Data(zip(mask, masked).map(^))
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

private func makeKeystream(key: Data, keyID: UInt32, length: Int) -> Data {
    var seed = Data()
    seed.append(key)
    appendUInt32(keyID, to: &seed)

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
