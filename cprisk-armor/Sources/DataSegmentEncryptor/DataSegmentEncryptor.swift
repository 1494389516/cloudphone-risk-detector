import CryptoKit
import Foundation
import MachOKit
import Security

private enum DataArmorSeed {
    static let blobMagic: UInt32 = 0x43504244
    static let accumulatorVersion: UInt32 = 2
    static let accumulatorRotation: UInt32 = 7
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
        var whiteboxRootKey = config.encryptionKey ?? Data(repeating: 0, count: ArmorABI.keySize)
        let whitebox = ArmorWhiteBox.build(rootKey: whiteboxRootKey)
        let anchorAccumulator = anchorBoundAccumulator(
            whitebox: whitebox,
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash
        )
        let loaderKey = deriveLoaderKey(
            whitebox: whitebox,
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash,
            anchorAccumulator: anchorAccumulator
        )

        let plaintextPayload = buildProtectedBlob(
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash,
            anchorAccumulator: anchorAccumulator
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

        var parentKey = loaderKey
        let defaultChainDepth: UInt32 = 1

        for section in targetSections {
            let plaintext = try section.readContent(from: file.data)
            let contentHash = sha256(plaintext)
            let keyID = stableKeyID(
                segment: section.segmentName,
                section: section.sectionName
            )
            let nonce = try generateNonce()
            let sectionIndex = UInt32(entries.count + 1)
            let sectionKey = deriveChainedKey(
                parentKey: parentKey,
                sectionIndex: sectionIndex,
                nonce: nonce,
                depth: defaultChainDepth
            )
            let encrypted = xor(
                plaintext,
                makeKeystream(key: sectionKey, keyID: keyID, nonce: nonce, length: plaintext.count)
            )
            try file.replaceBytes(at: UInt64(section.offset), with: encrypted)

            var hmacMessage = nonce
            hmacMessage.append(encrypted)
            let hmacTag = ArmorABI.hmacSHA256(key: sectionKey, message: hmacMessage)

            entries.append(ArmorABI.Loader.Entry(
                segmentName: section.segmentName,
                sectionName: section.sectionName,
                keyID: keyID,
                vmAddress: section.address,
                size: section.size,
                contentHash: contentHash,
                nonce: nonce,
                hmacTag: hmacTag,
                sectionIndex: sectionIndex,
                chainedKeyDepth: defaultChainDepth
            ))

            if !parentKey.isEmpty { parentKey.resetBytes(in: 0..<parentKey.count) }
            parentKey = sectionKey
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
        details.append(
            "Loader key is chained from the white-box accumulator seed plus pass4 anchor material"
        )

        if !parentKey.isEmpty { parentKey.resetBytes(in: 0..<parentKey.count) }
        if !whiteboxRootKey.isEmpty { whiteboxRootKey.resetBytes(in: 0..<whiteboxRootKey.count) }

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
        anchorAccumulator: UInt64
    ) -> Data {
        var payload = Data()
        appendUInt32(DataArmorSeed.blobMagic, to: &payload)
        appendUInt32(ArmorABI.version, to: &payload)
        appendUInt32(DataArmorSeed.accumulatorVersion, to: &payload)
        appendUInt32(DataArmorSeed.accumulatorRotation, to: &payload)
        payload.append(fullAnchorHash)
        payload.append(integrityHash)
        appendUInt64(anchorAccumulator, to: &payload)
        return payload
    }
}

package func anchorBoundAccumulator(
    rootKey: Data?,
    fullAnchorHash: Data,
    integrityHash: Data
) -> UInt64 {
    let whitebox = ArmorWhiteBox.build(rootKey: rootKey)
    return anchorBoundAccumulator(
        whitebox: whitebox,
        fullAnchorHash: fullAnchorHash,
        integrityHash: integrityHash
    )
}

package func deriveLoaderKey(
    rootKey: Data?,
    fullAnchorHash: Data,
    integrityHash: Data,
    anchorAccumulator: UInt64
) -> Data {
    let whitebox = ArmorWhiteBox.build(rootKey: rootKey)
    return deriveLoaderKey(
        whitebox: whitebox,
        fullAnchorHash: fullAnchorHash,
        integrityHash: integrityHash,
        anchorAccumulator: anchorAccumulator
    )
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

private func generateNonce() throws -> Data {
    var bytes = [UInt8](repeating: 0, count: ArmorABI.nonceSize)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    guard status == errSecSuccess else {
        throw MachOError.invalidData("SecRandomCopyBytes failed: \(status)")
    }
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

private func xor(_ lhs: Data, _ rhs: Data) -> Data {
    Data(zip(lhs, rhs).map(^))
}

private func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}

private func deriveChainedKey(
    parentKey: Data,
    sectionIndex: UInt32,
    nonce: Data,
    depth: UInt32
) -> Data {
    precondition(parentKey.count == ArmorABI.keySize, "parentKey must be 32 bytes")
    precondition(nonce.count == ArmorABI.nonceSize, "nonce must be 8 bytes")

    var material = Data()
    appendUInt32(sectionIndex, to: &material)
    material.append(nonce)

    var derived = ArmorABI.hmacSHA256(key: parentKey, message: material)
    if depth > 1 {
        for d in 1..<depth {
            derived = ArmorABI.hmacSHA256(
                key: derived,
                message: Data("cprisk.chained.v1.".utf8)
            )
            var depthMaterial = derived
            depthMaterial.append(UInt8(d))
            derived = ArmorABI.hmacSHA256(key: depthMaterial, message: depthMaterial)
        }
    }
    return derived
}

private func appendUInt32(_ value: UInt32, to data: inout Data) {
    var littleEndian = value.littleEndian
    withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
}

private func appendUInt64(_ value: UInt64, to data: inout Data) {
    var littleEndian = value.littleEndian
    withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
}

private func anchorBoundAccumulator(
    whitebox: ArmorWhiteBoxBundle,
    fullAnchorHash: Data,
    integrityHash: Data
) -> UInt64 {
    var digest = Data()
    digest.append(fullAnchorHash)
    digest.append(integrityHash)
    let accDigest = sha256(digest)
    let accSeed = whitebox.prf(domain: .anchorAccumulatorSeed, input: accDigest)
    let value = ArmorWhiteBox.littleEndianUInt64(from: accSeed)
    return ArmorWhiteBox.rotl64(value, by: Int(DataArmorSeed.accumulatorRotation))
}

private func deriveLoaderKey(
    whitebox: ArmorWhiteBoxBundle,
    fullAnchorHash: Data,
    integrityHash: Data,
    anchorAccumulator: UInt64
) -> Data {
    var digest = Data()
    digest.append(fullAnchorHash)
    digest.append(integrityHash)
    ArmorWhiteBox.appendLittleEndian(anchorAccumulator, to: &digest)
    let loaderDigest = sha256(digest)
    return whitebox.prf(domain: .loaderKey, input: loaderDigest)
}
