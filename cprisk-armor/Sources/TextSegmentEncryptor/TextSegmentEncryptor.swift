import CryptoKit
import Foundation
import MachOKit
import Security

private enum TextArmorSeed {
    static let accumulatorVersion: UInt32 = 2
    static let accumulatorRotation: UInt32 = 7
}

/// Pass 12: encrypts a conservative inner range of `__TEXT,__text` at page granularity
/// (skips first and last page) and emits `__DATA` text-encryption metadata (`ArmorABI.Sections.textEncryption`) for CRiskCore.
public final class TextSegmentEncryptorPass: ArmorPass {
    public let name = "TextSegmentEncryptor"

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        let fullAnchorHash = try readFullAnchorHash(from: file)
        let integrityHash = sha256(fullAnchorHash + fullAnchorHash + fullAnchorHash)
        let whitebox = ArmorWhiteBox.build(rootKey: config.encryptionKey)
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

        guard let textSection = try file.section(segment: "__TEXT", section: "__text") else {
            throw MachOError.sectionNotFound("__TEXT", "__text")
        }

        let pageSize = 4096
        let totalSize = Int(textSection.size)
        guard totalSize >= pageSize * 3 else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["Skipped: __text smaller than 3 pages (safe margin)"]
            )
        }

        let pageCount = totalSize / pageSize
        let firstPage = 1
        let lastPage = pageCount - 2
        guard firstPage <= lastPage else {
            return PassResult(passName: name, itemsProcessed: 0, bytesModified: 0, details: ["Skipped: no inner pages"])
        }

        let baseKeyID = stableKeyID(segment: "__TEXT", section: "__text")
        var entries = [TextEncryption.Entry]()
        var details = [String]()
        var bytesXor = 0

        for pageIdx in firstPage...lastPage {
            let offset = UInt64(textSection.offset) + UInt64(pageIdx * pageSize)
            let vmAddr = textSection.address + UInt64(pageIdx * pageSize)
            let start = Int(offset)
            let end = start + pageSize
            let plaintext = file.data.subdata(in: start..<end)
            let contentHash = sha256(plaintext)
            let nonce = try generateNonce()
            let sectionIndex = TextEncryption.sectionIndexBase + UInt32(pageIdx)
            let sectionKey = deriveChainedKey(
                parentKey: loaderKey,
                sectionIndex: sectionIndex,
                nonce: nonce,
                depth: 1
            )
            let keyID = baseKeyID &+ UInt32(pageIdx)
            let keystream = makeKeystream(key: sectionKey, keyID: keyID, nonce: nonce, length: pageSize)
            let encrypted = xor(plaintext, keystream)
            try file.replaceBytes(at: offset, with: encrypted)

            var hmacMessage = nonce
            hmacMessage.append(encrypted)
            let hmacTag = ArmorABI.hmacSHA256(key: sectionKey, message: hmacMessage)

            entries.append(
                TextEncryption.Entry(
                    vmAddress: vmAddr,
                    size: UInt64(pageSize),
                    keyID: keyID,
                    flags: 0,
                    nonce: nonce,
                    hmacTag: hmacTag,
                    contentHash: contentHash
                )
            )
            bytesXor += pageSize
            details.append("Encrypted __TEXT.__text page index \(pageIdx) @ 0x\(String(vmAddr, radix: 16))")
        }

        var payload = TextEncryption.Header(count: UInt32(entries.count)).serialized()
        for e in entries {
            payload.append(e.serialized())
        }

        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: TextEncryption.sectionName,
            content: payload,
            align: 3
        )

        details.append(
            "Wrote \(entries.count) text encrypt descriptor entries to __DATA.\(TextEncryption.sectionName)"
        )

        return PassResult(
            passName: name,
            itemsProcessed: entries.count,
            bytesModified: bytesXor + payload.count,
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

    private func appendUInt32(_ value: UInt32, to data: inout Data) {
        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
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
        return ArmorWhiteBox.rotl64(value, by: Int(TextArmorSeed.accumulatorRotation))
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
}

private enum TextEncryption {
    static let magic: UInt32 = 0x45545043 /* "CPTE" LE */
    static let abiVersion: UInt32 = 1
    static let sectionName = ArmorABI.Sections.textEncryption
    static let sectionIndexBase: UInt32 = 100_000

    struct Header {
        let count: UInt32

        func serialized() -> Data {
            var data = Data()
            data.appendLittleEndian(magic)
            data.appendLittleEndian(abiVersion)
            data.appendLittleEndian(count)
            data.appendLittleEndian(UInt32(0))
            return data
        }
    }

    struct Entry {
        let vmAddress: UInt64
        let size: UInt64
        let keyID: UInt32
        let flags: UInt32
        let nonce: Data
        let hmacTag: Data
        let contentHash: Data

        func serialized() -> Data {
            precondition(nonce.count == ArmorABI.nonceSize)
            precondition(hmacTag.count == ArmorABI.hashSize)
            precondition(contentHash.count == ArmorABI.hashSize)
            var data = Data()
            data.appendLittleEndian(vmAddress)
            data.appendLittleEndian(size)
            data.appendLittleEndian(keyID)
            data.appendLittleEndian(flags)
            data.append(nonce)
            data.append(hmacTag)
            data.append(contentHash)
            return data
        }
    }
}

private extension Data {
    mutating func appendLittleEndian(_ value: UInt32) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }

    mutating func appendLittleEndian(_ value: UInt64) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }
}
