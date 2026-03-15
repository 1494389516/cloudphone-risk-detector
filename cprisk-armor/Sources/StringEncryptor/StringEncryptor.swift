import CryptoKit
import Foundation
import MachOKit

private enum StringBootstrap {
    static let id: UInt32 = 1
    // Build-tool only — this literal does not appear in the final SDK binary.
    static let value = "cprisk-bootstrap-v1"
    static let maxCopiedStrings = 7
    static let minLength = 4
    static let maxLength = 96
}

private struct StringRecord {
    let id: UInt32
    let value: String
}

/// Pass 1: materialize a real runtime-consumable encrypted string table.
///
/// This minimal version does not rewrite every `__cstring` reference. Instead it
/// copies a small bootstrap subset into the string table section, encrypts it
/// with the runtime keystream ABI, and lets CRiskCore consume the section.
public final class StringEncryptorPass: ArmorPass {
    public let name = "StringEncryptor"

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        let records = buildRecords(from: try file.findCStrings())
        let stringKey = deriveStringKey(rootKey: config.encryptionKey)

        var payload = ArmorABI.StringTable.Header(count: UInt32(records.count)).serialized()
        var dataArea = Data()

        for record in records {
            let plaintext = Data(record.value.utf8)
            let encrypted = xor(
                plaintext,
                makeKeystream(key: stringKey, stringID: record.id, length: plaintext.count)
            )

            payload.append(
                ArmorABI.StringTable.IndexEntry(
                    stringID: record.id,
                    dataOffset: UInt32(dataArea.count),
                    dataLength: UInt32(plaintext.count)
                ).serialized()
            )
            dataArea.append(encrypted)
        }

        payload.append(dataArea)
        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.StringTable.sectionName,
            content: payload,
            align: 2
        )

        return PassResult(
            passName: name,
            itemsProcessed: records.count,
            bytesModified: payload.count,
            details: [
                "Wrote encrypted string table to \(ArmorABI.dataSegmentName).\(ArmorABI.StringTable.sectionName)",
                "Bootstrap string id \(StringBootstrap.id) is reserved for runtime key chaining",
                "Protected \(max(records.count - 1, 0)) copied __cstring entries plus one synthetic bootstrap string"
            ]
        )
    }

    private func buildRecords(from cStrings: [(offset: UInt64, value: String)]) -> [StringRecord] {
        var records = [StringRecord(id: StringBootstrap.id, value: StringBootstrap.value)]

        let selected = cStrings.lazy
            .map(\.value)
            .filter(isEligible)
            .prefix(StringBootstrap.maxCopiedStrings)

        for value in selected {
            records.append(StringRecord(id: UInt32(records.count + 1), value: value))
        }
        return records
    }

    private func isEligible(_ value: String) -> Bool {
        guard value.count >= StringBootstrap.minLength, value.count <= StringBootstrap.maxLength else {
            return false
        }
        return value.utf8.allSatisfy { byte in
            byte == 0x09 || byte == 0x0A || byte == 0x0D || (0x20...0x7E).contains(byte)
        }
    }
}

// Build-tool only — this salt does not appear in the final SDK binary.
private func deriveStringKey(rootKey: Data?) -> Data {
    var seed = Data("cprisk.pass1.key.v1".utf8)
    seed.append(normalizedRootKey(rootKey))
    return sha256(seed)
}

private func normalizedRootKey(_ rootKey: Data?) -> Data {
    var key = Data(repeating: 0, count: ArmorABI.keySize)
    guard let rootKey else { return key }

    let prefix = rootKey.prefix(ArmorABI.keySize)
    key.replaceSubrange(0..<prefix.count, with: prefix)
    return key
}

private func makeKeystream(key: Data, stringID: UInt32, length: Int) -> Data {
    var seed = Data()
    seed.append(key)

    var sid = stringID.littleEndian
    withUnsafeBytes(of: &sid) { seed.append(contentsOf: $0) }

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
