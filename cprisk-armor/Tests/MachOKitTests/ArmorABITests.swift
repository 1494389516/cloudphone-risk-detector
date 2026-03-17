import XCTest
import MachOKit

final class ArmorABITests: XCTestCase {
    private func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            UInt32(littleEndian: $0.load(as: UInt32.self))
        }
    }

    private func readLE64(_ data: Data, at offset: Int) -> UInt64 {
        data.subdata(in: offset..<(offset + 8)).withUnsafeBytes {
            UInt64(littleEndian: $0.load(as: UInt64.self))
        }
    }

    func testStringTableHeaderSerializationMatchesABI() {
        let header = ArmorABI.StringTable.Header(count: 7).serialized()

        XCTAssertEqual(header.count, ArmorABI.StringTable.headerSize)
        XCTAssertEqual(readLE32(header, at: 0), ArmorABI.StringTable.magic)
        XCTAssertEqual(readLE32(header, at: 4), ArmorABI.version)
        XCTAssertEqual(readLE32(header, at: 8), 7)
    }

    func testLoaderEntrySerializationMatchesABI() {
        let hash = Data((0..<ArmorABI.hashSize).map { UInt8($0) })
        let nonce = Data(repeating: 0xAA, count: ArmorABI.nonceSize)
        let hmac = Data(repeating: 0xBB, count: ArmorABI.hashSize)
        let entry = ArmorABI.Loader.Entry(
            segmentName: "__DATA",
            sectionName: "__swift5_mpenum",
            keyID: 0xAABBCCDD,
            vmAddress: 0x1122334455667788,
            size: 0x0102030405060708,
            contentHash: hash,
            nonce: nonce,
            hmacTag: hmac
        ).serialized()

        XCTAssertEqual(entry.count, ArmorABI.Loader.entrySize)
        XCTAssertEqual(String(decoding: entry[0..<6], as: UTF8.self), "__DATA")
        XCTAssertEqual(String(decoding: entry[16..<31], as: UTF8.self), "__swift5_mpenum")
        XCTAssertEqual(readLE32(entry, at: 32), 0xAABBCCDD)
        XCTAssertEqual(readLE32(entry, at: 36), 0)
        XCTAssertEqual(readLE64(entry, at: 40), 0x1122334455667788)
        XCTAssertEqual(readLE64(entry, at: 48), 0x0102030405060708)
        XCTAssertEqual(entry.subdata(in: 56..<88), hash)
        XCTAssertEqual(entry.subdata(in: 88..<96), nonce)
        XCTAssertEqual(entry.subdata(in: 96..<128), hmac)
    }

    func testIntegrityHelpersMatchRuntimeContract() {
        let digest = Data((0..<ArmorABI.hashSize).map { UInt8($0) })
        let lanes = ArmorABI.Integrity.splitAnchorLanes(for: digest)

        XCTAssertEqual(lanes.count, ArmorABI.Integrity.splitSectionCount)
        XCTAssertTrue(lanes.allSatisfy { $0.count == ArmorABI.Integrity.splitLaneSize })
        XCTAssertEqual(Data(lanes.joined()), digest)

        let anchorTag = Data(repeating: 0xA5, count: ArmorABI.hashSize)
        let section = ArmorABI.Integrity.anchorTagSection(anchorTag)

        XCTAssertEqual(section.count, ArmorABI.Integrity.hmacFullHashSectionSize)
        XCTAssertEqual(section, anchorTag)
    }

    func testWhiteBoxDescriptorSerializationMatchesABI() {
        let permutation = Data((0..<ArmorABI.WhiteBox.permutationSize).map { UInt8($0) })
        let finalMask = Data(repeating: 0xA1, count: ArmorABI.hashSize)
        let roundConstants = Data(repeating: 0xB2, count: ArmorABI.WhiteBox.roundConstantSize)
        let recordDigest = Data(repeating: 0xC3, count: ArmorABI.hashSize)
        let descriptor = ArmorABI.WhiteBox.Descriptor(
            domainID: ArmorABI.WhiteBox.Domain.loaderKey.rawValue,
            tableOffset: 0x01020304,
            tableLength: 0x00008000,
            permutation: permutation,
            finalMask: finalMask,
            roundConstants: roundConstants,
            recordDigest: recordDigest
        ).serialized()

        XCTAssertEqual(descriptor.count, ArmorABI.WhiteBox.Descriptor.serializedSize)
        XCTAssertEqual(readLE32(descriptor, at: 0), ArmorABI.WhiteBox.Domain.loaderKey.rawValue)
        XCTAssertEqual(readLE32(descriptor, at: 4), ArmorABI.WhiteBox.roundCount)
        XCTAssertEqual(readLE32(descriptor, at: 8), 0x01020304)
        XCTAssertEqual(readLE32(descriptor, at: 12), 0x00008000)
        XCTAssertEqual(descriptor.subdata(in: 16..<48), permutation)
        XCTAssertEqual(descriptor.subdata(in: 48..<80), finalMask)
        XCTAssertEqual(descriptor.subdata(in: 80..<208), roundConstants)
        XCTAssertEqual(descriptor.subdata(in: 208..<240), recordDigest)
    }

    func testWhiteBoxHeaderPayloadSizeExcludesDetachedTagSection() {
        let configDigest = Data(repeating: 0x5A, count: ArmorABI.hashSize)
        let header = ArmorABI.WhiteBox.Header(
            flags: ArmorABI.WhiteBox.engineReadyFlag | ArmorABI.WhiteBox.signingPipelineFlag,
            payloadSize: 0x11223344,
            configDigest: configDigest
        ).serialized()

        XCTAssertEqual(header.count, 48)
        XCTAssertEqual(readLE32(header, at: 0), ArmorABI.WhiteBox.magic)
        XCTAssertEqual(readLE32(header, at: 4), ArmorABI.WhiteBox.abiVersion)
        XCTAssertEqual(
            readLE32(header, at: 8),
            ArmorABI.WhiteBox.engineReadyFlag | ArmorABI.WhiteBox.signingPipelineFlag
        )
        XCTAssertEqual(
            readLE32(header, at: 12),
            0x11223344,
            "payload_size is reserved for white-box code+data only; the detached tag is validated separately"
        )
        XCTAssertEqual(header.subdata(in: 16..<48), configDigest)
    }
}
