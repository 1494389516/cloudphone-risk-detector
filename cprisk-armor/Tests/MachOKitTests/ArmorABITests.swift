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
        let entry = ArmorABI.Loader.Entry(
            segmentName: "__DATA",
            sectionName: "__swift5_mpenum",
            keyID: 0xAABBCCDD,
            vmAddress: 0x1122334455667788,
            size: 0x0102030405060708,
            contentHash: hash
        ).serialized()

        XCTAssertEqual(entry.count, ArmorABI.Loader.entrySize)
        XCTAssertEqual(String(decoding: entry[0..<6], as: UTF8.self), "__DATA")
        XCTAssertEqual(String(decoding: entry[16..<31], as: UTF8.self), "__swift5_mpenum")
        XCTAssertEqual(readLE32(entry, at: 32), 0xAABBCCDD)
        XCTAssertEqual(readLE32(entry, at: 36), 0)
        XCTAssertEqual(readLE64(entry, at: 40), 0x1122334455667788)
        XCTAssertEqual(readLE64(entry, at: 48), 0x0102030405060708)
        XCTAssertEqual(entry.subdata(in: 56..<88), hash)
    }

    func testIntegrityHelpersMatchRuntimeContract() {
        let digest = Data((0..<ArmorABI.hashSize).map { UInt8($0) })
        let lanes = ArmorABI.Integrity.splitAnchorLanes(for: digest)

        XCTAssertEqual(lanes.count, ArmorABI.Integrity.splitSectionCount)
        XCTAssertTrue(lanes.allSatisfy { $0.count == ArmorABI.Integrity.splitLaneSize })
        XCTAssertEqual(Data(lanes.joined()), digest)

        let mask = Data(repeating: 0xA5, count: ArmorABI.hashSize)
        let section = ArmorABI.Integrity.maskedFullHashSection(mask: mask, fullHash: digest)

        XCTAssertEqual(section.count, ArmorABI.Integrity.fullHashSectionSize)
        XCTAssertEqual(section.prefix(ArmorABI.hashSize), mask)

        let reconstructed = Data((0..<ArmorABI.hashSize).map { index in
            section[ArmorABI.hashSize + index] ^ section[index]
        })
        XCTAssertEqual(reconstructed, digest)
    }
}
