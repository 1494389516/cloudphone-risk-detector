import DataSegmentEncryptor
import Foundation
import IntegrityAnchor
import MachOKit
@testable import StringEncryptor
import XCTest

final class KDFChainTests: XCTestCase {
    private static let testRootKey = Data(repeating: 0xAB, count: ArmorABI.keySize)

    func testPass4WritesWhiteBoxAnchorAndSections() throws {
        let url = try Self.writeFixture(named: "wb_anchor")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let config = PassConfig(encryptionKey: Self.testRootKey)
        let textHash = try Self.textHash(from: file)
        let bundle = ArmorWhiteBox.build(rootKey: Self.testRootKey)

        _ = try IntegrityAnchorPass().execute(on: file, config: config)

        let anchorSection = try XCTUnwrap(
            try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.Integrity.fullHashSectionName)
        )
        XCTAssertEqual(
            try anchorSection.readContent(from: file.data),
            bundle.prf(domain: .anchorTag, input: textHash)
        )

        XCTAssertEqual(
            try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.WhiteBox.Sections.metadata))
                .readContent(from: file.data),
            bundle.metadataSection
        )
        XCTAssertEqual(
            try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.WhiteBox.Sections.code))
                .readContent(from: file.data),
            bundle.whiteboxCode
        )
        XCTAssertEqual(
            try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.WhiteBox.Sections.data))
                .readContent(from: file.data),
            bundle.whiteboxData
        )
        XCTAssertEqual(
            try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.WhiteBox.Sections.tag))
                .readContent(from: file.data),
            bundle.whiteboxTag
        )

        for (i, sectionName) in ArmorABI.Integrity.splitSectionNames.enumerated() {
            let section = try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: sectionName))
            let lane = try section.readContent(from: file.data)
            XCTAssertEqual(lane, textHash.subdata(in: (i * 8)..<((i + 1) * 8)))
        }
    }

    func testPass1StringKeyComesFromWhiteBoxDomain2() throws {
        let url = try Self.writeFixture(named: "wb_pass1")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let config = PassConfig(encryptionKey: Self.testRootKey)
        let bundle = ArmorWhiteBox.build(rootKey: Self.testRootKey)
        let expectedStringKey = bundle.prf(
            domain: .pass1StringKey,
            input: Data(repeating: 0, count: ArmorABI.hashSize)
        )

        _ = try StringEncryptorPass().execute(on: file, config: config)

        let section = try XCTUnwrap(
            try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.StringTable.sectionName)
        )
        let content = try section.readContent(from: file.data)
        let count = Int(Self.readLE32(content, at: 8))
        XCTAssertGreaterThan(count, 0)

        let indexBase = ArmorABI.StringTable.headerSize
        let dataBase = indexBase + count * ArmorABI.StringTable.indexEntrySize
        let firstID = Self.readLE32(content, at: indexBase)
        let firstOffset = Int(Self.readLE32(content, at: indexBase + 4))
        let firstLength = Int(Self.readLE32(content, at: indexBase + 8))
        let firstNonce = content.subdata(in: (indexBase + 12)..<(indexBase + 20))
        let firstEncrypted = content.subdata(
            in: (dataBase + firstOffset)..<(dataBase + firstOffset + firstLength)
        )
        let dispatchSeed = deriveKeystreamDispatchSeed(key: expectedStringKey)

        let keystream = buildKeystreamForRecord(
            key: expectedStringKey,
            stringID: firstID,
            nonce: firstNonce,
            length: firstLength,
            dispatchSeed: dispatchSeed
        )
        let decrypted = Data(zip(firstEncrypted, keystream).map(^))
        XCTAssertEqual(String(data: decrypted, encoding: .utf8), "cprisk-bootstrap-v1")
    }

    func testPass3DerivationUsesWhiteBoxDomains3And4() {
        let fullAnchorHash = Self.sha256(Data("anchor-material".utf8))
        let integrityHash = Self.sha256(fullAnchorHash + fullAnchorHash + fullAnchorHash)
        let bundle = ArmorWhiteBox.build(rootKey: Self.testRootKey)

        let accDigest = Self.sha256(fullAnchorHash + integrityHash)
        let accSeed = bundle.prf(domain: .anchorAccumulatorSeed, input: accDigest)
        let expectedAccumulator = ArmorWhiteBox.rotl64(
            ArmorWhiteBox.littleEndianUInt64(from: accSeed),
            by: 7
        )

        let actualAccumulator = anchorBoundAccumulator(
            rootKey: Self.testRootKey,
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash
        )
        XCTAssertEqual(actualAccumulator, expectedAccumulator)

        var loaderMaterial = Data()
        loaderMaterial.append(fullAnchorHash)
        loaderMaterial.append(integrityHash)
        ArmorWhiteBox.appendLittleEndian(expectedAccumulator, to: &loaderMaterial)
        let expectedLoaderKey = bundle.prf(
            domain: .loaderKey,
            input: Self.sha256(loaderMaterial)
        )

        let actualLoaderKey = deriveLoaderKey(
            rootKey: Self.testRootKey,
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash,
            anchorAccumulator: expectedAccumulator
        )
        XCTAssertEqual(actualLoaderKey, expectedLoaderKey)
    }

    func testFullWhiteBoxChainRunsAcrossPasses() throws {
        let url = try Self.writeFixture(named: "wb_chain")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let config = PassConfig(encryptionKey: Self.testRootKey)

        _ = try IntegrityAnchorPass().execute(on: file, config: config)
        _ = try StringEncryptorPass().execute(on: file, config: config)
        _ = try DataSegmentEncryptorPass().execute(on: file, config: config)

        XCTAssertNotNil(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.StringTable.sectionName))
        XCTAssertNotNil(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.Loader.sectionName))
        XCTAssertNotNil(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.WhiteBox.Sections.code))
        XCTAssertNoThrow(try file.validateStructure())
    }

    private static func sha256(_ data: Data) -> Data {
        ArmorWhiteBox.sha256(data)
    }

    private static func textHash(from file: MachOFile) throws -> Data {
        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        return sha256(try textSection.readContent(from: file.data))
    }

    private static func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            UInt32(littleEndian: $0.load(as: UInt32.self))
        }
    }

    private static func writeFixture(named name: String) throws -> URL {
        let url = temporaryURL(named: name)
        try makeFixture().write(to: url)
        return url
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
    }

    private static func makeFixture() -> Data {
        let textCodeContent = Data([
            0xFD, 0x7B, 0xBF, 0xA9,
            0xFD, 0x03, 0x00, 0x91,
            0x00, 0x00, 0x80, 0xD2,
            0xC0, 0x03, 0x5F, 0xD6,
            0x1F, 0x20, 0x03, 0xD5,
            0x1F, 0x20, 0x03, 0xD5,
            0xFD, 0x7B, 0xC1, 0xA8,
            0xC0, 0x03, 0x5F, 0xD6,
        ])

        let cstrings = [
            "/usr/bin/bash",
            "frida-server",
            "normal_text",
            "12345",
        ]
        var cstringData = Data()
        for value in cstrings {
            cstringData.append(contentsOf: value.utf8)
            cstringData.append(0)
        }

        let textSegCmdSize = 72 + 80 + 80
        let dataSegCmdSize = 72 + 80
        let sizeOfCmds = textSegCmdSize + dataSegCmdSize

        let textCodeOffset = 2048
        let cstringOffset = textCodeOffset + textCodeContent.count
        let textSegFileSize = 4096
        let dataSegOffset = 4096
        let dataSegSize = 4096
        let fileSize = dataSegOffset + dataSegSize

        var data = Data()
        data.appendLE32(0xFEEDFACF)
        data.appendLE32(0x0100000C)
        data.appendLE32(0)
        data.appendLE32(0x00000006)
        data.appendLE32(2)
        data.appendLE32(UInt32(sizeOfCmds))
        data.appendLE32(0)
        data.appendLE32(0)

        data.appendLE32(0x19)
        data.appendLE32(UInt32(textSegCmdSize))
        data.appendFixedCString16("__TEXT")
        data.appendLE64(0x1000)
        data.appendLE64(UInt64(textSegFileSize))
        data.appendLE64(0)
        data.appendLE64(UInt64(textSegFileSize))
        data.appendLE32(5)
        data.appendLE32(5)
        data.appendLE32(2)
        data.appendLE32(0)

        data.appendFixedCString16("__text")
        data.appendFixedCString16("__TEXT")
        data.appendLE64(0x1000 + UInt64(textCodeOffset))
        data.appendLE64(UInt64(textCodeContent.count))
        data.appendLE32(UInt32(textCodeOffset))
        data.appendLE32(2)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0x80000400)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)

        data.appendFixedCString16("__cstring")
        data.appendFixedCString16("__TEXT")
        data.appendLE64(0x1000 + UInt64(cstringOffset))
        data.appendLE64(UInt64(cstringData.count))
        data.appendLE32(UInt32(cstringOffset))
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0x02)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)

        data.appendLE32(0x19)
        data.appendLE32(UInt32(dataSegCmdSize))
        data.appendFixedCString16("__DATA")
        data.appendLE64(0x2000)
        data.appendLE64(UInt64(dataSegSize))
        data.appendLE64(UInt64(dataSegOffset))
        data.appendLE64(UInt64(dataSegSize))
        data.appendLE32(3)
        data.appendLE32(3)
        data.appendLE32(1)
        data.appendLE32(0)

        data.appendFixedCString16("__const")
        data.appendFixedCString16("__DATA")
        data.appendLE64(0x2000)
        data.appendLE64(8)
        data.appendLE32(UInt32(dataSegOffset))
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)

        if data.count < textCodeOffset {
            data.append(Data(count: textCodeOffset - data.count))
        }
        data.append(textCodeContent)

        if data.count < cstringOffset {
            data.append(Data(count: cstringOffset - data.count))
        }
        data.append(cstringData)

        if data.count < dataSegOffset {
            data.append(Data(count: dataSegOffset - data.count))
        }
        data.append(Data([0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD]))

        if data.count < fileSize {
            data.append(Data(count: fileSize - data.count))
        }
        return data
    }
}

private extension Data {
    mutating func appendLE32(_ value: UInt32) {
        var littleEndian = value.littleEndian
        append(Data(bytes: &littleEndian, count: 4))
    }

    mutating func appendLE64(_ value: UInt64) {
        var littleEndian = value.littleEndian
        append(Data(bytes: &littleEndian, count: 8))
    }

    mutating func appendFixedCString16(_ string: String) {
        var bytes = Array(string.utf8.prefix(16))
        while bytes.count < 16 { bytes.append(0) }
        append(contentsOf: bytes)
    }
}
