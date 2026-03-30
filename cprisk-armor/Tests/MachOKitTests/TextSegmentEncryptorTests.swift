import Foundation
import IntegrityAnchor
import MachOKit
@testable import TextSegmentEncryptor
import XCTest

final class TextSegmentEncryptorTests: XCTestCase {
    func testTextSectionKeyDerivationMixIsDeterministic() {
        let rootKey = Data(repeating: 0xC3, count: ArmorABI.keySize)
        let bundle = ArmorWhiteBox.build(rootKey: rootKey)
        let parent = Data(repeating: 0x19, count: ArmorABI.keySize)
        let sectionIndex: UInt32 = 100_002
        let nonce = Data(repeating: 0x7E, count: ArmorABI.nonceSize)

        let a = TextSectionKeyDerivation.derive(
            parentKey: parent,
            sectionIndex: sectionIndex,
            nonce: nonce,
            depth: 1,
            whitebox: bundle
        )
        let b = TextSectionKeyDerivation.derive(
            parentKey: parent,
            sectionIndex: sectionIndex,
            nonce: nonce,
            depth: 1,
            whitebox: bundle
        )
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, parent)
    }

    func testPass12EncryptsInnerTextPagesAndWritesDescriptor() throws {
        let fixtureURL = try Self.writeFixture(named: "pass12_text_encrypt")
        defer { try? FileManager.default.removeItem(at: fixtureURL) }

        let file = try MachOFile(url: fixtureURL)
        let config = PassConfig(encryptionKey: Data("pass12-test-key-material-32bytes!!".utf8.prefix(32)))

        _ = try IntegrityAnchorPass().execute(on: file, config: config)

        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let before = try textSection.readContent(from: file.data)
        XCTAssertEqual(before.count, 4096 * 4)

        let result = try TextSegmentEncryptorPass().execute(on: file, config: config)
        let after = try textSection.readContent(from: file.data)

        XCTAssertEqual(result.itemsProcessed, 2, "4 pages should encrypt middle 2 pages")
        XCTAssertGreaterThan(result.bytesModified, 0)
        XCTAssertNotEqual(before, after)
        XCTAssertEqual(before.count, after.count)

        // First and last page stay untouched for conservative safety margin.
        XCTAssertEqual(before.subdata(in: 0..<(4096)), after.subdata(in: 0..<(4096)))
        XCTAssertEqual(before.subdata(in: (4096 * 3)..<(4096 * 4)),
                       after.subdata(in: (4096 * 3)..<(4096 * 4)))
        XCTAssertNotEqual(before.subdata(in: (4096)..<(4096 * 2)),
                          after.subdata(in: (4096)..<(4096 * 2)))
        XCTAssertNotEqual(before.subdata(in: (4096 * 2)..<(4096 * 3)),
                          after.subdata(in: (4096 * 2)..<(4096 * 3)))

        let meta = try XCTUnwrap(try file.section(segment: "__DATA", section: ArmorABI.Sections.textEncryption))
        let payload = try meta.readContent(from: file.data)
        XCTAssertGreaterThanOrEqual(payload.count, 16)
        XCTAssertEqual(Self.readLE32(payload, at: 0), 0x45545043) // "CPTE"
        XCTAssertEqual(Self.readLE32(payload, at: 4), 1)
        XCTAssertEqual(Self.readLE32(payload, at: 8), 2)

        XCTAssertNoThrow(try file.validateStructure())
    }

    func testPass12CanEncryptFirstPageAndPartialTailWhenPolicyAllows() throws {
        let fixtureURL = try Self.writeEdgeFixture(named: "pass12_edge_text_encrypt")
        defer { try? FileManager.default.removeItem(at: fixtureURL) }

        let file = try MachOFile(url: fixtureURL)
        let config = PassConfig(encryptionKey: Data("pass12-edge-key-material-32bytes".utf8.prefix(32)))

        _ = try IntegrityAnchorPass().execute(on: file, config: config)

        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let dataSection = try XCTUnwrap(try file.section(segment: "__DATA", section: "__const"))
        let beforeText = try textSection.readContent(from: file.data)
        let beforeData = try dataSection.readContent(from: file.data)

        let result = try TextSegmentEncryptorPass().execute(on: file, config: config)
        let afterText = try textSection.readContent(from: file.data)
        let afterData = try dataSection.readContent(from: file.data)

        let pageSize = 4096
        let partialTail = 0x480

        XCTAssertEqual(result.itemsProcessed, 5, "4 full pages + 1 tail chunk should all be encrypted")
        XCTAssertNotEqual(beforeText.subdata(in: 0..<pageSize), afterText.subdata(in: 0..<pageSize))
        XCTAssertNotEqual(beforeText.subdata(in: pageSize..<(pageSize * 2)),
                          afterText.subdata(in: pageSize..<(pageSize * 2)))
        XCTAssertNotEqual(beforeText.subdata(in: (pageSize * 2)..<(pageSize * 3)),
                          afterText.subdata(in: (pageSize * 2)..<(pageSize * 3)))
        XCTAssertNotEqual(beforeText.subdata(in: (pageSize * 3)..<(pageSize * 4)),
                          afterText.subdata(in: (pageSize * 3)..<(pageSize * 4)))
        XCTAssertNotEqual(beforeText.subdata(in: (pageSize * 4)..<beforeText.count),
                          afterText.subdata(in: (pageSize * 4)..<afterText.count))
        XCTAssertEqual(beforeData, afterData, "tail encryption must not spill into the next section")

        let meta = try XCTUnwrap(try file.section(segment: "__DATA", section: ArmorABI.Sections.textEncryption))
        let payload = try meta.readContent(from: file.data)
        XCTAssertEqual(Self.readLE32(payload, at: 8), 5)

        let entrySize = 96
        let lastEntryOffset = 16 + (4 * entrySize)
        XCTAssertEqual(Self.readLE64(payload, at: lastEntryOffset + 8), UInt64(partialTail))

        XCTAssertNoThrow(try file.validateStructure())
    }

    func testPass12EncryptsPartialTailEvenWhenTailContainsNonVMSymbol() throws {
        let fixtureURL = try Self.writeEdgeFixture(
            named: "pass12_edge_tail_symbol",
            includeTailPlainSymbol: true
        )
        defer { try? FileManager.default.removeItem(at: fixtureURL) }

        let file = try MachOFile(url: fixtureURL)
        let config = PassConfig(encryptionKey: Data("pass12-tail-key-material-32bytes".utf8.prefix(32)))

        _ = try IntegrityAnchorPass().execute(on: file, config: config)

        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let dataSection = try XCTUnwrap(try file.section(segment: "__DATA", section: "__const"))
        let beforeText = try textSection.readContent(from: file.data)
        let beforeData = try dataSection.readContent(from: file.data)

        let result = try TextSegmentEncryptorPass().execute(on: file, config: config)
        let afterText = try textSection.readContent(from: file.data)
        let afterData = try dataSection.readContent(from: file.data)

        let pageSize = 4096
        let partialTail = 0x480
        XCTAssertEqual(result.itemsProcessed, 5, "tail symbols should no longer block partial-tail encryption")
        XCTAssertTrue(result.details.contains { $0.contains("encryptPartialTail=true") })
        XCTAssertNotEqual(beforeText.subdata(in: (pageSize * 4)..<beforeText.count),
                          afterText.subdata(in: (pageSize * 4)..<afterText.count))
        XCTAssertEqual(beforeData, afterData, "tail encryption must not spill into the next section")

        let meta = try XCTUnwrap(try file.section(segment: "__DATA", section: ArmorABI.Sections.textEncryption))
        let payload = try meta.readContent(from: file.data)
        XCTAssertEqual(Self.readLE32(payload, at: 8), 5)

        let entrySize = 96
        let lastEntryOffset = 16 + (4 * entrySize)
        XCTAssertEqual(Self.readLE64(payload, at: lastEntryOffset + 8), UInt64(partialTail))

        XCTAssertNoThrow(try file.validateStructure())
    }

    private static func writeFixture(named name: String) throws -> URL {
        let url = temporaryURL(named: name)
        try makeTextFixture().write(to: url)
        return url
    }

    private static func writeEdgeFixture(
        named name: String,
        includeTailPlainSymbol: Bool = false
    ) throws -> URL {
        let url = temporaryURL(named: name)
        try makeEdgeAwareTextFixture(includeTailPlainSymbol: includeTailPlainSymbol).write(to: url)
        return url
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
    }

    /// Two-segment synthetic Mach-O:
    /// - __TEXT.__text: 4 pages so Pass12 can encrypt inner pages.
    /// - __DATA.__const: writable payload for anchor/material sections.
    private static func makeTextFixture() -> Data {
        let textOffset: UInt32 = 0x1000
        let textSize = 4096 * 4
        let dataOffset = Int(textOffset) + textSize

        var data = Data()
        data.appendLE(UInt32(0xFEEDFACF))   // MH_MAGIC_64
        data.appendLE(UInt32(0x0100000C))   // CPU_TYPE_ARM64
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x00000006))   // MH_DYLIB
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(304))          // sizeofcmds
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __TEXT segment with one __text section.
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(152))
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(0x5000))
        data.appendLE(UInt64(0))
        data.appendLE(UInt64(dataOffset))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(0))

        data.appendFixedCString("__text", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x2000))
        data.appendLE(UInt64(textSize))
        data.appendLE(textOffset)
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x80000400))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __DATA segment with one __const section.
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(152))
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x7000))
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(dataOffset))
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(0))

        data.appendFixedCString("__const", length: 16)
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x7000))
        data.appendLE(UInt64(128))
        data.appendLE(UInt32(dataOffset))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        data.append(Data(count: Int(textOffset) - data.count))

        // Fill __text with deterministic page-distinct bytes.
        for page in 0..<4 {
            let byte = UInt8((0x20 + page * 0x11) & 0xFF)
            data.append(Data(repeating: byte, count: 4096))
        }

        data.append(Data(repeating: 0xA5, count: 128))
        if data.count < dataOffset + 0x1000 {
            data.append(Data(count: (dataOffset + 0x1000) - data.count))
        }
        return data
    }

    /// MH_EXECUTE fixture with:
    /// - `LC_MAIN.entryoff` pointing at page 1 of `__TEXT.__text` (so page 0 is encryptable)
    /// - `LC_SYMTAB` present but no symbols in the tail chunk (so the final chunk is encryptable)
    /// - `__TEXT.__text` sized as 4 full pages + one 0x480-byte tail chunk
    private static func makeEdgeAwareTextFixture(includeTailPlainSymbol: Bool = false) -> Data {
        let textOffset: UInt32 = 0x1000
        let fullPages = 4
        let partialTail = 0x480
        let textSize = (4096 * fullPages) + partialTail
        let dataOffset = Int(textOffset) + textSize
        let dataSectionSize = 128
        let textEncryptPlaceholderSize = 1024
        let symoff = UInt32(dataOffset + 0x1800)

        var stringTable = Data()
        stringTable.append(0)
        var nlistData = Data()
        func appendTextSymbol(name: String, vmAddr: UInt64) {
            let strx = UInt32(stringTable.count)
            stringTable.append(contentsOf: name.utf8)
            stringTable.append(0)

            nlistData.appendLE(strx)
            nlistData.append(0x0E) // N_SECT
            nlistData.append(0x01) // __TEXT.__text section ordinal
            nlistData.appendLE(Int16(0))
            nlistData.appendLE(vmAddr)
        }
        appendTextSymbol(name: "_pass12_anchor_symbol", vmAddr: UInt64(0x2000 + 0x1100)) // second page
        if includeTailPlainSymbol {
            appendTextSymbol(
                name: "_pass12_tail_plain_symbol",
                vmAddr: UInt64(0x2000 + (fullPages * 4096) + 0x100)
            )
        }

        var data = Data()
        data.appendLE(UInt32(0xFEEDFACF))   // MH_MAGIC_64
        data.appendLE(UInt32(0x0100000C))   // CPU_TYPE_ARM64
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x00000002))   // MH_EXECUTE
        data.appendLE(UInt32(4))
        data.appendLE(UInt32(432))          // 2 segments + LC_MAIN + LC_SYMTAB
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __TEXT segment with one __text section.
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(152))
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(0x7000))
        data.appendLE(UInt64(0))
        data.appendLE(UInt64(dataOffset))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(0))

        data.appendFixedCString("__text", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x2000))
        data.appendLE(UInt64(textSize))
        data.appendLE(textOffset)
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x80000400))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __DATA segment with one __const section.
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(232))
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x9000))
        data.appendLE(UInt64(0x2000))
        data.appendLE(UInt64(dataOffset))
        data.appendLE(UInt64(0x2000))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(0))

        data.appendFixedCString("__const", length: 16)
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x9000))
        data.appendLE(UInt64(dataSectionSize))
        data.appendLE(UInt32(dataOffset))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        data.appendFixedCString(ArmorABI.Sections.textEncryption, length: 16)
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x9000 + dataSectionSize))
        data.appendLE(UInt64(textEncryptPlaceholderSize))
        data.appendLE(UInt32(dataOffset + dataSectionSize))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // LC_MAIN with entryoff in the second __text page.
        data.appendLE(UInt32(0x80000028))
        data.appendLE(UInt32(24))
        data.appendLE(UInt64(Int(textOffset) + 0x1100))
        data.appendLE(UInt64(0))

        // LC_SYMTAB
        data.appendLE(UInt32(0x02))
        data.appendLE(UInt32(24))
        data.appendLE(symoff)
        data.appendLE(UInt32(nlistData.count / 16))
        data.appendLE(symoff + UInt32(nlistData.count))
        data.appendLE(UInt32(stringTable.count))

        data.append(Data(count: Int(textOffset) - data.count))

        for page in 0..<fullPages {
            let byte = UInt8((0x31 + page * 0x17) & 0xFF)
            data.append(Data(repeating: byte, count: 4096))
        }
        data.append(Data(repeating: 0xD7, count: partialTail))

        data.append(Data(repeating: 0xA5, count: dataSectionSize))
        data.append(Data(repeating: 0, count: textEncryptPlaceholderSize))
        if data.count < Int(symoff) {
            data.append(Data(count: Int(symoff) - data.count))
        }
        data.append(nlistData)
        data.append(stringTable)
        if data.count < dataOffset + 0x2000 {
            data.append(Data(count: (dataOffset + 0x2000) - data.count))
        }
        return data
    }

    private static func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        precondition(offset >= 0 && offset + 4 <= data.count)
        return UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
    }

    private static func readLE64(_ data: Data, at offset: Int) -> UInt64 {
        precondition(offset >= 0 && offset + 8 <= data.count)
        return UInt64(data[offset])
            | (UInt64(data[offset + 1]) << 8)
            | (UInt64(data[offset + 2]) << 16)
            | (UInt64(data[offset + 3]) << 24)
            | (UInt64(data[offset + 4]) << 32)
            | (UInt64(data[offset + 5]) << 40)
            | (UInt64(data[offset + 6]) << 48)
            | (UInt64(data[offset + 7]) << 56)
    }
}

private extension Data {
    mutating func appendLE(_ value: UInt32) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 4))
    }

    mutating func appendLE(_ value: UInt64) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 8))
    }

    mutating func appendLE(_ value: Int16) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 2))
    }

    mutating func appendFixedCString(_ string: String, length: Int) {
        var bytes = Array(string.utf8.prefix(length))
        while bytes.count < length {
            bytes.append(0)
        }
        append(contentsOf: bytes)
    }
}
