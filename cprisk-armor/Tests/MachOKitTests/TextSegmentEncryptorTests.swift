import Foundation
import IntegrityAnchor
import MachOKit
import TextSegmentEncryptor
import XCTest

final class TextSegmentEncryptorTests: XCTestCase {
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

    private static func writeFixture(named name: String) throws -> URL {
        let url = temporaryURL(named: name)
        try makeTextFixture().write(to: url)
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

    private static func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        precondition(offset >= 0 && offset + 4 <= data.count)
        return UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
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

    mutating func appendFixedCString(_ string: String, length: Int) {
        var bytes = Array(string.utf8.prefix(length))
        while bytes.count < length {
            bytes.append(0)
        }
        append(contentsOf: bytes)
    }
}
