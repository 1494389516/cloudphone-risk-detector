import Foundation
import MachOKit
import XCTest

final class ArmorFixtureTests: XCTestCase {
    func testDiskFixtureRoundTripMutatesCString() throws {
        let inputURL = try Self.writeFixture(named: "roundtrip_input")
        let outputURL = Self.temporaryURL(named: "roundtrip_output")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let file = try MachOFile(url: inputURL)
        let strings = try file.findCStrings()
        XCTAssertEqual(strings.map(\.value), ["Hello", "World"])

        try file.replaceBytes(at: strings[0].offset, with: Data("J".utf8))
        try file.write(to: outputURL)

        let reloaded = try MachOFile(url: outputURL)
        XCTAssertEqual(try reloaded.findCStrings().first?.value, "Jello")
    }

    func testDiskFixtureCanWriteCustomArmorSection() throws {
        let inputURL = try Self.writeFixture(named: "section_input")
        let outputURL = Self.temporaryURL(named: "section_output")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        var data = try Data(contentsOf: inputURL)
        let descriptor = Self.makeLoaderDescriptor(magic: 0x4350524B, version: 1, count: 1)

        let inserted = try MachOWriter.addSection(
            to: &data,
            segment: "__DATA",
            section: "__swift5_proto2",
            content: descriptor,
            protection: 0
        )
        try data.write(to: outputURL)

        let reloaded = try MachOFile(url: outputURL)
        let section = try XCTUnwrap(try reloaded.section(segment: "__DATA", section: "__swift5_proto2"))
        XCTAssertEqual(section.offset, inserted.offset)
        XCTAssertEqual(section.size, UInt64(descriptor.count))
        XCTAssertEqual(try section.readContent(from: reloaded.data), descriptor)
        XCTAssertEqual(reloaded.header.sizeOfCommands, UInt32(384))
    }

    func testTamperedFixtureMagicFailsPredictably() throws {
        let fixtureURL = try Self.writeFixture(named: "tampered_magic")
        defer { try? FileManager.default.removeItem(at: fixtureURL) }

        var data = try Data(contentsOf: fixtureURL)
        data[0] = 0x00
        try data.write(to: fixtureURL)

        XCTAssertThrowsError(try MachOFile(url: fixtureURL)) { error in
            guard case MachOError.invalidMagic = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }

    private static func writeFixture(named name: String) throws -> URL {
        let url = temporaryURL(named: name)
        try makeTwoSegmentFixture().write(to: url)
        return url
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
    }

    private static func makeTwoSegmentFixture() -> Data {
        var data = Data()

        data.appendLE(UInt32(0xFEEDFACF))   // MH_MAGIC_64
        data.appendLE(UInt32(0x0100000C))   // CPU_TYPE_ARM64
        data.appendLE(UInt32(0))            // cpusubtype
        data.appendLE(UInt32(0x00000006))   // MH_DYLIB
        data.appendLE(UInt32(2))            // ncmds
        data.appendLE(UInt32(304))          // sizeofcmds = 152 + 152
        data.appendLE(UInt32(0))            // flags
        data.appendLE(UInt32(0))            // reserved

        // __TEXT segment with one __cstring section.
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(152))
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(0))
        data.appendLE(UInt64(768))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(0))

        data.appendFixedCString("__cstring", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1200))
        data.appendLE(UInt64(12))
        data.appendLE(UInt32(512))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x02))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __DATA segment with one __const section.
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(152))
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x2000))
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(768))
        data.appendLE(UInt64(256))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(0))

        data.appendFixedCString("__const", length: 16)
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x2300))
        data.appendLE(UInt64(8))
        data.appendLE(UInt32(768))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        data.append(Data(count: 512 - data.count))
        data.append(contentsOf: "Hello".utf8)
        data.append(0)
        data.append(contentsOf: "World".utf8)
        data.append(0)
        data.append(Data(count: 768 - data.count))
        data.append(Data([0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD]))
        data.append(Data(count: 1024 - data.count))
        return data
    }

    private static func makeLoaderDescriptor(magic: UInt32, version: UInt32, count: UInt32) -> Data {
        var data = Data()
        data.appendLE(magic)
        data.appendLE(version)
        data.appendLE(count)
        data.appendLE(UInt32(0xDEADBEEF))        // name_hash
        data.appendLE(UInt64(0x2000))            // vm_addr
        data.appendLE(UInt64(16))                // size
        data.append(Data(repeating: 0xAB, count: 32))
        return data
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
