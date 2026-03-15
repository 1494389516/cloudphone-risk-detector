import XCTest
import MachOKit

final class MachOKitTests: XCTestCase {

    // MARK: - Test Data Builder

    /// Build a minimal valid ARM64 Mach-O (MH_DYLIB) in memory.
    static func makeMinimalMachO(
        cstringOffset: Int = 256,
        fileSize: Int = 512,
        includeCodeSignature: Bool = false,
        codeSignatureOffset: Int = 400,
        codeSignatureSize: Int = 16
    ) -> Data {
        precondition(cstringOffset >= 200)
        precondition(fileSize > cstringOffset + 12)

        let loadCommandCount: UInt32 = includeCodeSignature ? 2 : 1
        let sizeOfCommands: UInt32 = includeCodeSignature ? 168 : 152

        var data = Data()

        // -- mach_header_64 (32 bytes) --
        data.appendLE(UInt32(0xFEEDFACF))  // magic
        data.appendLE(UInt32(0x0100000C))  // CPU_TYPE_ARM64
        data.appendLE(UInt32(0x00000000))  // cpusubtype
        data.appendLE(UInt32(0x00000006))  // filetype = MH_DYLIB
        data.appendLE(loadCommandCount)    // ncmds
        data.appendLE(sizeOfCommands)      // sizeofcmds
        data.appendLE(UInt32(0))           // flags
        data.appendLE(UInt32(0))           // reserved
        assert(data.count == 32)

        // -- segment_command_64 for __TEXT (72 bytes) --
        data.appendLE(UInt32(0x19))        // cmd = LC_SEGMENT_64
        data.appendLE(UInt32(152))         // cmdsize = 72 + 80
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0))           // vmaddr
        data.appendLE(UInt64(fileSize))    // vmsize
        data.appendLE(UInt64(0))           // fileoff
        data.appendLE(UInt64(fileSize))    // filesize
        data.appendLE(UInt32(5))           // maxprot (r-x)
        data.appendLE(UInt32(5))           // initprot
        data.appendLE(UInt32(1))           // nsects
        data.appendLE(UInt32(0))           // flags
        assert(data.count == 104)

        // -- section_64 for __cstring (80 bytes) --
        data.appendFixedCString("__cstring", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(cstringOffset)) // addr
        data.appendLE(UInt64(12))            // size
        data.appendLE(UInt32(cstringOffset)) // offset
        data.appendLE(UInt32(0))             // align
        data.appendLE(UInt32(0))             // reloff
        data.appendLE(UInt32(0))             // nreloc
        data.appendLE(UInt32(0x02))          // flags = S_CSTRING_LITERALS
        data.appendLE(UInt32(0))             // reserved1
        data.appendLE(UInt32(0))             // reserved2
        data.appendLE(UInt32(0))             // reserved3
        assert(data.count == 184)

        if includeCodeSignature {
            data.appendLE(UInt32(LoadCommand.LC_CODE_SIGNATURE))
            data.appendLE(UInt32(16))
            data.appendLE(UInt32(codeSignatureOffset))
            data.appendLE(UInt32(codeSignatureSize))
            assert(data.count == 200)
        }

        data.append(Data(count: cstringOffset - data.count))
        data.append(contentsOf: "Hello".utf8)
        data.append(0)
        data.append(contentsOf: "World".utf8)
        data.append(0)

        if includeCodeSignature {
            if data.count < codeSignatureOffset {
                data.append(Data(count: codeSignatureOffset - data.count))
            }
            data.append(Data(repeating: 0xAA, count: codeSignatureSize))
        }

        if data.count < fileSize {
            data.append(Data(count: fileSize - data.count))
        }
        return data
    }

    // MARK: - 1. Header Parsing

    func testHeaderParsing() throws {
        let data = Self.makeMinimalMachO()
        let header = try MachOHeader(from: data)

        XCTAssertTrue(header.isValid)
        XCTAssertEqual(header.magic, 0xFEEDFACF)
        XCTAssertEqual(header.cpuType, 0x0100000C)
        XCTAssertEqual(header.cpuSubtype, 0)
        XCTAssertEqual(header.fileType, 6)
        XCTAssertEqual(header.numberOfCommands, 1)
        XCTAssertEqual(header.sizeOfCommands, 152)
    }

    func testHeaderInvalidMagic() {
        var data = Self.makeMinimalMachO()
        data[0] = 0x00
        let header = try? MachOHeader(from: data)
        XCTAssertNotNil(header)
        XCTAssertFalse(header!.isValid)
    }

    func testHeaderTooSmall() {
        let data = Data(count: 16)
        XCTAssertThrowsError(try MachOHeader(from: data))
    }

    // MARK: - 2. LoadCommand Parsing

    func testLoadCommandParsing() throws {
        let data = Self.makeMinimalMachO()
        let command = try LoadCommand(from: data, offset: UInt64(MachOHeader.size))

        XCTAssertEqual(command.cmd, LoadCommand.LC_SEGMENT_64)
        XCTAssertEqual(command.cmdSize, 152)
        XCTAssertEqual(command.offset, UInt64(MachOHeader.size))
        XCTAssertEqual(command.rawData.count, 152)
    }

    func testLoadCommandTooSmall() {
        let data = Data(count: 40)
        XCTAssertThrowsError(try LoadCommand(from: data, offset: 38))
    }

    // MARK: - 3. Segment / Section Parsing

    func testSegmentParsing() throws {
        let data = Self.makeMinimalMachO()
        let segment = try Segment(from: data, commandOffset: UInt64(MachOHeader.size))

        XCTAssertEqual(segment.name, "__TEXT")
        XCTAssertEqual(segment.vmAddress, 0)
        XCTAssertEqual(segment.vmSize, 512)
        XCTAssertEqual(segment.fileOffset, 0)
        XCTAssertEqual(segment.fileSize, 512)
        XCTAssertEqual(segment.maxProt, 5)
        XCTAssertEqual(segment.initProt, 5)
        XCTAssertEqual(segment.numberOfSections, 1)
        XCTAssertEqual(segment.sections.count, 1)
    }

    func testSectionParsing() throws {
        let data = Self.makeMinimalMachO()
        let segment = try Segment(from: data, commandOffset: UInt64(MachOHeader.size))
        let section = segment.sections[0]

        XCTAssertEqual(section.sectionName, "__cstring")
        XCTAssertEqual(section.segmentName, "__TEXT")
        XCTAssertEqual(section.address, 256)
        XCTAssertEqual(section.size, 12)
        XCTAssertEqual(section.offset, 256)
        XCTAssertEqual(section.flags, 0x02)
    }

    func testSectionReadContent() throws {
        let data = Self.makeMinimalMachO()
        let segment = try Segment(from: data, commandOffset: UInt64(MachOHeader.size))
        let section = segment.sections[0]
        let content = try section.readContent(from: data)

        XCTAssertEqual(content.count, 12)
        XCTAssertEqual(String(data: content.subdata(in: 0..<5), encoding: .utf8), "Hello")
        XCTAssertEqual(content[5], 0)
        XCTAssertEqual(String(data: content.subdata(in: 6..<11), encoding: .utf8), "World")
    }

    // MARK: - 4. Byte Replacement

    func testReplaceBytes() throws {
        var data = Self.makeMinimalMachO()
        XCTAssertEqual(data[256], 0x48) // 'H'

        try MachOWriter.replaceBytes(in: &data, at: 256, with: Data([0xFF, 0xEE]))

        XCTAssertEqual(data[256], 0xFF)
        XCTAssertEqual(data[257], 0xEE)
        XCTAssertEqual(data[258], 0x6C) // 'l' unchanged
    }

    func testReplaceBytesOutOfBoundsThrows() {
        var data = Data(count: 10)
        data[5] = 0xAA

        XCTAssertThrowsError(try MachOWriter.replaceBytes(in: &data, at: 9, with: Data([0x01, 0x02])))
        XCTAssertEqual(data[5], 0xAA)
        XCTAssertEqual(data[9], 0x00)
    }

    // MARK: - 5. C String Scanning

    func testFindCStrings() throws {
        let data = Self.makeMinimalMachO()
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("test_\(UUID().uuidString).macho")
        try data.write(to: tempURL)
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let file = try MachOFile(url: tempURL)
        let strings = try file.findCStrings()

        XCTAssertEqual(strings.count, 2)
        XCTAssertEqual(strings[0].value, "Hello")
        XCTAssertEqual(strings[0].offset, 256)
        XCTAssertEqual(strings[1].value, "World")
        XCTAssertEqual(strings[1].offset, 262)
    }

    // MARK: - 6. Write / Reparse

    func testMachOFileLoading() throws {
        let data = Self.makeMinimalMachO()
        let tempURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("test_\(UUID().uuidString).macho")
        try data.write(to: tempURL)
        defer { try? FileManager.default.removeItem(at: tempURL) }

        let file = try MachOFile(url: tempURL)
        XCTAssertTrue(file.header.isValid)
        XCTAssertEqual(file.loadCommands.count, 1)

        let segments = try file.segments()
        XCTAssertEqual(segments.count, 1)
        XCTAssertEqual(segments[0].name, "__TEXT")

        let section = try file.section(segment: "__TEXT", section: "__cstring")
        XCTAssertNotNil(section)
        XCTAssertEqual(section?.size, 12)
    }

    func testMachOFileWriteRoundTrip() throws {
        let data = Self.makeMinimalMachO()
        let inputURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("test_in_\(UUID().uuidString).macho")
        let outputURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("test_out_\(UUID().uuidString).macho")
        try data.write(to: inputURL)
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let file = try MachOFile(url: inputURL)
        try file.replaceBytes(at: 256, with: Data([0x4A])) // 'H' -> 'J'
        let validation = try file.write(to: outputURL)

        XCTAssertFalse(validation.codeSignatureWasInvalidated)
        XCTAssertEqual(validation.report.segmentCount, 1)

        let reloaded = try MachOFile(url: outputURL)
        let strings = try reloaded.findCStrings()
        XCTAssertEqual(strings[0].value, "Jello")
    }

    func testWriteInvalidatesCodeSignatureAndRoundTrips() throws {
        let data = Self.makeMinimalMachO(includeCodeSignature: true)
        let inputURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("codesig_in_\(UUID().uuidString).macho")
        let outputURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("codesig_out_\(UUID().uuidString).macho")
        try data.write(to: inputURL)
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let file = try MachOFile(url: inputURL)
        try file.replaceBytes(at: 256, with: Data([0x4A]))
        let validation = try file.write(to: outputURL)

        XCTAssertTrue(validation.codeSignatureWasInvalidated)
        XCTAssertEqual(validation.report.codeSignatureCommandCount, 1)

        let writtenData = try Data(contentsOf: outputURL)
        XCTAssertEqual(try writtenData.readLEUInt32(at: 192), 0)
        XCTAssertEqual(try writtenData.readLEUInt32(at: 196), 0)

        let reparsed = try MachOFile(url: outputURL)
        let strings = try reparsed.findCStrings()
        XCTAssertEqual(strings.first?.value, "Jello")
    }

    // MARK: - 7. Section Insertion

    func testAddSectionFailsWithoutHeaderPadding() {
        var data = Self.makeMinimalMachO()

        XCTAssertThrowsError(
            try MachOWriter.addSection(
                to: &data,
                segment: "__TEXT",
                section: "__test_sect",
                content: Data([0x01, 0x02, 0x03, 0x04]),
                protection: 5
            )
        ) { error in
            guard case MachOError.insufficientSpace = error else {
                return XCTFail("Expected insufficientSpace, got \(error)")
            }
        }
    }

    func testAddSectionUpdatesHeaderAndSegmentSizing() throws {
        var data = Self.makeMinimalMachO(cstringOffset: 336, fileSize: 640)
        let newSection = try MachOWriter.addSection(
            to: &data,
            segment: "__TEXT",
            section: "__test_sect",
            content: Data([0x01, 0x02, 0x03, 0x04]),
            protection: 5
        )

        XCTAssertEqual(newSection.offset, 640)
        XCTAssertEqual(newSection.address, 640)
        XCTAssertEqual(newSection.size, 4)

        let header = try MachOHeader(from: data)
        XCTAssertEqual(header.numberOfCommands, 1)
        XCTAssertEqual(header.sizeOfCommands, 232)

        let segment = try Segment(from: data, commandOffset: UInt64(MachOHeader.size))
        XCTAssertEqual(segment.numberOfSections, 2)
        XCTAssertEqual(segment.sections.count, 2)
        XCTAssertEqual(segment.sections[1].sectionName, "__test_sect")
        XCTAssertEqual(segment.fileSize, 644)
        XCTAssertEqual(segment.vmSize, 644)
    }

    func testUpdateHeader() throws {
        var data = Self.makeMinimalMachO()
        try MachOWriter.updateHeader(in: &data, numberOfCommands: 42, sizeOfCommands: 9999)

        let header = try MachOHeader(from: data)
        XCTAssertEqual(header.numberOfCommands, 42)
        XCTAssertEqual(header.sizeOfCommands, 9999)
    }
}

// MARK: - Data Helpers for Test Construction

private extension Data {
    mutating func appendLE(_ value: UInt32) {
        var littleEndianValue = value.littleEndian
        append(Data(bytes: &littleEndianValue, count: 4))
    }

    mutating func appendLE(_ value: UInt64) {
        var littleEndianValue = value.littleEndian
        append(Data(bytes: &littleEndianValue, count: 8))
    }

    mutating func appendFixedCString(_ string: String, length: Int) {
        var bytes = Array(string.utf8.prefix(length))
        while bytes.count < length { bytes.append(0) }
        append(contentsOf: bytes)
    }

    func readLEUInt32(at offset: Int) throws -> UInt32 {
        guard offset >= 0, offset + 4 <= count else {
            throw MachOError.outOfBoundsRead(offset: offset, size: 4, dataSize: count)
        }
        var value: UInt32 = 0
        _ = Swift.withUnsafeMutableBytes(of: &value) { (destination: UnsafeMutableRawBufferPointer) in
            copyBytes(to: destination, from: offset..<(offset + 4))
        }
        return UInt32(littleEndian: value)
    }
}
