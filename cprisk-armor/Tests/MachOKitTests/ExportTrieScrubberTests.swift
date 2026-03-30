import XCTest
import MachOKit
import SymbolStripper

final class ExportTrieScrubberTests: XCTestCase {

    private static let dyldInfoCommandOffset = 32 + 72
    private static let exportOffFieldOffset = dyldInfoCommandOffset + 40
    private static let exportSizeFieldOffset = dyldInfoCommandOffset + 44
    private static let exportBlobOffset = 0x1000
    private static let exportBlobSize = 0x80

    func testScrubsExportTrieForExecutable() throws {
        let url = try Self.writeFixture(named: "export_scrub_exec", fileType: MachOHeader.MH_EXECUTE)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        XCTAssertEqual(try file.readUInt32(at: Self.exportOffFieldOffset), UInt32(Self.exportBlobOffset))
        XCTAssertEqual(try file.readUInt32(at: Self.exportSizeFieldOffset), UInt32(Self.exportBlobSize))
        XCTAssertNotNil(file.data.range(of: Data("_cpra_0114".utf8)))

        let result = try ExportTrieScrubberPass().execute(on: file, config: PassConfig(buildSeed: 0x11))

        XCTAssertEqual(try file.readUInt32(at: Self.exportOffFieldOffset), 0)
        XCTAssertEqual(try file.readUInt32(at: Self.exportSizeFieldOffset), 0)
        XCTAssertNil(file.data.range(of: Data("_cpra_0114".utf8)))
        XCTAssertEqual(result.passName, "ExportTrieScrubber")
        XCTAssertEqual(result.itemsProcessed, 1)
        XCTAssertGreaterThan(result.bytesModified, 0)
    }

    func testSkipsNonExecutableImages() throws {
        let url = try Self.writeFixture(named: "export_scrub_dylib", fileType: MachOHeader.MH_DYLIB)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let beforeOff = try file.readUInt32(at: Self.exportOffFieldOffset)
        let beforeSize = try file.readUInt32(at: Self.exportSizeFieldOffset)

        let result = try ExportTrieScrubberPass().execute(on: file, config: PassConfig(buildSeed: 0x22))

        XCTAssertEqual(try file.readUInt32(at: Self.exportOffFieldOffset), beforeOff)
        XCTAssertEqual(try file.readUInt32(at: Self.exportSizeFieldOffset), beforeSize)
        XCTAssertNotNil(file.data.range(of: Data("_cpra_0114".utf8)))
        XCTAssertEqual(result.itemsProcessed, 0)
        XCTAssertEqual(result.bytesModified, 0)
        XCTAssertTrue(result.details.contains { $0.contains("Skipped: file type") })
    }

    private static func writeFixture(named name: String, fileType: UInt32) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
        try makeFixture(fileType: fileType).write(to: url)
        return url
    }

    private static func makeFixture(fileType: UInt32) -> Data {
        var d = Data()

        // mach_header_64
        d.appendLE32(0xFEEDFACF) // magic
        d.appendLE32(0x0100000C) // CPU_TYPE_ARM64
        d.appendLE32(0)          // cpusubtype
        d.appendLE32(fileType)   // MH_EXECUTE / MH_DYLIB
        d.appendLE32(2)          // ncmds: LC_SEGMENT_64 + LC_DYLD_INFO_ONLY
        d.appendLE32(120)        // sizeofcmds (72 + 48)
        d.appendLE32(0)          // flags
        d.appendLE32(0)          // reserved

        // LC_SEGMENT_64 __TEXT (no sections)
        d.appendLE32(0x19)       // cmd
        d.appendLE32(72)         // cmdsize
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE64(0)          // vmaddr
        d.appendLE64(0x2000)     // vmsize
        d.appendLE64(0)          // fileoff
        d.appendLE64(0x2000)     // filesize
        d.appendLE32(5)          // maxprot
        d.appendLE32(5)          // initprot
        d.appendLE32(0)          // nsects
        d.appendLE32(0)          // flags

        // LC_DYLD_INFO_ONLY
        d.appendLE32(0x80000022)             // cmd
        d.appendLE32(48)                     // cmdsize
        d.appendLE32(0)                      // rebase_off
        d.appendLE32(0)                      // rebase_size
        d.appendLE32(0)                      // bind_off
        d.appendLE32(0)                      // bind_size
        d.appendLE32(0)                      // weak_bind_off
        d.appendLE32(0)                      // weak_bind_size
        d.appendLE32(0)                      // lazy_bind_off
        d.appendLE32(0)                      // lazy_bind_size
        d.appendLE32(UInt32(exportBlobOffset)) // export_off
        d.appendLE32(UInt32(exportBlobSize))   // export_size

        d.append(Data(count: exportBlobOffset - d.count))
        var exportBlob = Data(repeating: 0x7A, count: exportBlobSize)
        let marker = Data("_cpra_0114".utf8)
        exportBlob.replaceSubrange(8..<(8 + marker.count), with: marker)
        d.append(exportBlob)

        return d
    }
}

private extension Data {
    mutating func appendLE32(_ value: UInt32) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 4))
    }

    mutating func appendLE64(_ value: UInt64) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 8))
    }

    mutating func appendFixedCString(_ string: String, length: Int) {
        var bytes = Array(string.utf8.prefix(length))
        while bytes.count < length { bytes.append(0) }
        append(contentsOf: bytes)
    }
}
