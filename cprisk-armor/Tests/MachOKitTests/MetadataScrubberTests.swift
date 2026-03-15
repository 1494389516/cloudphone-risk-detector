import XCTest
import MachOKit
import MetadataScrubber

final class MetadataScrubberTests: XCTestCase {

    // MARK: - A. Swift Type Name Obfuscation

    func testObfuscatesNonPublicAndNonSDKPublicTypes() throws {
        let (file, url) = try Self.loadFixture(named: "type_names")
        defer { try? FileManager.default.removeItem(at: url) }

        let before = try file.findSwiftTypeMetadata()
        XCTAssertEqual(before.count, 3)
        XCTAssertEqual(before[0].name, "_InternalHelper")
        XCTAssertFalse(before[0].isPublic)
        XCTAssertEqual(before[1].name, "CPRiskDetector")
        XCTAssertTrue(before[1].isPublic)
        XCTAssertEqual(before[2].name, "BusinessLogic")
        XCTAssertTrue(before[2].isPublic)

        let pass = MetadataScrubberPass()
        let result = try pass.execute(on: file, config: PassConfig())

        let after = try file.findSwiftTypeMetadata()

        // _InternalHelper: non-public → obfuscated, same length
        XCTAssertNotEqual(after[0].name, "_InternalHelper")
        XCTAssertEqual(after[0].name.count, "_InternalHelper".count)

        // CPRiskDetector: public + contains "CPRisk" → preserved
        XCTAssertEqual(after[1].name, "CPRiskDetector")

        // BusinessLogic: public, no SDK marker → obfuscated, same length
        XCTAssertNotEqual(after[2].name, "BusinessLogic")
        XCTAssertEqual(after[2].name.count, "BusinessLogic".count)

        XCTAssertTrue(result.details.contains { $0.contains("2/3") })
        XCTAssertGreaterThan(result.bytesModified, 0)
    }

    // MARK: - B. Reflection String Scrubbing

    func testReflectionStringsScrubbed() throws {
        let (file, url) = try Self.loadFixture(named: "reflstr")
        defer { try? FileManager.default.removeItem(at: url) }

        let section = try XCTUnwrap(
            try file.section(segment: "__TEXT", section: "__swift5_reflstr")
        )
        let originalContent = file.data.subdata(
            in: Int(section.offset)..<(Int(section.offset) + Int(section.size))
        )
        XCTAssertEqual(originalContent.count, 32)

        let pass = MetadataScrubberPass()
        let result = try pass.execute(on: file, config: PassConfig())

        let modifiedContent = file.data.subdata(
            in: Int(section.offset)..<(Int(section.offset) + Int(section.size))
        )
        XCTAssertEqual(modifiedContent.count, 32)
        XCTAssertNotEqual(modifiedContent, originalContent)
        XCTAssertTrue(result.details.contains { $0.contains("Reflection strings scrubbed: 32 bytes") })
    }

    // MARK: - C. ObjC Method Name Obfuscation

    func testObjCMethodNameObfuscation() throws {
        let (file, url) = try Self.loadFixture(named: "objc_meth")
        defer { try? FileManager.default.removeItem(at: url) }

        let pass = MetadataScrubberPass()
        let result = try pass.execute(on: file, config: PassConfig())

        let section = try XCTUnwrap(
            try file.section(segment: "__TEXT", section: "__objc_methname")
        )
        let content = try section.readContent(from: file.data)
        let methods = Self.parseCStrings(from: content)

        // System-prefixed methods preserved
        XCTAssertTrue(methods.contains("initWithFrame:"))
        XCTAssertTrue(methods.contains("setTitle:"))

        // Business methods obfuscated (original names gone)
        XCTAssertFalse(methods.contains("fetchUserData"))
        XCTAssertFalse(methods.contains("doSomething"))

        XCTAssertTrue(result.details.contains { $0.contains("ObjC method names obfuscated: 2/4") })
    }

    // MARK: - D. Structural Preservation

    func testSwiftTypesRelativePointersUntouched() throws {
        let (file, url) = try Self.loadFixture(named: "preserve")
        defer { try? FileManager.default.removeItem(at: url) }

        let typesSection = try XCTUnwrap(
            try file.section(segment: "__TEXT", section: "__swift5_types")
        )
        let originalPointers = file.data.subdata(
            in: Int(typesSection.offset)..<(Int(typesSection.offset) + Int(typesSection.size))
        )

        let pass = MetadataScrubberPass()
        _ = try pass.execute(on: file, config: PassConfig())

        let afterPointers = file.data.subdata(
            in: Int(typesSection.offset)..<(Int(typesSection.offset) + Int(typesSection.size))
        )
        XCTAssertEqual(originalPointers, afterPointers,
                        "Relative pointer table must not be modified")
    }

    func testGracefulWithNoMetadataSections() throws {
        let data = MachOKitTests.makeMinimalMachO()
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("meta_empty_\(UUID().uuidString).macho")
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let pass = MetadataScrubberPass()
        let result = try pass.execute(on: file, config: PassConfig())

        XCTAssertEqual(result.itemsProcessed, 0)
        XCTAssertEqual(result.bytesModified, 0)
    }

    func testPassResultReportsCorrectTotals() throws {
        let (file, url) = try Self.loadFixture(named: "totals")
        defer { try? FileManager.default.removeItem(at: url) }

        let pass = MetadataScrubberPass()
        let result = try pass.execute(on: file, config: PassConfig())

        // 2 type names + 1 reflstr section + 2 objc methods = 5 items
        XCTAssertEqual(result.itemsProcessed, 5)
        XCTAssertEqual(result.passName, "MetadataScrubber")

        // bytes: 15 (_InternalHelper) + 13 (BusinessLogic)
        //      + 32 (reflstr)
        //      + 13 (fetchUserData) + 11 (doSomething) = 84
        XCTAssertEqual(result.bytesModified, 84)
    }

    // MARK: - Helpers

    private static func loadFixture(named label: String) throws -> (MachOFile, URL) {
        let data = makeMetadataFixture()
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(label)_\(UUID().uuidString).macho")
        try data.write(to: url)
        return (try MachOFile(url: url), url)
    }

    private static func parseCStrings(from data: Data) -> [String] {
        var strings = [String]()
        var position = 0
        while position < data.count {
            var end = position
            while end < data.count && data[end] != 0 { end += 1 }
            if end > position,
               let s = String(data: data.subdata(in: position..<end), encoding: .utf8)
            {
                strings.append(s)
            }
            position = end + 1
        }
        return strings
    }

    // MARK: - Fixture Builder
    //
    // Layout (1024 bytes total):
    //
    //   [  0,  32)  mach_header_64
    //   [ 32, 344)  LC_SEGMENT_64 __TEXT  (72 hdr + 3×80 sections = 312)
    //   [344, 384)  padding
    //   [384, 396)  __swift5_types    (3 entries × 4 = 12 bytes)
    //   [396, 432)  type descriptors  (3 × 12 = 36 bytes)
    //   [432, 477)  name strings      (3 null-terminated C strings)
    //   [477, 480)  padding
    //   [480, 512)  __swift5_reflstr  (32 bytes)
    //   [512, 563)  __objc_methname   (4 null-terminated method names, 51 bytes)
    //   [563,1024)  zero padding
    //
    // Relative pointer math:
    //   entry[i] at (384 + i*4) stores Int32 offset to descriptor[i]
    //   descriptor[i].nameField at (descriptor + 8) stores Int32 offset to name string

    private static func makeMetadataFixture() -> Data {
        var d = Data()

        // ── mach_header_64 (32 bytes) ──
        d.appendLE(UInt32(0xFEEDFACF))
        d.appendLE(UInt32(0x0100000C))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0x00000006))
        d.appendLE(UInt32(1))             // ncmds
        d.appendLE(UInt32(312))           // sizeofcmds = 72 + 3*80
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        assert(d.count == 32)

        // ── LC_SEGMENT_64 __TEXT header (72 bytes) ──
        d.appendLE(UInt32(0x19))          // LC_SEGMENT_64
        d.appendLE(UInt32(312))           // cmdsize
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(0))             // vmaddr
        d.appendLE(UInt64(1024))          // vmsize
        d.appendLE(UInt64(0))             // fileoff
        d.appendLE(UInt64(1024))          // filesize
        d.appendLE(UInt32(5))             // maxprot
        d.appendLE(UInt32(5))             // initprot
        d.appendLE(UInt32(3))             // nsects
        d.appendLE(UInt32(0))
        assert(d.count == 104)

        // ── section_64: __swift5_types (80 bytes) ──
        d.appendFixedCString("__swift5_types", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(384))           // addr
        d.appendLE(UInt64(12))            // size  (3 entries)
        d.appendLE(UInt32(384))           // offset
        d.appendLE(UInt32(2))             // align
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))             // flags
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        assert(d.count == 184)

        // ── section_64: __swift5_reflstr (80 bytes) ──
        d.appendFixedCString("__swift5_reflstr", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(480))           // addr
        d.appendLE(UInt64(32))            // size
        d.appendLE(UInt32(480))           // offset
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        assert(d.count == 264)

        // ── section_64: __objc_methname (80 bytes) ──
        d.appendFixedCString("__objc_methname", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(512))           // addr
        d.appendLE(UInt64(51))            // size
        d.appendLE(UInt32(512))           // offset
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        d.appendLE(UInt32(0x02))          // S_CSTRING_LITERALS
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        assert(d.count == 344)

        // ── padding to content start ──
        d.append(Data(count: 384 - d.count))

        // ── __swift5_types entries (3 × Int32 relative pointers) ──
        //   entry[0] at 384 → descriptor at 396:  384 + 12 = 396
        //   entry[1] at 388 → descriptor at 408:  388 + 20 = 408
        //   entry[2] at 392 → descriptor at 420:  392 + 28 = 420
        d.appendLE(Int32(12))
        d.appendLE(Int32(20))
        d.appendLE(Int32(28))
        assert(d.count == 396)

        // ── type descriptors (3 × 12 bytes: flags, parent, name_rel) ──
        //   desc[0] at 396, nameField at 404 → name at 432: 404 + 28 = 432
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(Int32(28))
        assert(d.count == 408)
        //   desc[1] at 408, nameField at 416 → name at 448: 416 + 32 = 448
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(Int32(32))
        assert(d.count == 420)
        //   desc[2] at 420, nameField at 428 → name at 463: 428 + 35 = 463
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(Int32(35))
        assert(d.count == 432)

        // ── name strings ──
        d.append(contentsOf: "_InternalHelper".utf8); d.append(0)  // 16 bytes → [432,448)
        assert(d.count == 448)
        d.append(contentsOf: "CPRiskDetector".utf8); d.append(0)   // 15 bytes → [448,463)
        assert(d.count == 463)
        d.append(contentsOf: "BusinessLogic".utf8); d.append(0)    // 14 bytes → [463,477)
        assert(d.count == 477)

        d.append(Data(count: 480 - d.count))  // pad to 480

        // ── __swift5_reflstr content (32 bytes) ──
        let reflStr = "SomeField\0TypeName\0Extra\0Pad\0XX"  // 30 bytes
        d.append(contentsOf: reflStr.utf8)
        d.append(Data(count: 512 - d.count))   // pad to 512
        assert(d.count == 512)

        // ── __objc_methname content (51 bytes) ──
        d.append(contentsOf: "initWithFrame:".utf8); d.append(0)   // 15
        d.append(contentsOf: "fetchUserData".utf8);  d.append(0)   // 14  → 29
        d.append(contentsOf: "setTitle:".utf8);      d.append(0)   // 10  → 39
        d.append(contentsOf: "doSomething".utf8);    d.append(0)   // 12  → 51
        assert(d.count == 563)

        d.append(Data(count: 1024 - d.count))
        return d
    }
}

// MARK: - Data Helpers (private to this file, same pattern as other test files)

private extension Data {
    mutating func appendLE(_ value: UInt32) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 4))
    }

    mutating func appendLE(_ value: UInt64) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 8))
    }

    mutating func appendLE(_ value: Int32) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 4))
    }

    mutating func appendFixedCString(_ string: String, length: Int) {
        var bytes = Array(string.utf8.prefix(length))
        while bytes.count < length { bytes.append(0) }
        append(contentsOf: bytes)
    }
}
