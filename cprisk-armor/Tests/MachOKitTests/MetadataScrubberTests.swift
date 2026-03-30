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

        XCTAssertNotEqual(after[0].name, "_InternalHelper")
        XCTAssertEqual(after[0].name.count, "_InternalHelper".count)

        XCTAssertNotEqual(after[1].name, "CPRiskDetector")
        XCTAssertEqual(after[1].name.count, "CPRiskDetector".count)

        XCTAssertNotEqual(after[2].name, "BusinessLogic")
        XCTAssertEqual(after[2].name.count, "BusinessLogic".count)

        XCTAssertTrue(result.details.contains { $0.contains("3/3") })
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

    // MARK: - B2. Additional Metadata Section Scrubbing

    func testAdditionalMetadataSectionsScrubbed() throws {
        let (file, url) = try Self.loadFixture(named: "extra_sections", useExtendedFixture: true)
        defer { try? FileManager.default.removeItem(at: url) }

        let fieldmd = try XCTUnwrap(
            try file.section(segment: "__TEXT", section: "__swift5_fieldmd")
        )
        let originalFieldmd = file.data.subdata(
            in: Int(fieldmd.offset)..<(Int(fieldmd.offset) + Int(fieldmd.size))
        )

        let capture = try XCTUnwrap(
            try file.section(segment: "__TEXT", section: "__swift5_capture")
        )
        let originalCapture = file.data.subdata(
            in: Int(capture.offset)..<(Int(capture.offset) + Int(capture.size))
        )

        let pass = MetadataScrubberPass()
        let result = try pass.execute(on: file, config: PassConfig())

        let modifiedFieldmd = file.data.subdata(
            in: Int(fieldmd.offset)..<(Int(fieldmd.offset) + Int(fieldmd.size))
        )
        XCTAssertNotEqual(modifiedFieldmd, originalFieldmd)

        let modifiedCapture = file.data.subdata(
            in: Int(capture.offset)..<(Int(capture.offset) + Int(capture.size))
        )
        XCTAssertNotEqual(modifiedCapture, originalCapture)

        XCTAssertTrue(result.details.contains { $0.contains("Swift metadata sections (conservative, string payloads):") })
    }

    func testAdditionalMetadataSectionsAggressiveFullOverwrite() throws {
        let (file, url) = try Self.loadFixture(named: "extra_aggr", useExtendedFixture: true)
        defer { try? FileManager.default.removeItem(at: url) }

        let fieldmd = try XCTUnwrap(
            try file.section(segment: "__TEXT", section: "__swift5_fieldmd")
        )
        let originalFieldmd = file.data.subdata(
            in: Int(fieldmd.offset)..<(Int(fieldmd.offset) + Int(fieldmd.size))
        )

        let pass = MetadataScrubberPass()
        let result = try pass.execute(
            on: file,
            config: PassConfig(swiftMetadataScrubLevel: .aggressive)
        )

        let modifiedFieldmd = file.data.subdata(
            in: Int(fieldmd.offset)..<(Int(fieldmd.offset) + Int(fieldmd.size))
        )
        XCTAssertNotEqual(modifiedFieldmd, originalFieldmd)
        XCTAssertTrue(result.details.contains { $0.contains("Swift metadata sections (aggressive, full overwrite):") })
    }

    // MARK: - C. ObjC Method Name Obfuscation (aggressive mode)

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

        // System methods preserved (init prefix)
        XCTAssertTrue(methods.contains("initWithFrame:"))

        // Non-system methods are now ALL obfuscated (aggressive mode)
        XCTAssertFalse(methods.contains("cpriskCollect"))
        XCTAssertFalse(methods.contains("CPRiskCheck"))
        XCTAssertFalse(methods.contains("setTitle:"))

        // 3 out of 4 obfuscated: cpriskCollect, CPRiskCheck, setTitle: (all non-system)
        // initWithFrame: preserved (init prefix)
        XCTAssertTrue(result.details.contains { $0.contains("ObjC method names obfuscated: 3/4") })
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

        // 3 type names + 1 reflstr + 3 objc methods (aggressive: all non-system) = 7 items
        XCTAssertEqual(result.itemsProcessed, 7)
        XCTAssertEqual(result.passName, "MetadataScrubber")

        // bytes: 15 (_InternalHelper) + 14 (CPRiskDetector) + 13 (BusinessLogic)
        //      + 32 (reflstr)
        //      + 13 (cpriskCollect) + 9 (setTitle:) + 11 (CPRiskCheck) = 107
        XCTAssertEqual(result.bytesModified, 107)
    }

    // MARK: - Swift semantic leak (CString + catalog)

    func testCStringSemanticReportAndScrub() throws {
        let (file, url) = try Self.makeMachOWithRiskCString()
        defer { try? FileManager.default.removeItem(at: url) }

        let report = try MetadataScrubberPass().execute(
            on: file,
            config: PassConfig(
                swiftSemanticLeakOptions: SwiftSemanticLeakOptions(
                    reportCStringSemanticMatches: true,
                    scrubCStringSemanticMatches: false
                )
            )
        )
        XCTAssertTrue(report.details.contains { $0.contains("Swift semantic CString scan: 1 match") })

        let (file2, url2) = try Self.makeMachOWithRiskCString()
        defer { try? FileManager.default.removeItem(at: url2) }
        _ = try MetadataScrubberPass().execute(
            on: file2,
            config: PassConfig(
                swiftSemanticLeakOptions: SwiftSemanticLeakOptions(
                    reportCStringSemanticMatches: true,
                    scrubCStringSemanticMatches: true
                )
            )
        )
        let strings = try file2.findCStrings()
        XCTAssertFalse(strings.contains { $0.value.contains("RiskDetection") })
    }

    func testSemanticDecoySectionBestEffort() throws {
        var d = MachOKitTests.makeMinimalMachO(cstringOffset: 256, fileSize: 512)
        let payload = "RiskDetectionEngineProbe\0"
        let pb = Data(payload.utf8)
        d.replaceSubrange(256..<(256+12), with: pb)
        Self.patchUInt64LE(&d, offset: 144, value: UInt64(pb.count))
        let newSize = UInt64(d.count)
        Self.patchUInt64LE(&d, offset: 64, value: newSize)
        Self.patchUInt64LE(&d, offset: 80, value: newSize)

        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("decoy_\(UUID().uuidString).macho")
        try d.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let result = try MetadataScrubberPass().execute(
            on: file,
            config: PassConfig(
                randomSeed: 0xC0FFEE,
                swiftSemanticLeakOptions: SwiftSemanticLeakOptions(injectSemanticDecoys: true)
            )
        )
        XCTAssertTrue(
            result.details.contains { $0.contains("Swift semantic decoy section __cp5_swdec") }
                || result.details.contains { $0.contains("Swift semantic decoys skipped") }
        )
    }

    // MARK: - Helpers

    private static func patchUInt64LE(_ data: inout Data, offset: Int, value: UInt64) {
        var le = value.littleEndian
        withUnsafeBytes(of: &le) { buf in
            data.replaceSubrange(offset..<(offset + 8), with: buf)
        }
    }

    /// Minimal dylib with `__TEXT.__cstring` containing a `riskdetection`-style literal (patched from `makeMinimalMachO`).
    private static func makeMachOWithRiskCString() throws -> (MachOFile, URL) {
        var d = MachOKitTests.makeMinimalMachO(cstringOffset: 256, fileSize: 512)
        let payload = "RiskDetectionEngineProbe\0"
        let pb = Data(payload.utf8)
        d.replaceSubrange(256..<(256+12), with: pb)
        patchUInt64LE(&d, offset: 144, value: UInt64(pb.count))
        let newSize = UInt64(d.count)
        patchUInt64LE(&d, offset: 64, value: newSize)
        patchUInt64LE(&d, offset: 80, value: newSize)
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("cstring_sem_\(UUID().uuidString).macho")
        try d.write(to: url)
        return (try MachOFile(url: url), url)
    }

    private static func loadFixture(
        named label: String,
        useExtendedFixture: Bool = false
    ) throws -> (MachOFile, URL) {
        let data = useExtendedFixture ? makeExtendedMetadataFixture() : makeMetadataFixture()
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

    // MARK: - Fixture Builder (base: 3 sections)
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
        d.appendLE(Int32(12))
        d.appendLE(Int32(20))
        d.appendLE(Int32(28))
        assert(d.count == 396)

        // ── type descriptors (3 × 12 bytes: flags, parent, name_rel) ──
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(Int32(28))
        assert(d.count == 408)
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(Int32(32))
        assert(d.count == 420)
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(Int32(35))
        assert(d.count == 432)

        // ── name strings ──
        d.append(contentsOf: "_InternalHelper".utf8); d.append(0)
        assert(d.count == 448)
        d.append(contentsOf: "CPRiskDetector".utf8); d.append(0)
        assert(d.count == 463)
        d.append(contentsOf: "BusinessLogic".utf8); d.append(0)
        assert(d.count == 477)

        d.append(Data(count: 480 - d.count))

        // ── __swift5_reflstr content (32 bytes) ──
        let reflStr = "SomeField\0TypeName\0Extra\0Pad\0XX"
        d.append(contentsOf: reflStr.utf8)
        d.append(Data(count: 512 - d.count))
        assert(d.count == 512)

        // ── __objc_methname content (51 bytes) ──
        d.append(contentsOf: "initWithFrame:".utf8); d.append(0)   // 15
        d.append(contentsOf: "cpriskCollect".utf8);  d.append(0)   // 14  → 29
        d.append(contentsOf: "setTitle:".utf8);      d.append(0)   // 10  → 39
        d.append(contentsOf: "CPRiskCheck".utf8);    d.append(0)   // 12  → 51
        assert(d.count == 563)

        d.append(Data(count: 1024 - d.count))
        return d
    }

    // MARK: - Extended Fixture (with additional metadata sections)
    //
    // Adds __swift5_fieldmd (24 bytes) and __swift5_capture (16 bytes) to the base layout.
    // Layout (2048 bytes total):
    //
    //   [   0,   32)  mach_header_64
    //   [  32,  504)  LC_SEGMENT_64 __TEXT  (72 hdr + 5×80 sections = 472)
    //   [ 504,  512)  padding
    //   [ 512,  524)  __swift5_types    (3 entries × 4 = 12 bytes)
    //   [ 524,  560)  type descriptors  (3 × 12 = 36 bytes)
    //   [ 560,  605)  name strings
    //   [ 605,  608)  padding
    //   [ 608,  640)  __swift5_reflstr  (32 bytes)
    //   [ 640,  691)  __objc_methname   (51 bytes)
    //   [ 691,  704)  padding
    //   [ 704,  728)  __swift5_fieldmd  (24 bytes)
    //   [ 728,  744)  __swift5_capture  (16 bytes)
    //   [ 744, 2048)  zero padding

    private static func makeExtendedMetadataFixture() -> Data {
        var d = Data()

        let nsects: UInt32 = 5
        let cmdsize: UInt32 = 72 + nsects * 80   // 472

        // ── mach_header_64 (32 bytes) ──
        d.appendLE(UInt32(0xFEEDFACF))
        d.appendLE(UInt32(0x0100000C))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0x00000006))
        d.appendLE(UInt32(1))             // ncmds
        d.appendLE(cmdsize)               // sizeofcmds
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        assert(d.count == 32)

        // ── LC_SEGMENT_64 __TEXT header (72 bytes) ──
        d.appendLE(UInt32(0x19))
        d.appendLE(cmdsize)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(0))             // vmaddr
        d.appendLE(UInt64(2048))          // vmsize
        d.appendLE(UInt64(0))             // fileoff
        d.appendLE(UInt64(2048))          // filesize
        d.appendLE(UInt32(5))
        d.appendLE(UInt32(5))
        d.appendLE(nsects)
        d.appendLE(UInt32(0))
        assert(d.count == 104)

        // ── section: __swift5_types ──
        d.appendFixedCString("__swift5_types", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(512)); d.appendLE(UInt64(12))
        d.appendLE(UInt32(512)); d.appendLE(UInt32(2))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        assert(d.count == 184)

        // ── section: __swift5_reflstr ──
        d.appendFixedCString("__swift5_reflstr", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(608)); d.appendLE(UInt64(32))
        d.appendLE(UInt32(608)); d.appendLE(UInt32(0))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        assert(d.count == 264)

        // ── section: __objc_methname ──
        d.appendFixedCString("__objc_methname", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(640)); d.appendLE(UInt64(51))
        d.appendLE(UInt32(640)); d.appendLE(UInt32(0))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        d.appendLE(UInt32(0x02))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        assert(d.count == 344)

        // ── section: __swift5_fieldmd ──
        d.appendFixedCString("__swift5_fieldmd", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(704)); d.appendLE(UInt64(24))
        d.appendLE(UInt32(704)); d.appendLE(UInt32(2))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        assert(d.count == 424)

        // ── section: __swift5_capture ──
        d.appendFixedCString("__swift5_capture", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(728)); d.appendLE(UInt64(16))
        d.appendLE(UInt32(728)); d.appendLE(UInt32(2))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(UInt32(0))
        assert(d.count == 504)

        // ── padding to content start ──
        d.append(Data(count: 512 - d.count))

        // ── __swift5_types entries ──
        d.appendLE(Int32(12))
        d.appendLE(Int32(20))
        d.appendLE(Int32(28))
        assert(d.count == 524)

        // ── type descriptors ──
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(Int32(28))   // → 560
        assert(d.count == 536)
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(Int32(32))   // → 576
        assert(d.count == 548)
        d.appendLE(UInt32(0)); d.appendLE(UInt32(0)); d.appendLE(Int32(35))   // → 591
        assert(d.count == 560)

        // ── name strings ──
        d.append(contentsOf: "_InternalHelper".utf8); d.append(0)
        assert(d.count == 576)
        d.append(contentsOf: "CPRiskDetector".utf8); d.append(0)
        assert(d.count == 591)
        d.append(contentsOf: "BusinessLogic".utf8); d.append(0)
        assert(d.count == 605)

        d.append(Data(count: 608 - d.count))

        // ── __swift5_reflstr (32 bytes) ──
        let reflStr = "SomeField\0TypeName\0Extra\0Pad\0XX"
        d.append(contentsOf: reflStr.utf8)
        d.append(Data(count: 640 - d.count))

        // ── __objc_methname (51 bytes) ──
        d.append(contentsOf: "initWithFrame:".utf8); d.append(0)
        d.append(contentsOf: "cpriskCollect".utf8);  d.append(0)
        d.append(contentsOf: "setTitle:".utf8);      d.append(0)
        d.append(contentsOf: "CPRiskCheck".utf8);    d.append(0)
        assert(d.count == 691)

        d.append(Data(count: 704 - d.count))

        // ── __swift5_fieldmd content (24 bytes of fake field descriptor data) ──
        d.append(contentsOf: "StoredRiskReport\0Padding".utf8)
        assert(d.count <= 728)
        d.append(Data(count: 728 - d.count))

        // ── __swift5_capture content (16 bytes of fake capture descriptor data) ──
        // Includes `isVip` fragment to exercise Swift semantic-leak catalog (not only generic "Risk").
        d.append(contentsOf: "isVipOnlyX\0\0\0\0\0\0".utf8)
        assert(d.count == 744)

        d.append(Data(count: 2048 - d.count))
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
