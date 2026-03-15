import XCTest
import MachOKit
import StructureObfuscator

final class StructureObfuscatorTests: XCTestCase {

    // MARK: - Fixture Builder

    /// Build a two-segment ARM64 Mach-O with generous header padding and
    /// a __DATA segment with ample gap space for decoy section injection.
    ///
    /// Layout (8192 bytes total):
    ///   [0..32)       mach_header_64
    ///   [32..184)     LC_SEGMENT_64 __TEXT + 1 section (__cstring)
    ///   [184..336)    LC_SEGMENT_64 __DATA + 1 section (__const)
    ///   [336..2048)   padding (1712 bytes → room for 21 extra section headers)
    ///   [2048..2060)  __TEXT.__cstring content ("Hello\0World\0")
    ///   [2060..4096)  zero padding
    ///   [4096..4104)  __DATA.__const content
    ///   [4104..8192)  gap in __DATA for placing decoy content
    private static func makeObfuscationFixture() -> Data {
        var d = Data()

        d.appendLE(UInt32(0xFEEDFACF))
        d.appendLE(UInt32(0x0100000C))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0x00000006))
        d.appendLE(UInt32(2))
        d.appendLE(UInt32(304))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        assert(d.count == 32)

        // __TEXT segment (72 + 80 = 152 bytes)
        d.appendLE(UInt32(0x19))
        d.appendLE(UInt32(152))
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(0))
        d.appendLE(UInt64(4096))
        d.appendLE(UInt64(0))
        d.appendLE(UInt64(4096))
        d.appendLE(UInt32(5))
        d.appendLE(UInt32(5))
        d.appendLE(UInt32(1))
        d.appendLE(UInt32(0))

        // __TEXT.__cstring
        d.appendFixedCString("__cstring", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(2048))
        d.appendLE(UInt64(12))
        d.appendLE(UInt32(2048))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0x02))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        assert(d.count == 184)

        // __DATA segment (72 + 80 = 152 bytes)
        d.appendLE(UInt32(0x19))
        d.appendLE(UInt32(152))
        d.appendFixedCString("__DATA", length: 16)
        d.appendLE(UInt64(4096))
        d.appendLE(UInt64(4096))
        d.appendLE(UInt64(4096))
        d.appendLE(UInt64(4096))
        d.appendLE(UInt32(3))
        d.appendLE(UInt32(3))
        d.appendLE(UInt32(1))
        d.appendLE(UInt32(0))

        // __DATA.__const
        d.appendFixedCString("__const", length: 16)
        d.appendFixedCString("__DATA", length: 16)
        d.appendLE(UInt64(4096))
        d.appendLE(UInt64(8))
        d.appendLE(UInt32(4096))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        assert(d.count == 336)

        // Padding to __cstring content
        d.append(Data(count: 2048 - d.count))
        d.append(contentsOf: "Hello".utf8)
        d.append(0)
        d.append(contentsOf: "World".utf8)
        d.append(0)

        // Padding to __DATA file region
        d.append(Data(count: 4096 - d.count))
        d.append(Data([0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD]))

        // Fill rest of __DATA to 8192
        d.append(Data(count: 8192 - d.count))
        return d
    }

    private static func writeFixture(named name: String) throws -> URL {
        let url = temporaryURL(named: name)
        try makeObfuscationFixture().write(to: url)
        return url
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
    }

    // MARK: - A. Decoy Section Injection

    func testDecoySectionInjectionAddsSections() throws {
        let url = try Self.writeFixture(named: "decoy_inject")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let dataSeg = try XCTUnwrap(try file.segment(named: "__DATA"))
        let originalSectionCount = dataSeg.sections.count

        let config = PassConfig(verbose: true, randomSeed: 42)
        let result = try StructureObfuscatorPass().execute(on: file, config: config)

        XCTAssertGreaterThanOrEqual(result.itemsProcessed, 5)
        XCTAssertLessThanOrEqual(result.itemsProcessed, 8)
        XCTAssertGreaterThan(result.bytesModified, 0)

        let updatedDataSeg = try XCTUnwrap(try file.segment(named: "__DATA"))
        XCTAssertEqual(
            updatedDataSeg.sections.count,
            originalSectionCount + result.itemsProcessed
        )
    }

    func testDecoySectionContentIsStructured() throws {
        let url = try Self.writeFixture(named: "decoy_content")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let config = PassConfig(randomSeed: 42)
        let result = try StructureObfuscatorPass().execute(on: file, config: config)

        let dataSeg = try XCTUnwrap(try file.segment(named: "__DATA"))
        let decoySections = dataSeg.sections.filter { $0.sectionName != "__const" }

        XCTAssertEqual(decoySections.count, result.itemsProcessed)

        for section in decoySections {
            let content = try section.readContent(from: file.data)
            XCTAssertGreaterThanOrEqual(content.count, 64)
            XCTAssertLessThanOrEqual(content.count, 512)
            XCTAssertEqual(content.count % 8, 0, "Content should be 8-byte aligned")
            XCTAssertGreaterThanOrEqual(content.count, 12, "Must have at least a 12-byte header")
        }
    }

    // MARK: - B. Validation After Injection

    func testStructureRemainsValidAfterInjection() throws {
        let url = try Self.writeFixture(named: "valid_after")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let config = PassConfig(randomSeed: 99)
        _ = try StructureObfuscatorPass().execute(on: file, config: config)

        let report = try file.validateStructure()
        XCTAssertGreaterThan(report.sectionCount, 2)
        XCTAssertEqual(report.segmentCount, 2)
    }

    func testWriteRoundTripAfterInjection() throws {
        let inputURL = try Self.writeFixture(named: "roundtrip_in")
        let outputURL = Self.temporaryURL(named: "roundtrip_out")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let file = try MachOFile(url: inputURL)
        let config = PassConfig(randomSeed: 123)
        _ = try StructureObfuscatorPass().execute(on: file, config: config)

        let validation = try file.write(to: outputURL)
        XCTAssertEqual(validation.report.segmentCount, 2)

        let reloaded = try MachOFile(url: outputURL)
        let report = try reloaded.validateStructure()
        XCTAssertGreaterThan(report.sectionCount, 2)
    }

    // MARK: - C. Randomisation

    func testDifferentSeedsProduceDifferentLayouts() throws {
        let url1 = try Self.writeFixture(named: "seed_a")
        let url2 = try Self.writeFixture(named: "seed_b")
        defer {
            try? FileManager.default.removeItem(at: url1)
            try? FileManager.default.removeItem(at: url2)
        }

        let file1 = try MachOFile(url: url1)
        let file2 = try MachOFile(url: url2)

        let result1 = try StructureObfuscatorPass().execute(
            on: file1, config: PassConfig(randomSeed: 1)
        )
        let result2 = try StructureObfuscatorPass().execute(
            on: file2, config: PassConfig(randomSeed: 2)
        )

        let names1 = try XCTUnwrap(try file1.segment(named: "__DATA")).sections
            .map(\.sectionName).sorted()
        let names2 = try XCTUnwrap(try file2.segment(named: "__DATA")).sections
            .map(\.sectionName).sorted()

        let sameSectionSet = (names1 == names2)
        let sameBytesModified = (result1.bytesModified == result2.bytesModified)
        XCTAssertFalse(
            sameSectionSet && sameBytesModified,
            "Two different seeds should produce different layouts or sizes"
        )
    }

    func testSameSeedProducesIdenticalOutput() throws {
        let url1 = try Self.writeFixture(named: "determ_a")
        let url2 = try Self.writeFixture(named: "determ_b")
        defer {
            try? FileManager.default.removeItem(at: url1)
            try? FileManager.default.removeItem(at: url2)
        }

        let file1 = try MachOFile(url: url1)
        let file2 = try MachOFile(url: url2)
        let seed: UInt64 = 0xDEADBEEF

        let r1 = try StructureObfuscatorPass().execute(
            on: file1, config: PassConfig(randomSeed: seed)
        )
        let r2 = try StructureObfuscatorPass().execute(
            on: file2, config: PassConfig(randomSeed: seed)
        )

        XCTAssertEqual(r1.itemsProcessed, r2.itemsProcessed)
        XCTAssertEqual(r1.bytesModified, r2.bytesModified)
    }

    // MARK: - D. Reserved Section Safety

    func testReservedSectionsAreNotInjected() throws {
        let url = try Self.writeFixture(named: "reserved_safe")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        _ = try StructureObfuscatorPass().execute(
            on: file, config: PassConfig(randomSeed: 77)
        )

        let reserved: Set<String> = [
            ArmorABI.Sections.stringTable,
            ArmorABI.Sections.loader,
            ArmorABI.Sections.protectedBlob,
            ArmorABI.Sections.anchorA,
            ArmorABI.Sections.anchorB,
            ArmorABI.Sections.anchorC,
            ArmorABI.Sections.anchorD,
            ArmorABI.Sections.fullAnchorHash,
        ]

        let dataSeg = try XCTUnwrap(try file.segment(named: "__DATA"))
        let injectedNames = Set(dataSeg.sections.map(\.sectionName))
        XCTAssertTrue(injectedNames.isDisjoint(with: reserved))
    }

    func testPreExistingArmorSectionsUntouched() throws {
        let url = try Self.writeFixture(named: "armor_intact")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)

        let markerContent = Data(repeating: 0x42, count: 64)
        try file.addOrUpdateSection(
            segment: "__DATA",
            section: ArmorABI.Sections.stringTable,
            content: markerContent,
            align: 3,
            flags: 0
        )

        let beforeSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.Sections.stringTable)
        )
        let beforeContent = try beforeSection.readContent(from: file.data)

        _ = try StructureObfuscatorPass().execute(
            on: file, config: PassConfig(randomSeed: 55)
        )

        let afterSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.Sections.stringTable)
        )
        let afterContent = try afterSection.readContent(from: file.data)
        XCTAssertEqual(beforeContent, afterContent)
    }

    // MARK: - E. PassResult Reporting

    func testPassResultReportsInjectionDetails() throws {
        let url = try Self.writeFixture(named: "report_check")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let result = try StructureObfuscatorPass().execute(
            on: file, config: PassConfig(randomSeed: 7)
        )

        XCTAssertEqual(result.passName, "StructureObfuscator")
        XCTAssertGreaterThanOrEqual(result.itemsProcessed, 5)
        XCTAssertGreaterThan(result.bytesModified, 0)
        XCTAssertTrue(result.details.contains(where: { $0.contains("Random seed: 7") }))
        XCTAssertTrue(result.details.contains(where: { $0.hasPrefix("Injected __DATA.") }))
    }
}

// MARK: - Data Helpers

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
        while bytes.count < length { bytes.append(0) }
        append(contentsOf: bytes)
    }
}
