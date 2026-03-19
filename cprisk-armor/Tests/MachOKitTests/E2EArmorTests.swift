import CryptoKit
import Foundation
import MachOKit
import StringEncryptor
import MetadataScrubber
import DataSegmentEncryptor
import IntegrityAnchor
import StructureObfuscator
import AntiDebugInjector
import InstructionSubstitution
import SymbolStripper
import XCTest

final class E2EArmorTests: XCTestCase {
    // MARK: - Full Pipeline

    func testFullPipelineOnSyntheticBinary() throws {
        let inputURL = try Self.writeFixture(named: "e2e_full")
        let outputURL = Self.temporaryURL(named: "e2e_full_out")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let file = try MachOFile(url: inputURL)
        let config = PassConfig(
            verbose: true,
            encryptionKey: Data("test-e2e-key".utf8),
            randomSeed: 42
        )

        let preStrings = try file.findCStrings().map(\.value)
        XCTAssertTrue(preStrings.contains("frida-check"), "fixture should contain sensitive string")
        XCTAssertTrue(preStrings.contains("/usr/lib/test"), "fixture should contain path string")

        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let textBeforePass8 = try textSection.readContent(from: file.data)

        // Pass 8: InstructionSubstitution — must precede Pass 4 so the anchor hashes substituted code
        let r8 = try InstructionSubstitutionPass().execute(on: file, config: config)
        XCTAssertGreaterThan(r8.itemsProcessed, 0)
        XCTAssertGreaterThan(r8.bytesModified, 0)

        let textAfterPass8 = try textSection.readContent(from: file.data)
        XCTAssertNotEqual(textBeforePass8, textAfterPass8, "Pass 8 must modify __TEXT.__text")
        XCTAssertEqual(textBeforePass8.count, textAfterPass8.count, "Pass 8 must preserve __text size")
        XCTAssertNoThrow(try file.validateStructure(), "Pass 8 must preserve Mach-O structure")

        // Pass 4: IntegrityAnchor — must precede Pass 3
        let r4 = try IntegrityAnchorPass().execute(on: file, config: config)
        XCTAssertGreaterThan(r4.itemsProcessed, 0)
        XCTAssertGreaterThan(r4.bytesModified, 0)

        // Pass 1: StringEncryptor
        let r1 = try StringEncryptorPass().execute(on: file, config: config)
        XCTAssertGreaterThan(r1.itemsProcessed, 0)

        // Pass 3: DataSegmentEncryptor
        let r3 = try DataSegmentEncryptorPass().execute(on: file, config: config)
        XCTAssertGreaterThanOrEqual(r3.itemsProcessed, 0)

        // Pass 2: MetadataScrubber
        let r2 = try MetadataScrubberPass().execute(on: file, config: config)
        XCTAssertGreaterThanOrEqual(r2.itemsProcessed, 0)

        // Pass 5: StructureObfuscator
        let r5 = try StructureObfuscatorPass().execute(on: file, config: config)
        XCTAssertGreaterThan(r5.itemsProcessed, 0)

        // Pass 7: AntiDebugInjector
        let r7 = try AntiDebugInjectorPass().execute(on: file, config: config)
        XCTAssertGreaterThan(r7.itemsProcessed, 0)

        // Post-pass: __objc_data2 scrub (must also work independently from Pass 7)
        let r7s = try ObjCData2ScrubberPass().execute(on: file, config: config)
        XCTAssertGreaterThanOrEqual(r7s.itemsProcessed, 0)

        // Pass 6: SymbolStripper
        let r6 = try SymbolStripperPass().execute(on: file, config: config)
        XCTAssertGreaterThanOrEqual(r6.itemsProcessed, 0)

        // Sensitive strings must be gone from __cstring
        let postStrings = try file.findCStrings().map(\.value)
        XCTAssertFalse(postStrings.contains("frida-check"))
        XCTAssertFalse(postStrings.contains("/usr/lib/test"))

        // Anchor sections exist with correct sizes
        let anchorFull = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.Integrity.fullHashSectionName)
        )
        XCTAssertEqual(Int(anchorFull.size), ArmorABI.Integrity.fullHashSectionSize)

        for name in ArmorABI.Integrity.splitSectionNames {
            let lane = try XCTUnwrap(try file.section(segment: "__DATA", section: name))
            XCTAssertEqual(Int(lane.size), ArmorABI.Integrity.splitLaneSize)
        }

        // String table and loader descriptor sections exist
        XCTAssertNotNil(try file.section(segment: "__DATA", section: ArmorABI.StringTable.sectionName))
        XCTAssertNotNil(try file.section(segment: "__DATA", section: ArmorABI.Loader.sectionName))
        let antiDebugSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.AntiDebug.sectionName)
        )
        XCTAssertGreaterThan(Int(antiDebugSection.size), ArmorABI.AntiDebug.headerSize)

        // Validate structure and round-trip write
        let report = try file.validateStructure()
        XCTAssertGreaterThanOrEqual(report.segmentCount, 2)
        XCTAssertGreaterThan(report.sectionCount, 3)

        let writeResult = try file.write(to: outputURL)
        XCTAssertTrue(FileManager.default.fileExists(atPath: outputURL.path))
        XCTAssertGreaterThan(writeResult.report.sectionCount, 3)
    }

    // MARK: - Pass Order Dependency

    func testPass4MustPrecedePass3() throws {
        let inputURL = try Self.writeFixture(named: "e2e_order")
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let file = try MachOFile(url: inputURL)
        let config = PassConfig(encryptionKey: Data("test-order-key".utf8))

        // Pass 3 before Pass 4 → must fail (anchor hash section missing)
        XCTAssertThrowsError(
            try DataSegmentEncryptorPass().execute(on: file, config: config)
        ) { error in
            guard case MachOError.sectionNotFound(_, _) = error else {
                return XCTFail("Expected sectionNotFound, got: \(error)")
            }
        }

        // Correct order: Pass 4 then Pass 3 → succeeds
        _ = try IntegrityAnchorPass().execute(on: file, config: config)
        let r3 = try DataSegmentEncryptorPass().execute(on: file, config: config)
        XCTAssertGreaterThanOrEqual(r3.itemsProcessed, 0)
        _ = try file.validateStructure()
    }

    // MARK: - Idempotent Armoring

    func testIdempotentArmoring() throws {
        let inputURL = try Self.writeFixture(named: "e2e_idem")
        let firstURL = Self.temporaryURL(named: "e2e_idem_r1")
        let secondURL = Self.temporaryURL(named: "e2e_idem_r2")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: firstURL)
            try? FileManager.default.removeItem(at: secondURL)
        }

        let config = PassConfig(
            verbose: true,
            encryptionKey: Data("test-idem-key".utf8),
            randomSeed: 100
        )

        // Round 1
        let file1 = try MachOFile(url: inputURL)
        try runFullPipeline(on: file1, config: config)
        let report1 = try file1.validateStructure()
        try file1.write(to: firstURL)

        // Round 2 on the already-armored binary
        let file2 = try MachOFile(url: firstURL)
        try runFullPipeline(on: file2, config: config)
        let report2 = try file2.validateStructure()
        try file2.write(to: secondURL)

        XCTAssertEqual(report1.segmentCount, report2.segmentCount)
        XCTAssertGreaterThanOrEqual(report2.sectionCount, report1.sectionCount)

        let reloaded = try MachOFile(url: secondURL)
        XCTAssertNoThrow(try reloaded.validateStructure())
    }

    // MARK: - String Encryption Effectiveness

    func testStringEncryptionEffectiveness() throws {
        let inputURL = try Self.writeFixture(named: "e2e_strenc")
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let file = try MachOFile(url: inputURL)
        let config = PassConfig(encryptionKey: Data("test-strenc-key".utf8))

        let sensitiveStrings = ["/usr/lib/frida", "frida-check", "/usr/lib/test"]
        let preCStrings = try file.findCStrings().map(\.value)
        for s in sensitiveStrings where preCStrings.contains(s) {
            // At least some sensitive strings must exist before encryption
        }
        XCTAssertTrue(
            sensitiveStrings.contains(where: { preCStrings.contains($0) }),
            "fixture must contain at least one sensitive string before Pass 1"
        )

        guard let cstringSection = try file.section(segment: "__TEXT", section: "__cstring") else {
            return XCTFail("fixture missing __cstring section")
        }
        let rawBefore = try cstringSection.readContent(from: file.data)

        _ = try StringEncryptorPass().execute(on: file, config: config)

        let rawAfter = try cstringSection.readContent(from: file.data)
        for s in sensitiveStrings {
            let pattern = Data(s.utf8)
            XCTAssertNil(
                rawAfter.range(of: pattern),
                "Sensitive string '\(s)' should be zeroed in __cstring after Pass 1"
            )
        }
        XCTAssertNotEqual(rawBefore, rawAfter, "Pass 1 must modify __cstring content")
    }

    // MARK: - Integrity Anchor Content Changes

    func testIntegrityAnchorChangesWithTextModification() throws {
        let inputURL = try Self.writeFixture(named: "e2e_anchor_diff")
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let file = try MachOFile(url: inputURL)
        let config = PassConfig(encryptionKey: Data("test-anchor-key".utf8))

        _ = try IntegrityAnchorPass().execute(on: file, config: config)

        let fullHashSection1 = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.Integrity.fullHashSectionName)
        )
        let hash1 = try fullHashSection1.readContent(from: file.data)

        guard let textSection = try file.section(segment: "__TEXT", section: "__text") else {
            return XCTFail("fixture missing __text section")
        }
        var modifiedByte = try textSection.readContent(from: file.data)
        modifiedByte[0] ^= 0xFF
        try file.replaceBytes(at: UInt64(textSection.offset), with: modifiedByte)

        _ = try IntegrityAnchorPass().execute(on: file, config: config)

        let fullHashSection2 = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.Integrity.fullHashSectionName)
        )
        let hash2 = try fullHashSection2.readContent(from: file.data)

        XCTAssertNotEqual(hash1, hash2, "Anchor hash must change when __text is modified")
    }

    func testWhiteBoxMetadataPayloadSizeMatchesRuntimeContract() throws {
        let inputURL = try Self.writeFixture(named: "e2e_whitebox_payload")
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let file = try MachOFile(url: inputURL)
        let config = PassConfig(encryptionKey: Data("test-whitebox-key".utf8))

        _ = try IntegrityAnchorPass().execute(on: file, config: config)

        let metadataSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.WhiteBox.Sections.metadata)
        )
        let codeSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.WhiteBox.Sections.code)
        )
        let dataSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.WhiteBox.Sections.data)
        )
        let tagSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.WhiteBox.Sections.tag)
        )

        let metadata = try metadataSection.readContent(from: file.data)
        XCTAssertGreaterThanOrEqual(metadata.count, 16)

        let payloadSize = metadata.readLE32(at: 12)
        XCTAssertEqual(payloadSize, UInt32(codeSection.size + dataSection.size),
                       "payloadSize must cover only white-box code+data so CRiskCore validation passes")
        XCTAssertNotEqual(payloadSize, UInt32(codeSection.size + dataSection.size + tagSection.size),
                          "payloadSize must exclude the detached white-box tag section")
    }

    func testWhiteBoxMetadataConfigDigestMatchesRuntimeContract() throws {
        let inputURL = try Self.writeFixture(named: "e2e_whitebox_config_digest")
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let file = try MachOFile(url: inputURL)
        let config = PassConfig(encryptionKey: Data("test-whitebox-config".utf8))

        _ = try IntegrityAnchorPass().execute(on: file, config: config)

        let metadataSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.WhiteBox.Sections.metadata)
        )
        let codeSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.WhiteBox.Sections.code)
        )
        let dataSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.WhiteBox.Sections.data)
        )
        let tagSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.WhiteBox.Sections.tag)
        )

        let metadata = try metadataSection.readContent(from: file.data)
        let code = try codeSection.readContent(from: file.data)
        let data = try dataSection.readContent(from: file.data)
        let tag = try tagSection.readContent(from: file.data)

        XCTAssertGreaterThanOrEqual(metadata.count, 48)

        var expectedDigest = Data()
        expectedDigest.append(code)
        expectedDigest.append(data)
        expectedDigest.append(tag)

        XCTAssertEqual(
            metadata.subdata(in: 16..<48),
            Data(SHA256.hash(data: expectedDigest)),
            "configDigest must bind white-box code, data, and detached tag so the runtime can reject tampered metadata"
        )
    }

    // MARK: - Structure Obfuscator Decoy Sections

    func testStructureObfuscatorAddsFakeSections() throws {
        let inputURL = try Self.writeFixture(named: "e2e_struct_obf")
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let file = try MachOFile(url: inputURL)
        let config = PassConfig(encryptionKey: Data("test-obf-key".utf8), randomSeed: 77)

        let reportBefore = try file.validateStructure()
        let sectionCountBefore = reportBefore.sectionCount

        _ = try StructureObfuscatorPass().execute(on: file, config: config)

        let reportAfter = try file.validateStructure()
        let sectionCountAfter = reportAfter.sectionCount
        let added = sectionCountAfter - sectionCountBefore

        XCTAssertGreaterThanOrEqual(added, 5, "Pass 5 should inject at least 5 decoy sections")
        XCTAssertLessThanOrEqual(added, 8, "Pass 5 should inject at most 8 decoy sections")
    }

    // MARK: - Helpers

    private func runFullPipeline(on file: MachOFile, config: PassConfig) throws {
        _ = try InstructionSubstitutionPass().execute(on: file, config: config)
        _ = try IntegrityAnchorPass().execute(on: file, config: config)
        _ = try StringEncryptorPass().execute(on: file, config: config)
        _ = try DataSegmentEncryptorPass().execute(on: file, config: config)
        _ = try MetadataScrubberPass().execute(on: file, config: config)
        _ = try StructureObfuscatorPass().execute(on: file, config: config)
        _ = try AntiDebugInjectorPass().execute(on: file, config: config)
        _ = try ObjCData2ScrubberPass().execute(on: file, config: config)
        _ = try SymbolStripperPass().execute(on: file, config: config)
    }

    // MARK: - Fixture Builder

    private static func writeFixture(named name: String) throws -> URL {
        let url = temporaryURL(named: name)
        try makeE2EFixture().write(to: url)
        return url
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
    }

    /// Minimal arm64 Mach-O with __TEXT(__text, __cstring) + __DATA(__const).
    ///
    /// Layout:
    /// ```
    /// [0,     32)     mach_header_64
    /// [32,    416)    load commands (384 B, 2 cmds)
    /// [416,   2048)   padding (1632 B for future section headers)
    /// [2048,  2112)   __text  (64 B ARM64 substitution candidates)
    /// [2112,  2160)   __cstring (48 B)
    /// [2160,  8192)   __TEXT zero-fill
    /// [8192,  8256)   __const (64 B)
    /// [8256,  12288)  __DATA zero-fill
    /// ```
    private static func makeE2EFixture() -> Data {
        var d = Data()

        // ── mach_header_64 (32 bytes) ──
        d.appendLE(UInt32(0xFEEDFACF))
        d.appendLE(UInt32(0x0100000C))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(6))
        d.appendLE(UInt32(2))
        d.appendLE(UInt32(384))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

        // ── __TEXT segment_command_64 (72 + 2×80 = 232 bytes) ──
        d.appendLE(UInt32(0x19))
        d.appendLE(UInt32(232))
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(0x1000))
        d.appendLE(UInt64(0x2000))
        d.appendLE(UInt64(0))
        d.appendLE(UInt64(0x2000))
        d.appendLE(UInt32(5))
        d.appendLE(UInt32(5))
        d.appendLE(UInt32(2))
        d.appendLE(UInt32(0))

        // section: __text
        d.appendFixedCString("__text", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(0x1800))
        d.appendLE(UInt64(64))
        d.appendLE(UInt32(2048))
        d.appendLE(UInt32(2))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0x80000400))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

        // section: __cstring
        d.appendFixedCString("__cstring", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(0x1840))
        d.appendLE(UInt64(48))
        d.appendLE(UInt32(2112))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0x02))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

        // ── __DATA segment_command_64 (72 + 80 = 152 bytes) ──
        d.appendLE(UInt32(0x19))
        d.appendLE(UInt32(152))
        d.appendFixedCString("__DATA", length: 16)
        d.appendLE(UInt64(0x3000))
        d.appendLE(UInt64(0x1000))
        d.appendLE(UInt64(0x2000))
        d.appendLE(UInt64(0x1000))
        d.appendLE(UInt32(3))
        d.appendLE(UInt32(3))
        d.appendLE(UInt32(1))
        d.appendLE(UInt32(0))

        // section: __const
        d.appendFixedCString("__const", length: 16)
        d.appendFixedCString("__DATA", length: 16)
        d.appendLE(UInt64(0x3000))
        d.appendLE(UInt64(64))
        d.appendLE(UInt32(0x2000))
        d.appendLE(UInt32(3))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

        precondition(d.count == 416, "header(32) + cmds(384) should be 416 bytes")

        // padding to first content offset
        d.append(Data(count: 2048 - d.count))

        // __text: mixed ARM64 instructions that Pass 8 can legally substitute
        let textInstructions = makeTextInstructions()
        precondition(textInstructions.count == 16, "__text fixture must stay 64 bytes")
        for raw in textInstructions { d.appendLE(raw) }

        // __cstring: sensitive strings for StringEncryptor to detect
        for s in ["Hello", "frida-check", "World", "/usr/lib/test"] {
            d.append(contentsOf: s.utf8)
            d.append(0)
        }
        if d.count < 2160 { d.append(Data(count: 2160 - d.count)) }

        // __TEXT zero-fill to __DATA fileoff
        if d.count < 8192 { d.append(Data(count: 8192 - d.count)) }

        // __const: 64 bytes (0x00..0x3F)
        d.append(Data((0..<64).map { UInt8($0) }))

        // __DATA zero-fill
        if d.count < 12288 { d.append(Data(count: 12288 - d.count)) }

        return d
    }

    private static func makeTextInstructions() -> [UInt32] {
        [
            0xD503201F, // NOP
            0xAA0A03E9, // MOV X9, X10  (ORR alias)
            0x9100018B, // ADD X11, X12, #0
            0xD10001CD, // SUB X13, X14, #0
            0x8A10020F, // AND X15, X16, X16
            0xAA120251, // ORR X17, X18, X18
            0xD2801FF3, // MOVZ X19, #0x00FF
            0xD503201F, // NOP
            0xAA1403F4, // MOV X20, X20 (ORR alias self-copy)
            0x910002B5, // ADD X21, X21, #0
            0xD10002D6, // SUB X22, X22, #0
            0x8A1702F7, // AND X23, X23, X23
            0xAA180318, // ORR X24, X24, X24
            0xD28007F9, // MOVZ X25, #0x003F
            0xAA1A03FA, // MOV X26, X26 (ORR alias self-copy)
            0xD503201F, // NOP
        ]
    }
}

// MARK: - Data Helpers

private extension Data {
    func readLE32(at offset: Int) -> UInt32 {
        subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            UInt32(littleEndian: $0.load(as: UInt32.self))
        }
    }

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
