import Foundation
import MachOKit
import InstructionSubstitution
import XCTest

final class InstructionSubstitutionTests: XCTestCase {
    func testARM64CodecRoundTripsKnownInstructions() {
        for raw in Self.replaceableInstructions {
            let decoded = ARM64Decoder.decode(raw)
            let reencoded = ARM64Encoder.encode(decoded)
            XCTAssertEqual(reencoded, raw, String(format: "round-trip mismatch for 0x%08X", raw))
        }
    }

    func testBitmaskImmediateSubstitutionAcceptsCommonMOVZValues() throws {
        let engine = SubstitutionEngine()
        let cases: [(UInt32, UInt64)] = [
            (Self.movz(rd: 9, imm16: 0x0001), 1),
            (Self.movz(rd: 10, imm16: 0x0003), 2),
            (Self.movz(rd: 11, imm16: 0x000F), 3),
            (Self.movz(rd: 12, imm16: 0x00FF), 4),
        ]

        for (raw, seed) in cases {
            var rng = SplitMix64(seed: seed)
            let replacement = try XCTUnwrap(
                engine.substitute(for: raw, ratio: 1.0, using: &rng),
                String(format: "expected MOVZ substitution for 0x%08X", raw)
            )
            XCTAssertNotEqual(replacement, raw)
        }
    }

    func testSubstitutionEngineProducesEquivalentAlternatives() throws {
        let engine = SubstitutionEngine()
        let cases: [(name: String, raw: UInt32, allowed: Set<UInt32>)] = [
            (
                "canonical MOV alias",
                Self.movAlias(rd: 5, rm: 6),
                [
                    Self.addZero(rd: 5, rn: 6),
                    Self.subZero(rd: 5, rn: 6),
                    Self.andSelf(rd: 5, rn: 6),
                    Self.orrSelf(rd: 5, rn: 6),
                ]
            ),
            (
                "ADD #0",
                Self.addZero(rd: 7, rn: 8),
                [
                    Self.movAlias(rd: 7, rm: 8),
                    Self.subZero(rd: 7, rn: 8),
                    Self.andSelf(rd: 7, rn: 8),
                    Self.orrSelf(rd: 7, rn: 8),
                ]
            ),
            (
                "NOP",
                Self.nop,
                [
                    Self.orrZero,
                    Self.addZeroToXzr,
                    Self.subZeroToXzr,
                    Self.andZero,
                ]
            ),
        ]

        for testCase in cases {
            var rng = SplitMix64(seed: 0x1234_5678)
            let replacement = try XCTUnwrap(
                engine.substitute(for: testCase.raw, ratio: 1.0, using: &rng),
                testCase.name
            )
            XCTAssertTrue(
                testCase.allowed.contains(replacement),
                "\(testCase.name) produced unexpected replacement \(String(format: "0x%08X", replacement))"
            )
            XCTAssertNotEqual(replacement, testCase.raw)
        }
    }

    func testSubstitutionEngineIsDeterministicForSameSeed() {
        let input = Self.replaceableInstructions

        let outputA = Self.substituteSequence(input, seed: 0xCAFE_F00D)
        let outputB = Self.substituteSequence(input, seed: 0xCAFE_F00D)
        let outputC = Self.substituteSequence(input, seed: 0xCAFE_F00E)

        XCTAssertEqual(outputA, outputB, "same seed must produce the same substitutions")
        XCTAssertNotEqual(outputA, outputC, "different seed should alter at least one substitution choice")
    }

    func testPassMutatesTextButPreservesMachOStructure() throws {
        let inputURL = try Self.writeFixture(
            named: "subst_pass_integration",
            textInstructions: Self.replaceableInstructions
        )
        let outputURL = Self.temporaryURL(named: "subst_pass_integration_out")
        defer {
            try? FileManager.default.removeItem(at: inputURL)
            try? FileManager.default.removeItem(at: outputURL)
        }

        let file = try MachOFile(url: inputURL)
        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let textBefore = try textSection.readContent(from: file.data)

        let result = try InstructionSubstitutionPass().execute(
            on: file,
            config: PassConfig(verbose: true, randomSeed: 0x0BAD_C0DE)
        )

        let textAfter = try textSection.readContent(from: file.data)

        XCTAssertGreaterThan(result.itemsProcessed, 0)
        XCTAssertGreaterThan(result.bytesModified, 0)
        XCTAssertNotEqual(textBefore, textAfter, "Pass 8 must mutate __TEXT.__text")
        XCTAssertEqual(textBefore.count, textAfter.count, "Pass 8 must preserve section length")
        XCTAssertNoThrow(try file.validateStructure())

        let writeResult = try file.write(to: outputURL)
        XCTAssertEqual(writeResult.report.segmentCount, 2)
        XCTAssertTrue(FileManager.default.fileExists(atPath: outputURL.path))
    }

    func testPassLeavesBranchAndSystemInstructionsUntouched() throws {
        let inputURL = try Self.writeFixture(
            named: "subst_pass_safety",
            textInstructions: Self.mixedInstructions
        )
        defer { try? FileManager.default.removeItem(at: inputURL) }

        let file = try MachOFile(url: inputURL)
        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let beforeWords = try Self.readWords(from: textSection.readContent(from: file.data))

        let result = try InstructionSubstitutionPass().execute(
            on: file,
            config: PassConfig(randomSeed: 0x1234_5678)
        )

        let afterWords = try Self.readWords(from: textSection.readContent(from: file.data))
        XCTAssertGreaterThan(result.itemsProcessed, 0, "fixture should still contain replaceable instructions")

        for index in Self.nonReplaceableInstructionIndices {
            XCTAssertEqual(
                afterWords[index],
                beforeWords[index],
                "branch/system instruction at index \(index) must not be rewritten"
            )
        }
    }

    private static func substituteSequence(_ input: [UInt32], seed: UInt64) -> [UInt32?] {
        let engine = SubstitutionEngine()
        var rng = SplitMix64(seed: seed)
        return input.map { engine.substitute(for: $0, ratio: 1.0, using: &rng) }
    }

    private static func writeFixture(named name: String, textInstructions: [UInt32]) throws -> URL {
        let url = temporaryURL(named: name)
        try makeFixture(textInstructions: textInstructions).write(to: url)
        return url
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
    }

    private static func makeFixture(textInstructions: [UInt32]) -> Data {
        precondition(textInstructions.count == 16, "fixture expects exactly 16 instructions (64 bytes)")

        var d = Data()

        d.appendLE(UInt32(0xFEEDFACF))
        d.appendLE(UInt32(0x0100000C))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(6))
        d.appendLE(UInt32(2))
        d.appendLE(UInt32(384))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

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

        d.append(Data(count: 2048 - d.count))
        for raw in textInstructions { d.appendLE(raw) }

        for s in ["Hello", "frida-check", "World", "/usr/lib/test"] {
            d.append(contentsOf: s.utf8)
            d.append(0)
        }
        if d.count < 2160 { d.append(Data(count: 2160 - d.count)) }
        if d.count < 8192 { d.append(Data(count: 8192 - d.count)) }

        d.append(Data((0..<64).map { UInt8($0) }))
        if d.count < 12288 { d.append(Data(count: 12288 - d.count)) }

        return d
    }

    private static func readWords(from data: Data) throws -> [UInt32] {
        stride(from: 0, to: data.count, by: 4).map { offset in
            data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
                UInt32(littleEndian: $0.load(as: UInt32.self))
            }
        }
    }

    private static let nop: UInt32 = 0xD503201F
    private static let orrZero: UInt32 = 0xAA1F03FF
    private static let addZeroToXzr: UInt32 = 0x910003FF
    private static let subZeroToXzr: UInt32 = 0xD10003FF
    private static let andZero: UInt32 = 0x8A1F03FF

    private static func movAlias(rd: UInt32, rm: UInt32) -> UInt32 {
        0xAA0003E0 | (rm << 16) | rd
    }

    private static func addZero(rd: UInt32, rn: UInt32) -> UInt32 {
        0x91000000 | (rn << 5) | rd
    }

    private static func subZero(rd: UInt32, rn: UInt32) -> UInt32 {
        0xD1000000 | (rn << 5) | rd
    }

    private static func andSelf(rd: UInt32, rn: UInt32) -> UInt32 {
        0x8A000000 | (rn << 16) | (rn << 5) | rd
    }

    private static func orrSelf(rd: UInt32, rn: UInt32) -> UInt32 {
        0xAA000000 | (rn << 16) | (rn << 5) | rd
    }

    private static func movz(rd: UInt32, imm16: UInt32) -> UInt32 {
        0xD2800000 | (imm16 << 5) | rd
    }

    private static let replaceableInstructions: [UInt32] = [
        nop,
        movAlias(rd: 5, rm: 6),
        addZero(rd: 7, rn: 8),
        subZero(rd: 9, rn: 10),
        andSelf(rd: 11, rn: 12),
        orrSelf(rd: 13, rn: 14),
        movz(rd: 15, imm16: 0x00FF),
        nop,
        movAlias(rd: 16, rm: 17),
        addZero(rd: 18, rn: 19),
        subZero(rd: 20, rn: 21),
        andSelf(rd: 22, rn: 23),
        orrSelf(rd: 24, rn: 25),
        movz(rd: 26, imm16: 0x003F),
        movAlias(rd: 27, rm: 28),
        nop,
    ]

    private static let mixedInstructions: [UInt32] = [
        nop,
        movAlias(rd: 5, rm: 6),
        addZero(rd: 7, rn: 8),
        subZero(rd: 9, rn: 10),
        andSelf(rd: 11, rn: 12),
        orrSelf(rd: 13, rn: 14),
        movz(rd: 15, imm16: 0x00FF),
        0x14000000, // B #0
        0x94000000, // BL #0
        0xD65F03C0, // RET
        0xD4000001, // SVC #0
        0xD4200000, // BRK #0
        0xD5033FDF, // ISB
        movAlias(rd: 16, rm: 17),
        addZero(rd: 18, rn: 19),
        movz(rd: 20, imm16: 0x003F),
    ]

    private static let nonReplaceableInstructionIndices = [7, 8, 9, 10, 11, 12]
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
        while bytes.count < length { bytes.append(0) }
        append(contentsOf: bytes)
    }
}
