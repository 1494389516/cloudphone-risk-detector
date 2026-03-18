import Foundation
import MachOKit
import AntiDebugInjector
import XCTest

final class AntiDebugInjectorTests: XCTestCase {
    func testPassCreatesMetadataSectionWithValidABI() throws {
        let url = try Self.writeFixture(named: "adbg7_valid_abi")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let result = try AntiDebugInjectorPass().execute(
            on: file,
            config: PassConfig(verbose: true, randomSeed: 0x1234_5678)
        )

        XCTAssertGreaterThan(result.itemsProcessed, 0)
        XCTAssertGreaterThan(result.bytesModified, ArmorABI.AntiDebug.headerSize)

        let textSegment = try XCTUnwrap(try file.segment(named: "__TEXT"))
        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let antiDebugSection = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.AntiDebug.sectionName)
        )
        let payload = try antiDebugSection.readContent(from: file.data)
        let textSectionVMOffset = textSection.address - textSegment.vmAddress

        let header = Self.parseHeader(from: payload)
        XCTAssertEqual(header.magic, ArmorABI.AntiDebug.magic)
        XCTAssertEqual(header.version, ArmorABI.AntiDebug.abiVersion)
        XCTAssertEqual(header.headerSize, UInt32(ArmorABI.AntiDebug.headerSize))
        XCTAssertEqual(header.seed, 0x1234_5678)
        XCTAssertEqual(header.textBaseAddress, textSegment.vmAddress)
        XCTAssertEqual(header.entrySize, UInt32(ArmorABI.AntiDebug.entrySize))
        XCTAssertEqual(Int(header.entryCount), result.itemsProcessed)
        XCTAssertNotEqual(header.probeImmediate, 0)
        XCTAssertEqual(
            payload.count,
            ArmorABI.AntiDebug.headerSize + Int(header.entryCount) * ArmorABI.AntiDebug.entrySize
        )
        XCTAssertNotEqual(header.flags & ArmorABI.AntiDebug.flagHasSymbolTargets, 0)
        XCTAssertNotEqual(header.flags & ArmorABI.AntiDebug.flagSeedFromConfig, 0)

        let entries = Self.parseEntries(from: payload, entryCount: Int(header.entryCount))
        XCTAssertEqual(entries.count, result.itemsProcessed)

        let knownTargets = Set([
            "_debugProbeEntry",
            "_fridaTrapHandler",
            "_riskGuardMain",
            "_tamperSignalProbe",
            "__text+0x0",
            "__text+0x20",
            "__text+0x40",
            "__text+0x60",
        ])

        for (index, entry) in entries.enumerated() {
            XCTAssertTrue(knownTargets.contains(entry.targetName), "unexpected target: \(entry.targetName)")
            XCTAssertEqual(entry.identifierHash, Self.fnv1a64(entry.targetName))
            XCTAssertEqual(entry.scatterSlot, UInt32(index))
            XCTAssertNotEqual(entry.policyBits & ArmorABI.AntiDebug.policyRuntimeGate, 0)
            XCTAssertGreaterThanOrEqual(entry.patchSiteVMOffset, textSectionVMOffset)
            XCTAssertLessThan(entry.patchSiteVMOffset, textSectionVMOffset + textSection.size)
            XCTAssertGreaterThanOrEqual(UInt64(entry.patchSiteFileOffset), UInt64(textSection.offset))
            XCTAssertLessThan(
                UInt64(entry.patchSiteFileOffset),
                UInt64(textSection.offset) + textSection.size
            )
            XCTAssertFalse(entry.targetName.isEmpty)
            XCTAssertNotEqual(
                entry.entryFlags & ArmorABI.AntiDebug.entryFlagInlinePatchReserved,
                0
            )
        }

        XCTAssertNoThrow(try file.validateStructure())
    }

    func testSeedControlsPlanDeterministically() throws {
        let urlA = try Self.writeFixture(named: "adbg7_seed_a")
        let urlB = try Self.writeFixture(named: "adbg7_seed_b")
        let urlC = try Self.writeFixture(named: "adbg7_seed_c")
        defer {
            try? FileManager.default.removeItem(at: urlA)
            try? FileManager.default.removeItem(at: urlB)
            try? FileManager.default.removeItem(at: urlC)
        }

        let fileA = try MachOFile(url: urlA)
        let fileB = try MachOFile(url: urlB)
        let fileC = try MachOFile(url: urlC)

        _ = try AntiDebugInjectorPass().execute(on: fileA, config: PassConfig(randomSeed: 77))
        _ = try AntiDebugInjectorPass().execute(on: fileB, config: PassConfig(randomSeed: 77))
        _ = try AntiDebugInjectorPass().execute(on: fileC, config: PassConfig(randomSeed: 78))

        let sectionA = try XCTUnwrap(
            try fileA.section(segment: "__DATA", section: ArmorABI.AntiDebug.sectionName)
        )
        let sectionB = try XCTUnwrap(
            try fileB.section(segment: "__DATA", section: ArmorABI.AntiDebug.sectionName)
        )
        let sectionC = try XCTUnwrap(
            try fileC.section(segment: "__DATA", section: ArmorABI.AntiDebug.sectionName)
        )

        let payloadA = try sectionA.readContent(from: fileA.data)
        let payloadB = try sectionB.readContent(from: fileB.data)
        let payloadC = try sectionC.readContent(from: fileC.data)

        XCTAssertEqual(payloadA, payloadB, "same seed should generate the same injection plan")
        XCTAssertNotEqual(payloadA, payloadC, "different seeds should scatter/select differently")
    }

    private static func parseHeader(from data: Data) -> AntiDebugHeaderView {
        AntiDebugHeaderView(
            magic: readLE32(data, at: 0),
            version: readLE32(data, at: 4),
            flags: readLE32(data, at: 8),
            headerSize: readLE32(data, at: 12),
            seed: readLE64(data, at: 16),
            textBaseAddress: readLE64(data, at: 24),
            probeImmediate: readLE32(data, at: 32),
            entryCount: readLE32(data, at: 36),
            entrySize: readLE32(data, at: 40)
        )
    }

    private static func parseEntries(from data: Data, entryCount: Int) -> [AntiDebugEntryView] {
        var entries = [AntiDebugEntryView]()
        entries.reserveCapacity(entryCount)

        for index in 0..<entryCount {
            let base = ArmorABI.AntiDebug.headerSize + index * ArmorABI.AntiDebug.entrySize
            entries.append(AntiDebugEntryView(
                identifierHash: readLE64(data, at: base),
                patchSiteVMOffset: readLE64(data, at: base + 8),
                patchSiteFileOffset: readLE32(data, at: base + 16),
                policyBits: readLE32(data, at: base + 20),
                scatterSlot: readLE32(data, at: base + 24),
                entryFlags: readLE32(data, at: base + 28),
                targetName: readFixedCString(
                    data,
                    at: base + 32,
                    length: ArmorABI.AntiDebug.targetNameFieldSize
                )
            ))
        }

        return entries
    }

    private static func fnv1a64(_ string: String) -> UInt64 {
        var hash: UInt64 = 0xCBF29CE484222325
        for byte in string.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x00000100000001B3
        }
        return hash
    }

    private static func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            UInt32(littleEndian: $0.load(as: UInt32.self))
        }
    }

    private static func readLE64(_ data: Data, at offset: Int) -> UInt64 {
        data.subdata(in: offset..<(offset + 8)).withUnsafeBytes {
            UInt64(littleEndian: $0.load(as: UInt64.self))
        }
    }

    private static func readFixedCString(_ data: Data, at offset: Int, length: Int) -> String {
        let bytes = Array(data[offset..<(offset + length)].prefix { $0 != 0 })
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func writeFixture(named name: String) throws -> URL {
        let url = temporaryURL(named: name)
        try makeFixture().write(to: url)
        return url
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
    }

    /// Minimal Mach-O with __TEXT.__text, __DATA.__const, and LC_SYMTAB targets
    /// for deterministic anti-debug plan generation.
    private static func makeFixture() -> Data {
        let symbolNames = [
            "_debugProbeEntry",
            "_fridaTrapHandler",
            "_riskGuardMain",
            "_tamperSignalProbe",
        ]

        var stringTable = Data([0])
        var stringOffsets = [UInt32]()
        for name in symbolNames {
            stringOffsets.append(UInt32(stringTable.count))
            stringTable.append(contentsOf: name.utf8)
            stringTable.append(0)
        }

        let symoff: UInt32 = 8192
        let nsyms = UInt32(symbolNames.count)
        let stroff = symoff + nsyms * UInt32(Nlist64Entry.entrySize)

        var d = Data()

        d.appendLE(UInt32(0xFEEDFACF))
        d.appendLE(UInt32(0x0100000C))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(2))
        d.appendLE(UInt32(3))
        d.appendLE(UInt32(328))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

        // __TEXT segment (72 + 80).
        d.appendLE(UInt32(0x19))
        d.appendLE(UInt32(152))
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(0x1000))
        d.appendLE(UInt64(0x1000))
        d.appendLE(UInt64(0))
        d.appendLE(UInt64(0x1000))
        d.appendLE(UInt32(5))
        d.appendLE(UInt32(5))
        d.appendLE(UInt32(1))
        d.appendLE(UInt32(0))

        d.appendFixedCString("__text", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(0x1800))
        d.appendLE(UInt64(128))
        d.appendLE(UInt32(2048))
        d.appendLE(UInt32(2))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0x80000400))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

        // __DATA segment (72 + 80).
        d.appendLE(UInt32(0x19))
        d.appendLE(UInt32(152))
        d.appendFixedCString("__DATA", length: 16)
        d.appendLE(UInt64(0x3000))
        d.appendLE(UInt64(0x1000))
        d.appendLE(UInt64(0x1000))
        d.appendLE(UInt64(0x1000))
        d.appendLE(UInt32(3))
        d.appendLE(UInt32(3))
        d.appendLE(UInt32(1))
        d.appendLE(UInt32(0))

        d.appendFixedCString("__const", length: 16)
        d.appendFixedCString("__DATA", length: 16)
        d.appendLE(UInt64(0x3000))
        d.appendLE(UInt64(64))
        d.appendLE(UInt32(4096))
        d.appendLE(UInt32(3))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

        // LC_SYMTAB.
        d.appendLE(UInt32(0x02))
        d.appendLE(UInt32(24))
        d.appendLE(symoff)
        d.appendLE(nsyms)
        d.appendLE(stroff)
        d.appendLE(UInt32(stringTable.count))

        precondition(d.count == 360, "unexpected load-command layout")

        d.append(Data(count: 2048 - d.count))
        for _ in 0..<32 {
            d.appendLE(UInt32(0xD503201F))
        }

        d.append(Data(count: 4096 - d.count))
        d.append(Data((0..<64).map { UInt8($0) }))
        d.append(Data(count: 8192 - d.count))

        for (index, strx) in stringOffsets.enumerated() {
            d.appendLE(strx)
            d.append(0x0E)
            d.append(0x01)
            d.appendLE(Int16(0))
            d.appendLE(UInt64(0x1800 + UInt64(index * 0x20)))
        }

        d.append(stringTable)
        return d
    }
}

private struct AntiDebugHeaderView {
    let magic: UInt32
    let version: UInt32
    let flags: UInt32
    let headerSize: UInt32
    let seed: UInt64
    let textBaseAddress: UInt64
    let probeImmediate: UInt32
    let entryCount: UInt32
    let entrySize: UInt32
}

private struct AntiDebugEntryView {
    let identifierHash: UInt64
    let patchSiteVMOffset: UInt64
    let patchSiteFileOffset: UInt32
    let policyBits: UInt32
    let scatterSlot: UInt32
    let entryFlags: UInt32
    let targetName: String
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
        while bytes.count < length { bytes.append(0) }
        append(contentsOf: bytes)
    }
}
