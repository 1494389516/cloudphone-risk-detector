import Foundation
import MachOKit
import XCTest

final class VMSelfExpectInjectorIntegrationTests: XCTestCase {
    func testInjectorWritesMdvskPayloadForVMExecuteSymbol() throws {
        let fixture = Self.makeFixture(textSize: 160, symbolName: "_cprisk_vm_execute")
        let url = Self.temporaryURL(named: "vm_self_expect_ok")
        defer { try? FileManager.default.removeItem(at: url) }
        try fixture.data.write(to: url)

        let before = try Data(contentsOf: url)
        let symbolFileOffset = try XCTUnwrap(fixture.symbolFileOffset)
        let rangeEnd = symbolFileOffset + VMSelfExpectInjector.selfByteCount
        let expectedHash = VMSelfExpectInjector.fnv1a32(bytes: before.subdata(in: symbolFileOffset..<rangeEnd))

        let result = try VMSelfExpectInjector.inject(into: url)
        XCTAssertEqual(result.fnvExpect, expectedHash)
        XCTAssertEqual(result.resolvedSymbolName, "_cprisk_vm_execute")

        let file = try MachOFile(url: url)
        let section = try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.Sections.vmpSelfExpect))
        let payload = try section.readContent(from: file.data)
        XCTAssertEqual(payload.count, 8, "mdvsk payload must be 8 bytes (magic + fnv)")
        XCTAssertEqual(Self.readLE32(payload, at: 0), VMSelfExpectInjector.magicLE)
        XCTAssertEqual(Self.readLE32(payload, at: 4), expectedHash)
    }

    func testInjectorStrictlyFailsWhenVMExecuteSymbolMissing() throws {
        let fixture = Self.makeFixture(textSize: 160, symbolName: "_other_symbol")
        let url = Self.temporaryURL(named: "vm_self_expect_missing_symbol")
        defer { try? FileManager.default.removeItem(at: url) }
        try fixture.data.write(to: url)

        XCTAssertThrowsError(try VMSelfExpectInjector.inject(into: url)) { error in
            guard case MachOError.invalidData(let message) = error else {
                return XCTFail("Expected invalidData, got: \(error)")
            }
            XCTAssertTrue(
                message.contains("symbol _cprisk_vm_execute not found"),
                "strict behavior should reject missing vm execute symbol"
            )
        }
    }

    func testInjectorStrictlyFailsWhenTextWindowIsTooShort() throws {
        let fixture = Self.makeFixture(textSize: 64, symbolName: "_cprisk_vm_execute")
        let url = Self.temporaryURL(named: "vm_self_expect_short_window")
        defer { try? FileManager.default.removeItem(at: url) }
        try fixture.data.write(to: url)

        XCTAssertThrowsError(try VMSelfExpectInjector.inject(into: url)) { error in
            guard case MachOError.invalidData(let message) = error else {
                return XCTFail("Expected invalidData, got: \(error)")
            }
            XCTAssertTrue(
                message.contains("must be at least \(VMSelfExpectInjector.selfByteCount) bytes"),
                "strict behavior should reject insufficient hash window"
            )
        }
    }

    private struct Fixture {
        let data: Data
        let symbolFileOffset: Int?
    }

    private static func makeFixture(textSize: Int, symbolName: String?) -> Fixture {
        let textOffset: UInt32 = 0x800
        let textVMAddr: UInt64 = 0x1800
        let dataOffset: UInt32 = 0x1000
        let symoff: UInt32 = 0x1800
        let symbolOffsetInText: UInt64 = 0x10
        let mdvskSize: UInt64 = 8

        var strtab = Data([0])
        var nlist = Data()
        var symbolFileOffset: Int?

        if let symbolName {
            let strx = UInt32(strtab.count)
            strtab.append(contentsOf: symbolName.utf8)
            strtab.append(0)

            nlist.appendLE(strx)
            nlist.append(0x0E) // N_SECT
            nlist.append(0x01) // __TEXT.__text (first section)
            nlist.appendLE(Int16(0))
            nlist.appendLE(textVMAddr + symbolOffsetInText)
            symbolFileOffset = Int(textOffset + UInt32(symbolOffsetInText))
        }

        let nsyms = UInt32(nlist.count / 16)
        let stroff = symoff + UInt32(nlist.count)
        let sizeOfCmds: UInt32 = 152 + 152 + 24

        var data = Data()
        data.appendLE(UInt32(0xFEEDFACF)) // MH_MAGIC_64
        data.appendLE(UInt32(0x0100000C)) // CPU_TYPE_ARM64
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x00000002)) // MH_EXECUTE
        data.appendLE(UInt32(3))          // __TEXT + __DATA + LC_SYMTAB
        data.appendLE(sizeOfCmds)
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // LC_SEGMENT_64 __TEXT
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(152))
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(0x3000))
        data.appendLE(UInt64(0))
        data.appendLE(UInt64(dataOffset))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(0))

        data.appendFixedCString("__text", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(textVMAddr)
        data.appendLE(UInt64(textSize))
        data.appendLE(textOffset)
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x80000400))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // LC_SEGMENT_64 __DATA
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(152))
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x3000))
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(dataOffset))
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(0))

        data.appendFixedCString(ArmorABI.Sections.vmpSelfExpect, length: 16)
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x3000))
        data.appendLE(mdvskSize)
        data.appendLE(dataOffset)
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // LC_SYMTAB
        data.appendLE(UInt32(0x02))
        data.appendLE(UInt32(24))
        data.appendLE(symoff)
        data.appendLE(nsyms)
        data.appendLE(stroff)
        data.appendLE(UInt32(strtab.count))

        if data.count < Int(textOffset) {
            data.append(Data(count: Int(textOffset) - data.count))
        }
        for i in 0..<textSize {
            data.append(UInt8((0x41 + i) & 0xFF))
        }

        if data.count < Int(dataOffset) {
            data.append(Data(count: Int(dataOffset) - data.count))
        }
        data.append(Data(repeating: 0, count: Int(mdvskSize)))

        if data.count < Int(symoff) {
            data.append(Data(count: Int(symoff) - data.count))
        }
        data.append(nlist)
        data.append(strtab)

        return Fixture(data: data, symbolFileOffset: symbolFileOffset)
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
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

    mutating func appendLE(_ value: Int16) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 2))
    }

    mutating func appendFixedCString(_ string: String, length: Int) {
        var bytes = Array(string.utf8.prefix(length))
        while bytes.count < length {
            bytes.append(0)
        }
        append(contentsOf: bytes)
    }
}
