import Foundation
import MachOKit
import XCTest

final class VMSelfExpectInjectorIntegrationTests: XCTestCase {
    func testInjectorWritesMdvskPayloadFromSpanMapEvenWhenSymbolsAreUnhelpful() throws {
        let fixture = Self.makeFixture(
            textSize: 0x600,
            symbolMode: .wrongOnly,
            includeSpanMap: true
        )
        let url = Self.temporaryURL(named: "vm_self_expect_ok")
        defer { try? FileManager.default.removeItem(at: url) }
        try fixture.data.write(to: url)

        let before = try Data(contentsOf: url)
        let expectedHash = Self.expectedFnvFromFixture(before: before, layout: fixture.layout)

        let result = try VMSelfExpectInjector.inject(into: url)
        XCTAssertEqual(result.fnvExpect, expectedHash)
        XCTAssertEqual(result.expectMagicLE, VMSelfExpectInjector.magicLE)
        XCTAssertTrue(result.usedCPSVSpanMap)
        XCTAssertEqual(result.source, .cpsvSpanMap)
        XCTAssertEqual(result.resolvedSymbolNames, ["_other_symbol", "cpsv.loop[1]", "cpsv.dispatch[2]"])
        XCTAssertEqual(result.fileOffsets, [
            UInt64(fixture.layout.execFileOff),
            UInt64(fixture.layout.loopFileOff),
            UInt64(fixture.layout.dispatchFileOff),
        ])

        let file = try MachOFile(url: url)
        let section = try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.Sections.vmpSelfExpect))
        let payload = try section.readContent(from: file.data)
        XCTAssertEqual(payload.count, 8, "mdvsk payload must be 8 bytes (magic + fnv)")
        XCTAssertEqual(Self.readLE32(payload, at: 0), VMSelfExpectInjector.magicLE)
        XCTAssertEqual(Self.readLE32(payload, at: 4), expectedHash)
    }

    func testInjectorFallsBackToLegacyThreeSymbolLayoutWhenSpanMapMissing() throws {
        let fixture = Self.makeFixture(
            textSize: 0x600,
            symbolMode: .threeInterpreterSymbols,
            includeSpanMap: false
        )
        let url = Self.temporaryURL(named: "vm_self_expect_legacy")
        defer { try? FileManager.default.removeItem(at: url) }
        try fixture.data.write(to: url)

        let before = try Data(contentsOf: url)
        let expectedHash = Self.expectedFnvFromFixture(before: before, layout: fixture.layout)

        let result = try VMSelfExpectInjector.inject(into: url)
        XCTAssertEqual(result.fnvExpect, expectedHash)
        XCTAssertEqual(result.expectMagicLE, VMSelfExpectInjector.magicLE)
        XCTAssertFalse(result.usedCPSVSpanMap)
        XCTAssertEqual(result.source, .legacySymtab)
        XCTAssertEqual(
            Set(result.resolvedSymbolNames),
            Set(["_cprisk_vm_execute", "_cprisk_vm_interp_loop_a", "_cprisk_vm_dispatch_lookup"])
        )
    }

    func testInjectHmacWritesCPSHPayloadFromSpanMap() throws {
        let fixture = Self.makeFixture(
            textSize: 0x600,
            symbolMode: .wrongOnly,
            includeSpanMap: true
        )
        let url = Self.temporaryURL(named: "vm_self_expect_hmac")
        defer { try? FileManager.default.removeItem(at: url) }
        try fixture.data.write(to: url)

        let before = try Data(contentsOf: url)
        let runtimeMaterial = Data((0..<32).map { UInt8(($0 * 3 + 7) & 0xFF) })
        let expectedCodePrefix = Self.expectedCodePrefixFromFixture(before: before, layout: fixture.layout)
        let expectedTag = VMSelfExpectInjector.hmacSelfCheckTag32(
            codePrefix: expectedCodePrefix,
            runtimeMaterial32: runtimeMaterial
        )

        let result = try VMSelfExpectInjector.injectHmac(into: url, runtimeMaterial32: runtimeMaterial)
        XCTAssertEqual(result.fnvExpect, expectedTag)
        XCTAssertEqual(result.expectMagicLE, VMSelfExpectInjector.magicHmacLE)
        XCTAssertTrue(result.usedCPSVSpanMap)
        XCTAssertEqual(result.source, .cpsvSpanMap)

        let file = try MachOFile(url: url)
        let section = try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.Sections.vmpSelfExpect))
        let payload = try section.readContent(from: file.data)
        XCTAssertEqual(payload.count, 8)
        XCTAssertEqual(Self.readLE32(payload, at: 0), VMSelfExpectInjector.magicHmacLE)
        XCTAssertEqual(Self.readLE32(payload, at: 4), expectedTag)
    }

    func testInjectorStrictlyFailsWhenNoSpanMapAndVMExecuteSymbolMissing() throws {
        let fixture = Self.makeFixture(
            textSize: 0x600,
            symbolMode: .wrongOnly,
            includeSpanMap: false
        )
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

    func testInjectorStrictlyFailsWhenTextWindowDoesNotFitSection() throws {
        let fixture = Self.makeFixture(
            textSize: 0x220,
            symbolMode: .wrongOnly,
            includeSpanMap: true
        )
        let url = Self.temporaryURL(named: "vm_self_expect_short_window")
        defer { try? FileManager.default.removeItem(at: url) }
        try fixture.data.write(to: url)

        XCTAssertThrowsError(try VMSelfExpectInjector.inject(into: url)) { error in
            guard case MachOError.invalidData(let message) = error else {
                return XCTFail("Expected invalidData, got: \(error)")
            }
            XCTAssertTrue(
                message.contains("must be at least") && message.contains("cpsv.dispatch[2]"),
                "strict behavior should reject a span that exceeds __TEXT.__text"
            )
        }
    }

    func testMalformedCPSVSpanMapDoesNotSilentlyFallbackToLegacySymtab() throws {
        let fixture = Self.makeFixture(
            textSize: 0x600,
            symbolMode: .threeInterpreterSymbols,
            includeSpanMap: true
        )
        let url = Self.temporaryURL(named: "vm_self_expect_bad_cpsv")
        defer { try? FileManager.default.removeItem(at: url) }

        var broken = fixture.data
        let spanMapFileOff = try XCTUnwrap(fixture.layout.spanMapFileOff)
        Self.writeLE32(&broken, at: spanMapFileOff + 8, value: 2)
        try broken.write(to: url)

        XCTAssertThrowsError(try VMSelfExpectInjector.inject(into: url)) { error in
            guard case MachOError.invalidData(let message) = error else {
                return XCTFail("Expected invalidData, got: \(error)")
            }
            XCTAssertTrue(
                message.contains("CPSV span map must have count==3"),
                "existing but malformed CPSV must fail closed instead of falling back to legacy symtab"
            )
        }
    }

    private struct FixtureLayout {
        let execFileOff: Int
        let loopFileOff: Int
        let dispatchFileOff: Int
        let spanMapFileOff: Int?
    }

    private struct Fixture {
        let data: Data
        let layout: FixtureLayout
    }

    private enum SymbolMode {
        case threeInterpreterSymbols
        case wrongOnly
    }

    private static func expectedCodePrefixFromFixture(before: Data, layout: FixtureLayout) -> Data {
        let e = VMSelfExpectInjector.execSegmentBytes
        let l = VMSelfExpectInjector.loopSegmentBytes
        let d = VMSelfExpectInjector.dispatchSegmentBytes
        var concat = Data()
        concat.reserveCapacity(e + l + d)
        concat.append(before.subdata(in: layout.execFileOff..<(layout.execFileOff + e)))
        concat.append(before.subdata(in: layout.loopFileOff..<(layout.loopFileOff + l)))
        concat.append(before.subdata(in: layout.dispatchFileOff..<(layout.dispatchFileOff + d)))
        return concat
    }

    private static func expectedFnvFromFixture(before: Data, layout: FixtureLayout) -> UInt32 {
        VMSelfExpectInjector.fnv1a32(bytes: expectedCodePrefixFromFixture(before: before, layout: layout))
    }

    private static func makeFixture(textSize: Int, symbolMode: SymbolMode, includeSpanMap: Bool) -> Fixture {
        let textOffset: UInt32 = 0x800
        let textVMAddr: UInt64 = 0x1800
        let dataOffset: UInt32 = 0x1000
        let symoff: UInt32 = 0x1800
        let mdvskSize: UInt64 = 8
        let mdvsiOffset: UInt32 = dataOffset + 0x10
        let mdvsiSize: UInt64 = 16 + (3 * 16)

        let execOff: UInt64 = 0x10
        var loopOff: UInt64 = 0x300
        /// Default: far enough that 64B dispatch window fits in large __text fixtures.
        var dispatchOff: UInt64 = 0x500
        if textSize <= 0x220 {
            /* Pack symbols into 0x220-byte __text; dispatch at 0x1E1 => 481+64=545 > section size. */
            loopOff = 0x100
            dispatchOff = 0x1E1
        }

        var strtab = Data([0])
        var nlist = Data()

        func appendSymbol(name: String, offsetInText: UInt64) {
            let strx = UInt32(strtab.count)
            strtab.append(contentsOf: name.utf8)
            strtab.append(0)

            nlist.appendLE(strx)
            nlist.append(0x0E) // N_SECT
            nlist.append(0x01) // __TEXT.__text (first section)
            nlist.appendLE(Int16(0))
            nlist.appendLE(textVMAddr + offsetInText)
        }

        let layout = FixtureLayout(
            execFileOff: Int(textOffset) + Int(execOff),
            loopFileOff: Int(textOffset) + Int(loopOff),
            dispatchFileOff: Int(textOffset) + Int(dispatchOff),
            spanMapFileOff: includeSpanMap ? Int(mdvsiOffset) : nil
        )

        switch symbolMode {
        case .threeInterpreterSymbols:
            appendSymbol(name: "_cprisk_vm_execute", offsetInText: execOff)
            appendSymbol(name: "_cprisk_vm_interp_loop_a", offsetInText: loopOff)
            appendSymbol(name: "_cprisk_vm_dispatch_lookup", offsetInText: dispatchOff)
        case .wrongOnly:
            appendSymbol(name: "_other_symbol", offsetInText: execOff)
        }

        let nsyms = UInt32(nlist.count / 16)
        let stroff = symoff + UInt32(nlist.count)
        let dataSectionCount: UInt32 = includeSpanMap ? 2 : 1
        let textSegmentCmdSize: UInt32 = 72 + 80
        let dataSegmentCmdSize: UInt32 = 72 + 80 * dataSectionCount
        let sizeOfCmds: UInt32 = textSegmentCmdSize + dataSegmentCmdSize + 24

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
        data.appendLE(textSegmentCmdSize)
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
        data.appendLE(dataSegmentCmdSize)
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x3000))
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(dataOffset))
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(3))
        data.appendLE(dataSectionCount)
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

        if includeSpanMap {
            data.appendFixedCString(ArmorABI.Sections.vmpSelfSpans, length: 16)
            data.appendFixedCString("__DATA", length: 16)
            data.appendLE(UInt64(0x3010))
            data.appendLE(mdvsiSize)
            data.appendLE(mdvsiOffset)
            data.appendLE(UInt32(3))
            data.appendLE(UInt32(0))
            data.appendLE(UInt32(0))
            data.appendLE(UInt32(0))
            data.appendLE(UInt32(0))
            data.appendLE(UInt32(0))
            data.appendLE(UInt32(0))
        }

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
        if includeSpanMap {
            if data.count < Int(mdvsiOffset) {
                data.append(Data(count: Int(mdvsiOffset) - data.count))
            }
            var spanMap = Data()
            spanMap.appendLE(VMSelfExpectInjector.spanMagicLE)
            spanMap.appendLE(VMSelfExpectInjector.spanVersion)
            spanMap.appendLE(UInt32(3))
            spanMap.appendLE(UInt32(0))

            func appendSpan(offsetInText: UInt64, length: UInt32, kind: UInt32) {
                spanMap.appendLE(textVMAddr + offsetInText)
                spanMap.appendLE(length)
                spanMap.appendLE(kind)
            }

            appendSpan(offsetInText: execOff, length: UInt32(VMSelfExpectInjector.execSegmentBytes), kind: 1)
            appendSpan(offsetInText: loopOff, length: UInt32(VMSelfExpectInjector.loopSegmentBytes), kind: 2)
            appendSpan(offsetInText: dispatchOff, length: UInt32(VMSelfExpectInjector.dispatchSegmentBytes), kind: 3)
            data.append(spanMap)
        }

        if data.count < Int(symoff) {
            data.append(Data(count: Int(symoff) - data.count))
        }
        data.append(nlist)
        data.append(strtab)

        return Fixture(data: data, layout: layout)
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

    private static func writeLE32(_ data: inout Data, at offset: Int, value: UInt32) {
        precondition(offset >= 0 && offset + 4 <= data.count)
        data[offset] = UInt8(value & 0xFF)
        data[offset + 1] = UInt8((value >> 8) & 0xFF)
        data[offset + 2] = UInt8((value >> 16) & 0xFF)
        data[offset + 3] = UInt8((value >> 24) & 0xFF)
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
