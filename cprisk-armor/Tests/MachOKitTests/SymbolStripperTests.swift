import XCTest
import MachOKit
import SymbolStripper

final class SymbolStripperTests: XCTestCase {

    // MARK: - Fixture Builder

    /// Build an ARM64 Mach-O with __TEXT segment, LC_SYMTAB, and a symbol/string table
    /// containing a mix of local SDK symbols, local non-SDK symbols, external symbols,
    /// stab symbols, and "outlined" symbols.
    ///
    /// Layout:
    ///   [0..32)         mach_header_64
    ///   [32..184)       LC_SEGMENT_64 __TEXT (72 + 1 section = 152 bytes)
    ///   [184..208)      LC_SYMTAB (24 bytes)
    ///   [208..2048)     padding
    ///   [2048..4096)    __TEXT.__cstring content + padding
    ///   [4096..)        symbol table (nlist64 entries), then string table
    private static func makeSymtabFixture() -> Data {
        // -- String table --
        // Index 0: "\0" (empty, required by convention)
        // Index 1: "_$s10CPRiskKit20evaluateRiskPolicySiyF\0"  (local SDK symbol)
        // Index 43: "_regularHelperFunction\0"                  (local non-SDK symbol)
        // Index 66: "_$s10CPRiskKit8exported\0"                 (external symbol)
        // Index 90: "outlined init with copy of (RiskScenario, ScenarioPolicy)\0" (outlined local)
        // Index 149: "_$s9Detection15JailbreakCheckCfd\0"        (local SDK: Detection + Jailbreak)
        // Index 184: ""

        let strings: [(String, Bool)] = [
            ("", false), // index 0 placeholder
        ]
        _ = strings

        var stringTable = Data()
        stringTable.append(0) // index 0: empty string

        let sym1Name = "_$s10CPRiskKit20evaluateRiskPolicySiyF"
        let sym1Strx = UInt32(stringTable.count)
        stringTable.append(contentsOf: sym1Name.utf8)
        stringTable.append(0)

        let sym2Name = "_regularHelperFunction"
        let sym2Strx = UInt32(stringTable.count)
        stringTable.append(contentsOf: sym2Name.utf8)
        stringTable.append(0)

        let sym3Name = "_$s10CPRiskKit8exported"
        let sym3Strx = UInt32(stringTable.count)
        stringTable.append(contentsOf: sym3Name.utf8)
        stringTable.append(0)

        let sym4Name = "outlined init with copy of (RiskScenario, ScenarioPolicy)"
        let sym4Strx = UInt32(stringTable.count)
        stringTable.append(contentsOf: sym4Name.utf8)
        stringTable.append(0)

        let sym5Name = "_$s9Detection15JailbreakCheckCfd"
        let sym5Strx = UInt32(stringTable.count)
        stringTable.append(contentsOf: sym5Name.utf8)
        stringTable.append(0)

        let sym6Name = "_someStabSymbol"
        let sym6Strx = UInt32(stringTable.count)
        stringTable.append(contentsOf: sym6Name.utf8)
        stringTable.append(0)

        // Nlist entries start at file offset 4096
        let symoff: UInt32 = 4096
        let nsyms: UInt32 = 6
        let nlistSize = Int(nsyms) * 16
        let stroff = symoff + UInt32(nlistSize)

        // Build nlist64 entries
        var nlistData = Data()

        // Symbol 1: local SDK symbol (N_SECT, no N_EXT)
        nlistData.appendLE(sym1Strx)
        nlistData.append(0x0E) // n_type = N_SECT
        nlistData.append(0x01) // n_sect
        nlistData.appendLE(Int16(0)) // n_desc
        nlistData.appendLE(UInt64(0x100001000)) // n_value

        // Symbol 2: local non-SDK symbol (N_SECT, no N_EXT) — should NOT be obfuscated
        nlistData.appendLE(sym2Strx)
        nlistData.append(0x0E)
        nlistData.append(0x01)
        nlistData.appendLE(Int16(0))
        nlistData.appendLE(UInt64(0x100002000))

        // Symbol 3: external symbol (N_SECT | N_EXT) — should NOT be obfuscated
        nlistData.appendLE(sym3Strx)
        nlistData.append(0x0F) // n_type = N_SECT | N_EXT
        nlistData.append(0x01)
        nlistData.appendLE(Int16(0))
        nlistData.appendLE(UInt64(0x100003000))

        // Symbol 4: local "outlined" symbol (N_SECT, no N_EXT) — should be obfuscated
        nlistData.appendLE(sym4Strx)
        nlistData.append(0x0E)
        nlistData.append(0x01)
        nlistData.appendLE(Int16(0))
        nlistData.appendLE(UInt64(0x100004000))

        // Symbol 5: local SDK symbol with Detection + Jailbreak markers
        nlistData.appendLE(sym5Strx)
        nlistData.append(0x0E)
        nlistData.append(0x01)
        nlistData.appendLE(Int16(0))
        nlistData.appendLE(UInt64(0x100005000))

        // Symbol 6: stab debug symbol (N_STAB set) — should NOT be obfuscated
        nlistData.appendLE(sym6Strx)
        nlistData.append(0x24) // N_FUN stab type (has N_STAB bit set)
        nlistData.append(0x01)
        nlistData.appendLE(Int16(0))
        nlistData.appendLE(UInt64(0x100006000))

        // -- Build the full Mach-O --
        var d = Data()

        // mach_header_64
        d.appendLE(UInt32(0xFEEDFACF)) // magic
        d.appendLE(UInt32(0x0100000C)) // CPU_TYPE_ARM64
        d.appendLE(UInt32(0))          // cpusubtype
        d.appendLE(UInt32(2))          // MH_EXECUTE
        d.appendLE(UInt32(2))          // ncmds: __TEXT + LC_SYMTAB
        let sizeOfCmds: UInt32 = 152 + 24
        d.appendLE(sizeOfCmds)
        d.appendLE(UInt32(0))          // flags
        d.appendLE(UInt32(0))          // reserved
        assert(d.count == 32)

        // LC_SEGMENT_64 __TEXT (72 + 80 = 152)
        d.appendLE(UInt32(0x19))       // cmd = LC_SEGMENT_64
        d.appendLE(UInt32(152))        // cmdsize
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(0))          // vmaddr
        d.appendLE(UInt64(4096))       // vmsize
        d.appendLE(UInt64(0))          // fileoff
        d.appendLE(UInt64(4096))       // filesize
        d.appendLE(UInt32(5))          // maxprot
        d.appendLE(UInt32(5))          // initprot
        d.appendLE(UInt32(1))          // nsects
        d.appendLE(UInt32(0))          // flags

        // __TEXT.__cstring section header
        d.appendFixedCString("__cstring", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(2048))       // addr
        d.appendLE(UInt64(12))         // size
        d.appendLE(UInt32(2048))       // offset
        d.appendLE(UInt32(0))          // align
        d.appendLE(UInt32(0))          // reloff
        d.appendLE(UInt32(0))          // nreloc
        d.appendLE(UInt32(0x02))       // flags (S_CSTRING_LITERALS)
        d.appendLE(UInt32(0))          // reserved1
        d.appendLE(UInt32(0))          // reserved2
        d.appendLE(UInt32(0))          // reserved3
        assert(d.count == 184)

        // LC_SYMTAB
        d.appendLE(UInt32(0x02))       // cmd = LC_SYMTAB
        d.appendLE(UInt32(24))         // cmdsize
        d.appendLE(symoff)             // symoff
        d.appendLE(nsyms)              // nsyms
        d.appendLE(stroff)             // stroff
        d.appendLE(UInt32(stringTable.count)) // strsize
        assert(d.count == 208)

        // Padding to __cstring content at offset 2048
        d.append(Data(count: 2048 - d.count))
        d.append(contentsOf: "Hello".utf8)
        d.append(0)
        d.append(contentsOf: "World".utf8)
        d.append(0)

        // Padding to nlist entries at offset 4096
        d.append(Data(count: Int(symoff) - d.count))
        d.append(nlistData)
        assert(d.count == Int(stroff))
        d.append(stringTable)

        return d
    }

    private static func writeFixture(named name: String) throws -> URL {
        let url = temporaryURL(named: name)
        try makeSymtabFixture().write(to: url)
        return url
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
    }

    // MARK: - A. Symbol Table Parsing

    func testReadSymbolsReturnsAllEntries() throws {
        let url = try Self.writeFixture(named: "parse_symbols")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let symbols = try file.readSymbols()
        XCTAssertEqual(symbols.count, 6)

        XCTAssertTrue(symbols[0].name.contains("CPRiskKit"))
        XCTAssertTrue(symbols[1].name.contains("regularHelper"))
        XCTAssertTrue(symbols[2].name.contains("exported"))
        XCTAssertTrue(symbols[3].name.contains("outlined"))
        XCTAssertTrue(symbols[4].name.contains("Jailbreak"))
        XCTAssertTrue(symbols[5].name.contains("Stab"))
    }

    func testNlist64EntryFlags() throws {
        let url = try Self.writeFixture(named: "nlist_flags")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let symbols = try file.readSymbols()

        // sym1: local SDK
        XCTAssertTrue(symbols[0].nlist.isDefinedLocal)
        XCTAssertFalse(symbols[0].nlist.isExternal)
        XCTAssertFalse(symbols[0].nlist.isStab)

        // sym2: local non-SDK
        XCTAssertTrue(symbols[1].nlist.isDefinedLocal)

        // sym3: external
        XCTAssertFalse(symbols[2].nlist.isDefinedLocal)
        XCTAssertTrue(symbols[2].nlist.isExternal)

        // sym4: local outlined
        XCTAssertTrue(symbols[3].nlist.isDefinedLocal)

        // sym5: local detection/jailbreak
        XCTAssertTrue(symbols[4].nlist.isDefinedLocal)

        // sym6: stab
        XCTAssertTrue(symbols[5].nlist.isStab)
        XCTAssertFalse(symbols[5].nlist.isDefinedLocal)
    }

    // MARK: - B. Selective Obfuscation

    func testObfuscatesOnlySDKLocalSymbols() throws {
        let url = try Self.writeFixture(named: "selective_obfusc")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let config = PassConfig(verbose: true)
        let result = try SymbolStripperPass().execute(on: file, config: config)

        // Should obfuscate: sym1 (CPRisk), sym4 (outlined), sym5 (Detection+Jailbreak) = 3
        XCTAssertEqual(result.itemsProcessed, 3, "Expected 3 SDK/outlined symbols to be obfuscated")
        XCTAssertGreaterThan(result.bytesModified, 0)

        // Verify the names were actually changed
        let symbolsAfter = try file.readSymbols()

        // sym1: was CPRiskKit symbol → should be obfuscated
        XCTAssertFalse(symbolsAfter[0].name.contains("CPRisk"),
                       "SDK symbol should have been obfuscated")

        // sym2: was regularHelper → should be UNTOUCHED
        XCTAssertTrue(symbolsAfter[1].name.contains("regularHelper"),
                      "Non-SDK local symbol should be untouched")

        // sym3: was exported CPRiskKit → should be UNTOUCHED (external)
        XCTAssertTrue(symbolsAfter[2].name.contains("CPRiskKit"),
                      "External symbol should be untouched")

        // sym4: was "outlined init..." → should be obfuscated
        XCTAssertFalse(symbolsAfter[3].name.contains("outlined"),
                       "Outlined symbol should have been obfuscated")

        // sym5: was Detection/Jailbreak → should be obfuscated
        XCTAssertFalse(symbolsAfter[4].name.contains("Detection"),
                       "SDK symbol with Detection marker should have been obfuscated")

        // sym6: was stab → should be UNTOUCHED
        XCTAssertTrue(symbolsAfter[5].name.contains("Stab"),
                      "Stab symbol should be untouched")
    }

    func testObfuscatedNameLengthPreserved() throws {
        let url = try Self.writeFixture(named: "length_preserved")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let symbolsBefore = try file.readSymbols()
        let lengthsBefore = symbolsBefore.map { $0.nameLength }

        _ = try SymbolStripperPass().execute(on: file, config: PassConfig())

        let symbolsAfter = try file.readSymbols()
        let lengthsAfter = symbolsAfter.map { $0.nameLength }

        XCTAssertEqual(lengthsBefore, lengthsAfter,
                       "All symbol name lengths must be preserved after obfuscation")
    }

    // MARK: - C. Edge Cases

    func testNoSymbolTableReturnsEmpty() throws {
        // Build a minimal Mach-O without LC_SYMTAB
        var d = Data()
        d.appendLE(UInt32(0xFEEDFACF))
        d.appendLE(UInt32(0x0100000C))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(2))
        d.appendLE(UInt32(1))          // 1 command
        d.appendLE(UInt32(152))        // sizeofcmds
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

        // LC_SEGMENT_64 __TEXT
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

        d.appendFixedCString("__cstring", length: 16)
        d.appendFixedCString("__TEXT", length: 16)
        d.appendLE(UInt64(2048))
        d.appendLE(UInt64(6))
        d.appendLE(UInt32(2048))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0x02))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))
        d.appendLE(UInt32(0))

        d.append(Data(count: 2048 - d.count))
        d.append(contentsOf: "Hello".utf8)
        d.append(0)
        d.append(Data(count: 4096 - d.count))

        let url = Self.temporaryURL(named: "no_symtab")
        try d.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let result = try SymbolStripperPass().execute(on: file, config: PassConfig())

        XCTAssertEqual(result.itemsProcessed, 0)
        XCTAssertEqual(result.bytesModified, 0)
        XCTAssertTrue(result.details.first?.contains("No symbol table") == true)
    }

    // MARK: - D. PassResult

    func testPassResultReporting() throws {
        let url = try Self.writeFixture(named: "result_report")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let result = try SymbolStripperPass().execute(on: file, config: PassConfig())

        XCTAssertEqual(result.passName, "SymbolStripper")
        XCTAssertGreaterThan(result.itemsProcessed, 0)
        XCTAssertGreaterThan(result.bytesModified, 0)
        XCTAssertTrue(result.details.contains(where: { $0.contains("Local symbols:") }))
    }

    // MARK: - E. Obfuscated Content Is Hex

    func testObfuscatedNamesAreHexBytes() throws {
        let url = try Self.writeFixture(named: "hex_content")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        _ = try SymbolStripperPass().execute(on: file, config: PassConfig())

        let hexChars = Set("0123456789abcdef".unicodeScalars)
        let symbolsAfter = try file.readSymbols()

        // sym1 was obfuscated — verify content is all hex
        let name0 = symbolsAfter[0].name
        XCTAssertGreaterThan(name0.count, 0)
        for scalar in name0.unicodeScalars {
            XCTAssertTrue(hexChars.contains(scalar),
                          "Expected hex character, got '\(scalar)' in '\(name0)'")
        }
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
