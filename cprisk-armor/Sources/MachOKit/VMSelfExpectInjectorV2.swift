import CryptoKit
import Foundation

// CPSV v2 self-expectation.
//
// MAC construction: CPRisk-MAC (NON-STANDARD pads ipad 0x6D / opad 0xA3) —
// see `ArmorABI.cpriskMAC`. CPRisk-MAC is NOT standard HMAC-SHA256 and does
// NOT interoperate with standard implementations. The pads are frozen by the
// deployed runtime / server contract; do NOT change them. Migration to
// standard HMAC requires protocol/contract version negotiation.
//
// The CPSH value written here is the FIRST 4 BYTES of the CPRisk-MAC digest
// — a 32-bit truncation, not a full-width MAC. Do not make full-width MAC
// security claims for it.
//
// TOCTOU WINDOW: this function hashes an in-memory snapshot of the file
// (`file.data`), verifies it against the layout sidecar, then writes the
// expectation back to the same path — with no file lock and no post-write
// re-verification. If another writer modifies the file between the
// layout-hash check and the final write, the expectation may describe stale
// bytes (or the write may interleave with the other writer). Run this tool
// only on a private, single-writer copy of the image, never on a file that
// another process may rewrite concurrently.
//
// PASS 6 CONFLICT: CPSV v2 requires BOTH the symbol table (to resolve the
// layout ranges to symbols) AND `LC_FUNCTION_STARTS` (for boundary checks).
// Pass 6 (SymbolStripper) destroys the symbol table, so a Pass-6-stripped
// image CANNOT be used with CPSV v2 — `injectV2` fails closed with an
// explicit conflict error instead of producing a mismatched expectation.
// (Pass 6 now preserves `LC_FUNCTION_STARTS`, but the symtab loss alone is
// disqualifying for v2.)

extension VMSelfExpectInjector {
    /// Finalize a pre-reserved v2 image without adding/moving sections or touching
    /// chained-fixup slots. Must run after code mutations and before code signing.
    static func injectV2(file: MachOFile, layoutURL: URL?, material: Data) throws -> Result {
        guard let layoutURL else { throw MachOError.invalidData("CPSV v2 requires --cpsv2-layout from the final linked image") }
        let layout = try JSONDecoder().decode(CPSV2Manifest.Layout.self, from: Data(contentsOf: layoutURL))
        let imageHash = SHA256.hash(data: file.data).map { String(format: "%02x", $0) }.joined()
        guard layout.imageSHA256 == imageHash else { throw MachOError.invalidData("CPSV v2 layout/image SHA256 mismatch") }
        guard let textSegment = try file.segment(named: "__TEXT"), textSegment.fileOffset == 0,
              let text = try file.section(segment: "__TEXT", section: "__text"),
              text.storesDataInFile,
              let spans = try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.Sections.vmpSelfSpans),
              spans.storesDataInFile, spans.size == UInt64(CPSV2Manifest.byteCount),
              let expect = try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.Sections.vmpSelfExpect),
              expect.storesDataInFile, expect.size == 8 else { throw MachOError.invalidData("CPSV v2 requires reserved manifest/expectation and file-backed TEXT") }
        let uuidCommands = file.loadCommands.filter { $0.cmd == 0x1b } // LC_UUID
        guard uuidCommands.count == 1 else { throw MachOError.invalidData("CPSV v2 requires one LC_UUID") }
        guard let u = Int(exactly: uuidCommands[0].offset), u <= file.data.count,
              file.data.count - u >= 24 else { throw MachOError.invalidData("CPSV v2 UUID command outside file") }
        guard try file.readUInt32(at: u + 4) == 24 else { throw MachOError.invalidData("CPSV v2 malformed LC_UUID") }
        let uuid = file.data.subdata(in: (u+8)..<(u+24))
        guard text.address >= textSegment.vmAddress else { throw MachOError.invalidData("CPSV v2 TEXT RVA underflow") }
        let payload = try CPSV2Manifest.encode(uuid: uuid, ranges: layout.ranges,
            imageBase: textSegment.vmAddress, textRVA: text.address - textSegment.vmAddress, textSize: text.size)
        let symbols = try file.readSymbols()
        // Explicit Pass 6 conflict detection: CPSV v2 resolves every layout
        // range through the symbol table. An empty symtab means the image
        // was stripped (Pass 6 zeroes LC_SYMTAB and scrubs the nlist/strtab
        // payloads) — fail with a conflict error naming Pass 6 instead of
        // the generic “missing symbol” error below.
        if symbols.isEmpty {
            throw MachOError.invalidData(
                "CPSV v2 conflict: symbol table is empty — the image appears stripped by Pass 6 (SymbolStripper). "
                + "CPSV v2 requires the symbol table to resolve layout ranges; do not combine Pass 6 symbol stripping "
                + "with CPSV v2 self-expect injection. Rebuild without Pass 6 or use the CPSV v1 span-map path."
            )
        }
        let boundaries = try v2FunctionStarts(file: file, base: textSegment.vmAddress)
        var offsets: [UInt64] = []
        for range in layout.ranges {
            let matches = symbols.filter {
                ($0.name == range.name || $0.name == "_" + range.name)
                    && $0.nlist.typeField == Nlist64Entry.N_SECT
            }
            guard matches.count == 1, matches[0].nlist.n_value == range.address,
                  boundaries.contains(range.address),
                  let offset = try file.fileOffset(forVMAddress: range.address),
                  offset <= UInt64(file.data.count), UInt64(range.length) <= UInt64(file.data.count) - offset else {
                throw MachOError.invalidData("CPSV v2 missing/ambiguous/stale symbol extent: \(range.name)")
            }
            if let next = boundaries.first(where: { $0 > range.address }),
               UInt64(range.length) > next - range.address {
                throw MachOError.invalidData("CPSV v2 extent crosses a function boundary: \(range.name)")
            }
            offsets.append(offset)
        }
        let key = deriveSelfCheckCPRiskMACKey(runtimeMaterial32: material).withUnsafeBytes { Data($0) }
        // CPRisk-MAC over (manifest payload || hashed TEXT ranges), truncated
        // to the first 4 digest bytes for the CPSH tag. Pads are 0x6D / 0xA3
        // (see `ArmorABI.cpriskMAC`) — non-standard, frozen by deployed interop.
        var macMessage = Data(payload)
        for (range, offset) in zip(layout.ranges, offsets) {
            macMessage.append(file.data.subdata(in: Int(offset)..<(Int(offset) + Int(range.length))))
        }
        let digest = Array(ArmorABI.cpriskMAC(key: key, message: macMessage))
        let tag = UInt32(digest[0]) | UInt32(digest[1]) << 8 | UInt32(digest[2]) << 16 | UInt32(digest[3]) << 24
        guard tag != 0 else { throw MachOError.invalidData("CPSV v2 zero tag reserved; rebuild image") }
        var expectation = Data()
        for word in [magicHmacLE, tag] {
            for i in 0..<4 { expectation.append(UInt8(truncatingIfNeeded: word >> (8*i))) }
        }
        try file.replaceBytes(at: UInt64(spans.offset), with: payload)
        try file.replaceBytes(at: UInt64(expect.offset), with: expectation)
        _ = try file.write(to: file.url, validateRoundTrip: true)
        return Result(fnvExpect: tag, expectMagicLE: magicHmacLE,
                      resolvedSymbolNames: layout.ranges.map(\.name),
                      symbolVMAddresses: layout.ranges.map(\.address), fileOffsets: offsets,
                      source: .cpsvV2)
    }

    /// LC_FUNCTION_STARTS supplies independent start/bounds checks, never the
    /// function lengths (those must come from the trusted final linker map).
    /// Pass 6 preserves LC_FUNCTION_STARTS, but if an older / differently
    /// stripped image lacks it, CPSV v2 fails closed here with a conflict
    /// error instead of guessing boundaries.
    private static func v2FunctionStarts(file: MachOFile, base: UInt64) throws -> [UInt64] {
        let commands = file.loadCommands.filter { $0.cmd == LoadCommand.LC_FUNCTION_STARTS }
        guard commands.count == 1 else {
            throw MachOError.invalidData(
                "CPSV v2 requires exactly one LC_FUNCTION_STARTS (found \(commands.count)). "
                + "If the image was stripped by Pass 6 or another strip step that removed it, "
                + "do not use CPSV v2 on this image."
            )
        }
        guard let command = Int(exactly: commands[0].offset), command <= file.data.count,
              file.data.count - command >= 16 else { throw MachOError.invalidData("CPSV v2 function starts command outside file") }
        guard try file.readUInt32(at: command + 4) == 16 else { throw MachOError.invalidData("CPSV v2 malformed function starts command") }
        let offset = Int(try file.readUInt32(at: command + 8)), size = Int(try file.readUInt32(at: command + 12))
        guard offset <= file.data.count, size <= file.data.count - offset else { throw MachOError.invalidData("CPSV v2 function starts outside file") }
        var pos = offset, address = base, starts: [UInt64] = []
        while pos < offset + size {
            var delta: UInt64 = 0, shift = 0
            while true {
                guard pos < offset + size, shift < 64 else { throw MachOError.invalidData("CPSV v2 truncated/overflow ULEB") }
                let byte = file.data[pos]; pos += 1
                guard shift != 63 || byte <= 1 else { throw MachOError.invalidData("CPSV v2 ULEB overflow") }
                delta |= UInt64(byte & 0x7f) << shift
                if byte & 0x80 == 0 { break }
                shift += 7
            }
            if delta == 0 { return starts }
            guard delta <= UInt64.max - address else { throw MachOError.invalidData("CPSV v2 address overflow") }
            address += delta; starts.append(address)
        }
        throw MachOError.invalidData("CPSV v2 missing function starts terminator")
    }
}
