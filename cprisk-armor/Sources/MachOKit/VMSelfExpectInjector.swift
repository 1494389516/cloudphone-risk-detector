import CryptoKit
import Foundation

/// Post-link injection of M3 self-expect into `__DATA,__swift5_mdvsk` (magic + FNV-1a u32 or CPSH tag).
///
/// Preferred producer path: read `__DATA,__swift5_mdvsi` (CPSV span map), concatenate the recorded
/// TEXT windows in-order, then write CPSF/CPSH to `__DATA,__swift5_mdvsk`. When the span map is
/// absent (older fixtures / binaries), the injector falls back to the legacy three-symbol layout:
/// `cprisk_vm_execute` (48 B) + `cprisk_vm_interp_loop_a` (64 B) + `cprisk_vm_dispatch_lookup` (64 B).
/// Intended for the **linked** Mach-O (thin `MH_MAGIC_64` only).
public enum VMSelfExpectInjector {
    /// `CPRISK_VMP_SELF_EXPECT_MAGIC` — ASCII "CPSF" as little-endian u32.
    public static let magicLE: UInt32 = 0x4653_5043
    /// `CPRISK_VMP_SELF_EXPECT_MAGIC_HMAC` — ASCII "CPSH" as little-endian u32.
    public static let magicHmacLE: UInt32 = 0x4853_5043
    /// `CPRISK_VMP_SELF_SPAN_MAGIC` — ASCII "CPSV" as little-endian u32.
    public static let spanMagicLE: UInt32 = 0x5653_5043
    /// `CPRISK_VMP_SELF_SPAN_VERSION`
    public static let spanVersion: UInt32 = 1

    /// `CPRISK_VM_M3_SELF_EXEC_BYTES`
    public static let execSegmentBytes: Int = 48
    /// `CPRISK_VM_M3_SELF_LOOP_BYTES`
    public static let loopSegmentBytes: Int = 64
    /// `CPRISK_VM_M3_SELF_DISPATCH_BYTES`
    public static let dispatchSegmentBytes: Int = 64
    /// `CPRISK_VM_M3_SELF_BYTES` — current CRiskCore total concatenated code bytes hashed.
    public static let selfByteCount: Int = execSegmentBytes + loopSegmentBytes + dispatchSegmentBytes

    public enum Source: String, Sendable {
        case cpsvSpanMap = "cpsv"
        case legacySymtab = "symtab"
    }

    public struct Result: Sendable {
        /// LE u32 after magic in mdvsk: FNV-1a (`inject`) or CPSH tag (`injectHmac`).
        public let fnvExpect: UInt32
        /// LE u32 magic written to mdvsk: `CPSF` for FNV or `CPSH` for HMAC.
        public let expectMagicLE: UInt32
        public let resolvedSymbolNames: [String]
        public let symbolVMAddresses: [UInt64]
        public let fileOffsets: [UInt64]
        /// Explicit source path used to resolve the three self-check windows.
        public let source: Source
        /// Compatibility mirror for existing callers that only branch on CPSV vs legacy symtab.
        public var usedCPSVSpanMap: Bool { source == .cpsvSpanMap }
    }

    /// Derives the 32-byte HMAC key the same way as `cprisk_vm_selfchk_hmac_key_i` (SHA-256 over material || XOR-mixed label || 8-byte session bind; bind is zero at link/inject time).
    public static func deriveSelfCheckHmacKey(runtimeMaterial32: Data) -> SymmetricKey {
        precondition(runtimeMaterial32.count == 32)
        var payload = Data(count: 58)
        payload.replaceSubrange(0..<32, with: runtimeMaterial32)
        let enc: [UInt8] = [
            0x19, 0x0a, 0x08, 0x13, 0x09, 0x11, 0x05, 0x0c, 0x17, 0x05, 0x17, 0x69,
            0x05, 0x12, 0x17, 0x1b, 0x19, 0x5a,
        ]
        precondition(enc.count == 18)
        for i in 0..<18 {
            payload[32 + i] = enc[i] ^ 0x5A
        }
        /* bytes 50...57 session bind — zero for injected CPSH unless matching live session material */
        let digest = SHA256.hash(data: payload)
        return SymmetricKey(data: Data(digest))
    }

    /// First 4 bytes (LE) of the custom-pad SHA-256 MAC — matches runtime `cprisk_vm_m3_selfchk_run_i`.
    public static func hmacSelfCheckTag32(codePrefix: Data, runtimeMaterial32: Data) -> UInt32 {
        let key = deriveSelfCheckHmacKey(runtimeMaterial32: runtimeMaterial32)
        let keyData = key.withUnsafeBytes { Data($0) }
        let d = ArmorABI.hmacSHA256(key: keyData, message: codePrefix)
        guard d.count >= 4 else { return 0 }
        return UInt32(d[0]) | (UInt32(d[1]) << 8) | (UInt32(d[2]) << 16) | (UInt32(d[3]) << 24)
    }

    /// FNV-1a 32-bit over bytes — matches `cprisk_vm_m3_fnv1a_bytes_i` / `cprisk_vm_m3_fnv1a_continue_i`.
    public static func fnv1a32(bytes: Data) -> UInt32 {
        var h: UInt32 = 2_166_136_261
        for b in bytes {
            h ^= UInt32(b)
            h &*= 16_776_619
        }
        return h
    }

    /// Resolve the self-check span layout, hash the recorded code prefixes, then write CPSF into
    /// `__DATA,__swift5_mdvsk` and save (invalidates code signature if present).
    public static func inject(into machoURL: URL) throws -> Result {
        let file = try MachOFile(url: machoURL)
        let symbols = try file.readSymbols()
        let (concat, meta, usedCPSV) = try Self.selfCheckCodePrefix(file: file, symbols: symbols)
        let fnv = fnv1a32(bytes: concat)

        var payload = Data()
        payload.appendUInt32LE(Self.magicLE)
        payload.appendUInt32LE(fnv)

        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Sections.vmpSelfExpect,
            content: payload,
            align: 2,
            flags: 0
        )
        _ = try file.write(to: machoURL, validateRoundTrip: true)
        return Result(
            fnvExpect: fnv,
            expectMagicLE: Self.magicLE,
            resolvedSymbolNames: meta.map(\.name),
            symbolVMAddresses: meta.map(\.vmaddr),
            fileOffsets: meta.map(\.fileOffset),
            source: usedCPSV ? .cpsvSpanMap : .legacySymtab
        )
    }

    /// Writes CPSH (magic + LE u32 HMAC tag) for the HMAC self-check path (`CPRISK_VMP_BC_FLAG_M3_SELFCHK_HMAC`).
    /// - Parameter runtimeMaterial32: Must match runtime `cprisk_get_runtime_material` (default: 32 zero bytes for CI).
    public static func injectHmac(into machoURL: URL, runtimeMaterial32: Data? = nil) throws -> Result {
        let mat = runtimeMaterial32 ?? Data(count: 32)
        precondition(mat.count == 32)
        let file = try MachOFile(url: machoURL)
        let symbols = try file.readSymbols()
        let (concat, meta, usedCPSV) = try Self.selfCheckCodePrefix(file: file, symbols: symbols)
        let tag = hmacSelfCheckTag32(codePrefix: concat, runtimeMaterial32: mat)

        var payload = Data()
        payload.appendUInt32LE(Self.magicHmacLE)
        payload.appendUInt32LE(tag)

        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Sections.vmpSelfExpect,
            content: payload,
            align: 2,
            flags: 0
        )
        _ = try file.write(to: machoURL, validateRoundTrip: true)
        return Result(
            fnvExpect: tag,
            expectMagicLE: Self.magicHmacLE,
            resolvedSymbolNames: meta.map(\.name),
            symbolVMAddresses: meta.map(\.vmaddr),
            fileOffsets: meta.map(\.fileOffset),
            source: usedCPSV ? .cpsvSpanMap : .legacySymtab
        )
    }

    private struct SegmentMeta: Sendable {
        let name: String
        let vmaddr: UInt64
        let fileOffset: UInt64
        let length: Int
    }

    private struct SpanHeader {
        let magic: UInt32
        let version: UInt32
        let count: UInt32
        let reserved: UInt32
    }

    private struct SpanEntry {
        let vmaddr: UInt64
        let length: UInt32
        let kind: UInt32
    }

    private static let legacySegmentSpecs: [(names: [String], length: Int)] = [
        (["_cprisk_vm_execute", "cprisk_vm_execute"], execSegmentBytes),
        (["_cprisk_vm_interp_loop_a", "cprisk_vm_interp_loop_a"], loopSegmentBytes),
        (["_cprisk_vm_dispatch_lookup", "cprisk_vm_dispatch_lookup"], dispatchSegmentBytes),
    ]

    private static func selfCheckCodePrefix(file: MachOFile, symbols: [SymbolEntry]) throws -> (Data, [SegmentMeta], Bool) {
        let (meta, usedCPSV) = try selfCheckSegments(file: file, symbols: symbols)
        var concat = Data()
        concat.reserveCapacity(meta.reduce(into: 0) { $0 += $1.length })
        for item in meta {
            let start = Int(item.fileOffset)
            let end = try intAdd(start, item.length, context: "hash byte range for \(item.name)")
            concat.append(file.data.subdata(in: start..<end))
        }
        guard concat.count == selfByteCount else {
            throw MachOError.invalidData("self-check concatenated length \(concat.count) != \(selfByteCount)")
        }
        return (concat, meta, usedCPSV)
    }

    private static func selfCheckSegments(file: MachOFile, symbols: [SymbolEntry]) throws -> ([SegmentMeta], Bool) {
        if let spans = try spanSelfCheckSegments(file: file, symbols: symbols) {
            return (spans, true)
        }
        return (try legacySelfCheckSegments(file: file, symbols: symbols), false)
    }

    private static func spanSelfCheckSegments(file: MachOFile, symbols: [SymbolEntry]) throws -> [SegmentMeta]? {
        guard let section = try file.section(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Sections.vmpSelfSpans
        ) else {
            return nil
        }

        let payload = try section.readContent(from: file.data)
        // Treat "section exists but unusable" the same as "section absent": return nil and let the
        // caller fall back to the legacy symtab path. We only hard-fail after the CPSV magic has
        // matched — at that point truncation / wrong counts signal genuine data corruption, not a
        // build that just happens to not carry a valid span map yet.
        if payload.isEmpty {
            return nil
        }
        guard payload.count >= 16 else {
            return nil
        }

        let header = SpanHeader(
            magic: try readUInt32LE(payload, at: 0),
            version: try readUInt32LE(payload, at: 4),
            count: try readUInt32LE(payload, at: 8),
            reserved: try readUInt32LE(payload, at: 12)
        )
        guard header.magic == spanMagicLE else {
            return nil
        }
        // Magic matched — from here on, mismatches indicate real corruption / version skew and we
        // fall back rather than hard-fail, so producers that ship a future span layout alongside a
        // compatible set of symbols can still inject self-expect.
        guard header.version == spanVersion else {
            return nil
        }
        guard header.reserved == 0 else {
            return nil
        }
        guard header.count == 3 else {
            return nil
        }
        let count = 3
        let expectedSize = try intAdd(16, count * 16, context: "CPSV payload size")
        guard payload.count >= expectedSize else {
            throw MachOError.invalidData("CPSV span map payload is truncated for \(count) entries")
        }

        var meta: [SegmentMeta] = []
        meta.reserveCapacity(count)
        for index in 0..<count {
            let offset = 16 + (index * 16)
            let entry = SpanEntry(
                vmaddr: try readUInt64LE(payload, at: offset),
                length: try readUInt32LE(payload, at: offset + 8),
                kind: try readUInt32LE(payload, at: offset + 12)
            )
            let expectedKind = UInt32(index + 1)
            guard entry.kind == expectedKind else {
                throw MachOError.invalidData("CPSV entry \(index) kind \(entry.kind) (expected \(expectedKind))")
            }
            let length = Int(entry.length)
            let expectedLength: Int
            switch entry.kind {
            case 1:
                expectedLength = execSegmentBytes
            case 2:
                expectedLength = loopSegmentBytes
            case 3:
                expectedLength = dispatchSegmentBytes
            default:
                throw MachOError.invalidData("CPSV entry \(index) unknown kind \(entry.kind)")
            }
            guard length == expectedLength else {
                throw MachOError.invalidData(
                    "CPSV entry \(index) length \(length) != expected \(expectedLength) for kind \(entry.kind)"
                )
            }
            guard let fileOffset = try file.fileOffset(forVMAddress: entry.vmaddr) else {
                throw MachOError.invalidData("could not map CPSV entry \(index) vmaddr 0x\(String(entry.vmaddr, radix: 16)) to file offset")
            }
            let name = symbolName(for: entry.vmaddr, symbols: symbols) ?? spanLabel(for: entry.kind, index: index)
            try validateWindow(
                file: file,
                vmaddr: entry.vmaddr,
                length: length,
                label: name
            )
            meta.append(
                SegmentMeta(
                    name: name,
                    vmaddr: entry.vmaddr,
                    fileOffset: fileOffset,
                    length: length
                )
            )
        }
        return meta
    }

    private static func legacySelfCheckSegments(file: MachOFile, symbols: [SymbolEntry]) throws -> [SegmentMeta] {
        var meta: [SegmentMeta] = []
        meta.reserveCapacity(legacySegmentSpecs.count)
        for spec in legacySegmentSpecs {
            guard let sym = symbols.first(where: { spec.names.contains($0.name) && $0.nlist.typeField == Nlist64Entry.N_SECT })
            else {
                throw MachOError.invalidData(
                    "symbol \(spec.names[0]) not found (symtab empty or stripped?)"
                )
            }
            let addr = sym.nlist.n_value
            guard let fileOffset = try file.fileOffset(forVMAddress: addr) else {
                throw MachOError.invalidData("could not map \(sym.name) to a file offset")
            }
            try validateWindow(file: file, vmaddr: addr, length: spec.length, label: sym.name)
            meta.append(
                SegmentMeta(
                    name: sym.name,
                    vmaddr: addr,
                    fileOffset: fileOffset,
                    length: spec.length
                )
            )
        }
        return meta
    }

    private static func validateWindow(file: MachOFile, vmaddr: UInt64, length: Int, label: String) throws {
        guard let sec = try file.section(containingVMAddress: vmaddr) else {
            throw MachOError.invalidData("no section for \(label)")
        }
        let window = UInt64(length)
        let secEnd = try u64Add(sec.address, sec.size, context: "section end")
        let winEnd = try u64Add(vmaddr, window, context: "hash window end for \(label)")
        guard winEnd <= secEnd else {
            throw MachOError.invalidData(
                "__TEXT window for \(label) must be at least \(length) bytes"
            )
        }
    }

    private static func symbolName(for vmaddr: UInt64, symbols: [SymbolEntry]) -> String? {
        symbols.first(where: { $0.nlist.typeField == Nlist64Entry.N_SECT && $0.nlist.n_value == vmaddr })?.name
    }

    private static func spanLabel(for kind: UInt32, index: Int) -> String {
        switch kind {
        case 1:
            return "cpsv.exec[\(index)]"
        case 2:
            return "cpsv.loop[\(index)]"
        case 3:
            return "cpsv.dispatch[\(index)]"
        default:
            return "cpsv.kind\(kind)[\(index)]"
        }
    }

    private static func u64Add(_ a: UInt64, _ b: UInt64, context: String) throws -> UInt64 {
        let (r, o) = a.addingReportingOverflow(b)
        if o { throw MachOError.integerOverflow(context) }
        return r
    }

    private static func intAdd(_ a: Int, _ b: Int, context: String) throws -> Int {
        let (r, o) = a.addingReportingOverflow(b)
        if o { throw MachOError.integerOverflow(context) }
        return r
    }

    private static func readUInt32LE(_ data: Data, at offset: Int) throws -> UInt32 {
        guard offset >= 0, offset + 4 <= data.count else {
            throw MachOError.outOfBoundsRead(offset: offset, size: 4, dataSize: data.count)
        }
        return UInt32(data[offset])
            | (UInt32(data[offset + 1]) << 8)
            | (UInt32(data[offset + 2]) << 16)
            | (UInt32(data[offset + 3]) << 24)
    }

    private static func readUInt64LE(_ data: Data, at offset: Int) throws -> UInt64 {
        guard offset >= 0, offset + 8 <= data.count else {
            throw MachOError.outOfBoundsRead(offset: offset, size: 8, dataSize: data.count)
        }
        return UInt64(data[offset])
            | (UInt64(data[offset + 1]) << 8)
            | (UInt64(data[offset + 2]) << 16)
            | (UInt64(data[offset + 3]) << 24)
            | (UInt64(data[offset + 4]) << 32)
            | (UInt64(data[offset + 5]) << 40)
            | (UInt64(data[offset + 6]) << 48)
            | (UInt64(data[offset + 7]) << 56)
    }
}

private extension Data {
    mutating func appendUInt32LE(_ v: UInt32) {
        var le = v.littleEndian
        append(Swift.withUnsafeBytes(of: &le) { Data($0) })
    }
}
