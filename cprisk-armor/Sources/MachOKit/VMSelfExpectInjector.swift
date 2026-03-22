import CryptoKit
import Foundation

/// Post-link injection of M3 self-expect into `__DATA,__swift5_mdvsk` (magic + FNV-1a u32).
///
/// FNV and window size match `cprisk_vm_interpreter.c` / `cprisk_vm_interpreter.h` (96 bytes at
/// `cprisk_vm_execute`). Intended to run on the **linked** Mach-O (thin `MH_MAGIC_64` only).
public enum VMSelfExpectInjector {
    /// `CPRISK_VMP_SELF_EXPECT_MAGIC` — ASCII "CPSF" as little-endian u32.
    public static let magicLE: UInt32 = 0x4653_5043
    /// `CPRISK_VMP_SELF_EXPECT_MAGIC_HMAC` — ASCII "CPSH" as little-endian u32.
    public static let magicHmacLE: UInt32 = 0x4853_5043
    /// `CPRISK_VM_M3_SELF_BYTES`
    public static let selfByteCount: Int = 96

    public struct Result: Sendable {
        public let fnvExpect: UInt32
        public let resolvedSymbolName: String
        public let symbolVMA: UInt64
        public let fileOffset: UInt64
    }

    /// Derives the 32-byte HMAC key the same way as `cprisk_vm_selfchk_hmac_key_i` (SHA-256 over material||ASCII||NUL).
    public static func deriveSelfCheckHmacKey(runtimeMaterial32: Data) -> SymmetricKey {
        precondition(runtimeMaterial32.count == 32)
        var payload = Data(count: 50)
        payload.replaceSubrange(0..<32, with: runtimeMaterial32)
        let label = "CPRISK_VM_M3_HMAC"
        let labelBytes = [UInt8](label.utf8)
        for i in 0..<17 {
            payload[32 + i] = i < labelBytes.count ? labelBytes[i] : 0
        }
        payload[49] = 0
        let digest = SHA256.hash(data: payload)
        return SymmetricKey(data: Data(digest))
    }

    /// First 4 bytes (LE) of HMAC-SHA256(key, codePrefix) — matches runtime `cprisk_vm_m3_selfchk_run_i` HMAC path.
    public static func hmacSelfCheckTag32(codePrefix: Data, runtimeMaterial32: Data) -> UInt32 {
        let key = deriveSelfCheckHmacKey(runtimeMaterial32: runtimeMaterial32)
        let mac = HMAC<SHA256>.authenticationCode(for: codePrefix, using: key)
        let d = Data(mac)
        guard d.count >= 4 else { return 0 }
        return UInt32(d[0]) | (UInt32(d[1]) << 8) | (UInt32(d[2]) << 16) | (UInt32(d[3]) << 24)
    }

    /// FNV-1a 32-bit over bytes — matches `cprisk_vm_m3_fnv1a_bytes_i`.
    public static func fnv1a32(bytes: Data) -> UInt32 {
        var h: UInt32 = 2_166_136_261
        for b in bytes {
            h ^= UInt32(b)
            h &*= 16_777_619
        }
        return h
    }

    /// Locate `_cprisk_vm_execute`, hash the first ``selfByteCount`` code bytes, write 8-byte blob
    /// into `__DATA,__swift5_mdvsk`, and save (invalidates code signature if present).
    public static func inject(into machoURL: URL) throws -> Result {
        let file = try MachOFile(url: machoURL)
        let symbols = try file.readSymbols()
        let names = ["_cprisk_vm_execute", "cprisk_vm_execute"]
        guard let sym = symbols.first(where: { names.contains($0.name) && $0.nlist.typeField == Nlist64Entry.N_SECT })
        else {
            throw MachOError.invalidData("symbol _cprisk_vm_execute not found (symtab empty or stripped?)")
        }
        let addr = sym.nlist.n_value
        guard let fileOffOpt = try file.fileOffset(forVMAddress: addr) else {
            throw MachOError.invalidData("could not map _cprisk_vm_execute to a file offset")
        }
        guard let sec = try file.section(containingVMAddress: addr) else {
            throw MachOError.invalidData("no section for _cprisk_vm_execute")
        }
        let window = UInt64(selfByteCount)
        let secEnd = try u64Add(sec.address, sec.size, context: "section end")
        let winEnd = try u64Add(addr, window, context: "hash window end")
        guard winEnd <= secEnd else {
            throw MachOError.invalidData(
                "__TEXT window for _cprisk_vm_execute must be at least \(selfByteCount) bytes"
            )
        }

        let start = Int(fileOffOpt)
        let end = try intAdd(start, selfByteCount, context: "hash byte range")
        let slice = file.data.subdata(in: start..<end)
        let fnv = fnv1a32(bytes: slice)

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
            resolvedSymbolName: sym.name,
            symbolVMA: addr,
            fileOffset: fileOffOpt
        )
    }

    /// Writes CPSH (magic + LE u32 HMAC tag) for the HMAC self-check path (`CPRISK_VMP_BC_FLAG_M3_SELFCHK_HMAC`).
    /// - Parameter runtimeMaterial32: Must match runtime `cprisk_get_runtime_material` (default: 32 zero bytes for CI).
    public static func injectHmac(into machoURL: URL, runtimeMaterial32: Data? = nil) throws -> UInt32 {
        let mat = runtimeMaterial32 ?? Data(count: 32)
        precondition(mat.count == 32)
        let file = try MachOFile(url: machoURL)
        let symbols = try file.readSymbols()
        let names = ["_cprisk_vm_execute", "cprisk_vm_execute"]
        guard let sym = symbols.first(where: { names.contains($0.name) && $0.nlist.typeField == Nlist64Entry.N_SECT })
        else {
            throw MachOError.invalidData("symbol _cprisk_vm_execute not found (symtab empty or stripped?)")
        }
        let addr = sym.nlist.n_value
        guard let fileOffOpt = try file.fileOffset(forVMAddress: addr) else {
            throw MachOError.invalidData("could not map _cprisk_vm_execute to a file offset")
        }
        guard let sec = try file.section(containingVMAddress: addr) else {
            throw MachOError.invalidData("no section for _cprisk_vm_execute")
        }
        let window = UInt64(selfByteCount)
        let secEnd = try u64Add(sec.address, sec.size, context: "section end")
        let winEnd = try u64Add(addr, window, context: "hash window end")
        guard winEnd <= secEnd else {
            throw MachOError.invalidData(
                "__TEXT window for _cprisk_vm_execute must be at least \(selfByteCount) bytes"
            )
        }

        let start = Int(fileOffOpt)
        let end = try intAdd(start, selfByteCount, context: "hash byte range")
        let slice = file.data.subdata(in: start..<end)
        let tag = hmacSelfCheckTag32(codePrefix: slice, runtimeMaterial32: mat)

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
        return tag
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
}

private extension Data {
    mutating func appendUInt32LE(_ v: UInt32) {
        var le = v.littleEndian
        append(Swift.withUnsafeBytes(of: &le) { Data($0) })
    }
}
