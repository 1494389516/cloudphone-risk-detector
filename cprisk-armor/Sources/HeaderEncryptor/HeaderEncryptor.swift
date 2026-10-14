import CryptoKit
import Foundation
import MachOKit

/// Pass 3.5 / Pass 11: Header-backup encryption / header camouflage
/// (NOT “header encryption”).
///
/// What this pass actually does:
///  1. Copies six `mach_header_64` fields into a dedicated `__DATA`
///     `ArmorABI.Sections.headerBackup` section, encrypted with an XOR
///     keystream and authenticated with a tag.
///  2. Writes a per-binary camouflage value into `mach_header_64.reserved`.
///
/// What it does NOT do: the six fields (magic, filetype, ncmds,
/// sizeofcmds, flags, reserved) REMAIN IN PLAINTEXT in the file header —
/// only `reserved` is overwritten with the camouflage value. Do not describe
/// this pass as encrypting the header; the header itself is still readable,
/// and the encrypted copy lives in the backup section for a runtime restore
/// consumer. At runtime, CRiskCore reads the backup section, verifies the
/// tag, decrypts the fields via XOR keystream, and restores the header
/// before dyld finishes processing.
///
/// Legacy marker: this producer NO LONGER writes the fixed marker `CPBH`
/// (`0x43504248`) into the header — the camouflage value is per-binary.
/// The runtime still ACCEPTS `CPBH` for backward compatibility with old
/// binaries, which means old binaries still carry that globally stable,
/// searchable marker. Removing runtime acceptance is a runtime-side decision
/// (outside this producer); until then, the marker risk persists for
/// previously shipped artifacts only.
///
/// Layout of the backup section (64 bytes total, FROZEN):
///   nonce[8] | encrypted_fields[24] | cprisk_mac_tag[32]
///
/// Encrypted fields (24 bytes, in Mach-O native byte order):
///   magic(4) | filetype(4) | ncmds(4) | sizeofcmds(4) | flags(4) | reserved_placeholder(4)
///
/// The keystream is derived from the WhiteBox Domain-9 PRF output using the
/// same XOR-with-keystream pattern as DataSegmentEncryptor.
public final class HeaderEncryptorPass: ArmorPass {
    public let name = "HeaderEncryptor"

    /// Legacy fixed marker kept for runtime backward compatibility.
    public static let legacyHeaderMagic: UInt32 = 0x4350_4248  // "CPBH"

    /// Size of the backup section payload: nonce(8) + encrypted(24) + CPRisk-MAC tag(32).
    public static let backupSectionSize = 64

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        guard let rootKey = config.encryptionKey else {
            throw MachOError.invalidData(
                "HeaderEncryptorPass requires an encryption key (no zero/default key fallback)"
            )
        }

        // The backup must describe the header that will actually be written.
        // Reserve the section header first and remove the now-invalid code
        // signature command before taking the snapshot. Otherwise a binary
        // without a prelinked placeholder records stale ncmds/sizeofcmds, and
        // write(to:) can later remove LC_CODE_SIGNATURE behind its back.
        let removedCodeSignatureBytes = try file.removeCodeSignatureCommands()
        if try file.section(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Sections.headerBackup
        ) == nil {
            _ = try file.addOrUpdateSection(
                segment: ArmorABI.dataSegmentName,
                section: ArmorABI.Sections.headerBackup,
                content: Data(count: Self.backupSectionSize),
                align: 3
            )
        }

        // Build the WhiteBox bundle and derive the header encryption key.
        let whitebox = try ArmorWhiteBox.build(rootKey: rootKey)
        let headerKey = deriveHeaderKey(whitebox: whitebox)

        // --- Read the six header fields that need protection ---
        // Use the public MachOFile API to access raw header bytes.
        let magic       = try file.readUInt32(at: 0)
        let filetype    = try file.readUInt32(at: 12)
        let ncmds       = try file.readUInt32(at: 16)
        let sizeofcmds  = try file.readUInt32(at: 20)
        let flags       = try file.readUInt32(at: 24)
        let reserved    = try file.readUInt32(at: 28)

        // Pack the six fields into 24 bytes (each field is 4 bytes, LE).
        var fieldsData = Data()
        appendUInt32LE(magic, to: &fieldsData)
        appendUInt32LE(filetype, to: &fieldsData)
        appendUInt32LE(ncmds, to: &fieldsData)
        appendUInt32LE(sizeofcmds, to: &fieldsData)
        appendUInt32LE(flags, to: &fieldsData)
        appendUInt32LE(reserved, to: &fieldsData)
        precondition(fieldsData.count == 24, "Header fields must be exactly 24 bytes")

        // --- Generate a random 8-byte nonce ---
        let nonce = try generateNonce()

        // --- Derive the XOR keystream ---
        // Use keyID = 0 for the header backup section (stable identifier).
        let keystream = makeKeystream(
            key: headerKey,
            keyID: 0,
            nonce: nonce,
            length: fieldsData.count
        )

        // --- Encrypt via XOR ---
        let encryptedFields = xor(fieldsData, keystream)

        // CPRisk-MAC scope binds (nonce_len, nonce, ct_len, ciphertext) with
        // length prefixes — see the canonical encoding mirror in
        // cprisk_header_restore.c. The tag MUST use CPRisk-MAC
        // (ArmorABI.cpriskMAC, non-standard pads 0x6D/0xA3), NOT standard
        // HMAC, because the runtime verifier (cprisk_verify_header_mac)
        // computes CPRisk-MAC. A standard-HMAC tag would never verify.
        // The previous `nonce || ciphertext` form was vulnerable to
        // truncation/extension attacks in theory;
        // for the fixed 8+24 layout the practical risk is small but the
        // pattern matches DataSegmentEncryptor / StringEncryptor for
        // consistency, so future layout changes inherit the binding.
        var macMessage = Data()
        var nonceLenLE = UInt32(nonce.count).littleEndian
        withUnsafeBytes(of: &nonceLenLE) { macMessage.append(contentsOf: $0) }
        macMessage.append(nonce)
        var ctLenLE = UInt32(encryptedFields.count).littleEndian
        withUnsafeBytes(of: &ctLenLE) { macMessage.append(contentsOf: $0) }
        macMessage.append(encryptedFields)
        let macTag = ArmorABI.cpriskMAC(key: headerKey, message: macMessage)

        // --- Assemble the 64-byte backup payload ---
        var backupPayload = Data()
        backupPayload.append(nonce)        // 8 bytes
        backupPayload.append(encryptedFields) // 24 bytes
        backupPayload.append(macTag)      // 32 bytes
        precondition(backupPayload.count == Self.backupSectionSize,
                     "Backup payload must be exactly 64 bytes")

        // --- Write the backup section into __DATA ---
        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Sections.headerBackup,
            content: backupPayload,
            align: 3
        )

        // --- Write a camouflaged reserved value into mach_header_64.reserved ---
        // This avoids a globally stable marker while preserving deterministic
        // restoration logic (runtime recomputes the same value from nonce +
        // original reserved field). Note the other five header fields stay
        // plaintext in the file header (see the file header comment) — only
        // `reserved` is camouflaged here.
        let camouflagedReserved = makeCamouflagedReserved(
            originalReserved: reserved,
            nonce: nonce
        )
        try file.writeUInt32(camouflagedReserved, at: 28)

        let details = [
            "Encrypted mach_header_64 field COPY into \(ArmorABI.dataSegmentName).\(ArmorABI.Sections.headerBackup) (64 bytes); the 6 fields remain plaintext in the file header (only reserved is camouflaged)",
            "Wrote camouflaged reserved=0x\(String(camouflagedReserved, radix: 16)) into header.reserved (legacy marker 0x\(String(Self.legacyHeaderMagic, radix: 16)) no longer emitted; still accepted at runtime for old binaries)",
            "Header fields: magic=0x\(String(magic, radix: 16)), filetype=0x\(String(filetype, radix: 16)), ncmds=\(ncmds), sizeofcmds=\(sizeofcmds), flags=0x\(String(flags, radix: 16)), reserved=0x\(String(reserved, radix: 16))",
            "Removed \(removedCodeSignatureBytes) bytes of stale LC_CODE_SIGNATURE commands before snapshot",
            "Derived header key from WhiteBox Domain 9 (headerEncryptionKey)"
        ]

        return PassResult(
            passName: name,
            itemsProcessed: 1,
            bytesModified: Self.backupSectionSize + 4,
            details: details
        )
    }

    // MARK: - Key Derivation

    /// Derive the header encryption key from WhiteBox Domain 9. Per-build
    /// diversity is already carried by the generated white-box tables; the
    /// PRF input stays all-zero to match the early C header-restoration path.
    private func deriveHeaderKey(whitebox: ArmorWhiteBoxBundle) -> Data {
        whitebox.prf(
            domain: .headerEncryptionKey,
            input: Data(repeating: 0, count: ArmorABI.hashSize)
        )
    }

    // MARK: - Helpers (mirrors DataSegmentEncryptor patterns)

    private func makeKeystream(key: Data, keyID: UInt32, nonce: Data, length: Int) -> Data {
        var seed = Data()
        seed.append(key)
        appendUInt32LE(keyID, to: &seed)
        seed.append(nonce)

        var block = sha256(seed)
        var output = Data()
        output.reserveCapacity(length)

        while output.count < length {
            let remaining = length - output.count
            output.append(block.prefix(remaining))
            if output.count < length {
                block = sha256(block)
            }
        }
        return output
    }

    private func xor(_ lhs: Data, _ rhs: Data) -> Data {
        Data(zip(lhs, rhs).map(^))
    }

    private func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// HeaderEncryptor uses an 8-byte nonce (matches the fixed 64-byte backup layout
    /// nonce[8] | encrypted[24] | cprisk_mac_tag[32], and makeCamouflagedReserved's n0/n1 split).
    /// This is a FROZEN exception: do NOT “unify” it to `ArmorABI.nonceSize`
    /// (16). Widening the nonce would change the published 64-byte backup
    /// layout and the camouflage split the runtime parser expects.
    private static let nonceSize = 8

    private func generateNonce() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: Self.nonceSize)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw MachOError.invalidData("SecRandomCopyBytes failed: \(status)")
        }
        return Data(bytes)
    }

    private func appendUInt32LE(_ value: UInt32, to data: inout Data) {
        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
    }

    private func makeCamouflagedReserved(originalReserved: UInt32, nonce: Data) -> UInt32 {
        precondition(nonce.count == HeaderEncryptorPass.nonceSize, "Header nonce must be 8 bytes")

        let n0 = UInt32(nonce[0])
            | (UInt32(nonce[1]) << 8)
            | (UInt32(nonce[2]) << 16)
            | (UInt32(nonce[3]) << 24)
        let n1 = UInt32(nonce[4])
            | (UInt32(nonce[5]) << 8)
            | (UInt32(nonce[6]) << 16)
            | (UInt32(nonce[7]) << 24)

        let rotated = (n1 << 7) | (n1 >> 25)
        var camouflaged = originalReserved ^ n0 ^ rotated ^ 0xA5C3_1F27
        if camouflaged == originalReserved || camouflaged == Self.legacyHeaderMagic {
            camouflaged ^= 0x0101_0101
        }
        return camouflaged
    }
}
