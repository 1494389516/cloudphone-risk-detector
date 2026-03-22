import CryptoKit
import Foundation
import MachOKit

/// Pass 3.5 / Pass 11: Encrypt mach_header_64 critical fields and store them
/// in a dedicated `__DATA` `ArmorABI.Sections.headerBackup` section.  At runtime, CRiskCore
/// reads the backup section, verifies the HMAC, decrypts the fields via XOR
/// keystream, and restores the header before dyld finishes processing.
///
/// Instead of zeroing the header (which leaves obvious forensic markers), we
/// encrypt the fields and write a per-binary camouflage value into
/// mach_header_64.reserved. Runtime restoration still supports the legacy
/// fixed marker (`0x43504248`, "CPBH") for backward compatibility.
///
/// Layout of the backup section (64 bytes total):
///   nonce[8] | encrypted_fields[24] | hmac_tag[32]
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

    /// Size of the backup section payload: nonce(8) + encrypted(24) + HMAC(32).
    public static let backupSectionSize = 64

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        guard config.encryptionKey != nil else {
            throw MachOError.invalidData("HeaderEncryptorPass requires an encryption key")
        }

        // Build the WhiteBox bundle and derive the header encryption key.
        let whitebox = ArmorWhiteBox.build(rootKey: config.encryptionKey)
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

        // --- Compute HMAC-SHA256(key, nonce || encrypted_fields) ---
        var hmacMessage = nonce
        hmacMessage.append(encryptedFields)
        let hmacTag = ArmorABI.hmacSHA256(key: headerKey, message: hmacMessage)

        // --- Assemble the 64-byte backup payload ---
        var backupPayload = Data()
        backupPayload.append(nonce)        // 8 bytes
        backupPayload.append(encryptedFields) // 24 bytes
        backupPayload.append(hmacTag)      // 32 bytes
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
        // original reserved field).
        let camouflagedReserved = makeCamouflagedReserved(
            originalReserved: reserved,
            nonce: nonce
        )
        try file.writeUInt32(camouflagedReserved, at: 28)

        let details = [
            "Encrypted mach_header_64 fields into \(ArmorABI.dataSegmentName).\(ArmorABI.Sections.headerBackup) (64 bytes)",
            "Wrote camouflaged reserved=0x\(String(camouflagedReserved, radix: 16)) into header.reserved (legacy marker 0x\(String(Self.legacyHeaderMagic, radix: 16)) still supported at runtime)",
            "Header fields: magic=0x\(String(magic, radix: 16)), filetype=0x\(String(filetype, radix: 16)), ncmds=\(ncmds), sizeofcmds=\(sizeofcmds), flags=0x\(String(flags, radix: 16)), reserved=0x\(String(reserved, radix: 16))",
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

    /// Derive the header encryption key from WhiteBox Domain 9.
    /// We feed a fixed domain-9 input through the white-box PRF and use
    /// the resulting 32-byte output as the symmetric key.
    private func deriveHeaderKey(whitebox: ArmorWhiteBoxBundle) -> Data {
        // Use a fixed all-zero seed for Domain 9 derivation — the WhiteBox
        // PRF output is seeded purely by the domain key (which itself derives
        // from the root key).  This gives us a deterministic per-binary key
        // without needing any runtime input.
        let seed = Data(repeating: 0, count: 32)
        return whitebox.prf(domain: .headerEncryptionKey, input: seed)
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

    private func generateNonce() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: ArmorABI.nonceSize)
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
        precondition(nonce.count == ArmorABI.nonceSize, "Header nonce must be 8 bytes")

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
