import CryptoKit
import Foundation
import MachOKit
import XCTest

final class DataEncryptionTests: XCTestCase {
    // MARK: - Helpers

    private func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            UInt32(littleEndian: $0.load(as: UInt32.self))
        }
    }

    private func readLE64(_ data: Data, at offset: Int) -> UInt64 {
        data.subdata(in: offset..<(offset + 8)).withUnsafeBytes {
            UInt64(littleEndian: $0.load(as: UInt64.self))
        }
    }

    private func readFixedString(_ data: Data, at offset: Int, length: Int) -> String {
        let slice = data.subdata(in: offset..<(offset + length))
        return String(bytes: slice.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
    }

    private func stableKeyID(segment: String, section: String) -> UInt32 {
        let bytes = Array("\(segment).\(section)".utf8)
        var hash: UInt32 = 2166136261
        for byte in bytes {
            hash ^= UInt32(byte)
            hash &*= 16777619
        }
        return hash
    }

    private func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    private func makeKeystream(key: Data, keyID: UInt32, length: Int) -> Data {
        var seed = Data()
        seed.append(key)
        var le = keyID.littleEndian
        withUnsafeBytes(of: &le) { seed.append(contentsOf: $0) }

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

    // MARK: - Multi-Entry Serialization

    func testMultiEntryLoaderDescriptorSerialization() {
        let count: UInt32 = 3
        let hashes = (0..<3).map { i in Data(repeating: UInt8(0xAA + i), count: ArmorABI.hashSize) }
        let sections: [(String, String, UInt32, UInt64, UInt64)] = [
            ("__DATA", "__const",        100, 0x1000, 64),
            ("__DATA", "__cfstring",     200, 0x2000, 128),
            ("__DATA", "__swift5_mpenum", 300, 0x3000, 256),
        ]

        var payload = ArmorABI.Loader.Header(count: count).serialized()
        for (i, sec) in sections.enumerated() {
            payload.append(
                ArmorABI.Loader.Entry(
                    segmentName: sec.0,
                    sectionName: sec.1,
                    keyID: sec.2,
                    vmAddress: sec.3,
                    size: sec.4,
                    contentHash: hashes[i]
                ).serialized()
            )
        }

        let expectedSize = ArmorABI.Loader.headerSize + Int(count) * ArmorABI.Loader.entrySize
        XCTAssertEqual(payload.count, expectedSize)

        XCTAssertEqual(readLE32(payload, at: 0), ArmorABI.Loader.magic)
        XCTAssertEqual(readLE32(payload, at: 4), ArmorABI.version)
        XCTAssertEqual(readLE32(payload, at: 8), count)

        for (i, sec) in sections.enumerated() {
            let base = ArmorABI.Loader.headerSize + i * ArmorABI.Loader.entrySize
            XCTAssertEqual(readFixedString(payload, at: base, length: 16), sec.0)
            XCTAssertEqual(readFixedString(payload, at: base + 16, length: 16), sec.1)
            XCTAssertEqual(readLE32(payload, at: base + 32), sec.2)
            XCTAssertEqual(readLE32(payload, at: base + 36), 0, "flags should be 0")
            XCTAssertEqual(readLE64(payload, at: base + 40), sec.3)
            XCTAssertEqual(readLE64(payload, at: base + 48), sec.4)
            XCTAssertEqual(payload.subdata(in: (base + 56)..<(base + 88)), hashes[i])
        }
    }

    func testMultiEntryLoaderDescriptorDeserialization() {
        let entries: [(seg: String, sec: String, keyID: UInt32, addr: UInt64, sz: UInt64)] = [
            ("__DATA", "__const",        0x11111111, 0x4000, 32),
            ("__DATA", "__cfstring",     0x22222222, 0x5000, 48),
            ("__DATA", "__swift5_fieldmd", 0x33333333, 0x6000, 16),
            ("__DATA", "__swift5_mpenum", 0x44444444, 0x7000, 80),
        ]
        let count = UInt32(entries.count)

        var payload = ArmorABI.Loader.Header(count: count).serialized()
        let hashes = entries.map { e in
            Data(SHA256.hash(data: Data("\(e.seg).\(e.sec)".utf8)))
        }
        for (i, e) in entries.enumerated() {
            payload.append(
                ArmorABI.Loader.Entry(
                    segmentName: e.seg, sectionName: e.sec,
                    keyID: e.keyID, vmAddress: e.addr,
                    size: e.sz, contentHash: hashes[i]
                ).serialized()
            )
        }

        XCTAssertEqual(readLE32(payload, at: 8), count)

        for (i, e) in entries.enumerated() {
            let base = ArmorABI.Loader.headerSize + i * ArmorABI.Loader.entrySize
            XCTAssertEqual(readFixedString(payload, at: base, length: 16), e.seg)
            XCTAssertEqual(readFixedString(payload, at: base + 16, length: 16), e.sec)
            XCTAssertEqual(readLE32(payload, at: base + 32), e.keyID)
            XCTAssertEqual(readLE64(payload, at: base + 40), e.addr)
            XCTAssertEqual(readLE64(payload, at: base + 48), e.sz)
            XCTAssertEqual(payload.subdata(in: (base + 56)..<(base + 88)), hashes[i])
        }
    }

    // MARK: - Whitelist / Blacklist

    func testEncryptableWhitelist() {
        let allowed = ["__const", "__cfstring", "__swift5_fieldmd", "__swift5_assocty"]
        for name in allowed {
            XCTAssertTrue(
                ArmorABI.DataEncryption.isEncryptable(name),
                "\(name) should be encryptable"
            )
        }
        XCTAssertTrue(
            ArmorABI.DataEncryption.isEncryptable(ArmorABI.Sections.protectedBlob),
            "protected blob should be encryptable"
        )
    }

    func testBlacklistedSectionsAreRejected() {
        let forbidden = [
            "__objc_data", "__objc_const",
            "__la_symbol_ptr", "__nl_symbol_ptr",
            "__got", "__mod_init_func",
            "__objc_classlist", "__objc_catlist", "__objc_protolist",
        ]
        for name in forbidden {
            XCTAssertFalse(
                ArmorABI.DataEncryption.isEncryptable(name),
                "\(name) must NOT be encryptable"
            )
        }
    }

    func testArmorCustomSectionsAreBlacklisted() {
        let customSections = [
            ArmorABI.Sections.stringTable,
            ArmorABI.Sections.loader,
            ArmorABI.Sections.anchorA,
            ArmorABI.Sections.anchorB,
            ArmorABI.Sections.anchorC,
            ArmorABI.Sections.anchorD,
            ArmorABI.Sections.fullAnchorHash,
        ]
        for name in customSections {
            XCTAssertFalse(
                ArmorABI.DataEncryption.isEncryptable(name),
                "ArmorABI section \(name) must NOT be encryptable"
            )
        }
    }

    func testUnknownSectionIsNotEncryptable() {
        XCTAssertFalse(ArmorABI.DataEncryption.isEncryptable("__bss"))
        XCTAssertFalse(ArmorABI.DataEncryption.isEncryptable("__common"))
        XCTAssertFalse(ArmorABI.DataEncryption.isEncryptable("__random"))
    }

    // MARK: - Encryption Round-Trip

    func testXorEncryptionDecryptionRoundTrip() {
        let key = Data((0..<32).map { UInt8($0) })
        let plaintext = Data("CloudPhoneRiskKit SDK Protected".utf8)
        let keyID: UInt32 = stableKeyID(segment: "__DATA", section: "__const")

        let keystream = makeKeystream(key: key, keyID: keyID, length: plaintext.count)
        let encrypted = Data(zip(plaintext, keystream).map(^))

        XCTAssertNotEqual(encrypted, plaintext, "encrypted should differ from plaintext")

        let decrypted = Data(zip(encrypted, keystream).map(^))
        XCTAssertEqual(decrypted, plaintext, "decrypting must recover original plaintext")
    }

    func testMultiSectionRoundTripWithDistinctKeys() {
        let key = sha256(Data("test-root-key".utf8))
        let sections: [(String, String, Data)] = [
            ("__DATA", "__const", Data(repeating: 0x42, count: 64)),
            ("__DATA", "__cfstring", Data((0..<128).map { UInt8($0 & 0xFF) })),
            ("__DATA", "__swift5_mpenum", Data(repeating: 0xFF, count: 80)),
        ]

        var keyIDs = [UInt32]()
        var encrypted = [Data]()

        for (seg, sec, plaintext) in sections {
            let kid = stableKeyID(segment: seg, section: sec)
            keyIDs.append(kid)
            let ks = makeKeystream(key: key, keyID: kid, length: plaintext.count)
            encrypted.append(Data(zip(plaintext, ks).map(^)))
        }

        let uniqueKeyIDs = Set(keyIDs)
        XCTAssertEqual(uniqueKeyIDs.count, sections.count, "each section must have a distinct keyID")

        for (i, (seg, sec, plaintext)) in sections.enumerated() {
            let kid = stableKeyID(segment: seg, section: sec)
            let ks = makeKeystream(key: key, keyID: kid, length: encrypted[i].count)
            let decrypted = Data(zip(encrypted[i], ks).map(^))
            XCTAssertEqual(decrypted, plaintext, "round-trip failed for \(seg).\(sec)")

            let hash = sha256(decrypted)
            XCTAssertEqual(hash, sha256(plaintext), "content hash mismatch for \(seg).\(sec)")
        }
    }

    func testContentHashValidatesIntegrity() {
        let key = Data(repeating: 0xAB, count: 32)
        let plaintext = Data("integrity-check-payload".utf8)
        let keyID: UInt32 = 0xDEADBEEF

        let expectedHash = sha256(plaintext)
        let ks = makeKeystream(key: key, keyID: keyID, length: plaintext.count)
        let ciphertext = Data(zip(plaintext, ks).map(^))

        let decrypted = Data(zip(ciphertext, ks).map(^))
        XCTAssertEqual(sha256(decrypted), expectedHash)

        var tampered = ciphertext
        tampered[0] ^= 0xFF
        let badDecrypt = Data(zip(tampered, ks).map(^))
        XCTAssertNotEqual(sha256(badDecrypt), expectedHash, "tampered data must fail hash check")
    }

    // MARK: - Zero-Count / Empty Edge Cases

    func testEmptyPlaintextRoundTrip() {
        let key = Data(repeating: 0x42, count: 32)
        let plaintext = Data()
        let keyID: UInt32 = stableKeyID(segment: "__DATA", section: "__const")

        let keystream = makeKeystream(key: key, keyID: keyID, length: plaintext.count)
        let encrypted = Data(zip(plaintext, keystream).map(^))

        XCTAssertEqual(encrypted.count, 0, "empty plaintext should produce empty ciphertext")
        let decrypted = Data(zip(encrypted, keystream).map(^))
        XCTAssertEqual(decrypted, plaintext, "empty round-trip must preserve empty")
    }

    func testZeroCountLoaderDescriptor() {
        let payload = ArmorABI.Loader.Header(count: 0).serialized()
        XCTAssertEqual(payload.count, ArmorABI.Loader.headerSize)
        XCTAssertEqual(readLE32(payload, at: 0), ArmorABI.Loader.magic)
        XCTAssertEqual(readLE32(payload, at: 8), 0)
    }
}
