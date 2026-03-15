import CryptoKit
import Foundation
import IntegrityAnchor
import MachOKit
import StringEncryptor
import XCTest

// MARK: - KDF 全链路测试

/// 验证壳工具链从 rootKey → stringKey → anchor → loaderKey 的完整密钥派生链路。
/// 所有密钥派生逻辑在测试中独立重新实现，不依赖 Pass 的 private 函数。
final class KDFChainTests: XCTestCase {

    // MARK: - 固定测试常量

    static let testRootKey = Data(repeating: 0xAB, count: 32)
    static let pass1Salt = "cprisk.pass1.key.v1"
    static let pass3Salt = "cprisk.pass3.key.v1"
    static let pass4MaskSalt = "cprisk.pass4.mask.v1"
    static let bootstrapStringID: UInt32 = 1
    static let bootstrapValue = "cprisk-bootstrap-v1"

    // MARK: - Test 1: Pass 1 String Key Derivation

    func testPass1KeyDerivation() {
        let rootKey = Self.testRootKey
        let normalizedKey = Self.normalizedRootKey(rootKey)

        var seed = Data(Self.pass1Salt.utf8)
        seed.append(normalizedKey)
        let expectedStringKey = Self.sha256(seed)

        XCTAssertEqual(expectedStringKey.count, 32, "stringKey must be 32 bytes")

        let expectedFromHelper = Self.deriveStringKey(rootKey: rootKey)
        XCTAssertEqual(expectedStringKey, expectedFromHelper,
                       "manual calculation must match helper function")

        let nilRootKey = Self.deriveStringKey(rootKey: nil)
        let zeroRootKey = Self.deriveStringKey(rootKey: Data(repeating: 0, count: 32))
        XCTAssertEqual(nilRootKey, zeroRootKey,
                       "nil rootKey must produce same result as all-zero rootKey")
        XCTAssertNotEqual(expectedStringKey, nilRootKey,
                          "non-zero rootKey must differ from zero rootKey")
    }

    // MARK: - Test 2: Pass 1 Keystream Generation

    func testPass1KeystreamGeneration() {
        let stringKey = Self.deriveStringKey(rootKey: Self.testRootKey)
        let stringID: UInt32 = 1

        let keystream = Self.makeKeystream(key: stringKey, stringID: stringID, length: 64)
        XCTAssertEqual(keystream.count, 64)

        var seedForBlock0 = Data()
        seedForBlock0.append(stringKey)
        var sid = stringID.littleEndian
        withUnsafeBytes(of: &sid) { seedForBlock0.append(contentsOf: $0) }
        let block0 = Self.sha256(seedForBlock0)

        XCTAssertEqual(keystream.prefix(32), block0,
                       "first 32 bytes of keystream must be SHA256(key + LE32(stringID))")

        let block1 = Self.sha256(block0)
        XCTAssertEqual(keystream.suffix(32), block1,
                       "next 32 bytes must be SHA256(previous_block)")
    }

    func testPass1KeystreamDeterminism() {
        let key = Self.deriveStringKey(rootKey: Self.testRootKey)

        let ks1 = Self.makeKeystream(key: key, stringID: 42, length: 100)
        let ks2 = Self.makeKeystream(key: key, stringID: 42, length: 100)
        XCTAssertEqual(ks1, ks2, "same inputs must produce same keystream")

        let ks3 = Self.makeKeystream(key: key, stringID: 43, length: 100)
        XCTAssertNotEqual(ks1, ks3, "different stringID must produce different keystream")
    }

    func testPass1KeystreamPartialBlock() {
        let key = Self.deriveStringKey(rootKey: Self.testRootKey)
        let fullKs = Self.makeKeystream(key: key, stringID: 1, length: 48)
        let shortKs = Self.makeKeystream(key: key, stringID: 1, length: 48)

        XCTAssertEqual(fullKs, shortKs)
        XCTAssertEqual(fullKs.count, 48)

        let longerKs = Self.makeKeystream(key: key, stringID: 1, length: 64)
        XCTAssertEqual(fullKs, longerKs.prefix(48),
                       "shorter keystream must be prefix of longer one")
    }

    // MARK: - Test 3: Pass 4 Anchor Split

    func testPass4AnchorSplit() {
        let textHash = Self.sha256(Data("test-text-content".utf8))
        XCTAssertEqual(textHash.count, 32)

        let lanes = ArmorABI.Integrity.splitAnchorLanes(for: textHash)
        XCTAssertEqual(lanes.count, 4, "must split into 4 lanes")

        for (i, lane) in lanes.enumerated() {
            XCTAssertEqual(lane.count, 8, "lane \(i) must be 8 bytes")
        }

        var reassembled = Data()
        for lane in lanes { reassembled.append(lane) }
        XCTAssertEqual(reassembled, textHash,
                       "4 lanes concatenated must reconstruct original textHash")
    }

    func testPass4AnchorSplitBoundary() {
        let allZero = Data(repeating: 0, count: 32)
        let lanes = ArmorABI.Integrity.splitAnchorLanes(for: allZero)
        for lane in lanes {
            XCTAssertEqual(lane, Data(repeating: 0, count: 8))
        }

        let allFF = Data(repeating: 0xFF, count: 32)
        let lanesFF = ArmorABI.Integrity.splitAnchorLanes(for: allFF)
        for lane in lanesFF {
            XCTAssertEqual(lane, Data(repeating: 0xFF, count: 8))
        }
    }

    // MARK: - Test 4: Pass 4 Masked Full Hash

    func testPass4MaskedFullHash() {
        let textHash = Self.sha256(Data("test-text-content".utf8))
        let mask = Self.sha256(Data(Self.pass4MaskSalt.utf8) + textHash)

        let section = ArmorABI.Integrity.maskedFullHashSection(mask: mask, fullHash: textHash)
        XCTAssertEqual(section.count, 64, "section must be 64 bytes (mask + maskedHash)")

        let storedMask = section.prefix(32)
        let maskedHash = section.suffix(32)

        XCTAssertEqual(storedMask, mask, "first 32 bytes must be the mask")

        var recovered = Data(count: 32)
        for i in 0..<32 {
            recovered[i] = storedMask[i] ^ maskedHash[maskedHash.startIndex + i]
        }
        XCTAssertEqual(recovered, textHash,
                       "fullHash must be recoverable via mask ^ maskedHash")
    }

    func testPass4MaskedFullHashWithIdenticalInputs() {
        let hash = Self.sha256(Data("identical".utf8))
        let mask = Self.sha256(Data(Self.pass4MaskSalt.utf8) + hash)

        let section1 = ArmorABI.Integrity.maskedFullHashSection(mask: mask, fullHash: hash)
        let section2 = ArmorABI.Integrity.maskedFullHashSection(mask: mask, fullHash: hash)
        XCTAssertEqual(section1, section2, "deterministic: same inputs → same output")
    }

    // MARK: - Test 5: Pass 3 Loader Key Derivation

    func testPass3LoaderKeyDerivation() {
        let rootKey = Self.testRootKey
        let normalizedKey = Self.normalizedRootKey(rootKey)
        let fullAnchorHash = Self.sha256(Data("test-anchor-content".utf8))
        let integrityHash = Self.sha256(fullAnchorHash + fullAnchorHash + fullAnchorHash)
        let stringAccumulator = Self.bootstrapAccumulator()

        let loaderKey = Self.deriveLoaderKey(
            rootKey: rootKey,
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash,
            stringAccumulator: stringAccumulator
        )
        XCTAssertEqual(loaderKey.count, 32, "loaderKey must be 32 bytes")

        var expectedSeed = Data(Self.pass3Salt.utf8)
        expectedSeed.append(normalizedKey)
        expectedSeed.append(fullAnchorHash)
        expectedSeed.append(integrityHash)
        Self.appendUInt64(stringAccumulator, to: &expectedSeed)
        let expectedKey = Self.sha256(expectedSeed)

        XCTAssertEqual(loaderKey, expectedKey,
                       "loaderKey must match manual SHA256 calculation")
    }

    func testPass3LoaderKeyDependsOnAnchor() {
        let rootKey = Self.testRootKey
        let stringAcc = Self.bootstrapAccumulator()

        let anchor1 = Self.sha256(Data("anchor-content-1".utf8))
        let integrity1 = Self.sha256(anchor1 + anchor1 + anchor1)
        let key1 = Self.deriveLoaderKey(
            rootKey: rootKey,
            fullAnchorHash: anchor1,
            integrityHash: integrity1,
            stringAccumulator: stringAcc
        )

        let anchor2 = Self.sha256(Data("anchor-content-2".utf8))
        let integrity2 = Self.sha256(anchor2 + anchor2 + anchor2)
        let key2 = Self.deriveLoaderKey(
            rootKey: rootKey,
            fullAnchorHash: anchor2,
            integrityHash: integrity2,
            stringAccumulator: stringAcc
        )

        XCTAssertNotEqual(key1, key2,
                          "different anchor hash must produce different loader key")
    }

    func testPass3IntegrityHashIsTripleConcatenation() {
        let fullAnchorHash = Self.sha256(Data("test-content".utf8))
        let integrityHash = Self.sha256(fullAnchorHash + fullAnchorHash + fullAnchorHash)

        var triple = Data()
        triple.append(fullAnchorHash)
        triple.append(fullAnchorHash)
        triple.append(fullAnchorHash)
        XCTAssertEqual(triple.count, 96)
        XCTAssertEqual(integrityHash, Self.sha256(triple))
    }

    // MARK: - Test 6: Full KDF Chain Consistency

    func testFullKDFChainConsistency() throws {
        let fixtureData = Self.makeKDFTestFixture()
        let url = Self.temporaryURL(named: "kdf_chain")
        try fixtureData.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let rootKey = Self.testRootKey
        let config = PassConfig(encryptionKey: rootKey)
        let file = try MachOFile(url: url)

        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        let textContent = try textSection.readContent(from: file.data)
        let originalTextHash = Self.sha256(textContent)

        let anchorPass = IntegrityAnchorPass()
        _ = try anchorPass.execute(on: file, config: config)

        let fullHashSection = try XCTUnwrap(
            try file.section(
                segment: ArmorABI.dataSegmentName,
                section: ArmorABI.Integrity.fullHashSectionName
            )
        )
        let fullHashContent = try fullHashSection.readContent(from: file.data)
        XCTAssertEqual(fullHashContent.count, 64)
        let mask = fullHashContent.prefix(32)
        let maskedHash = fullHashContent.suffix(32)
        let recoveredFullHash = Data(zip(mask, maskedHash).map(^))
        XCTAssertEqual(recoveredFullHash, originalTextHash,
                       "recovered anchor hash must equal SHA256(__TEXT.__text)")

        let expectedMask = Self.sha256(Data(Self.pass4MaskSalt.utf8) + originalTextHash)
        XCTAssertEqual(Data(mask), expectedMask, "mask must match SHA256(salt + textHash)")

        for (i, sectionName) in ArmorABI.Integrity.splitSectionNames.enumerated() {
            let section = try XCTUnwrap(
                try file.section(segment: ArmorABI.dataSegmentName, section: sectionName)
            )
            let lane = try section.readContent(from: file.data)
            XCTAssertEqual(lane.prefix(8),
                           originalTextHash.subdata(in: (i * 8)..<((i + 1) * 8)),
                           "split lane \(i) must match textHash slice")
        }

        let stringPass = StringEncryptorPass()
        _ = try stringPass.execute(on: file, config: config)

        let stringKey = Self.deriveStringKey(rootKey: rootKey)
        let tableSection = try XCTUnwrap(
            try file.section(
                segment: ArmorABI.dataSegmentName,
                section: ArmorABI.StringTable.sectionName
            )
        )
        let tableContent = try tableSection.readContent(from: file.data)
        let entryCount = Int(Self.readLE32(tableContent, at: 8))
        XCTAssertGreaterThan(entryCount, 0)

        let indexBase = ArmorABI.StringTable.headerSize
        let dataBase = indexBase + entryCount * ArmorABI.StringTable.indexEntrySize
        let firstID = Self.readLE32(tableContent, at: indexBase)
        let firstOffset = Int(Self.readLE32(tableContent, at: indexBase + 4))
        let firstLength = Int(Self.readLE32(tableContent, at: indexBase + 8))
        let firstEncrypted = tableContent.subdata(
            in: (dataBase + firstOffset)..<(dataBase + firstOffset + firstLength)
        )
        let firstKeystream = Self.makeKeystream(key: stringKey, stringID: firstID, length: firstLength)
        let firstDecrypted = Data(zip(firstEncrypted, firstKeystream).map(^))
        XCTAssertNotNil(String(data: firstDecrypted, encoding: .utf8),
                        "first entry must decrypt to valid UTF-8")
    }

    func testFullKDFChainSensitivityToTextModification() throws {
        let rootKey = Self.testRootKey
        let config = PassConfig(encryptionKey: rootKey)

        let fixture1 = Self.makeKDFTestFixture()
        let url1 = Self.temporaryURL(named: "kdf_sensitivity_a")
        try fixture1.write(to: url1)
        defer { try? FileManager.default.removeItem(at: url1) }

        let file1 = try MachOFile(url: url1)
        let anchorPass1 = IntegrityAnchorPass()
        _ = try anchorPass1.execute(on: file1, config: config)
        let fh1 = try XCTUnwrap(
            try file1.section(
                segment: ArmorABI.dataSegmentName,
                section: ArmorABI.Integrity.fullHashSectionName
            )
        )
        let content1 = try fh1.readContent(from: file1.data)
        let hash1 = Data(zip(content1.prefix(32), content1.suffix(32)).map(^))

        var fixture2 = Self.makeKDFTestFixture()
        let tmpUrl = Self.temporaryURL(named: "kdf_tmp")
        try fixture2.write(to: tmpUrl)
        let tmpFile = try MachOFile(url: tmpUrl)
        let textSec = try XCTUnwrap(try tmpFile.section(segment: "__TEXT", section: "__text"))
        let textOffset = textSec.offset
        try? FileManager.default.removeItem(at: tmpUrl)
        fixture2[Int(textOffset)] ^= 0x01

        let url2 = Self.temporaryURL(named: "kdf_sensitivity_b")
        try fixture2.write(to: url2)
        defer { try? FileManager.default.removeItem(at: url2) }

        let file2 = try MachOFile(url: url2)
        let anchorPass2 = IntegrityAnchorPass()
        _ = try anchorPass2.execute(on: file2, config: config)
        let fh2 = try XCTUnwrap(
            try file2.section(
                segment: ArmorABI.dataSegmentName,
                section: ArmorABI.Integrity.fullHashSectionName
            )
        )
        let content2 = try fh2.readContent(from: file2.data)
        let hash2 = Data(zip(content2.prefix(32), content2.suffix(32)).map(^))

        XCTAssertNotEqual(hash1, hash2,
                          "modifying 1 byte of __TEXT.__text must change the anchor hash")

        let stringAcc = Self.bootstrapAccumulator()
        let integ1 = Self.sha256(hash1 + hash1 + hash1)
        let integ2 = Self.sha256(hash2 + hash2 + hash2)
        let lk1 = Self.deriveLoaderKey(rootKey: rootKey, fullAnchorHash: hash1,
                                       integrityHash: integ1, stringAccumulator: stringAcc)
        let lk2 = Self.deriveLoaderKey(rootKey: rootKey, fullAnchorHash: hash2,
                                       integrityHash: integ2, stringAccumulator: stringAcc)
        XCTAssertNotEqual(lk1, lk2,
                          "different anchor hash must cascade to different loader key")
    }

    func testBootstrapAccumulatorCalculation() {
        let digest = Self.sha256(Data(Self.bootstrapValue.utf8))
        var value: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &value) { target in
            digest.prefix(MemoryLayout<UInt64>.size).copyBytes(to: target)
        }
        let expected = Self.rotl64(value, by: Int(Self.bootstrapStringID % 64))
        let actual = Self.bootstrapAccumulator()
        XCTAssertEqual(actual, expected,
                       "bootstrapAccumulator must match rotl64(SHA256(bootstrapValue)[0:8], 1)")
    }

    // MARK: - Helpers (replicating private Pass logic for testing)

    private static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    private static func normalizedRootKey(_ rootKey: Data?) -> Data {
        var key = Data(repeating: 0, count: ArmorABI.keySize)
        guard let rootKey else { return key }
        let prefix = rootKey.prefix(ArmorABI.keySize)
        key.replaceSubrange(0..<prefix.count, with: prefix)
        return key
    }

    private static func deriveStringKey(rootKey: Data?) -> Data {
        var seed = Data(pass1Salt.utf8)
        seed.append(normalizedRootKey(rootKey))
        return sha256(seed)
    }

    private static func makeKeystream(key: Data, stringID: UInt32, length: Int) -> Data {
        var seed = Data()
        seed.append(key)
        var sid = stringID.littleEndian
        withUnsafeBytes(of: &sid) { seed.append(contentsOf: $0) }

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

    private static func deriveLoaderKey(
        rootKey: Data?,
        fullAnchorHash: Data,
        integrityHash: Data,
        stringAccumulator: UInt64
    ) -> Data {
        var seed = Data(pass3Salt.utf8)
        seed.append(normalizedRootKey(rootKey))
        seed.append(fullAnchorHash)
        seed.append(integrityHash)
        appendUInt64(stringAccumulator, to: &seed)
        return sha256(seed)
    }

    private static func bootstrapAccumulator() -> UInt64 {
        let digest = sha256(Data(bootstrapValue.utf8))
        var value: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &value) { target in
            digest.prefix(MemoryLayout<UInt64>.size).copyBytes(to: target)
        }
        return rotl64(value, by: Int(bootstrapStringID % 64))
    }

    private static func rotl64(_ value: UInt64, by amount: Int) -> UInt64 {
        guard amount != 0 else { return value }
        return (value << amount) | (value >> (64 - amount))
    }

    private static func appendUInt64(_ value: UInt64, to data: inout Data) {
        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
    }

    private static func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            UInt32(littleEndian: $0.load(as: UInt32.self))
        }
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
    }

    /// Mach-O fixture with __TEXT.__text + __TEXT.__cstring + __DATA segment.
    /// The __text section contains executable-like bytes so Pass 4 can hash them.
    /// Load commands area is generously padded (1024 bytes) to allow
    /// IntegrityAnchorPass to insert 5+ section headers (80 bytes each).
    static func makeKDFTestFixture() -> Data {
        let textCodeContent = Data([
            0xFD, 0x7B, 0xBF, 0xA9,  // stp x29, x30, [sp, #-0x10]!
            0xFD, 0x03, 0x00, 0x91,  // mov x29, sp
            0x00, 0x00, 0x80, 0xD2,  // mov x0, #0
            0xC0, 0x03, 0x5F, 0xD6,  // ret
            0xFD, 0x7B, 0xC1, 0xA8,  // ldp x29, x30, [sp], #0x10
            0xC0, 0x03, 0x5F, 0xD6,  // ret
            0x1F, 0x20, 0x03, 0xD5,  // nop
            0x1F, 0x20, 0x03, 0xD5,  // nop
        ])

        let cstrings: [String] = [
            "/usr/bin/bash",
            "frida-server",
            "test_func",
            "12345",
        ]
        var cstringData = Data()
        for s in cstrings {
            cstringData.append(contentsOf: s.utf8)
            cstringData.append(0)
        }

        let textSegCmdSize = 72 + 80 + 80  // seg header + __text section + __cstring section
        let dataSegCmdSize = 72 + 80       // seg header + __const section
        let sizeOfCmds = textSegCmdSize + dataSegCmdSize

        let textCodeOffset = 1024
        let cstringOffset = textCodeOffset + textCodeContent.count
        let textSegFileSize = 2048

        let dataSegOffset = 2048
        let dataSegSize = 2048
        let constSize = 8

        let fileSize = dataSegOffset + dataSegSize

        var data = Data()

        // mach_header_64
        data.appendLE32(0xFEEDFACF)
        data.appendLE32(0x0100000C)
        data.appendLE32(0)
        data.appendLE32(0x00000006)
        data.appendLE32(2)
        data.appendLE32(UInt32(sizeOfCmds))
        data.appendLE32(0)
        data.appendLE32(0)

        // __TEXT segment (72 bytes header + 2 sections × 80 bytes)
        data.appendLE32(0x19) // LC_SEGMENT_64
        data.appendLE32(UInt32(textSegCmdSize))
        data.appendFixedCString16("__TEXT")
        data.appendLE64(0x1000)
        data.appendLE64(UInt64(textSegFileSize))
        data.appendLE64(0)
        data.appendLE64(UInt64(textSegFileSize))
        data.appendLE32(5) // maxprot
        data.appendLE32(5) // initprot
        data.appendLE32(2) // nsects
        data.appendLE32(0)

        // __text section
        data.appendFixedCString16("__text")
        data.appendFixedCString16("__TEXT")
        data.appendLE64(0x1000 + UInt64(textCodeOffset))
        data.appendLE64(UInt64(textCodeContent.count))
        data.appendLE32(UInt32(textCodeOffset))
        data.appendLE32(2) // align
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0x80000400) // S_REGULAR | S_ATTR_PURE_INSTRUCTIONS
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)

        // __cstring section
        data.appendFixedCString16("__cstring")
        data.appendFixedCString16("__TEXT")
        data.appendLE64(0x1000 + UInt64(cstringOffset))
        data.appendLE64(UInt64(cstringData.count))
        data.appendLE32(UInt32(cstringOffset))
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0x02) // S_CSTRING_LITERALS
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)

        // __DATA segment (72 bytes header + 1 section × 80 bytes)
        data.appendLE32(0x19)
        data.appendLE32(UInt32(dataSegCmdSize))
        data.appendFixedCString16("__DATA")
        data.appendLE64(0x2000)
        data.appendLE64(UInt64(dataSegSize))
        data.appendLE64(UInt64(dataSegOffset))
        data.appendLE64(UInt64(dataSegSize))
        data.appendLE32(3) // maxprot
        data.appendLE32(3) // initprot
        data.appendLE32(1) // nsects
        data.appendLE32(0)

        // __const section
        data.appendFixedCString16("__const")
        data.appendFixedCString16("__DATA")
        data.appendLE64(0x2000)
        data.appendLE64(UInt64(constSize))
        data.appendLE32(UInt32(dataSegOffset))
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)

        // Pad to textCodeOffset, write __text content
        if data.count < textCodeOffset {
            data.append(Data(count: textCodeOffset - data.count))
        }
        data.append(textCodeContent)

        // Write __cstring content
        if data.count < cstringOffset {
            data.append(Data(count: cstringOffset - data.count))
        }
        data.append(cstringData)

        // Pad to __DATA segment, write __const content
        if data.count < dataSegOffset {
            data.append(Data(count: dataSegOffset - data.count))
        }
        data.append(Data([0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD]))

        // Pad to full file size
        if data.count < fileSize {
            data.append(Data(count: fileSize - data.count))
        }
        return data
    }
}

// MARK: - Data Helpers

private extension Data {
    mutating func appendLE32(_ value: UInt32) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 4))
    }

    mutating func appendLE64(_ value: UInt64) {
        var le = value.littleEndian
        append(Data(bytes: &le, count: 8))
    }

    mutating func appendFixedCString16(_ string: String) {
        var bytes = Array(string.utf8.prefix(16))
        while bytes.count < 16 { bytes.append(0) }
        append(contentsOf: bytes)
    }
}
