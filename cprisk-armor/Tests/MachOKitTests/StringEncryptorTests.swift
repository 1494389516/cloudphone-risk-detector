import CryptoKit
import Foundation
import MachOKit
import StringEncryptor
import XCTest

final class StringEncryptorTests: XCTestCase {

    // MARK: - 字符串分类：mustEncrypt（路径分隔符）

    func testClassifyPathStringsAreMustEncrypt() {
        XCTAssertEqual(StringClassifier.classify("/usr/bin/bash"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("/etc/passwd"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("/Applications/Cydia.app"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("/var/mobile"), .mustEncrypt)
    }

    // MARK: - 字符串分类：mustEncrypt（敏感关键词）

    func testClassifySensitiveKeywordsAreMustEncrypt() {
        XCTAssertEqual(StringClassifier.classify("frida-server"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("com.saurik.Cydia"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("MobileSubstrate"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("inject_dylib"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("DEBUG_MODE"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("ptrace"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("jailbreak_detected"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("ssh_connect"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("dpkg-query"), .mustEncrypt)
    }

    // MARK: - 字符串分类：mustEncrypt（大小写不敏感）

    func testClassifyCaseInsensitiveKeywords() {
        XCTAssertEqual(StringClassifier.classify("FRIDA"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("Cydia"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("HTTP_PROXY"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("SVC_CALL"), .mustEncrypt)
    }

    // MARK: - 字符串分类：shouldEncrypt

    func testClassifyNormalStringsAreShouldEncrypt() {
        XCTAssertEqual(StringClassifier.classify("Hello World"), .shouldEncrypt)
        XCTAssertEqual(StringClassifier.classify("test"), .shouldEncrypt)
        XCTAssertEqual(StringClassifier.classify("some_function_name"), .shouldEncrypt)
        XCTAssertEqual(StringClassifier.classify("CloudPhoneRiskKit"), .shouldEncrypt)
    }

    // MARK: - 字符串分类：边界长度

    func testClassifyBoundaryLength4IsShouldEncrypt() {
        XCTAssertEqual(StringClassifier.classify("test"), .shouldEncrypt)
        XCTAssertEqual(StringClassifier.classify("abcd"), .shouldEncrypt)
    }

    func testClassifyBoundaryLength256IsShouldEncrypt() {
        let str256 = String(repeating: "a", count: 256)
        XCTAssertEqual(StringClassifier.classify(str256), .shouldEncrypt)
    }

    func testClassifyLength257IsSkip() {
        let str257 = String(repeating: "a", count: 257)
        XCTAssertEqual(StringClassifier.classify(str257), .skip)
    }

    func testClassifyLength3IsSkip() {
        XCTAssertEqual(StringClassifier.classify("abc"), .skip)
    }

    // MARK: - 字符串分类：skip 类别

    func testClassifySingleCharIsSkip() {
        XCTAssertEqual(StringClassifier.classify("x"), .skip)
        XCTAssertEqual(StringClassifier.classify("A"), .skip)
        XCTAssertEqual(StringClassifier.classify("1"), .skip)
    }

    func testClassifyPureNumbersIsSkip() {
        XCTAssertEqual(StringClassifier.classify("12345"), .skip)
        XCTAssertEqual(StringClassifier.classify("00"), .skip)
        XCTAssertEqual(StringClassifier.classify("999999"), .skip)
    }

    func testClassifyObjCSelectorIsSkip() {
        XCTAssertEqual(StringClassifier.classify("init:"), .skip)
        XCTAssertEqual(StringClassifier.classify("setObject:forKey:"), .skip)
        XCTAssertEqual(StringClassifier.classify("performSelector:withObject:"), .skip)
    }

    func testClassifyEmptyStringIsSkip() {
        XCTAssertEqual(StringClassifier.classify(""), .skip)
    }

    // MARK: - 加密 String Table 格式验证

    func testStringTableHeaderFormatIsCorrect() throws {
        let fixture = Self.makeFixtureWithManyStrings()
        let url = Self.temporaryURL(named: "strtab_format")
        try fixture.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let pass = StringEncryptorPass()
        let config = PassConfig(encryptionKey: Data(repeating: 0x42, count: 32))
        let result = try pass.execute(on: file, config: config)

        // 1 bootstrap + 6 个非 skip 的 cstring = 7 条记录
        XCTAssertEqual(result.itemsProcessed, 7)

        let section = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.StringTable.sectionName)
        )
        let content = try section.readContent(from: file.data)
        XCTAssertGreaterThanOrEqual(content.count, ArmorABI.StringTable.headerSize)

        let magic = readLE32(content, at: 0)
        XCTAssertEqual(magic, ArmorABI.StringTable.magic)

        let version = readLE32(content, at: 4)
        XCTAssertEqual(version, ArmorABI.version)

        let count = readLE32(content, at: 8)
        XCTAssertEqual(count, UInt32(result.itemsProcessed))

        // 验证 index entries 的连续性
        let dataBase = ArmorABI.StringTable.headerSize + Int(count) * ArmorABI.StringTable.indexEntrySize
        for i in 0..<Int(count) {
            let entryOffset = ArmorABI.StringTable.headerSize + i * ArmorABI.StringTable.indexEntrySize
            let stringID = readLE32(content, at: entryOffset)
            XCTAssertGreaterThan(stringID, 0, "stringID should be positive")

            let dataOffset = readLE32(content, at: entryOffset + 4)
            let dataLength = readLE32(content, at: entryOffset + 8)
            XCTAssertTrue(
                dataBase + Int(dataOffset) + Int(dataLength) <= content.count,
                "Entry \(i) data region exceeds section bounds"
            )
        }
    }

    // MARK: - 加密→解密往返一致性

    func testEncryptDecryptRoundTrip() throws {
        let fixture = Self.makeFixtureWithManyStrings()
        let url = Self.temporaryURL(named: "roundtrip")
        try fixture.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let originalStrings = try file.findCStrings().map(\.value)

        let encryptionKey = Data(repeating: 0x42, count: 32)
        let pass = StringEncryptorPass()
        let config = PassConfig(encryptionKey: encryptionKey)
        _ = try pass.execute(on: file, config: config)

        let stringKey = Self.deriveStringKey(rootKey: encryptionKey)

        let section = try XCTUnwrap(
            try file.section(segment: "__DATA", section: ArmorABI.StringTable.sectionName)
        )
        let content = try section.readContent(from: file.data)

        let count = Int(readLE32(content, at: 8))
        let indexBase = ArmorABI.StringTable.headerSize
        let dataBase = indexBase + count * ArmorABI.StringTable.indexEntrySize

        for i in 0..<count {
            let entryOffset = indexBase + i * ArmorABI.StringTable.indexEntrySize
            let stringID = readLE32(content, at: entryOffset)
            let dataOffset = Int(readLE32(content, at: entryOffset + 4))
            let dataLength = Int(readLE32(content, at: entryOffset + 8))
            let nonce = content.subdata(in: (entryOffset + 12)..<(entryOffset + 20))

            let encrypted = content.subdata(
                in: (dataBase + dataOffset)..<(dataBase + dataOffset + dataLength)
            )
            let keystream = Self.makeKeystream(key: stringKey, stringID: stringID, nonce: nonce, length: dataLength)
            let decrypted = Data(zip(encrypted, keystream).map(^))
            let decryptedString = String(data: decrypted, encoding: .utf8)
            XCTAssertNotNil(decryptedString, "Failed to decode entry \(i)")

            if stringID == 1 {
                XCTAssertEqual(decryptedString, "cprisk-bootstrap-v1")
            } else {
                XCTAssertTrue(
                    originalStrings.contains(decryptedString!),
                    "Decrypted '\(decryptedString!)' not found in original strings"
                )
            }
        }
    }

    // MARK: - 零填充验证

    func testOriginalCStringsAreZeroFilled() throws {
        let fixture = Self.makeFixtureWithManyStrings()
        let url = Self.temporaryURL(named: "zerofill")
        try fixture.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let originalStrings = try file.findCStrings()

        // 记录应该被加密（非 skip）的字符串的偏移量和长度
        let encryptable = originalStrings.filter {
            StringClassifier.classify($0.value) != .skip
        }
        XCTAssertFalse(encryptable.isEmpty, "Fixture should contain encryptable strings")

        let pass = StringEncryptorPass()
        let config = PassConfig(encryptionKey: Data(repeating: 0x42, count: 32))
        _ = try pass.execute(on: file, config: config)

        // 验证被加密的字符串在原始位置已被零填充
        for entry in encryptable {
            let start = Int(entry.offset)
            let length = entry.value.utf8.count
            for byteIdx in start..<(start + length) {
                XCTAssertEqual(
                    file.data[byteIdx], 0,
                    "Expected zero at offset \(byteIdx) for string '\(entry.value)'"
                )
            }
        }
    }

    // MARK: - skip 类别字符串不被加密

    func testSkippedStringsRemainInCString() throws {
        let fixture = Self.makeFixtureWithManyStrings()
        let url = Self.temporaryURL(named: "skip_check")
        try fixture.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let originalStrings = try file.findCStrings()

        // 记录应该被 skip 的字符串的偏移量
        let skipped = originalStrings.filter {
            StringClassifier.classify($0.value) == .skip
        }
        XCTAssertFalse(skipped.isEmpty, "Fixture should contain skippable strings")

        let pass = StringEncryptorPass()
        let config = PassConfig(encryptionKey: Data(repeating: 0x42, count: 32))
        _ = try pass.execute(on: file, config: config)

        // 被 skip 的字符串应仍保持原始内容（未零填充）
        for entry in skipped {
            let start = Int(entry.offset)
            let originalBytes = Array(entry.value.utf8)
            for (i, expectedByte) in originalBytes.enumerated() {
                XCTAssertEqual(
                    file.data[start + i], expectedByte,
                    "Skipped string '\(entry.value)' should not be zeroed at offset \(start + i)"
                )
            }
        }
    }

    // MARK: - 辅助方法

    private func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            UInt32(littleEndian: $0.load(as: UInt32.self))
        }
    }

    /// 密钥派生（与 StringEncryptorPass 内部逻辑保持一致）
    private static func deriveStringKey(rootKey: Data) -> Data {
        var seed = Data("cprisk.pass1.key.v1".utf8)
        var key = Data(repeating: 0, count: 32)
        let prefix = rootKey.prefix(32)
        key.replaceSubrange(0..<prefix.count, with: prefix)
        seed.append(key)
        return Data(SHA256.hash(data: seed))
    }

    private static func makeKeystream(key: Data, stringID: UInt32, nonce: Data = Data(), length: Int) -> Data {
        var seed = Data()
        seed.append(key)
        var sid = stringID.littleEndian
        withUnsafeBytes(of: &sid) { seed.append(contentsOf: $0) }
        seed.append(nonce)

        var block = Data(SHA256.hash(data: seed))
        var output = Data()
        output.reserveCapacity(length)

        while output.count < length {
            let remaining = length - output.count
            output.append(block.prefix(remaining))
            if output.count < length {
                block = Data(SHA256.hash(data: block))
            }
        }
        return output
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
    }

    /// 构建包含多种类型字符串的 Mach-O fixture
    ///
    /// __cstring 包含 9 条字符串：
    ///  - 3 个 mustEncrypt（路径/关键词）
    ///  - 3 个 shouldEncrypt（普通可打印）
    ///  - 3 个 skip（ObjC selector/纯数字/单字符）
    static func makeFixtureWithManyStrings() -> Data {
        let strings: [String] = [
            "/usr/bin/bash",       // mustEncrypt (路径)
            "frida-server",        // mustEncrypt (关键词)
            "Hello World",         // shouldEncrypt
            "test_func",           // shouldEncrypt
            "init:",               // skip (ObjC selector)
            "12345",               // skip (纯数字)
            "x",                   // skip (单字符)
            "/etc/passwd",         // mustEncrypt (路径+关键词)
            "normal_string",       // shouldEncrypt
        ]

        var cstringData = Data()
        for str in strings {
            cstringData.append(contentsOf: str.utf8)
            cstringData.append(0)
        }
        let cstringSize = UInt64(cstringData.count)

        let cstringOffset = 512
        let dataSegmentOffset = 768
        let dataSegmentSize = 256
        let fileSize = dataSegmentOffset + dataSegmentSize

        var data = Data()

        // mach_header_64 (32 bytes)
        data.appendLE(UInt32(0xFEEDFACF))
        data.appendLE(UInt32(0x0100000C))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x00000006))
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(304))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __TEXT segment_command_64 + 1 section = 152 bytes
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(152))
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(dataSegmentOffset))
        data.appendLE(UInt64(0))
        data.appendLE(UInt64(dataSegmentOffset))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(0))

        data.appendFixedCString("__cstring", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000 + UInt64(cstringOffset)))
        data.appendLE(cstringSize)
        data.appendLE(UInt32(cstringOffset))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x02))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __DATA segment_command_64 + 1 section = 152 bytes
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(152))
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x2000))
        data.appendLE(UInt64(dataSegmentSize))
        data.appendLE(UInt64(dataSegmentOffset))
        data.appendLE(UInt64(dataSegmentSize))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(0))

        data.appendFixedCString("__const", length: 16)
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x2000))
        data.appendLE(UInt64(8))
        data.appendLE(UInt32(dataSegmentOffset))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        if data.count < cstringOffset {
            data.append(Data(count: cstringOffset - data.count))
        }
        data.append(cstringData)

        if data.count < dataSegmentOffset {
            data.append(Data(count: dataSegmentOffset - data.count))
        }
        data.append(Data([0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD]))

        if data.count < fileSize {
            data.append(Data(count: fileSize - data.count))
        }
        return data
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

    mutating func appendFixedCString(_ string: String, length: Int) {
        var bytes = Array(string.utf8.prefix(length))
        while bytes.count < length { bytes.append(0) }
        append(contentsOf: bytes)
    }
}
