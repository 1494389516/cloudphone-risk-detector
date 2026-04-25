import CryptoKit
import Foundation
import MachOKit
@testable import StringEncryptor
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

    func testClassifySignalIDsAreMustEncrypt() {
        XCTAssertEqual(StringClassifier.classify("anti_tampering:p_traced"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("task_port:task_for_pid_unexpected_success"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("vm_remap:shared_anon_exec:"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("dyld_shared_cache:symbol_mismatch:"), .mustEncrypt)
    }

    func testClassifyCJKBusinessStringsAreMustEncrypt() {
        XCTAssertEqual(StringClassifier.classify("检测到高风险行为模式"), .mustEncrypt)
        XCTAssertEqual(StringClassifier.classify("越狱设备禁止支付"), .mustEncrypt)
    }

    // MARK: - 字符串分类：shouldEncrypt

    func testClassifyNormalStringsAreShouldEncrypt() {
        XCTAssertEqual(StringClassifier.classify("Hello World"), .shouldEncrypt)
        XCTAssertEqual(StringClassifier.classify("test"), .shouldEncrypt)
        XCTAssertEqual(StringClassifier.classify("some_function_name"), .shouldEncrypt)
        // CloudPhoneRiskKit now hits the "riskkit" sensitive keyword → mustEncrypt
        XCTAssertEqual(StringClassifier.classify("CloudPhoneRiskKit"), .mustEncrypt)
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

    func testClassifyLength257IsShouldEncrypt() {
        // Length limit (256) removed — long strings are now shouldEncrypt to catch JSON config literals.
        let str257 = String(repeating: "a", count: 257)
        XCTAssertEqual(StringClassifier.classify(str257), .shouldEncrypt)
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

        // 1 条 Pass 1 合成 bootstrap 记录 + 6 个非 skip 的 cstring = 7 条记录。
        // 这条合成记录仅用于 string table 覆盖，Pass 3 不再依赖它派生 loader key。
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
        let dispatchSeed = deriveKeystreamDispatchSeed(key: stringKey)

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

            // Mirror the per-string KDF added in the encryption pass (WB#4 fix):
            //   perStringKey = HMAC(stringKey, "cprisk.str.key.v1" || sid_le4 || nonce)
            var pskMat = Data("cprisk.str.key.v1".utf8)
            var sidLE = stringID.littleEndian
            withUnsafeBytes(of: &sidLE) { pskMat.append(contentsOf: $0) }
            pskMat.append(nonce)
            let perStringKey = ArmorABI.hmacSHA256(key: stringKey, message: pskMat)

            let keystream = buildKeystreamForRecord(
                key: perStringKey,
                stringID: stringID,
                nonce: nonce,
                length: dataLength,
                dispatchSeed: dispatchSeed
            )
            let decrypted = Data(zip(encrypted, keystream).map(^))
            let decryptedString = String(data: decrypted, encoding: .utf8)
            XCTAssertNotNil(decryptedString, "Failed to decode entry \(i)")

            if stringID == 1 {
                // Pass 1 仍保留这条合成记录；它不再承担 runtime KDF bootstrap 语义。
                XCTAssertEqual(decryptedString, "cprisk-bootstrap-v1")
            } else {
                XCTAssertTrue(
                    originalStrings.contains(decryptedString!),
                    "Decrypted '\(decryptedString!)' not found in original strings"
                )
            }
        }
    }

    func testKeystreamVariantSelectionIsDeterministicAndDiverse() {
        let key = Data(repeating: 0x42, count: 32)
        let dispatchSeed = deriveKeystreamDispatchSeed(key: key)
        let nonce = Data([0x10, 0x22, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE])

        let a = selectKeystreamVariant(stringID: 7, nonce: nonce, dispatchSeed: dispatchSeed)
        let b = selectKeystreamVariant(stringID: 7, nonce: nonce, dispatchSeed: dispatchSeed)
        XCTAssertEqual(a, b, "same seed+stringID+nonce must map to a stable variant")

        var variants = Set<StringKeystreamVariant>()
        for sid in UInt32(1)...UInt32(64) {
            variants.insert(selectKeystreamVariant(stringID: sid, nonce: nonce, dispatchSeed: dispatchSeed))
        }
        XCTAssertGreaterThanOrEqual(variants.count, 3, "variant selector should spread calls across multiple paths")
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

    func testSwiftLiteralSectionsAcrossSegmentsAreEncryptedAndZeroFilled() throws {
        let fixture = Self.makeFixtureWithSwiftLiteralSections()
        let url = Self.temporaryURL(named: "swift_literal_sections")
        try fixture.data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)

        for target in fixture.targets {
            let section = try XCTUnwrap(
                try file.section(segment: target.segmentName, section: target.sectionName)
            )
            let content = try section.readContent(from: file.data)
            XCTAssertNotNil(content.range(of: Data(target.value.utf8)))
        }

        let pass = StringEncryptorPass()
        let config = PassConfig(encryptionKey: Data(repeating: 0x42, count: 32))
        let result = try pass.execute(on: file, config: config)

        XCTAssertEqual(result.itemsProcessed, fixture.targets.count + 1) // + bootstrap

        for target in fixture.targets {
            let section = try XCTUnwrap(
                try file.section(segment: target.segmentName, section: target.sectionName)
            )
            let content = try section.readContent(from: file.data)
            XCTAssertNil(
                content.range(of: Data(target.value.utf8)),
                "Expected literal '\(target.value)' to be removed from \(target.segmentName).\(target.sectionName)"
            )

            for offset in target.fileOffset..<(target.fileOffset + target.value.utf8.count) {
                XCTAssertEqual(file.data[offset], 0, "Expected zero fill at file offset \(offset)")
            }
        }
    }

    func testDataSectionUsesConservativeSensitiveOnlyEncryption() throws {
        let fixture = Self.makeFixtureWithDataSectionLiterals()
        let url = Self.temporaryURL(named: "data_section_literals")
        try fixture.data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let pass = StringEncryptorPass()
        let config = PassConfig(encryptionKey: Data(repeating: 0x42, count: 32))
        let result = try pass.execute(on: file, config: config)

        // bootstrap + 1 sensitive __data literal
        XCTAssertEqual(result.itemsProcessed, 2)

        for target in fixture.encryptedTargets {
            let section = try XCTUnwrap(
                try file.section(segment: target.segmentName, section: target.sectionName)
            )
            let content = try section.readContent(from: file.data)
            XCTAssertNil(content.range(of: Data(target.value.utf8)))

            for offset in target.fileOffset..<(target.fileOffset + target.value.utf8.count) {
                XCTAssertEqual(file.data[offset], 0, "Expected zero fill at file offset \(offset)")
            }
        }

        for target in fixture.preservedTargets {
            let section = try XCTUnwrap(
                try file.section(segment: target.segmentName, section: target.sectionName)
            )
            let content = try section.readContent(from: file.data)
            XCTAssertNotNil(
                content.range(of: Data(target.value.utf8)),
                "Expected non-sensitive __data literal '\(target.value)' to remain unchanged"
            )
        }
    }

    func testDataSectionEnhancedScannersCoverUTF16LengthPrefixedAndBoundedRuns() throws {
        let fixture = Self.makeFixtureWithEnhancedDataSectionLiterals()
        let url = Self.temporaryURL(named: "data_section_enhanced_literals")
        try fixture.data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let pass = StringEncryptorPass()
        let config = PassConfig(encryptionKey: Data(repeating: 0x42, count: 32))
        let result = try pass.execute(on: file, config: config)

        XCTAssertEqual(result.itemsProcessed, fixture.encryptedTargets.count + 1) // + bootstrap

        for target in fixture.encryptedTargets {
            for offset in target.fileOffset..<(target.fileOffset + target.rawBytes.count) {
                XCTAssertEqual(file.data[offset], 0, "Expected zero fill for \(target.label) at file offset \(offset)")
            }
        }

        for target in fixture.preservedTargets {
            let currentBytes = file.data.subdata(in: target.fileOffset..<(target.fileOffset + target.rawBytes.count))
            XCTAssertEqual(currentBytes, target.rawBytes, "Expected non-sensitive \(target.label) to remain unchanged")
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

    private static func deriveStringKey(rootKey: Data) -> Data {
        ArmorWhiteBox.build(rootKey: rootKey).prf(
            domain: .pass1StringKey,
            input: Data(repeating: 0, count: ArmorABI.hashSize)
        )
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

    private static func makeFixtureWithSwiftLiteralSections() -> SwiftLiteralFixture {
        let cstringLiteral = "/usr/bin/bash"
        let textConstLiteral = "frida_swift_const"
        let dataConstSwiftLiteral = "cloudphone_data_swift"

        let cstringData = Data(cstringLiteral.utf8) + Data([0])
        let textConstData = Data(textConstLiteral.utf8) + Data([0])
        let textConstSwiftTData = Data("safe_text_literal".utf8) + Data([0]) // shouldEncrypt
        let dataConstData = Data([0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD])
        let dataConstSwiftTData = Data(dataConstSwiftLiteral.utf8) + Data([0])

        let cstringOffset = 1024
        let textConstOffset = 1152
        let textConstSwiftTOffset = 1280
        let dataConstOffset = 2048
        let dataConstSwiftTOffset = 2112
        let fileSize = 2304

        var data = Data()

        // mach_header_64 (32 bytes)
        data.appendLE(UInt32(0xFEEDFACF))
        data.appendLE(UInt32(0x0100000C))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x00000006))
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(544)) // __TEXT(312) + __DATA(232)
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __TEXT segment_command_64 + 3 sections = 312 bytes
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(312))
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(2048))
        data.appendLE(UInt64(0))
        data.appendLE(UInt64(2048))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(0))

        // __TEXT.__cstring
        data.appendFixedCString("__cstring", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000 + UInt64(cstringOffset)))
        data.appendLE(UInt64(cstringData.count))
        data.appendLE(UInt32(cstringOffset))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x02))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __TEXT.__const
        data.appendFixedCString("__const", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000 + UInt64(textConstOffset)))
        data.appendLE(UInt64(textConstData.count))
        data.appendLE(UInt32(textConstOffset))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __TEXT.__constg_swiftt
        data.appendFixedCString("__constg_swiftt", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000 + UInt64(textConstSwiftTOffset)))
        data.appendLE(UInt64(textConstSwiftTData.count))
        data.appendLE(UInt32(textConstSwiftTOffset))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __DATA segment_command_64 + 2 sections = 232 bytes
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(232))
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x3000))
        data.appendLE(UInt64(256))
        data.appendLE(UInt64(dataConstOffset))
        data.appendLE(UInt64(256))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(0))

        // __DATA.__const
        data.appendFixedCString("__const", length: 16)
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x3000))
        data.appendLE(UInt64(dataConstData.count))
        data.appendLE(UInt32(dataConstOffset))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __DATA.__constg_swiftt (跨 segment 覆盖)
        data.appendFixedCString("__constg_swiftt", length: 16)
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x3000 + UInt64(dataConstSwiftTOffset - dataConstOffset)))
        data.appendLE(UInt64(dataConstSwiftTData.count))
        data.appendLE(UInt32(dataConstSwiftTOffset))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        precondition(data.count == 576, "header + commands layout mismatch")

        if data.count < cstringOffset {
            data.append(Data(count: cstringOffset - data.count))
        }
        data.append(cstringData)

        if data.count < textConstOffset {
            data.append(Data(count: textConstOffset - data.count))
        }
        data.append(textConstData)

        if data.count < textConstSwiftTOffset {
            data.append(Data(count: textConstSwiftTOffset - data.count))
        }
        data.append(textConstSwiftTData)

        if data.count < dataConstOffset {
            data.append(Data(count: dataConstOffset - data.count))
        }
        data.append(dataConstData)

        if data.count < dataConstSwiftTOffset {
            data.append(Data(count: dataConstSwiftTOffset - data.count))
        }
        data.append(dataConstSwiftTData)

        if data.count < fileSize {
            data.append(Data(count: fileSize - data.count))
        }

        return SwiftLiteralFixture(
            data: data,
            targets: [
                SwiftLiteralTarget(
                    segmentName: "__TEXT",
                    sectionName: "__cstring",
                    value: cstringLiteral,
                    fileOffset: cstringOffset
                ),
                SwiftLiteralTarget(
                    segmentName: "__TEXT",
                    sectionName: "__const",
                    value: textConstLiteral,
                    fileOffset: textConstOffset
                ),
                SwiftLiteralTarget(
                    segmentName: "__TEXT",
                    sectionName: "__constg_swiftt",
                    value: "safe_text_literal",
                    fileOffset: textConstSwiftTOffset
                ),
                SwiftLiteralTarget(
                    segmentName: "__DATA",
                    sectionName: "__constg_swiftt",
                    value: dataConstSwiftLiteral,
                    fileOffset: dataConstSwiftTOffset
                ),
            ]
        )
    }

    private static func makeFixtureWithDataSectionLiterals() -> ConservativeDataFixture {
        let textLiteral = "x"
        let dataSensitiveLiteral = "frida_debug_hook"
        let dataBenignLiteral = "status_ok_ascii"

        let cstringData = Data(textLiteral.utf8) + Data([0])
        let dataSectionContent = Data(dataSensitiveLiteral.utf8) + Data([0])
            + Data(dataBenignLiteral.utf8) + Data([0])

        let cstringOffset = 1024
        let dataSectionOffset = 2048
        let fileSize = 2304

        var data = Data()

        // mach_header_64 (32 bytes)
        data.appendLE(UInt32(0xFEEDFACF))
        data.appendLE(UInt32(0x0100000C))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x00000006))
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(384)) // __TEXT(232) + __DATA(152)
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __TEXT segment_command_64 + 2 sections = 232 bytes
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(232))
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(2048))
        data.appendLE(UInt64(0))
        data.appendLE(UInt64(2048))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(0))

        // __TEXT.__text
        data.appendFixedCString("__text", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1400))
        data.appendLE(UInt64(64))
        data.appendLE(UInt32(960))
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x80000400))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __TEXT.__cstring
        data.appendFixedCString("__cstring", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000 + UInt64(cstringOffset)))
        data.appendLE(UInt64(cstringData.count))
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
        data.appendLE(UInt64(0x3000))
        data.appendLE(UInt64(256))
        data.appendLE(UInt64(dataSectionOffset))
        data.appendLE(UInt64(256))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(0))

        // __DATA.__data
        data.appendFixedCString("__data", length: 16)
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x3000))
        data.appendLE(UInt64(dataSectionContent.count))
        data.appendLE(UInt32(dataSectionOffset))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        precondition(data.count == 416, "header + commands layout mismatch")

        if data.count < cstringOffset {
            data.append(Data(count: cstringOffset - data.count))
        }
        data.append(cstringData)

        if data.count < dataSectionOffset {
            data.append(Data(count: dataSectionOffset - data.count))
        }
        data.append(dataSectionContent)

        if data.count < fileSize {
            data.append(Data(count: fileSize - data.count))
        }

        let sensitiveOffset = dataSectionOffset
        let benignOffset = dataSectionOffset + dataSensitiveLiteral.utf8.count + 1

        return ConservativeDataFixture(
            data: data,
            encryptedTargets: [
                SwiftLiteralTarget(
                    segmentName: "__DATA",
                    sectionName: "__data",
                    value: dataSensitiveLiteral,
                    fileOffset: sensitiveOffset
                ),
            ],
            preservedTargets: [
                SwiftLiteralTarget(
                    segmentName: "__DATA",
                    sectionName: "__data",
                    value: dataBenignLiteral,
                    fileOffset: benignOffset
                ),
            ]
        )
    }

    private static func makeFixtureWithEnhancedDataSectionLiterals() -> EnhancedDataFixture {
        let textLiteral = "x"
        let utf16Sensitive = "frida_utf16_probe"
        let len8Sensitive = "jailbreak_len8"
        let len16Sensitive = "ptrace_len16_tag"
        let boundedSensitive = "tamper_nonterm_run"
        let boundedBenign = "status_ok_ascii"

        let cstringData = Data(textLiteral.utf8) + Data([0])

        var dataSectionContent = Data()
        let utf16SensitiveOffsetInSection = dataSectionContent.count
        dataSectionContent.append(utf16LEBytes(utf16Sensitive))
        dataSectionContent.append(contentsOf: [0, 0]) // UTF-16LE null terminator

        let len8StartInSection = dataSectionContent.count
        let len8Bytes = Data(len8Sensitive.utf8)
        dataSectionContent.append(UInt8(len8Bytes.count))
        dataSectionContent.append(len8Bytes)
        dataSectionContent.append(0xFD) // framed boundary

        let len16StartInSection = dataSectionContent.count
        let len16Bytes = Data(len16Sensitive.utf8)
        var len16LE = UInt16(len16Bytes.count).littleEndian
        withUnsafeBytes(of: &len16LE) { dataSectionContent.append(contentsOf: $0) }
        dataSectionContent.append(len16Bytes)
        dataSectionContent.append(0xFC) // framed boundary

        let boundedSensitiveStartInSection = dataSectionContent.count
        let boundedSensitiveBytes = Data(boundedSensitive.utf8)
        dataSectionContent.append(0xFF)
        dataSectionContent.append(boundedSensitiveBytes)
        dataSectionContent.append(0xFE)

        let boundedBenignStartInSection = dataSectionContent.count
        let boundedBenignBytes = Data(boundedBenign.utf8)
        dataSectionContent.append(0xFF)
        dataSectionContent.append(boundedBenignBytes)
        dataSectionContent.append(0xFE)

        let cstringOffset = 1024
        let dataSectionOffset = 2048
        let fileSize = 2560

        var data = Data()

        // mach_header_64 (32 bytes)
        data.appendLE(UInt32(0xFEEDFACF))
        data.appendLE(UInt32(0x0100000C))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x00000006))
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(384)) // __TEXT(232) + __DATA(152)
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __TEXT segment_command_64 + 2 sections = 232 bytes
        data.appendLE(UInt32(0x19))
        data.appendLE(UInt32(232))
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000))
        data.appendLE(UInt64(2048))
        data.appendLE(UInt64(0))
        data.appendLE(UInt64(2048))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(5))
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(0))

        // __TEXT.__text
        data.appendFixedCString("__text", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1400))
        data.appendLE(UInt64(64))
        data.appendLE(UInt32(960))
        data.appendLE(UInt32(2))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0x80000400))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        // __TEXT.__cstring
        data.appendFixedCString("__cstring", length: 16)
        data.appendFixedCString("__TEXT", length: 16)
        data.appendLE(UInt64(0x1000 + UInt64(cstringOffset)))
        data.appendLE(UInt64(cstringData.count))
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
        data.appendLE(UInt64(0x3000))
        data.appendLE(UInt64(512))
        data.appendLE(UInt64(dataSectionOffset))
        data.appendLE(UInt64(512))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(3))
        data.appendLE(UInt32(1))
        data.appendLE(UInt32(0))

        // __DATA.__data
        data.appendFixedCString("__data", length: 16)
        data.appendFixedCString("__DATA", length: 16)
        data.appendLE(UInt64(0x3000))
        data.appendLE(UInt64(dataSectionContent.count))
        data.appendLE(UInt32(dataSectionOffset))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))
        data.appendLE(UInt32(0))

        precondition(data.count == 416, "header + commands layout mismatch")

        if data.count < cstringOffset {
            data.append(Data(count: cstringOffset - data.count))
        }
        data.append(cstringData)

        if data.count < dataSectionOffset {
            data.append(Data(count: dataSectionOffset - data.count))
        }
        data.append(dataSectionContent)

        if data.count < fileSize {
            data.append(Data(count: fileSize - data.count))
        }

        let utf16FileOffset = dataSectionOffset + utf16SensitiveOffsetInSection
        let len8PayloadFileOffset = dataSectionOffset + len8StartInSection + 1
        let len16PayloadFileOffset = dataSectionOffset + len16StartInSection + 2
        let boundedSensitiveFileOffset = dataSectionOffset + boundedSensitiveStartInSection + 1
        let boundedBenignFileOffset = dataSectionOffset + boundedBenignStartInSection + 1

        return EnhancedDataFixture(
            data: data,
            encryptedTargets: [
                BinaryLiteralTarget(
                    label: "utf16-sensitive",
                    rawBytes: utf16LEBytes(utf16Sensitive),
                    fileOffset: utf16FileOffset
                ),
                BinaryLiteralTarget(
                    label: "len8-sensitive",
                    rawBytes: len8Bytes,
                    fileOffset: len8PayloadFileOffset
                ),
                BinaryLiteralTarget(
                    label: "len16-sensitive",
                    rawBytes: len16Bytes,
                    fileOffset: len16PayloadFileOffset
                ),
                BinaryLiteralTarget(
                    label: "bounded-sensitive",
                    rawBytes: boundedSensitiveBytes,
                    fileOffset: boundedSensitiveFileOffset
                ),
            ],
            preservedTargets: [
                BinaryLiteralTarget(
                    label: "bounded-benign",
                    rawBytes: boundedBenignBytes,
                    fileOffset: boundedBenignFileOffset
                ),
            ]
        )
    }

    private static func utf16LEBytes(_ value: String) -> Data {
        var encoded = Data()
        for unit in value.utf16 {
            var littleEndian = unit.littleEndian
            withUnsafeBytes(of: &littleEndian) { encoded.append(contentsOf: $0) }
        }
        return encoded
    }
}

private struct SwiftLiteralFixture {
    let data: Data
    let targets: [SwiftLiteralTarget]
}

private struct ConservativeDataFixture {
    let data: Data
    let encryptedTargets: [SwiftLiteralTarget]
    let preservedTargets: [SwiftLiteralTarget]
}

private struct EnhancedDataFixture {
    let data: Data
    let encryptedTargets: [BinaryLiteralTarget]
    let preservedTargets: [BinaryLiteralTarget]
}

private struct BinaryLiteralTarget {
    let label: String
    let rawBytes: Data
    let fileOffset: Int
}

private struct SwiftLiteralTarget {
    let segmentName: String
    let sectionName: String
    let value: String
    let fileOffset: Int
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
