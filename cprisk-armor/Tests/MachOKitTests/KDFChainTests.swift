import DataSegmentEncryptor
import Foundation
import IntegrityAnchor
import MachOKit
@testable import StringEncryptor
import XCTest

final class KDFChainTests: XCTestCase {
    private static let testRootKey = Data(repeating: 0xAB, count: ArmorABI.keySize)

    func testPass4WritesWhiteBoxAnchorAndSections() throws {
        let url = try Self.writeFixture(named: "wb_anchor")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let config = PassConfig(encryptionKey: Self.testRootKey)
        let textHash = try Self.textHash(from: file)
        let bundle = ArmorWhiteBox.build(rootKey: Self.testRootKey)

        _ = try IntegrityAnchorPass().execute(on: file, config: config)

        let anchorSection = try XCTUnwrap(
            try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.Integrity.fullHashSectionName)
        )
        XCTAssertEqual(
            try anchorSection.readContent(from: file.data),
            bundle.prf(domain: .anchorTag, input: textHash)
        )

        XCTAssertEqual(
            try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.WhiteBox.Sections.metadata))
                .readContent(from: file.data),
            bundle.metadataSection
        )
        XCTAssertEqual(
            try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.WhiteBox.Sections.code))
                .readContent(from: file.data),
            bundle.whiteboxCode
        )
        XCTAssertEqual(
            try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.WhiteBox.Sections.data))
                .readContent(from: file.data),
            bundle.whiteboxData
        )
        XCTAssertEqual(
            try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.WhiteBox.Sections.tag))
                .readContent(from: file.data),
            bundle.whiteboxTag
        )

        for (i, sectionName) in ArmorABI.Integrity.splitSectionNames.enumerated() {
            let section = try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: sectionName))
            let lane = try section.readContent(from: file.data)
            XCTAssertEqual(lane, textHash.subdata(in: (i * 8)..<((i + 1) * 8)))
        }
    }

    func testPass1StringKeyComesFromWhiteBoxDomain2() throws {
        let url = try Self.writeFixture(named: "wb_pass1")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let config = PassConfig(encryptionKey: Self.testRootKey)
        let bundle = ArmorWhiteBox.build(rootKey: Self.testRootKey)
        // Must mirror StringEncryptor.deriveStringKey(rootKey:): the PRF input
        // is SHA256 over the domain-separated seed material, not a zero block.
        var stringSeed = Data("cprisk.string.domain1.v2".utf8)
        if let raw = ProcessInfo.processInfo.environment["CPRISK_ARMOR_BUILD_SEED"] {
            stringSeed.append(Data(raw.utf8))
        }
        let expectedStringKey = bundle.prf(
            domain: .pass1StringKey,
            input: Self.sha256(stringSeed)
        )

        _ = try StringEncryptorPass().execute(on: file, config: config)

        let section = try XCTUnwrap(
            try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.StringTable.sectionName)
        )
        let content = try section.readContent(from: file.data)
        let count = Int(Self.readLE32(content, at: 8))
        XCTAssertGreaterThan(count, 0)

        let indexBase = ArmorABI.StringTable.headerSize
        let dataBase = indexBase + count * ArmorABI.StringTable.indexEntrySize
        let firstID = Self.readLE32(content, at: indexBase)
        let firstOffset = Int(Self.readLE32(content, at: indexBase + 4))
        let firstLength = Int(Self.readLE32(content, at: indexBase + 8))
        let firstNonce = content.subdata(in: (indexBase + 12)..<(indexBase + 28))
        let firstEncrypted = content.subdata(
            in: (dataBase + firstOffset)..<(dataBase + firstOffset + firstLength)
        )
        let dispatchSeed = deriveKeystreamDispatchSeed(key: expectedStringKey)

        // Mirror StringEncryptor per-string KDF:
        //   perStringKey = HMAC(stringKey, "cprisk.str.key.v1" || sid_le4 || nonce)
        var pskMaterial = Data("cprisk.str.key.v1".utf8)
        var sidLE = firstID.littleEndian
        withUnsafeBytes(of: &sidLE) { pskMaterial.append(contentsOf: $0) }
        pskMaterial.append(firstNonce)
        let perStringKey = ArmorABI.hmacSHA256(key: expectedStringKey, message: pskMaterial)

        let keystream = buildKeystreamForRecord(
            key: perStringKey,
            stringID: firstID,
            nonce: firstNonce,
            length: firstLength,
            dispatchSeed: dispatchSeed
        )
        let decrypted = Data(zip(firstEncrypted, keystream).map(^))
        XCTAssertEqual(String(data: decrypted, encoding: .utf8), "cprisk-bootstrap-v1")
    }

    func testPass3DerivationUsesWhiteBoxDomains3And4() {
        let fullAnchorHash = Self.sha256(Data("anchor-material".utf8))
        let integrityHash = Self.sha256(fullAnchorHash + fullAnchorHash + fullAnchorHash)
        let bundle = ArmorWhiteBox.build(rootKey: Self.testRootKey)

        let accDigest = Self.sha256(fullAnchorHash + integrityHash)
        let accSeed = bundle.prf(domain: .anchorAccumulatorSeed, input: accDigest)
        let expectedAccumulator = ArmorWhiteBox.rotl64(
            ArmorWhiteBox.littleEndianUInt64(from: accSeed),
            by: 7
        )

        let actualAccumulator = anchorBoundAccumulator(
            rootKey: Self.testRootKey,
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash
        )
        XCTAssertEqual(actualAccumulator, expectedAccumulator)

        var loaderMaterial = Data()
        loaderMaterial.append(fullAnchorHash)
        loaderMaterial.append(integrityHash)
        ArmorWhiteBox.appendLittleEndian(expectedAccumulator, to: &loaderMaterial)
        let expectedLoaderKey = bundle.prf(
            domain: .loaderKey,
            input: Self.sha256(loaderMaterial)
        )

        let actualLoaderKey = deriveLoaderKey(
            rootKey: Self.testRootKey,
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash,
            anchorAccumulator: expectedAccumulator
        )
        XCTAssertEqual(actualLoaderKey, expectedLoaderKey)
    }

    func testFullWhiteBoxChainRunsAcrossPasses() throws {
        let url = try Self.writeFixture(named: "wb_chain")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let config = PassConfig(encryptionKey: Self.testRootKey)

        _ = try IntegrityAnchorPass().execute(on: file, config: config)
        _ = try StringEncryptorPass().execute(on: file, config: config)
        _ = try DataSegmentEncryptorPass().execute(on: file, config: config)

        XCTAssertNotNil(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.StringTable.sectionName))
        XCTAssertNotNil(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.Loader.sectionName))
        XCTAssertNotNil(try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.WhiteBox.Sections.code))
        XCTAssertNoThrow(try file.validateStructure())
    }

    func testLoaderEntriesUseChainedKeysPerSection() throws {
        let url = try Self.writeFixture(named: "wb_chain_kdf")
        defer { try? FileManager.default.removeItem(at: url) }

        let file = try MachOFile(url: url)
        let config = PassConfig(encryptionKey: Self.testRootKey)

        _ = try IntegrityAnchorPass().execute(on: file, config: config)
        _ = try StringEncryptorPass().execute(on: file, config: config)
        _ = try DataSegmentEncryptorPass().execute(on: file, config: config)

        let loaderSection = try XCTUnwrap(
            try file.section(segment: ArmorABI.dataSegmentName, section: ArmorABI.Loader.sectionName)
        )
        let loaderBytes = try loaderSection.readContent(from: file.data)
        let entries = try Self.decodeLoaderEntries(from: loaderBytes)
        XCTAssertGreaterThan(entries.count, 1, "need at least 2 entries to verify chaining")

        let fullAnchorHash = try Self.readFullAnchorHash(from: file)
        let integrityHash = Self.sha256(fullAnchorHash + fullAnchorHash + fullAnchorHash)
        let loaderKey = deriveLoaderKey(
            rootKey: Self.testRootKey,
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash,
            anchorAccumulator: anchorBoundAccumulator(
                rootKey: Self.testRootKey,
                fullAnchorHash: fullAnchorHash,
                integrityHash: integrityHash
            )
        )

        var parentKey = loaderKey
        for (idx, entry) in entries.enumerated() {
            let depth = entry.chainedKeyDepth == 0 ? 1 : entry.chainedKeyDepth
            let sectionKey = Self.deriveChainedKey(
                parentKey: parentKey,
                sectionIndex: entry.sectionIndex,
                nonce: entry.nonce,
                depth: depth
            )
            XCTAssertNotEqual(sectionKey, parentKey, "section \(idx) key must differ from parent")

            let section = try XCTUnwrap(
                try file.section(segment: entry.segmentName, section: entry.sectionName)
            )
            let ciphertext = try section.readContent(from: file.data)
            // Mirror DataSegmentEncryptor's canonical HMAC scope:
            //   u32 section_index | u32 nonce_len | nonce | u32 ct_len | ciphertext
            // (the old `nonce || ciphertext` form was replaced to bind lengths).
            var hmacMsg = Data()
            var sectionIndexLE = entry.sectionIndex.littleEndian
            withUnsafeBytes(of: &sectionIndexLE) { hmacMsg.append(contentsOf: $0) }
            var nonceLenLE = UInt32(entry.nonce.count).littleEndian
            withUnsafeBytes(of: &nonceLenLE) { hmacMsg.append(contentsOf: $0) }
            hmacMsg.append(entry.nonce)
            var ctLenLE = UInt32(ciphertext.count).littleEndian
            withUnsafeBytes(of: &ctLenLE) { hmacMsg.append(contentsOf: $0) }
            hmacMsg.append(ciphertext)

            let expectedTag = ArmorABI.hmacSHA256(key: sectionKey, message: hmacMsg)
            XCTAssertEqual(expectedTag, entry.hmacTag, "HMAC must be derived from chained key")

            let loaderTag = ArmorABI.hmacSHA256(key: loaderKey, message: hmacMsg)
            XCTAssertNotEqual(loaderTag, entry.hmacTag, "HMAC must not reuse loader key")

            parentKey = sectionKey
        }
    }

    private static func sha256(_ data: Data) -> Data {
        ArmorWhiteBox.sha256(data)
    }

    private static func textHash(from file: MachOFile) throws -> Data {
        let textSection = try XCTUnwrap(try file.section(segment: "__TEXT", section: "__text"))
        return sha256(try textSection.readContent(from: file.data))
    }

    private static func readLE32(_ data: Data, at offset: Int) -> UInt32 {
        data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            UInt32(littleEndian: $0.load(as: UInt32.self))
        }
    }

    private static func readFullAnchorHash(from file: MachOFile) throws -> Data {
        var digest = Data(repeating: 0, count: ArmorABI.hashSize)
        for (i, name) in ArmorABI.Integrity.splitSectionNames.enumerated() {
            let section = try XCTUnwrap(try file.section(segment: ArmorABI.dataSegmentName, section: name))
            let lane = try section.readContent(from: file.data)
            digest.replaceSubrange(i * 8..<(i * 8 + 8), with: lane.prefix(8))
        }
        return digest
    }

    private struct LoaderEntry {
        let segmentName: String
        let sectionName: String
        let keyID: UInt32
        let vmAddress: UInt64
        let size: UInt64
        let contentHash: Data
        let nonce: Data
        let hmacTag: Data
        let sectionIndex: UInt32
        let chainedKeyDepth: UInt32
    }

    private static func decodeLoaderEntries(from data: Data) throws -> [LoaderEntry] {
        let headerSize = 12
        guard data.count >= headerSize else { throw XCTSkip("loader header truncated") }
        let count = readLE32(data, at: 8)
        let entrySize = 144
        var entries: [LoaderEntry] = []
        var offset = headerSize
        for _ in 0..<count {
            guard offset + entrySize <= data.count else { break }
            let entry = data.subdata(in: offset..<(offset + entrySize))
            let segmentName = entry.subdata(in: 0..<16).withUnsafeBytes { raw -> String in
                let bytes = raw.bindMemory(to: UInt8.self)
                let len = bytes.firstIndex(where: { $0 == 0 }) ?? 16
                return String(decoding: bytes.prefix(len), as: UTF8.self)
            }
            let sectionName = entry.subdata(in: 16..<32).withUnsafeBytes { raw -> String in
                let bytes = raw.bindMemory(to: UInt8.self)
                let len = bytes.firstIndex(where: { $0 == 0 }) ?? 16
                return String(decoding: bytes.prefix(len), as: UTF8.self)
            }
            let keyID = entry.subdata(in: 32..<36).withUnsafeBytes { UInt32(littleEndian: $0.load(as: UInt32.self)) }
            let vmAddr = entry.subdata(in: 40..<48).withUnsafeBytes { UInt64(littleEndian: $0.load(as: UInt64.self)) }
            let size = entry.subdata(in: 48..<56).withUnsafeBytes { UInt64(littleEndian: $0.load(as: UInt64.self)) }
            let contentHash = entry.subdata(in: 56..<88)
            let nonce = entry.subdata(in: 88..<104)
            let hmacTag = entry.subdata(in: 104..<136)
            let sectionIndex = entry.subdata(in: 136..<140).withUnsafeBytes { UInt32(littleEndian: $0.load(as: UInt32.self)) }
            let chainedDepth = entry.subdata(in: 140..<144).withUnsafeBytes { UInt32(littleEndian: $0.load(as: UInt32.self)) }
            entries.append(LoaderEntry(
                segmentName: segmentName,
                sectionName: sectionName,
                keyID: keyID,
                vmAddress: vmAddr,
                size: size,
                contentHash: contentHash,
                nonce: nonce,
                hmacTag: hmacTag,
                sectionIndex: sectionIndex,
                chainedKeyDepth: chainedDepth
            ))
            offset += entrySize
        }
        return entries
    }

    private static func deriveChainedKey(
        parentKey: Data,
        sectionIndex: UInt32,
        nonce: Data,
        depth: UInt32
    ) -> Data {
        var material = Data()
        var idx = sectionIndex.littleEndian
        withUnsafeBytes(of: &idx) { material.append(contentsOf: $0) }
        material.append(nonce)

        var key = ArmorABI.hmacSHA256(key: parentKey, message: material)
        if depth > 1 {
            for d in 1..<depth {
                key = ArmorABI.hmacSHA256(key: key, message: Data("cprisk.chained.v1.".utf8))
                var dm = key
                dm.append(UInt8(d))
                key = ArmorABI.hmacSHA256(key: dm, message: dm)
            }
        }
        return key
    }

    private static func writeFixture(named name: String) throws -> URL {
        let url = temporaryURL(named: name)
        try makeFixture().write(to: url)
        return url
    }

    private static func temporaryURL(named name: String) -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("\(name)_\(UUID().uuidString).macho")
    }

    private static func makeFixture() -> Data {
        // Pass 4 (IntegrityAnchor) only *populates* the white-box sections when
        // they already exist as placeholders (writeIfPresent in
        // IntegrityAnchor.swift — older app builds may not link them in). The
        // synthetic fixture must therefore pre-declare __swift5_mdext/mdbdy/
        // mddsc/mdchk in __DATA, each large enough to hold the corresponding
        // bundle section (addOrUpdateSection refuses to grow an existing
        // section). Size them from a freshly built bundle so the placeholders
        // auto-track any ABI change; bundle section *sizes* are salt-independent.
        let sizingBundle = ArmorWhiteBox.build(rootKey: testRootKey)
        let wbSections: [(name: String, size: Int)] = [
            (ArmorABI.WhiteBox.Sections.metadata, sizingBundle.metadataSection.count),
            (ArmorABI.WhiteBox.Sections.code, sizingBundle.whiteboxCode.count),
            (ArmorABI.WhiteBox.Sections.data, sizingBundle.whiteboxData.count),
            (ArmorABI.WhiteBox.Sections.tag, sizingBundle.whiteboxTag.count),
        ]

        let textCodeContent = Data([
            0xFD, 0x7B, 0xBF, 0xA9,
            0xFD, 0x03, 0x00, 0x91,
            0x00, 0x00, 0x80, 0xD2,
            0xC0, 0x03, 0x5F, 0xD6,
            0x1F, 0x20, 0x03, 0xD5,
            0x1F, 0x20, 0x03, 0xD5,
            0xFD, 0x7B, 0xC1, 0xA8,
            0xC0, 0x03, 0x5F, 0xD6,
        ])

        let cstrings = [
            "/usr/bin/bash",
            "frida-server",
            "normal_text",
            "12345",
        ]
        var cstringData = Data()
        for value in cstrings {
            cstringData.append(contentsOf: value.utf8)
            cstringData.append(0)
        }

        // __DATA now carries __const + 4 white-box placeholder sections.
        let dataSectionCount = 1 + wbSections.count
        let textSegCmdSize = 72 + 80 + 80
        let dataSegCmdSize = 72 + 80 * dataSectionCount
        let sizeOfCmds = textSegCmdSize + dataSegCmdSize

        let textCodeOffset = 2048
        let cstringOffset = textCodeOffset + textCodeContent.count
        let textSegFileSize = 4096
        let dataSegOffset = 4096

        // Lay __const then each white-box placeholder back-to-back in __DATA,
        // 8-byte aligned. Track per-section file offsets for the headers.
        let constSize = 8
        func align8(_ v: Int) -> Int { (v + 7) & ~7 }
        var cursor = 0
        let constRel = cursor
        cursor = align8(cursor + constSize)
        var wbRel: [Int] = []
        for s in wbSections {
            wbRel.append(cursor)
            cursor = align8(cursor + s.size)
        }
        let dataSegSize = max(4096, cursor)
        let fileSize = dataSegOffset + dataSegSize

        var data = Data()
        data.appendLE32(0xFEEDFACF)
        data.appendLE32(0x0100000C)
        data.appendLE32(0)
        data.appendLE32(0x00000006)
        data.appendLE32(2)
        data.appendLE32(UInt32(sizeOfCmds))
        data.appendLE32(0)
        data.appendLE32(0)

        data.appendLE32(0x19)
        data.appendLE32(UInt32(textSegCmdSize))
        data.appendFixedCString16("__TEXT")
        data.appendLE64(0x1000)
        data.appendLE64(UInt64(textSegFileSize))
        data.appendLE64(0)
        data.appendLE64(UInt64(textSegFileSize))
        data.appendLE32(5)
        data.appendLE32(5)
        data.appendLE32(2)
        data.appendLE32(0)

        data.appendFixedCString16("__text")
        data.appendFixedCString16("__TEXT")
        data.appendLE64(0x1000 + UInt64(textCodeOffset))
        data.appendLE64(UInt64(textCodeContent.count))
        data.appendLE32(UInt32(textCodeOffset))
        data.appendLE32(2)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0x80000400)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)

        data.appendFixedCString16("__cstring")
        data.appendFixedCString16("__TEXT")
        data.appendLE64(0x1000 + UInt64(cstringOffset))
        data.appendLE64(UInt64(cstringData.count))
        data.appendLE32(UInt32(cstringOffset))
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0x02)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)

        data.appendLE32(0x19)
        data.appendLE32(UInt32(dataSegCmdSize))
        data.appendFixedCString16("__DATA")
        data.appendLE64(0x2000)
        data.appendLE64(UInt64(dataSegSize))
        data.appendLE64(UInt64(dataSegOffset))
        data.appendLE64(UInt64(dataSegSize))
        data.appendLE32(3)
        data.appendLE32(3)
        data.appendLE32(UInt32(dataSectionCount))
        data.appendLE32(0)

        // __DATA.__const
        data.appendFixedCString16("__const")
        data.appendFixedCString16("__DATA")
        data.appendLE64(0x2000 + UInt64(constRel))
        data.appendLE64(UInt64(constSize))
        data.appendLE32(UInt32(dataSegOffset + constRel))
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)
        data.appendLE32(0)

        // __DATA white-box placeholder sections.
        for (i, s) in wbSections.enumerated() {
            data.appendFixedCString16(s.name)
            data.appendFixedCString16("__DATA")
            data.appendLE64(0x2000 + UInt64(wbRel[i]))
            data.appendLE64(UInt64(s.size))
            data.appendLE32(UInt32(dataSegOffset + wbRel[i]))
            data.appendLE32(3)
            data.appendLE32(0)
            data.appendLE32(0)
            data.appendLE32(0)
            data.appendLE32(0)
            data.appendLE32(0)
            data.appendLE32(0)
        }

        if data.count < textCodeOffset {
            data.append(Data(count: textCodeOffset - data.count))
        }
        data.append(textCodeContent)

        if data.count < cstringOffset {
            data.append(Data(count: cstringOffset - data.count))
        }
        data.append(cstringData)

        if data.count < dataSegOffset + constRel {
            data.append(Data(count: dataSegOffset + constRel - data.count))
        }
        data.append(Data([0x10, 0x20, 0x30, 0x40, 0xAA, 0xBB, 0xCC, 0xDD]))

        if data.count < fileSize {
            data.append(Data(count: fileSize - data.count))
        }
        return data
    }
}

private extension Data {
    mutating func appendLE32(_ value: UInt32) {
        var littleEndian = value.littleEndian
        append(Data(bytes: &littleEndian, count: 4))
    }

    mutating func appendLE64(_ value: UInt64) {
        var littleEndian = value.littleEndian
        append(Data(bytes: &littleEndian, count: 8))
    }

    mutating func appendFixedCString16(_ string: String) {
        var bytes = Array(string.utf8.prefix(16))
        while bytes.count < 16 { bytes.append(0) }
        append(contentsOf: bytes)
    }
}
