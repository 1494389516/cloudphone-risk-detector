import CryptoKit
import Foundation
import MachOKit
import Security

// MARK: - 字符串敏感度分类

/// 字符串敏感度分类结果
public enum StringSensitivity: Equatable {
    /// 包含路径分隔符、敏感关键词（frida/cydia/jailbreak 等），必须加密
    case mustEncrypt
    /// 长度 ∈ [4, 256] 的 ASCII 可打印字符串，建议加密
    case shouldEncrypt
    /// ObjC selector、纯数字、单字符等，跳过不加密
    case skip
}

/// 字符串分类器：判断字面量字符串的敏感度
public enum StringClassifier {
    /// 必须加密的关键词列表（匹配时大小写不敏感）
    public static let sensitiveKeywords: [String] = [
        "frida", "cydia", "substrate", "sileo", "jailbreak",
        "hook", "inject", "debug", "ptrace", "svc",
        "tamper", "risk", "score",
        "kernel", "passwd", "shadow", "bash", "ssh",
        "apt", "dpkg", "http",
        // Risk signal families and anti-tamper domains
        "anti_tampering", "code_signature", "signing_identity",
        "dyld_monitor", "dyld_shared_cache", "memory_integrity",
        "multipath_consistency", "physical_sensor", "fingerprint",
        "sensor_replay", "segment_layout", "task_port",
        "vm_remap", "lldb_jit", "gpu_probe",
        // Business module identifiers
        "cloudphone", "riskkit", "riskdetect", "risksignal",
        "criskcore", "graphrisk", "riskverdict", "riskappcore",
        // Detection config keys embedded in JSON literals
        "enablecloudphone", "jailbreakthreshold", "enablebehaviordetect",
        "enablenetworksignals", "cloudphonerisk",
    ]

    /// 按以下优先级判断字符串敏感度：
    ///  1. 单字符 → skip
    ///  2. 纯数字 → skip
    ///  3. 包含 "/" 或敏感关键词 → mustEncrypt（在 ASCII 检查之前，覆盖含中文的 JSON 配置）
    ///  4. 非 ASCII 可打印 → skip
    ///  5. ObjC selector 风格（含 ":" 且长度 < 100） → skip
    ///  6. 长度 ≥ 4 → shouldEncrypt（移除 256 字节上限，覆盖长 JSON 字面量）
    ///  7. 其余 → skip
    public static func classify(_ value: String) -> StringSensitivity {
        let length = value.count

        guard length > 1 else { return .skip }

        if value.allSatisfy(\.isNumber) { return .skip }

        if value.contains("/") { return .mustEncrypt }

        // Sensitive keyword check must happen BEFORE the ASCII guard so that JSON config
        // strings containing CJK characters (e.g. Chinese description fields) are still caught.
        let lower = value.lowercased()
        for keyword in sensitiveKeywords {
            if lower.contains(keyword) { return .mustEncrypt }
        }

        // Keep CJK business strings out of static binary text segments.
        if containsCJK(value) { return .mustEncrypt }

        // Signal IDs and debug labels commonly use ":" + "_" or "-".
        // Treat these as sensitive unless they are canonical ObjC selectors.
        if value.contains(":"), length < 100 {
            if value.contains("_") || value.contains("-") || value.contains(" ") {
                return .mustEncrypt
            }
            if isLikelyObjCSelector(value) {
                return .skip
            }
        }

        let isASCIIPrintable = value.utf8.allSatisfy { byte in
            byte == 0x09 || byte == 0x0A || byte == 0x0D || (0x20...0x7E).contains(byte)
        }
        guard isASCIIPrintable else { return .skip }

        // Skip remaining ObjC selector-style strings (short, contain ":") but not long JSON blobs.
        if value.contains(":"), length < 100, isLikelyObjCSelector(value) { return .skip }

        guard length >= 4 else { return .skip }

        return .shouldEncrypt
    }

    private static func isLikelyObjCSelector(_ value: String) -> Bool {
        guard value.hasSuffix(":") else { return false }
        return value.utf8.allSatisfy { byte in
            byte == 0x3A || // :
            byte == 0x5F || // _
            (0x30...0x39).contains(byte) || // 0-9
            (0x41...0x5A).contains(byte) || // A-Z
            (0x61...0x7A).contains(byte) // a-z
        }
    }

    private static func containsCJK(_ value: String) -> Bool {
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x3400...0x4DBF, // CJK Unified Ideographs Extension A
                 0x4E00...0x9FFF, // CJK Unified Ideographs
                 0xF900...0xFAFF, // CJK Compatibility Ideographs
                 0x20000...0x2EBEF: // CJK Extensions B-F
                return true
            default:
                continue
            }
        }
        return false
    }
}

// MARK: - Pass 1 内部类型

private enum StringBootstrap {
    static let id: UInt32 = 1
    // 仅构建工具侧使用，此字面量不会出现在最终 SDK 二进制中
    static let value = "cprisk-bootstrap-v1"
}

private struct StringLiteralLocation {
    let segmentName: String
    let sectionName: String
    let fileOffset: UInt64
    let byteLength: Int
}

private struct StringLiteralLocationKey: Hashable {
    let segmentName: String
    let sectionName: String
    let fileOffset: UInt64
    let byteLength: Int
}

private struct LocatedStringLiteral {
    let value: String
    let location: StringLiteralLocation
}

private struct StringRecord {
    let id: UInt32
    let value: String
    /// 原始字面量所在位置；nil 表示合成的 bootstrap 字符串
    let location: StringLiteralLocation?
}

enum StringKeystreamVariant: UInt8, CaseIterable {
    case pathA = 0
    case pathB = 1
    case pathC = 2
    case pathD = 3
}

// MARK: - Pass 1: 全量敏感字符串加密

/// Pass 1: 扫描字符串字面量相关 section（按 sectionName 匹配，跨 segment）：
/// `__cstring`、`__const`、`__constg_swiftt`。
///
/// 将 mustEncrypt 和 shouldEncrypt 类别全部加密写入 string table section，
/// 并将原始 section 中对应字节零填充，防止 `strings` 工具直接提取。
public final class StringEncryptorPass: ArmorPass {
    public let name = "StringEncryptor"

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        let locatedStrings = try collectStringLiterals(from: file)
        let records = buildRecords(from: locatedStrings)
        let stringKey = deriveStringKey(rootKey: config.encryptionKey)
        let dispatchSeed = deriveKeystreamDispatchSeed(key: stringKey)

        var payload = ArmorABI.StringTable.Header(count: UInt32(records.count)).serialized()
        var dataArea = Data()

        for record in records {
            let plaintext = Data(record.value.utf8)
            let nonce = try generateNonce()
            let encrypted = xor(
                plaintext,
                buildKeystreamForRecord(
                    key: stringKey,
                    stringID: record.id,
                    nonce: nonce,
                    length: plaintext.count,
                    dispatchSeed: dispatchSeed
                )
            )
            // HMAC scope binds (string_id, nonce_len, nonce, ct_len, ciphertext)
            // so two strings cannot be transposed without invalidating the
            // tag, and a truncation/extension cannot find a matching length
            // pair (the previous `nonce || ciphertext` form was vulnerable to
            // both). The C-side verifier in cprisk_string_decrypt.c MUST
            // mirror this exact canonical encoding.
            //
            // Wire layout (little-endian):
            //   u32 string_id | u32 nonce_len | nonce[nonce_len] |
            //   u32 ct_len    | ciphertext[ct_len]
            var hmacMessage = Data()
            var stringIDLE = record.id.littleEndian
            withUnsafeBytes(of: &stringIDLE) { hmacMessage.append(contentsOf: $0) }
            var nonceLenLE = UInt32(nonce.count).littleEndian
            withUnsafeBytes(of: &nonceLenLE) { hmacMessage.append(contentsOf: $0) }
            hmacMessage.append(nonce)
            var ctLenLE = UInt32(encrypted.count).littleEndian
            withUnsafeBytes(of: &ctLenLE) { hmacMessage.append(contentsOf: $0) }
            hmacMessage.append(encrypted)
            let hmacTag = ArmorABI.hmacSHA256(key: stringKey, message: hmacMessage)

            payload.append(
                ArmorABI.StringTable.IndexEntry(
                    stringID: record.id,
                    dataOffset: UInt32(dataArea.count),
                    dataLength: UInt32(plaintext.count),
                    nonce: nonce,
                    hmacTag: hmacTag
                ).serialized()
            )
            dataArea.append(encrypted)
        }

        payload.append(dataArea)
        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.StringTable.sectionName,
            content: payload,
            align: 2
        )

        // 零填充已加密字符串在原始 section 中的位置，防止 strings 工具提取
        var zeroFilledCount = 0
        var touchedSections = Set<String>()
        for record in records {
            guard let location = record.location else { continue }
            let zeroData = Data(repeating: 0, count: location.byteLength)
            try file.replaceBytes(at: location.fileOffset, with: zeroData)
            touchedSections.insert("\(location.segmentName).\(location.sectionName)")
            zeroFilledCount += 1
        }

        let encryptedFromBinary = records.filter { $0.location != nil }.count
        let sectionSummary = touchedSections.sorted().joined(separator: ", ")
        return PassResult(
            passName: name,
            itemsProcessed: records.count,
            bytesModified: payload.count,
            details: [
                "Wrote encrypted string table to \(ArmorABI.dataSegmentName).\(ArmorABI.StringTable.sectionName)",
                "Bootstrap string id \(StringBootstrap.id) is retained for compatibility with the existing table layout",
                "Encrypted \(encryptedFromBinary) string literals (zero-filled \(zeroFilledCount) original positions)",
                "Scanned sections: \(sectionSummary.isEmpty ? "none" : sectionSummary)",
            ]
        )
    }

    /// 构建加密记录：bootstrap 字符串 + 所有 mustEncrypt/shouldEncrypt 字面量
    private func buildRecords(from literals: [LocatedStringLiteral]) -> [StringRecord] {
        var records = [StringRecord(
            id: StringBootstrap.id,
            value: StringBootstrap.value,
            location: nil
        )]

        for literal in literals {
            let sensitivity = StringClassifier.classify(literal.value)
            guard shouldEncrypt(literal: literal, sensitivity: sensitivity) else { continue }
            let nextID = UInt32(records.count + 1)
            records.append(StringRecord(
                id: nextID,
                value: literal.value,
                location: literal.location
            ))
        }
        return records
    }

    private func collectStringLiterals(from file: MachOFile) throws -> [LocatedStringLiteral] {
        var literals = [LocatedStringLiteral]()

        for segment in try file.segments() {
            for section in segment.sections
            where ArmorABI.StringEncryption.sourceSectionNames.contains(section.sectionName) {
                let content = try section.readContent(from: file.data)
                guard !content.isEmpty else { continue }

                literals.append(contentsOf: scanSectionLiterals(
                    in: content,
                    segmentName: segment.name,
                    sectionName: section.sectionName,
                    sectionFileOffset: UInt64(section.offset)
                ))
            }
        }

        return literals.sorted { lhs, rhs in
            if lhs.location.fileOffset != rhs.location.fileOffset {
                return lhs.location.fileOffset < rhs.location.fileOffset
            }
            if lhs.location.segmentName != rhs.location.segmentName {
                return lhs.location.segmentName < rhs.location.segmentName
            }
            return lhs.location.sectionName < rhs.location.sectionName
        }
    }

    private func scanSectionLiterals(
        in content: Data,
        segmentName: String,
        sectionName: String,
        sectionFileOffset: UInt64
    ) -> [LocatedStringLiteral] {
        var candidates = scanNullTerminatedUTF8(
            in: content,
            segmentName: segmentName,
            sectionName: sectionName,
            sectionFileOffset: sectionFileOffset
        )

        guard ArmorABI.StringEncryption.enhancedDataScanSectionNames.contains(sectionName) else {
            return deduplicateLiterals(candidates)
        }

        if ArmorABI.StringEncryption.utf16LENullTerminatedSectionNames.contains(sectionName) {
            candidates.append(contentsOf: scanNullTerminatedUTF16LE(
                in: content,
                segmentName: segmentName,
                sectionName: sectionName,
                sectionFileOffset: sectionFileOffset
            ))
        }

        if ArmorABI.StringEncryption.lengthPrefixedSectionNames.contains(sectionName) {
            candidates.append(contentsOf: scanLengthPrefixedUTF8(
                in: content,
                segmentName: segmentName,
                sectionName: sectionName,
                sectionFileOffset: sectionFileOffset
            ))
        }

        if ArmorABI.StringEncryption.boundedRunSectionNames.contains(sectionName) {
            candidates.append(contentsOf: scanBoundedASCIIRuns(
                in: content,
                segmentName: segmentName,
                sectionName: sectionName,
                sectionFileOffset: sectionFileOffset
            ))
        }

        return deduplicateLiterals(candidates)
    }

    /// Parse null-terminated UTF-8 runs in a section and preserve exact byte ranges for zero-fill.
    private func scanNullTerminatedUTF8(
        in content: Data,
        segmentName: String,
        sectionName: String,
        sectionFileOffset: UInt64
    ) -> [LocatedStringLiteral] {
        var results = [LocatedStringLiteral]()
        var position = 0

        while position < content.count {
            var end = position
            while end < content.count, content[end] != 0 {
                end += 1
            }

            let length = end - position
            if length > 0, length <= 4096 {
                let bytes = content.subdata(in: position..<end)
                if ArmorABI.StringEncryption.asciiOnlySectionNames.contains(sectionName),
                   !isASCIIPrintable(bytes) {
                    if end == content.count {
                        break
                    }
                    position = end + 1
                    continue
                }
                if let value = String(data: bytes, encoding: .utf8), !value.isEmpty {
                    results.append(LocatedStringLiteral(
                        value: value,
                        location: StringLiteralLocation(
                            segmentName: segmentName,
                            sectionName: sectionName,
                            fileOffset: sectionFileOffset + UInt64(position),
                            byteLength: length
                        )
                    ))
                }
            }

            if end == content.count {
                break
            }
            position = end + 1
        }

        return results
    }

    /// Scan UTF-16LE null-terminated strings for `__data` enhanced coverage.
    /// Only `mustEncrypt` candidates are admitted to keep false positives low.
    private func scanNullTerminatedUTF16LE(
        in content: Data,
        segmentName: String,
        sectionName: String,
        sectionFileOffset: UInt64
    ) -> [LocatedStringLiteral] {
        var results = [LocatedStringLiteral]()
        var position = 0
        let minChars = ArmorABI.StringEncryption.minimumCandidateCharacterLength

        while position + 1 < content.count {
            var end = position
            var units = [UInt16]()
            var foundTerminator = false

            while end + 1 < content.count {
                let unit = UInt16(content[end]) | (UInt16(content[end + 1]) << 8)
                if unit == 0 {
                    foundTerminator = true
                    break
                }
                if !isReadableUTF16CodeUnit(unit) {
                    break
                }
                units.append(unit)
                if units.count > 2048 {
                    break
                }
                end += 2
            }

            if foundTerminator, units.count >= minChars {
                let utf16Data = Data(units.flatMap { unit in
                    [UInt8(unit & 0xFF), UInt8(unit >> 8)]
                })
                if let value = String(data: utf16Data, encoding: .utf16LittleEndian),
                   isSensitiveDataCandidate(value) {
                    results.append(LocatedStringLiteral(
                        value: value,
                        location: StringLiteralLocation(
                            segmentName: segmentName,
                            sectionName: sectionName,
                            fileOffset: sectionFileOffset + UInt64(position),
                            byteLength: end - position
                        )
                    ))
                }
                position = end + 2
                continue
            }

            position += 1
        }

        return results
    }

    /// Scan 1-byte / 2-byte LE length-prefixed readable UTF-8 payloads.
    /// Prefix bytes are preserved; only payload bytes are zero-filled.
    private func scanLengthPrefixedUTF8(
        in content: Data,
        segmentName: String,
        sectionName: String,
        sectionFileOffset: UInt64
    ) -> [LocatedStringLiteral] {
        var results = [LocatedStringLiteral]()
        let minLength = ArmorABI.StringEncryption.minimumCandidateCharacterLength
        let maxLength = ArmorABI.StringEncryption.maximumLengthPrefixedByteLength

        for position in 0..<content.count {
            // 1-byte length prefix.
            let len8 = Int(content[position])
            if len8 >= minLength, len8 <= maxLength {
                let payloadStart = position + 1
                let payloadEnd = payloadStart + len8
                if payloadEnd <= content.count,
                   hasFramedBoundaries(in: content, frameStart: position, payloadStart: payloadStart, payloadEnd: payloadEnd),
                   let value = decodeASCIIPrintableUTF8(content.subdata(in: payloadStart..<payloadEnd)),
                   isSensitiveDataCandidate(value) {
                    results.append(LocatedStringLiteral(
                        value: value,
                        location: StringLiteralLocation(
                            segmentName: segmentName,
                            sectionName: sectionName,
                            fileOffset: sectionFileOffset + UInt64(payloadStart),
                            byteLength: len8
                        )
                    ))
                }
            }

            // 2-byte little-endian length prefix.
            if position + 1 >= content.count {
                continue
            }
            let len16 = Int(content[position]) | (Int(content[position + 1]) << 8)
            if len16 >= minLength, len16 <= maxLength {
                let payloadStart = position + 2
                let payloadEnd = payloadStart + len16
                if payloadEnd <= content.count,
                   hasFramedBoundaries(in: content, frameStart: position, payloadStart: payloadStart, payloadEnd: payloadEnd),
                   let value = decodeASCIIPrintableUTF8(content.subdata(in: payloadStart..<payloadEnd)),
                   isSensitiveDataCandidate(value) {
                    results.append(LocatedStringLiteral(
                        value: value,
                        location: StringLiteralLocation(
                            segmentName: segmentName,
                            sectionName: sectionName,
                            fileOffset: sectionFileOffset + UInt64(payloadStart),
                            byteLength: len16
                        )
                    ))
                }
            }
        }

        return results
    }

    /// Scan bounded printable ASCII runs even when not null-terminated.
    /// Requires both boundaries to be non-text bytes and only keeps `mustEncrypt`.
    private func scanBoundedASCIIRuns(
        in content: Data,
        segmentName: String,
        sectionName: String,
        sectionFileOffset: UInt64
    ) -> [LocatedStringLiteral] {
        var results = [LocatedStringLiteral]()
        let minLength = ArmorABI.StringEncryption.minimumBoundedRunLength
        let maxLength = ArmorABI.StringEncryption.maximumBoundedRunByteLength
        var position = 0

        while position < content.count {
            guard isASCIITextByte(content[position]) else {
                position += 1
                continue
            }

            let start = position
            while position < content.count, isASCIITextByte(content[position]) {
                position += 1
            }
            let end = position
            let length = end - start

            guard length >= minLength, length <= maxLength else { continue }
            guard hasBoundedRunBoundaries(in: content, start: start, end: end) else { continue }

            let bytes = content.subdata(in: start..<end)
            guard let value = decodeASCIIPrintableUTF8(bytes),
                  isSensitiveDataCandidate(value) else {
                continue
            }

            results.append(LocatedStringLiteral(
                value: value,
                location: StringLiteralLocation(
                    segmentName: segmentName,
                    sectionName: sectionName,
                    fileOffset: sectionFileOffset + UInt64(start),
                    byteLength: length
                )
            ))
        }

        return results
    }

    private func deduplicateLiterals(_ literals: [LocatedStringLiteral]) -> [LocatedStringLiteral] {
        var selected = [StringLiteralLocationKey: LocatedStringLiteral]()

        for literal in literals {
            let key = StringLiteralLocationKey(
                segmentName: literal.location.segmentName,
                sectionName: literal.location.sectionName,
                fileOffset: literal.location.fileOffset,
                byteLength: literal.location.byteLength
            )
            guard let existing = selected[key] else {
                selected[key] = literal
                continue
            }
            if sensitivityRank(of: literal.value) > sensitivityRank(of: existing.value) {
                selected[key] = literal
            }
        }

        return selected.values.sorted { lhs, rhs in
            lhs.location.fileOffset < rhs.location.fileOffset
        }
    }

    private func sensitivityRank(of value: String) -> Int {
        switch StringClassifier.classify(value) {
        case .mustEncrypt:
            return 3
        case .shouldEncrypt:
            return 2
        case .skip:
            return 1
        }
    }

    private func isSensitiveDataCandidate(_ value: String) -> Bool {
        StringClassifier.classify(value) == .mustEncrypt
    }

    private func decodeASCIIPrintableUTF8(_ data: Data) -> String? {
        guard isASCIIPrintable(data),
              let value = String(data: data, encoding: .utf8),
              !value.isEmpty else {
            return nil
        }
        return value
    }

    private func isReadableUTF16CodeUnit(_ unit: UInt16) -> Bool {
        if unit == 0x09 || unit == 0x0A || unit == 0x0D || (0x20...0x7E).contains(unit) {
            return true
        }
        switch UInt32(unit) {
        case 0x3000...0x303F, 0x3400...0x4DBF, 0x4E00...0x9FFF, 0xF900...0xFAFF:
            return true
        default:
            return false
        }
    }

    private func hasFramedBoundaries(
        in content: Data,
        frameStart: Int,
        payloadStart: Int,
        payloadEnd: Int
    ) -> Bool {
        if frameStart > 0, !isBoundaryByte(content[frameStart - 1]) {
            return false
        }
        if payloadStart > 0, !isBoundaryByte(content[payloadStart - 1]) {
            return false
        }
        if payloadEnd < content.count, !isBoundaryByte(content[payloadEnd]) {
            return false
        }
        return true
    }

    private func hasBoundedRunBoundaries(in content: Data, start: Int, end: Int) -> Bool {
        guard start > 0, end < content.count else { return false }
        return isBoundaryByte(content[start - 1]) && isBoundaryByte(content[end])
    }

    private func isBoundaryByte(_ byte: UInt8) -> Bool {
        byte == 0 || byte == 0xFF || byte == 0xFE || byte < 0x20 || byte > 0x7E
    }

    private func isASCIITextByte(_ byte: UInt8) -> Bool {
        (0x20...0x7E).contains(byte)
    }

    /// Keep writable-data (`__data`) handling conservative: only `mustEncrypt`.
    private func shouldEncrypt(
        literal: LocatedStringLiteral,
        sensitivity: StringSensitivity
    ) -> Bool {
        switch sensitivity {
        case .skip:
            return false
        case .mustEncrypt:
            return true
        case .shouldEncrypt:
            return !ArmorABI.StringEncryption.sensitiveOnlySectionNames.contains(literal.location.sectionName)
        }
    }

    private func isASCIIPrintable(_ data: Data) -> Bool {
        data.allSatisfy { byte in
            byte == 0x09 || byte == 0x0A || byte == 0x0D || (0x20...0x7E).contains(byte)
        }
    }
}

// MARK: - 密钥派生与加密辅助（仅构建工具侧使用）

private func deriveStringKey(rootKey: Data?) -> Data {
    let whitebox = ArmorWhiteBox.build(rootKey: rootKey)
    var seedMaterial = Data("cprisk.string.domain1.v2".utf8)
    if let raw = ProcessInfo.processInfo.environment["CPRISK_ARMOR_BUILD_SEED"] {
        seedMaterial.append(Data(raw.utf8))
    }
    return whitebox.prf(
        domain: .pass1StringKey,
        input: Data(SHA256.hash(data: seedMaterial))
    )
}

private func generateNonce() throws -> Data {
    var bytes = [UInt8](repeating: 0, count: ArmorABI.nonceSize)
    let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    guard status == errSecSuccess else {
        throw MachOError.invalidData("SecRandomCopyBytes failed: \(status)")
    }
    return Data(bytes)
}

func deriveKeystreamDispatchSeed(key: Data) -> UInt64 {
    var hash = FNV1A64.offsetBasis
    for byte in key {
        hash = fnvMix(hash, byte: byte)
    }
    return avalanche64(hash)
}

func selectKeystreamVariant(
    stringID: UInt32,
    nonce: Data,
    dispatchSeed: UInt64
) -> StringKeystreamVariant {
    var hash = dispatchSeed == 0 ? FNV1A64.offsetBasis : dispatchSeed
    hash = fnvMix(hash, byte: UInt8(truncatingIfNeeded: stringID))
    hash = fnvMix(hash, byte: UInt8(truncatingIfNeeded: stringID >> 8))
    hash = fnvMix(hash, byte: UInt8(truncatingIfNeeded: stringID >> 16))
    hash = fnvMix(hash, byte: UInt8(truncatingIfNeeded: stringID >> 24))
    for byte in nonce {
        hash = fnvMix(hash, byte: byte)
    }

    let lane = Int(avalanche64(hash) & 0x3)
    return StringKeystreamVariant.allCases[lane]
}

func buildKeystreamForRecord(
    key: Data,
    stringID: UInt32,
    nonce: Data,
    length: Int,
    dispatchSeed: UInt64
) -> Data {
    guard length > 0 else { return Data() }

    let variant = selectKeystreamVariant(stringID: stringID, nonce: nonce, dispatchSeed: dispatchSeed)
    switch variant {
    case .pathA:
        return keystreamPathA(key: key, stringID: stringID, nonce: nonce, length: length)
    case .pathB:
        return keystreamPathB(key: key, stringID: stringID, nonce: nonce, length: length)
    case .pathC:
        return keystreamPathC(key: key, stringID: stringID, nonce: nonce, length: length)
    case .pathD:
        return keystreamPathD(key: key, stringID: stringID, nonce: nonce, length: length)
    }
}

private func keystreamPathA(key: Data, stringID: UInt32, nonce: Data, length: Int) -> Data {
    var seed = Data()
    seed.append(key)
    var sid = stringID.littleEndian
    withUnsafeBytes(of: &sid) { seed.append(contentsOf: $0) }
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

private func keystreamPathB(key: Data, stringID: UInt32, nonce: Data, length: Int) -> Data {
    var sidBE = stringID.bigEndian
    var blockSeed = Data()
    blockSeed.append(nonce)
    withUnsafeBytes(of: &sidBE) { blockSeed.append(contentsOf: $0) }
    blockSeed.append(key)

    var block = sha256(blockSeed)
    var output = Data()
    output.reserveCapacity(length)
    var counter: UInt32 = 0

    while output.count < length {
        let remaining = length - output.count
        output.append(block.prefix(remaining))
        if output.count < length {
            var round = Data()
            round.append(block)
            var ctrLE = counter.littleEndian
            withUnsafeBytes(of: &ctrLE) { round.append(contentsOf: $0) }
            round.append(nonce)
            block = sha256(round)
            counter &+= 1
        }
    }
    return output
}

private func keystreamPathC(key: Data, stringID: UInt32, nonce: Data, length: Int) -> Data {
    var sidLE = stringID.littleEndian
    var seedMessage = Data()
    withUnsafeBytes(of: &sidLE) { seedMessage.append(contentsOf: $0) }
    seedMessage.append(nonce)
    seedMessage.append(Data([0x43, 0x50, 0x52, 0x49])) // "CPRI"

    var block = ArmorABI.hmacSHA256(key: key, message: seedMessage)
    var output = Data()
    output.reserveCapacity(length)
    var counter: UInt32 = 1

    while output.count < length {
        let remaining = length - output.count
        output.append(block.prefix(remaining))
        if output.count < length {
            var round = Data()
            var ctrBE = counter.bigEndian
            withUnsafeBytes(of: &ctrBE) { round.append(contentsOf: $0) }
            round.append(block)
            withUnsafeBytes(of: &sidLE) { round.append(contentsOf: $0) }
            block = sha256(round)
            counter &+= 1
        }
    }
    return output
}

private func keystreamPathD(key: Data, stringID: UInt32, nonce: Data, length: Int) -> Data {
    var mixedKey = Data(key.map { $0 ^ 0x5A })
    var sidLE = stringID.littleEndian
    withUnsafeBytes(of: &sidLE) { mixedKey.append(contentsOf: $0) }
    mixedKey.append(contentsOf: nonce.reversed())

    var block = sha256(mixedKey)
    var output = Data()
    output.reserveCapacity(length)
    var counter: UInt32 = 0

    while output.count < length {
        let remaining = length - output.count
        output.append(block.prefix(remaining))
        if output.count < length {
            let lane = key[Int(counter % UInt32(max(1, key.count)))]
            var mixed = Data(block.map { $0 ^ lane })
            var ctrLE = counter.littleEndian
            withUnsafeBytes(of: &ctrLE) { mixed.append(contentsOf: $0) }
            block = sha256(mixed)
            counter &+= 1
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

private enum FNV1A64 {
    static let offsetBasis: UInt64 = 0xCBF2_9CE4_8422_2325
    static let prime: UInt64 = 0x0000_0100_0000_01B3
}

private func fnvMix(_ hash: UInt64, byte: UInt8) -> UInt64 {
    var mixed = hash
    mixed ^= UInt64(byte)
    mixed &*= FNV1A64.prime
    return mixed
}

private func avalanche64(_ value: UInt64) -> UInt64 {
    var v = value
    v ^= v >> 33
    v &*= 0xFF51_AFD7_ED55_8CCD
    v ^= v >> 33
    v &*= 0xC4CE_B9FE_1A85_EC53
    v ^= v >> 33
    return v == 0 ? 1 : v
}
