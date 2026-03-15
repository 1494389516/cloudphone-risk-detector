import CryptoKit
import Foundation
import MachOKit

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

/// 字符串分类器：判断 __cstring 中每条字符串的敏感度
public enum StringClassifier {
    /// 必须加密的关键词列表（匹配时大小写不敏感）
    public static let sensitiveKeywords: [String] = [
        "frida", "cydia", "substrate", "sileo", "jailbreak",
        "hook", "inject", "debug", "ptrace", "svc",
        "kernel", "passwd", "shadow", "bash", "ssh",
        "apt", "dpkg", "http",
    ]

    /// 按以下优先级判断字符串敏感度：
    ///  1. 单字符 → skip
    ///  2. 纯数字 → skip
    ///  3. 非 ASCII 可打印 → skip
    ///  4. 包含 "/" 或敏感关键词 → mustEncrypt
    ///  5. ObjC selector 风格（含 ":"） → skip
    ///  6. 长度 ∈ [4, 256] → shouldEncrypt
    ///  7. 其余 → skip
    public static func classify(_ value: String) -> StringSensitivity {
        let length = value.count

        guard length > 1 else { return .skip }

        if value.allSatisfy(\.isNumber) { return .skip }

        let isASCIIPrintable = value.utf8.allSatisfy { byte in
            byte == 0x09 || byte == 0x0A || byte == 0x0D || (0x20...0x7E).contains(byte)
        }
        guard isASCIIPrintable else { return .skip }

        if value.contains("/") { return .mustEncrypt }

        let lower = value.lowercased()
        for keyword in sensitiveKeywords {
            if lower.contains(keyword) { return .mustEncrypt }
        }

        if value.contains(":") { return .skip }

        guard length >= 4, length <= 256 else { return .skip }

        return .shouldEncrypt
    }
}

// MARK: - Pass 1 内部类型

private enum StringBootstrap {
    static let id: UInt32 = 1
    // 仅构建工具侧使用，此字面量不会出现在最终 SDK 二进制中
    static let value = "cprisk-bootstrap-v1"
}

private struct StringRecord {
    let id: UInt32
    let value: String
    /// 原始 __cstring 中的文件偏移量；nil 表示合成的 bootstrap 字符串
    let fileOffset: UInt64?
}

// MARK: - Pass 1: 全量敏感字符串加密

/// Pass 1: 扫描 `__TEXT.__cstring` 中所有字符串，按敏感度分类后将
/// mustEncrypt 和 shouldEncrypt 类别全部加密写入 string table section，
/// 并将原始 `__cstring` 中对应字节零填充，防止 `strings` 工具直接提取。
public final class StringEncryptorPass: ArmorPass {
    public let name = "StringEncryptor"

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        let cStrings = try file.findCStrings()
        let records = buildRecords(from: cStrings)
        let stringKey = deriveStringKey(rootKey: config.encryptionKey)

        var payload = ArmorABI.StringTable.Header(count: UInt32(records.count)).serialized()
        var dataArea = Data()

        for record in records {
            let plaintext = Data(record.value.utf8)
            let encrypted = xor(
                plaintext,
                makeKeystream(key: stringKey, stringID: record.id, length: plaintext.count)
            )

            payload.append(
                ArmorABI.StringTable.IndexEntry(
                    stringID: record.id,
                    dataOffset: UInt32(dataArea.count),
                    dataLength: UInt32(plaintext.count)
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

        // 零填充已加密字符串在原始 __cstring 中的位置，防止 strings 工具提取
        var zeroFilledCount = 0
        for record in records {
            guard let offset = record.fileOffset else { continue }
            let zeroData = Data(repeating: 0, count: record.value.utf8.count)
            try file.replaceBytes(at: offset, with: zeroData)
            zeroFilledCount += 1
        }

        let encryptedFromCString = records.filter { $0.fileOffset != nil }.count
        return PassResult(
            passName: name,
            itemsProcessed: records.count,
            bytesModified: payload.count,
            details: [
                "Wrote encrypted string table to \(ArmorABI.dataSegmentName).\(ArmorABI.StringTable.sectionName)",
                "Bootstrap string id \(StringBootstrap.id) is reserved for runtime key chaining",
                "Encrypted \(encryptedFromCString) __cstring entries (zero-filled \(zeroFilledCount) original positions)",
            ]
        )
    }

    /// 构建加密记录：bootstrap 字符串 + 所有 mustEncrypt/shouldEncrypt 字符串
    private func buildRecords(from cStrings: [(offset: UInt64, value: String)]) -> [StringRecord] {
        var records = [StringRecord(
            id: StringBootstrap.id,
            value: StringBootstrap.value,
            fileOffset: nil
        )]

        for entry in cStrings {
            let sensitivity = StringClassifier.classify(entry.value)
            guard sensitivity != .skip else { continue }
            let nextID = UInt32(records.count + 1)
            records.append(StringRecord(
                id: nextID,
                value: entry.value,
                fileOffset: entry.offset
            ))
        }
        return records
    }
}

// MARK: - 密钥派生与加密辅助（仅构建工具侧使用）

// Build-tool only — this salt does not appear in the final SDK binary.
private func deriveStringKey(rootKey: Data?) -> Data {
    var seed = Data("cprisk.pass1.key.v1".utf8)
    seed.append(normalizedRootKey(rootKey))
    return sha256(seed)
}

private func normalizedRootKey(_ rootKey: Data?) -> Data {
    var key = Data(repeating: 0, count: ArmorABI.keySize)
    guard let rootKey else { return key }

    let prefix = rootKey.prefix(ArmorABI.keySize)
    key.replaceSubrange(0..<prefix.count, with: prefix)
    return key
}

private func makeKeystream(key: Data, stringID: UInt32, length: Int) -> Data {
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

private func xor(_ lhs: Data, _ rhs: Data) -> Data {
    Data(zip(lhs, rhs).map(^))
}

private func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
}
