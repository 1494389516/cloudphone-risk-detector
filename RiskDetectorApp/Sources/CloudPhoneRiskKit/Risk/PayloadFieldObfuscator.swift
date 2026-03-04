import Foundation

/// 字段混淆映射配置。
/// 内部语义字段 -> 上报混淆字段。
public struct PayloadFieldMapping: Codable, Sendable {
    public let version: String
    public let mappings: [String: String]
    public let expiresAtMillis: Int64?

    public init(version: String, mappings: [String: String], expiresAtMillis: Int64? = nil) {
        self.version = version
        self.mappings = mappings
        self.expiresAtMillis = expiresAtMillis
    }

    public func isExpired(nowMillis: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> Bool {
        guard let expiresAtMillis else { return false }
        return nowMillis > expiresAtMillis
    }
}

public enum PayloadFieldObfuscator {
    /// 使用映射将语义字段混淆为上报字段
    public static func obfuscate(jsonData: Data, mapping: PayloadFieldMapping) throws -> Data {
        let object = try JSONSerialization.jsonObject(with: jsonData, options: [.fragmentsAllowed])
        let obfuscated = transform(object, with: mapping.mappings)

        guard JSONSerialization.isValidJSONObject(obfuscated) else {
            throw ReportEnvelope.ReportEnvelopeError.invalidPayload
        }
        return try JSONSerialization.data(withJSONObject: obfuscated, options: [])
    }

    /// 将混淆字段反向恢复为语义字段（用于调试/服务端回溯）
    public static func deobfuscate(jsonData: Data, mapping: PayloadFieldMapping) throws -> Data {
        let reverse = Dictionary(uniqueKeysWithValues: mapping.mappings.map { ($1, $0) })
        let object = try JSONSerialization.jsonObject(with: jsonData, options: [.fragmentsAllowed])
        let restored = transform(object, with: reverse)

        guard JSONSerialization.isValidJSONObject(restored) else {
            throw ReportEnvelope.ReportEnvelopeError.invalidPayload
        }
        return try JSONSerialization.data(withJSONObject: restored, options: [])
    }

    private static func transform(_ value: Any, with mapping: [String: String]) -> Any {
        if let dictionary = value as? [String: Any] {
            var transformed: [String: Any] = [:]
            transformed.reserveCapacity(dictionary.count)
            for (key, nestedValue) in dictionary {
                let targetKey = mapping[key] ?? key
                transformed[targetKey] = transform(nestedValue, with: mapping)
            }
            return transformed
        }

        if let array = value as? [Any] {
            return array.map { transform($0, with: mapping) }
        }

        return value
    }
}
