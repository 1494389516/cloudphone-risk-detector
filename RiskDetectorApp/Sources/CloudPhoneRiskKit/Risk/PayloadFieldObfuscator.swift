import CryptoKit
import Foundation

/// 字段混淆映射配置。
/// 内部语义字段 -> 上报混淆字段。
public struct PayloadFieldMapping: Codable, Sendable {
    /// Depth scope at which key renaming is applied. The previous default
    /// (top-level only) left nested signal dictionaries with literal
    /// names like "jailbreak" / "frida" / "ptrace" — readable on the wire
    /// even when the outer envelope was renamed. Per the P2a red-team
    /// finding, nested signal names ARE the sensitive surface; so the
    /// default is now `all` for any new mapping.
    public enum DepthScope: String, Codable, Sendable {
        /// Only rename top-level keys (legacy behavior). Use only when
        /// downstream parsers depend on nested key stability.
        case topLevel
        /// Rename keys at every nesting depth.
        case all
    }

    public let version: String
    public let mappings: [String: String]
    public let expiresAtMillis: Int64?
    public let depthScope: DepthScope

    private enum CodingKeys: String, CodingKey {
        case version = "v"
        case mappings = "m"
        case expiresAtMillis = "ea"
        case depthScope = "ds"
    }

    /// Default scope is `.topLevel` for backwards compatibility with existing
    /// callers (DecoyFieldInjector, legacy server-pushed mappings). New
    /// integrations that want full nested obfuscation should pass
    /// `depthScope: .all` explicitly, or use `deriveSessionMapping(...)`
    /// which forces .all.
    public init(version: String, mappings: [String: String], expiresAtMillis: Int64? = nil, depthScope: DepthScope = .topLevel) {
        self.version = version
        self.mappings = mappings
        self.expiresAtMillis = expiresAtMillis
        self.depthScope = depthScope
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.version = try c.decode(String.self, forKey: .version)
        self.mappings = try c.decode([String: String].self, forKey: .mappings)
        self.expiresAtMillis = try c.decodeIfPresent(Int64.self, forKey: .expiresAtMillis)
        // Old persisted mappings without `ds` default to `.topLevel` for
        // strict compatibility — server is expected to push a v2 mapping
        // with `ds: "all"` when nested obfuscation is desired.
        self.depthScope = try c.decodeIfPresent(DepthScope.self, forKey: .depthScope) ?? .topLevel
    }

    public func isExpired(nowMillis: Int64 = Int64(Date().timeIntervalSince1970 * 1000)) -> Bool {
        guard let expiresAtMillis else { return false }
        return nowMillis > expiresAtMillis
    }

    /// Validate that the mapping is collision-free in both directions, so
    /// that obfuscate(deobfuscate(x)) == x is well-defined. A duplicate
    /// target value would corrupt deobfuscation.
    public func validate() -> Bool {
        let targets = Array(mappings.values)
        return Set(targets).count == targets.count
    }
}

public enum PayloadFieldObfuscator {
    /// 使用映射将语义字段混淆为上报字段
    public static func obfuscate(jsonData: Data, mapping: PayloadFieldMapping) throws -> Data {
        let object = try JSONSerialization.jsonObject(with: jsonData, options: [.fragmentsAllowed])
        let obfuscated = transform(object, with: mapping.mappings, scope: mapping.depthScope)

        guard JSONSerialization.isValidJSONObject(obfuscated) else {
            throw ReportEnvelope.ReportEnvelopeError.invalidPayload
        }
        return try JSONSerialization.data(withJSONObject: obfuscated, options: [])
    }

    /// 将混淆字段反向恢复为语义字段（用于调试/服务端回溯）
    public static func deobfuscate(jsonData: Data, mapping: PayloadFieldMapping) throws -> Data {
        let pairs = mapping.mappings.map { ($1, $0) }
        let grouped = Dictionary(grouping: pairs, by: { $0.0 })
        if grouped.contains(where: { $0.value.count > 1 }) {
            throw ReportEnvelope.ReportEnvelopeError.invalidPayload
        }
        let reverse = Dictionary(pairs, uniquingKeysWith: { first, _ in first })
        let object = try JSONSerialization.jsonObject(with: jsonData, options: [.fragmentsAllowed])
        let restored = transform(object, with: reverse, scope: mapping.depthScope)

        guard JSONSerialization.isValidJSONObject(restored) else {
            throw ReportEnvelope.ReportEnvelopeError.invalidPayload
        }
        return try JSONSerialization.data(withJSONObject: restored, options: [])
    }

    private static func transform(
        _ value: Any,
        with mapping: [String: String],
        scope: PayloadFieldMapping.DepthScope,
        depth: Int = 0
    ) -> Any {
        if let dictionary = value as? [String: Any] {
            var transformed: [String: Any] = [:]
            transformed.reserveCapacity(dictionary.count)
            for (key, nestedValue) in dictionary {
                // P2a fix: previously only depth==0 keys were renamed, leaving
                // nested signal names ("jailbreak", "frida", "ptrace") visible
                // in cleartext on the wire. Under .all scope every dictionary
                // key consults the mapping; .topLevel preserves legacy behavior
                // for callers that depend on nested key stability.
                let shouldRename: Bool
                switch scope {
                case .all:
                    shouldRename = true
                case .topLevel:
                    shouldRename = (depth == 0)
                }
                let targetKey = shouldRename ? (mapping[key] ?? key) : key
                transformed[targetKey] = transform(nestedValue, with: mapping, scope: scope, depth: depth + 1)
            }
            return transformed
        }

        if let array = value as? [Any] {
            return array.map { transform($0, with: mapping, scope: scope, depth: depth + 1) }
        }

        return value
    }

    /// Derive a session-scoped mapping by renaming each known semantic key to
    /// `HMAC(sessionKey, "cprisk.field.v1" || keyName)[..8].hex`. The server,
    /// holding the same sessionKey, recomputes the same hash and reverses the
    /// mapping. Compared to a static mapping table downloaded from config,
    /// the session-derived form means an attacker's traffic snapshot from one
    /// session yields field names that don't match the next session's traffic
    /// — pattern recognition becomes a per-session reverse-engineering task.
    public static func deriveSessionMapping(
        baseKeys: [String],
        sessionKey: SymmetricKey,
        version: String,
        expiresAtMillis: Int64? = nil
    ) -> PayloadFieldMapping {
        var pairs: [String: String] = [:]
        let label = Data("cprisk.field.v1".utf8)
        for key in baseKeys {
            var msg = Data()
            msg.append(label)
            msg.append(Data(key.utf8))
            let mac = HMAC<SHA256>.authenticationCode(for: msg, using: sessionKey)
            // 8 bytes = 16 hex chars — short enough to keep payloads small,
            // wide enough that collision across the SDK's known-key set
            // (~150 entries) is astronomically unlikely.
            let hex = mac.prefix(8).map { String(format: "%02x", $0) }.joined()
            pairs[key] = hex
        }
        return PayloadFieldMapping(
            version: version,
            mappings: pairs,
            expiresAtMillis: expiresAtMillis,
            depthScope: .all
        )
    }
}
