import CryptoKit
import Foundation

/// 签名密钥编码方式（SDK 5.0 keyResolver 支持）
public enum SigningKeyEncoding: Sendable {
    /// UTF-8 字符串（默认，兼容既有调用）
    case utf8
    /// Hex 编码（用于 DeviceKey 派生场景）
    case hex
}

/// 上报信封，用于防止重放和篡改
/// v2 签名输入：sigVer|nonce|ts(ms)|sessionToken|reportId|keyId|fieldMappingVersion|attestationKeyId|payloadCanonical
public struct ReportEnvelope: Codable, Sendable {

    // MARK: - Properties

    /// 防重放随机数，使用 UUID 字符串
    public let nonce: String

    /// Unix 时间戳（毫秒）
    public let ts: Int64

    /// 服务端下发的会话 Token（建议短期有效）
    public let sessionToken: String

    /// 风险报告内容（JSON 编码后的 payload）
    public let payload: Data

    /// 报告 ID（用于日志定位）
    public let reportId: String

    /// 签名版本（默认 v2）
    public let sigVer: String

    /// 密钥标识（用于密钥轮换）
    public let keyId: String

    /// 字段映射版本（用于字段混淆轮换）
    public let fieldMappingVersion: String?

    /// HMAC-SHA256 签名（hex）
    public let signature: String

    /// App Attest 密钥标识（base64，可选；SDK 4.4 硬件信任根）
    public let attestationKeyId: String?

    /// App Attest 断言数据（可选；Secure Enclave 对 payload 摘要的硬件签名）
    public let attestationAssertion: Data?

    /// 端侧信任等级（SDK 5.0），服务端可据此调整决策权重
    public let trustLevel: TrustLevel?

    /// Re-attestation 断言（SDK 5.0，可选）
    /// 当 shouldRefreshAttestation 且服务端下发 reAttestationChallenge 时，客户端用 App Attest key 签名后填入
    public let reAttestationAssertion: Data?

    /// 是否具备完整硬件信任根（attestationKeyId 与 attestationAssertion 均存在且非空）。
    /// 调用方可用此判断是否发生静默降级；若业务要求硬件信任根，应检查此属性为 true。
    public var hasHardwareAttestation: Bool {
        guard let keyId = attestationKeyId, !keyId.isEmpty else { return false }
        guard let assertion = attestationAssertion, !assertion.isEmpty else { return false }
        return true
    }

    // MARK: - Configuration

    public struct Config: Sendable {
        /// nonce 防重放窗口（毫秒），默认 5 分钟
        public var nonceExpirationMillis: Int64 = 300_000

        /// 允许时间偏差（毫秒），默认 ±5 分钟
        public var timeDriftToleranceMillis: Int64 = 300_000

        /// 当前签名版本
        public var signatureVersion: String = "v2"

        public init(
            nonceExpirationMillis: Int64 = 300_000,
            timeDriftToleranceMillis: Int64 = 300_000,
            signatureVersion: String = "v2"
        ) {
            self.nonceExpirationMillis = nonceExpirationMillis
            self.timeDriftToleranceMillis = timeDriftToleranceMillis
            self.signatureVersion = signatureVersion
        }
    }

    // MARK: - Error

    public enum ReportEnvelopeError: Error, LocalizedError {
        case invalidPayload
        case signatureMismatch
        case replayDetected
        case nonceExpired
        case timestampOutOfRange
        case encodingFailed
        case signingFailed
        /// attestationKeyId 存在但 attestationAssertion 为空，表示硬件信任根不完整（可能被剥离或生成失败）。
        case attestationIncomplete

        public var errorDescription: String? {
            switch self {
            case .invalidPayload:
                return "无效的 payload 数据"
            case .signatureMismatch:
                return "签名验证失败"
            case .replayDetected:
                return "检测到重放请求"
            case .nonceExpired:
                return "Nonce 已过期"
            case .timestampOutOfRange:
                return "时间戳超出允许范围"
            case .encodingFailed:
                return "编码失败"
            case .signingFailed:
                return "签名生成失败"
            case .attestationIncomplete:
                return "attestationKeyId 存在但 attestationAssertion 为空，硬件信任根不完整"
            }
        }
    }

    // MARK: - Codable

    enum CodingKeys: String, CodingKey {
        case nonce
        case ts
        case sessionToken
        case payload
        case reportId
        case sigVer
        case keyId
        case fieldMappingVersion
        case signature
        case attestationKeyId
        case attestationAssertion
        case trustLevel
        case reAttestationAssertion
    }

    public init(
        nonce: String,
        ts: Int64,
        sessionToken: String,
        payload: Data,
        reportId: String,
        sigVer: String,
        keyId: String,
        fieldMappingVersion: String? = nil,
        signature: String,
        attestationKeyId: String? = nil,
        attestationAssertion: Data? = nil,
        trustLevel: TrustLevel? = nil,
        reAttestationAssertion: Data? = nil
    ) {
        self.nonce = nonce
        self.ts = ts
        self.sessionToken = sessionToken
        self.payload = payload
        self.reportId = reportId
        self.sigVer = sigVer
        self.keyId = keyId
        self.fieldMappingVersion = fieldMappingVersion
        self.signature = signature
        self.attestationKeyId = attestationKeyId
        self.attestationAssertion = attestationAssertion
        self.trustLevel = trustLevel
        self.reAttestationAssertion = reAttestationAssertion
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        nonce = try container.decode(String.self, forKey: .nonce)
        ts = try container.decode(Int64.self, forKey: .ts)
        sessionToken = try container.decode(String.self, forKey: .sessionToken)
        payload = try container.decode(Data.self, forKey: .payload)
        reportId = try container.decode(String.self, forKey: .reportId)
        sigVer = try container.decodeIfPresent(String.self, forKey: .sigVer) ?? "v1"
        keyId = try container.decodeIfPresent(String.self, forKey: .keyId) ?? "k1"
        fieldMappingVersion = try container.decodeIfPresent(String.self, forKey: .fieldMappingVersion)
        signature = try container.decode(String.self, forKey: .signature)
        attestationKeyId = try container.decodeIfPresent(String.self, forKey: .attestationKeyId)
        attestationAssertion = try container.decodeIfPresent(Data.self, forKey: .attestationAssertion)
        trustLevel = try container.decodeIfPresent(TrustLevel.self, forKey: .trustLevel)
        reAttestationAssertion = try container.decodeIfPresent(Data.self, forKey: .reAttestationAssertion)
    }

    // MARK: - Factory

    /// 从风险报告创建 ReportEnvelope
    /// - Parameters:
    ///   - payloadData: 原始 payload（JSON）
    ///   - reportId: 报告 ID
    ///   - sessionToken: 服务端下发会话 token
    ///   - signingKey: HMAC 密钥
    ///   - keyId: 密钥标识
    ///   - fieldMapping: 字段混淆映射（可选）
    ///   - attestationKeyId: App Attest 密钥 ID（可选）
    ///   - trustLevel: 端侧信任等级（SDK 5.0），Keychain 被清或 attestation 过期时应传 .degraded
    ///   - config: 签名配置
    public static func create(
        payloadData: Data,
        reportId: String,
        sessionToken: String,
        signingKey: String,
        keyId: String = "k1",
        fieldMapping: PayloadFieldMapping? = nil,
        attestationKeyId: String? = nil,
        trustLevel: TrustLevel? = nil,
        config: Config = Config()
    ) throws -> ReportEnvelope {
        let nonce = UUID().uuidString
        let ts = currentTimestampMillis()

        let effectivePayload: Data
        if let mapping = fieldMapping {
            effectivePayload = try PayloadFieldObfuscator.obfuscate(jsonData: payloadData, mapping: mapping)
        } else {
            effectivePayload = payloadData
        }

        let canonicalPayload = try canonicalJSONString(from: effectivePayload)
        let signatureInput = buildSignatureInput(
            sigVer: config.signatureVersion,
            nonce: nonce,
            ts: ts,
            sessionToken: sessionToken,
            reportId: reportId,
            keyId: keyId,
            fieldMappingVersion: fieldMapping?.version,
            attestationKeyId: attestationKeyId,
            canonicalPayload: canonicalPayload
        )

        guard let signatureData = signatureInput.data(using: .utf8) else {
            throw ReportEnvelopeError.signingFailed
        }
        guard var keyData = signingKey.data(using: .utf8) else {
            throw ReportEnvelopeError.signingFailed
        }
        defer { secureZeroData(&keyData) }

        let signatureHex = hmacHex(message: signatureData, keyData: keyData)

        return ReportEnvelope(
            nonce: nonce,
            ts: ts,
            sessionToken: sessionToken,
            payload: effectivePayload,
            reportId: reportId,
            sigVer: config.signatureVersion,
            keyId: keyId,
            fieldMappingVersion: fieldMapping?.version,
            signature: signatureHex,
            attestationKeyId: attestationKeyId,
            attestationAssertion: nil,
            trustLevel: trustLevel
        )
    }

    /// 返回带 App Attest 断言的副本（SDK 4.4）
    /// attestationKeyId 必须在 create() 时已传入并纳入签名域，此处仅附加断言数据。
    /// 返回带 App Attest 断言的副本（SDK 4.4），trustLevel 设为 .hardware
    public func withAttestation(attestationKeyId: String, assertion: Data) -> ReportEnvelope {
        ReportEnvelope(
            nonce: nonce,
            ts: ts,
            sessionToken: sessionToken,
            payload: payload,
            reportId: reportId,
            sigVer: sigVer,
            keyId: self.keyId,
            fieldMappingVersion: fieldMappingVersion,
            signature: signature,
            attestationKeyId: attestationKeyId,
            attestationAssertion: assertion,
            trustLevel: .hardware,
            reAttestationAssertion: reAttestationAssertion
        )
    }

    /// 设置信任等级（SDK 5.0）
    public func withTrustLevel(_ level: TrustLevel) -> ReportEnvelope {
        ReportEnvelope(
            nonce: nonce,
            ts: ts,
            sessionToken: sessionToken,
            payload: payload,
            reportId: reportId,
            sigVer: sigVer,
            keyId: keyId,
            fieldMappingVersion: fieldMappingVersion,
            signature: signature,
            attestationKeyId: attestationKeyId,
            attestationAssertion: attestationAssertion,
            trustLevel: level,
            reAttestationAssertion: reAttestationAssertion
        )
    }

    /// 附加 re-attestation 断言（SDK 5.0）
    public func withReAttestationAssertion(_ assertion: Data?) -> ReportEnvelope {
        ReportEnvelope(
            nonce: nonce,
            ts: ts,
            sessionToken: sessionToken,
            payload: payload,
            reportId: reportId,
            sigVer: sigVer,
            keyId: keyId,
            fieldMappingVersion: fieldMappingVersion,
            signature: signature,
            attestationKeyId: attestationKeyId,
            attestationAssertion: attestationAssertion,
            trustLevel: trustLevel,
            reAttestationAssertion: assertion
        )
    }

    // MARK: - Parser

    public static func fromJSON(_ data: Data) throws -> ReportEnvelope {
        try JSONDecoder().decode(ReportEnvelope.self, from: data)
    }

    public static func fromJSON(_ jsonString: String) throws -> ReportEnvelope {
        guard let data = jsonString.data(using: .utf8) else {
            throw ReportEnvelopeError.invalidPayload
        }
        return try fromJSON(data)
    }

    // MARK: - Verification

    /// 通过 key resolver 验签（支持 key rotation）
    /// - Parameter keyEncoding: 密钥编码，.utf8 为 UTF-8 字符串，.hex 为 hex 编码（用于 DeviceKey 派生场景）
    public func verifySignature(
        using keyResolver: (String) -> String?,
        keyEncoding: SigningKeyEncoding = .utf8
    ) -> Bool {
        guard let signingKey = keyResolver(keyId) else {
            return false
        }
        return verifySignature(signingKey, keyEncoding: keyEncoding)
    }

    /// 验签（支持 hex 编码密钥）
    public func verifySignature(_ signingKey: String, keyEncoding: SigningKeyEncoding = .utf8) -> Bool {
        let keyData: Data?
        switch keyEncoding {
        case .utf8:
            keyData = signingKey.data(using: .utf8)
        case .hex:
            keyData = Data(hexString: signingKey)
        }
        guard let keyData else { return false }
        return verifySignature(keyData: keyData)
    }

    /// 验签（内部实现，使用 Data 密钥）
    private func verifySignature(keyData: Data) -> Bool {
        guard let canonicalPayload = try? Self.canonicalJSONString(from: payload) else {
            return false
        }
        let signatureInput = Self.buildSignatureInput(
            sigVer: sigVer,
            nonce: nonce,
            ts: ts,
            sessionToken: sessionToken,
            reportId: reportId,
            keyId: keyId,
            fieldMappingVersion: fieldMappingVersion,
            attestationKeyId: attestationKeyId,
            canonicalPayload: canonicalPayload
        )
        guard let signatureData = signatureInput.data(using: .utf8) else {
            return false
        }
        let expectedSignature = Self.hmacHex(message: signatureData, keyData: keyData)
        return timingSafeCompare(expectedSignature, signature)
    }

    /// 检查 nonce 是否超时
    public func isExpired(_ config: Config = Config()) -> Bool {
        let now = Self.currentTimestampMillis()
        return abs(now - ts) > config.nonceExpirationMillis
    }

    /// 检查时间戳是否在允许范围内
    public func isTimestampValid(_ config: Config = Config()) -> Bool {
        let now = Self.currentTimestampMillis()
        return abs(now - ts) <= config.timeDriftToleranceMillis
    }

    /// 完整验证：时钟 + 签名 + 重放窗口
    public func validate(
        signingKey: String,
        nonceStore: NonceReplayProtecting? = nil,
        config: Config = Config()
    ) -> Result<Void, ReportEnvelopeError> {
        guard isTimestampValid(config) else {
            return .failure(.timestampOutOfRange)
        }

        guard verifySignature(signingKey) else {
            return .failure(.signatureMismatch)
        }

        guard !isExpired(config) else {
            return .failure(.nonceExpired)
        }

        if let nonceStore {
            let expiresAt = ts + config.nonceExpirationMillis
            let consumed = nonceStore.consumeIfNew(
                sessionToken: sessionToken,
                nonce: nonce,
                expiresAtMillis: expiresAt
            )
            guard consumed else {
                return .failure(.replayDetected)
            }
        }

        return .success(())
    }

    /// 完整验证：通过 key resolver 验签（支持 key rotation）
    public func validate(
        keyResolver: (String) -> String?,
        nonceStore: NonceReplayProtecting? = nil,
        config: Config = Config()
    ) -> Result<Void, ReportEnvelopeError> {
        let resolved = keyResolver(keyId)        guard let signingKey = resolved else {
            return .failure(.signingFailed)
        }
        return validate(signingKey: signingKey, nonceStore: nonceStore, config: config)
    }

    // MARK: - JSON

    public func toJSONData(prettyPrinted: Bool = false) throws -> Data {
        let encoder = JSONEncoder()
        if prettyPrinted {
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        }
        return try encoder.encode(self)
    }

    public func toJSONString(prettyPrinted: Bool = false) throws -> String {
        let data = try toJSONData(prettyPrinted: prettyPrinted)
        guard let string = String(data: data, encoding: .utf8) else {
            throw ReportEnvelopeError.encodingFailed
        }
        return string
    }

    // MARK: - Internals

    public func canonicalPayloadString() throws -> String {
        try Self.canonicalJSONString(from: payload)
    }

    /// v2 签名输入：sigVer|nonce|ts|sessionToken|reportId|keyId|fieldMappingVersion|attestationKeyId|canonicalPayload
    /// canonicalPayload 为 payload 的规范 JSON，已包含 compressedDigestHex、signalMappingVersion 等字段，故压缩摘要已纳入签名域。
    private static func buildSignatureInput(
        sigVer: String,
        nonce: String,
        ts: Int64,
        sessionToken: String,
        reportId: String,
        keyId: String,
        fieldMappingVersion: String?,
        attestationKeyId: String?,
        canonicalPayload: String
    ) -> String {
        let fmv = fieldMappingVersion ?? ""
        let akId = attestationKeyId ?? ""
        return "\(sigVer)|\(nonce)|\(ts)|\(sessionToken)|\(reportId)|\(keyId)|\(fmv)|\(akId)|\(canonicalPayload)"
    }

    private static func hmacHex(message: Data, keyData: Data) -> String {
        let key = SymmetricKey(data: keyData)
        let digest = HMAC<SHA256>.authenticationCode(for: message, using: key)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func currentTimestampMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }

    private static func canonicalJSONString(from payloadData: Data) throws -> String {
        let object = try JSONSerialization.jsonObject(with: payloadData, options: [.fragmentsAllowed])
        guard JSONSerialization.isValidJSONObject(object) else {
            throw ReportEnvelopeError.invalidPayload
        }
        let canonical = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        guard let canonicalString = String(data: canonical, encoding: .utf8) else {
            throw ReportEnvelopeError.encodingFailed
        }
        return canonicalString
    }

    private func timingSafeCompare(_ lhs: String, _ rhs: String) -> Bool {
        guard lhs.count == rhs.count else { return false }

        let lhsBytes = Array(lhs.utf8)
        let rhsBytes = Array(rhs.utf8)
        var result: UInt8 = 0

        for i in 0..<lhsBytes.count {
            result |= lhsBytes[i] ^ rhsBytes[i]
        }

        return result == 0
    }
}

// MARK: - Replay Protection

/// 服务器侧/网关侧推荐实现；SDK 内提供内存实现用于联调和测试。
public protocol NonceReplayProtecting: AnyObject {
    /// - Returns: true 表示首次消费；false 表示已见过（重放）
    func consumeIfNew(sessionToken: String, nonce: String, expiresAtMillis: Int64) -> Bool
}

public final class InMemoryNonceReplayStore: NonceReplayProtecting {
    private var storage: [String: Int64] = [:]
    private let lock = NSLock()

    public init() {}

    public func consumeIfNew(sessionToken: String, nonce: String, expiresAtMillis: Int64) -> Bool {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let key = "\(sessionToken):\(nonce)"

        lock.lock()
        defer { lock.unlock() }

        // 惰性清理过期项
        storage = storage.filter { $0.value > now }

        if storage[key] != nil {
            return false
        }

        storage[key] = expiresAtMillis
        return true
    }
}

// MARK: - Convenience

#if DEBUG
extension ReportEnvelope {
    /// Test-only convenience; excluded from Release builds.
    @available(*, deprecated, message: "仅用于测试，请使用带 signingKey 参数的方法")
    public static func createForTesting(
        payloadData: Data,
        reportId: String
    ) throws -> ReportEnvelope {
        try create(
            payloadData: payloadData,
            reportId: reportId,
            sessionToken: "test-token",
            signingKey: "default-test-key"
        )
    }
}
#endif
