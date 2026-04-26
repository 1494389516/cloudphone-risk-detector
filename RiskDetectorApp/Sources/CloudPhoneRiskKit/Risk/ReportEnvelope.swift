import CRiskCore
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

    /// 基于 SHA-256 的自定义 MAC 签名（hex）
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

    /// 材料绑定模式可观测值。
    /// `plain_hmac_v1` 表示常规 HMAC，`armor_request_binding_sha256_v1` 表示 CRiskCore 派生密钥 + request-binding，
    /// `plain_hmac_fallback_v1` 表示降级回普通 HMAC。
    public let bindingMode: String?

    /// 对签名输入做 SHA-256 后的 hex 摘要，用于观测 v2/v2a/v2d 的材料绑定上下文。
    /// 该值不是额外密钥材料，但可以帮助区分“签名不匹配”与“签名输入/绑定上下文漂移”。
    public let bindingDigest: String?

    /// 是否具备完整硬件信任根（attestationKeyId 与 attestationAssertion 均存在且非空）。
    /// 调用方可用此判断是否发生静默降级；若业务要求硬件信任根，应检查此属性为 true。
    public var hasHardwareAttestation: Bool {
        guard let keyId = attestationKeyId, !keyId.isEmpty else { return false }
        guard let assertion = attestationAssertion, !assertion.isEmpty else { return false }
        return true
    }

    public struct MaterialBindingObservation: Sendable, Equatable {
        public let mode: String?
        public let envelopeDigestHex: String?
        public let recomputedDigestHex: String
        public let isPresent: Bool
        public let isConsistent: Bool
        public let failureReason: String?

        public init(
            mode: String?,
            envelopeDigestHex: String?,
            recomputedDigestHex: String,
            isPresent: Bool,
            isConsistent: Bool,
            failureReason: String?
        ) {
            self.mode = mode
            self.envelopeDigestHex = envelopeDigestHex
            self.recomputedDigestHex = recomputedDigestHex
            self.isPresent = isPresent
            self.isConsistent = isConsistent
            self.failureReason = failureReason
        }
    }

    // MARK: - Configuration

    public struct Config: Sendable {
        /// nonce 防重放窗口（毫秒），默认 5 分钟
        public var nonceExpirationMillis: Int64 = 300_000

        /// 允许时间偏差（毫秒），默认 ±5 分钟
        public var timeDriftToleranceMillis: Int64 = 300_000

        /// 当前签名版本
        /// `v2h` — HKDF per-request key derivation on top of base HMAC (default, SDK 5.1+)
        /// `v2`  — plain HMAC with static key (legacy, kept for backward compatibility)
        /// `v2a` — armor CRiskCore-derived request binding
        public var signatureVersion: String = "v2h"

        /// When `true`, `create()` rejects requests that lack an `attestationKeyId`
        /// and `toGrpcRequestBytes()` / `toCompressedGrpcRequestBytes()` reject
        /// envelopes where `hasHardwareAttestation == false`.
        ///
        /// Set to `true` for high-risk operations (payment, account takeover
        /// prevention) where a hardware trust root is mandatory.
        /// Default: `false` — attestation is optional and advisory.
        public var requireHardwareAttestation: Bool = false

        public init(
            nonceExpirationMillis: Int64 = 300_000,
            timeDriftToleranceMillis: Int64 = 300_000,
            signatureVersion: String = "v2h",
            requireHardwareAttestation: Bool = false
        ) {
            self.nonceExpirationMillis = nonceExpirationMillis
            self.timeDriftToleranceMillis = timeDriftToleranceMillis
            self.signatureVersion = signatureVersion
            self.requireHardwareAttestation = requireHardwareAttestation
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
        case nonce = "n"
        case ts = "t"
        case sessionToken = "st"
        case payload = "p"
        case reportId = "ri"
        case sigVer = "sv"
        case keyId = "ki"
        case fieldMappingVersion = "fm"
        case signature = "sg"
        case attestationKeyId = "ak"
        case attestationAssertion = "aa"
        case trustLevel = "tl"
        case reAttestationAssertion = "ra"
        case bindingMode = "bm"
        case bindingDigest = "bd"
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
        reAttestationAssertion: Data? = nil,
        bindingMode: String? = nil,
        bindingDigest: String? = nil
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
        self.bindingMode = bindingMode
        self.bindingDigest = bindingDigest
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
        bindingMode = try container.decodeIfPresent(String.self, forKey: .bindingMode)
        bindingDigest = try container.decodeIfPresent(String.self, forKey: .bindingDigest)
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
        attestationAssertion: Data? = nil,
        reAttestationAssertion: Data? = nil,
        trustLevel: TrustLevel? = nil,
        config: Config = Config()
    ) throws -> ReportEnvelope {
        try create(
            payloadData: payloadData,
            reportId: reportId,
            sessionToken: sessionToken,
            signingKey: signingKey,
            keyId: keyId,
            fieldMapping: fieldMapping,
            attestationKeyId: attestationKeyId,
            attestationAssertion: attestationAssertion,
            reAttestationAssertion: reAttestationAssertion,
            trustLevel: trustLevel,
            config: config,
            signatureProvider: nil
        )
    }

    internal static func create(
        payloadData: Data,
        reportId: String,
        sessionToken: String,
        signingKey: String,
        keyId: String = "k1",
        fieldMapping: PayloadFieldMapping? = nil,
        attestationKeyId: String? = nil,
        attestationAssertion: Data? = nil,
        reAttestationAssertion: Data? = nil,
        trustLevel: TrustLevel? = nil,
        config: Config = Config(),
        signatureProvider: ((Data) throws -> String)?,
        bindingMode: String? = nil
    ) throws -> ReportEnvelope {
        let nonce = UUID().uuidString
        let ts = currentTimestampMillis()

        // Sanity-check the device clock at creation time: only the lower bound
        // (≥ 2020-01-01T00:00:00Z, i.e. 1_577_836_800_000 ms) is enforced here.
        // The upper bound (not too far in the future) is checked by the verifier
        // via isTimestampValid().  A clock stuck at epoch 0 or wrong by years is
        // caught before the server ever sees the envelope, giving a clearer error
        // than a silent timestampOutOfRange on the server side.
        let minReasonableTs: Int64 = 1_577_836_800_000  // 2020-01-01 UTC
        guard ts >= minReasonableTs else {
            throw ReportEnvelopeError.timestampOutOfRange
        }

        // Attestation enforcement: if the caller requires a hardware trust root,
        // the attestationKeyId must be provided at create() time (it is included
        // in the signature domain).  The assertion itself is added post-create via
        // withAttestation(); callers should call envelope.requireAttestation()
        // before transmitting to ensure it is complete.
        if config.requireHardwareAttestation && (attestationKeyId == nil || attestationKeyId!.isEmpty) {
            throw ReportEnvelopeError.attestationIncomplete
        }

        // Client-side nonce deduplication: guard against UUID-generator
        // tampering or accidental envelope reuse within the replay window.
        guard ClientNonceWindow.shared.registerIfNew(nonce, ts: ts) else {
            throw ReportEnvelopeError.replayDetected
        }

        let effectivePayload: Data
        if let mapping = fieldMapping {
            effectivePayload = try PayloadFieldObfuscator.obfuscate(jsonData: payloadData, mapping: mapping)
        } else {
            effectivePayload = payloadData
        }

        let canonicalPayload = try canonicalJSONString(from: effectivePayload)
        // For v3, the signature domain includes self-reported envelope fields
        // (trustLevel + assertion digests).  Callers must finalise these BEFORE
        // signing — i.e., pass the intended trustLevel here, and the assertion
        // (if any) must be obtained from AppAttestSigner.generateAssertion()
        // *before* calling create() so its digest can be bound into the HMAC.
        // For v2/v2a/v2d/v2h, these arguments are ignored in the signature
        // domain (legacy behaviour preserved).
        let signatureInput = buildSignatureInput(
            sigVer: config.signatureVersion,
            nonce: nonce,
            ts: ts,
            sessionToken: sessionToken,
            reportId: reportId,
            keyId: keyId,
            fieldMappingVersion: fieldMapping?.version,
            attestationKeyId: attestationKeyId,
            canonicalPayload: canonicalPayload,
            trustLevel: trustLevel,
            attestationAssertion: attestationAssertion,
            reAttestationAssertion: reAttestationAssertion
        )

        let signatureData = try signatureInputData(from: signatureInput)
        let bindingDigest = Self.bindingDigestHex(for: signatureData)
        let signatureHex: String
        if let signatureProvider {
            signatureHex = try signatureProvider(signatureData)
        } else {
            guard var baseKeyData = signingKey.data(using: .utf8) else {
                throw ReportEnvelopeError.signingFailed
            }
            defer { secureZeroData(&baseKeyData) }
            if config.signatureVersion == "v2h" {
                // HKDF per-request key derivation (v2h only): effective key =
                // HKDF(IKM=signingKey, salt=nonce|ts, info="cprisk.report.hmac.v2h").
                // Each envelope gets a unique effective key, preventing statistical
                // HMAC key recovery from a corpus of (input, MAC) pairs.
                var derivedKey = Self.hkdfDerivedKey(baseKey: baseKeyData, nonce: nonce, ts: ts)
                defer { secureZeroData(&derivedKey) }
                signatureHex = hmacHex(message: signatureData, keyData: derivedKey)
            } else {
                signatureHex = hmacHex(message: signatureData, keyData: baseKeyData)
            }
        }

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
            // For v3 the assertion bytes were folded into the HMAC, so the envelope
            // emits them at signing time (callers must NOT use withAttestation()
            // afterwards to swap them out).  For legacy versions, assertion is
            // attached post-signing via withAttestation() as before.
            attestationAssertion: attestationAssertion,
            trustLevel: trustLevel,
            reAttestationAssertion: reAttestationAssertion,
            bindingMode: bindingMode ?? defaultBindingMode(signatureProviderPresent: signatureProvider != nil, sigVer: config.signatureVersion),
            bindingDigest: bindingDigest
        )
    }

    /// 返回带 App Attest 断言的副本（SDK 4.4）
    /// attestationKeyId 必须在 create() 时已传入并纳入签名域，此处仅附加断言数据。
    /// 返回带 App Attest 断言的副本（SDK 4.4），trustLevel 设为 .hardware
    ///
    /// ⚠️ v3 (SDK 7.5+): 该路径仅适用于 v2/v2a/v2d/v2h legacy 签名版本。
    /// v3 把 assertion 字节摘要纳入签名域，必须在 `create()` 时传入 `attestationAssertion`，
    /// 不能在签名后通过本方法附加。若 envelope 是 v3，此处静默忽略写入并返回原值，
    /// 防止破坏 HMAC（导致 envelope 验签失败）。
    public func withAttestation(attestationKeyId: String, assertion: Data) -> ReportEnvelope {
        if sigVer == "v3" {
            // v3 demands assertion bytes are in the HMAC domain at signing time;
            // mutating them post-sign would invalidate the signature.  Caller
            // must use create(attestationAssertion:) instead.
            return self
        }
        return ReportEnvelope(
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
            reAttestationAssertion: reAttestationAssertion,
            bindingMode: bindingMode,
            bindingDigest: bindingDigest
        )
    }

    /// 设置信任等级（SDK 5.0）
    ///
    /// ⚠️ v3 (SDK 7.5+): trustLevel 已纳入签名域，签名后修改会破坏 HMAC。
    /// 必须在 `create(trustLevel:)` 时传入正确值；该方法对 v3 envelope 静默 no-op。
    public func withTrustLevel(_ level: TrustLevel) -> ReportEnvelope {
        if sigVer == "v3" {
            return self
        }
        return ReportEnvelope(
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
            reAttestationAssertion: reAttestationAssertion,
            bindingMode: bindingMode,
            bindingDigest: bindingDigest
        )
    }

    /// 附加 re-attestation 断言（SDK 5.0）
    ///
    /// ⚠️ v3: reAttestationAssertion 已纳入签名域，需在 `create()` 时传入；v3 此方法 no-op。
    public func withReAttestationAssertion(_ assertion: Data?) -> ReportEnvelope {
        if sigVer == "v3" {
            return self
        }
        return _withReAttestationAssertionLegacy(assertion)
    }

    private func _withReAttestationAssertionLegacy(_ assertion: Data?) -> ReportEnvelope {
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
            reAttestationAssertion: assertion,
            bindingMode: bindingMode,
            bindingDigest: bindingDigest
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

    // MARK: - Attestation Enforcement

    /// Throws `.attestationIncomplete` if this envelope does not carry a complete
    /// hardware attestation pair (`attestationKeyId` + `attestationAssertion`).
    ///
    /// Call this **before** `toGrpcRequestBytes()` when transmitting envelopes
    /// for high-risk operations that mandate App Attest hardware trust roots:
    /// ```swift
    /// let envelope = try ReportEnvelope.create(..., attestationKeyId: keyId)
    ///     .withAttestation(attestationKeyId: keyId, assertion: assertion)
    /// try envelope.requireAttestation()   // throws if assertion missing
    /// let bytes = try envelope.toGrpcRequestBytes()
    /// ```
    public func requireAttestation() throws {
        guard hasHardwareAttestation else {
            throw ReportEnvelopeError.attestationIncomplete
        }
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
        // For v2h: mirror the HKDF derivation used in create() so the effective
        // verification key matches.  For v1/v2/v2a/v2d: use the raw key as before.
        var effectiveKey: Data
        if sigVer == "v2h" {
            effectiveKey = Self.hkdfDerivedKey(baseKey: keyData, nonce: nonce, ts: ts)
        } else {
            effectiveKey = keyData
        }
        defer { secureZeroData(&effectiveKey) }
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
            canonicalPayload: canonicalPayload,
            trustLevel: trustLevel,
            attestationAssertion: attestationAssertion,
            reAttestationAssertion: reAttestationAssertion
        )
        guard let signatureData = try? Self.signatureInputData(from: signatureInput) else {
            return false
        }
        let bindingObservation = materialBindingObservation(
            signatureInputData: signatureData
        )
        guard bindingObservation.isConsistent else {
            return false
        }
        let expectedSignature = Self.hmacHex(message: signatureData, keyData: effectiveKey)
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

    internal func validate(
        signatureValidator: (Data, String) -> Bool,
        nonceStore: NonceReplayProtecting? = nil,
        config: Config = Config()
    ) -> Result<Void, ReportEnvelopeError> {
        guard isTimestampValid(config) else {
            return .failure(.timestampOutOfRange)
        }

        guard let canonicalPayload = try? Self.canonicalJSONString(from: payload) else {
            return .failure(.signatureMismatch)
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
            canonicalPayload: canonicalPayload,
            trustLevel: trustLevel,
            attestationAssertion: attestationAssertion,
            reAttestationAssertion: reAttestationAssertion
        )
        guard let signatureData = try? Self.signatureInputData(from: signatureInput) else {
            return .failure(.signatureMismatch)
        }
        let bindingObservation = materialBindingObservation(
            signatureInputData: signatureData
        )
        guard bindingObservation.isConsistent else {
            return .failure(.signatureMismatch)
        }
        guard
              signatureValidator(signatureData, signature) else {
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
        let resolved = keyResolver(keyId)
        guard let signingKey = resolved else {
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

    /// 对外暴露稳定的绑定诊断字段，便于日志、灰度和服务端回溯。
    /// 不包含密钥材料，只暴露签名输入 / material binding 的可观测摘要。
    public func bindingDiagnostics() -> [String: String] {
        let payloadRawDigestHex = Self.sha256Hex(payload)
        let canonicalPayload = try? Self.canonicalJSONString(from: payload)
        let canonicalPayloadDigestHex = canonicalPayload.map { Self.sha256Hex(Data($0.utf8)) } ?? "unavailable"

        let signatureInputDigestHex: String
        if let canonicalPayload {
            let signatureInput = Self.buildSignatureInput(
                sigVer: sigVer,
                nonce: nonce,
                ts: ts,
                sessionToken: sessionToken,
                reportId: reportId,
                keyId: keyId,
                fieldMappingVersion: fieldMappingVersion,
                attestationKeyId: attestationKeyId,
                canonicalPayload: canonicalPayload,
                trustLevel: trustLevel,
                attestationAssertion: attestationAssertion,
                reAttestationAssertion: reAttestationAssertion
            )
            signatureInputDigestHex = Self.sha256Hex(Data(signatureInput.utf8))
        } else {
            signatureInputDigestHex = "unavailable"
        }

        let bindingObservation = materialBindingObservation()
        var rows: [String: String] = [
            "sig_ver": sigVer,
            "key_id": keyId,
            "payload_raw_sha256": payloadRawDigestHex,
            "payload_canonical_sha256": canonicalPayloadDigestHex,
            "signature_input_sha256": signatureInputDigestHex,
            "binding_mode": bindingMode ?? inferredBindingMode(for: sigVer),
            "binding_digest_present": bindingDigest == nil ? "0" : "1",
            "binding_digest_consistent": bindingObservation.isConsistent ? "1" : "0",
            "binding_digest_failure_reason": bindingObservation.failureReason ?? "none",
            "attestation_pair_state": attestationPairState(),
            "trust_level": trustLevel?.rawValue ?? "nil",
            "field_mapping_version": fieldMappingVersion ?? "",
        ]

        if let digest = bindingObservation.envelopeDigestHex {
            rows["binding_digest_hex"] = digest
        }
        rows["binding_digest_recomputed_hex"] = bindingObservation.recomputedDigestHex

        let payloadMetadata = payloadBindingMetadata()
        rows["signals_digest_present"] = payloadMetadata.signalsDigestPresent ? "1" : "0"
        if let version = payloadMetadata.signalsDigestVersion {
            rows["signals_digest_version"] = version
        }
        if let digest = payloadMetadata.signalsDigest {
            rows["signals_digest"] = digest
        }

        return rows
    }

    /// 返回 envelope 当前的材料绑定观测结果。
    /// 旧版本 envelope 若未携带 `bindingMode` / `bindingDigest`，`isPresent == false` 且不会判为不一致。
    public func materialBindingObservation() -> MaterialBindingObservation {
        guard let canonicalPayload = try? Self.canonicalJSONString(from: payload) else {
            return MaterialBindingObservation(
                mode: bindingMode,
                envelopeDigestHex: bindingDigest,
                recomputedDigestHex: "",
                isPresent: bindingMode != nil || bindingDigest != nil,
                isConsistent: false,
                failureReason: "payload_canonicalization_failed"
            )
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
            canonicalPayload: canonicalPayload,
            trustLevel: trustLevel,
            attestationAssertion: attestationAssertion,
            reAttestationAssertion: reAttestationAssertion
        )
        guard let signatureData = try? Self.signatureInputData(from: signatureInput) else {
            return MaterialBindingObservation(
                mode: bindingMode,
                envelopeDigestHex: bindingDigest,
                recomputedDigestHex: "",
                isPresent: bindingMode != nil || bindingDigest != nil,
                isConsistent: false,
                failureReason: "signature_input_encoding_failed"
            )
        }
        return materialBindingObservation(signatureInputData: signatureData)
    }

    /// v2 签名输入：sigVer|nonce|ts|sessionToken|reportId|keyId|fieldMappingVersion|attestationKeyId|canonicalPayload
    /// v3 签名输入：v2 字段 + trustLevel + sha256(attestationAssertion) + sha256(reAttestationAssertion)
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
        canonicalPayload: String,
        trustLevel: TrustLevel? = nil,
        attestationAssertion: Data? = nil,
        reAttestationAssertion: Data? = nil
    ) -> String {
        let fmv = fieldMappingVersion ?? ""
        let akId = attestationKeyId ?? ""
        // v3 binds previously-unsigned envelope fields (trustLevel + assertion bytes)
        // into the HMAC domain so an attacker holding the signing key cannot tamper
        // these self-reported fields after signing without breaking the signature.
        // See SHA-256("") trap analysis: any field NOT in this domain is forgeable.
        if sigVer == "v3" {
            let tl = trustLevel?.rawValue ?? ""
            let aaHex = attestationAssertion.map { sha256Hex($0) } ?? ""
            let raHex = reAttestationAssertion.map { sha256Hex($0) } ?? ""
            return "\(sigVer)|\(nonce)|\(ts)|\(sessionToken)|\(reportId)|\(keyId)|\(fmv)|\(akId)|\(tl)|\(aaHex)|\(raHex)|\(canonicalPayload)"
        }
        return "\(sigVer)|\(nonce)|\(ts)|\(sessionToken)|\(reportId)|\(keyId)|\(fmv)|\(akId)|\(canonicalPayload)"
    }

    private static func hmacHex(message: Data, keyData: Data) -> String {
        CPRiskMessageAuth.authenticationCodeHex(for: message, keyData: keyData)
    }

    /// Derives a 32-byte per-request HMAC key using HKDF-SHA-256.
    ///
    /// `IKM`  = static `baseKey` provided by the caller
    /// `salt` = `"<nonce>|<ts>"` — unique per envelope, prevents key reuse
    /// `info` = `"cprisk.report.hmac.v2h"` || BE32(emuFlags)
    ///
    /// ## Emulator-probe poisoning
    /// Emulator detection results (bitmask from C-layer probes) are mixed into
    /// the HKDF `info` field.  On a real device all flags are 0 — the info is
    /// effectively `"cprisk.report.hmac.v2h\0\0\0\0"` and the server verifies
    /// successfully.  On unidbg at least one flag bit is set → info changes →
    /// derived key differs → HMAC mismatch → server rejects, silently.
    ///
    /// Two probes are combined:
    /// - `cprisk_emulator_probe()` — cached; runs full 8-check suite at VM init.
    /// - `cprisk_emulator_quick_probe()` — live, uncached re-probe of 3 fast checks
    ///   (kern.ostype, stack address, watchdog stuck).  Resists attacks where the
    ///   attacker zeroes the probe cache between VM init and signing.
    private static func hkdfDerivedKey(baseKey: Data, nonce: String, ts: Int64) -> Data {
        let salt = Data("\(nonce)|\(ts)".utf8)

        // Combine cached probe with live re-probe; OR so any set bit poisons.
        let emuCached = cprisk_emulator_probe()
        let emuQuick  = cprisk_emulator_quick_probe()
        let emuFlags  = emuCached | emuQuick

        var info = Data("cprisk.report.hmac.v2h".utf8)
        withUnsafeBytes(of: emuFlags.bigEndian) { info.append(contentsOf: $0) }

        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: baseKey),
            salt: salt,
            info: info,
            outputByteCount: 32
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    private static func defaultBindingMode(signatureProviderPresent: Bool, sigVer: String = "v2h") -> String {
        if signatureProviderPresent { return "external_signature_provider_v1" }
        switch sigVer {
        case "v3":   return "self_reported_fields_bound_v3"
        case "v2h":  return "hkdf_hmac_v1"
        default:     return "plain_hmac_v1"
        }
    }

    private static func bindingDigestHex(for signatureInputData: Data) -> String {
        Data(SHA256.hash(data: signatureInputData)).map { String(format: "%02x", $0) }.joined()
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func isBindingModeCompatible(_ mode: String, sigVer: String) -> Bool {
        switch mode {
        case "hkdf_hmac_v1":
            return sigVer == "v2h"
        case "plain_hmac_v1":
            return sigVer == "v1" || sigVer == "v2" || sigVer == "v2d"
        case "plain_hmac_fallback_v1":
            return sigVer == "v2d"
        case "armor_request_binding_sha256_v1":
            return sigVer == "v2a"
        case "self_reported_fields_bound_v3":
            return sigVer == "v3"
        case "external_signature_provider_v1":
            return true
        default:
            return true
        }
    }

    private static func signatureInputData(from signatureInput: String) throws -> Data {
        guard let signatureData = signatureInput.data(using: .utf8) else {
            throw ReportEnvelopeError.signingFailed
        }
        return signatureData
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

    private func materialBindingObservation(signatureInputData: Data) -> MaterialBindingObservation {
        let recomputedDigestHex = Self.bindingDigestHex(for: signatureInputData)
        let metadataPresent = bindingMode != nil || bindingDigest != nil
        guard metadataPresent else {
            return MaterialBindingObservation(
                mode: nil,
                envelopeDigestHex: nil,
                recomputedDigestHex: recomputedDigestHex,
                isPresent: false,
                isConsistent: true,
                failureReason: nil
            )
        }

        guard let bindingMode, let bindingDigest else {
            return MaterialBindingObservation(
                mode: self.bindingMode,
                envelopeDigestHex: self.bindingDigest,
                recomputedDigestHex: recomputedDigestHex,
                isPresent: true,
                isConsistent: false,
                failureReason: "binding_metadata_incomplete"
            )
        }

        guard Self.isBindingModeCompatible(bindingMode, sigVer: sigVer) else {
            return MaterialBindingObservation(
                mode: bindingMode,
                envelopeDigestHex: bindingDigest,
                recomputedDigestHex: recomputedDigestHex,
                isPresent: true,
                isConsistent: false,
                failureReason: "binding_mode_signature_version_mismatch"
            )
        }

        guard timingSafeCompare(bindingDigest.lowercased(), recomputedDigestHex) else {
            return MaterialBindingObservation(
                mode: bindingMode,
                envelopeDigestHex: bindingDigest,
                recomputedDigestHex: recomputedDigestHex,
                isPresent: true,
                isConsistent: false,
                failureReason: "binding_digest_mismatch"
            )
        }

        return MaterialBindingObservation(
            mode: bindingMode,
            envelopeDigestHex: bindingDigest,
            recomputedDigestHex: recomputedDigestHex,
            isPresent: true,
            isConsistent: true,
            failureReason: nil
        )
    }

    private func inferredBindingMode(for signatureVersion: String) -> String {
        switch signatureVersion {
        case "v2h":
            return "hkdf_hmac_v1"
        case "v2a":
            return "armor_request_binding_sha256_v1"
        case "v2d":
            return "plain_hmac_fallback_v1"
        case "v1", "v2":
            return "plain_hmac_v1"
        default:
            return "unknown"
        }
    }

    private func attestationPairState() -> String {
        let hasKeyId = attestationKeyId.map { !$0.isEmpty } ?? false
        let hasAssertion = attestationAssertion.map { !$0.isEmpty } ?? false
        switch (hasKeyId, hasAssertion) {
        case (true, true):
            return "paired"
        case (true, false):
            return "key_only"
        case (false, true):
            return "assertion_only"
        case (false, false):
            return "absent"
        }
    }

    private func payloadBindingMetadata() -> (signalsDigestPresent: Bool, signalsDigestVersion: String?, signalsDigest: String?) {
        guard let object = try? JSONSerialization.jsonObject(with: payload, options: [.fragmentsAllowed]) as? [String: Any] else {
            return (false, nil, nil)
        }
        let digest = object["sd"] as? String
        let version = object["dv2"] as? String
        return (digest != nil, version, digest)
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
    private let lock = UnfairLock()

    public init() {}

    public func consumeIfNew(sessionToken: String, nonce: String, expiresAtMillis: Int64) -> Bool {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let key = "\(sessionToken):\(nonce)"

        return lock.withLock {
            // 惰性清理过期项
            storage = storage.filter { $0.value > now }

            if storage[key] != nil {
                return false
            }

            storage[key] = expiresAtMillis
            return true
        }
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

public extension ReportEnvelope.ReportEnvelopeError {
    var reasonCode: String {
        switch self {
        case .invalidPayload:
            return "invalid_payload"
        case .signatureMismatch:
            return "signature_mismatch"
        case .replayDetected:
            return "replay_detected"
        case .nonceExpired:
            return "nonce_expired"
        case .timestampOutOfRange:
            return "timestamp_out_of_range"
        case .encodingFailed:
            return "encoding_failed"
        case .signingFailed:
            return "signing_failed"
        case .attestationIncomplete:
            return "attestation_incomplete"
        }
    }
}
