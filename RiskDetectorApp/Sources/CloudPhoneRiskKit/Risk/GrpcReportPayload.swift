import CRiskCore
import CryptoKit
import Foundation

// MARK: - gRPC/JSON 上报封装 (SDK 4.4)

/// 与 `risk_report.proto` UploadRiskReportRequest 对应的 Swift 结构体。
/// 用于手动 JSON 编码，不依赖 grpc-swift。
///
/// ## payload_json 与 payload_sha256
/// - `payload_json` 使用 bytes：JSON 传输时以 base64 编码；避免 UTF-8/转义/空白差异影响签名。
/// - `payload_sha256` 为 `SHA256(nonce|ts|reportId|payload)` 的上下文绑定摘要，防止跨请求嫁接。
///
/// ## 服务端验签顺序（必须严格按序执行）
/// 1. 校验 `ts` 是否在允许时间窗内
/// 2. 校验 `nonce` 是否首次出现（防重放）
/// 3. 校验 `session_token` 是否有效
/// 4. 重建 canonical payload JSON
/// 5. 校验 `signature`
/// 6. 校验顶层 `device_id` / `scene` 与 payload 内部字段是否一致
/// 7. 最后才进入风险数据入库、聚合和策略处理
///
/// 签名语义：`sigVer|nonce|ts|sessionToken|reportId|keyId|fieldMappingVersion|attestationKeyId|canonicalPayloadJSON`
public struct GrpcReportPayload: Sendable {
    public let appId: String
    public let sdkVersion: String
    public let reportId: String
    public let ts: Int64
    public let nonce: String
    public let sessionToken: String
    public let sigVer: String
    public let keyId: String
    public let fieldMappingVersion: String?
    public let deviceId: String
    public let scene: String
    public let payloadJson: Data
    public let signature: String
    public let payloadSha256: Data
    /// 输出链路完整性信号：用于观测 JSONSerialization/SHA256 关键 API 路径的一致性。
    /// 仅作为上报证据，不参与信封签名语义。
    public let outputPathIntegrity: [String: String]?

    public init(
        appId: String,
        sdkVersion: String,
        reportId: String,
        ts: Int64,
        nonce: String,
        sessionToken: String,
        sigVer: String,
        keyId: String,
        fieldMappingVersion: String?,
        deviceId: String,
        scene: String,
        payloadJson: Data,
        signature: String,
        payloadSha256: Data,
        outputPathIntegrity: [String: String]? = nil
    ) {
        self.appId = appId
        self.sdkVersion = sdkVersion
        self.reportId = reportId
        self.ts = ts
        self.nonce = nonce
        self.sessionToken = sessionToken
        self.sigVer = sigVer
        self.keyId = keyId
        self.fieldMappingVersion = fieldMappingVersion
        self.deviceId = deviceId
        self.scene = scene
        self.payloadJson = payloadJson
        self.signature = signature
        self.payloadSha256 = payloadSha256
        self.outputPathIntegrity = outputPathIntegrity
    }

    /// 转为与 proto 字段对应的 JSON 字典（snake_case），用于 HTTP/2 或 gRPC 客户端发送。
    /// `payload_json` 与 `payload_sha256` 以 base64 字符串形式输出。
    public func toJSONDictionary() -> [String: Any] {
        var dict: [String: Any] = [
            "app_id": appId,
            "sdk_version": sdkVersion,
            "report_id": reportId,
            "ts": ts,
            "nonce": nonce,
            "session_token": sessionToken,
            "sig_ver": sigVer,
            "key_id": keyId,
            "device_id": deviceId,
            "scene": scene,
            "payload_json": payloadJson.base64EncodedString(),
            "signature": signature,
            "payload_sha256": payloadSha256.base64EncodedString(),
        ]
        if let fmv = fieldMappingVersion, !fmv.isEmpty {
            dict["field_mapping_version"] = fmv
        }
        if let outputPathIntegrity, !outputPathIntegrity.isEmpty {
            dict["output_path_integrity"] = outputPathIntegrity
        }
        return dict
    }

    internal func validatedJSONDictionary() throws -> [String: Any] {
        let recomputed = Self.computePayloadSha256(
            nonce: nonce,
            ts: ts,
            reportId: reportId,
            payload: payloadJson
        )
        guard recomputed == payloadSha256 else {
            // fail-closed：关键绑定摘要出现不一致时拒绝继续序列化/上报
            throw ReportEnvelope.ReportEnvelopeError.encodingFailed
        }
        return toJSONDictionary()
    }

    internal static func computePayloadSha256(
        nonce: String,
        ts: Int64,
        reportId: String,
        payload: Data
    ) -> Data {
        var hasher = SHA256()
        // Length-prefix each field to prevent delimiter collision when fields contain '|'
        let nonceBytes = Data(nonce.utf8)
        let reportIdBytes = Data(reportId.utf8)
        hasher.update(data: Data("\(nonceBytes.count):\(nonce)|\(ts)|\(reportIdBytes.count):\(reportId)|".utf8))
        hasher.update(data: payload)
        return Data(hasher.finalize())
    }
}

/// 构建 gRPC 兼容 payload 时的可选上下文（app_id、device_id、scene 等索引字段）。
public struct GrpcReportContext: Sendable {
    public let appId: String
    public let deviceId: String
    public let scene: String

    public init(appId: String = "", deviceId: String = "", scene: String = "") {
        self.appId = appId
        self.deviceId = deviceId
        self.scene = scene
    }
}

// MARK: - ReportEnvelope Extension

extension ReportEnvelope {
    /// 将信封转为与 `UploadRiskReportRequest` proto 兼容的 payload 结构体。
    /// - Parameter context: 可选上下文，提供 app_id、device_id、scene；缺失时使用空字符串。
    /// - Returns: 与 proto 字段一一对应的 `GrpcReportPayload`
    public func toGrpcCompatiblePayload(context: GrpcReportContext? = nil) -> GrpcReportPayload {
        let ctx = context ?? GrpcReportContext()
        let payloadSha256 = GrpcReportPayload.computePayloadSha256(
            nonce: nonce,
            ts: ts,
            reportId: reportId,
            payload: payload
        )
        let outputPathIntegrity = buildOutputPathIntegritySignal(payloadSha256: payloadSha256)

        return GrpcReportPayload(
            appId: ctx.appId,
            sdkVersion: Version.current,
            reportId: reportId,
            ts: ts,
            nonce: nonce,
            sessionToken: sessionToken,
            sigVer: sigVer,
            keyId: keyId,
            fieldMappingVersion: fieldMappingVersion,
            deviceId: ctx.deviceId,
            scene: ctx.scene,
            payloadJson: payload,
            signature: signature,
            payloadSha256: payloadSha256,
            outputPathIntegrity: outputPathIntegrity
        )
    }

    /// 序列化为与 proto 结构匹配的 JSON 字符串，供 HTTP/2 或 gRPC 客户端发送。
    /// - Parameters:
    ///   - context: 可选上下文
    ///   - prettyPrinted: 是否格式化输出（调试用；生产建议 false）
    /// - Returns: JSON 字符串
    public func toGrpcCompatibleJSON(
        context: GrpcReportContext? = nil,
        prettyPrinted: Bool = false
    ) throws -> String {
        let payload = toGrpcCompatiblePayload(context: context)
        let dict = try payload.validatedJSONDictionary()

        let options: JSONSerialization.WritingOptions = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        let data = try JSONSerialization.data(withJSONObject: dict, options: options)
        guard let string = String(data: data, encoding: .utf8) else {
            throw ReportEnvelopeError.encodingFailed
        }
        return string
    }

    /// 序列化为与 proto 结构匹配的 JSON Data（bytes），供 HTTP/2 或 gRPC 客户端发送。
    /// - Parameter context: 可选上下文
    /// - Returns: JSON 编码后的 Data
    public func toGrpcRequestBytes(context: GrpcReportContext? = nil) throws -> Data {
        let payload = toGrpcCompatiblePayload(context: context)
        let dict = try payload.validatedJSONDictionary()
        return try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
    }

    // MARK: - Compressed Upload

    /// Returns the serialised request body compressed with zlib deflate (RFC 1950).
    ///
    /// The **signature covers the uncompressed canonical payload** so the server
    /// must decompress the body before verifying.  Set the HTTP header
    /// `Content-Encoding: zlib` when transmitting the compressed bytes.
    ///
    /// If zlib compression would *increase* the payload size (e.g. very small
    /// or already-compressed payloads) the raw uncompressed bytes are returned
    /// instead and `isCompressed` is `false`.
    ///
    /// - Returns: `(data, isCompressed)` — `isCompressed` indicates whether
    ///   `data` is zlib-compressed (`true`) or plain JSON (`false`).
    public func toCompressedGrpcRequestBytes(
        context: GrpcReportContext? = nil
    ) throws -> (data: Data, isCompressed: Bool) {
        let raw = try toGrpcRequestBytes(context: context)
        if let compressed = try? (raw as NSData).compressed(using: .zlib) as Data,
           compressed.count < raw.count {
            return (compressed, true)
        }
        return (raw, false)
    }

    private func buildOutputPathIntegritySignal(payloadSha256: Data) -> [String: String] {
        let recomputed = GrpcReportPayload.computePayloadSha256(
            nonce: nonce,
            ts: ts,
            reportId: reportId,
            payload: payload
        )
        let payloadShaMatches = (recomputed == payloadSha256)
        let bindingDiagnostics = bindingDiagnostics()
        let canonicalizationOK = bindingDiagnostics["payload_canonical_sha256"] != "unavailable"
        let trustValue = trustLevel?.rawValue ?? "unspecified"
        let signingTelemetry = AppSigningIdentityDetector().telemetry()
        let requestBindingFingerprint = Self.sha256Hex(Data([
            sigVer,
            keyId,
            trustValue,
            bindingDiagnostics["attestation_pair_state"] ?? "absent",
            reportId,
            signingTelemetry["signing_identity_fp"] ?? "",
            bindingDiagnostics["signature_input_sha256"] ?? "unavailable",
        ].joined(separator: "|").utf8))

        let status: String
        let reason: String
        if !payloadShaMatches {
            status = "blocked"
            reason = "payload_sha256_mismatch"
        } else if !canonicalizationOK {
            status = "high_risk"
            reason = "payload_canonicalization_failed"
        } else {
            status = "ok"
            reason = "consistent"
        }

        var rows = bindingDiagnostics
        rows.merge([
            "status": status,
            "reason": reason,
            "api_chain": "json_serialization+cryptokit_sha256",
            "route": "report_envelope->grpc_payload",
            "payload_sha256_match": payloadShaMatches ? "1" : "0",
            "binding_mode": Self.signatureBindingMode(for: sigVer),
            "binding_fields": "sigVer,nonce,ts,sessionToken,reportId,keyId,fieldMappingVersion,attestationKeyId,payloadCanonical",
            "attestation_pair_state": Self.attestationPairState(
                attestationKeyId: attestationKeyId,
                attestationAssertion: attestationAssertion
            ),
            "trust_level": trustValue,
            "request_binding_fp": requestBindingFingerprint,
        ]) { _, new in new }
        for (key, value) in signingTelemetry where !value.isEmpty {
            rows[key] = value
        }
        let mixFp = cprisk_get_signing_mix_fingerprint()
        if mixFp != 0 {
            rows["signing_mix_fp"] = String(format: "%08x", mixFp)
        }
        let wbPressure = cprisk_integrity_wb_prf_pressure_mask()
        if wbPressure != 0 {
            rows["wb_prf_pressure_mask"] = String(format: "%08x", wbPressure)
        }
        return rows
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func signatureBindingMode(for signatureVersion: String) -> String {
        switch signatureVersion {
        case "v2a":
            return "armor_runtime_derived_request_bound"
        case "v2d":
            return "degraded_base_key_request_bound"
        default:
            return "base_key_request_bound"
        }
    }

    private static func attestationPairState(
        attestationKeyId: String?,
        attestationAssertion: Data?
    ) -> String {
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
            return "none"
        }
    }
}
