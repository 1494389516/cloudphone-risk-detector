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
/// 签名语义不变：`sigVer|nonce|ts|sessionToken|reportId|keyId|fieldMappingVersion|canonicalPayloadJSON`
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
        payloadSha256: Data
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
        return dict
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
        var hasher = SHA256()
        hasher.update(data: Data("\(nonce)|\(ts)|\(reportId)|".utf8))
        hasher.update(data: payload)
        let payloadSha256 = Data(hasher.finalize())

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
            payloadSha256: payloadSha256
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
        let dict = payload.toJSONDictionary()

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
        let dict = payload.toJSONDictionary()
        return try JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys])
    }
}
