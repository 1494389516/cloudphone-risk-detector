import Foundation
import CryptoKit

/// 上报信封，用于防止重放攻击
/// 结构：
/// - nonce: UUID 字符串，防重放
/// - ts: Unix timestamp
/// - sessionToken: 服务端下发的一次性 token
/// - payload: 风险报告
/// - signature: HMAC-SHA256(nonce+ts+payload.reportId, key)
public struct ReportEnvelope: Codable, Sendable {

    // MARK: - Properties

    /// 防重放随机数，使用 UUID 字符串
    public let nonce: String

    /// Unix 时间戳（秒）
    public let ts: Int

    /// 服务端下发的会话 Token（一次性）
    public let sessionToken: String

    /// 风险报告内容（JSON 编码后的 Payload）
    public let payload: Data

    /// 报告 ID（从 payload 中提取，用于签名）
    public let reportId: String

    /// HMAC-SHA256 签名
    public let signature: String

    // MARK: - Configuration

    /// 默认配置
    public struct Config {
        /// nonce 过期时间（秒），默认 5 分钟
        public var nonceExpirationSeconds: TimeInterval = 300

        /// 允许的时间偏差（秒），防止时钟不同步攻击，默认 5 分钟
        public var timeDriftToleranceSeconds: TimeInterval = 300

        public init(
            nonceExpirationSeconds: TimeInterval = 300,
            timeDriftToleranceSeconds: TimeInterval = 300
        ) {
            self.nonceExpirationSeconds = nonceExpirationSeconds
            self.timeDriftToleranceSeconds = timeDriftToleranceSeconds
        }
    }

    // MARK: - Error

    public enum ReportEnvelopeError: Error, LocalizedError {
        case invalidPayload
        case signatureMismatch
        case nonceExpired
        case timestampOutOfRange
        case encodingFailed
        case signingFailed

        public var errorDescription: String? {
            switch self {
            case .invalidPayload:
                return "无效的 payload 数据"
            case .signatureMismatch:
                return "签名验证失败"
            case .nonceExpired:
                return "Nonce 已过期"
            case .timestampOutOfRange:
                return "时间戳超出允许范围"
            case .encodingFailed:
                return "编码失败"
            case .signingFailed:
                return "签名生成失败"
            }
        }
    }

    // MARK: - Factory Method

    /// 从风险报告创建 ReportEnvelope
    /// - Parameters:
    ///   - payloadData: 编码后的风险报告数据（JSON）
    ///   - reportId: 报告 ID
    ///   - sessionToken: 服务端下发的会话 Token
    ///   - signingKey: 签名密钥
    ///   - config: 配置（可选）
    /// - Returns: ReportEnvelope 实例
    public static func create(
        payloadData: Data,
        reportId: String,
        sessionToken: String,
        signingKey: String,
        config: Config = Config()
    ) throws -> ReportEnvelope {
        let nonce = UUID().uuidString
        let ts = Int(Date().timeIntervalSince1970)

        // 生成签名: HMAC-SHA256(nonce + ts + reportId, key)
        let signatureInput = "\(nonce)\(ts)\(reportId)"
        guard let signatureData = signatureInput.data(using: .utf8),
              let keyData = signingKey.data(using: .utf8) else {
            throw ReportEnvelopeError.signingFailed
        }

        let key = SymmetricKey(data: keyData)
        let signature = HMAC<SHA256>.authenticationCode(for: signatureData, using: key)
        let signatureString = Data(signature).base64EncodedString()

        return ReportEnvelope(
            nonce: nonce,
            ts: ts,
            sessionToken: sessionToken,
            payload: payloadData,
            reportId: reportId,
            signature: signatureString
        )
    }

    /// 从 JSON 数据解析 ReportEnvelope
    /// - Parameter data: JSON 数据
    /// - Returns: ReportEnvelope 实例
    public static func fromJSON(_ data: Data) throws -> ReportEnvelope {
        try JSONDecoder().decode(ReportEnvelope.self, from: data)
    }

    /// 从 JSON 字符串解析 ReportEnvelope
    /// - Parameter jsonString: JSON 字符串
    /// - Returns: ReportEnvelope 实例
    public static func fromJSON(_ jsonString: String) throws -> ReportEnvelope {
        guard let data = jsonString.data(using: .utf8) else {
            throw ReportEnvelopeError.invalidPayload
        }
        return try fromJSON(data)
    }

    // MARK: - Verification

    /// 验证签名是否正确
    /// - Parameter signingKey: 签名密钥
    /// - Returns: 是否验证通过
    public func verifySignature(_ signingKey: String) -> Bool {
        let signatureInput = "\(nonce)\(ts)\(reportId)"
        guard let signatureData = signatureInput.data(using: .utf8),
              let keyData = signingKey.data(using: .utf8) else {
            return false
        }

        let key = SymmetricKey(data: keyData)
        let expectedSignature = HMAC<SHA256>.authenticationCode(for: signatureData, using: key)
        let expectedSignatureString = Data(expectedSignature).base64EncodedString()

        // 使用恒定时间比较，防止时序攻击
        return timingSafeCompare(expectedSignatureString, signature)
    }

    /// 检查是否过期
    /// - Parameter config: 配置
    /// - Returns: 是否过期
    public func isExpired(_ config: Config = Config()) -> Bool {
        let currentTime = Int(Date().timeIntervalSince1970)
        let timeDiff = abs(currentTime - ts)
        return Double(timeDiff) > config.nonceExpirationSeconds
    }

    /// 检查时间戳是否在允许范围内（防止时钟不同步攻击）
    /// - Parameter config: 配置
    /// - Returns: 是否在允许范围内
    public func isTimestampValid(_ config: Config = Config()) -> Bool {
        let currentTime = Int(Date().timeIntervalSince1970)
        let timeDiff = abs(currentTime - ts)
        return Double(timeDiff) <= config.timeDriftToleranceSeconds
    }

    /// 完整验证
    /// - Parameters:
    ///   - signingKey: 签名密钥
    ///   - config: 配置
    /// - Returns: 验证结果
    public func validate(
        signingKey: String,
        config: Config = Config()
    ) -> Result<Void, ReportEnvelopeError> {
        // 1. 验证时间戳范围
        guard isTimestampValid(config) else {
            return .failure(.timestampOutOfRange)
        }

        // 2. 验证签名
        guard verifySignature(signingKey) else {
            return .failure(.signatureMismatch)
        }

        // 3. 检查是否过期
        guard !isExpired(config) else {
            return .failure(.nonceExpired)
        }

        return .success(())
    }

    // MARK: - JSON Serialization

    /// 转换为 JSON Data
    /// - Parameter prettyPrinted: 是否格式化输出
    /// - Returns: JSON Data
    public func toJSONData(prettyPrinted: Bool = false) throws -> Data {
        let encoder = JSONEncoder()
        if prettyPrinted {
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        }
        return try encoder.encode(self)
    }

    /// 转换为 JSON 字符串
    /// - Parameter prettyPrinted: 是否格式化输出
    /// - Returns: JSON 字符串
    public func toJSONString(prettyPrinted: Bool = false) throws -> String {
        let data = try toJSONData(prettyPrinted: prettyPrinted)
        guard let string = String(data: data, encoding: .utf8) else {
            throw ReportEnvelopeError.encodingFailed
        }
        return string
    }

    // MARK: - Private Helpers

    /// 恒定时间比较，防止时序攻击
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

// MARK: - Convenience Extensions

extension ReportEnvelope {

    /// 快速创建方法（使用默认空密钥，仅用于测试）
    /// - Parameters:
    ///   - payloadData: 编码后的风险报告数据
    ///   - reportId: 报告 ID
    /// - Returns: ReportEnvelope 实例
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
