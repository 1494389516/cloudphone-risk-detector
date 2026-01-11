import Foundation

struct RiskContext: Sendable {
    var device: DeviceFingerprint
    var deviceID: String
    var network: NetworkSignals
    var behavior: BehaviorSignals
    var jailbreak: DetectionResult
}

public struct RiskScoreReport: Sendable {
    public var score: Double
    public var isHighRisk: Bool
    public var signals: [RiskSignal]
    public var summary: String
}

public struct RiskSignal: Sendable, Codable {
    public var id: String
    public var category: String
    public var score: Double
    public var evidence: [String: String]
}

@objc(CPRiskSignal)
public final class CPRiskSignal: NSObject {
    @objc public let id: String
    @objc public let category: String
    @objc public let score: Double
    @objc public let evidenceJSON: String

    init(_ signal: RiskSignal) {
        self.id = signal.id
        self.category = signal.category
        self.score = signal.score
        self.evidenceJSON = (try? JSON.stringify(signal.evidence)) ?? "{}"
    }
}

@objc(CPRiskReport)
public final class CPRiskReport: NSObject {
    @objc public let deviceID: String
    @objc public let score: Double
    @objc public let isHighRisk: Bool
    @objc public let summary: String
    @objc public let jailbreakConfidence: Double
    @objc public let jailbreakIsJailbroken: Bool
    @objc public let detectedMethods: [String]
    @objc public let signals: [CPRiskSignal]

    private var payload: Payload

    init(context: RiskContext, report: RiskScoreReport) {
        self.deviceID = context.deviceID
        self.score = report.score
        self.isHighRisk = report.isHighRisk
        self.summary = report.summary
        self.jailbreakConfidence = context.jailbreak.confidence
        self.jailbreakIsJailbroken = context.jailbreak.isJailbroken
        self.detectedMethods = context.jailbreak.detectedMethods
        self.signals = report.signals.map(CPRiskSignal.init)
        self.payload = Payload(context: context, report: report)
    }

    /// 用于上报的 JSON（未加密）。
    @objc public func jsonData(prettyPrinted: Bool = false) -> Data {
        (try? JSON.encode(payload, prettyPrinted: prettyPrinted)) ?? Data()
    }

    @objc public func jsonString(prettyPrinted: Bool = false) -> String {
        String(data: jsonData(prettyPrinted: prettyPrinted), encoding: .utf8) ?? "{}"
    }

    /// 本地加密后的 bytes（AES-GCM，密钥在 Keychain）。
    @objc public func encryptedData() throws -> Data {
        try PayloadCrypto.encrypt(jsonData(prettyPrinted: false))
    }

    /// 本地加密后的 base64 字符串（便于写文件/复制）。
    @objc public func encryptedBase64() throws -> String {
        try encryptedData().base64EncodedString()
    }

    /// 预留：设置未来服务端聚合信号（本地环境下可不调用）。
    /// 这些字段会被写入 JSON 的 `server` 节点。
    @objc(setServerSignalsPublicIP:asn:asOrg:isDatacenter:ipDeviceAgg:ipAccountAgg:geoCountry:geoRegion:riskTags:)
    public func setServerSignals(
        publicIP: String?,
        asn: String?,
        asOrg: String?,
        isDatacenter: NSNumber?,
        ipDeviceAgg: NSNumber?,
        ipAccountAgg: NSNumber?,
        geoCountry: String?,
        geoRegion: String?,
        riskTags: [String]?
    ) {
        payload.server = ServerSignals(
            publicIP: publicIP,
            asn: asn,
            asOrg: asOrg,
            isDatacenter: isDatacenter?.boolValue,
            ipDeviceAgg: ipDeviceAgg?.intValue,
            ipAccountAgg: ipAccountAgg?.intValue,
            geoCountry: geoCountry,
            geoRegion: geoRegion,
            riskTags: riskTags
        )
        Logger.log("server.signals: publicIP=\(publicIP ?? "nil") asn=\(asn ?? "nil") asOrg=\(asOrg ?? "nil") dc=\(isDatacenter?.stringValue ?? "nil") ipDeviceAgg=\(ipDeviceAgg?.stringValue ?? "nil") ipAccountAgg=\(ipAccountAgg?.stringValue ?? "nil")")
    }

    func setServerSignals(_ signals: ServerSignals?) {
        payload.server = signals
    }

    func setLocalSignals(_ signals: LocalSignals?) {
        payload.local = signals
    }
}

private struct Payload: Codable {
    var sdkVersion: String
    var generatedAt: String
    var deviceID: String
    var device: DeviceFingerprint
    var network: NetworkSignals
    var behavior: BehaviorSignals
    var jailbreak: DetectionResultPayload
    var score: Double
    var isHighRisk: Bool
    var summary: String
    var signals: [RiskSignal]

    // 预留：未来服务端/云端聚合信号（IP 聚合度、ASN、机房属性等）
    var server: ServerSignals?

    // 本地聚合信号（不依赖云端）
    var local: LocalSignals?

    init(context: RiskContext, report: RiskScoreReport) {
        self.sdkVersion = Version.current
        self.generatedAt = ISO8601.nowString()
        self.deviceID = context.deviceID
        self.device = context.device
        self.network = context.network
        self.behavior = context.behavior
        self.jailbreak = DetectionResultPayload(context.jailbreak)
        self.score = report.score
        self.isHighRisk = report.isHighRisk
        self.summary = report.summary
        self.signals = report.signals
        self.server = nil
        self.local = nil
    }
}

public struct LocalSignals: Codable, Sendable {
    public var timePattern: TimePattern?
    public var cloudPhone: CloudPhoneLocalSignals?

    public init(timePattern: TimePattern? = nil, cloudPhone: CloudPhoneLocalSignals? = nil) {
        self.timePattern = timePattern
        self.cloudPhone = cloudPhone
    }
}

public struct ServerSignals: Codable, Sendable {
    public var publicIP: String?
    public var asn: String?
    public var asOrg: String?
    public var isDatacenter: Bool?
    public var ipDeviceAgg: Int?
    public var ipAccountAgg: Int?
    public var geoCountry: String?
    public var geoRegion: String?
    public var riskTags: [String]?

    public init(
        publicIP: String? = nil,
        asn: String? = nil,
        asOrg: String? = nil,
        isDatacenter: Bool? = nil,
        ipDeviceAgg: Int? = nil,
        ipAccountAgg: Int? = nil,
        geoCountry: String? = nil,
        geoRegion: String? = nil,
        riskTags: [String]? = nil
    ) {
        self.publicIP = publicIP
        self.asn = asn
        self.asOrg = asOrg
        self.isDatacenter = isDatacenter
        self.ipDeviceAgg = ipDeviceAgg
        self.ipAccountAgg = ipAccountAgg
        self.geoCountry = geoCountry
        self.geoRegion = geoRegion
        self.riskTags = riskTags
    }
}

private struct DetectionResultPayload: Codable {
    var isJailbroken: Bool
    var confidence: Double
    var detectedMethods: [String]
    var details: String

    init(_ result: DetectionResult) {
        self.isJailbroken = result.isJailbroken
        self.confidence = result.confidence
        self.detectedMethods = result.detectedMethods
        self.details = result.details
    }
}

enum Version {
    static let current = "0.1.0"
}
