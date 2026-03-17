import CryptoKit
import Foundation

// MARK: - Signal Identifiers

/// 统一管理所有 RiskSignal 的 ID，避免字符串散落各处导致拼写错误和维护困难
public enum SignalID {
    // Jailbreak
    static let jailbreak = "jailbreak"

    // Network
    static let vpnActive = "vpn_active"
    static let proxyEnabled = "proxy_enabled"
    static let networkInterfaceAnomaly = "network_interface_anomaly"

    // Behavior
    static let touchSpreadLow = "touch_spread_low"
    static let touchSpreadHigh = "touch_spread_high"
    static let touchIntervalTooRegular = "touch_interval_too_regular"
    static let touchIntervalTooChaotic = "touch_interval_too_chaotic"
    static let swipeTooLinear = "swipe_too_linear"
    static let swipeTooCurvy = "swipe_too_curvy"
    static let motionTooStill = "motion_too_still"
    static let touchMotionWeakCoupling = "touch_motion_weak_coupling"
    static let insufficientBehaviorData = "insufficient_behavior_data"

    // Time Pattern
    static let highVolume24h = "high_volume_24h"
    static let mediumVolume24h = "medium_volume_24h"
    static let wideHourCoverage = "wide_hour_coverage"
    static let nightActivityHigh = "night_activity_high"
    static let highFrequency = "high_frequency"

    // Server Aggregation
    static let datacenterIP = "datacenter_ip"
    static let ipDeviceAgg = "ip_device_agg"
    static let ipAccountAgg = "ip_account_agg"

    // Cloud Phone / Hardware
    static let gpuVirtual = "gpu_virtual"
    static let vphoneHardware = "vphone_hardware"
    static let hardwareInconsistency = "hardware_inconsistency"
    static let sensorEntropy = "sensor_entropy"
    static let touchEntropy = "touch_entropy"
    static let hookDetected = "hook_detected"
    static let blocklistHit = "blocklist_hit"

    /// Display Mux (SDK 5.2)
    static let screenCaptured = "screen_captured"
    static let externalDisplayAttached = "external_display_attached"

    /// Signal suppression detection (SDK 5.5)
    static let signalSuppressionDetected = "signal_suppression_detected"
}

// MARK: - Signal Categories

/// 统一管理所有 RiskSignal 的 category
public enum SignalCategory {
    static let jailbreak = "jailbreak"
    static let network = "network"
    static let behavior = "behavior"
    static let time = "time"
    static let server = "server"
    static let cloudphone = "cloudphone"
}

public struct RiskContext: Sendable {
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
    /// 内存语义压缩摘要（1.0=8 字节，1.1=9 字节含 byte 8 行为熵）
    public var compressedDigest: Data?
    /// 信号到 bit 映射表版本
    public var mappingVersion: String?
}

public enum RiskSignalState: Sendable, Codable, Equatable {
    case hard(detected: Bool)
    case soft(confidence: Double)
    case serverRequired
    case unavailable
    case tampered

    private enum CodingKeys: String, CodingKey {
        case type = "t"
        case detected = "d"
        case confidence = "c"
    }

    private enum StateType: String, Codable {
        case hard
        case soft
        case serverRequired
        case unavailable
        case tampered
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(StateType.self, forKey: .type)
        switch type {
        case .hard:
            self = .hard(detected: try container.decode(Bool.self, forKey: .detected))
        case .soft:
            let raw = try container.decode(Double.self, forKey: .confidence)
            self = .soft(confidence: raw.isFinite ? min(max(raw, 0), 1) : 0)
        case .serverRequired:
            self = .serverRequired
        case .unavailable:
            self = .unavailable
        case .tampered:
            self = .tampered
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .hard(let detected):
            try container.encode(StateType.hard, forKey: .type)
            try container.encode(detected, forKey: .detected)
        case .soft(let confidence):
            try container.encode(StateType.soft, forKey: .type)
            try container.encode(confidence, forKey: .confidence)
        case .serverRequired:
            try container.encode(StateType.serverRequired, forKey: .type)
        case .unavailable:
            try container.encode(StateType.unavailable, forKey: .type)
        case .tampered:
            try container.encode(StateType.tampered, forKey: .type)
        }
    }
}

public struct RiskSignal: Sendable, Codable {
    public var id: String
    public var category: String
    public var score: Double
    public var evidence: [String: String]
    public var state: RiskSignalState?
    public var layer: Int?
    public var weightHint: Double

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case category = "ca"
        case score = "s"
        case evidence = "ev"
        case state = "st"
        case layer = "l"
        case weightHint = "wh"
    }

    public init(
        id: String,
        category: String,
        score: Double,
        evidence: [String: String],
        state: RiskSignalState? = nil,
        layer: Int? = nil,
        weightHint: Double = 0
    ) {
        self.id = id
        self.category = category
        self.score = score
        self.evidence = evidence
        self.state = state
        self.layer = layer
        self.weightHint = weightHint
    }
}

@objc(CPRiskSignal)
public final class CPRiskSignal: NSObject {
    @objc public let id: String
    @objc public let category: String
    @objc public let score: Double
    @objc public let evidenceJSON: String
    /// Stable string representation of signal state for digest computation.
    public let stateDescription: String

    init(_ signal: RiskSignal) {
        self.id = signal.id
        self.category = signal.category
        self.score = signal.score
        self.stateDescription = Self.stableStateString(signal.state)
        do {
            self.evidenceJSON = try JSON.stringify(signal.evidence)
        } catch {
            Logger.log("CPRiskSignal: evidence JSON stringify failed - \(error.localizedDescription)")
            self.evidenceJSON = "{}"
        }
    }

    private static func stableStateString(_ state: RiskSignalState?) -> String {
        SignalDigest.stableStateTag(state)
    }
}

@objc(CPRiskReport)
public final class CPRiskReport: NSObject {
    @objc public let deviceID: String
    /// 设备指纹（用于 TrustChainManager.evaluateTrustLevel 等）
    public var device: DeviceFingerprint { payload.device }
    @objc public let reportID: String
    @objc public let score: Double
    @objc public let isHighRisk: Bool
    @objc public let summary: String
    @objc public let jailbreakConfidence: Double
    @objc public let jailbreakIsJailbroken: Bool
    @objc public let detectedMethods: [String]
    @objc public let signals: [CPRiskSignal]
    @objc public let tampered: Bool
    @objc public private(set) var accountId: String?
    @objc public private(set) var sessionId: String?

    private var payload: Payload

    init(context: RiskContext, report: RiskScoreReport) {
        let builtPayload = Payload(context: context, report: report)
        self.deviceID = context.deviceID
        self.reportID = builtPayload.reportId
        self.score = report.score
        self.isHighRisk = report.isHighRisk
        self.summary = report.summary
        self.jailbreakConfidence = context.jailbreak.confidence
        self.jailbreakIsJailbroken = context.jailbreak.isJailbroken
        self.detectedMethods = context.jailbreak.detectedMethods
        self.signals = report.signals.map(CPRiskSignal.init)
        self.tampered = builtPayload.tamperedCount > 0
        self.payload = builtPayload
    }

    func setGraphBindings(accountId: String?, sessionId: String?, sceneTag: String?) {
        self.accountId = accountId
        self.sessionId = sessionId
        payload.accountId = accountId
        payload.sessionId = sessionId
        payload.sceneTag = sceneTag
    }

    /// 用于上报的 JSON（未加密）。
    @available(*, deprecated, message: "Use securePayload() for production. jsonData() returns unencrypted data suitable only for debugging.")
    @objc public func jsonData(prettyPrinted: Bool = false) -> Data {
        #if DEBUG
        Logger.log("⚠️ CPRiskReport.jsonData(): returning unencrypted payload — use securePayload() in production")
        #else
        assertionFailure("CPRiskReport.jsonData() called in Release — prefer securePayload() for encrypted transport")
        #endif
        do {
            return try JSON.encode(payload, prettyPrinted: prettyPrinted)
        } catch {
            Logger.log("CPRiskReport: payload JSON encode failed - \(error.localizedDescription)")
            return Data()
        }
    }

    @objc public func jsonString(prettyPrinted: Bool = false) -> String {
        String(data: jsonData(prettyPrinted: prettyPrinted), encoding: .utf8) ?? "{}"
    }

    /// AES-GCM 加密后的 payload（生产环境推荐）。
    @objc public func securePayload() throws -> Data {
        let plaintext = try JSON.encode(payload, prettyPrinted: false)
        return try PayloadCrypto.encrypt(plaintext)
    }

    /// 本地加密后的 bytes（AES-GCM，密钥在 Keychain）。
    @objc public func encryptedData() throws -> Data {
        try securePayload()
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
        #if DEBUG
        Logger.log("server.signals: publicIP=\(publicIP ?? "nil") asn=\(asn ?? "nil") asOrg=\(asOrg ?? "nil") dc=\(isDatacenter?.stringValue ?? "nil") ipDeviceAgg=\(ipDeviceAgg?.stringValue ?? "nil") ipAccountAgg=\(ipAccountAgg?.stringValue ?? "nil")")
        #endif
    }

    func setServerSignals(_ signals: ServerSignals?) {
        payload.server = signals
    }

    func setLocalSignals(_ signals: LocalSignals?) {
        payload.local = signals
    }

    func setChallengeBinding(_ challengeBinding: ChallengeBindingPayload?) {
        payload.challengeBinding = challengeBinding
    }

    func setGraphNodeDescriptor(_ descriptor: GraphNodeDescriptor?) {
        payload.graphNode = descriptor
    }

    public func challengeBinding() -> ChallengeBindingPayload? {
        payload.challengeBinding
    }
}

private struct Payload: Codable {
    var sdkVersion: String
    var reportId: String
    var timestamp: Double
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
    var tamperedCount: Int

    var compressedDigestHex: String?
    var signalMappingVersion: String?

    var signalsDigest: String?
    var signalsDigestVersion: String?

    var server: ServerSignals?

    var local: LocalSignals?

    var challengeBinding: ChallengeBindingPayload?

    var gpuName: String?
    var kernelBuild: String?
    var deviceModel: String?
    var imuMagnitude: Double?
    var imuVariance: Double?
    var touchForceVar: Double?

    var accountId: String?
    var sessionId: String?
    var sceneTag: String?
    var behaviorVector: [Double]?

    var graphNode: GraphNodeDescriptor?

    var textSegmentIntegrity: TextSegmentIntegrityPayload?

    private enum CodingKeys: String, CodingKey {
        case sdkVersion = "sv"
        case reportId = "ri"
        case timestamp = "ts"
        case generatedAt = "ga"
        case deviceID = "di"
        case device = "dv"
        case network = "nw"
        case behavior = "bh"
        case jailbreak = "jb"
        case score = "sc"
        case isHighRisk = "hr"
        case summary = "sm"
        case signals = "sg"
        case tamperedCount = "tc"
        case compressedDigestHex = "cd"
        case signalMappingVersion = "mv"
        case signalsDigest = "sd"
        case signalsDigestVersion = "dv2"
        case server = "sr"
        case local = "lc"
        case challengeBinding = "cb"
        case gpuName = "gn"
        case kernelBuild = "kb"
        case deviceModel = "dm"
        case imuMagnitude = "im"
        case imuVariance = "iv"
        case touchForceVar = "tf"
        case accountId = "ai"
        case sessionId = "si"
        case sceneTag = "st"
        case behaviorVector = "bv"
        case graphNode = "gd"
        case textSegmentIntegrity = "ti"
    }

    init(context: RiskContext, report: RiskScoreReport) {
        self.sdkVersion = Version.current
        self.reportId = UUID().uuidString
        self.timestamp = Date().timeIntervalSince1970
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
        self.tamperedCount = report.signals.filter { $0.state == .tampered }.count
        self.compressedDigestHex = report.compressedDigest.map { $0.map { String(format: "%02x", $0) }.joined() }
        self.signalMappingVersion = report.mappingVersion
        self.signalsDigest = SignalDigest.computeFullDigest(report.signals)
        self.signalsDigestVersion = "v2a"
        self.server = nil
        self.local = nil
        self.challengeBinding = nil
        self.gpuName = report.signals.first(where: { $0.id == SignalID.gpuVirtual })?.evidence["gpu_name"]
        self.kernelBuild = report.signals.first(where: { $0.id == SignalID.vphoneHardware })?.evidence["kernel"]
        self.deviceModel = context.device.hardwareMachine ?? context.device.model
        self.imuMagnitude = nil
        self.imuVariance = nil
        self.touchForceVar = context.behavior.touch.forceVariance
        self.accountId = nil
        self.sessionId = nil
        self.sceneTag = nil
        self.behaviorVector = Self.computeBehaviorVector(from: context.behavior)
        self.graphNode = nil
        self.textSegmentIntegrity = Self.buildTextSegmentIntegrityPayload()
    }

    private static func buildTextSegmentIntegrityPayload() -> TextSegmentIntegrityPayload? {
        let result = TextSegmentIntegrityChecker.verify()
        guard !result.currentHash.isEmpty else { return nil }
        return TextSegmentIntegrityPayload(
            currentHash: result.currentHash,
            sdkVersion: result.sdkVersion,
            referenceSource: result.referenceSource,
            referenceVersion: result.referenceVersion,
            usedServerReference: result.usedServerReference,
            clientDetail: result.detail
        )
    }

    private static func computeBehaviorVector(from behavior: BehaviorSignals) -> [Double]? {
        guard behavior.touch.sampleCount > 0 || behavior.motion.sampleCount > 0 else { return nil }
        return [
            min((behavior.touch.coordinateSpread ?? 0) / 20.0, 1.0),
            min(behavior.touch.intervalCV ?? 0, 1.0),
            behavior.touch.averageLinearity ?? 0,
            min((behavior.touch.forceVariance ?? 0) / 5.0, 1.0),
            behavior.motion.stillnessRatio ?? 0,
            min((behavior.motion.motionEnergy ?? 0) / 100.0, 1.0)
        ]
    }
}

/// __TEXT.__text 完整性上报载荷（盲区四），供服务端二次校验
public struct TextSegmentIntegrityPayload: Codable, Sendable {
    public let currentHash: String
    public let sdkVersion: String
    /// 参考哈希来源，仅供服务端观测与审计，不应替代服务端独立查表。
    public let referenceSource: String?
    /// 参考哈希版本，如 RemoteConfig 版本号或业务侧参考表版本号。
    public let referenceVersion: String?
    /// 客户端本次是否命中了服务端参考哈希路径。
    public let usedServerReference: Bool
    /// 客户端本地结论细节，仅供观测，不应作为服务端最终信任依据。
    public let clientDetail: String?

    private enum CodingKeys: String, CodingKey {
        case currentHash = "ch"
        case sdkVersion = "sv"
        case referenceSource = "rs"
        case referenceVersion = "rv"
        case usedServerReference = "ur"
        case clientDetail = "cd"
    }

    public init(
        currentHash: String,
        sdkVersion: String,
        referenceSource: String? = nil,
        referenceVersion: String? = nil,
        usedServerReference: Bool = false,
        clientDetail: String? = nil
    ) {
        self.currentHash = currentHash
        self.sdkVersion = sdkVersion
        self.referenceSource = referenceSource
        self.referenceVersion = referenceVersion
        self.usedServerReference = usedServerReference
        self.clientDetail = clientDetail
    }
}

/// 探针执行状态（超时/不支持时上报）
public enum ChallengeExecutionStatus: String, Codable, Sendable {
    /// 正常完成
    case completed
    /// 客户端执行探针超时
    case timeout
    /// 设备不支持某些探针
    case unsupported
}

public struct ChallengeBindingPayload: Codable, Sendable {
    public var challengeId: String
    public var seed: String
    public var probeIds: [String]
    public var executedProbeIds: [String]
    public var expiresAt: Int64
    public var timestamp: Int64
    public var capabilityAnomalyCount: Int
    public var qualitySuspicion: Int
    public var totalProbes: Int
    public var tamperedCount: Int
    public var probeRiskContribution: Int
    public var triggerReason: String?
    /// 探针执行状态（超时/不支持时上报）
    public var executionStatus: ChallengeExecutionStatus
    /// seed 与设备指纹绑定：expectedHash = SHA256(seed + deviceFingerprint)，用于服务端防重放验证占位
    public var expectedHash: String?

    public init(
        challengeId: String,
        seed: String,
        probeIds: [String],
        executedProbeIds: [String],
        expiresAt: Int64,
        timestamp: Int64,
        capabilityAnomalyCount: Int,
        qualitySuspicion: Int,
        totalProbes: Int,
        tamperedCount: Int,
        probeRiskContribution: Int,
        triggerReason: String? = nil,
        executionStatus: ChallengeExecutionStatus = .completed,
        expectedHash: String? = nil
    ) {
        self.challengeId = challengeId
        self.seed = seed
        self.probeIds = probeIds
        self.executedProbeIds = executedProbeIds
        self.expiresAt = expiresAt
        self.timestamp = timestamp
        self.capabilityAnomalyCount = capabilityAnomalyCount
        self.qualitySuspicion = qualitySuspicion
        self.totalProbes = totalProbes
        self.tamperedCount = tamperedCount
        self.probeRiskContribution = probeRiskContribution
        self.triggerReason = triggerReason
        self.executionStatus = executionStatus
        self.expectedHash = expectedHash
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        challengeId = try container.decode(String.self, forKey: .challengeId)
        seed = try container.decode(String.self, forKey: .seed)
        probeIds = try container.decode([String].self, forKey: .probeIds)
        executedProbeIds = try container.decode([String].self, forKey: .executedProbeIds)
        expiresAt = try container.decode(Int64.self, forKey: .expiresAt)
        timestamp = try container.decode(Int64.self, forKey: .timestamp)
        capabilityAnomalyCount = try container.decode(Int.self, forKey: .capabilityAnomalyCount)
        qualitySuspicion = try container.decode(Int.self, forKey: .qualitySuspicion)
        totalProbes = try container.decode(Int.self, forKey: .totalProbes)
        tamperedCount = try container.decode(Int.self, forKey: .tamperedCount)
        probeRiskContribution = try container.decode(Int.self, forKey: .probeRiskContribution)
        triggerReason = try container.decodeIfPresent(String.self, forKey: .triggerReason)
        executionStatus = try container.decodeIfPresent(ChallengeExecutionStatus.self, forKey: .executionStatus) ?? .completed
        expectedHash = try container.decodeIfPresent(String.self, forKey: .expectedHash)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(challengeId, forKey: .challengeId)
        try container.encode(seed, forKey: .seed)
        try container.encode(probeIds, forKey: .probeIds)
        try container.encode(executedProbeIds, forKey: .executedProbeIds)
        try container.encode(expiresAt, forKey: .expiresAt)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(capabilityAnomalyCount, forKey: .capabilityAnomalyCount)
        try container.encode(qualitySuspicion, forKey: .qualitySuspicion)
        try container.encode(totalProbes, forKey: .totalProbes)
        try container.encode(tamperedCount, forKey: .tamperedCount)
        try container.encode(probeRiskContribution, forKey: .probeRiskContribution)
        try container.encodeIfPresent(triggerReason, forKey: .triggerReason)
        try container.encode(executionStatus, forKey: .executionStatus)
        try container.encodeIfPresent(expectedHash, forKey: .expectedHash)
    }

    private enum CodingKeys: String, CodingKey {
        case challengeId = "ci"
        case seed = "s"
        case probeIds = "pi"
        case executedProbeIds = "ep"
        case expiresAt = "ea"
        case timestamp = "ts"
        case capabilityAnomalyCount = "ca"
        case qualitySuspicion = "qs"
        case totalProbes = "tp"
        case tamperedCount = "tc"
        case probeRiskContribution = "pr"
        case triggerReason = "tr"
        case executionStatus = "es"
        case expectedHash = "eh"
    }
}

public struct LocalSignals: Codable, Sendable {
    public var timePattern: TimePattern?
    public var cloudPhone: CloudPhoneLocalSignals?

    private enum CodingKeys: String, CodingKey {
        case timePattern = "tp"
        case cloudPhone = "cp"
    }

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

    // 图算法反哺字段
    public var communityId: String?
    public var communityRiskDensity: Double?
    public var hwProfileDegree: Int?
    public var devicePageRank: Double?
    public var isInDenseSubgraph: Bool?

    private enum CodingKeys: String, CodingKey {
        case publicIP = "ip"
        case asn = "an"
        case asOrg = "ao"
        case isDatacenter = "dc"
        case ipDeviceAgg = "da"
        case ipAccountAgg = "aa"
        case geoCountry = "gc"
        case geoRegion = "gr"
        case riskTags = "rt"
        case communityId = "ci"
        case communityRiskDensity = "cr"
        case hwProfileDegree = "hd"
        case devicePageRank = "pr"
        case isInDenseSubgraph = "ds"
    }

    public init(
        publicIP: String? = nil,
        asn: String? = nil,
        asOrg: String? = nil,
        isDatacenter: Bool? = nil,
        ipDeviceAgg: Int? = nil,
        ipAccountAgg: Int? = nil,
        geoCountry: String? = nil,
        geoRegion: String? = nil,
        riskTags: [String]? = nil,
        communityId: String? = nil,
        communityRiskDensity: Double? = nil,
        hwProfileDegree: Int? = nil,
        devicePageRank: Double? = nil,
        isInDenseSubgraph: Bool? = nil
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
        self.communityId = communityId
        self.communityRiskDensity = communityRiskDensity
        self.hwProfileDegree = hwProfileDegree
        self.devicePageRank = devicePageRank
        self.isInDenseSubgraph = isInDenseSubgraph
    }
}

private struct DetectionResultPayload: Codable {
    var isJailbroken: Bool
    var confidence: Double
    var detectedMethods: [String]
    var details: String

    private enum CodingKeys: String, CodingKey {
        case isJailbroken = "ij"
        case confidence = "c"
        case detectedMethods = "dm"
        case details = "dt"
    }

    init(_ result: DetectionResult) {
        self.isJailbroken = result.isJailbroken
        self.confidence = result.confidence
        self.detectedMethods = result.detectedMethods
        self.details = result.details
    }
}

enum Version {
    static let current = "6.5.0"
}

// MARK: - Signal Digest

/// Shared signal digest computation used by SignedRiskConclusion, Payload, and signal continuity checks.
///
/// Score and confidence are quantized to discrete buckets so that minor floating-point
/// jitter between successive evaluations does not change the digest. This prevents
/// false-positive HMAC mismatches on legitimate devices while still detecting
/// meaningful manipulation (e.g., an attacker zeroing out a score).
enum SignalDigest {
    /// Full digest: SHA-256 of sorted "id:scoreBucket:stateTag" entries.
    static func computeFullDigest(_ signals: [RiskSignal]) -> String {
        let entries = signals.map { signal in
            "\(signal.id):\(scoreBucket(signal.score)):\(stableStateTag(signal.state))"
        }.sorted()
        let joined = entries.joined(separator: ",")
        let hash = SHA256.hash(data: Data(joined.utf8))
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    /// Full digest from CPRiskSignal array.
    static func computeFullDigest(_ signals: [CPRiskSignal]) -> String {
        let entries = signals.map { signal in
            "\(signal.id):\(scoreBucket(signal.score)):\(signal.stateDescription)"
        }.sorted()
        let joined = entries.joined(separator: ",")
        let hash = SHA256.hash(data: Data(joined.utf8))
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    /// Quantize score into coarse 10-point buckets so small fluctuations don't flip the digest.
    /// 0 → "0", 7 → "0", 15 → "10", 25 → "20", 100 → "100".
    static func scoreBucket(_ score: Double) -> String {
        let clamped = max(0, min(score, 100))
        if clamped < 1 { return "0" }
        let bucket = Int(clamped) / 10 * 10
        return "\(bucket)"
    }

    /// Stable discrete tag for signal state. Confidence is quantized to integer percentage
    /// via floor (e.g. 0.7444 and 0.7449 both become "74"), eliminating ±0.0001 jitter.
    static func stableStateTag(_ state: RiskSignalState?) -> String {
        guard let state else { return "none" }
        switch state {
        case .hard(let detected):
            return "hard:\(detected ? "1" : "0")"
        case .soft(let confidence):
            let quantized = Int(confidence * 100)
            return "soft:\(quantized)"
        case .serverRequired:
            return "serverRequired"
        case .unavailable:
            return "unavailable"
        case .tampered:
            return "tampered"
        }
    }

    static func stableStateString(_ state: RiskSignalState?) -> String {
        stableStateTag(state)
    }
}
