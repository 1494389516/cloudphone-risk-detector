import CloudPhoneRiskKit
import Foundation

public struct RiskReportDTO: Codable, Sendable {
    public var sdkVersion: String?
    public var reportId: String?
    public var timestamp: Double?
    public var generatedAt: String
    public var deviceID: String

    public var score: Double
    public var isHighRisk: Bool
    public var summary: String
    public var tamperedCount: Int?

    public var jailbreak: JailbreakDTO
    public var network: NetworkSignals
    public var behavior: BehaviorSignals
    public var server: ServerSignals?
    public var local: LocalSignals?

    public var gpuName: String?
    public var kernelBuild: String?
    public var deviceModel: String?
    public var imuMagnitude: Double?
    public var imuVariance: Double?
    public var touchForceVar: Double?

    public var signals: [RiskSignal]

    public var hardSignals: [SignalItemDTO]
    public var softSignals: [SignalItemDTO]

    public init(
        sdkVersion: String?,
        reportId: String? = nil,
        timestamp: Double? = nil,
        generatedAt: String,
        deviceID: String,
        score: Double,
        isHighRisk: Bool,
        summary: String,
        tamperedCount: Int? = nil,
        jailbreak: JailbreakDTO,
        network: NetworkSignals,
        behavior: BehaviorSignals,
        server: ServerSignals?,
        local: LocalSignals?,
        gpuName: String? = nil,
        kernelBuild: String? = nil,
        deviceModel: String? = nil,
        imuMagnitude: Double? = nil,
        imuVariance: Double? = nil,
        touchForceVar: Double? = nil,
        signals: [RiskSignal],
        hardSignals: [SignalItemDTO],
        softSignals: [SignalItemDTO]
    ) {
        self.sdkVersion = sdkVersion
        self.reportId = reportId
        self.timestamp = timestamp
        self.generatedAt = generatedAt
        self.deviceID = deviceID
        self.score = score
        self.isHighRisk = isHighRisk
        self.summary = summary
        self.tamperedCount = tamperedCount
        self.jailbreak = jailbreak
        self.network = network
        self.behavior = behavior
        self.server = server
        self.local = local
        self.gpuName = gpuName
        self.kernelBuild = kernelBuild
        self.deviceModel = deviceModel
        self.imuMagnitude = imuMagnitude
        self.imuVariance = imuVariance
        self.touchForceVar = touchForceVar
        self.signals = signals
        self.hardSignals = hardSignals
        self.softSignals = softSignals
    }
}

public struct JailbreakDTO: Codable, Sendable {
    public var isJailbroken: Bool
    public var confidence: Double
    public var detectedMethods: [String]
    public var details: String
}

public struct SignalItemDTO: Codable, Sendable {
    public enum Kind: String, Codable, Sendable { case hard, soft }

    public var id: String
    public var title: String
    public var kind: Kind
    public var detected: Bool
    public var confidence: SignalConfidence?
    public var method: String?
    public var evidenceSummary: String?

    public init(
        id: String,
        title: String,
        kind: Kind,
        detected: Bool,
        confidence: SignalConfidence? = nil,
        method: String? = nil,
        evidenceSummary: String? = nil
    ) {
        self.id = id
        self.title = title
        self.kind = kind
        self.detected = detected
        self.confidence = confidence
        self.method = method
        self.evidenceSummary = evidenceSummary
    }
}

public enum RiskReportMapper {
    public static func dto(from report: CPRiskReport) -> RiskReportDTO {
        let data = report.jsonData(prettyPrinted: false)
        return dto(from: data) ?? fallbackDTO(from: report)
    }

    public static func dto(from jsonData: Data) -> RiskReportDTO? {
        guard let payload = try? JSONDecoder().decode(PayloadMirror.self, from: jsonData) else { return nil }

        let jailbreak = JailbreakDTO(
            isJailbroken: payload.jailbreak.isJailbroken,
            confidence: payload.jailbreak.confidence,
            detectedMethods: payload.jailbreak.detectedMethods,
            details: payload.jailbreak.details
        )

        var hard = [
            SignalItemDTO(
                id: "jailbreak",
                title: "越狱",
                kind: .hard,
                detected: jailbreak.isJailbroken,
                confidence: .strong,
                method: "detectors",
                evidenceSummary: jailbreak.detectedMethods.prefix(5).joined(separator: ",")
            ),
        ]

        var soft: [SignalItemDTO] = []
        soft.append(
            SignalItemDTO(
                id: "vpn",
                title: "VPN 信号",
                kind: .soft,
                detected: payload.network.vpn.detected,
                confidence: payload.network.vpn.confidence,
                method: payload.network.vpn.method,
                evidenceSummary: payload.network.vpn.evidence?.prefix(5).joined(separator: ",")
            )
        )
        let proxyEvidence = payload.network.proxy.evidence?.map { "\($0.key)=\($0.value)" }.sorted().prefix(5).joined(separator: ",")
        soft.append(
            SignalItemDTO(
                id: "proxy",
                title: "代理信号",
                kind: .soft,
                detected: payload.network.proxy.detected,
                confidence: payload.network.proxy.confidence,
                method: payload.network.proxy.method,
                evidenceSummary: proxyEvidence
            )
        )

        if let cloud = payload.local?.cloudPhone {
            soft.append(
                SignalItemDTO(
                    id: "simulator",
                    title: "模拟器环境",
                    kind: .soft,
                    detected: cloud.device.isSimulator.detected,
                    confidence: cloud.device.isSimulator.confidence,
                    method: cloud.device.isSimulator.method,
                    evidenceSummary: summarizeEvidence(cloud.device.isSimulator.evidence)
                )
            )

            if let old = cloud.device.oldDeviceModel {
                soft.append(
                    SignalItemDTO(
                        id: "old_device_model",
                        title: "老机型信号",
                        kind: .soft,
                        detected: old.detected,
                        confidence: old.confidence,
                        method: old.method,
                        evidenceSummary: summarizeEvidence(old.evidence)
                    )
                )
            }

            let behaviorDetectedIDs: [String] = [
                cloud.behavior.touchSpreadLow.detected ? "touch_spread_low" : nil,
                cloud.behavior.touchSpreadHigh.detected ? "touch_spread_high" : nil,
                cloud.behavior.touchIntervalTooRegular.detected ? "touch_interval_too_regular" : nil,
                cloud.behavior.touchIntervalTooChaotic.detected ? "touch_interval_too_chaotic" : nil,
                cloud.behavior.swipeTooLinear.detected ? "swipe_too_linear" : nil,
                cloud.behavior.swipeTooCurvy.detected ? "swipe_too_curvy" : nil,
                cloud.behavior.motionTooStill.detected ? "motion_too_still" : nil,
                cloud.behavior.touchMotionWeakCoupling.detected ? "touch_motion_weak_coupling" : nil,
            ].compactMap { $0 }

            soft.append(
                SignalItemDTO(
                    id: "cloud_behavior",
                    title: "行为信号",
                    kind: .soft,
                    detected: !behaviorDetectedIDs.isEmpty,
                    confidence: behaviorDetectedIDs.isEmpty ? .weak : .medium,
                    method: "local_heuristics",
                    evidenceSummary: behaviorDetectedIDs.isEmpty ? "none" : behaviorDetectedIDs.joined(separator: ",")
                )
            )

            let timeDetectedIDs: [String] = [
                cloud.time.highVolume24h.detected ? "high_volume_24h" : nil,
                cloud.time.wideHourCoverage24h.detected ? "wide_hour_coverage_24h" : nil,
                cloud.time.nightActivityHigh24h.detected ? "night_activity_high_24h" : nil,
                cloud.time.highFrequency24h.detected ? "high_frequency_24h" : nil,
            ].compactMap { $0 }

            soft.append(
                SignalItemDTO(
                    id: "time_pattern",
                    title: "时间模式信号",
                    kind: .soft,
                    detected: !timeDetectedIDs.isEmpty,
                    confidence: timeDetectedIDs.isEmpty ? .weak : .medium,
                    method: "history_24h",
                    evidenceSummary: timeDetectedIDs.isEmpty ? "none" : timeDetectedIDs.joined(separator: ",")
                )
            )
        } else {
            soft.append(
                SignalItemDTO(
                    id: "cloud_local_unavailable",
                    title: "云手机信号（本地）",
                    kind: .soft,
                    detected: false,
                    confidence: nil,
                    method: "not_collected",
                    evidenceSummary: "local.cloudPhone is nil"
                )
            )
        }

        // Cloud phone / server-side aggregation signals (typically from backend).
        if let server = payload.server {
            soft.append(
                SignalItemDTO(
                    id: "cloud_datacenter",
                    title: "机房/云 IP",
                    kind: .soft,
                    detected: server.isDatacenter == true,
                    confidence: .strong,
                    method: "server_signals",
                    evidenceSummary: server.publicIP ?? server.asn ?? server.asOrg
                )
            )

            if let n = server.ipDeviceAgg {
                soft.append(
                    SignalItemDTO(
                        id: "cloud_ip_device_agg",
                        title: "IP 设备聚合度",
                        kind: .soft,
                        detected: n >= 20,
                        confidence: .medium,
                        method: "server_signals",
                        evidenceSummary: "\(n)"
                    )
                )
            }

            if let n = server.ipAccountAgg {
                soft.append(
                    SignalItemDTO(
                        id: "cloud_ip_account_agg",
                        title: "IP 账号聚合度",
                        kind: .soft,
                        detected: n >= 30,
                        confidence: .medium,
                        method: "server_signals",
                        evidenceSummary: "\(n)"
                    )
                )
            }

            if let tags = server.riskTags, !tags.isEmpty {
                soft.append(
                    SignalItemDTO(
                        id: "cloud_risk_tags",
                        title: "风险标签",
                        kind: .soft,
                        detected: true,
                        confidence: .medium,
                        method: "server_signals",
                        evidenceSummary: tags.prefix(5).joined(separator: ",")
                    )
                )
            }
        } else {
            soft.append(
                SignalItemDTO(
                    id: "cloud_unavailable",
                    title: "云手机信号（服务端）",
                    kind: .soft,
                    detected: false,
                    confidence: nil,
                    method: "need_backend",
                    evidenceSummary: "no_server_signals"
                )
            )
        }

        appendV3Signals(from: payload.signals, hard: &hard, soft: &soft)

        return RiskReportDTO(
            sdkVersion: payload.sdkVersion,
            reportId: payload.reportId,
            timestamp: payload.timestamp,
            generatedAt: payload.generatedAt,
            deviceID: payload.deviceID,
            score: payload.score,
            isHighRisk: payload.isHighRisk,
            summary: payload.summary,
            tamperedCount: payload.tamperedCount,
            jailbreak: jailbreak,
            network: payload.network,
            behavior: payload.behavior,
            server: payload.server,
            local: payload.local,
            gpuName: payload.gpuName,
            kernelBuild: payload.kernelBuild,
            deviceModel: payload.deviceModel,
            imuMagnitude: payload.imuMagnitude,
            imuVariance: payload.imuVariance,
            touchForceVar: payload.touchForceVar,
            signals: payload.signals,
            hardSignals: hard,
            softSignals: soft
        )
    }

    private static func fallbackDTO(from report: CPRiskReport) -> RiskReportDTO {
        let jailbreak = JailbreakDTO(
            isJailbroken: report.jailbreakIsJailbroken,
            confidence: report.jailbreakConfidence,
            detectedMethods: report.detectedMethods,
            details: ""
        )
        return RiskReportDTO(
            sdkVersion: nil,
            generatedAt: ISO8601DateFormatter().string(from: Date()),
            deviceID: report.deviceID,
            score: report.score,
            isHighRisk: report.isHighRisk,
            summary: report.summary,
            jailbreak: jailbreak,
            network: NetworkSignals.current(),
            behavior: emptyBehaviorSignals(),
            server: nil,
            local: nil,
            signals: [],
            hardSignals: [
                SignalItemDTO(id: "jailbreak", title: "越狱", kind: .hard, detected: jailbreak.isJailbroken),
            ],
            softSignals: [
                SignalItemDTO(
                    id: "cloud_unavailable",
                    title: "云手机信号（服务端）",
                    kind: .soft,
                    detected: false,
                    confidence: nil,
                    method: "need_backend",
                    evidenceSummary: "no_server_signals"
                ),
            ]
        )
    }

    private static func emptyBehaviorSignals() -> BehaviorSignals {
        // CloudPhoneRiskKit's memberwise inits are internal; decode a known-empty JSON instead.
        let json = """
        {
          "touch": {
            "sampleCount": 0,
            "tapCount": 0,
            "swipeCount": 0,
            "coordinateSpread": null,
            "intervalCV": null,
            "averageLinearity": null
          },
          "motion": {
            "sampleCount": 0,
            "stillnessRatio": null,
            "motionEnergy": null
          },
          "touchMotionCorrelation": null,
          "actionCount": 0
        }
        """
        let data = Data(json.utf8)
        // If this fails, something is seriously wrong with the public Codable schema; crash early in debug.
        return (try? JSONDecoder().decode(BehaviorSignals.self, from: data)) ?? {
            preconditionFailure("Unable to decode empty BehaviorSignals")
        }()
    }

    private static func summarizeEvidence(_ evidence: [String: String]?) -> String? {
        guard let evidence, !evidence.isEmpty else { return nil }
        return evidence
            .sorted { $0.key < $1.key }
            .prefix(6)
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: ",")
    }

    private static func appendV3Signals(
        from signals: [RiskSignal],
        hard: inout [SignalItemDTO],
        soft: inout [SignalItemDTO]
    ) {
        var hardIDs = Set(hard.map(\.id))
        var softIDs = Set(soft.map(\.id))

        for signal in signals {
            guard let state = signal.state else { continue }
            let title = signal.id
                .split(separator: "_")
                .map { $0.capitalized }
                .joined(separator: " ")
            let evidenceSummary = summarizeEvidence(signal.evidence)

            switch state {
            case .hard(let detected):
                guard !hardIDs.contains(signal.id) else { continue }
                hardIDs.insert(signal.id)
                hard.append(
                    SignalItemDTO(
                        id: signal.id,
                        title: title,
                        kind: .hard,
                        detected: detected,
                        confidence: detected ? .strong : .weak,
                        method: "layer\(signal.layer ?? 0)",
                        evidenceSummary: evidenceSummary
                    )
                )
            case .soft(let confidence):
                guard !softIDs.contains(signal.id) else { continue }
                softIDs.insert(signal.id)
                soft.append(
                    SignalItemDTO(
                        id: signal.id,
                        title: title,
                        kind: .soft,
                        detected: confidence > 0.3,
                        confidence: confidenceBucket(confidence),
                        method: "layer\(signal.layer ?? 0)",
                        evidenceSummary: evidenceSummary
                    )
                )
            case .tampered:
                guard !hardIDs.contains(signal.id) else { continue }
                hardIDs.insert(signal.id)
                hard.append(
                    SignalItemDTO(
                        id: signal.id,
                        title: "检测干扰",
                        kind: .hard,
                        detected: true,
                        confidence: .strong,
                        method: "layer\(signal.layer ?? 0)",
                        evidenceSummary: evidenceSummary
                    )
                )
            case .serverRequired:
                guard !softIDs.contains(signal.id) else { continue }
                softIDs.insert(signal.id)
                soft.append(
                    SignalItemDTO(
                        id: signal.id,
                        title: title,
                        kind: .soft,
                        detected: false,
                        confidence: nil,
                        method: "server_required",
                        evidenceSummary: evidenceSummary
                    )
                )
            case .unavailable:
                guard !softIDs.contains(signal.id) else { continue }
                softIDs.insert(signal.id)
                soft.append(
                    SignalItemDTO(
                        id: signal.id,
                        title: title,
                        kind: .soft,
                        detected: false,
                        confidence: nil,
                        method: "unavailable",
                        evidenceSummary: evidenceSummary
                    )
                )
            }
        }
    }

    private static func confidenceBucket(_ confidence: Double) -> SignalConfidence {
        switch confidence {
        case ..<0.35:
            return .weak
        case ..<0.75:
            return .medium
        default:
            return .strong
        }
    }
}

private struct PayloadMirror: Decodable {
    var sdkVersion: String?
    var reportId: String?
    var timestamp: Double?
    var generatedAt: String
    var deviceID: String
    var network: NetworkSignals
    var behavior: BehaviorSignals
    var jailbreak: JailbreakMirror
    var score: Double
    var isHighRisk: Bool
    var summary: String
    var tamperedCount: Int?
    var gpuName: String?
    var kernelBuild: String?
    var deviceModel: String?
    var imuMagnitude: Double?
    var imuVariance: Double?
    var touchForceVar: Double?
    var signals: [RiskSignal]
    var server: ServerSignals?
    var local: LocalSignals?
}

private struct JailbreakMirror: Decodable {
    var isJailbroken: Bool
    var confidence: Double
    var detectedMethods: [String]
    var details: String
}
