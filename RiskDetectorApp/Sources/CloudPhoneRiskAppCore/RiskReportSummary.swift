import CloudPhoneRiskKit
import Foundation

public struct RiskReportSummary: Codable, Sendable, Hashable {
    public var generatedAt: String?
    public var score: Double?
    public var isHighRisk: Bool?
    public var summary: String?

    public var jailbreakIsJailbroken: Bool?
    public var jailbreakConfidence: Double?

    public var vpnDetected: Bool?
    public var proxyDetected: Bool?
    public var interfaceType: String?

    /// Best-effort "cloud phone" flag from server aggregation signals.
    public var cloudDetected: Bool?
}

public enum RiskReportSummaryIO {
    public static func metaPath(forReportPath path: String) -> String {
        "\(path).meta.json"
    }

    public static func writeMeta(for dto: RiskReportDTO, reportPath: String) {
        let cloudDetected: Bool? = {
            guard let server = dto.server else { return nil }
            if server.isDatacenter == true { return true }
            if (server.ipDeviceAgg ?? 0) >= 50 { return true }
            if (server.ipAccountAgg ?? 0) >= 100 { return true }
            if let tags = server.riskTags, !tags.isEmpty { return true }
            return false
        }()
        let s = RiskReportSummary(
            generatedAt: dto.generatedAt,
            score: dto.score,
            isHighRisk: dto.isHighRisk,
            summary: dto.summary,
            jailbreakIsJailbroken: dto.jailbreak.isJailbroken,
            jailbreakConfidence: dto.jailbreak.confidence,
            vpnDetected: dto.network.vpn.detected,
            proxyDetected: dto.network.proxy.detected,
            interfaceType: dto.network.interfaceType.value,
            cloudDetected: cloudDetected
        )
        let metaURL = URL(fileURLWithPath: metaPath(forReportPath: reportPath))
        guard let data = try? JSONEncoder().encode(s) else { return }
        try? data.write(to: metaURL, options: [.atomic])
    }

    public static func readMeta(reportPath: String) -> RiskReportSummary? {
        let metaURL = URL(fileURLWithPath: metaPath(forReportPath: reportPath))
        guard let data = try? Data(contentsOf: metaURL) else { return nil }
        return try? JSONDecoder().decode(RiskReportSummary.self, from: data)
    }

    public static func summary(fromJSONData data: Data) -> RiskReportSummary? {
        guard let dto = RiskReportMapper.dto(from: data) else { return nil }
        let cloudDetected: Bool? = {
            guard let server = dto.server else { return nil }
            if server.isDatacenter == true { return true }
            if (server.ipDeviceAgg ?? 0) >= 50 { return true }
            if (server.ipAccountAgg ?? 0) >= 100 { return true }
            if let tags = server.riskTags, !tags.isEmpty { return true }
            return false
        }()
        return RiskReportSummary(
            generatedAt: dto.generatedAt,
            score: dto.score,
            isHighRisk: dto.isHighRisk,
            summary: dto.summary,
            jailbreakIsJailbroken: dto.jailbreak.isJailbroken,
            jailbreakConfidence: dto.jailbreak.confidence,
            vpnDetected: dto.network.vpn.detected,
            proxyDetected: dto.network.proxy.detected,
            interfaceType: dto.network.interfaceType.value,
            cloudDetected: cloudDetected
        )
    }
}
