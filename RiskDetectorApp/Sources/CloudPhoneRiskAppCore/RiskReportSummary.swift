import CloudPhoneRiskKit
import Foundation

/// 云手机判定阈值（共享常量）：`RiskReportDTO` 的 cloud 信号映射与
/// `RiskReportSummary` 的 `cloudDetected` 必须用同一常量。
/// 取值沿用 DTO 侧历史值（device 20 / account 30）；Summary 侧旧值
///（50 / 100）已统一为本常量——此前 Summary 侧对 20…49 的聚合会漏判。
public enum CloudPhoneAggregationThresholds {
    /// 同一 IP 聚合设备数 ≥ 该值 → 判定云手机。
    public static let ipDeviceAgg: Int = 20
    /// 同一 IP 聚合账号数 ≥ 该值 → 判定云手机。
    public static let ipAccountAgg: Int = 30

    public static func isCloudDetected(server: ServerSignals?) -> Bool? {
        guard let server else { return nil }
        if server.isDatacenter == true { return true }
        if (server.ipDeviceAgg ?? 0) >= ipDeviceAgg { return true }
        if (server.ipAccountAgg ?? 0) >= ipAccountAgg { return true }
        if let tags = server.riskTags, !tags.isEmpty { return true }
        return false
    }
}

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
        let cloudDetected = CloudPhoneAggregationThresholds.isCloudDetected(server: dto.server)
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
        let cloudDetected = CloudPhoneAggregationThresholds.isCloudDetected(server: dto.server)
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
