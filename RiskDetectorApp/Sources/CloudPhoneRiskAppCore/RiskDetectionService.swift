import CloudPhoneRiskKit
import Foundation

/// 检测 App 的“后端服务层”：统一封装 start/stop、evaluate、保存与注入能力。
public final class RiskDetectionService {
    public static let shared = RiskDetectionService()

    private init() {}

    /// 启动采集（触摸 + 传感器）。建议 App 启动尽早调用。
    public func start() {
        CPRiskKit.shared.start()
    }

    public func stop() {
        CPRiskKit.shared.stop()
    }

    public func setLogEnabled(_ enabled: Bool) {
        CPRiskKit.setLogEnabled(enabled)
    }

    /// 生成一次报告（同步）。
    public func evaluate(config: RiskAppConfig = .default) -> CPRiskReport {
        CPRiskKit.shared.evaluate(config: config.toCPRiskConfig())
    }

    /// 生成一次报告（异步，completion 回到主线程）。
    public func evaluateAsync(config: RiskAppConfig = .default, completion: @escaping (CPRiskReport) -> Void) {
        CPRiskKit.shared.evaluateAsync(config: config.toCPRiskConfig(), completion: completion)
    }

    /// 一次“检测运行”：evaluate -> DTO -> 保存（可选）-> 返回 DTO/JSON/路径。
    /// completion 始终回到主线程。
    public func runAsync(
        config: RiskAppConfig = .default,
        save: Bool = true,
        completion: @escaping (RiskDetectionRunResult) -> Void
    ) {
        evaluateAsync(config: config) { report in
            let dto = RiskReportMapper.dto(from: report)
            let json = String(data: report.jsonData(prettyPrinted: true), encoding: .utf8) ?? "{}"
            let path = save ? self.save(report: report, config: config) : nil
            completion(RiskDetectionRunResult(dto: dto, json: json, savedPath: path))
        }
    }

    /// 保存报告到本地（默认 AES-GCM 加密），返回绝对路径。
    @discardableResult
    public func save(report: CPRiskReport, config: RiskAppConfig = .default) -> String? {
#if os(iOS)
        CPRiskStore.shared.encryptionEnabled = config.storeEncryptionEnabled
        CPRiskStore.shared.maxFiles = config.storeMaxFiles
        let path = CPRiskStore.shared.save(report, error: nil)
        if let path, let dto = RiskReportMapper.dto(from: report.jsonData(prettyPrinted: false)) {
            RiskReportSummaryIO.writeMeta(for: dto, reportPath: path)
        }
        return path
#else
        guard let dir = try? RiskReportStorage.reportsDirectoryURL() else { return nil }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let filename = "risk-\(iso8601Now()).json"
        let url = dir.appendingPathComponent(filename)
        do {
            try report.jsonData(prettyPrinted: true).write(to: url, options: [.atomic])
            if let dto = RiskReportMapper.dto(from: report.jsonData(prettyPrinted: false)) {
                RiskReportSummaryIO.writeMeta(for: dto, reportPath: url.path)
            }
            return url.path
        } catch {
            return nil
        }
#endif
    }

    /// 同机读取/解密本地报告文件，返回 JSON 字符串。
    public func loadSavedReportJSON(atPath path: String) -> String? {
#if os(iOS)
        CPRiskStore.shared.decryptReport(atPath: path, error: nil)
#else
        RiskReportStorage.loadJSONString(atPath: path)
#endif
    }

    /// 注入“未来云端聚合信号”（用于调试验证 JSON/server 节点与 provider 评分链路）。
    public func setExternalServerSignals(
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
        CPRiskKit.setExternalServerSignals(
            publicIP: publicIP,
            asn: asn,
            asOrg: asOrg,
            isDatacenter: isDatacenter,
            ipDeviceAgg: ipDeviceAgg,
            ipAccountAgg: ipAccountAgg,
            geoCountry: geoCountry,
            geoRegion: geoRegion,
            riskTags: riskTags
        )
    }

    public func clearExternalServerSignals() {
        CPRiskKit.clearExternalServerSignals()
    }

    /// Provider 管理（Swift-only）。
    public func register(provider: RiskSignalProvider) {
        CPRiskKit.register(provider: provider)
    }

    public func unregisterProvider(id: String) {
        CPRiskKit.unregisterProvider(id: id)
    }

    public func registeredProviderIDs() -> [String] {
        CPRiskKit.registeredProviderIDs()
    }

    private func iso8601Now() -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: Date())
    }
}
