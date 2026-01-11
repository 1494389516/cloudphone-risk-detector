import CloudPhoneRiskKit
import Foundation

public struct StoredRiskReport: Sendable, Hashable {
    public var path: String
    public var filename: String
    public var modifiedAt: Date?
    public var bytes: Int64
    public var isEncrypted: Bool
}

/// 检测 App 的“报告存储层”：负责列举/读取/清空本地报告文件。
public enum RiskReportStorage {
    public static func reportsDirectoryURL() throws -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        guard let base else {
            throw NSError(domain: "CloudPhoneRiskAppCore", code: 1, userInfo: [NSLocalizedDescriptionKey: "applicationSupportDirectory unavailable"])
        }
        return base.appendingPathComponent("CloudPhoneRiskKit/reports", isDirectory: true)
    }

    public static func list() -> [StoredRiskReport] {
        guard let dir = try? reportsDirectoryURL() else { return [] }
        return list(in: dir)
    }

    public static func list(in dir: URL) -> [StoredRiskReport] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(
            at: dir,
            includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey],
            options: [.skipsHiddenFiles]
        ) else { return [] }

        let out: [StoredRiskReport] = items.compactMap { url in
            let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
            let bytes = Int64(values?.fileSize ?? 0)
            let name = url.lastPathComponent
            if name.hasSuffix(".meta.json") { return nil }
            return StoredRiskReport(
                path: url.path,
                filename: name,
                modifiedAt: values?.contentModificationDate,
                bytes: bytes,
                isEncrypted: !name.hasSuffix(".json")
            )
        }

        return out.sorted { (a, b) in
            let ad = a.modifiedAt ?? .distantPast
            let bd = b.modifiedAt ?? .distantPast
            return ad > bd
        }
    }

    public static func loadJSONString(atPath path: String) -> String? {
#if os(iOS)
        return CPRiskStore.shared.decryptReport(atPath: path, error: nil)
#else
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        return String(data: data, encoding: .utf8)
#endif
    }

    public static func loadDTO(atPath path: String) -> RiskReportDTO? {
        guard let json = loadJSONString(atPath: path) else { return nil }
        guard let data = json.data(using: .utf8) else { return nil }
        return RiskReportMapper.dto(from: data)
    }

    public static func listSummaries() -> [(report: StoredRiskReport, summary: RiskReportSummary?)] {
        guard let dir = try? reportsDirectoryURL() else { return [] }
        return listSummaries(in: dir)
    }

    public static func listSummaries(in dir: URL) -> [(report: StoredRiskReport, summary: RiskReportSummary?)] {
        let reports = list(in: dir)
        return reports.map { r in
            if let meta = RiskReportSummaryIO.readMeta(reportPath: r.path) {
                return (r, meta)
            }
            guard let dto = loadDTO(atPath: r.path) else { return (r, nil) }
            RiskReportSummaryIO.writeMeta(for: dto, reportPath: r.path)
            let summary = RiskReportSummaryIO.readMeta(reportPath: r.path)
            return (r, summary)
        }
    }

    public static func delete(atPath path: String) -> Bool {
        let meta = RiskReportSummaryIO.metaPath(forReportPath: path)
        _ = try? FileManager.default.removeItem(atPath: meta)
        return (try? FileManager.default.removeItem(atPath: path)) != nil
    }

    public static func deleteAll() {
        let items = list()
        for i in items {
            _ = delete(atPath: i.path)
        }
    }
}
