import Foundation
import SwiftUI

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
#endif

// MARK: - History Item (UI model wrapping StoredRiskReport + Summary)
public struct HistoryItem: Identifiable, Hashable {
    public let id: String  // path
    public let filename: String
    public let modifiedAt: Date?
    public let bytes: Int64
    public let isEncrypted: Bool

    // From meta.json (may be nil if not yet cached)
    public let summary: RiskReportSummary?

    // Convenience
    public var formattedDate: String {
        guard let date = modifiedAt else { return "-" }
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm"
        return formatter.string(from: date)
    }

    public var formattedSize: String {
        let bcf = ByteCountFormatter()
        bcf.allowedUnits = [.useKB, .useMB]
        bcf.countStyle = .file
        return bcf.string(fromByteCount: bytes)
    }

    public var riskLevel: RiskLevel? {
        guard let score = summary?.score else { return nil }
        return RiskLevel.from(score: score)
    }

    #if canImport(CloudPhoneRiskAppCore)
    public init(stored: StoredRiskReport, summary: RiskReportSummary?) {
        self.id = stored.path
        self.filename = stored.filename
        self.modifiedAt = stored.modifiedAt
        self.bytes = stored.bytes
        self.isEncrypted = stored.isEncrypted
        self.summary = summary
    }
    #endif

    // Mock init for preview
    public init(id: String, filename: String, modifiedAt: Date?, bytes: Int64, isEncrypted: Bool, summary: RiskReportSummary?) {
        self.id = id
        self.filename = filename
        self.modifiedAt = modifiedAt
        self.bytes = bytes
        self.isEncrypted = isEncrypted
        self.summary = summary
    }
}

// MARK: - History ViewModel
/// 规范：
/// - 输出：items: [HistoryItem]（包含 summary）
/// - 行为：reload/delete/loadDTO
/// - 点击详情才加载 DTO
@MainActor
public class HistoryViewModel: ObservableObject {
    // MARK: - Published State
    @Published public var items: [HistoryItem] = []
    @Published public var isLoading: Bool = false

    // Detail sheet
    @Published public var selectedDTO: RiskReportDTO?
    @Published public var selectedItem: HistoryItem?
    @Published public var showDetail: Bool = false

    public init() {}

    // MARK: - Actions

    /// 重新加载历史列表（优先读 meta.json）
    public func reload() {
        isLoading = true

        #if canImport(CloudPhoneRiskAppCore)
        let summaries = RiskReportStorage.listSummaries()
        items = summaries.map { HistoryItem(stored: $0.report, summary: $0.summary) }
        #else
        // Mock for preview
        items = Self.mockItems()
        #endif

        isLoading = false
    }

    /// 加载详情 DTO（点击列表项时调用）
    public func loadDetail(for item: HistoryItem) {
        selectedItem = item

        #if canImport(CloudPhoneRiskAppCore)
        if let dto = RiskReportStorage.loadDTO(atPath: item.id) {
            selectedDTO = dto
            showDetail = true
        }
        #else
        // Mock
        selectedDTO = nil
        showDetail = true
        #endif
    }

    /// 删除单个记录
    public func delete(_ item: HistoryItem) {
        #if canImport(CloudPhoneRiskAppCore)
        _ = RiskReportStorage.delete(atPath: item.id)
        #endif
        items.removeAll { $0.id == item.id }
    }

    /// 删除（配合 List 的 onDelete）
    public func delete(atOffsets offsets: IndexSet) {
        for idx in offsets {
            guard idx >= 0, idx < items.count else { continue }
            delete(items[idx])
        }
    }

    /// 删除全部记录
    public func deleteAll() {
        #if canImport(CloudPhoneRiskAppCore)
        RiskReportStorage.deleteAll()
        #endif
        items.removeAll()
    }

    /// 关闭详情
    public func dismissDetail() {
        showDetail = false
        selectedDTO = nil
        selectedItem = nil
    }

    // MARK: - Mock
    #if !canImport(CloudPhoneRiskAppCore)
    private static func mockItems() -> [HistoryItem] {
        let summary1 = RiskReportSummary(
            generatedAt: "2026-01-11T10:30:00Z",
            score: 75,
            isHighRisk: true,
            summary: "High risk detected",
            jailbreakIsJailbroken: true,
            jailbreakConfidence: 85,
            vpnDetected: true,
            proxyDetected: false,
            interfaceType: "wifi"
        )
        let summary2 = RiskReportSummary(
            generatedAt: "2026-01-10T15:22:00Z",
            score: 12,
            isHighRisk: false,
            summary: "Low risk",
            jailbreakIsJailbroken: false,
            jailbreakConfidence: 0,
            vpnDetected: false,
            proxyDetected: false,
            interfaceType: "wifi"
        )
        return [
            HistoryItem(id: "/path/1", filename: "risk-2026-01-11.enc", modifiedAt: Date(), bytes: 2048, isEncrypted: true, summary: summary1),
            HistoryItem(id: "/path/2", filename: "risk-2026-01-10.enc", modifiedAt: Date().addingTimeInterval(-86400), bytes: 1856, isEncrypted: true, summary: summary2),
        ]
    }
    #endif
}
