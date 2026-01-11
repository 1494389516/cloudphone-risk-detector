import Foundation
import SwiftUI
import Combine

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
import CloudPhoneRiskKit
#endif

// MARK: - Detection State
public enum DetectionState: Equatable {
    case idle
    case detecting
    case completed
    case error(String)
}

// MARK: - Risk Level (UI only)
public enum RiskLevel: String {
    case low = "低风险"
    case medium = "中风险"
    case high = "高风险"

    public var color: Color {
        switch self {
        case .low: return .green
        case .medium: return .orange
        case .high: return .red
        }
    }

    public var icon: String {
        switch self {
        case .low: return "checkmark.shield.fill"
        case .medium: return "exclamationmark.shield.fill"
        case .high: return "xmark.shield.fill"
        }
    }

    public static func from(score: Double) -> RiskLevel {
        if score < 30 { return .low }
        else if score < 60 { return .medium }
        else { return .high }
    }
}

// MARK: - Detection ViewModel
/// 规范：
/// - 输入：RiskAppConfig（来自 Settings）
/// - 输出：lastDTO, isDetecting, error
/// - 只暴露 DTO，UI 不接触 CPRiskReport
@MainActor
public class DetectionViewModel: ObservableObject {
    // MARK: - Published State
    @Published public var state: DetectionState = .idle
    @Published public var lastDTO: RiskReportDTO?
    @Published public var showResults: Bool = false

    // MARK: - Derived (UI convenience)
    public var riskLevel: RiskLevel? {
        guard let dto = lastDTO else { return nil }
        return RiskLevel.from(score: dto.score)
    }

    public var isDetecting: Bool {
        state == .detecting
    }

    // Keep raw report for save operation
    #if canImport(CloudPhoneRiskAppCore)
    private var lastReport: CPRiskReport?
    #endif

    public init() {}

    // MARK: - Actions

    /// 启动采集（App 启动时调用一次）
    public func startIfNeeded() {
        #if canImport(CloudPhoneRiskAppCore)
        RiskDetectionService.shared.start()
        #endif
    }

    /// 执行检测
    /// - Parameter config: 检测配置（来自 SettingsViewModel）
    public func detect(config: RiskAppConfig? = nil) {
        state = .detecting

        #if canImport(CloudPhoneRiskAppCore)
        let cfg = config ?? .default
        RiskDetectionService.shared.evaluateAsync(config: cfg) { [weak self] report in
            DispatchQueue.main.async {
                self?.lastReport = report
                self?.lastDTO = RiskReportMapper.dto(from: report)
                self?.state = .completed
                self?.showResults = true
            }
        }
        #else
        // Mock for preview
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            self?.lastDTO = Self.mockDTO()
            self?.state = .completed
            self?.showResults = true
        }
        #endif
    }

    /// 保存报告到本地（自动写 meta.json）
    /// - Returns: 保存路径，nil 表示失败
    @discardableResult
    public func save(config: RiskAppConfig? = nil) -> String? {
        #if canImport(CloudPhoneRiskAppCore)
        guard let report = lastReport, let dto = lastDTO else { return nil }
        let cfg = config ?? .default
        guard let path = RiskDetectionService.shared.save(report: report, config: cfg) else { return nil }
        // Write meta for fast History loading
        RiskReportSummaryIO.writeMeta(for: dto, reportPath: path)
        return path
        #else
        return nil
        #endif
    }

    /// 重置状态
    public func reset() {
        state = .idle
        lastDTO = nil
        showResults = false
        #if canImport(CloudPhoneRiskAppCore)
        lastReport = nil
        #endif
    }

    // MARK: - Mock for Preview
    #if !canImport(CloudPhoneRiskAppCore)
    private static func mockDTO() -> RiskReportDTO {
        // Minimal mock for SwiftUI preview
        fatalError("Mock DTO not implemented for non-iOS")
    }
    #endif
}
