import Foundation

public struct RiskDetectionRunResult: Sendable {
    public var dto: RiskReportDTO
    public var json: String
    public var savedPath: String?

    public init(dto: RiskReportDTO, json: String, savedPath: String?) {
        self.dto = dto
        self.json = json
        self.savedPath = savedPath
    }
}

