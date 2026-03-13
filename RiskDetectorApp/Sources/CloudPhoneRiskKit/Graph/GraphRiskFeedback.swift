import Foundation

// MARK: - 图风控反馈协议
///
/// 服务端返回图计算结果后，通过此协议注入 ExternalServerAggregateProvider，
/// 用于增强本地评分与决策。
public protocol GraphRiskFeedback: Sendable {
    var communityId: String? { get }
    var communityRiskDensity: Double? { get }
    var hwProfileDegree: Int? { get }
    var devicePageRank: Double? { get }
    var isInDenseSubgraph: Bool? { get }
    var riskTags: [String]? { get }
}

// MARK: - 默认实现
public struct DefaultGraphRiskFeedback: GraphRiskFeedback, Sendable {
    public let communityId: String?
    public let communityRiskDensity: Double?
    public let hwProfileDegree: Int?
    public let devicePageRank: Double?
    public let isInDenseSubgraph: Bool?
    public let riskTags: [String]?

    public init(
        communityId: String? = nil,
        communityRiskDensity: Double? = nil,
        hwProfileDegree: Int? = nil,
        devicePageRank: Double? = nil,
        isInDenseSubgraph: Bool? = nil,
        riskTags: [String]? = nil
    ) {
        self.communityId = communityId
        self.communityRiskDensity = communityRiskDensity
        self.hwProfileDegree = hwProfileDegree
        self.devicePageRank = devicePageRank
        self.isInDenseSubgraph = isInDenseSubgraph
        self.riskTags = riskTags
    }
}
