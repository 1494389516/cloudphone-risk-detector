import Foundation

/// Local injection point for future "server aggregation" signals (IP/ASN/datacenter/IP聚合度...).
/// You can set these fields locally (even without a backend) and they'll be:
/// - embedded into the JSON payload under `server`
/// - optionally contribute to score via generated `RiskSignal`s
final class ExternalServerAggregateProvider: RiskSignalProvider {
    static let shared = ExternalServerAggregateProvider()
    private init() {}

    let id = "server_aggregate"

    private let lock = NSLock()
    private var current: ServerSignals?
    private var graphFeatures: GraphFeatures?

    struct GraphFeatures {
        var communityId: String?
        var communityRiskDensity: Double?
        var hwProfileDegree: Int?
        var devicePageRank: Double?
        var isInDenseSubgraph: Bool?
        var riskTags: [String]?
    }

    func set(_ signals: ServerSignals?) {
        lock.lock()
        current = signals
        lock.unlock()
        Logger.log("server_aggregate.set: \(signals == nil ? "nil" : "set")")
    }

    func setGraphFeatures(
        communityId: String?,
        communityRiskDensity: Double?,
        hwProfileDegree: Int?,
        devicePageRank: Double?,
        isInDenseSubgraph: Bool?,
        riskTags: [String]?
    ) {
        lock.lock()
        graphFeatures = GraphFeatures(
            communityId: communityId,
            communityRiskDensity: communityRiskDensity,
            hwProfileDegree: hwProfileDegree,
            devicePageRank: devicePageRank,
            isInDenseSubgraph: isInDenseSubgraph,
            riskTags: riskTags
        )
        lock.unlock()
        Logger.log("server_aggregate.setGraphFeatures: community=\(communityId ?? "nil")")
    }

    func serverSignals(snapshot: RiskSnapshot) -> ServerSignals? {
        lock.lock()
        let s = current
        let gf = graphFeatures
        lock.unlock()
        guard s != nil || gf != nil else { return nil }
        var merged = s ?? ServerSignals()
        if let gf {
            merged.communityId = gf.communityId
            merged.communityRiskDensity = gf.communityRiskDensity
            merged.hwProfileDegree = gf.hwProfileDegree
            merged.devicePageRank = gf.devicePageRank
            merged.isInDenseSubgraph = gf.isInDenseSubgraph
            if let tags = gf.riskTags, !tags.isEmpty {
                var existing = merged.riskTags ?? []
                existing.append(contentsOf: tags)
                merged.riskTags = existing
            }
        }
        return merged
    }

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        lock.lock()
        let s = current
        let gf = graphFeatures
        lock.unlock()
        guard s != nil || gf != nil else { return [] }

        var out: [RiskSignal] = []

        if let s {
        if let ip = s.publicIP, !ip.isEmpty {
            out.append(
                RiskSignal(
                    id: "server_public_ip",
                    category: "server",
                    score: 0,
                    evidence: ["public_ip": ip],
                    state: .serverRequired,
                    layer: 4
                )
            )
        }

        if let asn = s.asn, !asn.isEmpty {
            out.append(
                RiskSignal(
                    id: "server_asn",
                    category: "server",
                    score: 0,
                    evidence: ["asn": asn],
                    state: .serverRequired,
                    layer: 4
                )
            )
        }

        if let asOrg = s.asOrg, !asOrg.isEmpty {
            out.append(
                RiskSignal(
                    id: "server_as_org",
                    category: "server",
                    score: 0,
                    evidence: ["as_org": asOrg],
                    state: .serverRequired,
                    layer: 4
                )
            )
        }

        if s.isDatacenter == true {
            out.append(RiskSignal(id: "datacenter_ip", category: "server", score: 20, evidence: ["is_datacenter": "true"]))
        }

        if let n = s.ipDeviceAgg {
            let score: Double
            if n >= 200 { score = 25 }
            else if n >= 50 { score = 15 }
            else if n >= 20 { score = 8 }
            else { score = 0 }
            if score > 0 {
                out.append(RiskSignal(id: "ip_device_agg", category: "server", score: score, evidence: ["ip_device_agg": "\(n)"]))
            }
        }

        if let n = s.ipAccountAgg {
            let score: Double
            if n >= 500 { score = 25 }
            else if n >= 100 { score = 15 }
            else if n >= 30 { score = 8 }
            else { score = 0 }
            if score > 0 {
                out.append(RiskSignal(id: "ip_account_agg", category: "server", score: score, evidence: ["ip_account_agg": "\(n)"]))
            }
        }

        if let tags = s.riskTags, !tags.isEmpty {
            out.append(
                RiskSignal(
                    id: "risk_tags",
                    category: "server",
                    score: 0,
                    evidence: ["tags": tags.joined(separator: ",")],
                    state: .serverRequired,
                    layer: 4
                )
            )
        }
        }

        if let gf {
            if let density = gf.communityRiskDensity, density > 50 {
                let score: Double = density > 80 ? 20 : (density > 65 ? 12 : 5)
                out.append(RiskSignal(
                    id: "graph_community_risk",
                    category: "server",
                    score: score,
                    evidence: [
                        "community_id": gf.communityId ?? "unknown",
                        "risk_density": "\(density)"
                    ],
                    state: .serverRequired,
                    layer: 4
                ))
            }

            if let degree = gf.hwProfileDegree, degree >= 10 {
                let score: Double = degree >= 100 ? 20 : (degree >= 50 ? 15 : 8)
                out.append(RiskSignal(
                    id: "graph_hw_profile_cluster",
                    category: "server",
                    score: score,
                    evidence: ["hw_profile_degree": "\(degree)"],
                    state: .serverRequired,
                    layer: 4
                ))
            }

            if gf.isInDenseSubgraph == true {
                out.append(RiskSignal(
                    id: "graph_dense_subgraph",
                    category: "server",
                    score: 15,
                    evidence: ["in_dense_subgraph": "true"],
                    state: .serverRequired,
                    layer: 4
                ))
            }
        }

        return out
    }
}
