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

    func set(_ signals: ServerSignals?) {
        lock.lock()
        current = signals
        lock.unlock()
        Logger.log("server_aggregate.set: \(signals == nil ? "nil" : "set")")
    }

    func serverSignals(snapshot: RiskSnapshot) -> ServerSignals? {
        lock.lock()
        let s = current
        lock.unlock()
        return s
    }

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        lock.lock()
        let s = current
        lock.unlock()
        guard let s else { return [] }

        var out: [RiskSignal] = []

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

        return out
    }
}
