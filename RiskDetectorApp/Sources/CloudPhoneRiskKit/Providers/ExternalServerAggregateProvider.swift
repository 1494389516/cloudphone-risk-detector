import CryptoKit
import Foundation

/// Local injection point for future "server aggregation" signals (IP/ASN/datacenter/IP聚合度...).
/// You can set these fields locally (even without a backend) and they'll be:
/// - embedded into the JSON payload under `server`
/// - optionally contribute to score via generated `RiskSignal`s
final class ExternalServerAggregateProvider: RiskSignalProvider {
    static let shared = ExternalServerAggregateProvider()
    private init() {}

    /// 图风控反馈应用后发送，业务侧可观察此通知并调用 evaluate() 重新评估风险。
    public static let graphRiskFeedbackDidApplyNotification = Notification.Name("CloudPhoneRiskKit.graphRiskFeedbackDidApply")

    let id = "server_aggregate"

    private let lock = UnfairLock()
    private var current: ServerSignals?
    private var graphFeatures: GraphFeatures?
    private var serverSignalKey: SymmetricKey?
    private var realtimeTelemetryFeedback: RealtimeTelemetryFeedback?

    struct GraphFeatures {
        var communityId: String?
        var communityRiskDensity: Double?
        var hwProfileDegree: Int?
        var devicePageRank: Double?
        var isInDenseSubgraph: Bool?
        var riskTags: [String]?
    }

    struct RealtimeTelemetryFeedback: Sendable {
        var riskPressure: Double?
        var minEvaluationIntervalMillis: Int?
        var defaultWeightScaleBps: Int?
        var categoryWeightScaleBps: [String: Int]
        var expiresAtEpochSeconds: TimeInterval?

        init(
            riskPressure: Double? = nil,
            minEvaluationIntervalMillis: Int? = nil,
            defaultWeightScaleBps: Int? = nil,
            categoryWeightScaleBps: [String: Int] = [:],
            expiresAtEpochSeconds: TimeInterval? = nil
        ) {
            self.riskPressure = riskPressure
            self.minEvaluationIntervalMillis = minEvaluationIntervalMillis
            self.defaultWeightScaleBps = defaultWeightScaleBps
            self.categoryWeightScaleBps = categoryWeightScaleBps
            self.expiresAtEpochSeconds = expiresAtEpochSeconds
        }
    }

    struct RealtimeAdaptiveFeedbackSnapshot: Sendable {
        let riskPressure: Double?
        let minEvaluationIntervalMillis: Int?
        let defaultWeightScaleBps: Int?
        let categoryWeightScaleBps: [String: Int]
        let source: String
    }

    private struct AdaptiveTagHints {
        var riskPressure: Double?
        var minEvaluationIntervalMillis: Int?
        var defaultWeightScaleBps: Int?
        var categoryWeightScaleBps: [String: Int] = [:]

        var hasAny: Bool {
            riskPressure != nil
                || minEvaluationIntervalMillis != nil
                || defaultWeightScaleBps != nil
                || !categoryWeightScaleBps.isEmpty
        }
    }

    /// 清空图特征，避免跨账号/跨会话残留。
    func clearGraphFeatures() {
        lock.withLock { graphFeatures = nil }
    }

    /// 注入实时遥测反馈（本地联调或服务端回注）。
    /// 该反馈用于动态调整评估频率与权重倍率。
    func setRealtimeTelemetryFeedback(_ feedback: RealtimeTelemetryFeedback?) {
        lock.withLock {
            realtimeTelemetryFeedback = sanitizedRealtimeTelemetryFeedback(feedback)
        }
    }

    func clearRealtimeTelemetryFeedback() {
        lock.withLock { realtimeTelemetryFeedback = nil }
    }

    /// Configure the HMAC key used by `setVerified(_:signature:)`.
    func configureServerSignalKey(_ key: Data) {
        lock.withLock { serverSignalKey = SymmetricKey(data: key) }
    }

    /// 清空服务端信号和图特征，Release 下始终可用（用于 clearExternalServerSignals）。
    func clear() {
        lock.withLock {
            current = nil
            graphFeatures = nil
            realtimeTelemetryFeedback = nil
        }
        Logger.log("server_aggregate.clear")
    }

    @available(*, deprecated, message: "Use setVerified(_:signature:) instead")
    func set(_ signals: ServerSignals?) {
        setDebugBypassingVerification(signals)
    }

    func setDebugBypassingVerification(_ signals: ServerSignals?) {
        if signals == nil {
            clear()
            return
        }
        #if DEBUG
        lock.withLock { current = signals }
        Logger.log("server_aggregate.set (deprecated): set")
        #else
        Logger.log("server_aggregate.set rejected: use setVerified in Release builds")
        #endif
    }

    /// Accept server signals only after custom SHA-256 MAC verification.
    /// `signature` = MAC(serverSignalKey, canonicalJSON(signals)).
    func setVerified(_ signals: ServerSignals, signature: Data) {
        guard let capturedKey = lock.withLock({ serverSignalKey }) else {
            Logger.log("server_aggregate.setVerified rejected: no key configured")
            return
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let payload = try? encoder.encode(signals) else {
            Logger.log("server_aggregate.setVerified rejected: encode failed")
            return
        }

        guard CPRiskMessageAuth.isValidAuthenticationCode(signature, authenticating: payload, using: capturedKey) else {
            Logger.log("server_aggregate.setVerified rejected: MAC mismatch")
            return
        }

        let accepted = lock.withLock { () -> Bool in
            // Re-check key hasn't been cleared between verification and store
            guard serverSignalKey != nil else { return false }
            current = signals
            return true
        }
        if !accepted {
            Logger.log("server_aggregate.setVerified rejected: key cleared during verification")
            return
        }
        Logger.log("server_aggregate.setVerified: accepted")
    }

    func setGraphFeatures(
        communityId: String?,
        communityRiskDensity: Double?,
        hwProfileDegree: Int?,
        devicePageRank: Double?,
        isInDenseSubgraph: Bool?,
        riskTags: [String]?
    ) {
        lock.withLock {
            graphFeatures = GraphFeatures(
                communityId: communityId,
                communityRiskDensity: communityRiskDensity,
                hwProfileDegree: hwProfileDegree,
                devicePageRank: devicePageRank,
                isInDenseSubgraph: isInDenseSubgraph,
                riskTags: riskTags
            )
        }
        #if DEBUG
        Logger.log("server_aggregate.setGraphFeatures: community=\(communityId ?? "nil")")
        #endif
    }

    /// 应用图风控反馈：服务端返回图计算结果后注入，用于增强本地评分。
    /// 注入后更新 graphFeatures，并发送 `graphRiskFeedbackDidApply` 通知，供业务侧触发 re-evaluate。
    /// 业务侧可观察该通知，在收到后调用 `CPRiskKit.shared.evaluate(...)` 重新评估风险。
    /// - Parameter feedback: 图风控反馈（communityId、communityRiskDensity 等）
    func applyGraphRiskFeedback(_ feedback: GraphRiskFeedback) {
        setGraphFeatures(
            communityId: feedback.communityId,
            communityRiskDensity: feedback.communityRiskDensity,
            hwProfileDegree: feedback.hwProfileDegree,
            devicePageRank: feedback.devicePageRank,
            isInDenseSubgraph: feedback.isInDenseSubgraph,
            riskTags: feedback.riskTags
        )
        NotificationCenter.default.post(
            name: Self.graphRiskFeedbackDidApplyNotification,
            object: self
        )
    }

    /// 生成“实时遥测自适应”快照：显式反馈优先，riskTags 可覆盖。
    /// 若无可用反馈，返回 nil（调用方应回退到静态配置）。
    func realtimeAdaptiveFeedbackSnapshot(nowEpochSeconds: TimeInterval = Date().timeIntervalSince1970) -> RealtimeAdaptiveFeedbackSnapshot? {
        let (s, gf, explicitFeedback) = lock.withLock { (current, graphFeatures, realtimeTelemetryFeedback) }
        var sourceTags: [String] = []

        var riskPressure: Double?
        var minEvaluationIntervalMillis: Int?
        var defaultWeightScaleBps: Int?
        var categoryWeightScaleBps: [String: Int] = [:]

        if let explicitFeedback, !isExpired(explicitFeedback, nowEpochSeconds: nowEpochSeconds) {
            riskPressure = explicitFeedback.riskPressure
            minEvaluationIntervalMillis = explicitFeedback.minEvaluationIntervalMillis
            defaultWeightScaleBps = explicitFeedback.defaultWeightScaleBps
            categoryWeightScaleBps = explicitFeedback.categoryWeightScaleBps
            sourceTags.append("explicit")
        }

        let mergedTags = (s?.riskTags ?? []) + (gf?.riskTags ?? [])
        let tagHints = parseAdaptiveTagHints(from: mergedTags)
        if tagHints.hasAny {
            if let pressure = tagHints.riskPressure {
                riskPressure = pressure
            }
            if let interval = tagHints.minEvaluationIntervalMillis {
                minEvaluationIntervalMillis = interval
            }
            if let bps = tagHints.defaultWeightScaleBps {
                defaultWeightScaleBps = bps
            }
            if !tagHints.categoryWeightScaleBps.isEmpty {
                categoryWeightScaleBps.merge(tagHints.categoryWeightScaleBps) { _, rhs in rhs }
            }
            sourceTags.append("risk_tags")
        }

        guard riskPressure != nil
            || minEvaluationIntervalMillis != nil
            || defaultWeightScaleBps != nil
            || !categoryWeightScaleBps.isEmpty else {
            return nil
        }

        return RealtimeAdaptiveFeedbackSnapshot(
            riskPressure: riskPressure,
            minEvaluationIntervalMillis: minEvaluationIntervalMillis,
            defaultWeightScaleBps: defaultWeightScaleBps,
            categoryWeightScaleBps: categoryWeightScaleBps,
            source: sourceTags.isEmpty ? "unknown" : sourceTags.joined(separator: "+")
        )
    }

    func serverSignals(snapshot: RiskSnapshot) -> ServerSignals? {
        let (s, gf) = lock.withLock { (current, graphFeatures) }
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
        let (s, gf) = lock.withLock { (current, graphFeatures) }
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
            out.append(RiskSignal(id: SignalID.datacenterIP, category: SignalCategory.server, score: 20, evidence: ["is_datacenter": "true"]))
        }

        if let n = s.ipDeviceAgg {
            let score: Double
            if n >= 200 { score = 25 }
            else if n >= 50 { score = 15 }
            else if n >= 20 { score = 8 }
            else { score = 0 }
            if score > 0 {
                out.append(RiskSignal(id: SignalID.ipDeviceAgg, category: SignalCategory.server, score: score, evidence: ["ip_device_agg": "\(n)"]))
            }
        }

        if let n = s.ipAccountAgg {
            let score: Double
            if n >= 500 { score = 25 }
            else if n >= 100 { score = 15 }
            else if n >= 30 { score = 8 }
            else { score = 0 }
            if score > 0 {
                out.append(RiskSignal(id: SignalID.ipAccountAgg, category: SignalCategory.server, score: score, evidence: ["ip_account_agg": "\(n)"]))
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

    private func sanitizedRealtimeTelemetryFeedback(_ feedback: RealtimeTelemetryFeedback?) -> RealtimeTelemetryFeedback? {
        guard var feedback else { return nil }

        feedback.riskPressure = sanitizedPressure(feedback.riskPressure)
        feedback.minEvaluationIntervalMillis = sanitizedInterval(feedback.minEvaluationIntervalMillis)
        feedback.defaultWeightScaleBps = sanitizedWeightBps(feedback.defaultWeightScaleBps)

        if !feedback.categoryWeightScaleBps.isEmpty {
            var sanitized: [String: Int] = [:]
            for (rawKey, rawValue) in feedback.categoryWeightScaleBps {
                guard let key = Self.normalizedWeightKey(rawKey),
                      let value = sanitizedWeightBps(rawValue) else {
                    continue
                }
                sanitized[key] = value
            }
            feedback.categoryWeightScaleBps = sanitized
        }

        return feedback
    }

    private func isExpired(_ feedback: RealtimeTelemetryFeedback, nowEpochSeconds: TimeInterval) -> Bool {
        guard let expiresAt = feedback.expiresAtEpochSeconds else {
            return false
        }
        return expiresAt < nowEpochSeconds
    }

    private func parseAdaptiveTagHints(from tags: [String]) -> AdaptiveTagHints {
        guard !tags.isEmpty else { return AdaptiveTagHints() }

        var hints = AdaptiveTagHints()
        for rawTag in tags {
            let tag = rawTag.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if tag.isEmpty { continue }

            if let value = parseDoubleTag(tag, prefix: "rt_pressure:") {
                let normalized = value > 1.0 ? value / 100.0 : value
                hints.riskPressure = sanitizedPressure(normalized)
                continue
            }
            if let value = parseIntTag(tag, prefix: "rt_eval_ms:") {
                hints.minEvaluationIntervalMillis = sanitizedInterval(value)
                continue
            }
            if let value = parseIntTag(tag, prefix: "rt_weight_bps:") {
                hints.defaultWeightScaleBps = sanitizedWeightBps(value)
                continue
            }

            for key in Self.supportedWeightKeys {
                let prefix = "rt_weight_\(key)_bps:"
                if let value = parseIntTag(tag, prefix: prefix),
                   let safeValue = sanitizedWeightBps(value) {
                    hints.categoryWeightScaleBps[key] = safeValue
                    break
                }
            }
        }

        return hints
    }

    private func parseDoubleTag(_ tag: String, prefix: String) -> Double? {
        guard tag.hasPrefix(prefix) else { return nil }
        let raw = String(tag.dropFirst(prefix.count))
        return Double(raw)
    }

    private func parseIntTag(_ tag: String, prefix: String) -> Int? {
        guard tag.hasPrefix(prefix) else { return nil }
        let raw = String(tag.dropFirst(prefix.count))
        return Int(raw)
    }

    private func sanitizedPressure(_ value: Double?) -> Double? {
        guard let value, value.isFinite else { return nil }
        return min(max(value, 0), 1)
    }

    private func sanitizedInterval(_ value: Int?) -> Int? {
        guard let value else { return nil }
        return min(max(value, 0), 60_000)
    }

    private func sanitizedWeightBps(_ value: Int?) -> Int? {
        guard let value else { return nil }
        return min(max(value, 1_000), 20_000)
    }

    private static let supportedWeightKeys: Set<String> = [
        "jailbreak",
        "network",
        "behavior",
        "device",
        "time",
    ]

    private static func normalizedWeightKey(_ raw: String) -> String? {
        let normalized = raw
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        return supportedWeightKeys.contains(normalized) ? normalized : nil
    }
}
