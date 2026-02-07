import Foundation

enum RiskScorer {
    static func score(context: RiskContext, config: RiskConfig, extraSignals: [RiskSignal] = []) -> RiskScoreReport {
        var total: Double = 0
        var signals: [RiskSignal] = []

        // Jailbreak is a strong signal cluster.
        let jbScore = min(context.jailbreak.confidence, 100)
        if jbScore > 0 {
            // Make jailbreak the primary line of defense (highest weight).
            let jbContribution = jbScore * 0.6
            total += jbContribution
            signals.append(
                RiskSignal(
                    id: "jailbreak",
                    category: "jailbreak",
                    score: jbScore,
                    evidence: [
                        "is_jailbroken": "\(context.jailbreak.isJailbroken)",
                        "hits": "\(context.jailbreak.detectedMethods.count)",
                    ]
                )
            )
            Logger.log("score +\(jbContribution) from jailbreak(conf=\(context.jailbreak.confidence))")
        }

        if config.enableNetworkSignals {
            if context.network.isVPNActive {
                total += 10
                signals.append(RiskSignal(id: "vpn_active", category: "network", score: 10, evidence: [:]))
                Logger.log("score +10 from vpn_active")
            }
            if context.network.proxyEnabled {
                total += 8
                signals.append(RiskSignal(id: "proxy_enabled", category: "network", score: 8, evidence: [:]))
                Logger.log("score +8 from proxy_enabled")
            }
        }

        if config.enableBehaviorDetect {
            let b = behaviorScore(behavior: context.behavior)
            total += b.score
            signals.append(contentsOf: b.signals)
            Logger.log("score +\(b.score) from behavior(signals=\(b.signals.count))")
        }

        if !extraSignals.isEmpty {
            // De-dupe by id/category to avoid double counting when multiple providers overlap.
            var seen = Set<String>()
            var unique: [RiskSignal] = []
            for s in extraSignals {
                let key = "\(s.category)::\(s.id)"
                if seen.contains(key) { continue }
                seen.insert(key)
                unique.append(s)
            }
            let pluginScoreRaw = unique.map(\.score).filter { $0 > 0 }.reduce(0, +)
            let pluginScore = min(pluginScoreRaw, 20)
            total += pluginScore
            signals.append(contentsOf: unique)
            Logger.log("score +\(pluginScore) from providers(raw=\(pluginScoreRaw) signals=\(extraSignals.count) unique=\(unique.count))")
        }

        total = min(total, 100)
        let isHighRisk = (total >= config.threshold) || context.jailbreak.isJailbroken
        if context.jailbreak.isJailbroken, total < config.threshold {
            // Hard verdict: jailbreak => at least threshold.
            total = config.threshold
        }
        Logger.log("score total=\(total) threshold=\(config.threshold) isHighRisk=\(isHighRisk)")
        return RiskScoreReport(
            score: total,
            isHighRisk: isHighRisk,
            signals: signals,
            summary: summary(score: total, isHighRisk: isHighRisk, jailbreak: context.jailbreak)
        )
    }

    private static func behaviorScore(behavior: BehaviorSignals) -> (score: Double, signals: [RiskSignal]) {
        var total: Double = 0
        var signals: [RiskSignal] = []

        if let spread = behavior.touch.coordinateSpread, spread < 2.0 {
            total += 12
            signals.append(RiskSignal(id: "touch_spread_low", category: "behavior", score: 12, evidence: ["spread": "\(spread)"]))
        }

        if let spread = behavior.touch.coordinateSpread, spread > 10.0 {
            total += 4
            signals.append(RiskSignal(id: "touch_spread_high", category: "behavior", score: 4, evidence: ["spread": "\(spread)"]))
        }

        if let cv = behavior.touch.intervalCV, cv < 0.2 {
            total += 10
            signals.append(RiskSignal(id: "touch_interval_too_regular", category: "behavior", score: 10, evidence: ["cv": "\(cv)"]))
        }

        if let cv = behavior.touch.intervalCV, cv > 0.6 {
            total += 4
            signals.append(RiskSignal(id: "touch_interval_too_chaotic", category: "behavior", score: 4, evidence: ["cv": "\(cv)"]))
        }

        if let lin = behavior.touch.averageLinearity, lin > 0.98, behavior.touch.swipeCount >= 3 {
            total += 8
            signals.append(RiskSignal(id: "swipe_too_linear", category: "behavior", score: 8, evidence: ["avg_linearity": "\(lin)"]))
        }

        if let lin = behavior.touch.averageLinearity, lin < 0.90, behavior.touch.swipeCount >= 3 {
            total += 4
            signals.append(RiskSignal(id: "swipe_too_curvy", category: "behavior", score: 4, evidence: ["avg_linearity": "\(lin)"]))
        }

        if let still = behavior.motion.stillnessRatio, still > 0.98, (behavior.touch.tapCount + behavior.touch.swipeCount) >= 10 {
            total += 10
            signals.append(RiskSignal(id: "motion_too_still", category: "behavior", score: 10, evidence: ["stillness": "\(still)"]))
        }

        if
            let corr = behavior.touchMotionCorrelation,
            corr < 0.10,
            behavior.actionCount >= 10,
            (behavior.motion.stillnessRatio ?? 0) > 0.95
        {
            total += 8
            signals.append(RiskSignal(id: "touch_motion_weak_coupling", category: "behavior", score: 8, evidence: ["corr": "\(corr)"]))
        }

        return (min(total, 30), signals)
    }

    private static func summary(score: Double, isHighRisk: Bool, jailbreak: DetectionResult) -> String {
        if jailbreak.isJailbroken {
            return "high_risk(jailbreak)"
        }
        return isHighRisk ? "high_risk" : "low_risk"
    }
}
