import Foundation

// MARK: - Risk Scorer
//
// Stateless scoring engine that converts a RiskContext into a RiskScoreReport.
//
// Scoring Pipeline:
//   1. Jailbreak confidence → ×jailbreakWeight (capped at scoreCap)
//   2. Network signals      → VPN +vpnScore, Proxy +proxyScore (if enabled)
//   3. Behavior analysis    → up to +maxBehaviorScore from 8 heuristics (capped)
//   4. Extra signals        → up to +maxExtraSignalsScore from providers (de-duped)
//   5. Total capped at scoreCap
//
// Hard Verdict: if isJailbroken && score < threshold → bumps score to threshold
// isHighRisk  = score >= threshold || isJailbroken

enum RiskScorer {
    // MARK: - Scoring Constants

    /// 总分和越狱置信度的上限
    private static let scoreCap: Double = 100
    /// 越狱信号权重
    private static let jailbreakWeight: Double = 0.6
    /// VPN 信号分值
    private static let vpnScore: Double = 10
    /// 代理信号分值
    private static let proxyScore: Double = 8
    /// 扩展信号（provider）最大分值
    private static let maxExtraSignalsScore: Double = 20

    // MARK: - Behavior Thresholds

    private static let touchSpreadLowThreshold: Double = 2.0
    private static let touchSpreadLowScore: Double = 12
    private static let touchSpreadHighThreshold: Double = 10.0
    private static let touchSpreadHighScore: Double = 4
    private static let touchIntervalCVLowThreshold: Double = 0.2
    private static let touchIntervalRegularScore: Double = 10
    private static let touchIntervalCVHighThreshold: Double = 0.6
    private static let touchIntervalChaoticScore: Double = 4
    private static let swipeLinearityHighThreshold: Double = 0.98
    private static let swipeLinearityLowThreshold: Double = 0.90
    private static let minSwipesForLinearity = 3
    private static let swipeTooLinearScore: Double = 8
    private static let swipeTooCurvyScore: Double = 4
    private static let motionStillnessThreshold: Double = 0.98
    private static let minActionsForStillness = 10
    private static let motionTooStillScore: Double = 10
    private static let touchMotionCorrelationThreshold: Double = 0.10
    private static let minActionsForCorrelation = 10
    private static let minStillnessForCorrelation: Double = 0.95
    private static let touchMotionWeakCouplingScore: Double = 8
    private static let minTotalActions = 3
    private static let minSampleCount = 5
    private static let insufficientDataScore: Double = 5
    private static let maxBehaviorScore: Double = 30

    static func score(context: RiskContext, config: RiskConfig, extraSignals: [RiskSignal] = []) -> RiskScoreReport {
        var total: Double = 0
        var signals: [RiskSignal] = []

        // Jailbreak is a strong signal cluster.
        let jbScore = min(context.jailbreak.confidence, scoreCap)
        if jbScore > 0 {
            // Make jailbreak the primary line of defense (highest weight).
            let jbContribution = jbScore * jailbreakWeight
            total += jbContribution
            signals.append(
                RiskSignal(
                    id: SignalID.jailbreak,
                    category: SignalCategory.jailbreak,
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
                total += vpnScore
                signals.append(RiskSignal(id: SignalID.vpnActive, category: SignalCategory.network, score: vpnScore, evidence: [:]))
                Logger.log("score +\(vpnScore) from vpn_active")
            }
            if context.network.proxyEnabled {
                total += proxyScore
                signals.append(RiskSignal(id: SignalID.proxyEnabled, category: SignalCategory.network, score: proxyScore, evidence: [:]))
                Logger.log("score +\(proxyScore) from proxy_enabled")
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
            let pluginScore = min(pluginScoreRaw, maxExtraSignalsScore)
            total += pluginScore
            signals.append(contentsOf: unique)
            Logger.log("score +\(pluginScore) from providers(raw=\(pluginScoreRaw) signals=\(extraSignals.count) unique=\(unique.count))")
        }

        total = min(total, scoreCap)
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

        if let spread = behavior.touch.coordinateSpread, spread < touchSpreadLowThreshold {
            total += touchSpreadLowScore
            signals.append(RiskSignal(id: SignalID.touchSpreadLow, category: SignalCategory.behavior, score: touchSpreadLowScore, evidence: ["spread": "\(spread)"]))
        }

        if let spread = behavior.touch.coordinateSpread, spread > touchSpreadHighThreshold {
            total += touchSpreadHighScore
            signals.append(RiskSignal(id: SignalID.touchSpreadHigh, category: SignalCategory.behavior, score: touchSpreadHighScore, evidence: ["spread": "\(spread)"]))
        }

        if let cv = behavior.touch.intervalCV, cv < touchIntervalCVLowThreshold {
            total += touchIntervalRegularScore
            signals.append(RiskSignal(id: SignalID.touchIntervalTooRegular, category: SignalCategory.behavior, score: touchIntervalRegularScore, evidence: ["cv": "\(cv)"]))
        }

        if let cv = behavior.touch.intervalCV, cv > touchIntervalCVHighThreshold {
            total += touchIntervalChaoticScore
            signals.append(RiskSignal(id: SignalID.touchIntervalTooChaotic, category: SignalCategory.behavior, score: touchIntervalChaoticScore, evidence: ["cv": "\(cv)"]))
        }

        if let lin = behavior.touch.averageLinearity, lin > swipeLinearityHighThreshold, behavior.touch.swipeCount >= minSwipesForLinearity {
            total += swipeTooLinearScore
            signals.append(RiskSignal(id: SignalID.swipeTooLinear, category: SignalCategory.behavior, score: swipeTooLinearScore, evidence: ["avg_linearity": "\(lin)"]))
        }

        if let lin = behavior.touch.averageLinearity, lin < swipeLinearityLowThreshold, behavior.touch.swipeCount >= minSwipesForLinearity {
            total += swipeTooCurvyScore
            signals.append(RiskSignal(id: SignalID.swipeTooCurvy, category: SignalCategory.behavior, score: swipeTooCurvyScore, evidence: ["avg_linearity": "\(lin)"]))
        }

        if let still = behavior.motion.stillnessRatio, still > motionStillnessThreshold, (behavior.touch.tapCount + behavior.touch.swipeCount) >= minActionsForStillness {
            total += motionTooStillScore
            signals.append(RiskSignal(id: SignalID.motionTooStill, category: SignalCategory.behavior, score: motionTooStillScore, evidence: ["stillness": "\(still)"]))
        }

        if
            let corr = behavior.touchMotionCorrelation,
            corr < touchMotionCorrelationThreshold,
            behavior.actionCount >= minActionsForCorrelation,
            (behavior.motion.stillnessRatio ?? 0) > minStillnessForCorrelation
        {
            total += touchMotionWeakCouplingScore
            signals.append(RiskSignal(id: SignalID.touchMotionWeakCoupling, category: SignalCategory.behavior, score: touchMotionWeakCouplingScore, evidence: ["corr": "\(corr)"]))
        }

        let totalActions = behavior.touch.tapCount + behavior.touch.swipeCount
        if totalActions < minTotalActions, behavior.touch.sampleCount < minSampleCount {
            total += insufficientDataScore
            signals.append(RiskSignal(
                id: SignalID.insufficientBehaviorData,
                category: SignalCategory.behavior,
                score: insufficientDataScore,
                evidence: [
                    "tapCount": "\(behavior.touch.tapCount)",
                    "swipeCount": "\(behavior.touch.swipeCount)",
                    "sampleCount": "\(behavior.touch.sampleCount)"
                ]
            ))
        }

        return (min(total, maxBehaviorScore), signals)
    }

    private static func summary(score: Double, isHighRisk: Bool, jailbreak: DetectionResult) -> String {
        if jailbreak.isJailbroken {
            return "high_risk(jailbreak)"
        }
        return isHighRisk ? "high_risk" : "low_risk"
    }
}
