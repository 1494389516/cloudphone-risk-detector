import Foundation

// MARK: - Risk Scorer
//
// Stateless scoring engine that converts a RiskContext into a RiskScoreReport.
//
// Scoring Pipeline:
//   1. Jailbreak confidence → ×jailbreakWeight (capped at scoreCap)
//   2. Network signals      → VPN +vpnScore, Proxy +proxyScore (if enabled)
//   3. Behavior analysis    → up to +maxBehaviorScore from 11 heuristics (capped)
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

    // MARK: - Behavior Scores (fixed point values, not remotely configurable)

    private static let touchSpreadLowScore: Double = 12
    private static let touchSpreadHighScore: Double = 4
    private static let touchIntervalRegularScore: Double = 10
    private static let touchIntervalChaoticScore: Double = 4
    private static let swipeTooLinearScore: Double = 8
    private static let swipeTooCurvyScore: Double = 4
    private static let motionTooStillScore: Double = 10
    private static let touchMotionWeakCouplingScore: Double = 8
    private static let forceTooUniformScore: Double = 10
    private static let radiusTooUniformScore: Double = 8
    private static let swipeSpeedTooRegularScore: Double = 6
    private static let insufficientDataScore: Double = 5

    // MARK: - Behavior Sample Counts (fixed)

    private static let minSwipesForLinearity = 3
    private static let minActionsForStillness = 10
    private static let minActionsForCorrelation = 10
    private static let minForceSamples = 6
    private static let minRadiusSamples = 6

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
            #if DEBUG
            Logger.log("score +\(jbContribution) from jailbreak(conf=\(context.jailbreak.confidence))")
            #endif
        }

        if config.enableNetworkSignals {
            if context.network.isVPNActive {
                total += vpnScore
                signals.append(RiskSignal(id: SignalID.vpnActive, category: SignalCategory.network, score: vpnScore, evidence: [:]))
                #if DEBUG
                Logger.log("score +\(vpnScore) from vpn_active")
                #endif
            }
            if context.network.proxyEnabled {
                total += proxyScore
                signals.append(RiskSignal(id: SignalID.proxyEnabled, category: SignalCategory.network, score: proxyScore, evidence: [:]))
                #if DEBUG
                Logger.log("score +\(proxyScore) from proxy_enabled")
                #endif
            }
        }

        if config.enableBehaviorDetect {
            let thresholds = config.behaviorThresholds ?? .default
            let b = behaviorScore(behavior: context.behavior, thresholds: thresholds)
            total += b.score
            signals.append(contentsOf: b.signals)
            #if DEBUG
            Logger.log("score +\(b.score) from behavior(signals=\(b.signals.count))")
            #endif
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
            #if DEBUG
            Logger.log("score +\(pluginScore) from providers(raw=\(pluginScoreRaw) signals=\(extraSignals.count) unique=\(unique.count))")
            #endif
        }

        total = min(total, scoreCap)
        let isHighRisk = (total >= config.threshold) || context.jailbreak.isJailbroken
        if context.jailbreak.isJailbroken, total < config.threshold {
            // Hard verdict: jailbreak => at least threshold.
            total = min(config.threshold, scoreCap)
        }
        #if DEBUG
        Logger.log("score total=\(total) threshold=\(config.threshold) isHighRisk=\(isHighRisk)")
        #endif
        return RiskScoreReport(
            score: total,
            isHighRisk: isHighRisk,
            signals: signals,
            summary: summary(score: total, isHighRisk: isHighRisk, jailbreak: context.jailbreak),
            compressedDigest: nil,
            mappingVersion: nil
        )
    }

    private static func behaviorScore(behavior: BehaviorSignals, thresholds: BehaviorThresholds) -> (score: Double, signals: [RiskSignal]) {
        var total: Double = 0
        var signals: [RiskSignal] = []

        // 样本不足时跳过高置信度启发式，仅产出 insufficient_data 软信号
        // 防止低样本量下 Pearson 相关等统计量产生不稳定的误判
        switch behavior.sampleSufficiency {
        case .none:
            return (insufficientDataScore, [RiskSignal(
                id: SignalID.insufficientBehaviorData,
                category: SignalCategory.behavior,
                score: insufficientDataScore,
                evidence: [
                    "tapCount": "\(behavior.touch.tapCount)",
                    "sampleCount": "\(behavior.touch.sampleCount)",
                    "motionSampleCount": "\(behavior.motion.sampleCount)",
                    "reason": "no_samples",
                ]
            )])
        case .insufficient:
            // 样本不足：仅产出 insufficient_data 信号，跳过所有启发式
            return (insufficientDataScore, [RiskSignal(
                id: SignalID.insufficientBehaviorData,
                category: SignalCategory.behavior,
                score: insufficientDataScore,
                evidence: [
                    "tapCount": "\(behavior.touch.tapCount)",
                    "sampleCount": "\(behavior.touch.sampleCount)",
                    "motionSampleCount": "\(behavior.motion.sampleCount)",
                    "reason": "below_minimum_threshold",
                    "minimumRequired": "\(BehaviorSignals.minimumTouchSamples)",
                ]
            )])
        case .sufficient:
            break // 样本充足，继续执行启发式分析
        }

        if let spread = behavior.touch.coordinateSpread, spread < thresholds.touchSpreadLow {
            total += touchSpreadLowScore
            signals.append(RiskSignal(id: SignalID.touchSpreadLow, category: SignalCategory.behavior, score: touchSpreadLowScore, evidence: ["spread": "\(spread)"]))
        }

        if let spread = behavior.touch.coordinateSpread, spread > thresholds.touchSpreadHigh {
            total += touchSpreadHighScore
            signals.append(RiskSignal(id: SignalID.touchSpreadHigh, category: SignalCategory.behavior, score: touchSpreadHighScore, evidence: ["spread": "\(spread)"]))
        }

        if let cv = behavior.touch.intervalCV, cv < thresholds.touchIntervalCVLow {
            total += touchIntervalRegularScore
            signals.append(RiskSignal(id: SignalID.touchIntervalTooRegular, category: SignalCategory.behavior, score: touchIntervalRegularScore, evidence: ["cv": "\(cv)"]))
        }

        if let cv = behavior.touch.intervalCV, cv > thresholds.touchIntervalCVHigh {
            total += touchIntervalChaoticScore
            signals.append(RiskSignal(id: SignalID.touchIntervalTooChaotic, category: SignalCategory.behavior, score: touchIntervalChaoticScore, evidence: ["cv": "\(cv)"]))
        }

        if let lin = behavior.touch.averageLinearity, lin > thresholds.swipeLinearityHigh, behavior.touch.swipeCount >= minSwipesForLinearity {
            total += swipeTooLinearScore
            signals.append(RiskSignal(id: SignalID.swipeTooLinear, category: SignalCategory.behavior, score: swipeTooLinearScore, evidence: ["avg_linearity": "\(lin)"]))
        }

        if let lin = behavior.touch.averageLinearity, lin < thresholds.swipeLinearityLow, behavior.touch.swipeCount >= minSwipesForLinearity {
            total += swipeTooCurvyScore
            signals.append(RiskSignal(id: SignalID.swipeTooCurvy, category: SignalCategory.behavior, score: swipeTooCurvyScore, evidence: ["avg_linearity": "\(lin)"]))
        }

        if let still = behavior.motion.stillnessRatio, still > thresholds.motionStillness, (behavior.touch.tapCount + behavior.touch.swipeCount) >= minActionsForStillness {
            total += motionTooStillScore
            signals.append(RiskSignal(id: SignalID.motionTooStill, category: SignalCategory.behavior, score: motionTooStillScore, evidence: ["stillness": "\(still)"]))
        }

        if
            let corr = behavior.touchMotionCorrelation,
            corr < thresholds.touchMotionCorrelation,
            behavior.actionCount >= minActionsForCorrelation,
            (behavior.motion.stillnessRatio ?? 0) > thresholds.minStillnessForCorrelation
        {
            total += touchMotionWeakCouplingScore
            signals.append(RiskSignal(id: SignalID.touchMotionWeakCoupling, category: SignalCategory.behavior, score: touchMotionWeakCouplingScore, evidence: ["corr": "\(corr)"]))
        }

        if let forceVar = behavior.touch.forceVariance,
           behavior.touch.tapCount + behavior.touch.swipeCount >= minForceSamples,
           forceVar < thresholds.forceVariance {
            total += forceTooUniformScore
            signals.append(RiskSignal(id: SignalID.forceTooUniform, category: SignalCategory.behavior, score: forceTooUniformScore, evidence: ["force_variance": "\(forceVar)"]))
        }

        if let radiusVar = behavior.touch.majorRadiusVariance,
           behavior.touch.tapCount + behavior.touch.swipeCount >= minRadiusSamples,
           radiusVar < thresholds.radiusVariance {
            total += radiusTooUniformScore
            signals.append(RiskSignal(id: SignalID.radiusTooUniform, category: SignalCategory.behavior, score: radiusTooUniformScore, evidence: ["radius_variance": "\(radiusVar)"]))
        }

        if let speedCV = behavior.touch.swipeSpeedCV,
           behavior.touch.swipeCount >= minSwipesForLinearity,
           speedCV < thresholds.swipeSpeedCV {
            total += swipeSpeedTooRegularScore
            signals.append(RiskSignal(id: SignalID.swipeSpeedTooRegular, category: SignalCategory.behavior, score: swipeSpeedTooRegularScore, evidence: ["speed_cv": "\(speedCV)"]))
        }

        // Note: insufficient data is already handled by the sampleSufficiency switch
        // at the top of this function (.none / .insufficient both early-return).
        // No redundant check needed here.

        return (min(total, thresholds.maxBehaviorScore), signals)
    }

    private static func summary(score: Double, isHighRisk: Bool, jailbreak: DetectionResult) -> String {
        if jailbreak.isJailbroken {
            return "high_risk(jailbreak)"
        }
        return isHighRisk ? "high_risk" : "low_risk"
    }
}
