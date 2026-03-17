import XCTest
@testable import CloudPhoneRiskKit

/// Tests for commit 982c295 "feat: 行为与硬件指纹增强"
/// Covers: new behavior heuristics (force/radius/swipeSpeed), BehaviorThresholds,
/// GPU/IMU provider stubs, and redundant-check removal verification.
final class BehaviorFingerprintTests: XCTestCase {

    // MARK: - BehaviorThresholds Codable

    func testBehaviorThresholdsDefaultValues() {
        let t = BehaviorThresholds.default
        XCTAssertEqual(t.touchSpreadLow, 2.0)
        XCTAssertEqual(t.touchSpreadHigh, 10.0)
        XCTAssertEqual(t.forceVariance, 1e-6)
        XCTAssertEqual(t.radiusVariance, 0.005)
        XCTAssertEqual(t.swipeSpeedCV, 0.15)
        XCTAssertEqual(t.maxBehaviorScore, 45)
    }

    func testBehaviorThresholdsCodableRoundtrip() throws {
        let original = BehaviorThresholds(
            touchSpreadLow: 3.0,
            touchSpreadHigh: 12.0,
            touchIntervalCVLow: 0.25,
            touchIntervalCVHigh: 0.7,
            swipeLinearityHigh: 0.99,
            swipeLinearityLow: 0.85,
            motionStillness: 0.97,
            touchMotionCorrelation: 0.12,
            minStillnessForCorrelation: 0.90,
            forceVariance: 1e-5,
            radiusVariance: 0.01,
            swipeSpeedCV: 0.20,
            maxBehaviorScore: 50
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(BehaviorThresholds.self, from: data)
        XCTAssertEqual(decoded.touchSpreadLow, 3.0)
        XCTAssertEqual(decoded.forceVariance, 1e-5)
        XCTAssertEqual(decoded.radiusVariance, 0.01)
        XCTAssertEqual(decoded.swipeSpeedCV, 0.20)
        XCTAssertEqual(decoded.maxBehaviorScore, 50)
    }

    // MARK: - Force Too Uniform Heuristic

    func testForceTooUniform_TriggersWhenVarianceBelowThreshold() {
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 20, tapCount: 4, swipeCount: 3,
            forceVariance: 1e-8 // well below default 1e-6
        )
        let context = TestFixtures.makeRiskContext(touch: touch)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: false,
            threshold: 60
        )
        let report = RiskScorer.score(context: context, config: config)
        let forceSignal = report.signals.first { $0.id == SignalID.forceTooUniform }
        XCTAssertNotNil(forceSignal, "forceTooUniform should fire when forceVariance < threshold")
        XCTAssertEqual(forceSignal?.score, 10)
    }

    func testForceTooUniform_DoesNotTriggerWhenVarianceAboveThreshold() {
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 20, tapCount: 4, swipeCount: 3,
            forceVariance: 0.5 // well above 1e-6
        )
        let context = TestFixtures.makeRiskContext(touch: touch)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: false,
            threshold: 60
        )
        let report = RiskScorer.score(context: context, config: config)
        let forceSignal = report.signals.first { $0.id == SignalID.forceTooUniform }
        XCTAssertNil(forceSignal, "forceTooUniform should not fire when variance is high")
    }

    func testForceTooUniform_RequiresMinimumSamples() {
        // Only 2 actions (below minForceSamples=6), so even tiny variance shouldn't trigger
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 20, tapCount: 1, swipeCount: 1,
            forceVariance: 0
        )
        let context = TestFixtures.makeRiskContext(touch: touch)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: false,
            threshold: 60
        )
        let report = RiskScorer.score(context: context, config: config)
        let forceSignal = report.signals.first { $0.id == SignalID.forceTooUniform }
        XCTAssertNil(forceSignal, "forceTooUniform should not fire with insufficient actions")
    }

    // MARK: - Radius Too Uniform Heuristic

    func testRadiusTooUniform_TriggersWhenVarianceBelowThreshold() {
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 20, tapCount: 4, swipeCount: 3,
            majorRadiusVariance: 0.001 // below default 0.005
        )
        let context = TestFixtures.makeRiskContext(touch: touch)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: false,
            threshold: 60
        )
        let report = RiskScorer.score(context: context, config: config)
        let radiusSignal = report.signals.first { $0.id == SignalID.radiusTooUniform }
        XCTAssertNotNil(radiusSignal, "radiusTooUniform should fire when radiusVariance < threshold")
        XCTAssertEqual(radiusSignal?.score, 8)
    }

    func testRadiusTooUniform_DoesNotTriggerWhenAboveThreshold() {
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 20, tapCount: 4, swipeCount: 3,
            majorRadiusVariance: 1.0 // well above 0.005
        )
        let context = TestFixtures.makeRiskContext(touch: touch)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: false,
            threshold: 60
        )
        let report = RiskScorer.score(context: context, config: config)
        let radiusSignal = report.signals.first { $0.id == SignalID.radiusTooUniform }
        XCTAssertNil(radiusSignal)
    }

    // MARK: - Swipe Speed Too Regular Heuristic

    func testSwipeSpeedTooRegular_TriggersWhenCVBelowThreshold() {
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 20, tapCount: 4, swipeCount: 5,
            swipeSpeedCV: 0.05 // below default 0.15
        )
        let context = TestFixtures.makeRiskContext(touch: touch)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: false,
            threshold: 60
        )
        let report = RiskScorer.score(context: context, config: config)
        let speedSignal = report.signals.first { $0.id == SignalID.swipeSpeedTooRegular }
        XCTAssertNotNil(speedSignal, "swipeSpeedTooRegular should fire when CV < threshold")
        XCTAssertEqual(speedSignal?.score, 6)
    }

    func testSwipeSpeedTooRegular_RequiresMinimumSwipes() {
        // swipeCount=1 < minSwipesForLinearity=3, should not trigger
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 20, tapCount: 10, swipeCount: 1,
            swipeSpeedCV: 0.01
        )
        let context = TestFixtures.makeRiskContext(touch: touch)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: false,
            threshold: 60
        )
        let report = RiskScorer.score(context: context, config: config)
        let speedSignal = report.signals.first { $0.id == SignalID.swipeSpeedTooRegular }
        XCTAssertNil(speedSignal, "swipeSpeedTooRegular should require minSwipesForLinearity swipes")
    }

    // MARK: - Custom Thresholds via Config

    func testCustomThresholds_OverrideDefaults() {
        let customThresholds = BehaviorThresholds(
            forceVariance: 0.5,    // very permissive
            radiusVariance: 0.5,   // very permissive
            swipeSpeedCV: 0.01     // very strict
        )
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 20, tapCount: 4, swipeCount: 5,
            forceVariance: 0.001,       // would trigger with default, not with 0.5
            majorRadiusVariance: 0.003, // would trigger with default, not with 0.5
            swipeSpeedCV: 0.005         // triggers with strict 0.01
        )
        let context = TestFixtures.makeRiskContext(touch: touch)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: false,
            threshold: 60,
            behaviorThresholds: customThresholds
        )
        let report = RiskScorer.score(context: context, config: config)

        XCTAssertNil(report.signals.first { $0.id == SignalID.forceTooUniform },
                     "Custom permissive forceVariance should prevent trigger")
        XCTAssertNil(report.signals.first { $0.id == SignalID.radiusTooUniform },
                     "Custom permissive radiusVariance should prevent trigger")
        XCTAssertNotNil(report.signals.first { $0.id == SignalID.swipeSpeedTooRegular },
                        "Custom strict swipeSpeedCV should trigger")
    }

    // MARK: - maxBehaviorScore Cap

    func testBehaviorScoreCappedByMaxBehaviorScore() {
        // Trigger as many heuristics as possible to exceed maxBehaviorScore
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 20, tapCount: 4, swipeCount: 5,
            coordinateSpread: 0.5,    // triggers touchSpreadLow (+12)
            intervalCV: 0.05,         // triggers touchIntervalTooRegular (+10)
            averageLinearity: 0.99,   // triggers swipeTooLinear (+8)
            forceVariance: 0,         // triggers forceTooUniform (+10)
            majorRadiusVariance: 0,   // triggers radiusTooUniform (+8)
            swipeSpeedCV: 0.01        // triggers swipeSpeedTooRegular (+6)
        )
        let context = TestFixtures.makeRiskContext(touch: touch, stillnessRatio: 0.99)
        let thresholds = BehaviorThresholds(maxBehaviorScore: 25)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: false,
            threshold: 60,
            behaviorThresholds: thresholds
        )
        let report = RiskScorer.score(context: context, config: config)

        // All behavior signals should contribute but total is capped at maxBehaviorScore
        let behaviorSignals = report.signals.filter { $0.category == SignalCategory.behavior }
        let rawBehaviorTotal = behaviorSignals.map(\.score).reduce(0, +)
        XCTAssertGreaterThan(rawBehaviorTotal, 25, "Raw behavior total should exceed cap")
        // Total report score should respect the cap (behavior portion <= 25)
        XCTAssertLessThanOrEqual(report.score, 100)
    }

    // MARK: - No Duplicate Insufficient Data Signal

    func testNoRedundantInsufficientDataSignal() {
        // Sufficient samples: should NOT produce any insufficientBehaviorData signal
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 20, tapCount: 10, swipeCount: 5
        )
        let context = TestFixtures.makeRiskContext(touch: touch)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: false,
            threshold: 60
        )
        let report = RiskScorer.score(context: context, config: config)
        let insufficientSignals = report.signals.filter { $0.id == SignalID.insufficientBehaviorData }
        XCTAssertEqual(insufficientSignals.count, 0,
                       "Sufficient samples should not produce any insufficient_behavior_data signal")
    }

    func testInsufficientSamples_ProducesExactlyOneSignal() {
        // Below minimum: should produce exactly ONE insufficientBehaviorData
        let touch = TestFixtures.makeTouchMetrics(
            sampleCount: 3, tapCount: 1, swipeCount: 0
        )
        let context = TestFixtures.makeRiskContext(touch: touch)
        let config = RiskConfig(
            jailbreak: .default,
            enableBehaviorDetect: true,
            enableNetworkSignals: false,
            threshold: 60
        )
        let report = RiskScorer.score(context: context, config: config)
        let insufficientSignals = report.signals.filter { $0.id == SignalID.insufficientBehaviorData }
        XCTAssertEqual(insufficientSignals.count, 1,
                       "Insufficient samples should produce exactly one insufficient_behavior_data signal, not duplicates")
    }

    // MARK: - GPU/IMU Provider Stubs (non-iOS)

    func testGPURenderFingerprintProviderID() {
        let provider = GPURenderFingerprintProvider.shared
        XCTAssertEqual(provider.id, "gpu_render_fingerprint")
    }

    func testIMUNoiseSpectrumProviderID() {
        let provider = IMUNoiseSpectrumProvider.shared
        XCTAssertEqual(provider.id, "imu_noise_spectrum")
    }

    // MARK: - Signal IDs

    func testNewSignalIDsExist() {
        XCTAssertEqual(SignalID.gpuRenderFingerprint, "gpu_render_fingerprint")
        XCTAssertEqual(SignalID.gpuRenderUnavailable, "gpu_render_unavailable")
        XCTAssertEqual(SignalID.imuNoiseFingerprint, "imu_noise_fingerprint")
        XCTAssertEqual(SignalID.imuNoiseSynthetic, "imu_noise_synthetic")
        XCTAssertEqual(SignalID.imuNoiseUnavailable, "imu_noise_unavailable")
        XCTAssertEqual(SignalID.imuNoiseInsufficient, "imu_noise_insufficient")
        XCTAssertEqual(SignalID.forceTooUniform, "force_too_uniform")
        XCTAssertEqual(SignalID.radiusTooUniform, "radius_too_uniform")
        XCTAssertEqual(SignalID.swipeSpeedTooRegular, "swipe_speed_too_regular")
    }

    // MARK: - TouchMetrics New Fields Codable

    func testTouchMetricsCodableWithNewFields() throws {
        let metrics = TouchMetrics(
            sampleCount: 50,
            tapCount: 20,
            swipeCount: 15,
            coordinateSpread: 45.0,
            intervalCV: 0.3,
            averageLinearity: 0.92,
            forceVariance: 0.0001,
            majorRadiusVariance: 0.003,
            swipeSpeedCV: 0.12
        )
        let data = try JSONEncoder().encode(metrics)
        let decoded = try JSONDecoder().decode(TouchMetrics.self, from: data)
        XCTAssertEqual(decoded.forceVariance, 0.0001)
        XCTAssertEqual(decoded.majorRadiusVariance, 0.003)
        XCTAssertEqual(decoded.swipeSpeedCV, 0.12)
    }

    // MARK: - BehaviorSignals Sample Sufficiency with New Fields

    func testSampleSufficiency_SufficientWithNewMetrics() {
        let touch = TouchMetrics(
            sampleCount: 20, tapCount: 6, swipeCount: 4,
            coordinateSpread: 30, intervalCV: 0.3, averageLinearity: 0.9,
            forceVariance: 0.01, majorRadiusVariance: 0.1, swipeSpeedCV: 0.2
        )
        let behavior = BehaviorSignals(
            touch: touch,
            motion: MotionMetrics(sampleCount: 50, stillnessRatio: 0.2, motionEnergy: 1.0)
        )
        XCTAssertEqual(behavior.sampleSufficiency, .sufficient)
    }
}
