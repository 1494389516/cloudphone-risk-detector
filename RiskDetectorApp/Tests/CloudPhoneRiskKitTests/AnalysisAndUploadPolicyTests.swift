import XCTest

@testable import CloudPhoneRiskKit

// MARK: - UploadPolicy Tests

final class UploadPolicyTests: XCTestCase {

  let policy = UploadPolicy()

  // MARK: riskLevel

  func testHighRiskLevel() {
    XCTAssertEqual(policy.riskLevel(for: 80), .high)
    XCTAssertEqual(policy.riskLevel(for: 100), .high)
    XCTAssertEqual(policy.riskLevel(for: 99), .high)
  }

  func testMediumRiskLevel() {
    XCTAssertEqual(policy.riskLevel(for: 50), .medium)
    XCTAssertEqual(policy.riskLevel(for: 79), .medium)
    XCTAssertEqual(policy.riskLevel(for: 65), .medium)
  }

  func testLowRiskLevel() {
    XCTAssertEqual(policy.riskLevel(for: 0), .low)
    XCTAssertEqual(policy.riskLevel(for: 49), .low)
    XCTAssertEqual(policy.riskLevel(for: 30), .low)
  }

  func testBoundaryThresholds() {
    XCTAssertEqual(policy.riskLevel(for: 80), .high)
    XCTAssertEqual(policy.riskLevel(for: 50), .medium)
    XCTAssertEqual(policy.riskLevel(for: 49), .low)
  }

  // MARK: shouldImmediateUpload / shouldBatch

  func testShouldImmediateUploadHighRisk() {
    XCTAssertTrue(policy.shouldImmediateUpload(score: 85))
    XCTAssertFalse(policy.shouldImmediateUpload(score: 60))
    XCTAssertFalse(policy.shouldImmediateUpload(score: 20))
  }

  func testShouldBatchLowRisk() {
    XCTAssertTrue(policy.shouldBatch(score: 20))
    XCTAssertFalse(policy.shouldBatch(score: 60))
    XCTAssertFalse(policy.shouldBatch(score: 90))
  }

  // MARK: calculateDelay — bounds

  func testCalculateDelayHighRiskNonNegative() {
    for _ in 0..<50 {
      let delay = policy.calculateDelay(for: 90)
      XCTAssertGreaterThanOrEqual(delay, 0, "延迟不得为负")
    }
  }

  func testCalculateDelayLowRiskStaysBounded() {
    // lowRiskBatchInterval=300, jitterRatio=0.2, jitter factor max=±0.5
    // max jitter = 300 * 0.2 * 0.5 = 30 → delay ∈ [270, 330]
    let config = UploadPolicy.PolicyConfig(
      highRiskDelayRange: 0...2,
      mediumRiskDelayRange: 30...120,
      lowRiskBatchInterval: 300,
      jitterRatio: 0.2
    )
    let p = UploadPolicy(config: config)
    for _ in 0..<100 {
      let delay = p.calculateDelay(for: 10)
      XCTAssertGreaterThanOrEqual(delay, 0)
      // Max possible: 300 + 300*0.2*0.5 = 330
      XCTAssertLessThanOrEqual(delay, 330.001, "抖动不应超过 ±0.5×jitterRatio×base")
    }
  }

  // MARK: strict / lenient presets

  func testStrictPresetHigherSensitivity() {
    XCTAssertEqual(UploadPolicy.strict.riskLevel(for: 70), .high)
    XCTAssertEqual(UploadPolicy.strict.riskLevel(for: 69), .medium)
  }

  func testLenientPresetLowerSensitivity() {
    XCTAssertEqual(UploadPolicy.lenient.riskLevel(for: 89), .medium)
    XCTAssertEqual(UploadPolicy.lenient.riskLevel(for: 90), .high)
  }

  // MARK: nextBatchDelay

  func testNextBatchDelayInFuture() {
    let now = Date().timeIntervalSince1970
    let delay = policy.nextBatchDelay(since: now)
    // batch interval = 300s, just started → remaining ≈ 300
    XCTAssertGreaterThan(delay, 290)
    XCTAssertLessThanOrEqual(delay, 300.1)
  }

  func testNextBatchDelayElapsed() {
    let past = Date().timeIntervalSince1970 - 400
    let delay = policy.nextBatchDelay(since: past)
    XCTAssertEqual(delay, 0, "已过期应返回 0")
  }
}

// MARK: - AnomalyDetector Tests

final class AnomalyDetectorTests: XCTestCase {

  let detector = AnomalyDetector()

  // MARK: Z-score

  func testZScoreInsufficientSamples() {
    let result = detector.detectZScore(value: 100, samples: [1, 2])
    XCTAssertFalse(result.isAnomalous)
    XCTAssertEqual(result.zScore, 0)
  }

  func testZScoreNotAnomalous() {
    let samples = [10.0, 10.0, 10.0, 10.0, 10.0]
    // All values equal → stdDev = 0 → not anomalous
    let result = detector.detectZScore(value: 10, samples: samples)
    XCTAssertFalse(result.isAnomalous)
  }

  func testZScoreAnomalousOutlier() {
    let samples = Array(repeating: 10.0, count: 20) + [10.0, 10.0, 10.0]
    let result = detector.detectZScore(value: 100.0, samples: samples, threshold: 2.0)
    XCTAssertTrue(result.isAnomalous)
    XCTAssertGreaterThan(result.zScore, 2.0)
  }

  func testZScoreNormalValue() {
    let samples = [10.0, 12.0, 11.0, 13.0, 10.0, 11.0, 12.0, 13.0, 11.0, 10.0]
    let result = detector.detectZScore(value: 11.5, samples: samples, threshold: 3.0)
    XCTAssertFalse(result.isAnomalous)
  }

  // MARK: IQR

  func testIQRInsufficientSamples() {
    let result = detector.detectIQR(value: 50, samples: [1, 2, 3])
    XCTAssertFalse(result.isAnomalous)
  }

  func testIQRNormalValue() {
    let samples = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0]
    let result = detector.detectIQR(value: 45.0, samples: samples)
    XCTAssertFalse(result.isAnomalous)
  }

  func testIQRHighOutlier() {
    let samples = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0]
    let result = detector.detectIQR(value: 200.0, samples: samples)
    XCTAssertTrue(result.isAnomalous)
    XCTAssertTrue(result.isAboveUpperBound)
    XCTAssertFalse(result.isBelowLowerBound)
  }

  func testIQRLowOutlier() {
    let samples = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0]
    let result = detector.detectIQR(value: -100.0, samples: samples)
    XCTAssertTrue(result.isAnomalous)
    XCTAssertTrue(result.isBelowLowerBound)
  }

  /// Q1/Q3 should be computed via linear interpolation, not raw integer index.
  /// For sorted=[10,20,30,40,50]: correct Q1=17.5, Q3=42.5
  func testIQRInterpolationCorrectness() {
    let samples = [30.0, 10.0, 50.0, 20.0, 40.0]  // sorted: [10,20,30,40,50]
    let result = detector.detectIQR(value: 30.0, samples: samples)
    // Q1 = interpolated 25th percentile of [10,20,30,40,50] = 17.5
    // Q3 = interpolated 75th percentile = 42.5
    // IQR = 25, lower = 17.5 - 1.5*25 = -20, upper = 42.5 + 1.5*25 = 80
    XCTAssertFalse(result.isAnomalous, "30 should be within IQR bounds")
    XCTAssertEqual(result.lowerBound, -20.0, accuracy: 0.01)
    XCTAssertEqual(result.upperBound, 80.0, accuracy: 0.01)
  }

  func testIQRAllSameValues() {
    // IQR = 0 → no anomaly detection possible
    let samples = [5.0, 5.0, 5.0, 5.0, 5.0]
    let result = detector.detectIQR(value: 5.0, samples: samples)
    XCTAssertFalse(result.isAnomalous)
  }
}

// MARK: - StatisticalFeatures / BehaviorBaseline Tests

final class StatisticalFeaturesTests: XCTestCase {

  // MARK: percentile interpolation via StatisticalFeatures.from

  func testPercentile25SingleElement() {
    let features = StatisticalFeatures.from([42.0])
    XCTAssertNotNil(features)
    XCTAssertEqual(features!.percentile25, 42.0, accuracy: 0.001)
    XCTAssertEqual(features!.percentile75, 42.0, accuracy: 0.001)
  }

  func testPercentileInterpolationFiveElements() {
    // sorted: [10, 20, 30, 40, 50]
    let features = StatisticalFeatures.from([30.0, 10.0, 50.0, 20.0, 40.0])
    XCTAssertNotNil(features)
    // p25 = 0.25 * 4 = index 1.0 = 20.0
    XCTAssertEqual(features!.percentile25, 17.5, accuracy: 0.01)
    // p75 = 0.75 * 4 = index 3.0 = 40.0
    XCTAssertEqual(features!.percentile75, 42.5, accuracy: 0.01)
  }

  func testPercentileEmptyReturnsNil() {
    XCTAssertNil(StatisticalFeatures.from([]))
  }

  func testMedianEvenCount() {
    // sorted: [1, 2, 3, 4] → median = (2+3)/2 = 2.5
    let features = StatisticalFeatures.from([3.0, 1.0, 4.0, 2.0])
    XCTAssertNotNil(features)
    XCTAssertEqual(features!.median, 2.5, accuracy: 0.001)
  }

  func testMedianOddCount() {
    // sorted: [1, 2, 3] → median = 2
    let features = StatisticalFeatures.from([3.0, 1.0, 2.0])
    XCTAssertNotNil(features)
    XCTAssertEqual(features!.median, 2.0, accuracy: 0.001)
  }

  func testMeanAndStdDev() {
    let features = StatisticalFeatures.from([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
    XCTAssertNotNil(features)
    XCTAssertEqual(features!.mean, 5.0, accuracy: 0.001)
    XCTAssertEqual(features!.stdDev, 2.0, accuracy: 0.001)
  }

  func testCoefficientOfVariationZeroMean() {
    // mean=0 → cv should be 0, not NaN
    let features = StatisticalFeatures.from([0.0, 0.0, 0.0])
    XCTAssertNotNil(features)
    XCTAssertFalse(features!.coefficientOfVariation.isNaN)
    XCTAssertEqual(features!.coefficientOfVariation, 0.0)
  }

  func testIQRCalculation() {
    let features = StatisticalFeatures.from([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0])
    XCTAssertNotNil(features)
    // IQR = p75 - p25, should be positive
    XCTAssertGreaterThan(features!.iqr, 0)
    XCTAssertEqual(features!.iqr, features!.percentile75 - features!.percentile25, accuracy: 0.001)
  }
}

// MARK: - TemporalFeatures Regression Slope Tests

final class TemporalFeaturesRegressionTests: XCTestCase {

  private func makeSnapshot(deviceID: String = "dev1", score: Double, offset: TimeInterval)
    -> DeviceDetectionSnapshot
  {
    DeviceDetectionSnapshot(
      timestamp: Date().timeIntervalSince1970 - offset,
      deviceID: deviceID,
      riskScore: score,
      isHighRisk: score >= 60,
      jailbreakStatus: JailbreakStatus(isJailbroken: false, confidence: 0.1, detectedMethods: []),
      isVPNActive: false,
      isProxyEnabled: false,
      networkInterfaceType: "wifi"
    )
  }

  /// All scores identical → denominator = 0 → should return .stable
  func testRegressionDenominatorZeroReturnStable() {
    // Build a calculator with snapshots that all have the same score
    let history = DeviceHistory.shared
    let deviceID = "test_regression_stable_\(UUID().uuidString)"
    for i in 0..<5 {
      let snap = makeSnapshot(deviceID: deviceID, score: 50.0, offset: TimeInterval(i * 3600))
      history.addSnapshot(snap)
    }
    let calculator = TemporalFeaturesCalculator(history: history)
    let features = calculator.calculate(for: deviceID)
    // Flat line → stable
    XCTAssertEqual(features.riskTrend, .stable)
  }

  /// Monotonically increasing scores → deteriorating
  func testRegressionIncreasingScoresDeteriorate() {
    let history = DeviceHistory.shared
    let deviceID = "test_regression_increase_\(UUID().uuidString)"
    let scores = [10.0, 25.0, 40.0, 55.0, 70.0, 85.0]
    for (i, score) in scores.enumerated() {
      let snap = makeSnapshot(
        deviceID: deviceID, score: score, offset: TimeInterval((scores.count - i) * 3600))
      history.addSnapshot(snap)
    }
    let calculator = TemporalFeaturesCalculator(history: history)
    let features = calculator.calculate(for: deviceID)
    XCTAssertEqual(features.riskTrend, .deteriorating)
  }

  /// Monotonically decreasing scores → improving
  func testRegressionDecreasingScoresImprove() {
    let history = DeviceHistory.shared
    let deviceID = "test_regression_decrease_\(UUID().uuidString)"
    let scores = [85.0, 70.0, 55.0, 40.0, 25.0, 10.0]
    for (i, score) in scores.enumerated() {
      let snap = makeSnapshot(
        deviceID: deviceID, score: score, offset: TimeInterval((scores.count - i) * 3600))
      history.addSnapshot(snap)
    }
    let calculator = TemporalFeaturesCalculator(history: history)
    let features = calculator.calculate(for: deviceID)
    XCTAssertEqual(features.riskTrend, .improving)
  }

  /// Fewer than 3 snapshots → unknown
  func testRegressionInsufficientDataReturnsUnknown() {
    let history = DeviceHistory.shared
    let deviceID = "test_regression_unknown_\(UUID().uuidString)"
    let snap = makeSnapshot(deviceID: deviceID, score: 50.0, offset: 0)
    history.addSnapshot(snap)
    let calculator = TemporalFeaturesCalculator(history: history)
    let features = calculator.calculate(for: deviceID)
    XCTAssertEqual(features.riskTrend, .unknown)
  }

  func testDeviceHistoryResolveStorageDirectoryPrefersApplicationSupport() {
    let appSupport = URL(fileURLWithPath: "/tmp/app-support", isDirectory: true)
    let caches = URL(fileURLWithPath: "/tmp/caches", isDirectory: true)
    let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

    let resolved = DeviceHistory.resolveStorageDirectory(
      applicationSupportDirectories: [appSupport],
      cachesDirectories: [caches],
      temporaryDirectory: temp
    )

    XCTAssertEqual(resolved, appSupport)
  }

  func testDeviceHistoryResolveStorageDirectoryFallsBackToCaches() {
    let caches = URL(fileURLWithPath: "/tmp/caches", isDirectory: true)
    let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

    let resolved = DeviceHistory.resolveStorageDirectory(
      applicationSupportDirectories: [],
      cachesDirectories: [caches],
      temporaryDirectory: temp
    )

    XCTAssertEqual(resolved, caches.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true))
  }

  func testDeviceHistoryResolveStorageDirectoryFallsBackToTemporaryDirectory() {
    let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

    let resolved = DeviceHistory.resolveStorageDirectory(
      applicationSupportDirectories: [],
      cachesDirectories: [],
      temporaryDirectory: temp
    )

    XCTAssertEqual(resolved, temp.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true))
  }

}
