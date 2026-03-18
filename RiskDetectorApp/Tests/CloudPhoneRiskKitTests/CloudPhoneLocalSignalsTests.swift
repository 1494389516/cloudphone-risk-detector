import XCTest
@testable import CloudPhoneRiskKit

final class CloudPhoneLocalSignalsTests: XCTestCase {

    // MARK: - CloudPhoneLocalSignals Codable

    func testCloudPhoneLocalSignalsCodableRoundTrip() throws {
        let signals = makeLocalSignals()
        let data = try JSONEncoder().encode(signals)
        let decoded = try JSONDecoder().decode(CloudPhoneLocalSignals.self, from: data)

        XCTAssertEqual(decoded.device.isSimulator.detected, signals.device.isSimulator.detected)
        XCTAssertEqual(decoded.behavior.touchSpreadLow.detected, signals.behavior.touchSpreadLow.detected)
        XCTAssertEqual(decoded.time.highVolume24h.detected, signals.time.highVolume24h.detected)
    }

    func testCloudPhoneLocalSignalsUsesShortCodingKeys() throws {
        let signals = makeLocalSignals()
        let data = try JSONEncoder().encode(signals)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]

        XCTAssertNotNil(json["d"], "Device should use short key 'd'")
        XCTAssertNotNil(json["b"], "Behavior should use short key 'b'")
        XCTAssertNotNil(json["t"], "Time should use short key 't'")
        XCTAssertNil(json["device"], "Should not use full key 'device'")
    }

    // MARK: - CloudPhoneLocalSignalsBuilder

    func testBuildWithNormalDevice() {
        let device = TestFixtures.makeDeviceFingerprint(isSimulator: false, hardwareMachine: "iPhone15,3")
        let behavior = TestFixtures.makeBehaviorSignals()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: nil)

        XCTAssertFalse(result.device.isSimulator.detected)
    }

    func testBuildWithSimulator() {
        let device = TestFixtures.makeDeviceFingerprint(isSimulator: true)
        let behavior = TestFixtures.makeBehaviorSignals()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: nil)

        XCTAssertTrue(result.device.isSimulator.detected)
    }

    func testBuildOldDeviceModel() {
        let device = TestFixtures.makeDeviceFingerprint(hardwareMachine: "iPhone10,1")
        let behavior = TestFixtures.makeBehaviorSignals()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: nil)

        // iPhone10,1 = family 10, <= 11 threshold → detected
        XCTAssertNotNil(result.device.oldDeviceModel)
        XCTAssertTrue(result.device.oldDeviceModel?.detected ?? false)
    }

    func testBuildNewDeviceModel() {
        let device = TestFixtures.makeDeviceFingerprint(hardwareMachine: "iPhone16,1")
        let behavior = TestFixtures.makeBehaviorSignals()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: nil)

        // iPhone16,1 = family 16, > 11 threshold → not detected
        XCTAssertNotNil(result.device.oldDeviceModel)
        XCTAssertFalse(result.device.oldDeviceModel?.detected ?? true)
    }

    func testBuildNonIPhoneDevice() {
        let device = TestFixtures.makeDeviceFingerprint(hardwareMachine: "iPad13,1")
        let behavior = TestFixtures.makeBehaviorSignals()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: nil)

        // Non-iPhone → unparsed, not detected
        XCTAssertNotNil(result.device.oldDeviceModel)
        XCTAssertFalse(result.device.oldDeviceModel?.detected ?? true)
    }

    // MARK: - Behavior Signals

    func testBuildTouchSpreadLow() {
        let touch = TestFixtures.makeTouchMetrics(tapCount: 10, coordinateSpread: 1.0)
        let behavior = TestFixtures.makeBehaviorSignals(touch: touch)
        let device = TestFixtures.makeDeviceFingerprint()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: nil)

        XCTAssertTrue(result.behavior.touchSpreadLow.detected, "Spread < 2.0 with 10 taps should detect")
    }

    func testBuildTouchSpreadLowNotDetectedWhenAboveThreshold() {
        let touch = TestFixtures.makeTouchMetrics(tapCount: 10, coordinateSpread: 5.0)
        let behavior = TestFixtures.makeBehaviorSignals(touch: touch)
        let device = TestFixtures.makeDeviceFingerprint()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: nil)

        XCTAssertFalse(result.behavior.touchSpreadLow.detected)
    }

    func testBuildTouchIntervalTooRegular() {
        let touch = TestFixtures.makeTouchMetrics(tapCount: 10, intervalCV: 0.1)
        let behavior = TestFixtures.makeBehaviorSignals(touch: touch)
        let device = TestFixtures.makeDeviceFingerprint()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: nil)

        XCTAssertTrue(result.behavior.touchIntervalTooRegular.detected, "CV < 0.2 with 10 taps should detect")
    }

    func testBuildMotionTooStill() {
        let touch = TestFixtures.makeTouchMetrics(sampleCount: 20, tapCount: 15, swipeCount: 5)
        let behavior = TestFixtures.makeBehaviorSignals(touch: touch, stillnessRatio: 0.99)
        let device = TestFixtures.makeDeviceFingerprint()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: nil)

        // actionCount = tapCount + swipeCount = 20, >= 10, and stillness > 0.98
        XCTAssertTrue(result.behavior.motionTooStill.detected)
    }

    // MARK: - Time Signals

    func testBuildWithNilTimePattern() {
        let device = TestFixtures.makeDeviceFingerprint()
        let behavior = TestFixtures.makeBehaviorSignals()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: nil)

        XCTAssertFalse(result.time.highVolume24h.detected)
        XCTAssertFalse(result.time.wideHourCoverage24h.detected)
        XCTAssertFalse(result.time.nightActivityHigh24h.detected)
        XCTAssertFalse(result.time.highFrequency24h.detected)
    }

    func testBuildHighVolume24h() {
        let pattern = TimePattern(events24h: 300, uniqueHours24h: 10, nightRatio24h: 0.1, averageIntervalSeconds24h: 100)
        let device = TestFixtures.makeDeviceFingerprint()
        let behavior = TestFixtures.makeBehaviorSignals()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: pattern)

        XCTAssertTrue(result.time.highVolume24h.detected, "300 events >= 200 threshold should detect")
    }

    func testBuildWideHourCoverage() {
        let pattern = TimePattern(events24h: 100, uniqueHours24h: 20, nightRatio24h: 0.1, averageIntervalSeconds24h: 100)
        let device = TestFixtures.makeDeviceFingerprint()
        let behavior = TestFixtures.makeBehaviorSignals()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: pattern)

        XCTAssertTrue(result.time.wideHourCoverage24h.detected, "20 hours >= 18 threshold with 100 events should detect")
    }

    func testBuildHighNightActivity() {
        let pattern = TimePattern(events24h: 100, uniqueHours24h: 10, nightRatio24h: 0.5, averageIntervalSeconds24h: 100)
        let device = TestFixtures.makeDeviceFingerprint()
        let behavior = TestFixtures.makeBehaviorSignals()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: pattern)

        XCTAssertTrue(result.time.nightActivityHigh24h.detected, "nightRatio 0.5 > 0.4 with 100 events should detect")
    }

    func testBuildHighFrequency() {
        let pattern = TimePattern(events24h: 100, uniqueHours24h: 10, nightRatio24h: 0.1, averageIntervalSeconds24h: 5.0)
        let device = TestFixtures.makeDeviceFingerprint()
        let behavior = TestFixtures.makeBehaviorSignals()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: pattern)

        XCTAssertTrue(result.time.highFrequency24h.detected, "avgInterval 5s < 8s with 100 events should detect")
    }

    func testBuildLowVolumeDoesNotTriggerTimeSignals() {
        let pattern = TimePattern(events24h: 10, uniqueHours24h: 20, nightRatio24h: 0.9, averageIntervalSeconds24h: 1.0)
        let device = TestFixtures.makeDeviceFingerprint()
        let behavior = TestFixtures.makeBehaviorSignals()
        let result = CloudPhoneLocalSignalsBuilder.build(device: device, behavior: behavior, timePattern: pattern)

        // 10 events < 80 minEvents for time signals
        XCTAssertFalse(result.time.wideHourCoverage24h.detected, "Low volume should not trigger even with extreme values")
        XCTAssertFalse(result.time.nightActivityHigh24h.detected)
        XCTAssertFalse(result.time.highFrequency24h.detected)
    }

    // MARK: - Helpers

    private func makeLocalSignals() -> CloudPhoneLocalSignals {
        let emptyEvidence: [String: String] = [:]
        return CloudPhoneLocalSignals(
            device: CloudPhoneDeviceSignals(
                isSimulator: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak),
                oldDeviceModel: nil
            ),
            behavior: CloudPhoneBehaviorSignals(
                touchSpreadLow: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak),
                touchSpreadHigh: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak),
                touchIntervalTooRegular: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak),
                touchIntervalTooChaotic: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak),
                swipeTooLinear: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak),
                swipeTooCurvy: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak),
                motionTooStill: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak),
                touchMotionWeakCoupling: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak)
            ),
            time: CloudPhoneTimeSignals(
                highVolume24h: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak),
                wideHourCoverage24h: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak),
                nightActivityHigh24h: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak),
                highFrequency24h: DetectionSignal(detected: false, method: "test", evidence: emptyEvidence, confidence: .weak)
            )
        )
    }
}
