import XCTest
@testable import CloudPhoneRiskKit

final class RiskScoringTests: XCTestCase {
    func test_scoreThreshold() {
        let device = DeviceFingerprint(
            systemName: "iOS",
            systemVersion: "17.0",
            model: "iPhone",
            localizedModel: "iPhone",
            identifierForVendor: nil,
            localeIdentifier: "en_US",
            timeZoneIdentifier: "UTC",
            timeZoneOffsetSeconds: 0,
            screenWidth: 1170,
            screenHeight: 2532,
            screenScale: 3
        )

        let context = RiskContext(
            device: device,
            deviceID: "test",
            network: NetworkSignals(
                interfaceType: InterfaceTypeSignal(value: "wifi", method: "test"),
                isExpensive: false,
                isConstrained: false,
                vpn: DetectionSignal(detected: true, method: "test", evidence: ["utun0"], confidence: .weak),
                proxy: DetectionSignal(detected: true, method: "test", evidence: ["http_proxy": "127.0.0.1:8888"], confidence: .weak)
            ),
            behavior: BehaviorSignals(
                touch: TouchMetrics(
                    sampleCount: 20,
                    tapCount: 10,
                    swipeCount: 0,
                    coordinateSpread: 1.0,
                    intervalCV: 0.1,
                    averageLinearity: nil,
                    forceVariance: nil,
                    majorRadiusVariance: nil
                ),
                motion: MotionMetrics(sampleCount: 100, stillnessRatio: 0.99, motionEnergy: 0.001)
            ),
            jailbreak: DetectionResult(isJailbroken: false, confidence: 0, detectedMethods: [], details: "")
        )

        let report = RiskScorer.score(context: context, config: .default)
        XCTAssertTrue(report.score > 0)
        XCTAssertTrue(report.signals.count >= 3)
    }

    func test_jailbreakHardVerdictAtLeastThreshold() {
        let device = DeviceFingerprint(
            systemName: "iOS",
            systemVersion: "17.0",
            model: "iPhone",
            localizedModel: "iPhone",
            identifierForVendor: nil,
            localeIdentifier: "en_US",
            timeZoneIdentifier: "UTC",
            timeZoneOffsetSeconds: 0,
            screenWidth: 1170,
            screenHeight: 2532,
            screenScale: 3
        )

        let context = RiskContext(
            device: device,
            deviceID: "test",
            network: NetworkSignals(
                interfaceType: InterfaceTypeSignal(value: "wifi", method: "test"),
                isExpensive: false,
                isConstrained: false,
                vpn: DetectionSignal(detected: false, method: "test", evidence: nil, confidence: .weak),
                proxy: DetectionSignal(detected: false, method: "test", evidence: nil, confidence: .weak)
            ),
            behavior: BehaviorSignals(
                touch: TouchMetrics(
                    sampleCount: 0,
                    tapCount: 0,
                    swipeCount: 0,
                    coordinateSpread: nil,
                    intervalCV: nil,
                    averageLinearity: nil,
                    forceVariance: nil,
                    majorRadiusVariance: nil
                ),
                motion: .empty
            ),
            jailbreak: DetectionResult(isJailbroken: true, confidence: 80, detectedMethods: ["file:/var/jb"], details: "")
        )

        let report = RiskScorer.score(context: context, config: .default)
        XCTAssertTrue(report.isHighRisk)
        XCTAssertEqual(report.score, 60)
        XCTAssertTrue(report.summary.contains("jailbreak"))
    }
}
