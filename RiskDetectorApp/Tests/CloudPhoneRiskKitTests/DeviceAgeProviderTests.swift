import XCTest
@testable import CloudPhoneRiskKit

final class DeviceAgeProviderTests: XCTestCase {
    func test_oldDeviceScores() {
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
            screenScale: 3,
            hardwareMachine: "iPhone10,6",
            hardwareModel: "D22AP",
            isSimulator: false
        )
        let snap = RiskSnapshot(
            deviceID: "x",
            device: device,
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
            jailbreak: DetectionResult(isJailbroken: false, confidence: 0, detectedMethods: [], details: "")
        )

        let signals = DeviceAgeProvider.shared.signals(snapshot: snap)
        XCTAssertTrue(signals.contains(where: { $0.id == "old_device_model" }))
    }
}
