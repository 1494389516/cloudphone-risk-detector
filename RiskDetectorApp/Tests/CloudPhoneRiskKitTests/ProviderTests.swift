import XCTest
@testable import CloudPhoneRiskKit

private final class TestProvider: RiskSignalProvider {
    let id: String
    private let produce: () -> [RiskSignal]

    init(id: String, produce: @escaping () -> [RiskSignal]) {
        self.id = id
        self.produce = produce
    }

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        _ = snapshot.deviceID
        return produce()
    }
}

final class ProviderTests: XCTestCase {
    func test_providerSignalsContributeToScore() {
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
            jailbreak: DetectionResult(isJailbroken: false, confidence: 0, detectedMethods: [], details: "")
        )

        let providerSignals = [
            RiskSignal(id: "p", category: "custom", score: 7, evidence: [:]),
        ]
        let report = RiskScorer.score(context: context, config: .default, extraSignals: providerSignals)
        XCTAssertTrue(report.score >= 7)
        XCTAssertTrue(report.signals.contains(where: { $0.id == "p" && $0.category == "custom" }))
    }

    func test_registryDeDupByProviderID() {
        let p1 = TestProvider(id: "dup") { [RiskSignal(id: "a", category: "c", score: 1, evidence: [:])] }
        let p2 = TestProvider(id: "dup") { [RiskSignal(id: "b", category: "c", score: 2, evidence: [:])] }
        RiskSignalProviderRegistry.shared.register(p1)
        RiskSignalProviderRegistry.shared.register(p2)
        XCTAssertEqual(RiskSignalProviderRegistry.shared.listIDs().filter { $0 == "dup" }.count, 1)
    }
}
