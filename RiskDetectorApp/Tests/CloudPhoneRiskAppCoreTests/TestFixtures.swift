import Foundation
@testable import CloudPhoneRiskKit

/// 与 CloudPhoneRiskKitTests 共享的测试 fixture，供 CloudPhoneRiskAppCoreTests 使用。
enum TestFixtures {

    static func makeDeviceFingerprint(
        isSimulator: Bool = false,
        hardwareMachine: String? = "iPhone15,3"
    ) -> DeviceFingerprint {
        DeviceFingerprint(
            systemName: "iOS",
            systemVersion: "17.0",
            model: "iPhone",
            localizedModel: "iPhone",
            identifierForVendor: "TEST-UUID-1234",
            localeIdentifier: "zh_CN",
            timeZoneIdentifier: "Asia/Shanghai",
            timeZoneOffsetSeconds: 28800,
            screenWidth: 1179,
            screenHeight: 2556,
            screenScale: 3.0,
            hardwareMachine: hardwareMachine,
            hardwareModel: "D73AP",
            isSimulator: isSimulator
        )
    }

    static func makeNetworkSignals(
        vpnActive: Bool = false,
        proxyEnabled: Bool = false
    ) -> NetworkSignals {
        NetworkSignals(
            interfaceType: InterfaceTypeSignal(value: "wifi", method: "NWPathMonitor"),
            isExpensive: false,
            isConstrained: false,
            vpn: DetectionSignal<[String]>(
                detected: vpnActive,
                method: "ifaddrs_prefix",
                evidence: vpnActive ? ["utun0"] : nil,
                confidence: .weak
            ),
            proxy: DetectionSignal<[String: String]>(
                detected: proxyEnabled,
                method: "CFNetworkCopySystemProxySettings",
                evidence: proxyEnabled ? ["http_proxy": "127.0.0.1:8080"] : nil,
                confidence: .weak
            )
        )
    }

    static func makeTouchMetrics(
        sampleCount: Int = 20,
        tapCount: Int = 10,
        swipeCount: Int = 5,
        coordinateSpread: Double? = 50.0,
        intervalCV: Double? = 0.35,
        averageLinearity: Double? = 0.95,
        forceVariance: Double? = nil,
        majorRadiusVariance: Double? = nil,
        swipeSpeedCV: Double? = nil
    ) -> TouchMetrics {
        TouchMetrics(
            sampleCount: sampleCount,
            tapCount: tapCount,
            swipeCount: swipeCount,
            coordinateSpread: coordinateSpread,
            intervalCV: intervalCV,
            averageLinearity: averageLinearity,
            forceVariance: forceVariance,
            majorRadiusVariance: majorRadiusVariance,
            swipeSpeedCV: swipeSpeedCV
        )
    }

    static func makeBehaviorSignals(
        touch: TouchMetrics? = nil,
        stillnessRatio: Double? = 0.3,
        touchMotionCorrelation: Double? = 0.5
    ) -> BehaviorSignals {
        let t = touch ?? makeTouchMetrics()
        return BehaviorSignals(
            touch: t,
            motion: MotionMetrics(sampleCount: 100, stillnessRatio: stillnessRatio, motionEnergy: 0.5),
            touchMotionCorrelation: touchMotionCorrelation
        )
    }

    static func makeDetectionResult(
        isJailbroken: Bool = false,
        confidence: Double = 0,
        detectedMethods: [String] = []
    ) -> DetectionResult {
        DetectionResult(
            isJailbroken: isJailbroken,
            confidence: confidence,
            detectedMethods: detectedMethods,
            details: isJailbroken ? "jailbreak_detected" : "clean"
        )
    }

    static func makeRiskContext(
        isJailbroken: Bool = false,
        jailbreakConfidence: Double = 0,
        vpnActive: Bool = false,
        proxyEnabled: Bool = false,
        touch: TouchMetrics? = nil,
        stillnessRatio: Double? = 0.3
    ) -> RiskContext {
        RiskContext(
            device: makeDeviceFingerprint(),
            deviceID: "test-device-id",
            network: makeNetworkSignals(vpnActive: vpnActive, proxyEnabled: proxyEnabled),
            behavior: makeBehaviorSignals(touch: touch, stillnessRatio: stillnessRatio),
            jailbreak: makeDetectionResult(
                isJailbroken: isJailbroken,
                confidence: jailbreakConfidence,
                detectedMethods: isJailbroken ? ["file:test_path"] : []
            )
        )
    }

    static let defaultRiskConfig = RiskConfig(
        jailbreak: .default,
        enableBehaviorDetect: true,
        enableNetworkSignals: true,
        threshold: 60
    )
}
