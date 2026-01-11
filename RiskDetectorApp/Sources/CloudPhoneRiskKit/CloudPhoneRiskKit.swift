import Foundation
#if canImport(UIKit)
import UIKit

@objc(CPRiskKit)
public final class CPRiskKit: NSObject {
    @objc public static let shared = CPRiskKit()

    private let touchCapture = TouchCapture.shared
    private let motionSampler = MotionSampler.shared
    private let jailbreakEngine = JailbreakEngine()
    private let evaluateQueue = DispatchQueue(label: "CloudPhoneRiskKit.Evaluate", qos: .utility)

    private override init() {}

    /// 启动自动采集（全局触摸 + 传感器）。
    /// 建议在 `application(_:didFinishLaunchingWithOptions:)` 里尽早调用。
    @objc public func start() {
        Logger.log("start()")
        RiskSignalProviderRegistry.shared.register(ExternalServerAggregateProvider.shared)
        RiskSignalProviderRegistry.shared.register(DeviceHardwareProvider.shared)
        RiskSignalProviderRegistry.shared.register(DeviceAgeProvider.shared)
        RiskSignalProviderRegistry.shared.register(TimePatternProvider.shared)
        touchCapture.start()
        motionSampler.start()
    }

    @objc public func stop() {
        Logger.log("stop()")
        motionSampler.stop()
        touchCapture.stop()
    }

    @objc public static func setLogEnabled(_ enabled: Bool) {
        Logger.isEnabled = enabled
        Logger.log("Logger.isEnabled=\(enabled)")
    }

    @objc(setExternalServerSignalsPublicIP:asn:asOrg:isDatacenter:ipDeviceAgg:ipAccountAgg:geoCountry:geoRegion:riskTags:)
    public static func setExternalServerSignals(
        publicIP: String?,
        asn: String?,
        asOrg: String?,
        isDatacenter: NSNumber?,
        ipDeviceAgg: NSNumber?,
        ipAccountAgg: NSNumber?,
        geoCountry: String?,
        geoRegion: String?,
        riskTags: [String]?
    ) {
        ExternalServerAggregateProvider.shared.set(
            ServerSignals(
                publicIP: publicIP,
                asn: asn,
                asOrg: asOrg,
                isDatacenter: isDatacenter?.boolValue,
                ipDeviceAgg: ipDeviceAgg?.intValue,
                ipAccountAgg: ipAccountAgg?.intValue,
                geoCountry: geoCountry,
                geoRegion: geoRegion,
                riskTags: riskTags
            )
        )
    }

    @objc public static func clearExternalServerSignals() {
        ExternalServerAggregateProvider.shared.set(nil)
    }

    /// Register a custom signal provider (Swift only).
    public static func register(provider: RiskSignalProvider) {
        RiskSignalProviderRegistry.shared.register(provider)
        Logger.log("provider.register: id=\(provider.id)")
    }

    public static func unregisterProvider(id: String) {
        RiskSignalProviderRegistry.shared.unregister(id: id)
        Logger.log("provider.unregister: id=\(id)")
    }

    public static func registeredProviderIDs() -> [String] {
        RiskSignalProviderRegistry.shared.listIDs()
    }

    @objc public func evaluate() -> CPRiskReport {
        evaluate(config: .default)
    }

    /// 生成一次完整风控报告（本地评分 + JSON 载荷）。
    @objc(evaluateWithConfig:)
    public func evaluate(config: CPRiskConfig = .default) -> CPRiskReport {
        let swiftConfig = config.toSwift()
        Logger.log("evaluate(config): threshold=\(swiftConfig.threshold) behavior=\(swiftConfig.enableBehaviorDetect) network=\(swiftConfig.enableNetworkSignals) jb.threshold=\(swiftConfig.jailbreak.threshold)")

        RiskSignalProviderRegistry.shared.register(ExternalServerAggregateProvider.shared)
        RiskSignalProviderRegistry.shared.register(DeviceHardwareProvider.shared)
        RiskSignalProviderRegistry.shared.register(DeviceAgeProvider.shared)
        RiskSignalProviderRegistry.shared.register(TimePatternProvider.shared)

        let (touchMetrics, actionTimestamps) = touchCapture.snapshotDetailAndReset()
        let (motionMetrics, motionSeries) = motionSampler.snapshotDetailAndReset()
        let coupling = BehaviorCoupling.touchMotionCorrelation(actionTimestamps: actionTimestamps, motion: motionSeries)
        Logger.log("behavior.coupling: actions=\(actionTimestamps.count) corr=\(coupling?.description ?? "nil")")

        let context = RiskContext(
            device: DeviceFingerprint.current(),
            deviceID: KeychainDeviceID.shared.getOrCreate(),
            network: NetworkSignals.current(),
            behavior: BehaviorSignals(touch: touchMetrics, motion: motionMetrics, touchMotionCorrelation: coupling, actionCount: actionTimestamps.count),
            jailbreak: jailbreakEngine.detect(config: swiftConfig.jailbreak)
        )

        let snapshot = RiskSnapshot(
            deviceID: context.deviceID,
            device: context.device,
            network: context.network,
            behavior: context.behavior,
            jailbreak: context.jailbreak
        )
        let extraSignals = RiskSignalProviderRegistry.shared.signals(snapshot: snapshot)

        let report = RiskScorer.score(context: context, config: swiftConfig, extraSignals: extraSignals)
        Logger.log("final: score=\(report.score) isHighRisk=\(report.isHighRisk) signals=\(report.signals.count) summary=\(report.summary)")
        let out = CPRiskReport(context: context, report: report)
        out.setServerSignals(RiskSignalProviderRegistry.shared.serverSignals(snapshot: snapshot))
        RiskHistoryStore.shared.append(
            RiskHistoryEvent(
                t: Date().timeIntervalSince1970,
                score: report.score,
                isHighRisk: report.isHighRisk,
                summary: report.summary
            )
        )
        let pattern = RiskHistoryStore.shared.pattern()
        out.setLocalSignals(
            LocalSignals(
                timePattern: pattern,
                cloudPhone: CloudPhoneLocalSignalsBuilder.build(device: context.device, behavior: context.behavior, timePattern: pattern)
            )
        )
        return out
    }

    /// 异步生成报告（避免在主线程做重活）。
    /// completion 始终回到主线程。
    @objc(evaluateAsyncWithCompletion:)
    public func evaluateAsync(completion: @escaping (CPRiskReport) -> Void) {
        evaluateAsync(config: .default, completion: completion)
    }

    /// 异步生成报告（避免在主线程做重活）。
    /// completion 始终回到主线程。
    @objc(evaluateAsyncWithConfig:completion:)
    public func evaluateAsync(config: CPRiskConfig, completion: @escaping (CPRiskReport) -> Void) {
        let cfg = config
        evaluateQueue.async {
            let report = self.evaluate(config: cfg)
            DispatchQueue.main.async {
                completion(report)
            }
        }
    }
}
#else

@objc(CPRiskKit)
public final class CPRiskKit: NSObject {
    @objc public static let shared = CPRiskKit()
    private let evaluateQueue = DispatchQueue(label: "CloudPhoneRiskKit.Evaluate", qos: .utility)
    private override init() {}

    @objc public func start() {}
    @objc public func stop() {}

    @objc public static func setLogEnabled(_ enabled: Bool) {
        Logger.isEnabled = enabled
        Logger.log("Logger.isEnabled=\(enabled)")
    }

    @objc(setExternalServerSignalsPublicIP:asn:asOrg:isDatacenter:ipDeviceAgg:ipAccountAgg:geoCountry:geoRegion:riskTags:)
    public static func setExternalServerSignals(
        publicIP: String?,
        asn: String?,
        asOrg: String?,
        isDatacenter: NSNumber?,
        ipDeviceAgg: NSNumber?,
        ipAccountAgg: NSNumber?,
        geoCountry: String?,
        geoRegion: String?,
        riskTags: [String]?
    ) {
        ExternalServerAggregateProvider.shared.set(
            ServerSignals(
                publicIP: publicIP,
                asn: asn,
                asOrg: asOrg,
                isDatacenter: isDatacenter?.boolValue,
                ipDeviceAgg: ipDeviceAgg?.intValue,
                ipAccountAgg: ipAccountAgg?.intValue,
                geoCountry: geoCountry,
                geoRegion: geoRegion,
                riskTags: riskTags
            )
        )
    }

    @objc public static func clearExternalServerSignals() {
        ExternalServerAggregateProvider.shared.set(nil)
    }

    public static func register(provider: RiskSignalProvider) {
        RiskSignalProviderRegistry.shared.register(provider)
        Logger.log("provider.register: id=\(provider.id)")
    }

    public static func unregisterProvider(id: String) {
        RiskSignalProviderRegistry.shared.unregister(id: id)
        Logger.log("provider.unregister: id=\(id)")
    }

    public static func registeredProviderIDs() -> [String] {
        RiskSignalProviderRegistry.shared.listIDs()
    }

    @objc public func evaluate() -> CPRiskReport {
        evaluate(config: .default)
    }

    @objc(evaluateWithConfig:)
    public func evaluate(config: CPRiskConfig = .default) -> CPRiskReport {
        let swiftConfig = config.toSwift()
        let context = RiskContext(
            device: DeviceFingerprint.current(),
            deviceID: KeychainDeviceID.shared.getOrCreate(),
            network: NetworkSignals.current(),
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
            jailbreak: DetectionResult(isJailbroken: false, confidence: 0, detectedMethods: [], details: "unsupported_platform")
        )
        let snapshot = RiskSnapshot(
            deviceID: context.deviceID,
            device: context.device,
            network: context.network,
            behavior: context.behavior,
            jailbreak: context.jailbreak
        )
        RiskSignalProviderRegistry.shared.register(ExternalServerAggregateProvider.shared)
        RiskSignalProviderRegistry.shared.register(DeviceHardwareProvider.shared)
        RiskSignalProviderRegistry.shared.register(DeviceAgeProvider.shared)
        RiskSignalProviderRegistry.shared.register(TimePatternProvider.shared)
        let extraSignals = RiskSignalProviderRegistry.shared.signals(snapshot: snapshot)
        let report = RiskScorer.score(context: context, config: swiftConfig, extraSignals: extraSignals)
        let out = CPRiskReport(context: context, report: report)
        out.setServerSignals(RiskSignalProviderRegistry.shared.serverSignals(snapshot: snapshot))
        RiskHistoryStore.shared.append(
            RiskHistoryEvent(
                t: Date().timeIntervalSince1970,
                score: report.score,
                isHighRisk: report.isHighRisk,
                summary: report.summary
            )
        )
        let pattern = RiskHistoryStore.shared.pattern()
        out.setLocalSignals(
            LocalSignals(
                timePattern: pattern,
                cloudPhone: CloudPhoneLocalSignalsBuilder.build(device: context.device, behavior: context.behavior, timePattern: pattern)
            )
        )
        return out
    }

    @objc(evaluateAsyncWithCompletion:)
    public func evaluateAsync(completion: @escaping (CPRiskReport) -> Void) {
        evaluateAsync(config: .default, completion: completion)
    }

    @objc(evaluateAsyncWithConfig:completion:)
    public func evaluateAsync(config: CPRiskConfig, completion: @escaping (CPRiskReport) -> Void) {
        let cfg = config
        evaluateQueue.async {
            let report = self.evaluate(config: cfg)
            DispatchQueue.main.async {
                completion(report)
            }
        }
    }
}
#endif
