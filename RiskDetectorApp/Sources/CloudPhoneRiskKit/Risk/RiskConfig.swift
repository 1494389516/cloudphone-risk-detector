import Foundation

public struct RiskConfig: Sendable {
    /// 默认风险阈值
    public static let defaultThreshold: Double = 60
    /// 轻量模式风险阈值
    public static let lightThreshold: Double = 70
    /// 完整模式风险阈值
    public static let fullThreshold: Double = 55
    /// 默认越狱检测阈值
    public static let defaultJailbreakThreshold: Double = 50

    public var jailbreak: JailbreakConfig
    public var enableBehaviorDetect: Bool
    public var enableNetworkSignals: Bool
    public var threshold: Double

    /// 阈值合法范围
    public static let thresholdRange: ClosedRange<Double> = 0...100

    public init(
        jailbreak: JailbreakConfig = .default,
        enableBehaviorDetect: Bool = true,
        enableNetworkSignals: Bool = true,
        threshold: Double = RiskConfig.defaultThreshold
    ) {
        self.jailbreak = jailbreak
        self.enableBehaviorDetect = enableBehaviorDetect
        self.enableNetworkSignals = enableNetworkSignals
        let clampedThreshold = min(max(threshold, Self.thresholdRange.lowerBound), Self.thresholdRange.upperBound)
        self.threshold = clampedThreshold
        if threshold != clampedThreshold {
            Logger.log("RiskConfig: threshold \(threshold) clamped to \(clampedThreshold)")
        }
    }

    public static let `default` = RiskConfig()

    public static let light = RiskConfig(
        jailbreak: .light,
        enableBehaviorDetect: true,
        enableNetworkSignals: true,
        threshold: lightThreshold
    )

    public static let full = RiskConfig(
        jailbreak: .full,
        enableBehaviorDetect: true,
        enableNetworkSignals: true,
        threshold: fullThreshold
    )
}

@objc(CPRiskConfig)
public final class CPRiskConfig: NSObject {
    @objc public var enableBehaviorDetect: Bool = true
    @objc public var enableNetworkSignals: Bool = true
    @objc public var threshold: Double = RiskConfig.defaultThreshold

    @objc public var jailbreakEnableFileDetect: Bool = true
    @objc public var jailbreakEnableDyldDetect: Bool = true
    @objc public var jailbreakEnableEnvDetect: Bool = true
    @objc public var jailbreakEnableSysctlDetect: Bool = true
    @objc public var jailbreakEnableSchemeDetect: Bool = true
    @objc public var jailbreakEnableHookDetect: Bool = true
    @objc public var jailbreakThreshold: Double = RiskConfig.defaultJailbreakThreshold

    // MARK: - 2.0 新增配置

    /// 是否启用远程配置
    @objc public var enableRemoteConfig: Bool = true

    /// 默认评估场景
    @objc public var defaultScenario: RiskScenario = .default

    /// 是否启用时序分析（预留开关）
    @objc public var enableTemporalAnalysis: Bool = true

    /// 是否启用反篡改检测（预留开关）
    @objc public var enableAntiTamper: Bool = true

    /// 远程配置地址（可选）
    @objc public var remoteConfigURLString: String = ""

    @objc public static let `default` = CPRiskConfig()

    func toSwift() -> RiskConfig {
        var jb = JailbreakConfig.default
        jb.enableFileDetect = jailbreakEnableFileDetect
        jb.enableDyldDetect = jailbreakEnableDyldDetect
        jb.enableEnvDetect = jailbreakEnableEnvDetect
        jb.enableSysctlDetect = jailbreakEnableSysctlDetect
        jb.enableSchemeDetect = jailbreakEnableSchemeDetect
        jb.enableHookDetect = jailbreakEnableHookDetect
        let clampedJBThreshold = min(max(jailbreakThreshold, RiskConfig.thresholdRange.lowerBound), RiskConfig.thresholdRange.upperBound)
        if jailbreakThreshold != clampedJBThreshold {
            Logger.log("CPRiskConfig: jailbreakThreshold \(jailbreakThreshold) clamped to \(clampedJBThreshold)")
        }
        jb.threshold = clampedJBThreshold

        return RiskConfig(
            jailbreak: jb,
            enableBehaviorDetect: enableBehaviorDetect,
            enableNetworkSignals: enableNetworkSignals,
            threshold: threshold
        )
    }
}
