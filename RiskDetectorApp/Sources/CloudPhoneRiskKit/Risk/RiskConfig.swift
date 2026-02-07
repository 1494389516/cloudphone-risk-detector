import Foundation

public struct RiskConfig: Sendable {
    public var jailbreak: JailbreakConfig
    public var enableBehaviorDetect: Bool
    public var enableNetworkSignals: Bool
    public var threshold: Double

    public init(
        jailbreak: JailbreakConfig = .default,
        enableBehaviorDetect: Bool = true,
        enableNetworkSignals: Bool = true,
        threshold: Double = 60
    ) {
        self.jailbreak = jailbreak
        self.enableBehaviorDetect = enableBehaviorDetect
        self.enableNetworkSignals = enableNetworkSignals
        self.threshold = threshold
    }

    public static let `default` = RiskConfig()

    public static let light = RiskConfig(
        jailbreak: .light,
        enableBehaviorDetect: true,
        enableNetworkSignals: true,
        threshold: 70
    )

    public static let full = RiskConfig(
        jailbreak: .full,
        enableBehaviorDetect: true,
        enableNetworkSignals: true,
        threshold: 55
    )
}

@objc(CPRiskConfig)
public final class CPRiskConfig: NSObject {
    @objc public var enableBehaviorDetect: Bool = true
    @objc public var enableNetworkSignals: Bool = true
    @objc public var threshold: Double = 60

    @objc public var jailbreakEnableFileDetect: Bool = true
    @objc public var jailbreakEnableDyldDetect: Bool = true
    @objc public var jailbreakEnableEnvDetect: Bool = true
    @objc public var jailbreakEnableSysctlDetect: Bool = true
    @objc public var jailbreakEnableSchemeDetect: Bool = true
    @objc public var jailbreakEnableHookDetect: Bool = true
    @objc public var jailbreakThreshold: Double = 50

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
        jb.threshold = jailbreakThreshold

        return RiskConfig(
            jailbreak: jb,
            enableBehaviorDetect: enableBehaviorDetect,
            enableNetworkSignals: enableNetworkSignals,
            threshold: threshold
        )
    }
}
