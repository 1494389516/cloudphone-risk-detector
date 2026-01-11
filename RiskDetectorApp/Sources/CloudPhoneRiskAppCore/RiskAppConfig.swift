import CloudPhoneRiskKit
import Foundation

/// 检测 App 的“后端配置”（可持久化、可映射到 `CPRiskConfig`）。
public struct RiskAppConfig: Codable, Sendable {
    public var enableBehaviorDetect: Bool
    public var enableNetworkSignals: Bool
    public var threshold: Double

    public var jailbreakEnableFileDetect: Bool
    public var jailbreakEnableDyldDetect: Bool
    public var jailbreakEnableEnvDetect: Bool
    public var jailbreakEnableSysctlDetect: Bool
    public var jailbreakEnableSchemeDetect: Bool
    public var jailbreakEnableHookDetect: Bool
    public var jailbreakThreshold: Double

    public var storeEncryptionEnabled: Bool
    public var storeMaxFiles: Int

    public init(
        enableBehaviorDetect: Bool = true,
        enableNetworkSignals: Bool = true,
        threshold: Double = 60,
        jailbreakEnableFileDetect: Bool = true,
        jailbreakEnableDyldDetect: Bool = true,
        jailbreakEnableEnvDetect: Bool = true,
        jailbreakEnableSysctlDetect: Bool = true,
        jailbreakEnableSchemeDetect: Bool = true,
        jailbreakEnableHookDetect: Bool = true,
        jailbreakThreshold: Double = 50,
        storeEncryptionEnabled: Bool = true,
        storeMaxFiles: Int = 50
    ) {
        self.enableBehaviorDetect = enableBehaviorDetect
        self.enableNetworkSignals = enableNetworkSignals
        self.threshold = threshold
        self.jailbreakEnableFileDetect = jailbreakEnableFileDetect
        self.jailbreakEnableDyldDetect = jailbreakEnableDyldDetect
        self.jailbreakEnableEnvDetect = jailbreakEnableEnvDetect
        self.jailbreakEnableSysctlDetect = jailbreakEnableSysctlDetect
        self.jailbreakEnableSchemeDetect = jailbreakEnableSchemeDetect
        self.jailbreakEnableHookDetect = jailbreakEnableHookDetect
        self.jailbreakThreshold = jailbreakThreshold
        self.storeEncryptionEnabled = storeEncryptionEnabled
        self.storeMaxFiles = storeMaxFiles
    }

    public static let `default` = RiskAppConfig()

    public func toCPRiskConfig() -> CPRiskConfig {
        let c = CPRiskConfig()
        c.enableBehaviorDetect = enableBehaviorDetect
        c.enableNetworkSignals = enableNetworkSignals
        c.threshold = threshold

        c.jailbreakEnableFileDetect = jailbreakEnableFileDetect
        c.jailbreakEnableDyldDetect = jailbreakEnableDyldDetect
        c.jailbreakEnableEnvDetect = jailbreakEnableEnvDetect
        c.jailbreakEnableSysctlDetect = jailbreakEnableSysctlDetect
        c.jailbreakEnableSchemeDetect = jailbreakEnableSchemeDetect
        c.jailbreakEnableHookDetect = jailbreakEnableHookDetect
        c.jailbreakThreshold = jailbreakThreshold
        return c
    }
}

