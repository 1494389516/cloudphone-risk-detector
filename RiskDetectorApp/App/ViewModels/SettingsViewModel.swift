import Foundation
import SwiftUI

#if canImport(CloudPhoneRiskAppCore)
import CloudPhoneRiskAppCore
#endif

// MARK: - Settings ViewModel
/// 规范：
/// - 输出：config: RiskAppConfig（通过各个 @Published 属性暴露）
/// - 行为：load/save/reset/setLogEnabled
/// - 检测时由 Dashboard 传入 config
@MainActor
public class SettingsViewModel: ObservableObject {
    // MARK: - 检测开关
    @Published public var enableBehaviorDetect: Bool = true
    @Published public var enableNetworkSignals: Bool = true

    // MARK: - 越狱检测开关
    @Published public var jailbreakEnableFileDetect: Bool = true
    @Published public var jailbreakEnableDyldDetect: Bool = true
    @Published public var jailbreakEnableEnvDetect: Bool = true
    @Published public var jailbreakEnableSysctlDetect: Bool = true
    @Published public var jailbreakEnableSchemeDetect: Bool = true
    @Published public var jailbreakEnableHookDetect: Bool = true

    // MARK: - 阈值
    @Published public var threshold: Double = 60
    @Published public var jailbreakThreshold: Double = 50

    // MARK: - 存储设置
    @Published public var storeEncryptionEnabled: Bool = true
    @Published public var storeMaxFiles: Int = 50

    // MARK: - 调试
    @Published public var logEnabled: Bool = false
    @Published public var debugSimulateCloudPhoneSignals: Bool = false
    @Published public var debugShowDetailedSignals: Bool = false  // 显示 method/evidence 详情

    #if canImport(CloudPhoneRiskAppCore)
    private let store = RiskAppConfigStore()
    #endif

    public init() {
        load()
    }

    // MARK: - Actions

    /// 从持久化加载配置
    public func load() {
        #if canImport(CloudPhoneRiskAppCore)
        let config = store.load()
        enableBehaviorDetect = config.enableBehaviorDetect
        enableNetworkSignals = config.enableNetworkSignals
        threshold = config.threshold
        jailbreakEnableFileDetect = config.jailbreakEnableFileDetect
        jailbreakEnableDyldDetect = config.jailbreakEnableDyldDetect
        jailbreakEnableEnvDetect = config.jailbreakEnableEnvDetect
        jailbreakEnableSysctlDetect = config.jailbreakEnableSysctlDetect
        jailbreakEnableSchemeDetect = config.jailbreakEnableSchemeDetect
        jailbreakEnableHookDetect = config.jailbreakEnableHookDetect
        jailbreakThreshold = config.jailbreakThreshold
        storeEncryptionEnabled = config.storeEncryptionEnabled
        storeMaxFiles = config.storeMaxFiles
        #endif
    }

    /// 保存配置到持久化
    public func save() {
        #if canImport(CloudPhoneRiskAppCore)
        try? store.save(currentConfig())
        #endif
    }

    /// 重置为默认配置
    public func resetToDefault() {
        enableBehaviorDetect = true
        enableNetworkSignals = true
        threshold = 60
        jailbreakEnableFileDetect = true
        jailbreakEnableDyldDetect = true
        jailbreakEnableEnvDetect = true
        jailbreakEnableSysctlDetect = true
        jailbreakEnableSchemeDetect = true
        jailbreakEnableHookDetect = true
        jailbreakThreshold = 50
        storeEncryptionEnabled = true
        storeMaxFiles = 50
        logEnabled = false
        debugSimulateCloudPhoneSignals = false
        debugShowDetailedSignals = false

        #if canImport(CloudPhoneRiskAppCore)
        store.reset()
        #endif
        save()
        setLogEnabled(false)
        setSimulateCloudPhoneSignals(false)
    }

    /// 设置日志开关
    public func setLogEnabled(_ enabled: Bool) {
        logEnabled = enabled
        #if canImport(CloudPhoneRiskAppCore)
        RiskDetectionService.shared.setLogEnabled(enabled)
        #endif
    }

    /// 调试用：注入一组“云手机/服务端聚合信号”，用于验证 UI/评分链路。
    public func setSimulateCloudPhoneSignals(_ enabled: Bool) {
        debugSimulateCloudPhoneSignals = enabled
        #if canImport(CloudPhoneRiskAppCore)
        if enabled {
            RiskDetectionService.shared.setExternalServerSignals(
                publicIP: "203.0.113.10",
                asn: "AS64500",
                asOrg: "Cloud-DC",
                isDatacenter: NSNumber(value: true),
                ipDeviceAgg: NSNumber(value: 260),
                ipAccountAgg: NSNumber(value: 800),
                geoCountry: "CN",
                geoRegion: "BJ",
                riskTags: ["cloud_phone_sim"]
            )
        } else {
            RiskDetectionService.shared.clearExternalServerSignals()
        }
        #endif
    }

    /// 获取当前配置（用于传给检测）
    #if canImport(CloudPhoneRiskAppCore)
    public func currentConfig() -> RiskAppConfig {
        RiskAppConfig(
            enableBehaviorDetect: enableBehaviorDetect,
            enableNetworkSignals: enableNetworkSignals,
            threshold: threshold,
            jailbreakEnableFileDetect: jailbreakEnableFileDetect,
            jailbreakEnableDyldDetect: jailbreakEnableDyldDetect,
            jailbreakEnableEnvDetect: jailbreakEnableEnvDetect,
            jailbreakEnableSysctlDetect: jailbreakEnableSysctlDetect,
            jailbreakEnableSchemeDetect: jailbreakEnableSchemeDetect,
            jailbreakEnableHookDetect: jailbreakEnableHookDetect,
            jailbreakThreshold: jailbreakThreshold,
            storeEncryptionEnabled: storeEncryptionEnabled,
            storeMaxFiles: storeMaxFiles
        )
    }
    #endif
}
