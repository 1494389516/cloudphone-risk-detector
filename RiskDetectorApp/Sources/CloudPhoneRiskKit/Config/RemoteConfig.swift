import Foundation

// MARK: - 远程配置模型
///
/// ## 设计理念
///
/// 远程配置（RemoteConfig）是 SDK 2.0 的核心数据结构，定义了从服务端下发的完整配置格式。
/// 它包含：
///
/// 1. **策略配置**：风险决策引擎的阈值和规则
/// 2. **检测器配置**：各个检测模块的开关和参数
/// 3. **白名单规则**：设备、IP、版本的黑白名单
/// 4. **AB 实验配置**：灰度实验的分流和参数
///
/// ## 数据结构
///
/// ```
/// RemoteConfig
/// ├── version: Int              # 配置版本号
/// ├── timestamp: TimeInterval   # 配置生成时间
/// ├── policy: Policy            # 策略配置
/// ├── detector: RemoteDetectorConfig  # 检测器配置
/// ├── whitelist: WhitelistRules # 白名单规则
/// └── experiments: ExperimentConfig # AB 实验配置
/// ```
///
/// ## 版本管理
///
/// - 每次配置更新，`version` 必须递增
/// - 客户端通过比较版本号判断是否需要更新
/// - 支持配置回滚（服务端下发旧版本号）
///
public struct RemoteConfig: Codable, Sendable {

    // MARK: - 基础信息

    /// 配置版本号（必须单调递增）
    public let version: Int

    /// 配置生成时间戳
    public let timestamp: TimeInterval

    /// 配置环境（dev/staging/prod）
    public let environment: ConfigEnvironment

    /// 配置描述
    public let description: String?

    // MARK: - 策略配置

    /// 风险决策策略
    public let policy: Policy

    // MARK: - 检测器配置

    /// 检测器配置
    public let detector: RemoteDetectorConfig

    // MARK: - 白名单规则

    /// 白名单规则
    public let whitelist: WhitelistRules

    // MARK: - AB 实验配置

    /// 实验配置
    public let experiments: ExperimentConfig

    // MARK: - 高级配置

    /// 高级配置选项
    public let advanced: AdvancedConfig?

    // MARK: - 初始化

    public init(
        version: Int,
        timestamp: TimeInterval = Date().timeIntervalSince1970,
        environment: ConfigEnvironment = .production,
        description: String? = nil,
        policy: Policy,
        detector: RemoteDetectorConfig,
        whitelist: WhitelistRules,
        experiments: ExperimentConfig,
        advanced: AdvancedConfig? = nil
    ) {
        self.version = version
        self.timestamp = timestamp
        self.environment = environment
        self.description = description
        self.policy = policy
        self.detector = detector
        self.whitelist = whitelist
        self.experiments = experiments
        self.advanced = advanced
    }

    // MARK: - 默认配置

    /// 默认配置（生产环境）
    public static let `default` = RemoteConfig(
        version: 1,
        timestamp: Date().timeIntervalSince1970,
        environment: .production,
        description: "Default production configuration",
        policy: Policy.default,
        detector: RemoteDetectorConfig.default,
        whitelist: WhitelistRules.default,
        experiments: ExperimentConfig.default,
        advanced: AdvancedConfig.default
    )

    /// 开发环境配置
    public static let development = RemoteConfig(
        version: 1,
        timestamp: Date().timeIntervalSince1970,
        environment: .development,
        description: "Development configuration",
        policy: Policy.development,
        detector: RemoteDetectorConfig.development,
        whitelist: WhitelistRules.default,
        experiments: ExperimentConfig.default,
        advanced: AdvancedConfig.default
    )

    // MARK: - 验证

    /// 验证配置是否有效
    public func validate() -> ValidationResult {
        var errors: [String] = []
        var warnings: [String] = []

        // 验证版本号
        if version < 0 {
            errors.append("版本号不能为负数")
        }

        // 验证策略
        if policy.threshold < 0 || policy.threshold > 100 {
            errors.append("策略阈值必须在 0-100 之间")
        }

        // 验证检测器配置
        if detector.jailbreakThreshold < 0 || detector.jailbreakThreshold > 100 {
            errors.append("越狱检测阈值必须在 0-100 之间")
        }

        // 验证实验配置
        if let trafficWarning = experiments.validateTraffic() {
            warnings.append(trafficWarning)
        }

        return ValidationResult(
            isValid: errors.isEmpty,
            errors: errors,
            warnings: warnings
        )
    }

    /// 检查配置是否过期
    public func isExpired(duration: TimeInterval) -> Bool {
        let now = Date().timeIntervalSince1970
        return (now - timestamp) > duration
    }
}

// MARK: - 验证结果

public struct ValidationResult: Sendable {
    public let isValid: Bool
    public let errors: [String]
    public let warnings: [String]
}

// MARK: - 配置环境

public enum ConfigEnvironment: String, Codable, Sendable {
    case development
    case staging
    case production

    public var displayName: String {
        switch self {
        case .development: return "开发环境"
        case .staging: return "预发布环境"
        case .production: return "生产环境"
        }
    }
}

// MARK: - 策略配置

public struct Policy: Codable, Sendable {

    // MARK: - 阈值配置

    /// 高风险阈值（分数 >= 此值判定为高风险）
    public let threshold: Double

    /// 中风险阈值
    public let mediumThreshold: Double

    // MARK: - 时间窗口配置

    /// 时间窗口（秒），用于时序分析
    public let timeWindow: TimeInterval

    /// 最小检测次数（时间窗口内的最小事件数）
    public let minDetectionCount: Int

    // MARK: - 权重配置

    /// 各风险信号的权重
    public let weights: Weights

    // MARK: - 动作配置

    /// 高风险动作列表
    public let highRemoteRiskActions: [RemoteRiskAction]

    /// 中风险动作列表
    public let mediumRemoteRiskActions: [RemoteRiskAction]

    // MARK: - 初始化

    public init(
        threshold: Double,
        mediumThreshold: Double = 40,
        timeWindow: TimeInterval = 86400, // 24小时
        minDetectionCount: Int = 3,
        weights: Weights,
        highRemoteRiskActions: [RemoteRiskAction],
        mediumRemoteRiskActions: [RemoteRiskAction]
    ) {
        self.threshold = threshold
        self.mediumThreshold = mediumThreshold
        self.timeWindow = timeWindow
        self.minDetectionCount = minDetectionCount
        self.weights = weights
        self.highRemoteRiskActions = highRemoteRiskActions
        self.mediumRemoteRiskActions = mediumRemoteRiskActions
    }

    // MARK: - 默认配置

    public static let `default` = Policy(
        threshold: 60,
        mediumThreshold: 40,
        timeWindow: 86400,
        minDetectionCount: 3,
        weights: Weights.default,
        highRemoteRiskActions: [.block, .log],
        mediumRemoteRiskActions: [.challenge, .log]
    )

    public static let development = Policy(
        threshold: 80,
        mediumThreshold: 50,
        timeWindow: 3600,
        minDetectionCount: 1,
        weights: Weights.default,
        highRemoteRiskActions: [.log],
        mediumRemoteRiskActions: [.log]
    )
}

// MARK: - 权重配置

public struct Weights: Codable, Sendable {
    /// 越狱检测权重
    public let jailbreak: Double

    /// 网络检测权重
    public let network: Double

    /// 行为检测权重
    public let behavior: Double

    /// 云手机检测权重
    public let cloudPhone: Double

    /// 时序模式权重
    public let timePattern: Double

    public init(
        jailbreak: Double = 0.6,
        network: Double = 0.15,
        behavior: Double = 0.15,
        cloudPhone: Double = 0.05,
        timePattern: Double = 0.05
    ) {
        self.jailbreak = jailbreak
        self.network = network
        self.behavior = behavior
        self.cloudPhone = cloudPhone
        self.timePattern = timePattern
    }

    public static let `default` = Weights()
}

// MARK: - 风险动作

public enum RemoteRiskAction: String, Codable, Sendable {
    /// 拦截操作
    case block

    /// 增加验证（如验证码）
    case challenge

    /// 记录日志
    case log

    /// 发送告警
    case alert

    /// 限制功能
    case restrict

    /// 放行但标记
    case flag

    public var displayName: String {
        switch self {
        case .block: return "拦截"
        case .challenge: return "增加验证"
        case .log: return "记录日志"
        case .alert: return "发送告警"
        case .restrict: return "限制功能"
        case .flag: return "标记"
        }
    }
}

// MARK: - 检测器配置

public struct RemoteDetectorConfig: Codable, Sendable {

    // MARK: - 越狱检测配置

    /// 越狱检测阈值
    public let jailbreakThreshold: Double

    /// 是否启用越狱文件检测
    public let jailbreakEnableFileDetect: Bool

    /// 是否启用越狱 dyld 检测
    public let jailbreakEnableDyldDetect: Bool

    /// 是否启用越狱环境变量检测
    public let jailbreakEnableEnvDetect: Bool

    /// 是否启用越狱 sysctl 检测
    public let jailbreakEnableSysctlDetect: Bool

    /// 是否启用越狱 URL Scheme 检测
    public let jailbreakEnableSchemeDetect: Bool

    /// ���否启用越狱 Hook 检测
    public let jailbreakEnableHookDetect: Bool

    // MARK: - 行为检测配置

    /// 是否启用行为检测
    public let enableBehaviorDetect: Bool

    /// 行为采样窗口大小（事件数）
    public let behaviorSampleWindow: Int

    /// 触摸检测最小样本数
    public let touchMinSampleCount: Int

    /// 运动检测最小样本数
    public let motionMinSampleCount: Int

    // MARK: - 网络检测配置

    /// 是否启用网络信号检测
    public let enableNetworkSignals: Bool

    /// 是否检测 VPN
    public let detectVPN: Bool

    /// 是否检测代理
    public let detectProxy: Bool

    // MARK: - 云手机检测配置

    /// 是否启用云手机检测
    public let enableCloudPhoneDetect: Bool

    // MARK: - 性能配置

    /// 最大检测耗时（毫秒）
    public let maxDetectionDuration: Int

    /// 是否启用异步检测
    public let enableAsyncDetection: Bool

    // MARK: - 初始化

    public init(
        jailbreakThreshold: Double = 50,
        jailbreakEnableFileDetect: Bool = true,
        jailbreakEnableDyldDetect: Bool = true,
        jailbreakEnableEnvDetect: Bool = true,
        jailbreakEnableSysctlDetect: Bool = true,
        jailbreakEnableSchemeDetect: Bool = true,
        jailbreakEnableHookDetect: Bool = true,
        enableBehaviorDetect: Bool = true,
        behaviorSampleWindow: Int = 100,
        touchMinSampleCount: Int = 6,
        motionMinSampleCount: Int = 10,
        enableNetworkSignals: Bool = true,
        detectVPN: Bool = true,
        detectProxy: Bool = true,
        enableCloudPhoneDetect: Bool = true,
        maxDetectionDuration: Int = 3000,
        enableAsyncDetection: Bool = false
    ) {
        self.jailbreakThreshold = jailbreakThreshold
        self.jailbreakEnableFileDetect = jailbreakEnableFileDetect
        self.jailbreakEnableDyldDetect = jailbreakEnableDyldDetect
        self.jailbreakEnableEnvDetect = jailbreakEnableEnvDetect
        self.jailbreakEnableSysctlDetect = jailbreakEnableSysctlDetect
        self.jailbreakEnableSchemeDetect = jailbreakEnableSchemeDetect
        self.jailbreakEnableHookDetect = jailbreakEnableHookDetect
        self.enableBehaviorDetect = enableBehaviorDetect
        self.behaviorSampleWindow = behaviorSampleWindow
        self.touchMinSampleCount = touchMinSampleCount
        self.motionMinSampleCount = motionMinSampleCount
        self.enableNetworkSignals = enableNetworkSignals
        self.detectVPN = detectVPN
        self.detectProxy = detectProxy
        self.enableCloudPhoneDetect = enableCloudPhoneDetect
        self.maxDetectionDuration = maxDetectionDuration
        self.enableAsyncDetection = enableAsyncDetection
    }

    // MARK: - 默认配置

    public static let `default` = RemoteDetectorConfig()

    public static let development = RemoteDetectorConfig(
        jailbreakThreshold: 50,
        enableBehaviorDetect: false, // 开发环境关闭行为检测
        enableNetworkSignals: true,
        maxDetectionDuration: 5000 // 开发环境允许更长时间
    )
}

// MARK: - 白名单规则

public struct WhitelistRules: Codable, Sendable {

    // MARK: - 设备白名单

    /// 设备 ID 白名单（完整匹配）
    public let deviceIDs: Set<String>

    /// 设备 ID 前缀白名单
    public let deviceIDPrefixes: [String]

    // MARK: - 黑名单

    /// 设备 ID 黑名单
    public let blacklistedDeviceIDs: Set<String>

    // MARK: - 版本白名单

    /// 信任的系统版本列表
    public let trustedVersions: [String]

    /// 信任的最低版本
    public let minTrustedVersion: String?

    // MARK: - IP/CIDR 白名单

    /// IP 白名单
    public let ipWhitelist: [String]

    // MARK: - 初始化

    public init(
        deviceIDs: Set<String> = [],
        deviceIDPrefixes: [String] = [],
        blacklistedDeviceIDs: Set<String> = [],
        trustedVersions: [String] = [],
        minTrustedVersion: String? = nil,
        ipWhitelist: [String] = []
    ) {
        self.deviceIDs = deviceIDs
        self.deviceIDPrefixes = deviceIDPrefixes
        self.blacklistedDeviceIDs = blacklistedDeviceIDs
        self.trustedVersions = trustedVersions
        self.minTrustedVersion = minTrustedVersion
        self.ipWhitelist = ipWhitelist
    }

    // MARK: - 默认配置

    public static let `default` = WhitelistRules()

    // MARK: - 检查方法

    /// 检查设备 ID 是否在白名单中
    public func contains(deviceID: String) -> Bool {
        // 完整匹配
        if deviceIDs.contains(deviceID) {
            return true
        }

        // 前缀匹配
        for prefix in deviceIDPrefixes {
            if deviceID.hasPrefix(prefix) {
                return true
            }
        }

        return false
    }

    /// 检查设备 ID 是否在黑名单中
    public func isBlacklisted(deviceID: String) -> Bool {
        return blacklistedDeviceIDs.contains(deviceID)
    }

    /// 检查系统版本是否受信任
    public func isTrusted(version: String) -> Bool {
        if trustedVersions.contains(version) {
            return true
        }

        // 版本号比较
        if let minVersion = minTrustedVersion {
            return version >= minVersion
        }

        return false
    }

    /// 检查 IP 是否在白名单中
    public func contains(ip: String) -> Bool {
        // 简单实现：精确匹配
        // TODO: 支持 CIDR 格式
        return ipWhitelist.contains(ip)
    }
}

// MARK: - 实验配置

public struct ExperimentConfig: Codable, Sendable {

    // MARK: - 活跃实验

    /// 当前活跃的实验列表
    public let active: [Experiment]

    // MARK: - 分流配置

    /// 分流算法
    public let bucketingAlgorithm: BucketingAlgorithm

    /// 实验过期时间
    public let experimentsExpiration: TimeInterval?

    // MARK: - 初始化

    public init(
        active: [Experiment] = [],
        bucketingAlgorithm: BucketingAlgorithm = .consistentHash,
        experimentsExpiration: TimeInterval? = nil
    ) {
        self.active = active
        self.bucketingAlgorithm = bucketingAlgorithm
        self.experimentsExpiration = experimentsExpiration
    }

    // MARK: - 默认配置

    public static let `default` = ExperimentConfig()

    // MARK: - 查询方法

    /// 获取指定实验的配置
    public func config(for experimentKey: String, deviceID: String) -> ExperimentVariant? {
        guard let experiment = active.first(where: { $0.key == experimentKey }) else {
            return nil
        }

        // 检查实验是否过期
        if let expiration = experimentsExpiration {
            let now = Date().timeIntervalSince1970
            if experiment.createdAt + expiration < now {
                return nil
            }
        }

        // 计算实验分桶
        let bucket = bucket(for: deviceID, experimentKey: experimentKey, traffic: experiment.traffic)

        // 返回对应分桶的配置
        return experiment.variants.first { $0.bucket == bucket }
    }

    /// 设备分桶
    private func bucket(for deviceID: String, experimentKey: String, traffic: Double) -> Int {
        switch bucketingAlgorithm {
        case .consistentHash:
            return consistentHashBucket(deviceID: deviceID, experimentKey: experimentKey, traffic: traffic)
        case .modular:
            return modularBucket(deviceID: deviceID, traffic: traffic)
        case .random:
            return Int.random(in: 0...100)
        }
    }

    /// 一致性哈希分桶
    private func consistentHashBucket(deviceID: String, experimentKey: String, traffic: Double) -> Int {
        let input = "\(deviceID):\(experimentKey)"
        let hash = input.data(using: .utf8)?.reduce(Int(0)) { ($0 << 8) + Int($1) } ?? 0
        let normalized = Double(hash % 10000) / 10000.0
        return normalized <= traffic ? 1 : 0
    }

    /// 模运算分桶
    private func modularBucket(deviceID: String, traffic: Double) -> Int {
        let hash = deviceID.data(using: .utf8)?.reduce(0) { partial, byte in partial + Int(byte) } ?? 0
        let bucket = hash % 100
        return Double(bucket) <= (traffic * 100) ? 1 : 0
    }

    // MARK: - 验证

    /// 验证流量分配
    public func validateTraffic() -> String? {
        let totalTraffic = active.reduce(0.0) { $0 + $1.traffic }
        if totalTraffic > 1.0 {
            return "实验总流量超过 100%: \(totalTraffic * 100)%"
        }
        return nil
    }
}

// MARK: - 实验

public struct Experiment: Codable, Sendable, Identifiable {
    public let id: String
    public let key: String
    public let name: String
    public let description: String?
    public let traffic: Double // 0-1
    public let variants: [ExperimentVariant]
    public let createdAt: TimeInterval
    public let updatedAt: TimeInterval

    public init(
        id: String,
        key: String,
        name: String,
        description: String? = nil,
        traffic: Double,
        variants: [ExperimentVariant],
        createdAt: TimeInterval = Date().timeIntervalSince1970,
        updatedAt: TimeInterval = Date().timeIntervalSince1970
    ) {
        self.id = id
        self.key = key
        self.name = name
        self.description = description
        self.traffic = traffic
        self.variants = variants
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

// MARK: - 实验变体

public struct ExperimentVariant: Codable, Sendable, Identifiable {
    public let id: String
    public let bucket: Int // 0=对照组, 1=实验组
    public let name: String
    public let description: String?
    public let parameters: [String: String]

    public init(
        id: String,
        bucket: Int,
        name: String,
        description: String? = nil,
        parameters: [String: String] = [:]
    ) {
        self.id = id
        self.bucket = bucket
        self.name = name
        self.description = description
        self.parameters = parameters
    }

    /// 获取参数值
    public func parameter(for key: String) -> String? {
        return parameters[key]
    }

    /// 获取参数值，带默认值
    public func parameter(for key: String, default: String) -> String {
        return parameters[key] ?? `default`
    }
}

// MARK: - 分流算法

public enum BucketingAlgorithm: String, Codable, Sendable {
    /// 一致性哈希（推荐，设备分桶稳定）
    case consistentHash

    /// 模运算（简单，但可能分布不均）
    case modular

    /// 随机（不推荐，设备分桶不稳定）
    case random
}

// MARK: - 高级配置

public struct AdvancedConfig: Codable, Sendable {

    // MARK: - 性能配置

    /// 是否启用性能监控
    public let enablePerformanceMonitoring: Bool

    /// 最大内存占用（MB）
    public let maxMemoryUsage: Int

    // MARK: - 调试配置

    /// 是否启用调试日志
    public let enableDebugLogging: Bool

    /// 是否收集诊断信息
    public let enableDiagnostics: Bool

    // MARK: - 上报配置

    /// 上报端点 URL
    public let reportEndpoint: String?

    /// 上报批量大小
    public let reportBatchSize: Int

    /// 上报间隔（秒）
    public let reportInterval: TimeInterval

    // MARK: - 初始化

    public init(
        enablePerformanceMonitoring: Bool = false,
        maxMemoryUsage: Int = 50,
        enableDebugLogging: Bool = false,
        enableDiagnostics: Bool = false,
        reportEndpoint: String? = nil,
        reportBatchSize: Int = 10,
        reportInterval: TimeInterval = 60
    ) {
        self.enablePerformanceMonitoring = enablePerformanceMonitoring
        self.maxMemoryUsage = maxMemoryUsage
        self.enableDebugLogging = enableDebugLogging
        self.enableDiagnostics = enableDiagnostics
        self.reportEndpoint = reportEndpoint
        self.reportBatchSize = reportBatchSize
        self.reportInterval = reportInterval
    }

    public static let `default` = AdvancedConfig()
}

// MARK: - RemoteConfig 扩展

extension RemoteConfig {

    /// 转换为 RiskConfig（兼容现有接口）
    public func toRiskConfig() -> RiskConfig {
        return RiskConfig(
            jailbreak: JailbreakConfig(
                enableFileDetect: detector.jailbreakEnableFileDetect,
                enableDyldDetect: detector.jailbreakEnableDyldDetect,
                enableEnvDetect: detector.jailbreakEnableEnvDetect,
                enableSysctlDetect: detector.jailbreakEnableSysctlDetect,
                enableSchemeDetect: detector.jailbreakEnableSchemeDetect,
                enableHookDetect: detector.jailbreakEnableHookDetect,
                threshold: detector.jailbreakThreshold
            ),
            enableBehaviorDetect: detector.enableBehaviorDetect,
            enableNetworkSignals: detector.enableNetworkSignals,
            threshold: policy.threshold
        )
    }

    /// 导出为 JSON 字符串
    public func toJSONString(prettyPrinted: Bool = false) -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = prettyPrinted ? [.prettyPrinted, .sortedKeys] : []
        guard let data = try? encoder.encode(self) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// 从 JSON 字符串创建
    public static func from(jsonString: String) -> RemoteConfig? {
        guard let data = jsonString.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(RemoteConfig.self, from: data)
    }
}

// MARK: - 示例配置 JSON

extension RemoteConfig {

    /// 示例配置 JSON（用于文档和测试）
    public static var sampleJSON: String {
        return """
        {
            "version": 1,
            "timestamp": \(Date().timeIntervalSince1970),
            "environment": "production",
            "description": "示例生产环境配置",
            "policy": {
                "threshold": 60,
                "mediumThreshold": 40,
                "timeWindow": 86400,
                "minDetectionCount": 3,
                "weights": {
                    "jailbreak": 0.6,
                    "network": 0.15,
                    "behavior": 0.15,
                    "cloudPhone": 0.05,
                    "timePattern": 0.05
                },
                "highRemoteRiskActions": ["block", "log"],
                "mediumRemoteRiskActions": ["challenge", "log"]
            },
            "detector": {
                "jailbreakThreshold": 50,
                "jailbreakEnableFileDetect": true,
                "jailbreakEnableDyldDetect": true,
                "jailbreakEnableEnvDetect": true,
                "jailbreakEnableSysctlDetect": true,
                "jailbreakEnableSchemeDetect": true,
                "jailbreakEnableHookDetect": true,
                "enableBehaviorDetect": true,
                "behaviorSampleWindow": 100,
                "touchMinSampleCount": 6,
                "motionMinSampleCount": 10,
                "enableNetworkSignals": true,
                "detectVPN": true,
                "detectProxy": true,
                "enableCloudPhoneDetect": true,
                "maxDetectionDuration": 3000,
                "enableAsyncDetection": false
            },
            "whitelist": {
                "deviceIDs": [],
                "deviceIDPrefixes": [],
                "blacklistedDeviceIDs": [],
                "trustedVersions": [],
                "minTrustedVersion": null,
                "ipWhitelist": []
            },
            "experiments": {
                "active": [
                    {
                        "id": "exp_001",
                        "key": "new_algorithm",
                        "name": "新算法实验",
                        "description": "测试新的风险评分算法",
                        "traffic": 0.1,
                        "variants": [
                            {
                                "id": "variant_control",
                                "bucket": 0,
                                "name": "对照组",
                                "parameters": {}
                            },
                            {
                                "id": "variant_treatment",
                                "bucket": 1,
                                "name": "实验组",
                                "parameters": {
                                    "algorithm": "v2",
                                    "threshold": "55"
                                }
                            }
                        ],
                        "createdAt": \(Date().timeIntervalSince1970),
                        "updatedAt": \(Date().timeIntervalSince1970)
                    }
                ],
                "bucketingAlgorithm": "consistentHash",
                "experimentsExpiration": null
            },
            "advanced": {
                "enablePerformanceMonitoring": false,
                "maxMemoryUsage": 50,
                "enableDebugLogging": false,
                "enableDiagnostics": false,
                "reportEndpoint": null,
                "reportBatchSize": 10,
                "reportInterval": 60
            }
        }
        """
    }
}
