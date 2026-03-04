import CloudPhoneRiskKit
import Foundation

// MARK: - 3.0-beta.2 新增：面向图算法的结构体

/// 图算法载荷 - 包含图算法所需的全部特征数据
public struct GraphPayload: Codable, Sendable {
    /// 设备指纹向量 - 连续值特征
    public var fingerprintVector: FingerprintVector

    /// 构图边信号 - 用于构建设备关联图
    public var edgeSignals: EdgeSignals

    /// 时序分位数 - 用户行为时序特征
    public var temporalRhythm: TemporalRhythm

    /// 探针结果 - 能力检测得分
    public var capabilityScore: CapabilityScorePayload

    public init(
        fingerprintVector: FingerprintVector,
        edgeSignals: EdgeSignals,
        temporalRhythm: TemporalRhythm,
        capabilityScore: CapabilityScorePayload
    ) {
        self.fingerprintVector = fingerprintVector
        self.edgeSignals = edgeSignals
        self.temporalRhythm = temporalRhythm
        self.capabilityScore = capabilityScore
    }
}

/// 设备指纹向量 - 连续值特征，用于图节点特征表示
public struct FingerprintVector: Codable, Sendable {
    /// 硬件熵 - 越低越像云手机
    /// 取值范围: 0.0 ~ 8.0 (香农熵理论最大值)
    /// 真实设备通常在 4.0-7.0，云手机/模拟器通常 < 3.5
    public var hwEntropy: Double

    /// 分辨率偏差 - 屏幕分辨率与标准值的偏离程度
    /// 取值范围: 0.0 ~ 1.0
    /// 0 表示完全匹配标准分辨率，接近 1 表示异常分辨率
    public var screenRatioDrift: Double

    /// CPU 特征自洽性 - CPU 核心数与厂商信息的一致性
    /// 取值范围: 0.0 ~ 1.0
    /// 1 表示完全一致，0 表示严重不一致
    public var cpuCoreConsistency: Double

    /// 距上次重启秒数 - 设备运行时间
    /// 取值范围: 0 ~ 实际时间
    /// 云手机通常较短 (< 3600s)，真实设备通常较长
    public var bootTimeDelta: Int

    /// GPU 层级 - 图形能力评估
    /// 取值: 0=swiftshader(软件渲染，高度可疑), 1=低端GPU, 2=正常GPU
    public var gpuTier: Int

    public init(
        hwEntropy: Double,
        screenRatioDrift: Double,
        cpuCoreConsistency: Double,
        bootTimeDelta: Int,
        gpuTier: Int
    ) {
        self.hwEntropy = hwEntropy
        self.screenRatioDrift = screenRatioDrift
        self.cpuCoreConsistency = cpuCoreConsistency
        self.bootTimeDelta = bootTimeDelta
        self.gpuTier = gpuTier
    }
}

/// 构图边信号 - 用于在图结构中建立设备间关联
public struct EdgeSignals: Codable, Sendable {
    /// IP /24 子网 - 用于同网段设备关联
    /// 格式: "xxx.xxx.xxx" (如 "192.168.1")
    public var ipSubnet: String?

    /// 运营商 ASN - 机房 IP 特征识别
    /// 运营商 ASN 编号，数据中心/云服务 ASN 通常有特定范围
    public var carrierASN: Int?

    /// 时区偏移量 - 与 UTC 的时差（秒）
    /// 取值范围: -43200 ~ 43200 (-12 ~ +12 小时)
    public var timezoneOffset: Int

    /// 地区标识 - locale 信息
    /// 格式: "zh_CN", "en_US" 等
    public var locale: String

    public init(
        ipSubnet: String? = nil,
        carrierASN: Int? = nil,
        timezoneOffset: Int,
        locale: String
    ) {
        self.ipSubnet = ipSubnet
        self.carrierASN = carrierASN
        self.timezoneOffset = timezoneOffset
        self.locale = locale
    }
}

/// 时序分位数 - 用户行为时序特征，用于时序异常检测
public struct TemporalRhythm: Codable, Sendable {
    /// 本会话第几次上报 - 会话内序号
    /// 用于识别高频上报的自动化行为
    public var sessionSeq: Int

    /// 安装天数 - 应用安装时长
    /// 取值范围: 0 ~ 实际天数
    /// 新安装 (< 7天) 的设备风险更高
    public var installAgeDays: Int

    /// 点击间隔中位数 (毫秒)
    /// 用于识别过于规律或过于随机的点击行为
    public var tapIntervalP50: Double?

    /// 会话时长中位数 (秒)
    /// 异常短的会话可能表示自动化脚本
    public var sessionDurationP50: Double?

    public init(
        sessionSeq: Int,
        installAgeDays: Int,
        tapIntervalP50: Double? = nil,
        sessionDurationP50: Double? = nil
    ) {
        self.sessionSeq = sessionSeq
        self.installAgeDays = installAgeDays
        self.tapIntervalP50 = tapIntervalP50
        self.sessionDurationP50 = sessionDurationP50
    }
}

/// 探针结果 - 设备能力检测得分
public struct CapabilityScorePayload: Codable, Sendable {
    /// 基础异常数量 - 检测到的异常项总数
    /// 越高表示设备越可疑
    public var basicAnomalyCount: Int

    /// 质量可疑度 - 综合评估得分
    /// 取值范围: 0 ~ 100，越高越可疑
    public var qualitySuspicion: Int

    /// 探针总数 - 执行的探针检测项数量
    public var totalProbes: Int

    public init(
        basicAnomalyCount: Int,
        qualitySuspicion: Int,
        totalProbes: Int
    ) {
        self.basicAnomalyCount = basicAnomalyCount
        self.qualitySuspicion = qualitySuspicion
        self.totalProbes = totalProbes
    }
}
