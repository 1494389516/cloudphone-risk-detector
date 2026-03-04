import Darwin
import Foundation
import MachO

// MARK: - 探针结果结构

/// 能力探针的执行结果
public struct ProbeResult: Codable, Sendable {
    /// 探针 ID
    public let id: String
    /// 是否成功（不该成功却成功了 = 异常）
    public let succeeded: Bool
    /// 执行耗时（微秒）
    public let elapsedMicros: UInt64
    /// errno 值
    public let errnoValue: Int32
    /// 调用栈帧（用于 B 类探针分析）
    public let callerFrame: String?

    public init(
        id: String,
        succeeded: Bool,
        elapsedMicros: UInt64,
        errnoValue: Int32,
        callerFrame: String? = nil
    ) {
        self.id = id
        self.succeeded = succeeded
        self.elapsedMicros = elapsedMicros
        self.errnoValue = errnoValue
        self.callerFrame = callerFrame
    }
}

// MARK: - 能力分数

/// 能力探针的评估分数
public struct CapabilityScore: Codable, Sendable {
    /// 不该通过却通过的探针数（A 类异常）
    public let basicAnomalyCount: Int
    /// Hook 伪造痕迹分（B 类异常）
    public let qualitySuspicion: Int
    /// 总探针数
    public let totalProbes: Int
    /// 风险贡献值
    public let riskContribution: Int

    public init(
        basicAnomalyCount: Int,
        qualitySuspicion: Int,
        totalProbes: Int
    ) {
        self.basicAnomalyCount = basicAnomalyCount
        self.qualitySuspicion = qualitySuspicion
        self.totalProbes = totalProbes
        // 核心逻辑：大部分失败 = 低风险，异常通过 = 高风险
        self.riskContribution = basicAnomalyCount * 3 + qualitySuspicion
    }

    /// 转换为软信号
    public func toSignal() -> RiskSignal {
        let confidence = min(Double(riskContribution) / 100.0, 1.0)
        return RiskSignal(
            id: "capability_probe",
            category: "capability",
            score: Double(riskContribution),
            evidence: [
                "basicAnomalyCount": "\(basicAnomalyCount)",
                "qualitySuspicion": "\(qualitySuspicion)",
                "totalProbes": "\(totalProbes)"
            ],
            state: RiskSignalState.soft(confidence: confidence),
            layer: 3,
            weightHint: Double(riskContribution) / 100.0
        )
    }
}

// MARK: - 能力探针引擎

/// 能力探针引擎
///
/// 核心思想：正常沙箱 = 大部分探针失败
/// - A 类探针：结论可能被伪造，权重低
/// - B 类探针：hook 伪造反而暴露自己
public final class CapabilityProbeEngine: @unchecked Sendable {

    // MARK: - 配置

    public struct Config: Sendable {
        /// 期望失败的最大耗时（微秒）
        public let maxElapsedMicros: UInt64
        /// 是否启用 B 类质量探针
        public let enableQualityProbes: Bool
        /// 自定义探针列表（可选）
        public let customProbes: [ProbeDefinition]?

        public init(
            maxElapsedMicros: UInt64 = 80,
            enableQualityProbes: Bool = true,
            customProbes: [ProbeDefinition]? = nil
        ) {
            self.maxElapsedMicros = maxElapsedMicros
            self.enableQualityProbes = enableQualityProbes
            self.customProbes = customProbes
        }

        public static let `default` = Config()
    }

    // MARK: - 探针定义

    public struct ProbeDefinition: Sendable {
        public let id: String
        public let expectedOutcome: ProbeExpectation
        public let maxElapsedMicros: UInt64
        public let weight: Int

        public init(
            id: String,
            expectedOutcome: ProbeExpectation,
            maxElapsedMicros: UInt64 = 80,
            weight: Int = 1
        ) {
            self.id = id
            self.expectedOutcome = expectedOutcome
            self.maxElapsedMicros = maxElapsedMicros
            self.weight = weight
        }
    }

    public enum ProbeExpectation: String, Codable, Sendable {
        case fail  // 期望失败（正常沙箱应该失败）
        case pass  // 期望通过
    }

    // MARK: - 私有属性

    private let config: Config

    // MARK: - 初始化

    public init(config: Config = .default) {
        self.config = config
    }

    // MARK: - A 类探针：基础能力探针

    /// 运行基础探针
    public func runBasicProbes() -> [ProbeResult] {
        return [
            probe("stat_bash")    { self.statFile("/bin/bash") },
            probe("stat_apt")     { self.statFile("/etc/apt") },
            probe("dyld_frida")   { self.dlopenFrida() },
            probe("sock_27042")   { self.canConnect(port: 27042) },
            probe("sock_27043")   { self.canConnect(port: 27043) },
            probe("sock_23946")   { self.canConnect(port: 23946) },
            probe("fork_ability") { self.canFork() },
            probe("dyld_insert")  { self.getEnvDYLD() }
        ]
    }

    // MARK: - B 类探针：质量探针

    /// 运行质量探针，分析 A 类结果
    public func runQualityProbes(_ basics: [ProbeResult]) -> Int {
        var suspicion = 0

        for result in basics where !result.succeeded {
            // ① 时序异常：伪造失败比真实失败慢
            if result.elapsedMicros > config.maxElapsedMicros {
                suspicion += 2
            }

            // ② errno 不一致：懒得设置或设置错误
            if result.id.contains("stat") {
                // stat 失败应该是 ENOENT 或 EACCES
                if result.errnoValue != ENOENT && result.errnoValue != EACCES {
                    suspicion += 2
                }
            }

            // ③ 调用栈出现陌生帧（Hook 框架特征）
            if let frame = result.callerFrame {
                let hookFrameworks = ["frida", "substrate", "substitute", "dobby", "fishhook"]
                if hookFrameworks.contains(where: { frame.lowercased().contains($0) }) {
                    suspicion += 5
                }
            }
        }

        return suspicion
    }

    // MARK: - 主评估入口

    /// 执行完整评估
    public func evaluate() -> CapabilityScore {
        let basics = runBasicProbes()
        let quality = config.enableQualityProbes ? runQualityProbes(basics) : 0
        let passed = basics.filter { $0.succeeded }.count

        return CapabilityScore(
            basicAnomalyCount: passed,
            qualitySuspicion: quality,
            totalProbes: basics.count
        )
    }

    /// 执行评估并返回详细结果（用于调试）
    public func evaluateDetailed() -> (score: CapabilityScore, probes: [ProbeResult]) {
        let basics = runBasicProbes()
        let quality = config.enableQualityProbes ? runQualityProbes(basics) : 0
        let passed = basics.filter { $0.succeeded }.count

        let score = CapabilityScore(
            basicAnomalyCount: passed,
            qualitySuspicion: quality,
            totalProbes: basics.count
        )

        return (score, basics)
    }

    // MARK: - 私有方法

    /// 通用探针执行器
    private func probe(_ id: String, block: () -> Bool) -> ProbeResult {
        let start = mach_absolute_time()
        let succeeded = block()
        let end = mach_absolute_time()

        // 转换为微秒
        var timebaseInfo = mach_timebase_info_data_t()
        mach_timebase_info(&timebaseInfo)
        let elapsedNanos = (end - start) * UInt64(timebaseInfo.numer) / UInt64(timebaseInfo.denom)
        let elapsedMicros = elapsedNanos / 1000

        return ProbeResult(
            id: id,
            succeeded: succeeded,
            elapsedMicros: elapsedMicros,
            errnoValue: errno
        )
    }

    /// stat 文件探针
    private func statFile(_ path: String) -> Bool {
        var statInfo = stat()
        return stat(path, &statInfo) == 0
    }

    /// dlopen Frida dylib 探针
    private func dlopenFrida() -> Bool {
        let fridaLibs = [
            "FridaGadget.dylib",
            "frida-agent-arm64.dylib",
            "frida-agent.dylib",
            "frida-server"
        ]
        for lib in fridaLibs {
            if dlopen(lib, RTLD_NOW) != nil {
                return true
            }
        }
        return false
    }

    /// 端口连接探针
    private func canConnect(port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }

    /// fork 能力探针
    /// 注意：iOS 上 fork 不可用，使用 pthread 检测线程创建能力作为替代
    private func canFork() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        // 使用 pthread 创建线程能力作为 sandbox 逃逸的代理指标
        // 在受限沙箱中，pthread_create 可能会失败
        var thread: pthread_t? = nil
        let result = pthread_create(&thread, nil, { _ in return nil }, nil)
        if result == 0, let thread = thread {
            pthread_cancel(thread)
            return true
        }
        return false
        #endif
    }

    /// DYLD_INSERT_LIBRARIES 环境变量探针
    private func getEnvDYLD() -> Bool {
        return getenv("DYLD_INSERT_LIBRARIES") != nil
    }
}

// MARK: - 探针配置热下发支持

extension CapabilityProbeEngine {

    /// 从远程配置创建引擎
    /// - Parameter probeConfig: 来自 RemoteConfig.probeConfig
    public static func fromRemoteConfig(_ probeConfig: ProbeConfig) -> CapabilityProbeEngine {
        let definitions = probeConfig.probes.map { config in
            ProbeDefinition(
                id: config.id,
                expectedOutcome: config.expectedOutcome == "fail" ? .fail : .pass,
                maxElapsedMicros: UInt64(config.maxElapsedUs),
                weight: config.weight
            )
        }

        let config = Config(
            maxElapsedMicros: 80,
            enableQualityProbes: true,
            customProbes: definitions
        )

        return CapabilityProbeEngine(config: config)
    }
}

// MARK: - 远程配置探针结构（使用 RemoteConfig 中的定义）

// ProbeConfig 和 ProbeConfigItem 已移至 RemoteConfig.swift
// 使用时 import CloudPhoneRiskKit 并通过 RemoteConfig.ProbeConfig 访问
