import Foundation

// MARK: - Risk Signal Vocabulary
//
// Signal identifier registry, categories, and the shared signal value types
// (RiskContext / RiskScoreReport / RiskSignalState). Extracted from RiskReport.swift
// so the signal type system is decoupled from report serialization.

// MARK: - Signal Identifiers

/// 统一管理所有 RiskSignal 的 ID，避免字符串散落各处导致拼写错误和维护困难
public enum SignalID {
    // Jailbreak
    static let jailbreak = ObfuscatedConstants.signalJailbreak

    // Network
    static let vpnActive = ObfuscatedConstants.requiredSignalVpnActive
    static let proxyEnabled = "proxy_enabled"
    static let networkInterfaceAnomaly = "network_interface_anomaly"
    /// 证书固定路径侧信道（Trust 交叉校验、完整性、stub、时序等）
    static let certificatePinningAnomaly = "certificate_pinning_anomaly"

    // Behavior
    static let touchSpreadLow = "touch_spread_low"
    static let touchSpreadHigh = "touch_spread_high"
    static let touchIntervalTooRegular = "touch_interval_too_regular"
    static let touchIntervalTooChaotic = "touch_interval_too_chaotic"
    static let swipeTooLinear = "swipe_too_linear"
    static let swipeTooCurvy = "swipe_too_curvy"
    static let motionTooStill = "motion_too_still"
    static let touchMotionWeakCoupling = "touch_motion_weak_coupling"
    static let insufficientBehaviorData = "insufficient_behavior_data"
    /// 该有交互上下文（app 被驱动/actionCount 过活动地板）却无真实触摸足迹（touch 样本≈0），
    /// 合成/自动化输入的签名。比 insufficient_behavior_data 强,贯彻 fail-closed。
    static let behaviorInteractionExpectedButAbsent = "behavior_interaction_expected_but_absent"
    static let forceTooUniform = "force_too_uniform"
    static let radiusTooUniform = "radius_too_uniform"
    static let swipeSpeedTooRegular = "swipe_speed_too_regular"

    // Time Pattern
    static let highVolume24h = "high_volume_24h"
    static let mediumVolume24h = "medium_volume_24h"
    static let wideHourCoverage = "wide_hour_coverage"
    static let nightActivityHigh = "night_activity_high"
    static let highFrequency = "high_frequency"

    // Server Aggregation
    static let datacenterIP = "datacenter_ip"
    static let ipDeviceAgg = "ip_device_agg"
    static let ipAccountAgg = "ip_account_agg"

    // Cloud Phone / Hardware
    static let gpuVirtual = "gpu_virtual"
    static let vphoneHardware = "vphone_hardware"
    static let hardwareInconsistency = "hardware_inconsistency"
    static let sensorEntropy = "sensor_entropy"
    static let touchEntropy = "touch_entropy"
    static let hookDetected = ObfuscatedConstants.signalHookDetected
    static let blocklistHit = "blocklist_hit"

    /// Display Mux (SDK 5.2)
    static let screenCaptured = "screen_captured"
    static let externalDisplayAttached = "external_display_attached"

    /// Signal suppression detection (SDK 5.5)
    static let signalSuppressionDetected = "signal_suppression_detected"

    // GPU Render Fingerprint (SDK 6.5)
    static let gpuRenderFingerprint = "gpu_render_fingerprint"
    static let gpuRenderUnavailable = "gpu_render_unavailable"

    // IMU Noise Spectrum (SDK 6.5)
    static let imuNoiseFingerprint = "imu_noise_fingerprint"
    static let imuNoiseSynthetic = "imu_noise_synthetic"
    static let imuNoiseUnavailable = "imu_noise_unavailable"
    static let imuNoiseInsufficient = "imu_noise_insufficient"

    // Anti-debug watchdog
    static let antiDebugWatchdogAnomaly = ObfuscatedConstants.signalAntiDebugWatchdogAnomaly
    static let antiDebugWatchdogTraced = ObfuscatedConstants.signalAntiDebugWatchdogTraced
    static let antiDebugWatchdogDenyAttachFailed = ObfuscatedConstants.signalAntiDebugWatchdogDenyAttachFailed
    static let antiDebugWatchdogExceptionPort = ObfuscatedConstants.signalAntiDebugWatchdogExceptionPort
    static let antiDebugWatchdogExceptionQuery = ObfuscatedConstants.signalAntiDebugWatchdogExceptionQuery
    static let antiDebugWatchdogDyldInjection = ObfuscatedConstants.signalAntiDebugWatchdogDyldInjection
    static let antiDebugWatchdogDenyAttachVerify = ObfuscatedConstants.signalAntiDebugWatchdogDenyAttachVerify
    static let antiDebugWatchdogAMFICsFlags = ObfuscatedConstants.signalAntiDebugWatchdogAMFICsFlags
    static let antiDebugWatchdogGetTaskAllow = ObfuscatedConstants.signalAntiDebugWatchdogGetTaskAllow
    /// objc_msgSend / libdyld prologue baseline mismatch (watchdog-aligned).
    static let antiDebugWatchdogCriticalHookSurface = ObfuscatedConstants.signalAntiDebugWatchdogCriticalHookSurface
    static let antiDebugWatchdogPacThreadEntry = ObfuscatedConstants.signalAntiDebugWatchdogPacThreadEntry
    static let antiDebugWatchdogVmImageLayoutDrift = ObfuscatedConstants.signalAntiDebugWatchdogVmImageLayoutDrift
    static let whiteboxPrfProbeDegraded = ObfuscatedConstants.signalWhiteboxPrfProbeDegraded
    static let softwareBreakpointDetected = ObfuscatedConstants.signalSoftwareBreakpointDetected
    static let exceptionDeliveryTimeout = ObfuscatedConstants.signalExceptionDeliveryTimeout
    /// CRiskCore recorded at least one libc (or arc4random) path because direct syscall was unavailable for this API surface.
    static let libcDirectSyscallFallback = ObfuscatedConstants.signalLibcDirectSyscallFallback
    /// `DebuggerDetector` aggregate signal.
    static let debuggerDetected = ObfuscatedConstants.signalDebuggerDetected
    static let csopsDebugged = ObfuscatedConstants.signalCsopsDebugged
    static let hardwareBreakpointDetected = ObfuscatedConstants.signalHardwareBreakpointDetected
    static let signalProbeDebugger = ObfuscatedConstants.signalSignalProbeDebugger
    /// Anti-debug plan section reported escalation / trap activity.
    static let antidebugPlanEscalated = ObfuscatedConstants.signalAntidebugPlanEscalated
    /// Multiple anti-debug channels (watchdog / debugger / strategy plan) agree at runtime.
    static let antiDebugRuntimeConsensus = "anti_debug_runtime_consensus"
    /// Code-signature and signing-identity lanes both report suspicious drift/tamper.
    static let signingChainConsensus = "signing_chain_consensus"

    // Frida module
    /// Multiple Frida-facing detectors (runtime / module / thread / heap / socket / hook surfaces) agree.
    static let fridaRuntimeConsensus = "frida_runtime_consensus"
    static let fridaExceptionPortStartupRace = ObfuscatedConstants.signalFridaExceptionPortStartupRace
    static let fridaModuleDetected = ObfuscatedConstants.signalFridaModuleDetected
    static let fridaModuleImage = ObfuscatedConstants.signalFridaModuleImage
    static let fridaModuleSection = ObfuscatedConstants.signalFridaModuleSection
    static let fridaModuleString = ObfuscatedConstants.signalFridaModuleString
    static let fridaModuleTrampoline = "frida_module_trampoline"

    // RWX / JIT (Stalker-like)
    static let stalkerJitRWX = ObfuscatedConstants.signalStalkerJitRWX
    static let rwxJitCoexistence = ObfuscatedConstants.signalRwxJitCoexistence

    // Multi-path consistency / vm_remap / PAC / task-port / dtrace-kdebug / LLDB JIT / dyld shared cache
    static let multiPathCrossInconsistency = ObfuscatedConstants.signalMultipathCrossInconsistency
    static let vmRemapSharedAnonymous = ObfuscatedConstants.signalVMRemapSharedAnonymous
    static let vmRemapImageAlias = ObfuscatedConstants.signalVMRemapImageAlias
    static let pacDisabled = ObfuscatedConstants.signalPacDisabled
    static let pacPointerInvalid = ObfuscatedConstants.signalPacPointerInvalid

    /// MIE / MTE（含 EMTE sysctl 形状）设备姿态：仅 sysctl 观测，保守分级。
    static let miePosture = "mie_posture"
    /// 窄条件：sysctl 子集之间出现与“基位/扩展位”不一致的形状（不推断具体攻击）。
    static let mteUnavailableOnCapable = "mte_unavailable_on_capable_device"
    /// 进程级 MTE tagging 无法仅从 sysctl 断言；iOS 上作说明性软信号。
    static let mteInactiveForProcess = "mte_inactive_for_process"
    /// 预留：native MTE canary 链路与 CRiskCore 对齐后由底层填充；Swift 层不伪造。
    static let mteCanaryTampered = "mte_canary_tampered"
    static let taskPortExceptionHijack = ObfuscatedConstants.signalTaskPortExceptionHijack
    static let taskPortRightsAnomaly = ObfuscatedConstants.signalTaskPortRightsAnomaly
    static let dtraceKdebugActivity = ObfuscatedConstants.signalDtraceKdebugActivity
    static let lldbJitSmallRWX = ObfuscatedConstants.signalLldbJitSmallRWX
    static let dyldSharedCacheIntegrity = ObfuscatedConstants.signalDyldSharedCacheIntegrity
    static let dyldSharedCacheUUIDMismatch = ObfuscatedConstants.signalDyldSharedCacheUUIDMismatch
    static let dyldSharedCacheSlideMismatch = ObfuscatedConstants.signalDyldSharedCacheSlideMismatch
    static let dyldSharedCacheSymbolMismatch = ObfuscatedConstants.signalDyldSharedCacheSymbolMismatch
    static let dylibInjectImageCountLow = ObfuscatedConstants.signalDylibInjectImageCountLow
    /// Multi-path libc spawn entry resolution mismatch (RTLD_DEFAULT / dlopen+dlsym / export trie) or prologue anomaly.
    static let ifaceSpawnPathDivergence = ObfuscatedConstants.signalIfaceSpawnPathDivergence

    // MARK: - CR-001: Jailbreak + Debug + Kernel Anomaly

    /// Anti-debug watchdog: is_debugged 聚合信号（traced / deny_attach / exception_port 等）
    static let isDebugged = "is_debugged"
    /// Frida V8/QuickJS heap 异常（大匿名 RWX 区域）
    static let v8HeapAnomaly = ObfuscatedConstants.signalFridaJSEngineHeap
    /// Frida 端口开放（frida_port_* 系列信号）
    static let fridaPortOpen = "frida_port_open"
    /// 内核 Build 指纹异常（kernelBuild 与已知云手机/模拟器 build 不一致）
    static let kernelBuildAnomaly = "kernel_build_anomaly"

    // MARK: - CR-002: Device Tamper + IDFV + MCC

    /// 设备篡改综合分（来自 AntiTamperingSignalProvider 的聚合分）
    static let deviceTamperScore = "device_tamper_score"
    /// IDFV 重装次数异常（短时间多次重装）
    static let idfvReinstallCount = "idfv_reinstall_count"
    /// MCC（移动国家码）与设备归属地不一致
    static let mccMismatch = "mcc_mismatch"

    // MARK: - CR-003: Simulator + Cloud Hostname

    /// 模拟器检测（targetEnvironment(simulator) 或 FingerprintDeobfuscation 命中）
    static let isSimulator = "is_simulator"
    /// 设备 hostname 包含云手机标识（如 cloudphone, vphone, vm 等）
    static let hostnameContainsCloud = "hostname_contains_cloud"

    // MARK: - CR-004: No Cellular + Battery Static

    /// 电池电量静止（多采样期间无变化）
    static let batteryLevelStatic = "battery_level_static"
    /// 充电状态无变化（多采样期间）
    static let noChargeStateChange = "no_charge_state_change"

    // MARK: - CR-005: Frida Triple Stack

    /// DNS 隧道检测（异常 DNS 查询模式）
    static let dnsTunnelDetected = "dns_tunnel_detected"

    // MARK: - CR-006: Time Anomaly Combo

    /// 启动时间回拨（boot time 比上次记录更早）
    static let bootTimeRollback = "boot_time_rollback"
    /// 系统时间跳跃（短时间内大幅前进或后退）
    static let systemTimeJump = "system_time_jump"
    /// 安装日期异常（过新/过旧/不符合设备生命周期）
    static let installDateUnusual = "install_date_unusual"

    // MARK: - CR-007: CVD Multilayer Detection

    /// CVD 触摸-运动解耦：大量触摸事件但传感器完全静默（虚拟输入注入特征）
    static let touchMotionDecoupling = "touch_motion_decoupling"
    /// CVD 环境冻结锁：热状态+电池+亮度三维同时静止（虚拟环境不可能状态）
    static let environmentFreezeLock = "environment_freeze_lock"
}

// MARK: - Signal Categories

/// 统一管理所有 RiskSignal 的 category
public enum SignalCategory {
    static let jailbreak = ObfuscatedConstants.signalJailbreak
    static let network = "network"
    static let behavior = "behavior"
    static let time = "time"
    static let server = "server"
    static let cloudphone = "cloudphone"
}

public struct RiskContext: Sendable {
    var device: DeviceFingerprint
    var deviceID: String
    var network: NetworkSignals
    var behavior: BehaviorSignals
    var jailbreak: DetectionResult
}

public struct RiskScoreReport: Sendable {
    public var score: Double
    public var isHighRisk: Bool
    public var signals: [RiskSignal]
    public var summary: String
    /// 内存语义压缩摘要（1.0=8 字节，1.1=9 字节含 byte 8 行为熵）
    public var compressedDigest: Data?
    /// 信号到 bit 映射表版本
    public var mappingVersion: String?
    /// 最终动作，供上报链路与服务端联动使用。
    public var action: RiskAction? = nil
    /// 引擎提炼后的主要原因，便于静默标记与审计对齐。
    public var primaryReasons: [String] = []
    /// 引擎聚合/底线决策的可观测元数据。
    public var decisionMetadata: [String: String]? = nil
}

public enum RiskSignalState: Sendable, Codable, Equatable {
    case hard(detected: Bool)
    case soft(confidence: Double)
    case serverRequired
    case unavailable
    case tampered

    private enum CodingKeys: String, CodingKey {
        case type = "t"
        case detected = "d"
        case confidence = "c"
    }

    private enum StateType: String, Codable {
        case hard
        case soft
        case serverRequired
        case unavailable
        case tampered
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(StateType.self, forKey: .type)
        switch type {
        case .hard:
            self = .hard(detected: try container.decode(Bool.self, forKey: .detected))
        case .soft:
            let raw = try container.decode(Double.self, forKey: .confidence)
            self = .soft(confidence: raw.isFinite ? min(max(raw, 0), 1) : 0)
        case .serverRequired:
            self = .serverRequired
        case .unavailable:
            self = .unavailable
        case .tampered:
            self = .tampered
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .hard(let detected):
            try container.encode(StateType.hard, forKey: .type)
            try container.encode(detected, forKey: .detected)
        case .soft(let confidence):
            try container.encode(StateType.soft, forKey: .type)
            try container.encode(confidence, forKey: .confidence)
        case .serverRequired:
            try container.encode(StateType.serverRequired, forKey: .type)
        case .unavailable:
            try container.encode(StateType.unavailable, forKey: .type)
        case .tampered:
            try container.encode(StateType.tampered, forKey: .type)
        }
    }
}
