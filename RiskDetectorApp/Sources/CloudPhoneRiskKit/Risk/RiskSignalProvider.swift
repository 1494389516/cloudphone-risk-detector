import Foundation

// MARK: - Signal Provider System
//
// Extension point for injecting custom risk signals into the evaluation pipeline.
//
// Built-in Providers (auto-registered by CPRiskKit.start()):
//   server_aggregate   → IP/ASN/datacenter signals from server injection
//   device_hardware    → hw.machine, simulator detection
//   device_age         → old model heuristic risk scoring
//   biometric_state   → LAContext biometry probe (not enrolled / not available / lockout)
//   time_pattern       → 24h activity pattern analysis
//   vphone_hardware    → GPU/BoardID/kernel cloud phone indicators
//   battery_entropy    → ChargeCounter/voltage variance
//   drm_capability     → FairPlay DRM level
//   mount_point        → filesystem mount anomalies
//   layered_consistency→ cross-layer signal coherence
//
// Security: registry is sealed after start() — attempts to replace internal
// providers inject tamper signals (provider_tamper_attempt / provider_instance_replaced)

/// Pluggable signal provider (B2).
/// Register providers with `CPRiskKit.register(provider:)`.
public protocol RiskSignalProvider: AnyObject {
    /// Stable provider identifier (e.g. "device_age", "asn_aggregate").
    var id: String { get }

    /// Produce extra signals for the current evaluation snapshot.
    func signals(snapshot: RiskSnapshot) -> [RiskSignal]

    /// Optional: provide server-side aggregation fields to embed into the JSON payload.
    /// Default implementation returns nil.
    func serverSignals(snapshot: RiskSnapshot) -> ServerSignals?
}

public extension RiskSignalProvider {
    func serverSignals(snapshot: RiskSnapshot) -> ServerSignals? { nil }
}

enum BuiltInProviderBootstrap {
    private struct Entry {
        let token: UInt64
        let isEnabled: (CPRiskConfig) -> Bool
        let apply: (RiskSignalProviderRegistry) -> Void
    }

    private static let tokenMix: UInt64 = 0x8F42_C193_A55E_17D4

    private static let internalProviders: [RiskSignalProvider] = [
        ExternalServerAggregateProvider.shared,
        DeviceHardwareProvider.shared,
        DeviceAgeProvider.shared,
        AppAttestSignalProvider.shared,
        VPhoneHardwareProvider.shared,
        HardwareCapabilityProvider.shared,
        DisplayMuxProvider.shared,
        BiometricStateProvider.shared,
        LayeredConsistencyProvider.shared,
        MountPointProvider.shared,
        NetworkInterfaceProvider.shared,
        DRMCapabilityProvider.shared,
        BatteryEntropyProvider.shared,
        EnvironmentConsistencyProvider.shared,
        AudioRouteProvider.shared,
        BasebandIsolationProvider.shared,
        GPURenderFingerprintProvider.shared,
        IMUNoiseSpectrumProvider.shared,
        TimePatternProvider.shared,
        AntiTamperingSignalProvider.shared,
        CloudPhoneEnvironmentProvider.shared,
    ]

    private static let plan: [Entry] = [
        Entry(token: 0x1010_A001_B201_C301, isEnabled: { _ in true }) { registry in
            registry.register(ExternalServerAggregateProvider.shared)
        },
        Entry(token: 0x1010_A002_B202_C302, isEnabled: { _ in true }) { registry in
            registry.register(DeviceHardwareProvider.shared)
        },
        Entry(token: 0x1010_A003_B203_C303, isEnabled: { _ in true }) { registry in
            registry.register(DeviceAgeProvider.shared)
        },
        Entry(token: 0x1010_A004_B204_C304, isEnabled: { _ in true }) { registry in
            registry.register(AppAttestSignalProvider.shared)
        },
        Entry(token: 0x1010_A005_B205_C305, isEnabled: { _ in true }) { registry in
            registry.register(VPhoneHardwareProvider.shared)
        },
        Entry(token: 0x1010_A006_B206_C306, isEnabled: { _ in true }) { registry in
            registry.register(HardwareCapabilityProvider.shared)
        },
        Entry(token: 0x1010_A007_B207_C307, isEnabled: { _ in true }) { registry in
            registry.register(DisplayMuxProvider.shared)
        },
        Entry(token: 0x1010_A008_B208_C308, isEnabled: { _ in true }) { registry in
            registry.register(BiometricStateProvider.shared)
        },
        Entry(token: 0x1010_A009_B209_C309, isEnabled: { _ in true }) { registry in
            registry.register(LayeredConsistencyProvider.shared)
        },
        Entry(token: 0x1010_A00A_B20A_C30A, isEnabled: { _ in true }) { registry in
            registry.register(MountPointProvider.shared)
        },
        Entry(token: 0x1010_A00B_B20B_C30B, isEnabled: { _ in true }) { registry in
            registry.register(NetworkInterfaceProvider.shared)
        },
        Entry(token: 0x1010_A00C_B20C_C30C, isEnabled: { _ in true }) { registry in
            registry.register(DRMCapabilityProvider.shared)
        },
        Entry(token: 0x1010_A00D_B20D_C30D, isEnabled: { _ in true }) { registry in
            registry.register(BatteryEntropyProvider.shared)
        },
        Entry(token: 0x1010_A00E_B20E_C30E, isEnabled: { _ in true }) { registry in
            registry.register(EnvironmentConsistencyProvider.shared)
        },
        Entry(token: 0x1010_A00F_B20F_C30F, isEnabled: { _ in true }) { registry in
            registry.register(AudioRouteProvider.shared)
        },
        Entry(token: 0x1010_A010_B210_C310, isEnabled: { _ in true }) { registry in
            registry.register(BasebandIsolationProvider.shared)
        },
        Entry(token: 0x1010_A011_B211_C311, isEnabled: { _ in true }) { registry in
            registry.register(GPURenderFingerprintProvider.shared)
        },
        Entry(token: 0x1010_A012_B212_C312, isEnabled: { _ in true }) { registry in
            registry.register(IMUNoiseSpectrumProvider.shared)
        },
        Entry(token: 0x1010_A013_B213_C313, isEnabled: { $0.enableTemporalAnalysis }) { registry in
            registry.register(TimePatternProvider.shared)
        },
        Entry(token: 0x1010_A014_B214_C314, isEnabled: { !$0.enableTemporalAnalysis }) { registry in
            registry.unregister(id: TimePatternProvider.shared.id)
        },
        Entry(token: 0x1010_A015_B215_C315, isEnabled: { _ in true }) { registry in
            registry.register(AntiTamperingSignalProvider.shared)
        },
        Entry(token: 0x1010_A016_B216_C316, isEnabled: { _ in true }) { registry in
            registry.register(CloudPhoneEnvironmentProvider.shared)
        },
    ]

    static let internalProviderIDs: Set<String> = Set(internalProviders.map(\.id))

    static func apply(to registry: RiskSignalProviderRegistry, config: CPRiskConfig) {
        let orderedPlan = plan.sorted { lhs, rhs in
            (lhs.token ^ tokenMix) < (rhs.token ^ tokenMix)
        }
        for entry in orderedPlan where entry.isEnabled(config) {
            entry.apply(registry)
        }
    }
}

/// ## 线程模型（所有 Provider 必须遵守）
///
/// `collectWithTimeout` 是 Registry 的线程模型守卫：
///
/// **主线程调用路径（来自 UI 事件 / @MainActor 方法）**
/// - `collectWithTimeout` 检测到 `Thread.isMainThread == true` 时，直接同步执行 `provider.signals`。
/// - Provider 内部**不得**使用 `DispatchQueue.main.sync` 或 `semaphore.wait`，
///   否则主线程会在等待自己的队列时死锁（self-deadlock）。
/// - Provider 内部可以自由使用 `DispatchQueue.main.async`（不等待）。
///
/// **后台线程调用路径（来自 global 队列 / Task）**
/// - `collectWithTimeout` 在后台线程使用 `DispatchQueue.global().async + semaphore.wait(timeout:3s)`。
/// - Provider 内部可以使用 `DispatchQueue.main.sync`（跨线程等待主线程，不会死锁）。
/// - Provider 内部**不得**在主线程上再 `semaphore.wait`，否则回到主线程后会形成
///   「主线程 wait → 依赖主队列的 asyncAfter → 永不触发」的二次死锁。
///
/// **Provider 实现规范（摘要）**
/// - 需要 UIKit/CoreHaptics 的调用：用 `runOnMainIfNeeded { ... }`（即 `main.sync` 包装）。
/// - 需要延迟 + 等待结果的调用（如 proximitySensor）：
///   必须先 `guard !Thread.isMainThread` 跳过主线程，延迟调度用 `DispatchQueue.global().asyncAfter`，
///   读写 UIDevice 状态仍需内嵌 `DispatchQueue.main.sync`。
/// - 纯计算或 Darwin/POSIX API（getifaddrs、sysctl、LAContext）：无线程限制，直接调用。
final class RiskSignalProviderRegistry {
    static let shared = RiskSignalProviderRegistry()
    private init() {}

    /// 单个 Provider 执行超时时间（秒）
    private static let providerTimeoutSeconds: Double = 3.0
    /// 连续失败阈值，超过后跳过该 provider
    private static let maxConsecutiveFailures = 3

    private let lock = UnfairLock()
    private var providers: [RiskSignalProvider] = []
    private(set) var isSealed = false
    private var sealedProviderTypes: [String: ObjectIdentifier] = [:]
    private var sealedProviderInstances: [String: ObjectIdentifier] = [:]
    private var instanceReplacedProviderIDs: Set<String> = []
    private var activeProviderIDs: Set<String> = []
    private(set) var tamperedUnregisterAttempts: Int = 0
    private var consecutiveFailures: [String: Int] = [:]

    private static let internalProviderIDs = BuiltInProviderBootstrap.internalProviderIDs

    func seal() {
        lock.withLock {
            isSealed = true
            for provider in providers {
                sealedProviderTypes[provider.id] = ObjectIdentifier(type(of: provider))
                if Self.internalProviderIDs.contains(provider.id) {
                    sealedProviderInstances[provider.id] = ObjectIdentifier(provider)
                }
            }
        }
    }

    func register(_ provider: RiskSignalProvider) {
        lock.withLock {
            if isSealed {
                if !Self.internalProviderIDs.contains(provider.id) {
                    Logger.log("provider.register rejected (sealed): id=\(provider.id)")
                    return
                }
                if let expectedType = sealedProviderTypes[provider.id],
                   ObjectIdentifier(type(of: provider)) != expectedType {
                    Logger.log("provider.register rejected (type mismatch): id=\(provider.id)")
                    return
                }
                if let expectedInstance = sealedProviderInstances[provider.id],
                   ObjectIdentifier(provider) != expectedInstance {
                    instanceReplacedProviderIDs.insert(provider.id)
                    Logger.log("provider.register rejected (instance mismatch): id=\(provider.id)")
                    return
                }
            }
            providers.removeAll { $0.id == provider.id }
            providers.append(provider)
        }
    }

    func unregister(id: String) {
        lock.withLock {
            if isSealed, Self.internalProviderIDs.contains(id) {
                tamperedUnregisterAttempts += 1
                Logger.log("provider.unregister rejected (sealed internal): id=\(id) attempts=\(tamperedUnregisterAttempts)")
                return
            }
            providers.removeAll { $0.id == id }
        }
    }

    func listIDs() -> [String] {
        lock.withLock {
            providers.map(\.id)
        }
    }

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let (current, knownActive, unregisterAttempts, replacedIDs) = lock.withLock {
            (providers, activeProviderIDs, tamperedUnregisterAttempts, instanceReplacedProviderIDs)
        }

        var out: [RiskSignal] = []
        var newlyActive: Set<String> = []

        if unregisterAttempts > 0 {
            out.append(RiskSignal(
                id: "provider_tamper_attempt",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 85,
                evidence: ["attempts": "\(unregisterAttempts)"],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        if !replacedIDs.isEmpty {
            let ids = replacedIDs.sorted().joined(separator: ",")
            out.append(RiskSignal(
                id: "provider_instance_replaced",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 85,
                evidence: ["providers": ids],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        for provider in current {
            // 跳过连续失败过多的 provider
            let failures = lock.withLock { consecutiveFailures[provider.id] ?? 0 }
            if failures >= Self.maxConsecutiveFailures {
                Logger.log("provider[\(provider.id)]: skipped (consecutive failures=\(failures))")
                continue
            }

            let collected: [RiskSignal] = collectWithTimeout(provider: provider, snapshot: snapshot)

            if !collected.isEmpty {
                newlyActive.insert(provider.id)
                lock.withLock { consecutiveFailures[provider.id] = 0 }
                Logger.log("provider[\(provider.id)]: signals=\(collected.count)")
                for s in collected where s.score > 0 {
                    #if DEBUG
                    let keys = s.evidence.keys.sorted().joined(separator: ",")
                    Logger.log("provider.signal: provider=\(provider.id) category=\(s.category) id=\(s.id) score=\(s.score) evidenceKeys=\(keys)")
                    #endif
                }
                out.append(contentsOf: collected)
            } else if knownActive.contains(provider.id) {
                Logger.log("provider[\(provider.id)]: unexpectedly empty — injecting tamper signal")
                out.append(RiskSignal(
                    id: "signalCollectionFailed",
                    category: "tampering",
                    score: 80,
                    evidence: ["provider": provider.id, "reason": "previously_active_now_empty"]
                ))
            }
        }

        lock.withLock { activeProviderIDs.formUnion(newlyActive) }

        return out
    }

    func serverSignals(snapshot: RiskSnapshot) -> ServerSignals? {
        let current = lock.withLock { providers }

        var merged: ServerSignals?
        for provider in current {
            guard let s = provider.serverSignals(snapshot: snapshot) else { continue }
            if merged == nil { merged = s }
            else { merged = merged.map { merge($0, s) } ?? s }
        }
        if merged != nil {
            Logger.log("provider.serverSignals: merged")
        }
        return merged
    }

    /// 带超时和崩溃隔离地收集 provider 信号
    /// - 主线程调用时：直接同步执行，避免 DisplayMuxProvider/AudioRouteProvider 等内部 main.sync 导致死锁
    ///   （主线程 wait 时无法处理 main queue，后台 main.sync 会永久阻塞）
    /// - 非主线程调用时：async 到后台执行，主线程 wait 不会阻塞 main queue
    private func collectWithTimeout(provider: RiskSignalProvider, snapshot: RiskSnapshot) -> [RiskSignal] {
        if Thread.isMainThread {
            return autoreleasepool { provider.signals(snapshot: snapshot) }
        }

        let semaphore = DispatchSemaphore(value: 0)
        // Use a lock-protected box to avoid data race between background write
        // and calling thread read at the exact timeout boundary.
        let resultLock = UnfairLock()
        var result: [RiskSignal] = []

        DispatchQueue.global(qos: .userInitiated).async {
            let collected: [RiskSignal] = autoreleasepool {
                provider.signals(snapshot: snapshot)
            }
            resultLock.withLock { result = collected }
            semaphore.signal()
        }

        let timeout = DispatchTime.now() + Self.providerTimeoutSeconds
        if semaphore.wait(timeout: timeout) == .timedOut {
            Logger.log("provider[\(provider.id)]: timed out after \(Self.providerTimeoutSeconds)s")
            lock.withLock { consecutiveFailures[provider.id, default: 0] += 1 }
            return []
        }

        return resultLock.withLock { result }
    }

    private func merge(_ a: ServerSignals, _ b: ServerSignals) -> ServerSignals {
        ServerSignals(
            publicIP: b.publicIP ?? a.publicIP,
            asn: b.asn ?? a.asn,
            asOrg: b.asOrg ?? a.asOrg,
            isDatacenter: b.isDatacenter ?? a.isDatacenter,
            ipDeviceAgg: b.ipDeviceAgg ?? a.ipDeviceAgg,
            ipAccountAgg: b.ipAccountAgg ?? a.ipAccountAgg,
            geoCountry: b.geoCountry ?? a.geoCountry,
            geoRegion: b.geoRegion ?? a.geoRegion,
            riskTags: (b.riskTags ?? a.riskTags)
        )
    }
}
