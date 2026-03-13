import Foundation

// MARK: - Signal Provider System
//
// Extension point for injecting custom risk signals into the evaluation pipeline.
//
// Built-in Providers (auto-registered by CPRiskKit.start()):
//   server_aggregate   → IP/ASN/datacenter signals from server injection
//   device_hardware    → hw.machine, simulator detection
//   device_age         → old model heuristic risk scoring
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

final class RiskSignalProviderRegistry {
    static let shared = RiskSignalProviderRegistry()
    private init() {}

    /// 单个 Provider 执行超时时间（秒）
    private static let providerTimeoutSeconds: Double = 3.0
    /// 连续失败阈值，超过后跳过该 provider
    private static let maxConsecutiveFailures = 3

    private let lock = NSLock()
    private var providers: [RiskSignalProvider] = []
    private(set) var isSealed = false
    private var sealedProviderTypes: [String: ObjectIdentifier] = [:]
    private var sealedProviderInstances: [String: ObjectIdentifier] = [:]
    private var instanceReplacedProviderIDs: Set<String> = []
    private var activeProviderIDs: Set<String> = []
    private(set) var tamperedUnregisterAttempts: Int = 0
    private var consecutiveFailures: [String: Int] = [:]

    private static let internalProviderIDs: Set<String> = [
        "server_aggregate",
        "device_hardware",
        "device_age",
        "vphone_hardware",
        "layered_consistency",
        "mount_point",
        "drm_capability",
        "battery_entropy",
        "time_pattern",
        "anti_tampering",
        "app_attest",
    ]

    func seal() {
        lock.lock()
        defer { lock.unlock() }
        isSealed = true
        for provider in providers {
            sealedProviderTypes[provider.id] = ObjectIdentifier(type(of: provider))
            if Self.internalProviderIDs.contains(provider.id) {
                sealedProviderInstances[provider.id] = ObjectIdentifier(provider)
            }
        }
    }

    func register(_ provider: RiskSignalProvider) {
        lock.lock()
        defer { lock.unlock() }
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

    func unregister(id: String) {
        lock.lock()
        defer { lock.unlock() }
        if isSealed, Self.internalProviderIDs.contains(id) {
            tamperedUnregisterAttempts += 1
            Logger.log("provider.unregister rejected (sealed internal): id=\(id) attempts=\(tamperedUnregisterAttempts)")
            return
        }
        providers.removeAll { $0.id == id }
    }

    func listIDs() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return providers.map(\.id)
    }

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        lock.lock()
        let current = providers
        let knownActive = activeProviderIDs
        let unregisterAttempts = tamperedUnregisterAttempts
        let replacedIDs = instanceReplacedProviderIDs
        lock.unlock()

        var out: [RiskSignal] = []
        var newlyActive: Set<String> = []

        if unregisterAttempts > 0 {
            out.append(RiskSignal(
                id: "provider_tamper_attempt",
                category: "anti_tamper",
                score: 0,
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
                category: "anti_tamper",
                score: 0,
                evidence: ["providers": ids],
                state: .tampered,
                layer: 2,
                weightHint: 85
            ))
        }

        for provider in current {
            // 跳过连续失败过多的 provider
            lock.lock()
            let failures = consecutiveFailures[provider.id] ?? 0
            lock.unlock()
            if failures >= Self.maxConsecutiveFailures {
                Logger.log("provider[\(provider.id)]: skipped (consecutive failures=\(failures))")
                continue
            }

            let collected: [RiskSignal] = collectWithTimeout(provider: provider, snapshot: snapshot)

            if !collected.isEmpty {
                newlyActive.insert(provider.id)
                lock.lock()
                consecutiveFailures[provider.id] = 0
                lock.unlock()
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

        lock.lock()
        activeProviderIDs.formUnion(newlyActive)
        lock.unlock()

        return out
    }

    func serverSignals(snapshot: RiskSnapshot) -> ServerSignals? {
        lock.lock()
        let current = providers
        lock.unlock()

        var merged: ServerSignals?
        for provider in current {
            guard let s = provider.serverSignals(snapshot: snapshot) else { continue }
            if merged == nil { merged = s }
            else { merged = merge(merged!, s) }
        }
        if merged != nil {
            Logger.log("provider.serverSignals: merged")
        }
        return merged
    }

    /// 带超时和崩溃隔离地收集 provider 信号
    private func collectWithTimeout(provider: RiskSignalProvider, snapshot: RiskSnapshot) -> [RiskSignal] {
        let semaphore = DispatchSemaphore(value: 0)
        var result: [RiskSignal] = []

        DispatchQueue.global(qos: .userInitiated).async {
            let collected: [RiskSignal] = autoreleasepool {
                provider.signals(snapshot: snapshot)
            }
            result = collected
            semaphore.signal()
        }

        let timeout = DispatchTime.now() + Self.providerTimeoutSeconds
        if semaphore.wait(timeout: timeout) == .timedOut {
            Logger.log("provider[\(provider.id)]: timed out after \(Self.providerTimeoutSeconds)s")
            lock.lock()
            consecutiveFailures[provider.id, default: 0] += 1
            lock.unlock()
            return []
        }

        return result
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
