import Foundation

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

    private let lock = NSLock()
    private var providers: [RiskSignalProvider] = []
    private(set) var isSealed = false
    private var sealedProviderTypes: [String: ObjectIdentifier] = [:]
    private var activeProviderIDs: Set<String> = []
    private(set) var tamperedUnregisterAttempts: Int = 0

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
    ]

    func seal() {
        lock.lock()
        defer { lock.unlock() }
        isSealed = true
        for provider in providers {
            sealedProviderTypes[provider.id] = ObjectIdentifier(type(of: provider))
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

        for provider in current {
            let collected: [RiskSignal] = autoreleasepool {
                provider.signals(snapshot: snapshot)
            }

            if !collected.isEmpty {
                newlyActive.insert(provider.id)
                Logger.log("provider[\(provider.id)]: signals=\(collected.count)")
                for s in collected where s.score > 0 {
                    let keys = s.evidence.keys.sorted().joined(separator: ",")
                    Logger.log("provider.signal: provider=\(provider.id) category=\(s.category) id=\(s.id) score=\(s.score) evidenceKeys=\(keys)")
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
