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

    func register(_ provider: RiskSignalProvider) {
        lock.lock()
        defer { lock.unlock() }
        providers.removeAll { $0.id == provider.id }
        providers.append(provider)
    }

    func unregister(id: String) {
        lock.lock()
        defer { lock.unlock() }
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
        lock.unlock()

        var out: [RiskSignal] = []
        for provider in current {
            let signals = provider.signals(snapshot: snapshot)
            if !signals.isEmpty {
                Logger.log("provider[\(provider.id)]: signals=\(signals.count)")
                for s in signals where s.score > 0 {
                    let keys = s.evidence.keys.sorted().joined(separator: ",")
                    Logger.log("provider.signal: provider=\(provider.id) category=\(s.category) id=\(s.id) score=\(s.score) evidenceKeys=\(keys)")
                }
            }
            out.append(contentsOf: signals)
        }
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
