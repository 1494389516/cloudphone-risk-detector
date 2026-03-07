import Foundation

public struct RiskHistoryEvent: Codable, Sendable {
    var t: TimeInterval
    var score: Double
    var isHighRisk: Bool
    var summary: String
}

public struct TimePattern: Codable, Sendable {
    public var events24h: Int
    public var uniqueHours24h: Int
    public var nightRatio24h: Double?
    public var averageIntervalSeconds24h: Double?
}

public final class RiskHistoryStore {
    public static let shared = RiskHistoryStore()

    private struct StoredEnvelope: Codable {
        var schemaVersion: Int
        var events: [RiskHistoryEvent]
        var latestTimestamp: Double
        var sequence: UInt64
    }

    private struct LoadedState {
        var events: [RiskHistoryEvent]
        var freshness: FreshnessState
    }

    private let lock = NSLock()
    private let defaults: UserDefaults
    private let key = "cloudphone_risk_history_v1"
    private let hmacKey = "cloudphone_risk_history_v1_hmac"
    private let hmacPurpose = "risk_history"
    private let freshnessAnchor = FreshnessAnchor(account: "risk_history_v2_freshness")
    private let maxEvents = 200
    private let maxAgeSeconds: TimeInterval = 7 * 24 * 3600

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public func append(_ event: RiskHistoryEvent) {
        lock.lock()
        defer { lock.unlock() }

        var state = loadStateLocked()
        state.events.append(event)
        state.events = pruneLocked(state.events)
        saveLocked(state)
    }

    public func pattern(now: TimeInterval = Date().timeIntervalSince1970) -> TimePattern {
        lock.lock()
        let events = loadStateLocked().events
        lock.unlock()

        let windowStart = now - 24 * 3600
        let recent = events.filter { $0.t >= windowStart && $0.t <= now }.sorted { $0.t < $1.t }
        let events24h = recent.count

        var hours = Set<Int>()
        var nightCount = 0
        var intervals: [Double] = []

        let cal = Calendar(identifier: .gregorian)
        for e in recent {
            let date = Date(timeIntervalSince1970: e.t)
            let hour = cal.component(.hour, from: date)
            hours.insert(hour)
            if hour >= 0 && hour <= 5 { nightCount += 1 }
        }

        if recent.count >= 2 {
            for (a, b) in zip(recent.dropFirst(), recent) {
                let dt = a.t - b.t
                if dt > 0 { intervals.append(dt) }
            }
        }

        let nightRatio = events24h > 0 ? (Double(nightCount) / Double(events24h)) : nil
        let avgInterval = intervals.isEmpty ? nil : (intervals.reduce(0, +) / Double(intervals.count))

        return TimePattern(
            events24h: events24h,
            uniqueHours24h: hours.count,
            nightRatio24h: nightRatio,
            averageIntervalSeconds24h: avgInterval
        )
    }

    private func loadStateLocked() -> LoadedState {
        let anchor = freshnessAnchor.read() ?? .zero
        guard let stored = defaults.data(forKey: key) else {
            return LoadedState(events: [], freshness: anchor)
        }
        guard let signature = defaults.data(forKey: hmacKey),
              StorageIntegrityGuard.verify(stored, signature: signature, purpose: hmacPurpose) else {
            clearPersistedDataLocked(resetAnchor: false)
            return LoadedState(events: [], freshness: anchor)
        }
        #if DEBUG
        let data: Data
        if let decrypted = try? PayloadCrypto.decrypt(stored) {
            data = decrypted
        } else {
            data = stored
        }
        #else
        guard let data = try? PayloadCrypto.decrypt(stored) else {
            Logger.log("RiskHistoryStore: decrypt failed, clearing cache in release build")
            clearPersistedDataLocked(resetAnchor: false)
            return LoadedState(events: [], freshness: anchor)
        }
        #endif

        let decodedState: LoadedState?
        if let envelope = try? JSONDecoder().decode(StoredEnvelope.self, from: data) {
            decodedState = LoadedState(
                events: envelope.events,
                freshness: FreshnessState(
                    latestTimestamp: envelope.latestTimestamp,
                    sequence: envelope.sequence
                )
            )
        } else if let legacyEvents = try? JSONDecoder().decode([RiskHistoryEvent].self, from: data) {
            decodedState = LoadedState(
                events: legacyEvents,
                freshness: FreshnessState(
                    latestTimestamp: legacyEvents.map(\.t).max() ?? 0,
                    sequence: 0
                )
            )
        } else {
            clearPersistedDataLocked(resetAnchor: false)
            return LoadedState(events: [], freshness: anchor)
        }

        var state = decodedState ?? LoadedState(events: [], freshness: anchor)
        state.events = pruneLocked(state.events)

        // 防时钟回拨/回放攻击：最新事件时间戳不允许超过当前时间 60s
        let wallNow = Date().timeIntervalSince1970
        if let newest = state.events.max(by: { $0.t < $1.t }), newest.t > wallNow + 60 {
            Logger.log("RiskHistoryStore: future timestamp detected (newest=\(newest.t) now=\(wallNow)), possible replay/clock attack, clearing cache")
            clearPersistedDataLocked(resetAnchor: false)
            return LoadedState(events: [], freshness: anchor)
        }

        if state.freshness.sequence < anchor.sequence || state.freshness.latestTimestamp < anchor.latestTimestamp {
            Logger.log("RiskHistoryStore: freshness rollback detected")
            clearPersistedDataLocked(resetAnchor: false)
            #if DEBUG
            return LoadedState(events: [], freshness: anchor)
            #else
            return LoadedState(events: [], freshness: anchor)
            #endif
        }

        if state.freshness.sequence > anchor.sequence || state.freshness.latestTimestamp > anchor.latestTimestamp {
            _ = freshnessAnchor.write(state.freshness)
        }

        return LoadedState(events: state.events, freshness: maxFreshness(anchor, state.freshness))
    }

    private func saveLocked(_ state: LoadedState) {
        if state.events.isEmpty {
            clearPersistedDataLocked(resetAnchor: true)
            return
        }

        let anchor = freshnessAnchor.read() ?? .zero
        let maxEventTimestamp = state.events.map(\.t).max() ?? 0
        let freshness = FreshnessState(
            latestTimestamp: max(maxEventTimestamp, max(anchor.latestTimestamp, state.freshness.latestTimestamp)),
            sequence: max(anchor.sequence, state.freshness.sequence) + 1
        )
        let envelope = StoredEnvelope(
            schemaVersion: 2,
            events: state.events,
            latestTimestamp: freshness.latestTimestamp,
            sequence: freshness.sequence
        )
        guard let encoded = try? JSONEncoder().encode(envelope) else { return }
        #if DEBUG
        let stored = (try? PayloadCrypto.encrypt(encoded)) ?? encoded
        #else
        guard let stored = try? PayloadCrypto.encrypt(encoded) else {
            Logger.log("RiskHistoryStore: encrypt failed, skipping save in release build")
            return
        }
        #endif
        defaults.set(stored, forKey: key)
        defaults.set(StorageIntegrityGuard.sign(stored, purpose: hmacPurpose), forKey: hmacKey)

        guard freshnessAnchor.write(freshness) else {
            Logger.log("RiskHistoryStore: failed to update freshness anchor")
            if BuildConfig.isRelease {
                clearPersistedDataLocked(resetAnchor: false)
            }
            return
        }
    }

    private func pruneLocked(_ events: [RiskHistoryEvent]) -> [RiskHistoryEvent] {
        let now = Date().timeIntervalSince1970
        let minT = now - maxAgeSeconds
        var out = events.filter { $0.t >= minT }
        if out.count > maxEvents {
            out = Array(out.suffix(maxEvents))
        }
        return out
    }

    private func clearPersistedDataLocked(resetAnchor: Bool) {
        defaults.removeObject(forKey: key)
        defaults.removeObject(forKey: hmacKey)
        if resetAnchor {
            freshnessAnchor.remove()
        }
    }

    private func maxFreshness(_ lhs: FreshnessState, _ rhs: FreshnessState) -> FreshnessState {
        FreshnessState(
            latestTimestamp: max(lhs.latestTimestamp, rhs.latestTimestamp),
            sequence: max(lhs.sequence, rhs.sequence)
        )
    }
}
