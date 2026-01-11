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

    private let lock = NSLock()
    private let defaults: UserDefaults
    private let key = "cloudphone_risk_history_v1"
    private let maxEvents = 200
    private let maxAgeSeconds: TimeInterval = 7 * 24 * 3600

    public init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    public func append(_ event: RiskHistoryEvent) {
        lock.lock()
        defer { lock.unlock() }
        var events = loadLocked()
        events.append(event)
        events = pruneLocked(events)
        saveLocked(events)
    }

    public func pattern(now: TimeInterval = Date().timeIntervalSince1970) -> TimePattern {
        lock.lock()
        let events = loadLocked()
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

    private func loadLocked() -> [RiskHistoryEvent] {
        guard let data = defaults.data(forKey: key) else { return [] }
        return (try? JSONDecoder().decode([RiskHistoryEvent].self, from: data)) ?? []
    }

    private func saveLocked(_ events: [RiskHistoryEvent]) {
        if let data = try? JSONEncoder().encode(events) {
            defaults.set(data, forKey: key)
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
}
