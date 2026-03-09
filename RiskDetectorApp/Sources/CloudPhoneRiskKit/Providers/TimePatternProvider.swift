import Foundation

final class TimePatternProvider: RiskSignalProvider {
    static let shared = TimePatternProvider()
    private init() {}

    let id = "time_pattern"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let pattern = RiskHistoryStore.shared.pattern()
        var out: [RiskSignal] = []

        if pattern.events24h >= 500 {
            out.append(RiskSignal(id: SignalID.highVolume24h, category: SignalCategory.time, score: 15, evidence: ["events24h": "\(pattern.events24h)"]))
        } else if pattern.events24h >= 200 {
            out.append(RiskSignal(id: SignalID.mediumVolume24h, category: SignalCategory.time, score: 8, evidence: ["events24h": "\(pattern.events24h)"]))
        }

        if pattern.uniqueHours24h >= 18, pattern.events24h >= 80 {
            out.append(RiskSignal(id: SignalID.wideHourCoverage, category: SignalCategory.time, score: 12, evidence: ["uniqueHours24h": "\(pattern.uniqueHours24h)"]))
        }

        if let night = pattern.nightRatio24h, night > 0.4, pattern.events24h >= 80 {
            out.append(RiskSignal(id: SignalID.nightActivityHigh, category: SignalCategory.time, score: 10, evidence: ["nightRatio24h": "\(night)"]))
        }

        if let avg = pattern.averageIntervalSeconds24h, avg < 8, pattern.events24h >= 80 {
            out.append(RiskSignal(id: SignalID.highFrequency, category: SignalCategory.time, score: 8, evidence: ["avgIntervalSec": "\(avg)"]))
        }

        _ = snapshot.deviceID
        return out
    }
}

