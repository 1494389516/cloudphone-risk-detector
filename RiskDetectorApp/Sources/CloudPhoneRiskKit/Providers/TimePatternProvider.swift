import Foundation

final class TimePatternProvider: RiskSignalProvider {
    static let shared = TimePatternProvider()
    private init() {}

    let id = "time_pattern"
    private static let lastClockOffsetKey = "cprk_time_pattern.last_clock_offset"
    private static let lastBootTimeKey = "cprk_time_pattern.last_boot_time"
    private static let systemTimeJumpThreshold: TimeInterval = 300
    private static let bootTimeRollbackThreshold: TimeInterval = 120
    private static let installDateFutureThreshold: TimeInterval = 300
    private static let installDateMaxAgeDays: Double = 3650

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

        out.append(contentsOf: timelineSignals(snapshot: snapshot))
        return out
    }

    private func timelineSignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let now = Date().timeIntervalSince1970
        let bootTime = now - ProcessInfo.processInfo.systemUptime
        let defaults = UserDefaults.standard
        var out: [RiskSignal] = []

        if let previousOffset = defaults.object(forKey: Self.lastClockOffsetKey) as? Double {
            let delta = abs(bootTime - previousOffset)
            if delta >= Self.systemTimeJumpThreshold {
                out.append(
                    RiskSignal(
                        id: SignalID.systemTimeJump,
                        category: SignalCategory.time,
                        score: 0,
                        evidence: [
                            "current_offset": String(format: "%.0f", bootTime),
                            "previous_offset": String(format: "%.0f", previousOffset),
                            "delta_seconds": String(format: "%.0f", delta),
                        ],
                        state: .soft(confidence: 0.75),
                        layer: 2,
                        weightHint: 45
                    )
                )
            }
        }

        if let previousBootTime = defaults.object(forKey: Self.lastBootTimeKey) as? Double,
           bootTime + Self.bootTimeRollbackThreshold < previousBootTime {
            out.append(
                RiskSignal(
                    id: SignalID.bootTimeRollback,
                    category: SignalCategory.time,
                    score: 0,
                    evidence: [
                        "current_boot_time": String(format: "%.0f", bootTime),
                        "previous_boot_time": String(format: "%.0f", previousBootTime),
                        "delta_seconds": String(format: "%.0f", previousBootTime - bootTime),
                    ],
                    state: .soft(confidence: 0.8),
                    layer: 2,
                    weightHint: 50
                )
            )
        }

        if let installDate = BundleInfo.shared.installDate?.timeIntervalSince1970 {
            let ageDays = (now - installDate) / 86_400
            if installDate > now + Self.installDateFutureThreshold || ageDays > Self.installDateMaxAgeDays {
                out.append(
                    RiskSignal(
                        id: SignalID.installDateUnusual,
                        category: SignalCategory.time,
                        score: 0,
                        evidence: [
                            "install_date": String(format: "%.0f", installDate),
                            "age_days": String(format: "%.1f", ageDays),
                        ],
                        state: .soft(confidence: 0.72),
                        layer: 2,
                        weightHint: 40
                    )
                )
            }
        }

        defaults.set(bootTime, forKey: Self.lastClockOffsetKey)
        defaults.set(bootTime, forKey: Self.lastBootTimeKey)
        _ = snapshot.deviceID
        return out
    }
}
