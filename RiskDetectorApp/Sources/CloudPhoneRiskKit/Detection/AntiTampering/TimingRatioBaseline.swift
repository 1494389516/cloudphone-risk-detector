import Foundation

struct TimingRatioBaseline {
    struct Evaluation {
        let medianRatio: Double
        let p95Ratio: Double
        let isAnomalous: Bool
    }

    private struct TimingStats {
        let median: UInt64
        let p95: UInt64
    }

    static let defaultSampleCount = 30
    static let defaultRatioThreshold = 15.0

    static func evaluate(
        getpidSamples: [UInt64],
        statSamples: [UInt64],
        ratioThreshold: Double = defaultRatioThreshold
    ) -> Evaluation? {
        let getpidStats = computeStats(getpidSamples)
        let statStats = computeStats(statSamples)

        guard getpidStats.median > 0 else { return nil }

        let medianRatio = Double(statStats.median) / Double(getpidStats.median)
        let p95Ratio = getpidStats.p95 > 0
            ? Double(statStats.p95) / Double(getpidStats.p95)
            : 0.0

        return Evaluation(
            medianRatio: medianRatio,
            p95Ratio: p95Ratio,
            isAnomalous: medianRatio > ratioThreshold || p95Ratio > ratioThreshold
        )
    }

    static func isAnomalous(
        getpidSamples: [UInt64],
        statSamples: [UInt64],
        ratioThreshold: Double = defaultRatioThreshold
    ) -> Bool {
        evaluate(
            getpidSamples: getpidSamples,
            statSamples: statSamples,
            ratioThreshold: ratioThreshold
        )?.isAnomalous ?? false
    }

    private static func computeStats(_ samples: [UInt64]) -> TimingStats {
        let sorted = samples.sorted()
        let count = sorted.count
        guard count > 0 else {
            return TimingStats(median: 0, p95: 0)
        }

        let median = sorted[count / 2]
        let p95Index = min(Int(Double(count) * 0.95), count - 1)
        let p95 = sorted[p95Index]
        return TimingStats(median: median, p95: p95)
    }
}
