import Foundation

struct MotionSample: Sendable {
    var timestamp: TimeInterval
    var energy: Double
}

enum BehaviorCoupling {
    static func touchMotionCorrelation(actionTimestamps: [TimeInterval], motion: [MotionSample]) -> Double? {
        guard actionTimestamps.count >= 6 else { return nil }
        guard motion.count >= 40 else { return nil }

        let start = max(actionTimestamps.min() ?? 0, motion.first?.timestamp ?? 0)
        let end = min(actionTimestamps.max() ?? 0, motion.last?.timestamp ?? 0)
        let span = end - start
        guard span >= 4 else { return nil }

        let bucketCount = Int(min(60, max(4, floor(span))))
        guard bucketCount >= 4 else { return nil }

        var touchBuckets = [Double](repeating: 0, count: bucketCount)
        var motionSum = [Double](repeating: 0, count: bucketCount)
        var motionCount = [Double](repeating: 0, count: bucketCount)

        func idx(_ t: TimeInterval) -> Int? {
            let p = (t - start) / span
            if p < 0 || p > 1 { return nil }
            let i = Int(floor(p * Double(bucketCount)))
            return min(max(i, 0), bucketCount - 1)
        }

        for t in actionTimestamps {
            guard let i = idx(t) else { continue }
            touchBuckets[i] += 1
        }

        for s in motion {
            guard let i = idx(s.timestamp) else { continue }
            motionSum[i] += s.energy
            motionCount[i] += 1
        }

        var motionBuckets = [Double](repeating: 0, count: bucketCount)
        for i in 0..<bucketCount {
            if motionCount[i] > 0 { motionBuckets[i] = motionSum[i] / motionCount[i] }
        }

        return pearson(x: touchBuckets, y: motionBuckets)
    }

    private static func pearson(x: [Double], y: [Double]) -> Double? {
        guard x.count == y.count, x.count >= 4 else { return nil }
        let n = Double(x.count)
        let meanX = x.reduce(0, +) / n
        let meanY = y.reduce(0, +) / n
        var cov = 0.0
        var varX = 0.0
        var varY = 0.0
        for i in 0..<x.count {
            let dx = x[i] - meanX
            let dy = y[i] - meanY
            cov += dx * dy
            varX += dx * dx
            varY += dy * dy
        }
        guard varX > 0, varY > 0 else { return nil }
        return cov / sqrt(varX * varY)
    }
}

