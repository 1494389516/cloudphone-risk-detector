import Foundation

struct MutationPlanner: Sendable {
    private let strategy: MutationStrategy?
    private let scopeSeed: UInt64

    init(strategy: MutationStrategy?, scope: String, deviceID: String) {
        self.strategy = strategy
        let rawSeed = (strategy?.seed ?? "default") + "|" + scope + "|" + deviceID
        self.scopeSeed = Self.fnv1a64(rawSeed)
    }

    func jitter(base: Double, maxBps: Int) -> Double {
        guard maxBps > 0 else { return base }
        let range = Double(maxBps) / 10_000.0
        let unit = unitRandom(offset: 0xA11CE)
        let factor = 1.0 + ((unit * 2.0 - 1.0) * range)
        return max(0, base * factor)
    }

    func softConfidenceGate(default value: Double) -> Double {
        let bps = strategy?.thresholdJitterBps ?? 0
        guard bps > 0 else { return value }
        return min(0.8, max(0.1, jitter(base: value, maxBps: bps)))
    }

    func tamperedBase(default value: Double) -> Double {
        let bps = strategy?.scoreJitterBps ?? 0
        guard bps > 0 else { return value }
        return min(90, max(20, jitter(base: value, maxBps: bps)))
    }

    func maybeShuffle<T>(_ values: [T], salt: String) -> [T] {
        guard strategy?.shuffleChecks == true, values.count > 1 else { return values }
        var out = values
        var rng = LCG(seed: scopeSeed ^ Self.fnv1a64(salt))
        for i in stride(from: out.count - 1, through: 1, by: -1) {
            let j = Int(rng.next() % UInt64(i + 1))
            if i != j {
                out.swapAt(i, j)
            }
        }
        return out
    }

    private func unitRandom(offset: UInt64) -> Double {
        let value = splitmix64(scopeSeed ^ offset)
        return Double(value) / Double(UInt64.max)
    }

    private static func fnv1a64(_ text: String) -> UInt64 {
        var hash: UInt64 = 0xcbf29ce484222325
        for b in text.utf8 {
            hash ^= UInt64(b)
            hash &*= 0x100000001b3
        }
        return hash
    }
}

private struct LCG {
    private var state: UInt64
    init(seed: UInt64) { state = seed == 0 ? 0x9e3779b97f4a7c15 : seed }

    mutating func next() -> UInt64 {
        state = 6364136223846793005 &* state &+ 1442695040888963407
        return state
    }
}

private func splitmix64(_ x: UInt64) -> UInt64 {
    var z = x &+ 0x9e3779b97f4a7c15
    z = (z ^ (z >> 30)) &* 0xbf58476d1ce4e5b9
    z = (z ^ (z >> 27)) &* 0x94d049bb133111eb
    return z ^ (z >> 31)
}
