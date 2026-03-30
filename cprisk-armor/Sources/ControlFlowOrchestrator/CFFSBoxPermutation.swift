import Foundation

/// Build-time 256-byte S-box as a **bijective** permutation of `0...255`, keyed by `seed`.
/// Intended for CFF / white-box style tooling: Fisher–Yates shuffle with deterministic SplitMix64.
/// Runtime consumers (e.g. `cprisk_cff`) must agree on the same construction if they adopt this material.
///
/// **Cross-language alignment:** the app’s canonical seed is `CPRISK_CFF_SPN_CANONICAL_SEED_U64` /
/// `CFFSBoxMaterial.canonicalSeed` (FNV-1a label XOR registry mix). Armor `ControlFlowOrchestrator`
/// uses a separate `buildSeed` for per-function plans; only this permutation **algorithm** must match.
public enum CFFSBoxPermutation256 {
    /// Generate a permutation of all byte values using `seed` (0 is mapped to 1 for the PRNG state).
    public static func generate(seed: UInt64) -> [UInt8] {
        var a = Array(0..<256).map { UInt8(truncatingIfNeeded: $0) }
        var g = CFFSplitMix64(seed: seed == 0 ? 1 : seed)
        var i = 255
        while i > 0 {
            let j = Int(g.next() % UInt64(i + 1))
            a.swapAt(i, j)
            i -= 1
        }
        return a
    }

    /// True iff `box` is a permutation of 0...255 (bijection on bytes).
    public static func isBijection(_ box: [UInt8]) -> Bool {
        guard box.count == 256 else { return false }
        var seen = [Bool](repeating: false, count: 256)
        for b in box {
            let i = Int(b)
            if seen[i] { return false }
            seen[i] = true
        }
        return true
    }
}

/// Local SplitMix64 (same family as `VMProtectorSplitMix64` / other armor PRNGs).
private struct CFFSplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed == 0 ? 1 : seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }
}
