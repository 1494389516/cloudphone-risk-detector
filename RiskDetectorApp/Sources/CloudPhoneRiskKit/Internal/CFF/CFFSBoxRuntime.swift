import CRiskCore
import Foundation

// MARK: - SplitMix64 + Fisher–Yates (must match cprisk-armor `CFFSBoxPermutation256` and CRiskCore `cprisk_cff`)

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

private enum CFFSBoxPermutation256 {
    static func generate(seed: UInt64) -> [UInt8] {
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

    static func isBijection(_ box: [UInt8]) -> Bool {
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

/// Runtime Feistel SPN forward S-box (256-byte bijection), shared by `CFFStateCodec`,
/// `CFFOpaquePredicates`, and CRiskCore `cprisk_cff` (same SplitMix64 + Fisher–Yates).
internal enum CFFSBoxRuntime {
    private static let lock = NSLock()
    private static var cachedForward: [UInt8]?

    /// Lazily materialize; first access pins the table for the process lifetime.
    static func forwardTable() -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        if let cachedForward {
            return cachedForward
        }
        var runtimeForward = [UInt8](repeating: 0, count: 256)
        let rc = runtimeForward.withUnsafeMutableBufferPointer { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return -1 }
            return Int32(cprisk_cff_spn_sbox_copy_forward(base))
        }
        if rc == 0, CFFSBoxPermutation256.isBijection(runtimeForward) {
            cachedForward = runtimeForward
            return runtimeForward
        }

        let fallback = CFFSBoxPermutation256.generate(seed: CFFSBoxMaterial.canonicalSeed)
        precondition(CFFSBoxPermutation256.isBijection(fallback), "CFF SPN S-box must be a bijection")
        cachedForward = fallback
        return fallback
    }

    @inline(__always)
    static func spnSboxByte(_ idx: UInt8) -> UInt8 {
        let table = forwardTable()
        return table[Int(idx)]
    }
}
