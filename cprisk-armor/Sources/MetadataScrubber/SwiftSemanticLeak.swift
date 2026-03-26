import Foundation
import MachOKit

/// Curated substring tokens (always compared lowercased) for Swift / SDK–specific semantic leaks.
///
/// **Design:** Prefer multi-character distinctive fragments (`riskdetection`, `isvip`, `honeypot`) over
/// very short tokens (`vip` alone) to limit false positives in unrelated literals.
/// **ABI:** Call sites only rewrite **C-string body bytes** in place (length preserved); no pointer / layout edits.
///
/// **Build / output verification:** Prefer lowering Swift reflection emission first (Xcode:
/// `SWIFT_REFLECTION_METADATA_LEVEL=minimal` on the app + kit targets; SwiftPM Release opt-in:
/// `CPRISK_ENABLE_SWIFT_METADATA_CONVERGENCE=1` in `Package.swift`). Then run Pass 2 with
/// `--swift-semantic-report` on the shipped Mach-O and compare reported `__TEXT.__cstring` hits
/// (and optional `strings` greps for catalog needles) against a prior build — fewer hits implies
/// less literal surface, independent of Pass 2 scrubbing.
enum SwiftSemanticLeakCatalog {
    /// Lowercase ASCII needles matched via `String.contains` after lowercasing the haystack.
    static let utf8Substrings: [String] = [
        "riskdetection", "detectionengine", "riskengine", "riskdetector", "riskreport",
        "isvip", "vipstatus", "vipmember", "vip_level", "vipflag",
        "antitamper", "antifraud", "honeypot", "cloudphonerisk",
        "runtimeintegrity", "swiftruntimeintegrity",
        "criskcore", "cprisk",
    ]

    /// Returns true if `s` should be treated as a semantic-leak string for scrub/report.
    static func matchesUTF8(_ s: String) -> Bool {
        let lower = s.lowercased()
        for needle in utf8Substrings where lower.contains(needle) {
            return true
        }
        return false
    }

    /// Raw-byte fallback when UTF-8 decoding fails (ASCII case-insensitive).
    static func rawSliceMatches(_ slice: Data, length: Int) -> Bool {
        for needle in utf8Substrings {
            let kw = Array(needle.utf8)
            guard length >= kw.count else { continue }
            for i in 0...(length - kw.count) {
                var match = true
                for j in 0..<kw.count {
                    let b = slice[i + j]
                    let kb = kw[j]
                    if b == kb { continue }
                    if (65...90).contains(b), b + 32 == kb { continue }
                    if (97...122).contains(b), b - 32 == kb { continue }
                    match = false
                    break
                }
                if match { return true }
            }
        }
        if length > 5 {
            let riskBytes = Array("risk".utf8)
            for i in 0...(length - riskBytes.count) {
                var match = true
                for j in 0..<riskBytes.count {
                    let b = slice[i + j]
                    let kb = riskBytes[j]
                    if b == kb { continue }
                    if (65...90).contains(b), b + 32 == kb { continue }
                    if (97...122).contains(b), b - 32 == kb { continue }
                    match = false
                    break
                }
                if match { return true }
            }
        }
        return false
    }

    /// Fake Swift-mangled lines + nulls + deterministic padding to bloat binary search noise.
    static func decoyPayload(seed: UInt64) -> Data {
        var rng = SeededSplitMix64(seed: seed ^ 0x51FF_1C5E)
        let lines: [String] = [
            "$s21RiskEngineDecoyStubC15isVipProxyFieldSSvg",
            "$s18DetectionEngineBogusC03runC0yyF",
            "$s15HoneypotModule0C0C12fakeRiskSignySSF",
            "_$s12CloudPhoneRisk0C13DetectorStubVwCP",
        ]
        var d = Data()
        for line in lines {
            d.append(contentsOf: line.utf8)
            d.append(0)
        }
        let pad = 192
        for _ in 0..<pad {
            d.append(UInt8(truncatingIfNeeded: rng.nextUInt64()))
        }
        return d
    }

    private struct SeededSplitMix64 {
        private var state: UInt64

        init(seed: UInt64) {
            self.state = seed == 0 ? 0xDEAD_BEEF_CAFE_0001 : seed
        }

        mutating func nextUInt64() -> UInt64 {
            state &+= 0x9E3779B97F4A7C15
            var z = state
            z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
            z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
            return z ^ (z >> 31)
        }
    }
}
