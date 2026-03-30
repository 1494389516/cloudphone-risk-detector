import CRiskCore
import Darwin
import Foundation

/// Cross-checks `posix_spawn` / `posix_spawnp` resolution across dyld default, explicit
/// `libsystem_c` handle, and export-trie discovery, then layers arm64 prologue heuristics.
struct ProcessSpawnIfaceConsistencyDetector {
    func asSignals() -> [RiskSignal] {
        var raw = cprisk_spawn_iface_probe_result_t()
        guard cprisk_spawn_iface_probe(&raw) == 0 else { return [] }

        let pathBits = UInt32(raw.flags)
        var prologueMarks: [String] = []
        #if arch(arm64) || arch(arm64e)
        if LibcPrologueGuard.isInlineHooked(symbol: "posix_spawn") {
            prologueMarks.append("s")
        }
        if LibcPrologueGuard.isInlineHooked(symbol: "posix_spawnp") {
            prologueMarks.append("p")
        }
        #endif

        guard pathBits != 0 || !prologueMarks.isEmpty else { return [] }

        let score: Double = pathBits != 0 ? 88 : 72
        var evidence: [String: String] = [
            "f": String(pathBits, radix: 16),
            "ds": String(raw.addr_rtld_default_spawn, radix: 16),
            "es": String(raw.addr_dlopen_libc_spawn, radix: 16),
            "ts": String(raw.addr_export_trie_spawn, radix: 16),
            "dp": String(raw.addr_rtld_default_spawnp, radix: 16),
            "ep": String(raw.addr_dlopen_libc_spawnp, radix: 16),
            "tp": String(raw.addr_export_trie_spawnp, radix: 16),
        ]
        if !prologueMarks.isEmpty {
            evidence["pr"] = prologueMarks.joined(separator: ",")
        }

        return [
            RiskSignal(
                id: SignalID.ifaceSpawnPathDivergence,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: score,
                evidence: evidence,
                state: .tampered,
                layer: 2,
                weightHint: 90
            ),
        ]
    }
}
