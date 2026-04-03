import CRiskCore
import Foundation

// MARK: - Protocol

/// Implement this protocol and register it with `CPRiskKit.shared` to receive
/// hostile-environment signals for server-side risk assessment.
///
/// The SDK performs all detection on-device.  Without a server-side component,
/// a sufficiently motivated attacker can patch the on-device result.  Wiring
/// these signals to your backend provides a second verification layer that
/// cannot be bypassed purely through binary patching.
///
/// ## Usage
/// ```swift
/// class MyReporter: HostileEnvironmentReporter {
///     func reportHostileEnvironment(_ report: HostileEnvironmentReport) {
///         // POST report.jsonPayload to your risk backend
///     }
/// }
/// CPRiskKit.shared.hostileEnvironmentReporter = MyReporter()
/// ```
public protocol HostileEnvironmentReporter: AnyObject, Sendable {
    /// Called when C-layer detection identifies one or more hostile signals.
    /// May be called on any thread; implementations must be thread-safe.
    func reportHostileEnvironment(_ report: HostileEnvironmentReport)
}

// MARK: - Report model

public struct HostileEnvironmentReport: Sendable {

    /// Bitmask of `CPRISK_EMU_FLAG_*` constants from `cprisk_emulator_detect.h`.
    public let rawFlags: UInt32

    /// Weighted score (0–100) computed from the active flag bits.
    public let score: Int

    /// Human-readable list of active detection signals.
    public let activeSignals: [String]

    /// Whether the SDK considers this environment definitively hostile
    /// (score ≥ 25 or highest-confidence flags set).
    public let isHostile: Bool

    /// ISO-8601 timestamp of when the report was generated.
    public let timestamp: String

    /// A JSON-serialisable dictionary suitable for POSTing to a risk backend.
    public var jsonPayload: [String: Any] {
        [
            "raw_flags":      rawFlags,
            "score":          score,
            "signals":        activeSignals,
            "is_hostile":     isHostile,
            "timestamp":      timestamp,
            "sdk_version":    "cprisk.emulator.v1",
        ]
    }

    // MARK: Flag name mapping

    private static let flagNames: [(UInt32, String)] = [
        (0x001, "dyld_cache_absent"),
        (0x002, "low_vm_regions"),
        (0x004, "low_stack_addr"),
        (0x008, "ostype_not_darwin"),
        (0x010, "low_thread_count"),
        (0x020, "jvm_env_var"),
        (0x040, "timebase_flat"),
        (0x080, "cpu_clock_frozen"),
        (0x100, "watchdog_stuck"),
    ]

    static func signals(from flags: UInt32) -> [String] {
        flagNames.compactMap { (mask, name) in flags & mask != 0 ? name : nil }
    }
}

// MARK: - Bridge

/// Reads the current emulator flags from the C layer and dispatches a report
/// to the registered `HostileEnvironmentReporter` if any hostile signals are
/// active.  Call this once after each SDK evaluation cycle.
internal func dispatchHostileEnvironmentReport(to reporter: HostileEnvironmentReporter?) {
    guard let reporter else { return }

    let flags = cprisk_emulator_probe()
    guard flags != 0 else { return }

    let score = Int(cprisk_emulator_score(flags))
    let signals = HostileEnvironmentReport.signals(from: flags)

    let formatter = ISO8601DateFormatter()
    let report = HostileEnvironmentReport(
        rawFlags: flags,
        score: score,
        activeSignals: signals,
        isHostile: cprisk_emulator_is_hostile(flags) != 0,
        timestamp: formatter.string(from: Date())
    )

    reporter.reportHostileEnvironment(report)
}
