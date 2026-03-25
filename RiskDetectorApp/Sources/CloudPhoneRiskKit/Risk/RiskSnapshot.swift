import Foundation

/// A stable snapshot of signals collected during an `evaluate()` call.
/// Custom providers can use this to derive extra `RiskSignal`s without depending on internal types.
public struct RiskSnapshot: Sendable {
    public var deviceID: String
    public var device: DeviceFingerprint
    public var network: NetworkSignals
    public var behavior: BehaviorSignals
    public var jailbreak: DetectionResult
    public var mutationStrategy: MutationStrategy?
    /// Whether the anti-debug watchdog snapshot path is available on this build/runtime.
    public var antiDebugWatchdogSupported: Bool
    /// Bitset from CRiskCore describing which direct-syscall surfaces fell back to libc/arc4random.
    public var libcFallbackUsedMask: UInt32
    /// Monotonic count of fallback notifications since the C mask was last reset.
    public var libcFallbackEventTotal: UInt32

    public init(
        deviceID: String,
        device: DeviceFingerprint,
        network: NetworkSignals,
        behavior: BehaviorSignals,
        jailbreak: DetectionResult,
        mutationStrategy: MutationStrategy? = nil,
        antiDebugWatchdogSupported: Bool = false,
        libcFallbackUsedMask: UInt32 = 0,
        libcFallbackEventTotal: UInt32 = 0
    ) {
        self.deviceID = deviceID
        self.device = device
        self.network = network
        self.behavior = behavior
        self.jailbreak = jailbreak
        self.mutationStrategy = mutationStrategy
        self.antiDebugWatchdogSupported = antiDebugWatchdogSupported
        self.libcFallbackUsedMask = libcFallbackUsedMask
        self.libcFallbackEventTotal = libcFallbackEventTotal
    }
}

