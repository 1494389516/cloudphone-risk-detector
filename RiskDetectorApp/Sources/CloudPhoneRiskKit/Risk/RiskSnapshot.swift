import Foundation

/// A stable snapshot of signals collected during an `evaluate()` call.
/// Custom providers can use this to derive extra `RiskSignal`s without depending on internal types.
public struct RiskSnapshot: Sendable {
    public var deviceID: String
    public var device: DeviceFingerprint
    public var network: NetworkSignals
    public var behavior: BehaviorSignals
    public var jailbreak: DetectionResult

    public init(
        deviceID: String,
        device: DeviceFingerprint,
        network: NetworkSignals,
        behavior: BehaviorSignals,
        jailbreak: DetectionResult
    ) {
        self.deviceID = deviceID
        self.device = device
        self.network = network
        self.behavior = behavior
        self.jailbreak = jailbreak
    }
}

