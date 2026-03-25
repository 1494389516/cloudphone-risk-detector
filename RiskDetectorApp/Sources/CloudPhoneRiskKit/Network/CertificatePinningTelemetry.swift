import Foundation

/// 证书固定路径上的可观测事件（供后续聚合为 `RiskSignal`）。
public enum CertificatePinningTelemetryKind: String, Sendable {
    case trustEvalFailed
    case trustResultMismatch
    case leafPublicKeyMissing
    case integrityRecheckTamper
    case integrityRecheckComputeFailed
    case svcStubIntegrity
    case trustEvalSuspiciouslyFast
    case pinValidatorDiverged
    case pinMismatch
    case emptyCertificateChain
}

/// 线程安全的侧信道缓冲：网络 delegate 写入，Risk 管线读取。
public final class CertificatePinningTelemetry: @unchecked Sendable {
    public static let shared = CertificatePinningTelemetry()

    private let lock = UnfairLock()
    private var events: [CertificatePinningTelemetryEvent] = []
    private let maxBuffered = 32

    private init() {}

    public func record(host: String, kind: CertificatePinningTelemetryKind, detail: [String: String] = [:]) {
        let ev = CertificatePinningTelemetryEvent(
            host: host,
            kind: kind,
            detail: detail,
            recordedAt: Date()
        )
        lock.withLock {
            events.append(ev)
            if events.count > maxBuffered {
                events.removeFirst(events.count - maxBuffered)
            }
        }
    }

    /// 取出并清空缓冲，供 `RiskSignalProvider` 转为 `RiskSignal`。
    public func drainEvents() -> [CertificatePinningTelemetryEvent] {
        lock.withLock {
            let out = events
            events.removeAll(keepingCapacity: true)
            return out
        }
    }

    /// 测试或调试：不清空读取。
    func peekEventsForTesting() -> [CertificatePinningTelemetryEvent] {
        lock.withLock { events }
    }

    func resetForTesting() {
        lock.withLock { events.removeAll(keepingCapacity: true) }
    }
}

public struct CertificatePinningTelemetryEvent: Sendable {
    public let host: String
    public let kind: CertificatePinningTelemetryKind
    public let detail: [String: String]
    public let recordedAt: Date
}
