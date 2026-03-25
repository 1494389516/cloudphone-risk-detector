import Foundation

/// 将证书固定路径侧信道事件转为 `RiskSignal`（内置注册，随 `CPRiskKit.start()` 生效）。
final class CertificatePinningTelemetryProvider: RiskSignalProvider {
    static let shared = CertificatePinningTelemetryProvider()

    let id = "certificate_pinning_telemetry"

    private init() {}

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let drained = CertificatePinningTelemetry.shared.drainEvents()
        guard !drained.isEmpty else { return [] }

        return drained.map { ev in
            let (score, state) = scoreAndState(for: ev.kind)
            var evidence = ev.detail
            evidence["kind"] = ev.kind.rawValue
            evidence["host"] = ev.host
            evidence["ts"] = String(format: "%.3f", ev.recordedAt.timeIntervalSince1970)
            return RiskSignal(
                id: SignalID.certificatePinningAnomaly,
                category: SignalCategory.network,
                score: score,
                evidence: evidence,
                state: state
            )
        }
    }

    private func scoreAndState(for kind: CertificatePinningTelemetryKind) -> (Double, RiskSignalState?) {
        switch kind {
        case .trustResultMismatch, .integrityRecheckTamper, .svcStubIntegrity, .integrityRecheckComputeFailed, .pinValidatorDiverged:
            return (78, .tampered)
        case .trustEvalFailed, .leafPublicKeyMissing, .pinMismatch, .emptyCertificateChain:
            return (65, .hard(detected: true))
        case .trustEvalSuspiciouslyFast:
            return (38, .soft(confidence: 0.55))
        }
    }
}
