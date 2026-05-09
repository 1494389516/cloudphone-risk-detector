import Foundation
#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// App Attest 主动 SE 探针（在 isSupported=true 之外再实际驱动一次密钥/断言流程）
///
/// 设计动机：
/// `AppAttestSignalProvider` 仅检查 `DCAppAttestService.isSupported`。一些复杂的越狱
/// 环境会让 `isSupported` 返回 true（比如挂钩了 DeviceCheck 框架）但底层 Secure Enclave
/// 调用其实失败或是被代理。本 Provider 主动调用 `AppAttestSigner.resolveKeyId()`
/// (内部触发 generateKey + attestKey) — 仅在真机 + 真 SE 环境下成功。
///
/// 借鉴自小红书 x274 字段的 5 级 Key Attestation 证书链思路：硬件信任根的强度来自
/// "实际能跑通 TEE 操作"，不是"声称支持 TEE"。
///
/// 状态机：
///   notProbed → probing → probed(outcome, time)
///
/// TTL 复探：
///   probed 之后超过 `probeTTL`（默认 1 小时）会重新触发一次后台探针，应对 mid-session
///   被 hook 的场景。复探期间继续返回上次的 outcome，复探完成后切换。
///
/// 信号：
///   - probed(.ok)             → 不发信号
///   - probed(.failed(reason)) → app_attest_active_probe_failed (score 70, layer 1)
///   - notProbed / probing     → 不发信号（避免在结果未稳定时拍脑袋）
final class AppAttestActiveProbeProvider: RiskSignalProvider {

    static let shared = AppAttestActiveProbeProvider()
    let id = "app_attest_active_probe"

    /// 一次探针结果的有效期。超过后下次 signals() 触发后台复探。
    private static let probeTTL: TimeInterval = 3600

    private enum ProbeState {
        case notProbed
        case probing
        case probed(ProbeOutcome, at: Date)
    }

    private enum ProbeOutcome {
        case ok
        case failed(reason: String)
    }

    private let stateLock = UnfairLock()
    private var state: ProbeState = .notProbed

    private init() {}

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let action = stateLock.withLock { () -> StateAction in
            switch state {
            case .notProbed:
                return .kickOff(currentOutcome: nil)
            case .probing:
                return .wait(currentOutcome: nil)
            case .probed(let outcome, let at):
                if Date().timeIntervalSince(at) > Self.probeTTL {
                    return .kickOff(currentOutcome: outcome)
                }
                return .emit(outcome)
            }
        }

        switch action {
        case .kickOff(let pendingOutcome):
            kickOffProbe()
            // 若有上次的 outcome，复探期间用旧值，避免空窗。
            if let prev = pendingOutcome {
                return signal(for: prev)
            }
            return []

        case .wait:
            return []

        case .emit(let outcome):
            return signal(for: outcome)
        }
    }

    private enum StateAction {
        case kickOff(currentOutcome: ProbeOutcome?)
        case wait(currentOutcome: ProbeOutcome?)
        case emit(ProbeOutcome)
    }

    private func signal(for outcome: ProbeOutcome) -> [RiskSignal] {
        switch outcome {
        case .ok:
            return []
        case .failed(let reason):
            return [
                RiskSignal(
                    id: "app_attest_active_probe_failed",
                    category: "hardware_trust",
                    score: 70,
                    evidence: [
                        "reason": reason,
                        "hint": "DCAppAttestService.isSupported=true 但底层 SE 调用失败 — 怀疑 SE 被代理或 DeviceCheck 框架被挂钩",
                    ],
                    state: .hard(detected: true),
                    layer: 1,
                    weightHint: 80
                )
            ]
        }
    }

    private func kickOffProbe() {
        // 把 state 置为 .probing；如果已经在 probing 中（其他线程刚开始）就放弃。
        let shouldRun = stateLock.withLock { () -> Bool in
            if case .probing = state { return false }
            state = .probing
            return true
        }
        guard shouldRun else { return }

        guard AppAttestSignalProvider.isHardwareTrustSupported else {
            stateLock.withLock { state = .probed(.ok, at: Date()) }
            return
        }

        #if canImport(DeviceCheck)
        if #available(iOS 14.0, macOS 11.0, *) {
            Task.detached(priority: .background) { [weak self] in
                let outcome = await Self.runActiveProbe()
                self?.stateLock.withLock { self?.state = .probed(outcome, at: Date()) }
            }
        } else {
            stateLock.withLock { state = .probed(.ok, at: Date()) }
        }
        #else
        stateLock.withLock { state = .probed(.ok, at: Date()) }
        #endif
    }

    @available(iOS 14.0, macOS 11.0, *)
    private static func runActiveProbe() async -> ProbeOutcome {
        do {
            _ = try await AppAttestSigner.resolveKeyId()
            return .ok
        } catch let err as AppAttestSigner.AppAttestError {
            switch err {
            case .hardwareTrustUnsupported:
                return .ok
            case .invalidPayloadHashSize:
                return .failed(reason: "invalid_payload_hash_size")
            }
        } catch {
            #if canImport(DeviceCheck)
            if let dcErr = error as? DCError {
                switch dcErr.code {
                case .featureUnsupported:
                    return .failed(reason: "dc_feature_unsupported")
                case .invalidKey:
                    return .failed(reason: "dc_invalid_key")
                case .invalidInput:
                    return .failed(reason: "dc_invalid_input")
                case .serverUnavailable:
                    // 网络问题 — 不视为环境异常
                    return .ok
                @unknown default:
                    return .failed(reason: "dc_error_\(dcErr.code.rawValue)")
                }
            }
            #endif
            return .failed(reason: "unknown_\(String(describing: type(of: error)))")
        }
    }
}
