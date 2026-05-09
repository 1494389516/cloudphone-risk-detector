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
///   notProbed → probing → probed(.ok) | probed(.failed(reason))
///
/// 信号：
///   - probed(.ok)             → 不发信号
///   - probed(.failed(reason)) → app_attest_active_probe_failed (score 70, layer 1)
///   - notProbed / probing     → 不发信号（避免在结果未稳定时拍脑袋）
final class AppAttestActiveProbeProvider: RiskSignalProvider {

    static let shared = AppAttestActiveProbeProvider()
    let id = "app_attest_active_probe"

    private enum ProbeState {
        case notProbed
        case probing
        case probed(ProbeOutcome)
    }

    private enum ProbeOutcome {
        case ok
        case failed(reason: String)
    }

    private let stateLock = UnfairLock()
    private var state: ProbeState = .notProbed

    private init() {}

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let current = stateLock.withLock { state }

        switch current {
        case .notProbed:
            kickOffProbe()
            return []

        case .probing:
            return []

        case .probed(.ok):
            return []

        case .probed(.failed(let reason)):
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
        stateLock.withLock {
            guard case .notProbed = state else { return }
            state = .probing
        }

        // 仅在 isSupported 时才走主动 SE 探针 — isSupported=false 已由
        // AppAttestSignalProvider 单独信号化。
        guard AppAttestSignalProvider.isHardwareTrustSupported else {
            stateLock.withLock { state = .probed(.ok) }
            return
        }

        #if canImport(DeviceCheck)
        if #available(iOS 14.0, macOS 11.0, *) {
            Task.detached(priority: .background) { [weak self] in
                let outcome = await Self.runActiveProbe()
                self?.stateLock.withLock { self?.state = .probed(outcome) }
            }
        } else {
            stateLock.withLock { state = .probed(.ok) }
        }
        #else
        stateLock.withLock { state = .probed(.ok) }
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
