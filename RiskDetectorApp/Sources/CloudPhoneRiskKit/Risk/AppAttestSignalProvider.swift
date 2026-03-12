import Foundation
#if canImport(DeviceCheck)
import DeviceCheck
#endif

/// App Attest 硬件信任根信号提供者（SDK 4.4）
/// 当 DCAppAttestService.isSupported 为 false 时，发出 hardware_trust_unsupported（权重 95）。
final class AppAttestSignalProvider: RiskSignalProvider {

    static let shared = AppAttestSignalProvider()
    let id = "app_attest"

    private init() {}

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        guard !Self.isHardwareTrustSupported else {
            return []
        }
        return [
            RiskSignal(
                id: "hardware_trust_unsupported",
                category: "hardware_trust",
                score: 95,
                evidence: [
                    "reason": "DCAppAttestService.isSupported=false",
                    "hint": "模拟器/黑苹果/QEMU/虚拟机或无效 App ID",
                ],
                state: .hard(detected: true),
                layer: 1,
                weightHint: 95
            )
        ]
    }

    /// 运行时检测：当前环境是否支持 App Attest 硬件信任根
    static var isHardwareTrustSupported: Bool {
        #if canImport(DeviceCheck)
        if #available(iOS 14.0, macOS 11.0, *) {
            return DCAppAttestService.shared.isSupported
        }
        #endif
        return false
    }
}
