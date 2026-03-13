import Foundation
import LocalAuthentication

/// 生物识别状态探测 Provider
///
/// 通过 LAContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics) 探测设备生物识别能力，
/// 不弹窗、仅探测。用于识别云手机/机架设备常见特征：
/// - biometryNotEnrolled：机架设备常态未录入指纹/面容
/// - biometryNotAvailable：硬件缺失或虚拟化环境（仅当 biometryType == .none 时上报，避免 Touch ID 老机型误报）
/// - biometryLockout：可辅助判断，权重较低
///
/// 注意：
/// - 模拟器环境下直接返回空数组（LAContext 在模拟器上可能抛异常或行为异常）
/// - 不使用 main.sync 派发，因 Registry 在 main 上 wait 时会导致死锁；canEvaluatePolicy 不弹窗，可在当前线程执行
/// - 需在 Info.plist 配置 NSFaceIDUsageDescription，否则 Face ID 设备上可能崩溃
final class BiometricStateProvider: RiskSignalProvider {
    static let shared = BiometricStateProvider()
    private init() {}

    let id = "biometric_state"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return []
        #else
        return probeBiometricState()
        #endif
    }

    private func probeBiometricState() -> [RiskSignal] {
        let context = LAContext()
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)

        if canEvaluate {
            // 生物识别可用且已录入，无风险信号
            return []
        }

        guard let laError = error as? LAError else {
            return []
        }

        switch laError.code {
        case .biometryNotEnrolled:
            return [
                RiskSignal(
                    id: "biometric_not_enrolled",
                    category: "device",
                    score: 0,
                    evidence: [
                        "reason": "biometryNotEnrolled",
                        "detail": "机架设备常态未录入",
                    ],
                    state: .soft(confidence: 0.5),
                    layer: 1,
                    weightHint: 40
                ),
            ]
        case .biometryNotAvailable:
            // 仅当 biometryType == .none 时上报，避免 Touch ID 老机型（如 iPhone 8）误报：
            // 有硬件但 biometryNotAvailable 可能由权限/临时故障引起，非真实硬件缺失
            if context.biometryType != .none {
                return []
            }
            return [
                RiskSignal(
                    id: "biometric_not_available",
                    category: "device",
                    score: 0,
                    evidence: [
                        "reason": "biometryNotAvailable",
                        "detail": "硬件缺失或虚拟化",
                    ],
                    state: .soft(confidence: 0.9),
                    layer: 1,
                    weightHint: 85
                ),
            ]
        case .biometryLockout:
            return [
                RiskSignal(
                    id: "biometric_lockout",
                    category: "device",
                    score: 0,
                    evidence: [
                        "reason": "biometryLockout",
                        "detail": "可辅助",
                    ],
                    state: .soft(confidence: 0.3),
                    layer: 1,
                    weightHint: 25
                ),
            ]
        default:
            return []
        }
    }
}
