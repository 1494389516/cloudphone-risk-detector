import Darwin
import Foundation
#if canImport(UIKit)
import UIKit
#endif

/*
 * HoneypotConflictFieldProvider
 *
 * 借鉴自小红书 libtiny.so 的 x5="Vivo" 蜜罐设计：
 *   libtiny 在尝试连接小米/酷派 OAID 服务失败后硬编码 vendor 为 "Vivo"，但同一个指纹
 *   里 x23=Google、x24=Pixel 6、x7=gs101 — 三个字段公然矛盾。这个矛盾**是预期的**。
 *   后端知道矛盾应该存在；如果某个上传里 x5 被"修正"成 "Google"（与 x23 一致），
 *   反而暴露了攻击者在客户端做了字段标准化 — 因为正常 SDK 永远不会自我修正。
 *
 * 客户端单端的价值：
 *   1. **误导成本**：分析者在 IDA 里看到我们故意输出 vendor_a/vendor_b 矛盾对，
 *      自然会去研究"这是不是个 bug、要不要 patch 掉"，浪费时间。
 *   2. **印章防伪**：vendor_a/vendor_b 由 GF(2) 仿射 seal 绑定。攻击者改任一字段
 *      seal 就不再有效；要同时伪造 seal 必须先还原 128×128 矩阵。
 *   3. **未来服务器扩展锚点**：当 SDK 上传到服务器（即使现在没有），服务器只要知道
 *      这条矛盾应该存在，就能用一行规则识别"被清洗过的载荷"。
 *
 * 自我审计：
 *   首次 emit 时把 (vendor_a, vendor_b, seal) 元组写进 lock 保护的 baseline。后续 emit
 *   时重新计算 seal — 如果跟 baseline 不一致，说明某个 hook 修改了我们的输出常量，
 *   作为强信号上报 honeypot_baseline_drift。
 */

final class HoneypotConflictFieldProvider: RiskSignalProvider {

    static let shared = HoneypotConflictFieldProvider()
    let id = "honeypot_conflict_field"

    private struct Baseline {
        let vendorA: String
        let vendorB: String
        let sealHex: String
    }

    private let lock = UnfairLock()
    private var baseline: Baseline?

    private init() {}

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let observed = currentObservation()
        let canonical = "\(observed.vendorA)|\(observed.vendorB)"
        let seal = IntegritySealComputer.seal(forCanonicalString: canonical)
        let observedSealHex = seal.hexString

        let drift = lock.withLock { () -> Bool in
            if let cached = baseline {
                if cached.vendorA != observed.vendorA
                    || cached.vendorB != observed.vendorB
                    || cached.sealHex != observedSealHex {
                    return true
                }
                return false
            } else {
                baseline = Baseline(vendorA: observed.vendorA, vendorB: observed.vendorB, sealHex: observedSealHex)
                return false
            }
        }

        var signals: [RiskSignal] = []

        // 蜜罐主信号：分数 0，纯粹为了把矛盾对 + seal 传出去。
        // 若 seal 矩阵自校验失败，把分数提到 35（说明 .rodata 里的矩阵被改）。
        let matrixIntact = IntegritySealComputer.isMatrixIntact
        signals.append(
            RiskSignal(
                id: "honeypot_vendor_conflict",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: matrixIntact ? 0 : 35,
                evidence: [
                    "vendor_a": observed.vendorA,
                    "vendor_b": observed.vendorB,
                    "seal": observedSealHex,
                    "matrix_intact": matrixIntact ? "1" : "0",
                ],
                state: matrixIntact ? nil : .tampered,
                layer: 1,
                weightHint: matrixIntact ? 0 : 60
            )
        )

        if drift {
            // 我们自己的输出常量被在内存里改了 — 强信号。
            signals.append(
                RiskSignal(
                    id: "honeypot_baseline_drift",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 75,
                    evidence: [
                        "reason": "first-seen vendor pair / seal differs from current emission",
                        "expected_seal": baselineSealHex() ?? "",
                        "observed_seal": observedSealHex,
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 80
                )
            )
        }

        return signals
    }

    // MARK: - Observation

    private struct Observation {
        let vendorA: String
        let vendorB: String
    }

    /// 故意输出矛盾的 vendor 对：vendor_a 是真实平台值，vendor_b 是 hard-coded 的"错误"值。
    /// 任何把两者标准化成一致的中间层都是异常。
    private func currentObservation() -> Observation {
        return Observation(
            vendorA: realVendorString(),
            vendorB: hardcodedDecoyVendor()
        )
    }

    private func realVendorString() -> String {
        #if canImport(UIKit)
        // 真机预期是 "Apple Inc." — 不依赖 UIDevice 一类容易被 swizzle 的 API，
        // 直接读 sysctl hw.product / hw.machine 拼出。
        return "\(sysctlString("hw.machine")):\(sysctlString("kern.osrelease"))"
        #else
        return "macos:\(sysctlString("kern.osrelease"))"
        #endif
    }

    /// 故意硬编码的"假" vendor — 跟真机不可能匹配的字符串。
    /// 取自 NES 早期文化梗，不会在任何设备字段里自然出现。
    private func hardcodedDecoyVendor() -> String {
        "Konami_x42"
    }

    private func sysctlString(_ name: String) -> String {
        var size: size_t = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return "" }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return "" }
        return String(cString: buf)
    }

    private func baselineSealHex() -> String? {
        lock.withLock { baseline?.sealHex }
    }
}
