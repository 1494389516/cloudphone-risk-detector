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
 *   2. **常量篡改检测**：vendor_b 是编译期常量。每次 emit 与编译期 expected 比对；
 *      若不一致说明某个 hook 或 .data 篡改了字符串。
 *   3. **印章绑定**：vendor_a/vendor_b 由 GF(2) 仿射 seal 绑定。
 *   4. **未来服务器扩展锚点**：服务器只要看 vendor_b == expected 就能识别"被清洗
 *      过的载荷"。
 *
 * 注意（攻击者已在 launch 时 hook 的场景）：
 *   如果 hook 在 SDK 加载前就已经在了，攻击者可以同时改 vendor_b 字符串和我们读取它的
 *   逻辑。常量比对仅能检测 hook 不到位的攻击者。这是已知的限制；与服务器端验证组合
 *   使用时威力最大。
 */

final class HoneypotConflictFieldProvider: RiskSignalProvider {

    static let shared = HoneypotConflictFieldProvider()
    let id = "honeypot_conflict_field"

    /// 编译期常量：vendor_b 必须始终等于这个字符串。
    /// 取自 NES 早期文化梗，不会在任何设备字段里自然出现。
    private static let expectedVendorB = "Konami_x42"

    private init() {}

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let observed = currentObservation()
        let canonical = "\(observed.vendorA)|\(observed.vendorB)"
        let seal = IntegritySealComputer.seal(forCanonicalString: canonical)
        let observedSealHex = seal.hexString

        let matrixIntact = IntegritySealComputer.isMatrixIntact
        let vendorBMatchesExpected = observed.vendorB == Self.expectedVendorB

        var signals: [RiskSignal] = []

        // 主信号：分数 0 = 良性遥测；矩阵被改 → 35。
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

        // 编译期 vendor_b 检查 — 任何 hook 修正了我们的硬编码字符串都会落到这。
        if !vendorBMatchesExpected {
            signals.append(
                RiskSignal(
                    id: "honeypot_constant_drift",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 75,
                    evidence: [
                        "expected_vendor_b": Self.expectedVendorB,
                        "observed_vendor_b": observed.vendorB,
                        "hint": "硬编码常量被 hook 或字符串段被修改",
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
            vendorB: Self.expectedVendorB
        )
    }

    /// 真实平台标识。形如 "iPhone15,2:23.1.0" — 设备相关，无法编译期固定。
    private func realVendorString() -> String {
        let machine = sysctlString("hw.machine")
        let osrel = sysctlString("kern.osrelease")
        return "\(machine):\(osrel)"
    }

    private func sysctlString(_ name: String) -> String {
        var size: size_t = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return "" }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return "" }
        return String(cString: buf)
    }
}
