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

    /// vendor_b 输出值 — 故意暴露在 .cstring。攻击者若用字节级 patch 改这个字面量，
    /// `currentObservation()` 返回的 vendorB 会变；下面 `expectedVendorB()` 重组的
    /// 期望值不动，触发 drift 告警。
    private static let observedVendorBLiteral = "Konami_x42"

    /// 期望值，运行时从 XOR 编码字节重组（key=0x42）。源代码里看不到 "Konami_x42" 字面量，
    /// 字节序列也不在 .cstring 段，跟 observedVendorBLiteral 不共享存储 — 防止编译器
    /// 把 observed == expected 折叠为 true，也防止单点 .cstring patch 同时命中两侧。
    @inline(never)
    private static func expectedVendorB() -> String {
        var bytes: [UInt8] = [0x09, 0x2D, 0x2C, 0x23, 0x2F, 0x2B, 0x1D, 0x3A, 0x76, 0x70]
        for i in 0..<bytes.count {
            bytes[i] ^= 0x42
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private init() {}

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let observed = currentObservation()
        let canonical = "\(observed.vendorA)|\(observed.vendorB)"
        let seal = IntegritySealComputer.seal(Data(canonical.utf8))
        let observedSealHex = seal.hexString

        let matrixIntact = IntegritySealComputer.isMatrixIntact
        let expectedVendorB = Self.expectedVendorB()
        let vendorBMatchesExpected = observed.vendorB == expectedVendorB

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
                        "expected_vendor_b": expectedVendorB,
                        "observed_vendor_b": observed.vendorB,
                        "hint": "硬编码常量被 hook 或字符串段被修改",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 80
                )
            )
        }

        // v7.7 audit-fix F8: 双边坍缩检测 — vendor_a 来自 sysctl(hw.machine + kern.osrelease)，
        // 形如 "iPhone15,2:23.1.0"；vendor_b 是硬编码 "Konami_x42"。两者在合法硬件上**永远**
        // 不可能相等。
        // 攻击场景：攻击者 hook sysctlString 让 vendorA 也返回 "Konami_x42" → 蜜罐主信号
        // (vendorA != vendorB) 不再"矛盾"，drift 检测也通过 → 整个蜜罐失效。
        // 加这条信号闭合"双边都被 hook"的攻击路径：等于 = 异常本身。
        if observed.vendorA == observed.vendorB {
            signals.append(
                RiskSignal(
                    id: "honeypot_vendor_collapsed",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 80,
                    evidence: [
                        "vendor_a": observed.vendorA,
                        "vendor_b": observed.vendorB,
                        "hint": "vendor_a == vendor_b — 合法硬件不可能；sysctl 或字符串段被 hook 同步修正",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 85
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
            vendorB: Self.observedVendorBLiteral
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
