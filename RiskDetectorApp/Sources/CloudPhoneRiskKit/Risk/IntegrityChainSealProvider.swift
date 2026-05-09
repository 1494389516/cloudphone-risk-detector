import CryptoKit
import Foundation

/// 完整性链印章 Provider — 把 GF(2) 仿射 + SE 签名 + 跨 session 持久化串成一条链。
///
/// 流程：
///   1. 把 snapshot 里的设备不变量（deviceID / hardwareModel / systemVersion / ...）拼成
///      canonical 字符串
///   2. SHA-256 → 取前 16 字节 → cprisk_gf2_affine_transform_16 → 16 字节 seal
///   3. 用 Secure Enclave 私钥对 seal 做 ECDSA-P256-SHA256 签名（X9.62 DER）
///   4. 跨 session 比对：从 Keychain 读上次的 seal hex；如不一致 → invariant_seal_drift
///      （score 65, state .tampered）
///   5. 把当前 seal 写入 Keychain，作为下次的对照
///
/// 防御价值：
///   - GF(2) 终于接到主链路：任何修改 snapshot 内容或 SHA-256 实现的 hook 都会让 seal
///     变化，而 attacker 必须同时还原 128×128 矩阵才能伪造正确 seal
///   - SE 签名是硬件锚定：私钥永不出 SE，模拟器/unidbg/Frida-on-rooted-vm 全部
///     无法伪造签名 — 上传到 server（未来）后能强校验
///   - 跨 session 比对：即使本次启动 hook 完美无痕，"上一次启动我看到的 seal"和
///     "这次启动我看到的 seal"差异本身就是信号 — 抓"setup 时干净、运行时被 hook"
///     的攻击模式
///
/// 状态机：
///   notSealed → sealing → sealed(seal, sig?, at)
///   TTL = 300s。超时后下次 signals() 触发后台复算。
final class IntegrityChainSealProvider: RiskSignalProvider {

    static let shared = IntegrityChainSealProvider()
    let id = "integrity_chain_seal"

    private static let sealTTL: TimeInterval = 300
    private static let keychainKeyLastSeal = "invariant_seal_v1"
    private static let keychainKeyLastSealAt = "invariant_seal_v1_at"

    private struct SealResult {
        let sealHex: String
        let sig: Data?
        let sigError: String?
        let driftFromLast: String?  // 上次的 seal hex（如果不同）
        let computedAt: Date
    }

    private enum State {
        case notSealed
        case sealing
        case sealed(SealResult)
    }

    private let lock = UnfairLock()
    private var state: State = .notSealed

    private init() {}

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let action = lock.withLock { () -> Action in
            switch state {
            case .notSealed:
                return .startSeal(returnCached: nil)
            case .sealing:
                return .returnEmpty
            case .sealed(let result):
                if Date().timeIntervalSince(result.computedAt) > Self.sealTTL {
                    return .startSeal(returnCached: result)
                }
                return .returnCached(result)
            }
        }

        switch action {
        case .startSeal(let cached):
            kickOffSeal(canonical: buildCanonical(snapshot: snapshot))
            if let cached {
                return signals(forResult: cached)
            }
            return []
        case .returnEmpty:
            return []
        case .returnCached(let result):
            return signals(forResult: result)
        }
    }

    private enum Action {
        case startSeal(returnCached: SealResult?)
        case returnEmpty
        case returnCached(SealResult)
    }

    // MARK: - Signal Construction

    private func signals(forResult result: SealResult) -> [RiskSignal] {
        var signals: [RiskSignal] = []

        var evidence: [String: String] = [
            "seal": result.sealHex,
            "se_signed": result.sig != nil ? "1" : "0",
            "matrix_intact": IntegritySealComputer.isMatrixIntact ? "1" : "0",
        ]
        if let sig = result.sig {
            evidence["sig_len"] = "\(sig.count)"
            // 仅暴露签名前 8 字节（足够用作 evidence 锚点，避免 evidence 过大）
            evidence["sig_prefix"] = sig.prefix(8).map { String(format: "%02x", $0) }.joined()
        }
        if let err = result.sigError {
            evidence["sig_err"] = err
        }

        // 主信号：分数 0 = 良性遥测；矩阵被改 / SE 签名失败 → 提分
        var sealScore: Double = 0
        var sealState: RiskSignalState? = nil
        var sealWeight: Double = 0
        if !IntegritySealComputer.isMatrixIntact {
            sealScore = 40
            sealState = .tampered
            sealWeight = 65
        } else if result.sig == nil && SecureEnclaveSigner.isSupported && result.sigError != nil {
            // SE 支持但签名失败 — 比 isSupported=false 更可疑（环境异常）
            sealScore = 30
            sealState = .soft(confidence: 0.7)
            sealWeight = 50
        }

        signals.append(
            RiskSignal(
                id: "integrity_chain_seal",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: sealScore,
                evidence: evidence,
                state: sealState,
                layer: 1,
                weightHint: sealWeight
            )
        )

        if let prev = result.driftFromLast {
            signals.append(
                RiskSignal(
                    id: "invariant_seal_drift",
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: 65,
                    evidence: [
                        "current_seal": result.sealHex,
                        "previous_seal": prev,
                        "hint": "设备不变量集自上次 evaluate 后发生了变化 — 怀疑跨 session 篡改 / 设备指纹被 hook",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 75
                )
            )
        }

        return signals
    }

    // MARK: - Canonical Build

    /// 把 snapshot 里"对同一设备应当稳定不变"的字段拼成一个 canonical 字符串。
    /// 不包含会随时间变化的字段（如 systemVersion 的 minor、jailbreak 分数等）。
    private func buildCanonical(snapshot: RiskSnapshot) -> String {
        var fields: [String] = []
        fields.append("did:\(snapshot.deviceID)")
        if let hw = snapshot.device.hardwareModel {
            fields.append("hw:\(hw)")
        }
        // systemVersion 取主版本，避免 minor 升级导致误报
        let osMajor = snapshot.device.systemVersion.split(separator: ".").first.map(String.init) ?? ""
        fields.append("os_major:\(osMajor)")
        fields.append("se_supported:\(SecureEnclaveSigner.isSupported ? "1" : "0")")
        fields.append("attest_supported:\(AppAttestSignalProvider.isHardwareTrustSupported ? "1" : "0")")
        // 排序保证 canonical 形式稳定
        return fields.sorted().joined(separator: "|")
    }

    // MARK: - Async Seal

    private func kickOffSeal(canonical: String) {
        // 标记为 sealing；如果其他线程已经在 sealing，退出
        let shouldRun = lock.withLock { () -> Bool in
            if case .sealing = state { return false }
            state = .sealing
            return true
        }
        guard shouldRun else { return }

        Task.detached(priority: .background) { [weak self] in
            let result = await Self.computeSeal(canonical: canonical)
            guard let self = self else { return }
            self.lock.withLock { self.state = .sealed(result) }
        }
    }

    private static func computeSeal(canonical: String) async -> SealResult {
        let seal = IntegritySealComputer.seal(forCanonicalString: canonical)
        let sealHex = seal.hexString
        let sealBytes = Data(seal.bytes)

        // SE 签名（best-effort；失败不阻断主信号）
        // 签的是 16 字节 seal — 服务器拿公钥验签后即知该 seal 真实来自此设备 SE
        var sig: Data? = nil
        var sigError: String? = nil
        if SecureEnclaveSigner.isSupported {
            do {
                sig = try SecureEnclaveSigner.sign(sealBytes)
            } catch {
                sigError = String(describing: error)
            }
        }

        // 跨 session 比对：读 Keychain 上次的 seal hex
        let previousHex = LongitudinalStateStore.loadString(key: keychainKeyLastSeal)
        let drift = (previousHex != nil && previousHex != sealHex) ? previousHex : nil

        // 写入本次 seal 作为下次基线
        LongitudinalStateStore.saveString(key: keychainKeyLastSeal, value: sealHex)
        LongitudinalStateStore.saveString(
            key: keychainKeyLastSealAt,
            value: ISO8601DateFormatter().string(from: Date())
        )

        return SealResult(
            sealHex: sealHex,
            sig: sig,
            sigError: sigError,
            driftFromLast: drift,
            computedAt: Date()
        )
    }
}
