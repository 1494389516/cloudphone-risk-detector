import Foundation

public enum SecureEnvelopeValidationError: Error, LocalizedError, Sendable {
    case invalidEnvelopeJSON
    case unsupportedSignatureVersion(actual: String, allowed: [String])
    case unknownKeyId(String)
    case reportEnvelope(ReportEnvelope.ReportEnvelopeError)

    public var errorDescription: String? {
        switch self {
        case .invalidEnvelopeJSON:
            return "安全信封 JSON 无法解析"
        case .unsupportedSignatureVersion(let actual, let allowed):
            return "签名版本不被允许：actual=\(actual), allowed=\(allowed.joined(separator: ","))"
        case .unknownKeyId(let keyId):
            return "找不到 keyId 对应的签名密钥：\(keyId)"
        case .reportEnvelope(let error):
            return error.errorDescription
        }
    }
}

/// 默认本地重放保护存储（仅用于 SDK 自测与联调）。
/// 生产网关应使用服务端一致性存储。
public final class LocalEnvelopeReplayStore: NonceReplayProtecting, @unchecked Sendable {
    public static let shared = LocalEnvelopeReplayStore()

    private struct StoredEnvelope: Codable {
        var schemaVersion: Int
        var entries: [String: Int64]
        var latestExpiryMillis: Int64
        var sequence: UInt64
    }

    private let defaults = UserDefaults.standard
    private let lock = NSLock()
    private let key = "cloudphone_envelope_replay_v2"
    private let hmacKey = "cloudphone_envelope_replay_v2_hmac"
    private let hmacPurpose = "envelope_replay"
    private let freshnessAnchor = FreshnessAnchor(account: "envelope_replay_v2_freshness")
    private let maxEntries = 2048
    private var storage: [String: Int64] = [:]
    private var freshness: FreshnessState = .zero
    private var failClosed = false

    private init() {
        lock.lock()
        defer { lock.unlock() }
        loadLocked()
    }

    public func consumeIfNew(sessionToken: String, nonce: String, expiresAtMillis: Int64) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard !failClosed else {
            Logger.log("LocalEnvelopeReplayStore: fail-closed active, rejecting nonce consumption")
            return false
        }

        pruneExpiredLocked(nowMillis: nowMillis())

        let key = replayKey(sessionToken: sessionToken, nonce: nonce)
        if storage[key] != nil {
            return false
        }

        storage[key] = expiresAtMillis
        trimToLimitLocked()
        guard persistLocked() else {
            storage.removeValue(forKey: key)
            return false
        }
        return true
    }

    private func loadLocked() {
        let anchor = freshnessAnchor.read() ?? .zero
        guard let stored = defaults.data(forKey: key) else {
            storage = [:]
            freshness = anchor
            failClosed = false
            return
        }
        guard let signature = defaults.data(forKey: hmacKey),
              StorageIntegrityGuard.verify(stored, signature: signature, purpose: hmacPurpose) else {
            handleCorruptedStateLocked(reason: "signature verification failed", anchor: anchor)
            return
        }

        let plaintext: Data
        #if DEBUG
        if let decrypted = try? PayloadCrypto.decrypt(stored) {
            plaintext = decrypted
        } else {
            plaintext = stored
        }
        #else
        guard let decrypted = try? PayloadCrypto.decrypt(stored) else {
            handleCorruptedStateLocked(reason: "decrypt failed in release build", anchor: anchor)
            return
        }
        plaintext = decrypted
        #endif

        guard let envelope = try? JSONDecoder().decode(StoredEnvelope.self, from: plaintext) else {
            handleCorruptedStateLocked(reason: "json decode failed", anchor: anchor)
            return
        }

        let diskFreshness = FreshnessState(
            latestTimestamp: Double(envelope.latestExpiryMillis),
            sequence: envelope.sequence
        )
        if diskFreshness.sequence < anchor.sequence || diskFreshness.latestTimestamp < anchor.latestTimestamp {
            handleCorruptedStateLocked(reason: "freshness rollback detected", anchor: anchor)
            return
        }

        storage = envelope.entries
        freshness = FreshnessState(
            latestTimestamp: max(anchor.latestTimestamp, diskFreshness.latestTimestamp),
            sequence: max(anchor.sequence, diskFreshness.sequence)
        )
        pruneExpiredLocked(nowMillis: nowMillis())
        failClosed = false

        if diskFreshness.sequence > anchor.sequence || diskFreshness.latestTimestamp > anchor.latestTimestamp {
            _ = freshnessAnchor.write(diskFreshness)
        }
    }

    private func persistLocked() -> Bool {
        let anchor = freshnessAnchor.read() ?? .zero
        let latestExpiry = storage.values.max() ?? Int64(anchor.latestTimestamp)
        let nextFreshness = FreshnessState(
            latestTimestamp: max(Double(latestExpiry), max(anchor.latestTimestamp, freshness.latestTimestamp)),
            sequence: max(anchor.sequence, freshness.sequence) + 1
        )
        let envelope = StoredEnvelope(
            schemaVersion: 2,
            entries: storage,
            latestExpiryMillis: Int64(nextFreshness.latestTimestamp),
            sequence: nextFreshness.sequence
        )
        guard let raw = try? JSONEncoder().encode(envelope) else {
            activateFailClosedLocked(reason: "encode failed")
            return false
        }

        let stored: Data
        #if DEBUG
        stored = (try? PayloadCrypto.encrypt(raw)) ?? raw
        #else
        guard let encrypted = try? PayloadCrypto.encrypt(raw) else {
            activateFailClosedLocked(reason: "encrypt failed in release build")
            return false
        }
        stored = encrypted
        #endif

        defaults.set(stored, forKey: key)
        defaults.set(StorageIntegrityGuard.sign(stored, purpose: hmacPurpose), forKey: hmacKey)
        guard freshnessAnchor.write(nextFreshness) else {
            activateFailClosedLocked(reason: "freshness anchor update failed")
            return false
        }

        freshness = nextFreshness
        return true
    }

    private func handleCorruptedStateLocked(reason: String, anchor: FreshnessState) {
        Logger.log("LocalEnvelopeReplayStore: \(reason)")
        clearPersistedStateLocked(resetAnchor: false)
        storage = [:]
        freshness = anchor
        #if DEBUG
        failClosed = false
        #else
        failClosed = true
        #endif
    }

    private func activateFailClosedLocked(reason: String) {
        Logger.log("LocalEnvelopeReplayStore: \(reason)")
        #if DEBUG
        failClosed = false
        #else
        failClosed = true
        #endif
        if failClosed {
            clearPersistedStateLocked(resetAnchor: false)
        }
    }

    private func clearPersistedStateLocked(resetAnchor: Bool) {
        defaults.removeObject(forKey: key)
        defaults.removeObject(forKey: hmacKey)
        if resetAnchor {
            freshnessAnchor.remove()
        }
    }

    private func pruneExpiredLocked(nowMillis: Int64) {
        storage = storage.filter { $0.value > nowMillis }
    }

    private func trimToLimitLocked() {
        guard storage.count > maxEntries else { return }
        let sorted = storage.sorted { $0.value < $1.value }
        for item in sorted.prefix(storage.count - maxEntries) {
            storage.removeValue(forKey: item.key)
        }
    }

    private func replayKey(sessionToken: String, nonce: String) -> String {
        "\(sessionToken):\(nonce)"
    }

    private func nowMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }
}

extension CPRiskKit {
    /// 本地校验安全信封（用于 SDK 回归验证链路）。
    /// 默认仅接受 v2 签名，并启用持久化重放保护。
    public func validateSecureReportEnvelope(
        _ envelope: ReportEnvelope,
        signingKey: String,
        allowedSignatureVersions: Set<String> = ["v2"],
        enableReplayProtection: Bool = true,
        nonceStore: NonceReplayProtecting? = nil,
        config: ReportEnvelope.Config = ReportEnvelope.Config()
    ) -> Result<Void, SecureEnvelopeValidationError> {
        guard allowedSignatureVersions.contains(envelope.sigVer) else {
            let allowed = Array(allowedSignatureVersions).sorted()
            return .failure(.unsupportedSignatureVersion(actual: envelope.sigVer, allowed: allowed))
        }

        let replayStore = enableReplayProtection ? (nonceStore ?? LocalEnvelopeReplayStore.shared) : nil
        let result = envelope.validate(signingKey: signingKey, nonceStore: replayStore, config: config)
        switch result {
        case .success:
            return .success(())
        case .failure(let error):
            return .failure(.reportEnvelope(error))
        }
    }

    /// 通过 keyId 动态解析签名密钥进行本地校验。
    public func validateSecureReportEnvelope(
        _ envelope: ReportEnvelope,
        keyResolver: (String) -> String?,
        allowedSignatureVersions: Set<String> = ["v2"],
        enableReplayProtection: Bool = true,
        nonceStore: NonceReplayProtecting? = nil,
        config: ReportEnvelope.Config = ReportEnvelope.Config()
    ) -> Result<Void, SecureEnvelopeValidationError> {
        guard let signingKey = keyResolver(envelope.keyId) else {
            return .failure(.unknownKeyId(envelope.keyId))
        }
        return validateSecureReportEnvelope(
            envelope,
            signingKey: signingKey,
            allowedSignatureVersions: allowedSignatureVersions,
            enableReplayProtection: enableReplayProtection,
            nonceStore: nonceStore,
            config: config
        )
    }

    /// 解析 JSON 并完成本地校验，成功时返回解析后的信封。
    public func validateSecureReportEnvelopeJSON(
        _ json: String,
        signingKey: String,
        allowedSignatureVersions: Set<String> = ["v2"],
        enableReplayProtection: Bool = true,
        nonceStore: NonceReplayProtecting? = nil,
        config: ReportEnvelope.Config = ReportEnvelope.Config()
    ) -> Result<ReportEnvelope, SecureEnvelopeValidationError> {
        guard let data = json.data(using: .utf8),
              let envelope = try? ReportEnvelope.fromJSON(data) else {
            return .failure(.invalidEnvelopeJSON)
        }

        switch validateSecureReportEnvelope(
            envelope,
            signingKey: signingKey,
            allowedSignatureVersions: allowedSignatureVersions,
            enableReplayProtection: enableReplayProtection,
            nonceStore: nonceStore,
            config: config
        ) {
        case .success:
            return .success(envelope)
        case .failure(let error):
            return .failure(error)
        }
    }
}
