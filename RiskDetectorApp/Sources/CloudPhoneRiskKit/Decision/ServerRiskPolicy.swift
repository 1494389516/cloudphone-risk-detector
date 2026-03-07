import CryptoKit
import Foundation

public struct ServerRiskPolicy: Codable, Sendable {
    public let version: Int
    public let signalWeights: [String: Double]
    public let thresholds: PolicyThresholds
    public let newVPhonePatterns: [String]
    public let blocklist: [String]
    public let mutation: MutationConfig?
    public let blindChallenge: BlindChallengeConfig?

    public struct PolicyThresholds: Codable, Sendable {
        public let block: Double
        public let challenge: Double
        public let monitor: Double

        public init(block: Double, challenge: Double, monitor: Double) {
            self.block = block
            self.challenge = challenge
            self.monitor = monitor
        }
    }

    public struct MutationConfig: Codable, Sendable {
        /// 服务端控制的变形种子，建议每版本更新。
        public let seed: String
        /// 是否打乱检测顺序。
        public let shuffleChecks: Bool
        /// 阈值抖动范围（basis points），如 1200 代表 ±12%。
        public let thresholdJitterBps: Int
        /// 打分抖动范围（basis points）。
        public let scoreJitterBps: Int

        public init(
            seed: String,
            shuffleChecks: Bool = true,
            thresholdJitterBps: Int = 0,
            scoreJitterBps: Int = 0
        ) {
            self.seed = seed
            self.shuffleChecks = shuffleChecks
            self.thresholdJitterBps = thresholdJitterBps
            self.scoreJitterBps = scoreJitterBps
        }
    }

    public struct BlindChallengeConfig: Codable, Sendable {
        public let enabled: Bool
        public let challengeSalt: String
        public let windowSeconds: Int
        /// 现场 challenge 可选探针池（beta.4）
        public let probePool: [String]
        /// challenge 有效期（毫秒）
        public let challengeTTLMillis: Int64
        public let rules: [BlindRule]

        public init(
            enabled: Bool = true,
            challengeSalt: String,
            windowSeconds: Int = 300,
            probePool: [String] = [],
            challengeTTLMillis: Int64 = 300_000,
            rules: [BlindRule]
        ) {
            self.enabled = enabled
            self.challengeSalt = challengeSalt
            self.windowSeconds = windowSeconds
            self.probePool = probePool
            self.challengeTTLMillis = challengeTTLMillis
            self.rules = rules
        }
    }

    public struct BlindRule: Codable, Sendable {
        /// 仅用于服务端回溯，不下发到客户端日志。
        public let id: String
        public let allOfSignalIDs: [String]
        public let anyOfSignalIDs: [String]
        public let minTamperedCount: Int
        public let minDistinctRiskLayers: Int
        public let requireCrossLayerInconsistency: Bool
        /// 最小能力探针异常数（beta.2 新增）
        public let minCapabilityAnomalyCount: Int
        public let weight: Double

        public init(
            id: String,
            allOfSignalIDs: [String] = [],
            anyOfSignalIDs: [String] = [],
            minTamperedCount: Int = 0,
            minDistinctRiskLayers: Int = 0,
            requireCrossLayerInconsistency: Bool = false,
            minCapabilityAnomalyCount: Int = 0,
            weight: Double = 75
        ) {
            self.id = id
            self.allOfSignalIDs = allOfSignalIDs
            self.anyOfSignalIDs = anyOfSignalIDs
            self.minTamperedCount = minTamperedCount
            self.minDistinctRiskLayers = minDistinctRiskLayers
            self.requireCrossLayerInconsistency = requireCrossLayerInconsistency
            self.minCapabilityAnomalyCount = minCapabilityAnomalyCount
            self.weight = weight
        }
    }

    public init(
        version: Int,
        signalWeights: [String: Double],
        thresholds: PolicyThresholds,
        newVPhonePatterns: [String] = [],
        blocklist: [String] = [],
        mutation: MutationConfig? = nil,
        blindChallenge: BlindChallengeConfig? = nil
    ) {
        self.version = version
        self.signalWeights = signalWeights
        self.thresholds = thresholds
        self.newVPhonePatterns = newVPhonePatterns
        self.blocklist = blocklist
        self.mutation = mutation
        self.blindChallenge = blindChallenge
    }
}

public final class PolicyManager: @unchecked Sendable {
    public static let shared = PolicyManager()

    private struct PolicyCacheEntry: Codable {
        let policy: ServerRiskPolicy
        let cachedAt: TimeInterval
        let isVerifiedByServer: Bool
        let contentHash: String?

        init(
            policy: ServerRiskPolicy,
            cachedAt: TimeInterval,
            isVerifiedByServer: Bool,
            contentHash: String? = nil
        ) {
            self.policy = policy
            self.cachedAt = cachedAt
            self.isVerifiedByServer = isVerifiedByServer
            self.contentHash = contentHash ?? Self.computeContentHash(for: policy)
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            policy = try container.decode(ServerRiskPolicy.self, forKey: .policy)
            cachedAt = (try? container.decodeIfPresent(TimeInterval.self, forKey: .cachedAt))
                ?? Date.distantPast.timeIntervalSince1970
            isVerifiedByServer = (try? container.decodeIfPresent(Bool.self, forKey: .isVerifiedByServer)) ?? false
            contentHash = try? container.decodeIfPresent(String.self, forKey: .contentHash)
        }

        fileprivate static func computeContentHash(for policy: ServerRiskPolicy) -> String? {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            guard let data = try? encoder.encode(policy) else { return nil }
            return SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
        }
    }

    private let lock = NSLock()
    private var cachedPolicy: ServerRiskPolicy?
    private let cacheKey = "com.cloudphone.riskkit.policy.v3"
    private let hmacCacheKey = "com.cloudphone.riskkit.policy.v3_hmac"
    private let verifiedKey = "com.cloudphone.riskkit.policy.v3_verified_flag"
    private let hmacPurpose = "policy_cache"
    private let cacheValidityDuration: TimeInterval = 86_400
    private var urlSession: URLSession

    private init() {
        self.urlSession = CertificatePinningSessionDelegate.pinnedSession(
            hashes: [],
            allowsSystemCA: false
        )
        self.cachedPolicy = loadFromCache()
    }

    public func configurePinning(hashes: Set<String>) {
        lock.lock()
        defer { lock.unlock() }
        urlSession = CertificatePinningSessionDelegate.pinnedSession(
            hashes: hashes,
            allowsSystemCA: false
        )
    }

    public var activePolicy: ServerRiskPolicy? {
        lock.lock()
        defer { lock.unlock() }
        return cachedPolicy
    }

    public func update(policy: ServerRiskPolicy) {
        update(policy: policy, verifiedByServer: false)
    }

    public func reloadTrustedCacheState() {
        let restored = loadFromCache()
        lock.lock()
        cachedPolicy = restored
        lock.unlock()
    }

    public func clear() {
        lock.lock()
        cachedPolicy = nil
        lock.unlock()
        UserDefaults.standard.removeObject(forKey: cacheKey)
        UserDefaults.standard.removeObject(forKey: hmacCacheKey)
        UserDefaults.standard.removeObject(forKey: verifiedKey)
    }

    @discardableResult
    public func update(fromJSON json: String) -> Bool {
#if DEBUG
        guard let data = json.data(using: .utf8) else { return false }
        guard let decoded = try? JSONDecoder().decode(ServerRiskPolicy.self, from: data) else {
            return false
        }
        update(policy: decoded)
        return true
#else
        Logger.log("PolicyManager.update(fromJSON:) rejected: not allowed in release build")
        return false
#endif
    }

    @available(iOS 13.0, macOS 10.15, *)
    public func fetchLatestPolicy(from url: URL) async throws -> ServerRiskPolicy {
        let (data, response) = try await urlSession.data(from: url)

        let signatureHex = (response as? HTTPURLResponse)?
            .value(forHTTPHeaderField: "X-Policy-Signature") ?? ""
        let verification = ConfigSignatureVerifier.verify(payload: data, signatureHex: signatureHex)
        if !verification.isValid {
            throw ConfigError.signatureVerificationFailed(reason: verification.reason ?? "unknown")
        }

        let policy = try JSONDecoder().decode(ServerRiskPolicy.self, from: data)
        update(policy: policy, verifiedByServer: ConfigSignatureVerifier.isConfigured && verification.isValid)
        return policy
    }

    private func update(policy: ServerRiskPolicy, verifiedByServer: Bool) {
        lock.lock()
        cachedPolicy = policy
        lock.unlock()
        persist(policy: policy, verifiedByServer: verifiedByServer)
    }

    private func persist(policy: ServerRiskPolicy, verifiedByServer: Bool) {
        let entry = PolicyCacheEntry(
            policy: policy,
            cachedAt: Date().timeIntervalSince1970,
            isVerifiedByServer: verifiedByServer
        )
        guard let encoded = try? JSONEncoder().encode(entry) else { return }
        #if DEBUG
        let stored = (try? PayloadCrypto.encrypt(encoded)) ?? encoded
        #else
        guard let stored = try? PayloadCrypto.encrypt(encoded) else {
            Logger.log("PolicyManager: encrypt failed, skipping save in release build")
            return
        }
        #endif
        UserDefaults.standard.set(stored, forKey: cacheKey)
        UserDefaults.standard.set(StorageIntegrityGuard.sign(stored, purpose: hmacPurpose), forKey: hmacCacheKey)
        UserDefaults.standard.set(verifiedByServer, forKey: verifiedKey)
    }

    private func loadFromCache() -> ServerRiskPolicy? {
        #if !DEBUG
        let wasVerified = UserDefaults.standard.bool(forKey: verifiedKey)
        if !wasVerified {
            Logger.log("PolicyManager.loadFromCache: skipping unverified cache in release build")
            return nil
        }
        #endif
        guard let stored = UserDefaults.standard.data(forKey: cacheKey) else { return nil }
        guard let signature = UserDefaults.standard.data(forKey: hmacCacheKey),
              StorageIntegrityGuard.verify(stored, signature: signature, purpose: hmacPurpose) else {
            UserDefaults.standard.removeObject(forKey: cacheKey)
            UserDefaults.standard.removeObject(forKey: hmacCacheKey)
            return nil
        }
        #if DEBUG
        let data: Data
        if let decrypted = try? PayloadCrypto.decrypt(stored) {
            data = decrypted
        } else {
            data = stored
        }
        #else
        guard let data = try? PayloadCrypto.decrypt(stored) else {
            Logger.log("PolicyManager: decrypt failed, clearing cache in release build")
            UserDefaults.standard.removeObject(forKey: cacheKey)
            UserDefaults.standard.removeObject(forKey: hmacCacheKey)
            return nil
        }
        #endif
        let entry = (try? JSONDecoder().decode(PolicyCacheEntry.self, from: data))
            ?? ((try? JSONDecoder().decode(ServerRiskPolicy.self, from: data)).map {
                PolicyCacheEntry(
                    policy: $0,
                    cachedAt: Date.distantPast.timeIntervalSince1970,
                    isVerifiedByServer: false,
                    contentHash: nil
                )
            })
        guard let entry, isUsableTrustedEntry(entry) else { return nil }
        return entry.policy
    }

    private func isUsableTrustedEntry(_ entry: PolicyCacheEntry) -> Bool {
        guard entry.contentHash == PolicyCacheEntry.computeContentHash(for: entry.policy) else {
#if DEBUG
            Logger.log("PolicyManager: content hash missing or mismatch, allowing cache only in debug")
            return true
#else
            Logger.log("PolicyManager: rejecting cache entry due to missing or mismatched content hash")
            return false
#endif
        }

        let age = Date().timeIntervalSince1970 - entry.cachedAt
#if DEBUG
        if age > cacheValidityDuration {
            Logger.log("PolicyManager: stale cache entry restored in debug, age=\(Int(age))s")
        }
        return true
#else
        guard ConfigSignatureVerifier.isConfigured else {
            Logger.log("PolicyManager: rejecting cache entry because signing key is not configured")
            return false
        }
        guard entry.isVerifiedByServer else {
            Logger.log("PolicyManager: rejecting unverified cache entry version=\(entry.policy.version)")
            return false
        }
        guard age <= cacheValidityDuration else {
            Logger.log("PolicyManager: rejecting stale cache entry version=\(entry.policy.version)")
            return false
        }
        return true
#endif
    }
}
