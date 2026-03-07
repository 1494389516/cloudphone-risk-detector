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

    private let lock = NSLock()
    private var cachedPolicy: ServerRiskPolicy?
    private let cacheKey = "com.cloudphone.riskkit.policy.v3"
    private let hmacCacheKey = "com.cloudphone.riskkit.policy.v3_hmac"
    private let hmacPurpose = "policy_cache"
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
        lock.lock()
        cachedPolicy = policy
        lock.unlock()
        persist(policy: policy)
    }

    public func clear() {
        lock.lock()
        cachedPolicy = nil
        lock.unlock()
        UserDefaults.standard.removeObject(forKey: cacheKey)
        UserDefaults.standard.removeObject(forKey: hmacCacheKey)
    }

    @discardableResult
    public func update(fromJSON json: String) -> Bool {
        guard let data = json.data(using: .utf8) else { return false }
        guard let decoded = try? JSONDecoder().decode(ServerRiskPolicy.self, from: data) else {
            return false
        }
        update(policy: decoded)
        return true
    }

    @available(iOS 13.0, macOS 10.15, *)
    public func fetchLatestPolicy(from url: URL) async throws -> ServerRiskPolicy {
        let (data, response) = try await urlSession.data(from: url)

        if ConfigSignatureVerifier.isConfigured {
            let signatureHex = (response as? HTTPURLResponse)?
                .value(forHTTPHeaderField: "X-Policy-Signature") ?? ""
            let result = ConfigSignatureVerifier.verify(payload: data, signatureHex: signatureHex)
            if !result.isValid {
                throw ConfigError.signatureVerificationFailed(reason: result.reason ?? "unknown")
            }
        }

        let policy = try JSONDecoder().decode(ServerRiskPolicy.self, from: data)
        update(policy: policy)
        return policy
    }

    private func persist(policy: ServerRiskPolicy) {
        guard let encoded = try? JSONEncoder().encode(policy) else { return }
        let stored = (try? PayloadCrypto.encrypt(encoded)) ?? encoded
        UserDefaults.standard.set(stored, forKey: cacheKey)
        UserDefaults.standard.set(StorageIntegrityGuard.sign(stored, purpose: hmacPurpose), forKey: hmacCacheKey)
    }

    private func loadFromCache() -> ServerRiskPolicy? {
        guard let stored = UserDefaults.standard.data(forKey: cacheKey) else { return nil }
        guard let signature = UserDefaults.standard.data(forKey: hmacCacheKey),
              StorageIntegrityGuard.verify(stored, signature: signature, purpose: hmacPurpose) else {
            UserDefaults.standard.removeObject(forKey: cacheKey)
            UserDefaults.standard.removeObject(forKey: hmacCacheKey)
            return nil
        }
        let data: Data
        if let decrypted = try? PayloadCrypto.decrypt(stored) {
            data = decrypted
        } else {
            data = stored
        }
        return try? JSONDecoder().decode(ServerRiskPolicy.self, from: data)
    }
}
