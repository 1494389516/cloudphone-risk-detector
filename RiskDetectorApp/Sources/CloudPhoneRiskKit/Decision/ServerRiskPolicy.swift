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
        public let rules: [BlindRule]

        public init(
            enabled: Bool = true,
            challengeSalt: String,
            windowSeconds: Int = 300,
            rules: [BlindRule]
        ) {
            self.enabled = enabled
            self.challengeSalt = challengeSalt
            self.windowSeconds = windowSeconds
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
        public let weight: Double

        public init(
            id: String,
            allOfSignalIDs: [String] = [],
            anyOfSignalIDs: [String] = [],
            minTamperedCount: Int = 0,
            minDistinctRiskLayers: Int = 0,
            requireCrossLayerInconsistency: Bool = false,
            weight: Double = 75
        ) {
            self.id = id
            self.allOfSignalIDs = allOfSignalIDs
            self.anyOfSignalIDs = anyOfSignalIDs
            self.minTamperedCount = minTamperedCount
            self.minDistinctRiskLayers = minDistinctRiskLayers
            self.requireCrossLayerInconsistency = requireCrossLayerInconsistency
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

    private init() {
        self.cachedPolicy = loadFromCache()
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
        let (data, _) = try await URLSession.shared.data(from: url)
        let policy = try JSONDecoder().decode(ServerRiskPolicy.self, from: data)
        update(policy: policy)
        return policy
    }

    private func persist(policy: ServerRiskPolicy) {
        guard let data = try? JSONEncoder().encode(policy) else { return }
        UserDefaults.standard.set(data, forKey: cacheKey)
    }

    private func loadFromCache() -> ServerRiskPolicy? {
        guard let data = UserDefaults.standard.data(forKey: cacheKey) else { return nil }
        return try? JSONDecoder().decode(ServerRiskPolicy.self, from: data)
    }
}
