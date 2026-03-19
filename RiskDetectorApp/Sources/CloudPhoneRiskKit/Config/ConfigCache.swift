import CryptoKit
import Foundation

public protocol ConfigCaching: Sendable {
    func load() -> CachedConfig?
    func save(_ config: RemoteConfig)
    func save(_ config: RemoteConfig, verifiedByServer: Bool)
    func clear()
    func cacheSize() -> Int
    func cacheStats() -> CacheStats
}

extension ConfigCaching {
    public func save(_ config: RemoteConfig) {
        save(config, verifiedByServer: false)
    }
}

// Storage: sandboxed file with NSFileProtectionComplete via SecureFileStore.
// Migrated from UserDefaults to ensure data-at-rest encryption when device is locked.
public final class ConfigCache: @unchecked Sendable, ConfigCaching {
    public static let shared = ConfigCache()

    private struct CacheEntry: Codable {
        let config: RemoteConfig
        let cachedAt: TimeInterval
        let isVerifiedByServer: Bool
        let contentHash: String?

        private enum CodingKeys: String, CodingKey {
            case config = "c"
            case cachedAt = "ca"
            case isVerifiedByServer = "iv"
            case contentHash = "ch"
        }

        init(config: RemoteConfig, cachedAt: TimeInterval, isVerifiedByServer: Bool = false, contentHash: String? = nil) {
            self.config = config
            self.cachedAt = cachedAt
            self.isVerifiedByServer = isVerifiedByServer
            self.contentHash = contentHash ?? Self.computeContentHash(for: config)
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            config = try container.decode(RemoteConfig.self, forKey: .config)
            cachedAt = try container.decode(TimeInterval.self, forKey: .cachedAt)
            isVerifiedByServer = try container.decodeIfPresent(Bool.self, forKey: .isVerifiedByServer) ?? false
            contentHash = try container.decodeIfPresent(String.self, forKey: .contentHash)
        }

        fileprivate static func computeContentHash(for config: RemoteConfig) -> String? {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            guard let data = try? encoder.encode(config) else { return nil }
            return SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
        }
    }

    private static let globalLock = NSRecursiveLock()
    private var memoryCache: CacheEntry?
    private let diskKey: String
    private let hmacDiskKey: String
    private let versionKey: String
    private let rollbackVersionKey: String
    private let maxDiskEntries: Int
    private let persistToDisk: Bool
    private let fileStore: SecureFileStore

    private init(
        namespace: String? = nil,
        persistToDisk: Bool = true,
        maxDiskEntries: Int = 5
    ) {
        if let namespace, !namespace.isEmpty {
            self.diskKey = "com.cloudphone.riskkit.remote_config_cache.\(namespace)"
            self.hmacDiskKey = "com.cloudphone.riskkit.remote_config_cache.\(namespace)_hmac"
            self.versionKey = "com.cloudphone.riskkit.config_version.\(namespace)"
            self.rollbackVersionKey = "com.cloudphone.riskkit.config_rollback_version.\(namespace)"
        } else {
            self.diskKey = "com.cloudphone.riskkit.remote_config_cache"
            self.hmacDiskKey = "com.cloudphone.riskkit.remote_config_cache_hmac"
            self.versionKey = "com.cloudphone.riskkit.config_version"
            self.rollbackVersionKey = "com.cloudphone.riskkit.config_rollback_version"
        }
        self.persistToDisk = persistToDisk
        self.maxDiskEntries = maxDiskEntries
        self.fileStore = SecureFileStore.shared
        self.memoryCache = nil
        ConfigCache.globalLock.lock()
        self.memoryCache = loadLatestFromDisk()
        ConfigCache.globalLock.unlock()
    }

    public static func instance(withNamespace namespace: String) -> ConfigCache {
        ConfigCache(namespace: namespace, persistToDisk: true)
    }

    public static func inMemoryCache() -> ConfigCache {
        ConfigCache(namespace: "memory", persistToDisk: false)
    }

    public func load() -> CachedConfig? {
        ConfigCache.globalLock.lock()
        defer { ConfigCache.globalLock.unlock() }

        #if DEBUG
        let isUsable = { [self] (e: CacheEntry, s: String) in self.isUsableDebugEntry(e, source: s) }
        #else
        let isUsable = { [self] (e: CacheEntry, s: String) in self.isUsableTrustedEntry(e, source: s) }
        #endif
        if let memoryCache, isUsable(memoryCache, "memory_cache") {
            return CachedConfig(
                config: memoryCache.config,
                cachedAt: memoryCache.cachedAt,
                isVerifiedByServer: memoryCache.isVerifiedByServer,
                contentHash: memoryCache.contentHash
            )
        }
        memoryCache = nil

        if let latest = loadLatestFromDisk() {
            memoryCache = latest
            return CachedConfig(
                config: latest.config,
                cachedAt: latest.cachedAt,
                isVerifiedByServer: latest.isVerifiedByServer,
                contentHash: latest.contentHash
            )
        }

        return nil
    }

    public func save(_ config: RemoteConfig, verifiedByServer: Bool = false) {
        ConfigCache.globalLock.lock()
        defer { ConfigCache.globalLock.unlock() }

        let entry = CacheEntry(
            config: config,
            cachedAt: Date().timeIntervalSince1970,
            isVerifiedByServer: verifiedByServer
        )
        memoryCache = entry

        guard persistToDisk else { return }

        var entries = loadAllDiskEntries()
        entries.removeAll { $0.config.version == config.version }
        entries.append(entry)
        entries = entries.sorted { $0.config.version > $1.config.version }

        if entries.count > maxDiskEntries {
            entries = Array(entries.prefix(maxDiskEntries))
        }

        saveDiskEntries(entries)
        if let vData = "\(config.version)".data(using: .utf8) {
            fileStore.write(key: versionKey, data: vData)
        }
        fileStore.remove(key: rollbackVersionKey)
    }

    public func clear() {
        ConfigCache.globalLock.lock()
        defer { ConfigCache.globalLock.unlock() }

        memoryCache = nil
        guard persistToDisk else { return }
        fileStore.remove(key: diskKey)
        fileStore.remove(key: hmacDiskKey)
        fileStore.remove(key: versionKey)
        fileStore.remove(key: rollbackVersionKey)
    }

    public func cacheSize() -> Int {
        ConfigCache.globalLock.lock()
        defer { ConfigCache.globalLock.unlock() }

        guard persistToDisk,
              let data = fileStore.read(key: diskKey) else {
            return 0
        }
        return data.count
    }

    public func cacheStats() -> CacheStats {
        ConfigCache.globalLock.lock()
        defer { ConfigCache.globalLock.unlock() }

        return CacheStats(
            hasMemoryCache: memoryCache != nil,
            diskSizeBytes: cacheSizeUnlocked(),
            diskEntryCount: loadAllDiskEntries().count
        )
    }

    public func rollback(to version: Int) -> RemoteConfig? {
#if DEBUG
        ConfigCache.globalLock.lock()
        defer { ConfigCache.globalLock.unlock() }

        guard let target = loadAllDiskEntries().first(where: { $0.config.version == version }) else {
            return nil
        }

        memoryCache = target
        if persistToDisk, let data = "\(version)".data(using: .utf8) {
            fileStore.write(key: rollbackVersionKey, data: data)
        }
        return target.config
#else
        Logger.log("ConfigCache.rollback rejected: not allowed in release build")
        return nil
#endif
    }

    public func availableVersions() -> [Int] {
        ConfigCache.globalLock.lock()
        defer { ConfigCache.globalLock.unlock() }
        return loadAllDiskEntries().map { $0.config.version }.sorted(by: >)
    }

    public func versionHistory() -> [VersionHistoryEntry] {
        ConfigCache.globalLock.lock()
        defer { ConfigCache.globalLock.unlock() }

        return loadAllDiskEntries()
            .sorted { $0.cachedAt > $1.cachedAt }
            .map {
                VersionHistoryEntry(
                    version: $0.config.version,
                    timestamp: $0.cachedAt,
                    environment: $0.config.environment,
                    description: $0.config.description
                )
            }
    }

    public func migrate(from legacyData: Data, using migrator: (Data) throws -> RemoteConfig) throws {
        let config = try migrator(legacyData)
        save(config)
    }

    public func exportCache() -> Data? {
        ConfigCache.globalLock.lock()
        defer { ConfigCache.globalLock.unlock() }

        let entries = loadAllDiskEntries()
        let payload = CacheExport(exportedAt: Date().timeIntervalSince1970, entries: entries)
        return try? JSONEncoder().encode(payload)
    }

    public func importCache(from data: Data) throws {
#if DEBUG
        let decoded = try JSONDecoder().decode(CacheExport.self, from: data)
        for entry in decoded.entries {
            save(entry.config, verifiedByServer: false)
        }
#else
        Logger.log("ConfigCache.importCache rejected: not allowed in release build")
        throw ConfigError.importFailed(reason: "importCache not allowed in release build")
#endif
    }

    private struct CacheExport: Codable {
        let exportedAt: TimeInterval
        let entries: [CacheEntry]

        private enum CodingKeys: String, CodingKey {
            case exportedAt = "ea"
            case entries = "en"
        }
    }

    private func loadLatestFromDisk() -> CacheEntry? {
        guard persistToDisk else { return nil }
        let allEntries = loadAllDiskEntries()
        #if DEBUG
        let all = allEntries.filter { isUsableDebugEntry($0, source: "disk_cache") }
        #else
        let all = allEntries.filter { isUsableTrustedEntry($0, source: "disk_cache") }
        #endif
        if let rollbackData = fileStore.read(key: rollbackVersionKey),
           let rollbackStr = String(data: rollbackData, encoding: .utf8),
           let rollbackVer = Int(rollbackStr),
           let pinned = all.first(where: { $0.config.version == rollbackVer }) {
            return pinned
        }
        if let verified = all
            .filter({ $0.isVerifiedByServer })
            .max(by: { $0.config.version < $1.config.version }) {
            return verified
        }

#if DEBUG
        if let fallback = all.max(by: { $0.config.version < $1.config.version }) {
            Logger.log("⚠️ ConfigCache.loadLatestFromDisk: [DEBUG] using unverified cache entry version=\(fallback.config.version)")
            return fallback
        }
#else
        Logger.log("ConfigCache.loadLatestFromDisk: no verified cache entry in release build, returning nil")
#endif
        return nil
    }

    private func loadAllDiskEntries() -> [CacheEntry] {
        guard persistToDisk,
              let stored = fileStore.read(key: diskKey) else {
            return []
        }
        guard let signature = fileStore.read(key: hmacDiskKey),
              StorageIntegrityGuard.verify(stored, signature: signature, purpose: "config_cache") else {
            fileStore.remove(key: diskKey)
            fileStore.remove(key: hmacDiskKey)
            return []
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
            Logger.log("ConfigCache: decrypt failed, clearing cache in release build")
            fileStore.remove(key: diskKey)
            fileStore.remove(key: hmacDiskKey)
            return []
        }
        #endif
        return (try? JSONDecoder().decode([CacheEntry].self, from: data)) ?? []
    }

    private func saveDiskEntries(_ entries: [CacheEntry]) {
        guard persistToDisk,
              let encoded = try? JSONEncoder().encode(entries) else {
            return
        }
        #if DEBUG
        let stored = (try? PayloadCrypto.encrypt(encoded)) ?? encoded
        #else
        guard let stored = try? PayloadCrypto.encrypt(encoded) else {
            Logger.log("ConfigCache: encrypt failed, skipping save in release build")
            return
        }
        #endif
        fileStore.write(key: diskKey, data: stored)
        fileStore.write(key: hmacDiskKey, data: StorageIntegrityGuard.sign(stored, purpose: "config_cache"))
    }

    private func isUsableTrustedEntry(_ entry: CacheEntry, source: String) -> Bool {
        guard entry.contentHash == CacheEntry.computeContentHash(for: entry.config) else {
            Logger.log("ConfigCache.\(source): rejecting cache entry due to missing or mismatched content hash")
            return false
        }

        guard ConfigSignatureVerifier.isConfigured else {
            Logger.log("ConfigCache.\(source): rejecting cache entry because signing key is not configured")
            return false
        }
        guard entry.isVerifiedByServer else {
            Logger.log("ConfigCache.\(source): rejecting unverified cache entry version=\(entry.config.version)")
            return false
        }
        return true
    }

    #if DEBUG
    private func isUsableDebugEntry(_ entry: CacheEntry, source: String) -> Bool {
        if isUsableTrustedEntry(entry, source: source) {
            return true
        }
        Logger.log("⚠️ ConfigCache.\(source): [DEBUG] allowing unverified/untrusted cache entry version=\(entry.config.version) — this would be REJECTED in Release")
        return true
    }
    #endif

    private func cacheSizeUnlocked() -> Int {
        guard persistToDisk,
              let data = fileStore.read(key: diskKey) else {
            return 0
        }
        return data.count
    }
}

public struct CachedConfig: Sendable {
    public let config: RemoteConfig
    public let cachedAt: TimeInterval
    public let isVerifiedByServer: Bool
    public let contentHash: String?

    public func isExpired(duration: TimeInterval) -> Bool {
        Date().timeIntervalSince1970 - cachedAt > duration
    }

    public var age: TimeInterval {
        Date().timeIntervalSince1970 - cachedAt
    }
}

public struct CacheStats: Sendable {
    public let hasMemoryCache: Bool
    public let diskSizeBytes: Int
    public let diskEntryCount: Int

    public var diskSizeFormatted: String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useKB, .useMB]
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(diskSizeBytes))
    }
}

public struct VersionHistoryEntry: Codable, Sendable, Identifiable {
    public let id = UUID()
    public let version: Int
    public let timestamp: TimeInterval
    public let environment: ConfigEnvironment
    public let description: String?

    private enum CodingKeys: String, CodingKey {
        case id = "i"
        case version = "v"
        case timestamp = "ts"
        case environment = "ev"
        case description = "ds"
    }

    public var date: Date {
        Date(timeIntervalSince1970: timestamp)
    }

    public var formattedDate: String {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }
}

extension ConfigError {
    static func importFailed(reason: String) -> ConfigError {
        .validationFailed(underlying: NSError(domain: "ConfigCache", code: -1, userInfo: [
            NSLocalizedDescriptionKey: "Import failed: \(reason)"
        ]))
    }
}
