import Foundation
import Security
import CryptoKit

// MARK: - Multi-Tenant Key Management

/// Per-tenant Keychain-backed key lifecycle manager with rotation, versioning, and emergency revocation.
///
/// Thread safety is provided by an internal `NSLock`; all public methods are safe to call
/// from any thread. Tenant isolation is enforced via Keychain access groups — each tenant's
/// keys are stored under a distinct service prefix so that one tenant cannot read another's material.
public final class TenantKeyManager: @unchecked Sendable {

    // MARK: - Types

    public enum KeyState: String, Codable, Sendable {
        /// Currently used for signing / encryption.
        case active
        /// Rotation target — will become active after the grace period.
        case pending
        /// Previous active key kept for verification during grace period.
        case retired
        /// Emergency-revoked — must not be used for any operation.
        case revoked
    }

    public struct ManagedKey: Codable, Sendable {
        public let keyID: String
        public let version: Int
        public let tenantID: String
        public var state: KeyState
        public let createdAt: Date
        public var activatedAt: Date?
        public var retiredAt: Date?
        public var revokedAt: Date?
        public var expiresAt: Date?
        public let algorithm: String

        public init(
            keyID: String = UUID().uuidString,
            version: Int,
            tenantID: String,
            state: KeyState = .pending,
            createdAt: Date = Date(),
            activatedAt: Date? = nil,
            retiredAt: Date? = nil,
            revokedAt: Date? = nil,
            expiresAt: Date? = nil,
            algorithm: String = "AES-256-GCM"
        ) {
            self.keyID = keyID
            self.version = version
            self.tenantID = tenantID
            self.state = state
            self.createdAt = createdAt
            self.activatedAt = activatedAt
            self.retiredAt = retiredAt
            self.revokedAt = revokedAt
            self.expiresAt = expiresAt
            self.algorithm = algorithm
        }
    }

    public enum KeyManagerError: Error, LocalizedError {
        case tenantNotFound(String)
        case keyNotFound(keyID: String)
        case noActiveKey(tenantID: String)
        case rotationInProgress(tenantID: String)
        case keyRevoked(keyID: String)
        case keychainError(OSStatus)
        case encodingError(Error)
        case invalidKeyMaterial
        case gracePeriodNotElapsed(remaining: TimeInterval)

        public var errorDescription: String? {
            switch self {
            case .tenantNotFound(let id):
                return "Tenant not found: \(id)"
            case .keyNotFound(let keyID):
                return "Key not found: \(keyID)"
            case .noActiveKey(let tenantID):
                return "No active key for tenant: \(tenantID)"
            case .rotationInProgress(let tenantID):
                return "Key rotation already in progress for tenant: \(tenantID)"
            case .keyRevoked(let keyID):
                return "Key has been revoked: \(keyID)"
            case .keychainError(let status):
                return "Keychain operation failed: \(status)"
            case .encodingError(let error):
                return "Encoding error: \(error.localizedDescription)"
            case .invalidKeyMaterial:
                return "Invalid or corrupted key material"
            case .gracePeriodNotElapsed(let remaining):
                return "Grace period not elapsed, \(Int(remaining))s remaining"
            }
        }
    }

    // MARK: - Configuration

    public struct Configuration: Sendable {
        public var keychainAccessGroup: String?
        public var defaultGracePeriod: TimeInterval
        public var defaultKeyTTL: TimeInterval
        public var maxRetiredKeysPerTenant: Int
        public var keychainServicePrefix: String

        public init(
            keychainAccessGroup: String? = nil,
            defaultGracePeriod: TimeInterval = 3600,
            defaultKeyTTL: TimeInterval = 86400 * 90,
            maxRetiredKeysPerTenant: Int = 3,
            keychainServicePrefix: String = "com.cloudphone.riskkit.tenant"
        ) {
            self.keychainAccessGroup = keychainAccessGroup
            self.defaultGracePeriod = defaultGracePeriod
            self.defaultKeyTTL = defaultKeyTTL
            self.maxRetiredKeysPerTenant = maxRetiredKeysPerTenant
            self.keychainServicePrefix = keychainServicePrefix
        }

        public static let `default` = Configuration()
    }

    // MARK: - Properties

    private let config: Configuration
    private let lock = NSLock()
    private var tenantKeys: [String: [ManagedKey]] = [:]

    // MARK: - Singleton

    public static let shared = TenantKeyManager()

    // MARK: - Init

    public init(configuration: Configuration = .default) {
        self.config = configuration
    }

    // MARK: - Tenant Registration

    /// Register a new tenant and generate the initial active key.
    @discardableResult
    public func registerTenant(_ tenantID: String) throws -> ManagedKey {
        lock.lock()
        defer { lock.unlock() }

        let keyMaterial = generateKeyMaterial()
        var key = ManagedKey(
            version: 1,
            tenantID: tenantID,
            state: .active,
            activatedAt: Date(),
            expiresAt: Date().addingTimeInterval(config.defaultKeyTTL)
        )

        try storeKeyMaterial(keyMaterial, for: key)
        key.state = .active
        tenantKeys[tenantID, default: []].append(key)
        return key
    }

    /// Remove all keys and state for a tenant.
    public func deregisterTenant(_ tenantID: String) throws {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }
        for key in keys {
            try? deleteKeyMaterial(for: key)
        }
        tenantKeys.removeValue(forKey: tenantID)
    }

    // MARK: - Key Retrieval

    /// Returns the currently active key for a tenant.
    public func activeKey(for tenantID: String) throws -> ManagedKey {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }
        guard let active = keys.first(where: { $0.state == .active }) else {
            throw KeyManagerError.noActiveKey(tenantID: tenantID)
        }
        return active
    }

    /// Returns all keys for a tenant (including retired/revoked).
    public func allKeys(for tenantID: String) throws -> [ManagedKey] {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }
        return keys
    }

    /// Retrieve raw key material from Keychain for a given managed key.
    public func keyMaterial(for managedKey: ManagedKey) throws -> Data {
        guard managedKey.state != .revoked else {
            throw KeyManagerError.keyRevoked(keyID: managedKey.keyID)
        }
        return try loadKeyMaterial(for: managedKey)
    }

    // MARK: - Key Rotation

    /// Begin key rotation: generate a new pending key.
    /// The current active key remains active until `commitRotation` is called.
    @discardableResult
    public func beginRotation(for tenantID: String) throws -> ManagedKey {
        lock.lock()
        defer { lock.unlock() }

        guard var keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }

        if keys.contains(where: { $0.state == .pending }) {
            throw KeyManagerError.rotationInProgress(tenantID: tenantID)
        }

        let currentVersion = keys.map(\.version).max() ?? 0
        let keyMaterial = generateKeyMaterial()
        let pendingKey = ManagedKey(
            version: currentVersion + 1,
            tenantID: tenantID,
            state: .pending,
            expiresAt: Date().addingTimeInterval(config.defaultKeyTTL)
        )

        try storeKeyMaterial(keyMaterial, for: pendingKey)
        keys.append(pendingKey)
        tenantKeys[tenantID] = keys
        return pendingKey
    }

    /// Commit rotation: activate the pending key, retire the current active key.
    /// Enforces grace period — the pending key must have existed for at least `gracePeriod`.
    @discardableResult
    public func commitRotation(
        for tenantID: String,
        gracePeriod: TimeInterval? = nil
    ) throws -> ManagedKey {
        lock.lock()
        defer { lock.unlock() }

        guard var keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }

        guard let pendingIndex = keys.firstIndex(where: { $0.state == .pending }) else {
            throw KeyManagerError.keyNotFound(keyID: "pending")
        }

        let effectiveGrace = gracePeriod ?? config.defaultGracePeriod
        let elapsed = Date().timeIntervalSince(keys[pendingIndex].createdAt)
        if elapsed < effectiveGrace {
            throw KeyManagerError.gracePeriodNotElapsed(remaining: effectiveGrace - elapsed)
        }

        let now = Date()

        if let activeIndex = keys.firstIndex(where: { $0.state == .active }) {
            keys[activeIndex].state = .retired
            keys[activeIndex].retiredAt = now
        }

        keys[pendingIndex].state = .active
        keys[pendingIndex].activatedAt = now

        pruneRetiredKeys(&keys)
        tenantKeys[tenantID] = keys

        return keys[pendingIndex]
    }

    /// Cancel an in-progress rotation, removing the pending key.
    public func cancelRotation(for tenantID: String) throws {
        lock.lock()
        defer { lock.unlock() }

        guard var keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }

        if let pendingIndex = keys.firstIndex(where: { $0.state == .pending }) {
            try? deleteKeyMaterial(for: keys[pendingIndex])
            keys.remove(at: pendingIndex)
            tenantKeys[tenantID] = keys
        }
    }

    // MARK: - Emergency Revocation

    /// Immediately revoke a specific key. If the revoked key is active, the tenant
    /// will have no active key until a new one is rotated in.
    public func revokeKey(_ keyID: String, tenantID: String) throws {
        lock.lock()
        defer { lock.unlock() }

        guard var keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }

        guard let index = keys.firstIndex(where: { $0.keyID == keyID }) else {
            throw KeyManagerError.keyNotFound(keyID: keyID)
        }

        keys[index].state = .revoked
        keys[index].revokedAt = Date()

        try deleteKeyMaterial(for: keys[index])
        tenantKeys[tenantID] = keys
    }

    /// Revoke ALL keys for a tenant (emergency wipe). Caller must register new keys after.
    public func revokeAllKeys(for tenantID: String) throws {
        lock.lock()
        defer { lock.unlock() }

        guard var keys = tenantKeys[tenantID] else {
            throw KeyManagerError.tenantNotFound(tenantID)
        }

        let now = Date()
        for i in keys.indices {
            keys[i].state = .revoked
            keys[i].revokedAt = now
            try? deleteKeyMaterial(for: keys[i])
        }
        tenantKeys[tenantID] = keys
    }

    // MARK: - Key Lifecycle Queries

    /// Check whether a tenant has an active, non-expired key.
    public func hasValidActiveKey(for tenantID: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else { return false }
        return keys.contains { key in
            key.state == .active && (key.expiresAt.map { $0 > Date() } ?? true)
        }
    }

    /// Returns keys that are approaching expiration within the given horizon.
    public func expiringKeys(
        for tenantID: String,
        within horizon: TimeInterval = 86400 * 7
    ) -> [ManagedKey] {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else { return [] }
        let cutoff = Date().addingTimeInterval(horizon)
        return keys.filter { key in
            key.state == .active && (key.expiresAt.map { $0 < cutoff } ?? false)
        }
    }

    /// Summary of key states for a tenant.
    public func keyStateSummary(for tenantID: String) -> [KeyState: Int] {
        lock.lock()
        defer { lock.unlock() }

        guard let keys = tenantKeys[tenantID] else { return [:] }
        var counts: [KeyState: Int] = [:]
        for key in keys {
            counts[key.state, default: 0] += 1
        }
        return counts
    }

    // MARK: - Private — Keychain Operations

    private func keychainService(for key: ManagedKey) -> String {
        "\(config.keychainServicePrefix).\(key.tenantID)"
    }

    private func keychainAccount(for key: ManagedKey) -> String {
        "key_v\(key.version)_\(key.keyID)"
    }

    private func storeKeyMaterial(_ data: Data, for key: ManagedKey) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService(for: key),
            kSecAttrAccount as String: keychainAccount(for: key),
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        if let group = config.keychainAccessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let updateQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService(for: key),
                kSecAttrAccount as String: keychainAccount(for: key),
            ]
            let updateAttributes: [String: Any] = [
                kSecValueData as String: data,
            ]
            let updateStatus = SecItemUpdate(
                updateQuery as CFDictionary,
                updateAttributes as CFDictionary
            )
            guard updateStatus == errSecSuccess else {
                throw KeyManagerError.keychainError(updateStatus)
            }
        } else if status != errSecSuccess {
            throw KeyManagerError.keychainError(status)
        }
    }

    private func loadKeyMaterial(for key: ManagedKey) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService(for: key),
            kSecAttrAccount as String: keychainAccount(for: key),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let group = config.keychainAccessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            if status == errSecItemNotFound {
                throw KeyManagerError.keyNotFound(keyID: key.keyID)
            }
            throw KeyManagerError.keychainError(status)
        }
        return data
    }

    private func deleteKeyMaterial(for key: ManagedKey) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService(for: key),
            kSecAttrAccount as String: keychainAccount(for: key),
        ]
        if let group = config.keychainAccessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeyManagerError.keychainError(status)
        }
    }

    // MARK: - Private — Key Generation

    private func generateKeyMaterial() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed: \(status)")
        return Data(bytes)
    }

    // MARK: - Private — Housekeeping

    private func pruneRetiredKeys(_ keys: inout [ManagedKey]) {
        let retired = keys
            .enumerated()
            .filter { $0.element.state == .retired }
            .sorted { ($0.element.retiredAt ?? .distantPast) < ($1.element.retiredAt ?? .distantPast) }

        if retired.count > config.maxRetiredKeysPerTenant {
            let excess = retired.prefix(retired.count - config.maxRetiredKeysPerTenant)
            for item in excess {
                try? deleteKeyMaterial(for: item.element)
                keys[item.offset].state = .revoked
                keys[item.offset].revokedAt = Date()
            }
        }
    }
}
