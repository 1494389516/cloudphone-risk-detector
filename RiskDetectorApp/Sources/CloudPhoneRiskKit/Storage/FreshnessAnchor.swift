import Foundation
import Security

struct FreshnessState: Codable, Sendable {
    var latestTimestamp: Double
    var sequence: UInt64

    static let zero = FreshnessState(latestTimestamp: 0, sequence: 0)

    func dominates(_ other: FreshnessState) -> Bool {
        sequence >= other.sequence && latestTimestamp >= other.latestTimestamp
    }
}

final class FreshnessAnchor {
    private let service = "CloudPhoneRiskKit.FreshnessAnchor"
    private let account: String
    private let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    private let lock = NSLock()

    init(account: String) {
        self.account = account
    }

    func read() -> FreshnessState? {
        lock.lock()
        defer { lock.unlock() }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return try? JSONDecoder().decode(FreshnessState.self, from: data)
    }

    func write(_ state: FreshnessState) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard let data = try? JSONEncoder().encode(state) else {
            return false
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess {
            return true
        }
        if updateStatus != errSecItemNotFound {
            return false
        }

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = accessible
        return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
    }

    func remove() {
        lock.lock()
        defer { lock.unlock() }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
