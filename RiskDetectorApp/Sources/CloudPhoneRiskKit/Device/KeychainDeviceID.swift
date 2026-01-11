import Foundation
import Security

final class KeychainDeviceID {
    static let shared = KeychainDeviceID()
    private init() {}

    private let service = "CloudPhoneRiskKit"
    private let account = "device_id"
    private let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    func getOrCreate() -> String {
        if let existing = read() { return existing }
        let newID = UUID().uuidString
        _ = save(newID)
        return newID
    }

    private func read() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func save(_ value: String) -> Bool {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]

        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]

        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess { return true }
        if status != errSecItemNotFound { return false }

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = accessible
        return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
    }
}
