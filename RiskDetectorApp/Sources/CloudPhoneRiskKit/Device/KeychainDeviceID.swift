import Foundation
import Security

final class KeychainDeviceID {
    static let shared = KeychainDeviceID()
    private init() {}

    private let service = "CloudPhoneRiskKit"
    private let account = "device_id"
    private let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    private let defaults = UserDefaults.standard
    private let fallbackKey = "cloudphone_device_id_fallback_v1"
    private let fallbackHMACKey = "cloudphone_device_id_fallback_v1_hmac"
    private let fallbackHMACPurpose = "device_id_fallback"
    private let unavailableDeviceID = "CPRISKKIT-DEVICE-ID-UNAVAILABLE"

    func getOrCreate() -> String {
        if let existing = read() {
            _ = saveFallback(existing)
            return existing
        }

        if let fallback = readFallback() {
            if !save(fallback) {
                Logger.log("KeychainDeviceID: keychain unavailable, using signed fallback copy")
            }
            return fallback
        }

        let newID = UUID().uuidString
        let fallbackSaved = saveFallback(newID)
        if save(newID) {
            return newID
        }
        if fallbackSaved {
            Logger.log("KeychainDeviceID: keychain save failed, returning persisted fallback ID")
            return newID
        }
        // 并发写入竞争：再次尝试读取（另一线程可能已写入）
        if let retry = read() { return retry }
        // 两层存储均失败：返回带 ephemeral: 前缀的降级 ID，服务端可识别并拒绝高信任请求
        Logger.log("KeychainDeviceID: save failed, returning ephemeral-tagged fallback ID")
        return "ephemeral:\(newID)"
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

        // Create access control with device passcode protection (ACL)
        var aclError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [],
            &aclError
        ) else {
            return saveFallback(data: data, query: query)
        }

        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessControl as String: accessControl,
        ]

        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess { return true }
        if status != errSecItemNotFound { return saveFallback(data: data, query: query) }

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessControl as String] = accessControl
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess { return true }
        return saveFallback(data: data, query: query)
    }

    private func saveFallback(data: Data, query: [String: Any]) -> Bool {
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

    private func readFallback() -> String? {
        guard let data = defaults.data(forKey: fallbackKey),
              let signature = defaults.data(forKey: fallbackHMACKey),
              StorageIntegrityGuard.verify(data, signature: signature, purpose: fallbackHMACPurpose),
              let value = String(data: data, encoding: .utf8),
              !value.isEmpty else {
            defaults.removeObject(forKey: fallbackKey)
            defaults.removeObject(forKey: fallbackHMACKey)
            return nil
        }
        return value
    }

    @discardableResult
    private func saveFallback(_ value: String) -> Bool {
        let data = Data(value.utf8)
        let signature = StorageIntegrityGuard.sign(data, purpose: fallbackHMACPurpose)
        defaults.set(data, forKey: fallbackKey)
        defaults.set(signature, forKey: fallbackHMACKey)
        return defaults.data(forKey: fallbackKey) == data
    }
}
