import Foundation
import Security

/// 设备 ID 持久化（Keychain + UserDefaults 降级）
///
/// ## Keychain 可访问性（SDK 4.4 Phase 6）
/// - 使用 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` 实现设备绑定
/// - 不使用 `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`，避免无密码设备兼容性问题
/// - 多 App 共享：仅在需要跨 App 共享时添加 `kSecAttrAccessGroup`，默认不添加
///
/// ## App Store 换号场景（同一设备、不同 Apple ID 重装）
/// 用户更换 Apple ID 后通过 App Store 重装 App，系统可能清除该 App 的 Keychain 数据。
/// 此时：
/// - `read()` 返回 nil，`readFallback()` 若 UserDefaults 也被清除则返回 nil
/// - 会生成新的 UUID，并尝试写入 Keychain
/// - 若 Keychain 写入失败，返回 `ephemeral:<uuid>` 前缀 ID，服务端可识别并限制高信任请求
/// - 所有依赖 Keychain 的基线（SDKBinaryIntegrityChecker、TextSegmentIntegrityChecker 等）
///   在 Keychain 被清除后会自动重建，视为首次运行
///
/// ## ephemeral: 前缀
/// 当 Keychain 与 UserDefaults 两层存储均无法持久化时，返回 `ephemeral:<uuid>`。
/// 服务端可通过此前缀识别设备身份不可靠，限制高信任操作。
final class KeychainDeviceID {
    static let shared = KeychainDeviceID()
    private init() {}

    private let lock = NSLock()  // NSLock: Keychain I/O inside lock
    private let service = "CloudPhoneRiskKit"
    private let account = "device_id"
    /// SDK 4.4 Phase 6: 设备绑定，兼容无密码设备；避免 kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    private let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    private let defaults = UserDefaults.standard
    private let fallbackKey = "cloudphone_device_id_fallback_v1"
    private let fallbackHMACKey = "cloudphone_device_id_fallback_v1_hmac"
    private let fallbackHMACPurpose = "device_id_fallback"
    private let unavailableDeviceID = "CPRISKKIT-DEVICE-ID-UNAVAILABLE"

    func getOrCreate() -> String {
        lock.withLock {
            if let existing = read() {
                let usedFallback = saveFallback(existing)
                if usedFallback {
                    Logger.log("KeychainDeviceID: persisted device ID to fallback store (keychain primary read succeeded)")
                }
                return existing
            }

            if let fallback = readFallback() {
                if save(fallback) {
                    return fallback
                }
                // Keychain 写失败，仅 UserDefaults 有值：返回 ephemeral 前缀，服务端可识别并限制高信任请求
                Logger.log("KeychainDeviceID: keychain unavailable, using ephemeral-tagged fallback copy")
                return "ephemeral:\(fallback)"
            }

            let newID = UUID().uuidString
            let fallbackSaved = saveFallback(newID)
            if save(newID) {
                return newID
            }
            if fallbackSaved {
                Logger.log("KeychainDeviceID: keychain save failed, returning ephemeral-tagged fallback ID (fallback store used)")
                return "ephemeral:\(newID)"
            }
            // 并发写入竞争：再次尝试读取（另一线程可能已写入）
            if let retry = read() { return retry }
            Logger.log("KeychainDeviceID: save failed, returning ephemeral-tagged fallback ID (no fallback store)")
            return "ephemeral:\(newID)"
        }
    }

    private func read() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: accessible,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecInteractionNotAllowed {
            Logger.log("KeychainDeviceID.read: errSecInteractionNotAllowed (device locked or keychain unavailable)")
            return nil
        }
        if status == errSecAuthFailed {
            Logger.log("KeychainDeviceID.read: errSecAuthFailed (auth failed)")
            return nil
        }
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

        // SDK 4.4 Phase 6: ACL 使用 AfterFirstUnlockThisDeviceOnly，兼容无密码设备
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
        if status == errSecInteractionNotAllowed {
            Logger.log("KeychainDeviceID.save: errSecInteractionNotAllowed (device locked or keychain unavailable)")
            return saveFallback(data: data, query: query)
        }
        if status == errSecAuthFailed {
            Logger.log("KeychainDeviceID.save: errSecAuthFailed (auth failed)")
            return saveFallback(data: data, query: query)
        }
        if status != errSecItemNotFound { return saveFallback(data: data, query: query) }

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessControl as String] = accessControl
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess { return true }
        if addStatus == errSecInteractionNotAllowed {
            Logger.log("KeychainDeviceID.save: SecItemAdd errSecInteractionNotAllowed")
            return saveFallback(data: data, query: query)
        }
        if addStatus == errSecAuthFailed {
            Logger.log("KeychainDeviceID.save: SecItemAdd errSecAuthFailed")
            return saveFallback(data: data, query: query)
        }
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
