import Foundation
import Security

/// Keychain-backed kv store for cross-session signal state.
///
/// 用途：让蜜罐 / baseline / invariant 类信号有"上次结果"作为对照系。
/// 例如本次启动算出 invariant_seal=ABC，上次启动是 XYZ —— 显著漂移就报警。
///
/// 设计选择：
///   - Service: "CloudPhoneRiskKit.LongitudinalState"
///   - Accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
///     （解锁后可用、不跨设备同步、不进 iCloud Keychain）
///   - 不做加密层 — Keychain 本身就有硬件后端保护；额外加密只是混淆
///   - 写入策略：先 Update，失败再 Add（原子化处理首次写）
enum LongitudinalStateStore {

    private static let service = "CloudPhoneRiskKit.LongitudinalState"
    private static let lock = NSLock()

    /// 读取 key 对应的 blob，不存在返回 nil。
    static func load(key: String) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            return nil
        }
        return data
    }

    /// 保存 key→value。已存在则覆盖。返回是否成功。
    @discardableResult
    static func save(key: String, value: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String: value,
        ]
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess {
            return true
        }
        if updateStatus == errSecItemNotFound {
            var addAttrs = baseQuery
            addAttrs[kSecValueData as String] = value
            addAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let addStatus = SecItemAdd(addAttrs as CFDictionary, nil)
            return addStatus == errSecSuccess
        }
        return false
    }

    /// 删除 key（用于测试 / 重置）。
    @discardableResult
    static func delete(key: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    // MARK: - String helpers

    static func loadString(key: String) -> String? {
        guard let data = load(key: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    @discardableResult
    static func saveString(key: String, value: String) -> Bool {
        guard let data = value.data(using: .utf8) else { return false }
        return save(key: key, value: data)
    }
}
