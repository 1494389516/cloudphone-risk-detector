import CryptoKit
import DeviceCheck
import Foundation
import Security

/// App Attest 硬件信任根签名器（SDK 4.4）
/// 使用 Secure Enclave 对 payload 摘要进行硬件签名，防止伪造。
/// SDK 4.4 Phase 6: Keychain 存 keyId，kSecAttrAccessibleWhenUnlockedThisDeviceOnly。
@available(iOS 14.0, macOS 11.0, *)
public enum AppAttestSigner {

    /// 是否支持 App Attest（真机 + 有效 App ID；模拟器/黑苹果/虚拟机返回 false）
    public static var isSupported: Bool {
        DCAppAttestService.shared.isSupported
    }

    /// 获取或创建 attestation key ID（不生成断言）
    public static func resolveKeyId() async throws -> String {
        try await getOrCreateKeyId()
    }

    /// 对 payload 数据生成硬件断言（内部计算 SHA256）
    /// - Parameter payloadData: 待签名数据（通常为 canonical payload）
    /// - Returns: (keyId, assertionData)
    public static func generateAssertion(for payloadData: Data) async throws -> (keyId: String, assertion: Data) {
        guard AppAttestSigner.isSupported else {
            throw AppAttestError.hardwareTrustUnsupported
        }
        let hash = SHA256.hash(data: payloadData)
        let payloadHash = Data(hash)
        guard payloadHash.count == 32 else {
            throw AppAttestError.invalidPayloadHashSize(payloadHash.count)
        }

        let keyId = try await getOrCreateKeyId()
        let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: payloadHash)
        return (keyId, assertion)
    }

    /// 对 payload 摘要生成断言（调用方已计算 SHA256，32 字节）
    public static func generateAssertion(forPayloadHash payloadHash: Data) async throws -> (keyId: String, assertion: Data) {
        guard payloadHash.count == 32 else {
            throw AppAttestError.invalidPayloadHashSize(payloadHash.count)
        }
        guard AppAttestSigner.isSupported else {
            throw AppAttestError.hardwareTrustUnsupported
        }
        let keyId = try await getOrCreateKeyId()
        let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: payloadHash)
        return (keyId, assertion)
    }

    // MARK: - Key Management

    private static let keychainService = "CloudPhoneRiskKit.AppAttest"
    private static let keychainAccount = "attestation_key_id"
    private static let attestationChallenge = Data("CloudPhoneRiskKit.AppAttest.KeyAttest.v1".utf8)
    private static let lock = UnfairLock()

    private static func getOrCreateKeyId() async throws -> String {
        if let existing = loadKeyId() {
            return existing
        }
        let keyId = try await DCAppAttestService.shared.generateKey()
        let clientDataHash = SHA256.hash(data: attestationChallenge)
        _ = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: Data(clientDataHash))
        if let winner = saveKeyId(keyId) {
            return winner
        }
        return keyId
    }

    private static func loadKeyId() -> String? {
        lock.withLock {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainAccount,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
            ]
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            guard status == errSecSuccess, let data = item as? Data, let str = String(data: data, encoding: .utf8) else {
                return nil
            }
            return str
        }
    }

    /// Add-only save: returns nil on success, or the existing keyId if another caller won the race.
    @discardableResult
    private static func saveKeyId(_ keyId: String) -> String? {
        lock.withLock {
            guard let data = keyId.data(using: .utf8) else { return nil }
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainAccount,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecValueData as String: data,
            ]
            let status = SecItemAdd(addQuery as CFDictionary, nil)
            if status == errSecSuccess { return nil }
            if status == errSecDuplicateItem, let existing = loadKeyIdLocked() {
                return existing
            }
            return nil
        }
    }

    /// Read keyId while the caller already holds `lock`.
    private static func loadKeyIdLocked() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data, let str = String(data: data, encoding: .utf8) else {
            return nil
        }
        return str
    }

    // MARK: - Error

    public enum AppAttestError: Error, LocalizedError {
        case hardwareTrustUnsupported
        case invalidPayloadHashSize(Int)

        public var errorDescription: String? {
            switch self {
            case .hardwareTrustUnsupported:
                return "App Attest 不支持（模拟器/黑苹果/虚拟机或无效 App ID）"
            case .invalidPayloadHashSize(let count):
                return "payloadHash 必须为 32 字节 (SHA256)，当前: \(count)"
            }
        }
    }
}
