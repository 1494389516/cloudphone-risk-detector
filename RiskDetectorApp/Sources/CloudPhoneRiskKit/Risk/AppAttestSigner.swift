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
    private static let lock = NSLock()

    private static func getOrCreateKeyId() async throws -> String {
        if let existing = loadKeyId() {
            return existing
        }
        let keyId = try await DCAppAttestService.shared.generateKey()
        let clientDataHash = SHA256.hash(data: attestationChallenge)
        _ = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: Data(clientDataHash))
        saveKeyId(keyId)
        return keyId
    }

    private static func loadKeyId() -> String? {
        lock.lock()
        defer { lock.unlock() }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
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

    private static func saveKeyId(_ keyId: String) {
        lock.lock()
        defer { lock.unlock() }
        guard let data = keyId.data(using: .utf8) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data,
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
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
