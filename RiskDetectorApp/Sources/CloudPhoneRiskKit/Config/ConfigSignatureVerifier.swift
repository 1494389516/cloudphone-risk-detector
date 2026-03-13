import Foundation
import CryptoKit
import Security

public enum ConfigSignatureVerifier {

    public struct VerificationResult {
        public let isValid: Bool
        public let reason: String?
    }

    private static let lock = NSLock()
    private static let keychainService = "CloudPhoneRiskKit.ConfigSigning"
    private static let keychainAccount = "verification_key"
    private static let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    public static func configure(serverSigningKey: String) {
        lock.lock()
        defer { lock.unlock() }
        var keyData = Data(serverSigningKey.utf8)
        defer { secureZeroData(&keyData) }
        let hashed = SHA256.hash(data: keyData)
        let keyBytes = Data(hashed)
        saveKeyToKeychain(keyBytes)
    }

    public static func configure(serverSigningKeyData: Data) {
        lock.lock()
        defer { lock.unlock() }
        var keyData = serverSigningKeyData
        defer { secureZeroData(&keyData) }
        saveKeyToKeychain(keyData)
    }

    public static var isConfigured: Bool {
        lock.lock()
        defer { lock.unlock() }
        return keychainHasKey()
    }

    public static func verify(payload: Data, signatureHex: String) -> VerificationResult {
        lock.lock()
        guard let keyBytes = readKeyFromKeychain() else {
            lock.unlock()
            #if DEBUG
            return VerificationResult(isValid: true, reason: "verification_not_configured_debug")
            #else
            return VerificationResult(isValid: false, reason: "verification_not_configured")
            #endif
        }
        lock.unlock()

        var mutableKeyBytes = keyBytes
        defer { secureZeroData(&mutableKeyBytes) }
        let key = SymmetricKey(data: mutableKeyBytes)

        guard let signatureData = Data(hexString: signatureHex) else {
            return VerificationResult(isValid: false, reason: "invalid_signature_format")
        }

        let isValid = HMAC<SHA256>.isValidAuthenticationCode(
            signatureData,
            authenticating: payload,
            using: key
        )

        return VerificationResult(isValid: isValid, reason: isValid ? nil : "signature_mismatch")
    }

    // MARK: - Keychain Helpers

    private static func keychainHasKey() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: false,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return status == errSecSuccess
    }

    private static func readKeyFromKeychain() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return data
    }

    private static func saveKeyToKeychain(_ keyBytes: Data) {
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: keyBytes,
            kSecAttrAccessible as String: accessible,
        ]
        _ = SecItemAdd(addQuery as CFDictionary, nil)
    }
}

extension Data {
    init?(hexString: String) {
        let hex = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hex.count.isMultiple(of: 2) else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
