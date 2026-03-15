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
        if !saveKeyToKeychain(keyBytes) {
            Logger.log("ConfigSignatureVerifier.configure(serverSigningKey): keychain save failed")
        }
    }

    public static func configure(serverSigningKeyData: Data) {
        lock.lock()
        defer { lock.unlock() }
        var keyData = serverSigningKeyData
        defer { secureZeroData(&keyData) }
        if !saveKeyToKeychain(keyData) {
            Logger.log("ConfigSignatureVerifier.configure(serverSigningKeyData): keychain save failed")
        }
    }

    public static var isConfigured: Bool {
        lock.lock()
        defer { lock.unlock() }
        return keychainHasKey()
    }

    public static var isConfiguredForDebug: Bool {
        #if DEBUG
        let configured = isConfigured
        if !configured {
            Logger.log("⚠️ ConfigSignatureVerifier: signing key not configured in DEBUG build — verify() will return isValid=false. Call configure() to set up signature verification.")
        }
        return configured
        #else
        return isConfigured
        #endif
    }

    public static func verify(payload: Data, signatureHex: String) -> VerificationResult {
        lock.lock()
        guard let keyBytes = readKeyFromKeychain() else {
            lock.unlock()
            #if DEBUG
            Logger.log("⚠️ ConfigSignatureVerifier.verify: not configured in DEBUG — returning isValid=false. Use isConfiguredForDebug to check setup.")
            #endif
            return VerificationResult(isValid: false, reason: "verification_not_configured")
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
            kSecAttrAccessible as String: accessible,
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
            kSecAttrAccessible as String: accessible,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return data
    }

    private static func saveKeyToKeychain(_ keyBytes: Data) -> Bool {
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
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            Logger.log("ConfigSignatureVerifier.saveKeyToKeychain: SecItemAdd failed (status=\(status)), key lost after Delete")
            return false
        }
        return true
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
