import Foundation
import CryptoKit
import Security

/// Server config signature verification. Verify is only valid after a successful configure.
public enum ConfigSignatureVerifier {

    public struct VerificationResult {
        public let isValid: Bool
        public let reason: String?
    }

    private static let lock = NSLock()
    private static let keychainService = "CloudPhoneRiskKit.ConfigSigning"
    private static let keychainAccount = "verification_key"
    private static let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    /// Configure with UTF-8 signing key. Returns false if keychain save failed; verify is only valid after true.
    @discardableResult
    public static func configure(serverSigningKey: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        var keyData = Data(serverSigningKey.utf8)
        defer { secureZeroData(&keyData) }
        let hashed = SHA256.hash(data: keyData)
        let keyBytes = Data(hashed)
        guard saveKeyToKeychain(keyBytes) else {
            Logger.log("ConfigSignatureVerifier.configure(serverSigningKey): keychain save failed")
            return false
        }
        return true
    }

    /// Configure with raw key data. Returns false if keychain save failed; verify is only valid after true.
    @discardableResult
    public static func configure(serverSigningKeyData: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        var keyData = serverSigningKeyData
        defer { secureZeroData(&keyData) }
        guard saveKeyToKeychain(keyData) else {
            Logger.log("ConfigSignatureVerifier.configure(serverSigningKeyData): keychain save failed")
            return false
        }
        return true
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
