import Foundation
import CryptoKit
import Security

/// Server config signature verification. Verify is only valid after a successful configure.
public enum ConfigSignatureVerifier {

    public struct VerificationResult {
        public let isValid: Bool
        public let reason: String?
    }

    private static let lock = UnfairLock()
    private static let keychainService = "CloudPhoneRiskKit.ConfigSigning"
    private static let keychainAccount = "verification_key"
    private static let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
#if DEBUG
    // Simulator / CI may not expose usable Keychain entitlements (-34018).
    // Keep a process-local fallback so verification semantics remain testable.
    private static var debugInMemoryKeys: [String: Data] = [:]
#endif

    /// Configure with UTF-8 signing key. Returns false if keychain save failed; verify is only valid after true.
    @discardableResult
    public static func configure(serverSigningKey: String) -> Bool {
        lock.withLock {
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
    }

    /// Configure with raw key data. The key is hashed with SHA-256 before storage,
    /// consistent with the string variant. Returns false if keychain save failed.
    @discardableResult
    public static func configure(serverSigningKeyData: Data) -> Bool {
        lock.withLock {
            var keyData = serverSigningKeyData
            defer { secureZeroData(&keyData) }
            let hashed = SHA256.hash(data: keyData)
            let keyBytes = Data(hashed)
            guard saveKeyToKeychain(keyBytes) else {
                Logger.log("ConfigSignatureVerifier.configure(serverSigningKeyData): keychain save failed")
                return false
            }
            return true
        }
    }

    public static var isConfigured: Bool {
        lock.withLock { keychainHasKey() }
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
        // 优先尝试 Ed25519 非对称验签（更安全：SDK 仅嵌入公钥，无法伪造签名）
        if let ed25519Result = verifyEd25519(payload: payload, signatureHex: signatureHex) {
            return ed25519Result
        }

        // 回退到自定义 pad 的 SHA-256 MAC 对称验签（兼容旧配置接口）
        let keyBytes: Data? = lock.withLock { readKeyFromKeychain() }
        guard let keyBytes else {
            #if DEBUG
            Logger.log("⚠️ ConfigSignatureVerifier.verify: not configured in DEBUG — returning isValid=false. Use isConfiguredForDebug to check setup.")
            #endif
            return VerificationResult(isValid: false, reason: "verification_not_configured")
        }

        var mutableKeyBytes = keyBytes
        defer { secureZeroData(&mutableKeyBytes) }

        guard let signatureData = Data(hexString: signatureHex) else {
            return VerificationResult(isValid: false, reason: "invalid_signature_format")
        }

        let isValid = CPRiskMessageAuth.isValidAuthenticationCode(signatureData, authenticating: payload, keyData: mutableKeyBytes)

        return VerificationResult(isValid: isValid, reason: isValid ? nil : "signature_mismatch")
    }

    // MARK: - Ed25519 非对称签名

    private static let ed25519KeychainAccount = "ed25519_verification_pubkey"

    /// 配置 Ed25519 公钥用于配置签名验证（推荐：SDK 仅持有公钥，无法伪造配置）
    @discardableResult
    public static func configureEd25519PublicKey(_ publicKeyBytes: Data) -> Bool {
        lock.withLock {
            guard publicKeyBytes.count == 32 else {
                Logger.log("ConfigSignatureVerifier.configureEd25519: invalid key size \(publicKeyBytes.count), expected 32")
                return false
            }
            // 验证公钥格式合法性
            guard (try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyBytes)) != nil else {
                Logger.log("ConfigSignatureVerifier.configureEd25519: invalid Ed25519 public key format")
                return false
            }
            return saveToKeychain(publicKeyBytes, account: ed25519KeychainAccount)
        }
    }

    /// 配置 Ed25519 公钥（hex 编码）
    @discardableResult
    public static func configureEd25519PublicKey(hex: String) -> Bool {
        guard let keyData = Data(hexString: hex), keyData.count == 32 else {
            Logger.log("ConfigSignatureVerifier.configureEd25519(hex): invalid hex or wrong length")
            return false
        }
        return configureEd25519PublicKey(keyData)
    }

    public static var isEd25519Configured: Bool {
        lock.withLock { readFromKeychain(account: ed25519KeychainAccount) != nil }
    }

    private static func verifyEd25519(payload: Data, signatureHex: String) -> VerificationResult? {
        let pubKeyBytes: Data? = lock.withLock { readFromKeychain(account: ed25519KeychainAccount) }
        guard let pubKeyBytes else {
            return nil // Ed25519 未配置，回退到 HMAC
        }

        guard let signatureData = Data(hexString: signatureHex) else {
            return VerificationResult(isValid: false, reason: "invalid_signature_format")
        }

        // Ed25519 签名长度为 64 字节；若不是，拒绝而非回退到 HMAC（防止降级攻击）
        guard signatureData.count == 64 else {
            return VerificationResult(isValid: false, reason: "ed25519_configured_but_signature_not_64_bytes")
        }

        do {
            let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: pubKeyBytes)
            let isValid = publicKey.isValidSignature(signatureData, for: payload)
            return VerificationResult(
                isValid: isValid,
                reason: isValid ? nil : "ed25519_signature_mismatch"
            )
        } catch {
            Logger.log("ConfigSignatureVerifier.verifyEd25519: key reconstruction failed: \(error)")
            return VerificationResult(isValid: false, reason: "ed25519_key_error")
        }
    }

    // MARK: - Keychain Helpers

    private static func keychainHasKey() -> Bool {
        readFromKeychain(account: keychainAccount) != nil
    }

    private static func readKeyFromKeychain() -> Data? {
        readFromKeychain(account: keychainAccount)
    }

    private static func saveKeyToKeychain(_ keyBytes: Data) -> Bool {
        saveToKeychain(keyBytes, account: keychainAccount)
    }

    private static func readFromKeychain(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let data = item as? Data {
            return data
        }
#if DEBUG
        if keychainStatusIndicatesUnavailable(status) {
            return debugInMemoryKeys[account]
        }
#endif
        return nil
    }

    private static func saveToKeychain(_ data: Data, account: String) -> Bool {
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecSuccess {
            return true
        }
#if DEBUG
        if keychainStatusIndicatesUnavailable(status) {
            debugInMemoryKeys[account] = data
            return true
        }
#endif
        guard status == errSecSuccess else {
            Logger.log("ConfigSignatureVerifier.saveToKeychain(\(account)): SecItemAdd failed (status=\(status))")
            return false
        }
        return true
    }

    private static func keychainStatusIndicatesUnavailable(_ status: OSStatus) -> Bool {
        if status == errSecInteractionNotAllowed ||
            status == errSecMissingEntitlement ||
            status == errSecNotAvailable {
            return true
        }
        #if DEBUG && os(macOS)
        // SwiftPM/XCTest hosts without a usable login keychain can surface
        // keychain unavailability as errSecParam. Keep this out of iOS and
        // all Release builds so real query bugs do not become production fallback.
        return status == errSecParam
        #else
        return false
        #endif
    }
}

extension Data {
    init?(hexString: String) {
        let hex = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hex.count.isMultiple(of: 2) else { return nil }
        if hex.isEmpty {
            self = Data()
            return
        }
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
