import CryptoKit
import Foundation
import Security

/// AES-GCM 载荷加解密，密钥存 Keychain。
/// SDK 4.4 Phase 6: kSecAttrAccessibleWhenUnlockedThisDeviceOnly（设备绑定，兼容无密码设备）
enum PayloadCrypto {
    private static let keyService = "CloudPhoneRiskKit"
    private static let keyAccount = "aes_gcm_key_v1"
    private static let accessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    private static let lock = NSLock()

    /// 加密载荷的 magic 标识字节，用于区分密文与明文，防止静默降级
    static let encryptedMagic: UInt8 = 0xAE

    static func encrypt(_ plaintext: Data) throws -> Data {
        if arc4random_uniform(10) == 0 {
            let (malicious, _) = CallStackUnwinder.validateCallStack()
            if malicious {
                throw NSError(domain: "CloudPhoneRiskKit", code: 10, userInfo: [NSLocalizedDescriptionKey: "Call stack validation failed (rop_chain_detected)"])
            }
        }
        let key = try symmetricKey()
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else {
            throw NSError(domain: "CloudPhoneRiskKit", code: 2, userInfo: [NSLocalizedDescriptionKey: "AES.GCM combined unavailable"])
        }
        var result = Data([encryptedMagic])
        result.append(combined)
        return result
    }

    static func decrypt(_ combined: Data) throws -> Data {
        if arc4random_uniform(10) == 0 {
            let (malicious, _) = CallStackUnwinder.validateCallStack()
            if malicious {
                throw NSError(domain: "CloudPhoneRiskKit", code: 11, userInfo: [NSLocalizedDescriptionKey: "Call stack validation failed (rop_chain_detected)"])
            }
        }
        guard !combined.isEmpty, combined[combined.startIndex] == encryptedMagic else {
            throw NSError(
                domain: "CloudPhoneRiskKit",
                code: 4,
                userInfo: [NSLocalizedDescriptionKey: "Not an encrypted payload (missing magic header)"]
            )
        }
        let key = try symmetricKey()
        let cipherData = Data(combined.dropFirst())
        let box = try AES.GCM.SealedBox(combined: cipherData)
        return try AES.GCM.open(box, using: key)
    }

    static func encrypt(_ plaintext: Data, rawKey: Data) throws -> Data {
        guard rawKey.count == 16 || rawKey.count == 24 || rawKey.count == 32 else {
            throw NSError(domain: "PayloadCrypto", code: -1, userInfo: [NSLocalizedDescriptionKey: "rawKey must be 16, 24, or 32 bytes"])
        }
        let key = SymmetricKey(data: rawKey)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else {
            throw NSError(domain: "CloudPhoneRiskKit", code: 2, userInfo: [NSLocalizedDescriptionKey: "AES.GCM combined unavailable"])
        }
        return combined
    }

    static func decrypt(_ combined: Data, rawKey: Data) throws -> Data {
        guard rawKey.count == 16 || rawKey.count == 24 || rawKey.count == 32 else {
            throw NSError(domain: "PayloadCrypto", code: -1, userInfo: [NSLocalizedDescriptionKey: "rawKey must be 16, 24, or 32 bytes"])
        }
        let key = SymmetricKey(data: rawKey)
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key)
    }

    private static func symmetricKey() throws -> SymmetricKey {
        lock.lock()
        defer { lock.unlock() }

        if var keyData = try readKey() {
            let key = SymmetricKey(data: keyData)
            secureZeroData(&keyData)
            return key
        }
        var secureData: Data?
        _ = SecureBuffer(size: 32).use { ptr in
            let status = SecRandomCopyBytes(kSecRandomDefault, 32, ptr)
            guard status == errSecSuccess else { return }
            secureData = Data(UnsafeRawBufferPointer(start: ptr, count: 32))
        }
        guard var data = secureData else {
            throw NSError(domain: "CloudPhoneRiskKit", code: 3, userInfo: [NSLocalizedDescriptionKey: "SecRandomCopyBytes failed"])
        }
        defer { secureZeroData(&data) }
        if let existing = try saveKey(data) {
            return SymmetricKey(data: existing)
        }
        return SymmetricKey(data: data)
    }

    private static func readKey() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keyService,
            kSecAttrAccount as String: keyAccount,
            kSecAttrAccessible as String: accessible,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecInteractionNotAllowed {
            throw NSError(domain: "PayloadCrypto", code: Int(errSecInteractionNotAllowed))
        }
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return data
    }

    private static func saveKey(_ data: Data) throws -> Data? {
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keyService,
            kSecAttrAccount as String: keyAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessible,
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecInteractionNotAllowed {
            throw NSError(domain: "PayloadCrypto", code: Int(errSecInteractionNotAllowed))
        }
        if status == errSecSuccess { return nil }

        if status == errSecDuplicateItem, let existing = try readKey() {
            return existing
        }

        Logger.log("PayloadCrypto: saveKey failed with unexpected status \(status) — key will not be persisted")
        throw NSError(
            domain: "PayloadCrypto",
            code: Int(status),
            userInfo: [NSLocalizedDescriptionKey: "SecItemAdd failed with status \(status)"]
        )
    }
}

