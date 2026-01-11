import CryptoKit
import Foundation
import Security

enum PayloadCrypto {
    private static let keyService = "CloudPhoneRiskKit"
    private static let keyAccount = "aes_gcm_key_v1"
    private static let accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    static func encrypt(_ plaintext: Data) throws -> Data {
        let key = try symmetricKey()
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else {
            throw NSError(domain: "CloudPhoneRiskKit", code: 2, userInfo: [NSLocalizedDescriptionKey: "AES.GCM combined unavailable"])
        }
        return combined
    }

    static func decrypt(_ combined: Data) throws -> Data {
        let key = try symmetricKey()
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key)
    }

    static func encrypt(_ plaintext: Data, rawKey: Data) throws -> Data {
        let key = SymmetricKey(data: rawKey)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else {
            throw NSError(domain: "CloudPhoneRiskKit", code: 2, userInfo: [NSLocalizedDescriptionKey: "AES.GCM combined unavailable"])
        }
        return combined
    }

    static func decrypt(_ combined: Data, rawKey: Data) throws -> Data {
        let key = SymmetricKey(data: rawKey)
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key)
    }

    private static func symmetricKey() throws -> SymmetricKey {
        if let data = readKey() {
            return SymmetricKey(data: data)
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw NSError(domain: "CloudPhoneRiskKit", code: 3, userInfo: [NSLocalizedDescriptionKey: "SecRandomCopyBytes failed (\(status))"])
        }
        let data = Data(bytes)
        _ = saveKey(data)
        return SymmetricKey(data: data)
    }

    private static func readKey() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keyService,
            kSecAttrAccount as String: keyAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return data
    }

    private static func saveKey(_ data: Data) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keyService,
            kSecAttrAccount as String: keyAccount,
        ]

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
}

