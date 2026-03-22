import Foundation
import CryptoKit

/// HMAC 签名/校验，密钥存 Keychain。SDK 4.4 Phase 6: kSecAttrAccessibleWhenUnlockedThisDeviceOnly。
enum StorageIntegrityGuard {
    private static let keychainService = "CloudPhoneRiskKit.StorageHMAC"
    private static let keychainAccount = "hmac_key_v1"
    private static let lock = NSLock()  // NSLock: Keychain I/O inside lock

    static func sign(_ data: Data, purpose: String) -> Data {
        let key = getOrCreateKey()
        let purposeData = Data(purpose.utf8)
        var combined = Data()
        var length = UInt32(purposeData.count).bigEndian
        combined.append(Data(bytes: &length, count: 4))
        combined.append(purposeData)
        combined.append(data)
        let mac = HMAC<SHA256>.authenticationCode(for: combined, using: key)
        return Data(mac)
    }

    static func verify(_ data: Data, signature: Data, purpose: String) -> Bool {
        let key = getOrCreateKey()
        let purposeData = Data(purpose.utf8)
        var combined = Data()
        var length = UInt32(purposeData.count).bigEndian
        combined.append(Data(bytes: &length, count: 4))
        combined.append(purposeData)
        combined.append(data)
        return HMAC<SHA256>.isValidAuthenticationCode(signature, authenticating: combined, using: key)
    }

    private static func getOrCreateKey() -> SymmetricKey {
        lock.withLock {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainAccount,
                kSecReturnData as String: true,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]

            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)

            if status == errSecSuccess, let data = result as? Data {
                var mutableData = data
                let key = SymmetricKey(data: mutableData)
                secureZeroData(&mutableData)
                return key
            }

            let newKey = SymmetricKey(size: .bits256)
            var keyData = newKey.withUnsafeBytes { Data($0) }
            defer { secureZeroData(&keyData) }

            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainAccount,
                kSecValueData as String: keyData,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]

            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)

            if addStatus == errSecSuccess {
                return newKey
            }

            if addStatus == errSecDuplicateItem {
                var existing: AnyObject?
                if SecItemCopyMatching(query as CFDictionary, &existing) == errSecSuccess,
                   let existingData = existing as? Data {
                    var mutableExisting = existingData
                    let key = SymmetricKey(data: mutableExisting)
                    secureZeroData(&mutableExisting)
                    return key
                }
            }

            Logger.log("StorageIntegrityGuard: SecItemAdd failed with status \(addStatus)")
            return newKey
        }
    }
}
