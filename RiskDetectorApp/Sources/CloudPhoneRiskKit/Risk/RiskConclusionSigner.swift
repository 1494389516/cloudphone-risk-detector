import CryptoKit
import Darwin
import Foundation
import Security

public struct SignedRiskConclusion: Codable, Sendable {
    public let score: Double
    public let isHighRisk: Bool
    public let timestamp: TimeInterval
    public let tampered: Bool
    public let nonce: String
    public let signature: String

    public static func sign(report: CPRiskReport, deviceKey: SymmetricKey) -> SignedRiskConclusion {
        let nonce = UUID().uuidString
        let timestamp = Date().timeIntervalSince1970
        let input = "\(report.score)|\(report.isHighRisk)|\(timestamp)|\(nonce)|\(report.tampered)"
        let hmac = SecureScope.withSecureBytes(Array(input.utf8)) { ptr in
            let data = Data(buffer: ptr)
            return HMAC<SHA256>.authenticationCode(for: data, using: deviceKey)
        }
        let sigHex = Data(hmac).map { String(format: "%02x", $0) }.joined()
        return SignedRiskConclusion(
            score: report.score,
            isHighRisk: report.isHighRisk,
            timestamp: timestamp,
            tampered: report.tampered,
            nonce: nonce,
            signature: sigHex
        )
    }

    public func verify(deviceKey: SymmetricKey, maxAgeSeconds: TimeInterval = 300) -> Bool {
        let age = Date().timeIntervalSince1970 - timestamp
        guard age >= 0, age <= maxAgeSeconds else { return false }

        let input = "\(score)|\(isHighRisk)|\(timestamp)|\(nonce)|\(tampered)"
        guard let signatureData = Data(hexString: signature) else { return false }
        return SecureScope.withSecureBytes(Array(input.utf8)) { ptr in
            let data = Data(buffer: ptr)
            return HMAC<SHA256>.isValidAuthenticationCode(signatureData, authenticating: data, using: deviceKey)
        }
    }
}

public enum DeviceKeyDeriver {
    /// 默认 DeviceKey 版本（v1），与 KeyRotationPolicy.deviceKeyVersion 对应
    public static let defaultInfoVersion = "v1"

    private static func info(for version: String) -> Data {
        Data("CloudPhoneRiskKit.DeviceKey.\(version)".utf8)
    }

    /// 派生 DeviceKey（使用默认版本 v1）
    public static func deriveKey(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String,
        salt: Data? = nil
    ) -> SymmetricKey {
        deriveKey(
            deviceID: deviceID,
            hardwareMachine: hardwareMachine,
            kernelVersion: kernelVersion,
            salt: salt,
            infoVersion: defaultInfoVersion
        )
    }

    /// 派生 DeviceKey（支持 infoVersion 可配置，用于密钥轮换）
    /// - Parameter infoVersion: 与 KeyRotationPolicy.deviceKeyVersion 对应，如 "v1"、"v2"
    public static func deriveKey(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String,
        salt: Data? = nil,
        infoVersion: String
    ) -> SymmetricKey {
        let (keychainSalt, _) = KeychainSalt.shared.getOrCreateWithPersistedFlag()
        let combined = "\(deviceID)|\(hardwareMachine)|\(kernelVersion)|\(keychainSalt)"
        return SecureScope.withSecureValue(combined) { str in
            var dataBytes = Array(str.utf8)
            defer { secureZeroBytes(&dataBytes) }
            let hash = SHA256.hash(data: Data(dataBytes))
            let inputKeyMaterial = SymmetricKey(data: Data(hash))
            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: inputKeyMaterial,
                salt: salt ?? Data(),
                info: info(for: infoVersion),
                outputByteCount: 32
            )
        }
    }

    /// 派生 DeviceKey，返回 (key, wasPersistedSalt)
    /// wasPersistedSalt 为 false 表示 Keychain 无持久化 salt（新建），TrustLevel 应为 .degraded
    public static func deriveKeyWithTrustInfo(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String,
        salt: Data? = nil,
        infoVersion: String = defaultInfoVersion
    ) -> (key: SymmetricKey, saltWasPersisted: Bool) {
        let (keychainSalt, wasPersisted) = KeychainSalt.shared.getOrCreateWithPersistedFlag()
        let combined = "\(deviceID)|\(hardwareMachine)|\(kernelVersion)|\(keychainSalt)"
        let key = SecureScope.withSecureValue(combined) { str in
            var dataBytes = Array(str.utf8)
            defer { secureZeroBytes(&dataBytes) }
            let hash = SHA256.hash(data: Data(dataBytes))
            let inputKeyMaterial = SymmetricKey(data: Data(hash))
            return HKDF<SHA256>.deriveKey(
                inputKeyMaterial: inputKeyMaterial,
                salt: salt ?? Data(),
                info: info(for: infoVersion),
                outputByteCount: 32
            )
        }
        return (key, wasPersisted)
    }
}

/// DeviceKey 派生盐，存 Keychain。SDK 4.4 Phase 6: kSecAttrAccessibleWhenUnlockedThisDeviceOnly。
private final class KeychainSalt {
    static let shared = KeychainSalt()
    private init() {}

    private let service = "CloudPhoneRiskKit"
    private let account = "device_key_salt"
    private let saltLength = 32
    private let lock = NSLock()

    func getOrCreate() -> String {
        getOrCreateWithPersistedFlag().0
    }

    /// 返回 (salt, wasPersisted)：wasPersisted 为 true 表示从 Keychain 读取到已有 salt
    func getOrCreateWithPersistedFlag() -> (String, Bool) {
        lock.lock()
        defer { lock.unlock() }

        if let existing = read() { return (existing, true) }

        var bytes = [UInt8](repeating: 0, count: saltLength)
        defer { secureZeroBytes(&bytes) }
        var status = SecRandomCopyBytes(kSecRandomDefault, saltLength, &bytes)
        if status != errSecSuccess {
            status = SecRandomCopyBytes(kSecRandomDefault, saltLength, &bytes)
        }
        if status != errSecSuccess {
            let fallback = "\(UUID().uuidString)\(mach_absolute_time())"
            let hash = SHA256.hash(data: Data(fallback.utf8))
            bytes = Array(hash.prefix(saltLength))
        }

        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        if let existing = save(hex) {
            return (existing, true)
        }
        return (hex, false)
    }

    private func read() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let dataObj = item as? Data else { return nil }
        var data = dataObj
        defer { secureZeroData(&data) }
        return String(data: data, encoding: .utf8)
    }

    private func save(_ value: String) -> String? {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess { return nil }

        if status == errSecDuplicateItem, let existing = read() {
            return existing
        }

        return nil
    }
}
