import CryptoKit
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
        let data = Data(input.utf8)
        let hmac = HMAC<SHA256>.authenticationCode(for: data, using: deviceKey)
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
        let data = Data(input.utf8)
        guard let signatureData = Data(hexString: signature) else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(signatureData, authenticating: data, using: deviceKey)
    }
}

public enum DeviceKeyDeriver {
    private static let infoVersion = 1
    private static var info: Data {
        Data("CloudPhoneRiskKit.DeviceKey.v\(infoVersion)".utf8)
    }

    public static func deriveKey(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String,
        salt: Data? = nil
    ) -> SymmetricKey {
        let keychainSalt = KeychainSalt.shared.getOrCreate()
        let combined = "\(deviceID)|\(hardwareMachine)|\(kernelVersion)|\(keychainSalt)"
        let combinedData = Data(combined.utf8)
        let hash = SHA256.hash(data: combinedData)
        let inputKeyMaterial = SymmetricKey(data: Data(hash))
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt ?? Data(),
            info: info,
            outputByteCount: 32
        )
        return derivedKey
    }
}

private final class KeychainSalt {
    static let shared = KeychainSalt()
    private init() {}

    private let service = "CloudPhoneRiskKit"
    private let account = "device_key_salt"
    private let saltLength = 32
    private let lock = NSLock()

    func getOrCreate() -> String {
        lock.lock()
        defer { lock.unlock() }

        if let existing = read() { return existing }

        var bytes = [UInt8](repeating: 0, count: saltLength)
        var status = SecRandomCopyBytes(kSecRandomDefault, saltLength, &bytes)
        if status != errSecSuccess {
            status = SecRandomCopyBytes(kSecRandomDefault, saltLength, &bytes)
        }
        if status != errSecSuccess {
            let fallback = "\(UUID().uuidString)\(ProcessInfo.processInfo.systemUptime)"
            let hash = SHA256.hash(data: Data(fallback.utf8))
            bytes = Array(hash.prefix(saltLength))
        }

        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        if let existing = save(hex) {
            return existing
        }
        return hex
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
        guard status == errSecSuccess, let data = item as? Data else { return nil }
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
