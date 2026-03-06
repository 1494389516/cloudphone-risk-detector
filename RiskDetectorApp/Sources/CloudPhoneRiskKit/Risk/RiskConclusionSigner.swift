import CryptoKit
import Foundation

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
        let sigHex = hmac.map { String(format: "%02x", $0) }.joined()
        return SignedRiskConclusion(
            score: report.score,
            isHighRisk: report.isHighRisk,
            timestamp: timestamp,
            tampered: report.tampered,
            nonce: nonce,
            signature: sigHex
        )
    }

    public func verify(deviceKey: SymmetricKey) -> Bool {
        let input = "\(score)|\(isHighRisk)|\(timestamp)|\(nonce)|\(tampered)"
        let data = Data(input.utf8)
        let hmac = HMAC<SHA256>.authenticationCode(for: data, using: deviceKey)
        let expected = hmac.map { String(format: "%02x", $0) }.joined()
        return signature == expected
    }
}

public enum DeviceKeyDeriver {
    private static let info = Data("CloudPhoneRiskKit.DeviceKey".utf8)

    public static func deriveKey(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String,
        salt: Data? = nil
    ) -> SymmetricKey {
        let combined = "\(deviceID)|\(hardwareMachine)|\(kernelVersion)"
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
