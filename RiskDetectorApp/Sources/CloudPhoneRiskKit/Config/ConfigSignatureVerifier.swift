import Foundation
import CryptoKit

public enum ConfigSignatureVerifier {

    public struct VerificationResult {
        public let isValid: Bool
        public let reason: String?
    }

    private static var verificationKey: SymmetricKey?
    private static let lock = NSLock()

    public static func configure(serverSigningKey: String) {
        lock.lock()
        defer { lock.unlock() }
        let keyData = Data(serverSigningKey.utf8)
        verificationKey = SymmetricKey(data: SHA256.hash(data: keyData))
    }

    public static func configure(serverSigningKeyData: Data) {
        lock.lock()
        defer { lock.unlock() }
        verificationKey = SymmetricKey(data: serverSigningKeyData)
    }

    public static var isConfigured: Bool {
        lock.lock()
        defer { lock.unlock() }
        return verificationKey != nil
    }

    public static func verify(payload: Data, signatureHex: String) -> VerificationResult {
        lock.lock()
        let key = verificationKey
        lock.unlock()

        guard let key = key else {
            #if DEBUG
            return VerificationResult(isValid: true, reason: "verification_not_configured_debug")
            #else
            return VerificationResult(isValid: false, reason: "verification_not_configured")
            #endif
        }

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
