import CryptoKit
import DeviceCheck
import Foundation
import Security

/// App Attest 硬件信任根签名器（SDK 4.4）
/// 使用 Secure Enclave 对 payload 摘要进行硬件签名，防止伪造。
/// SDK 4.4 Phase 6: Keychain 存 keyId，kSecAttrAccessibleWhenUnlockedThisDeviceOnly。
@available(iOS 14.0, macOS 11.0, *)
public enum AppAttestSigner {

    /// 是否支持 App Attest（真机 + 有效 App ID；模拟器/黑苹果/虚拟机返回 false）
    public static var isSupported: Bool {
        DCAppAttestService.shared.isSupported
    }

    /// 获取或创建 attestation key ID（不生成断言）
    public static func resolveKeyId() async throws -> String {
        try await getOrCreateKeyId()
    }

    /// 对 payload 数据生成硬件断言（内部计算 SHA256）
    /// - Parameter payloadData: 待签名数据（通常为 canonical payload）
    /// - Returns: (keyId, assertionData)
    public static func generateAssertion(for payloadData: Data) async throws -> (keyId: String, assertion: Data) {
        guard AppAttestSigner.isSupported else {
            throw AppAttestError.hardwareTrustUnsupported
        }
        let hash = SHA256.hash(data: payloadData)
        let payloadHash = Data(hash)
        guard payloadHash.count == 32 else {
            throw AppAttestError.invalidPayloadHashSize(payloadHash.count)
        }

        let keyId = try await getOrCreateKeyId()
        let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: payloadHash)
        return (keyId, assertion)
    }

    /// 对 payload 摘要生成断言（调用方已计算 SHA256，32 字节）
    public static func generateAssertion(forPayloadHash payloadHash: Data) async throws -> (keyId: String, assertion: Data) {
        guard payloadHash.count == 32 else {
            throw AppAttestError.invalidPayloadHashSize(payloadHash.count)
        }
        guard AppAttestSigner.isSupported else {
            throw AppAttestError.hardwareTrustUnsupported
        }
        let keyId = try await getOrCreateKeyId()
        let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: payloadHash)
        return (keyId, assertion)
    }

    /// Configure authenticated Collector enrollment before generating assertions.
    /// Submit must return only after the server validates Apple's attestation chain.
    public struct EnrollmentChallenge: Sendable {
        public let id: String
        public let bytes: Data
        public init(id: String, bytes: Data) { self.id = id; self.bytes = bytes }
    }
    public typealias ChallengeProvider = @Sendable () async throws -> EnrollmentChallenge
    public typealias EnrollmentSubmitter = @Sendable (String, Data, String) async throws -> Void
    private static var enrollment: (ChallengeProvider, EnrollmentSubmitter)?

    public static func configureEnrollment(challenge: @escaping ChallengeProvider, submit: @escaping EnrollmentSubmitter) {
        lock.withLock { enrollment = (challenge, submit) }
    }

    /// Explicit v3 Collector path; all proofs exist BEFORE the envelope is signed.
    /// Challenge bytes come from POST /reports/challenge and are single-use.
    public static func createCollectorEnvelope(
        payloadData: Data, reportId: String, sessionToken: String, signingKey: String,
        keyId: String, serverChallenge: Data
    ) async throws -> ReportEnvelope {
        guard serverChallenge.count >= 32 else { throw AppAttestError.invalidServerChallenge }
        let attestationKeyId = try await resolveKeyId()
        let config = ReportEnvelope.Config(signatureVersion: "v3", requireHardwareAttestation: true)
        let draft = try ReportEnvelope.create(payloadData: payloadData, reportId: reportId,
            sessionToken: sessionToken, signingKey: signingKey, keyId: keyId,
            attestationKeyId: attestationKeyId, config: config)
        let canonical = Data(try draft.canonicalPayloadString().utf8)
        let (_, assertion) = try await generateAssertion(for: canonical)
        let (_, freshAssertion) = try await generateAssertion(for: serverChallenge)
        return try ReportEnvelope.create(payloadData: payloadData, reportId: reportId,
            sessionToken: sessionToken, signingKey: signingKey, keyId: keyId,
            attestationKeyId: attestationKeyId, attestationAssertion: assertion,
            reAttestationAssertion: freshAssertion, trustLevel: .hardware, config: config)
    }

    // MARK: - Key Management

    private static let keychainService = "CloudPhoneRiskKit.AppAttest"
    private static let keychainAccount = "attestation_key_id.server_enrolled.v2"
    private static let lock = NSLock()  // NSLock: Keychain I/O inside lock

    private static func getOrCreateKeyId() async throws -> String {
        if let existing = loadKeyId() {
            return existing
        }
        guard let handlers = lock.withLock({ enrollment }) else {
            throw AppAttestError.enrollmentNotConfigured
        }
        let challenge = try await handlers.0()
        guard !challenge.id.isEmpty, challenge.bytes.count >= 32 else {
            throw AppAttestError.invalidServerChallenge
        }
        let keyId = try await DCAppAttestService.shared.generateKey()
        let clientDataHash = SHA256.hash(data: challenge.bytes)
        let attestation = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: Data(clientDataHash))
        try await handlers.1(keyId, attestation, challenge.id)
        if let winner = saveKeyId(keyId) {
            return winner
        }
        return keyId
    }

    private static func loadKeyId() -> String? {
        lock.withLock {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainAccount,
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
            ]
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            guard status == errSecSuccess, let data = item as? Data, let str = String(data: data, encoding: .utf8) else {
                return nil
            }
            return str
        }
    }

    /// Add-only save: returns nil on success, or the existing keyId if another caller won the race.
    @discardableResult
    private static func saveKeyId(_ keyId: String) -> String? {
        lock.withLock {
            guard let data = keyId.data(using: .utf8) else { return nil }
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: keychainService,
                kSecAttrAccount as String: keychainAccount,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecValueData as String: data,
            ]
            let status = SecItemAdd(addQuery as CFDictionary, nil)
            if status == errSecSuccess { return nil }
            if status == errSecDuplicateItem, let existing = loadKeyIdLocked() {
                return existing
            }
            return nil
        }
    }

    /// Read keyId while the caller already holds `lock`.
    private static func loadKeyIdLocked() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data, let str = String(data: data, encoding: .utf8) else {
            return nil
        }
        return str
    }

    // MARK: - Error

    public enum AppAttestError: Error, LocalizedError {
        case enrollmentNotConfigured
        case invalidServerChallenge
        case hardwareTrustUnsupported
        case invalidPayloadHashSize(Int)

        public var errorDescription: String? {
            switch self {
            case .enrollmentNotConfigured: return "Configure authenticated server enrollment first"
            case .invalidServerChallenge: return "Server challenge must have an ID and at least 32 bytes"
            case .hardwareTrustUnsupported:
                return "App Attest 不支持（模拟器/黑苹果/虚拟机或无效 App ID）"
            case .invalidPayloadHashSize(let count):
                return "payloadHash 必须为 32 字节 (SHA256)，当前: \(count)"
            }
        }
    }
}
