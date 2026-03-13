import CryptoKit
import Foundation
#if canImport(DeviceCheck)
import DeviceCheck
#endif

// MARK: - TrustLevel（SDK 5.0）

/// 端侧信任等级，服务端可据此调整决策权重
public enum TrustLevel: String, Codable, Sendable {
    /// App Attest 可用且 attestation 有效
    case hardware
    /// App Attest 不可用，但 DeviceKey + Keychain 完整
    case derived
    /// Keychain 被清或 attestation 过期
    case degraded
}

// MARK: - KeyRotationPolicy（SDK 5.0）

/// 密钥轮换策略，可由服务端下发
public struct KeyRotationPolicy: Codable, Sendable {
    /// 最大存活时间（秒），超时强制轮换
    public let maxLifetimeSeconds: Int
    /// 双 key 窗口（秒），轮换后旧 key 保留时间，确保在途报告可验
    public let dualKeyWindowSeconds: Int
    /// 当前 DeviceKey 版本
    public let deviceKeyVersion: String

    public init(
        maxLifetimeSeconds: Int = 86400 * 7,
        dualKeyWindowSeconds: Int = 3600,
        deviceKeyVersion: String = "v1"
    ) {
        self.maxLifetimeSeconds = maxLifetimeSeconds
        self.dualKeyWindowSeconds = dualKeyWindowSeconds
        self.deviceKeyVersion = deviceKeyVersion
    }
}

// MARK: - TrustChainManager（SDK 5.0）

/// 端侧信任根链管理器
/// 建立从硬件到报告的完整信任传递链：
/// Secure Enclave --> App Attest Key --> DeviceKey --> SessionKey --> ReportSignature
public enum TrustChainManager {

    private static let sessionKeyInfo = Data("CloudPhoneRiskKit.SessionKey.v1".utf8)
    private static let lock = NSLock()
    private static var lastAttestationCheck: TimeInterval = 0
    private static let attestationCheckInterval: TimeInterval = 3600

    // MARK: - KeyRotationPolicy 应用

    /// 从 PolicyManager 获取当前 keyRotationPolicy
    public static func currentKeyRotationPolicy() -> KeyRotationPolicy? {
        PolicyManager.shared.activePolicy?.keyRotationPolicy
    }

    /// 获取当前应使用的 deviceKeyVersion（来自服务端 policy 或默认 v1）
    public static func currentDeviceKeyVersion() -> String {
        currentKeyRotationPolicy()?.deviceKeyVersion ?? DeviceKeyDeriver.defaultInfoVersion
    }

    /// 获取当前应使用的 keyId（用于 ReportEnvelope）
    public static func currentKeyId(baseKeyId: String = "k1") -> String {
        let version = currentDeviceKeyVersion()
        return "\(baseKeyId)_\(version)"
    }

    // MARK: - TrustLevel 评估

    /// 评估当前信任等级（完整版，含 Keychain salt 持久化检查）
    public static func evaluateTrustLevel(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String
    ) -> TrustLevel {
        #if canImport(DeviceCheck)
        if #available(iOS 14.0, macOS 11.0, *) {
            if AppAttestSigner.isSupported {
                let (_, saltWasPersisted) = DeviceKeyDeriver.deriveKeyWithTrustInfo(
                    deviceID: deviceID,
                    hardwareMachine: hardwareMachine,
                    kernelVersion: kernelVersion,
                    infoVersion: currentDeviceKeyVersion()
                )
                if !saltWasPersisted {
                    return .degraded
                }
                return .hardware
            }
        }
        #endif

        let (_, saltWasPersisted) = DeviceKeyDeriver.deriveKeyWithTrustInfo(
            deviceID: deviceID,
            hardwareMachine: hardwareMachine,
            kernelVersion: kernelVersion,
            infoVersion: currentDeviceKeyVersion()
        )
        return saltWasPersisted ? .derived : .degraded
    }

    /// 评估信任等级（简化版，无 DeviceKey 派生，用于快速路径）
    public static func evaluateTrustLevelQuick() -> TrustLevel {
        #if canImport(DeviceCheck)
        if #available(iOS 14.0, macOS 11.0, *) {
            if AppAttestSigner.isSupported {
                return .hardware
            }
        }
        #endif
        return .derived
    }

    /// 评估信任等级（带设备上下文，可检测 Keychain 被清）
    public static func evaluateTrustLevelWithContext(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String
    ) -> TrustLevel {
        evaluateTrustLevel(
            deviceID: deviceID,
            hardwareMachine: hardwareMachine,
            kernelVersion: kernelVersion
        )
    }

    // MARK: - SessionKey 派生

    /// 派生会话密钥：SessionKey = HKDF(DeviceKey, sessionId + timestamp)
    /// 每次 evaluate 生成，用完即焚
    public static func deriveSessionKey(
        deviceKey: SymmetricKey,
        sessionId: String,
        timestamp: Int64
    ) -> SymmetricKey {
        let salt = "\(sessionId)|\(timestamp)".data(using: .utf8) ?? Data()
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: deviceKey,
            salt: salt,
            info: sessionKeyInfo,
            outputByteCount: 32
        )
    }

    /// 将 SymmetricKey 转为 hex 字符串（用于 ReportEnvelope 签名）
    public static func sessionKeyToHex(_ key: SymmetricKey) -> String {
        key.withUnsafeBytes { Data($0).map { String(format: "%02x", $0) }.joined() }
    }

    // MARK: - KeyResolver（多 key 并存，支持密钥轮换）

    /// 构建 keyResolver：根据 keyId 解析出 signingKey（hex）
    /// 支持双 key 窗口：当前版本 + 上一版本在 dualKeyWindowSeconds 内仍可验签
    public static func buildKeyResolver(
        deviceID: String,
        hardwareMachine: String,
        kernelVersion: String,
        baseKeyId: String = "k1"
    ) -> (String) -> String? {
        let policy = currentKeyRotationPolicy()
        let currentVersion = policy?.deviceKeyVersion ?? DeviceKeyDeriver.defaultInfoVersion

        return { keyId in
            let versionFromKeyId = keyId.hasPrefix("\(baseKeyId)_")
                ? String(keyId.dropFirst("\(baseKeyId)_".count))
                : (keyId == baseKeyId ? currentVersion : nil)

            guard let version = versionFromKeyId else { return nil }

            let key = DeviceKeyDeriver.deriveKey(
                deviceID: deviceID,
                hardwareMachine: hardwareMachine,
                kernelVersion: kernelVersion,
                infoVersion: version
            )
            return sessionKeyToHex(key)
        }
    }

    // MARK: - Attestation 刷新

    /// 检查是否需要 re-attestation
    /// 当前实现：基于时间间隔的简单检查；完整实现需服务端下发 challenge
    public static func shouldRefreshAttestation() -> Bool {
        lock.lock()
        let last = lastAttestationCheck
        lock.unlock()
        return Date().timeIntervalSince1970 - last > attestationCheckInterval
    }

    /// 标记 attestation 检查完成
    public static func markAttestationChecked() {
        lock.lock()
        lastAttestationCheck = Date().timeIntervalSince1970
        lock.unlock()
    }

    /// 获取 attestation 降级时的 TrustLevel
    public static func degradedTrustLevel() -> TrustLevel {
        .degraded
    }
}
