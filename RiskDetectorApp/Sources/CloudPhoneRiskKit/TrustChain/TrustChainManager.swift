import CryptoKit
import Foundation
#if canImport(DeviceCheck)
import DeviceCheck
#endif

private enum TrustChainCFF {
    static func salt(
        deviceID: String = "",
        hardwareMachine: String = "",
        kernelVersion: String = "",
        sessionId: String = "",
        policyVersion: String = "",
        timestamp: Int64 = 0,
        lastCheck: TimeInterval = 0
    ) -> UInt32 {
        CFFRuntimeSalt.combine(
            words: [
                UInt64(bitPattern: timestamp),
                lastCheck.bitPattern,
                UInt64(sessionId.utf8.count),
            ],
            strings: [
                deviceID,
                hardwareMachine,
                kernelVersion,
                sessionId,
                policyVersion,
                ChallengeSession.shared.state.rawValue,
            ],
            flags: [
                !deviceID.isEmpty,
                !sessionId.isEmpty,
                ChallengeSession.shared.currentChallengeId != nil,
            ]
        )
    }
}

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

    private enum CodingKeys: String, CodingKey {
        case maxLifetimeSeconds = "ml"
        case dualKeyWindowSeconds = "dw"
        case deviceKeyVersion = "dv"
    }

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
        let salt = TrustChainCFF.salt(
            deviceID: deviceID,
            hardwareMachine: hardwareMachine,
            kernelVersion: kernelVersion,
            policyVersion: currentDeviceKeyVersion()
        )
        let seed: UInt32 = 0x2E7C41B9
        let entryState: UInt32 = 0x11
        let capabilityState: UInt32 = 0x12
        let hardwareState: UInt32 = 0x13
        let derivedState: UInt32 = 0x14

        var sink = CFFReturnSink<TrustLevel>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: salt)
        var hardwareSupported = false

        #if canImport(DeviceCheck)
        if #available(iOS 14.0, macOS 11.0, *) {
            hardwareSupported = AppAttestSigner.isSupported
        }
        #endif

        while !sink.isResolved {
            switch CFFStateCodec.decode(encodedState, seed: seed, salt: salt) {
            case entryState:
                encodedState = CFFStateCodec.encode(capabilityState, seed: seed, salt: salt)
            case capabilityState:
                encodedState = CFFStateCodec.encode(hardwareSupported ? hardwareState : derivedState, seed: seed, salt: salt)
            case hardwareState:
                let (_, saltWasPersisted) = DeviceKeyDeriver.deriveKeyWithTrustInfo(
                    deviceID: deviceID,
                    hardwareMachine: hardwareMachine,
                    kernelVersion: kernelVersion,
                    infoVersion: currentDeviceKeyVersion()
                )
                sink.store(saltWasPersisted ? .hardware : .degraded)
            case derivedState:
                let (_, saltWasPersisted) = DeviceKeyDeriver.deriveKeyWithTrustInfo(
                    deviceID: deviceID,
                    hardwareMachine: hardwareMachine,
                    kernelVersion: kernelVersion,
                    infoVersion: currentDeviceKeyVersion()
                )
                sink.store(saltWasPersisted ? .derived : .degraded)
            default:
                sink.store(.degraded)
            }
        }

        return sink.resolve(or: .degraded)
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
        let cffSalt = TrustChainCFF.salt(
            sessionId: sessionId,
            policyVersion: currentDeviceKeyVersion(),
            timestamp: timestamp
        )
        let seed: UInt32 = 0x73A15C4D
        let entryState: UInt32 = 0x21
        let materialState: UInt32 = 0x22
        let deriveState: UInt32 = 0x23
        let connectorState: UInt32 = 0x24
        let settleState: UInt32 = 0x25
        let fallbackSalt = "\(sessionId)|\(timestamp)".data(using: .utf8) ?? Data()

        var sink = CFFReturnSink<SymmetricKey>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: cffSalt)
        var hkdfSalt = Data()

        while !sink.isResolved {
            let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: cffSalt)

            if decodedState == entryState {
                encodedState = CFFStateCodec.encode(materialState, seed: seed, salt: cffSalt)
            } else if decodedState == materialState {
                hkdfSalt = fallbackSalt
                encodedState = CFFStateCodec.encode(connectorState, seed: seed, salt: cffSalt)
            } else if decodedState == connectorState {
                let nextState = CFFDispatcher.prefersPrimaryBranch(encodedState: encodedState, salt: cffSalt) ? deriveState : settleState
                encodedState = CFFStateCodec.encode(nextState, seed: seed, salt: cffSalt)
            } else if decodedState == settleState {
                encodedState = CFFStateCodec.encode(deriveState, seed: seed, salt: cffSalt)
            } else if decodedState == deriveState {
                sink.store(
                    HKDF<SHA256>.deriveKey(
                        inputKeyMaterial: deviceKey,
                        salt: hkdfSalt,
                        info: sessionKeyInfo,
                        outputByteCount: 32
                    )
                )
            } else {
                sink.store(
                    HKDF<SHA256>.deriveKey(
                        inputKeyMaterial: deviceKey,
                        salt: fallbackSalt,
                        info: sessionKeyInfo,
                        outputByteCount: 32
                    )
                )
            }
        }

        return sink.resolve(
            or: HKDF<SHA256>.deriveKey(
                inputKeyMaterial: deviceKey,
                salt: fallbackSalt,
                info: sessionKeyInfo,
                outputByteCount: 32
            )
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
        let cffSalt = TrustChainCFF.salt(
            deviceID: deviceID,
            hardwareMachine: hardwareMachine,
            kernelVersion: kernelVersion,
            policyVersion: currentVersion
        )
        let seed: UInt32 = 0x5CA217E3
        let entryState: UInt32 = 0x31
        let buildState: UInt32 = 0x32

        var sink = CFFReturnSink<(String) -> String?>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: cffSalt)

        while !sink.isResolved {
            switch CFFStateCodec.decode(encodedState, seed: seed, salt: cffSalt) {
            case entryState:
                encodedState = CFFStateCodec.encode(buildState, seed: seed, salt: cffSalt)
            case buildState:
                sink.store { keyId in
                    let innerSalt = TrustChainCFF.salt(
                        deviceID: deviceID,
                        hardwareMachine: hardwareMachine,
                        kernelVersion: kernelVersion,
                        sessionId: keyId,
                        policyVersion: currentVersion,
                        timestamp: Int64(keyId.utf8.count)
                    )
                    let innerSeed: UInt32 = 0x4F31A28C
                    let classifyState: UInt32 = 0x41
                    let deriveState: UInt32 = 0x42
                    let rejectState: UInt32 = 0x43

                    var localSink = CFFReturnSink<String?>()
                    var localState = CFFStateCodec.encode(classifyState, seed: innerSeed, salt: innerSalt)
                    var version: String?

                    while !localSink.isResolved {
                        let decodedState = CFFStateCodec.decode(localState, seed: innerSeed, salt: innerSalt)

                        if decodedState == classifyState {
                            version = keyId.hasPrefix("\(baseKeyId)_")
                                ? String(keyId.dropFirst("\(baseKeyId)_".count))
                                : (keyId == baseKeyId ? currentVersion : nil)
                            localState = CFFStateCodec.encode(version == nil ? rejectState : deriveState, seed: innerSeed, salt: innerSalt)
                        } else if decodedState == deriveState {
                            if let version {
                                let key = DeviceKeyDeriver.deriveKey(
                                    deviceID: deviceID,
                                    hardwareMachine: hardwareMachine,
                                    kernelVersion: kernelVersion,
                                    infoVersion: version
                                )
                                localSink.store(sessionKeyToHex(key))
                            } else {
                                localSink.store(nil)
                            }
                        } else if decodedState == rejectState {
                            localSink.store(nil)
                        } else {
                            localSink.store(nil)
                        }
                    }

                    return localSink.resolve(or: nil)
                }
            default:
                sink.store({ _ in nil })
            }
        }

        return sink.resolve(or: { _ in nil })
    }

    // MARK: - Attestation 刷新

    /// 检查是否需要 re-attestation
    /// 当前实现：基于时间间隔的简单检查；完整实现需服务端下发 challenge
    public static func shouldRefreshAttestation() -> Bool {
        lock.lock()
        let last = lastAttestationCheck
        lock.unlock()

        let cffSalt = TrustChainCFF.salt(
            policyVersion: currentDeviceKeyVersion(),
            timestamp: Int64(last.rounded()),
            lastCheck: last
        )
        let seed: UInt32 = 0x18D2BF65
        let entryState: UInt32 = 0x51
        let compareState: UInt32 = 0x52

        var sink = CFFReturnSink<Bool>()
        var encodedState = CFFStateCodec.encode(entryState, seed: seed, salt: cffSalt)
        var now: TimeInterval = 0

        while !sink.isResolved {
            let decodedState = CFFStateCodec.decode(encodedState, seed: seed, salt: cffSalt)

            if decodedState == entryState {
                now = Date().timeIntervalSince1970
                encodedState = CFFStateCodec.encode(compareState, seed: seed, salt: cffSalt)
            } else if decodedState == compareState {
                sink.store(now - last > attestationCheckInterval)
            } else {
                sink.store(true)
            }
        }

        return sink.resolve(or: true)
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
