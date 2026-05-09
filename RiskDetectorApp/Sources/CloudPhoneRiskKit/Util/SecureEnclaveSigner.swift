import Foundation
import Security

/// Secure Enclave 私钥签名器（P-256 ECDSA over SHA-256）
///
/// **不是** App Attest（那是 Apple 服务器侧验签的应用证明）。
/// 这是**通用 SE 签名能力**：在 Secure Enclave 里生成一对 P-256 密钥，
/// 私钥永远不出 SE，公钥可导出供未来服务器或本地校验链使用。
///
/// 价值：
///   - 任何能拿到 SE 私钥签名输出 = 强证据当前进程跑在真实硬件上
///   - 攻击者即使 hook 了所有 CryptoKit / SecKey API，**也伪造不出有效 ECDSA 签名**
///     除非他们物理上有这个设备 — 因为私钥永远不出 SE
///   - 模拟器、unidbg、Frida-on-rooted-vm 全部失败：模拟器没有真 SE
///
/// 注意：
///   - 第一次 ensureKey() 会生成新密钥并存入 Keychain（受 SE 控制访问）
///   - SecKey 引用是 transient 的；每次 sign 都从 Keychain 重新拿
///   - kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly：解锁后可用，不跨设备同步
enum SecureEnclaveSigner {

    private static let keychainTag = Data("com.cloudphoneriskkit.localsign.v1".utf8)
    private static let lock = NSLock()

    enum SignError: Error, LocalizedError {
        case unsupportedDevice
        case keyCreationFailed(String)
        case keyLoadFailed(OSStatus)
        case publicKeyCopyFailed
        case signFailed(String)
        case publicKeyExportFailed(String)

        var errorDescription: String? {
            switch self {
            case .unsupportedDevice: return "Secure Enclave 不可用（模拟器或老旧设备）"
            case .keyCreationFailed(let r): return "SE 密钥生成失败: \(r)"
            case .keyLoadFailed(let s): return "SE 密钥加载失败 OSStatus=\(s)"
            case .publicKeyCopyFailed: return "公钥导出失败"
            case .signFailed(let r): return "签名失败: \(r)"
            case .publicKeyExportFailed(let r): return "公钥导出失败: \(r)"
            }
        }
    }

    /// 当前设备/环境是否能跑 SE 签名。
    static var isSupported: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        // 通过实际尝试创建一个 SE access control 来探测；失败说明不支持
        var error: Unmanaged<CFError>?
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage],
            &error
        )
        if access != nil {
            return true
        }
        error?.release()
        return false
        #endif
    }

    /// 取得（或第一次创建）SE 密钥，返回 transient SecKey 引用。
    static func ensureKey() throws -> SecKey {
        lock.lock()
        defer { lock.unlock() }
        if let existing = try? loadExistingKeyLocked() {
            return existing
        }
        return try createKeyLocked()
    }

    /// 用 SE 私钥对 `data` 做 ECDSA-P256-SHA256 签名（X9.62 DER 格式）。
    /// SE 内部会先对 data 做 SHA-256，再签摘要。
    static func sign(_ data: Data) throws -> Data {
        let key = try ensureKey()
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            let msg = (error?.takeRetainedValue() as Error?).map { String(describing: $0) } ?? "unknown"
            throw SignError.signFailed(msg)
        }
        return signature
    }

    /// 导出公钥的 X9.62 未压缩点表示（65 字节: 0x04 || X32 || Y32），可用于服务器验签。
    static func publicKeyX962() throws -> Data {
        let priv = try ensureKey()
        guard let pub = SecKeyCopyPublicKey(priv) else {
            throw SignError.publicKeyCopyFailed
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            let msg = (error?.takeRetainedValue() as Error?).map { String(describing: $0) } ?? "unknown"
            throw SignError.publicKeyExportFailed(msg)
        }
        return data
    }

    // MARK: - Private

    private static func loadExistingKeyLocked() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keychainTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw SignError.keyLoadFailed(status)
        }
        // SecKey is a CF type; force-cast is the canonical pattern when status==success.
        return result as! SecKey  // swiftlint:disable:this force_cast
    }

    private static func createKeyLocked() throws -> SecKey {
        guard isSupported else {
            throw SignError.unsupportedDevice
        }
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage],
            &accessError
        ) else {
            let msg = (accessError?.takeRetainedValue() as Error?).map { String(describing: $0) } ?? "unknown"
            throw SignError.keyCreationFailed("access_control: \(msg)")
        }

        let privateKeyAttrs: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: keychainTag,
            kSecAttrAccessControl as String: access,
        ]

        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyAttrs,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            let msg = (error?.takeRetainedValue() as Error?).map { String(describing: $0) } ?? "unknown"
            throw SignError.keyCreationFailed(msg)
        }
        return key
    }
}
