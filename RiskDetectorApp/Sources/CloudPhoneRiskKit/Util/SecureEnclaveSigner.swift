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
///   - `isSupported` 用懒 probe：实际尝试 ensureKey 一次后缓存结果。
///     SecAccessControlCreateWithFlags 不实际探测 SE 硬件存在性，所以不能用。
enum SecureEnclaveSigner {

    private static let keychainTag = Data("com.cloudphoneriskkit.localsign.v1".utf8)
    private static let lock = NSLock()
    private static var probedSupport: Bool? = nil

    enum SignError: Error, LocalizedError {
        case unsupportedDevice
        case keyCreationFailed(domain: String, code: Int)
        case keyLoadFailed(OSStatus)
        case publicKeyCopyFailed
        case signFailed(domain: String, code: Int)
        case publicKeyExportFailed(domain: String, code: Int)

        var errorDescription: String? {
            switch self {
            case .unsupportedDevice: return "SE_unsupported"
            case .keyCreationFailed(let d, let c): return "SE_keygen_failed:\(d):\(c)"
            case .keyLoadFailed(let s): return "SE_keyload_failed:\(s)"
            case .publicKeyCopyFailed: return "SE_pubkey_copy_failed"
            case .signFailed(let d, let c): return "SE_sign_failed:\(d):\(c)"
            case .publicKeyExportFailed(let d, let c): return "SE_pubkey_export_failed:\(d):\(c)"
            }
        }
    }

    /// 当前设备/环境是否能跑 SE 签名（懒 probe + 缓存）。
    /// 第一次调用会实际尝试生成/加载 SE 密钥，结果缓存。
    /// 不像 SecAccessControlCreateWithFlags 那种"看起来在工作"的伪 probe，
    /// 这里直接对 SE 硬件做真实交互。
    static var isSupported: Bool {
        if let cached = readCachedSupport() {
            return cached
        }
        #if targetEnvironment(simulator)
        cacheSupport(false)
        return false
        #else
        let result: Bool
        do {
            _ = try ensureKeyInternal()
            result = true
        } catch {
            result = false
        }
        cacheSupport(result)
        return result
        #endif
    }

    /// 测试用：清空 isSupported 缓存。
    static func resetSupportCacheForTesting() {
        lock.lock()
        defer { lock.unlock() }
        probedSupport = nil
    }

    /// 取得（或第一次创建）SE 密钥，返回 transient SecKey 引用。
    static func ensureKey() throws -> SecKey {
        return try ensureKeyInternal()
    }

    /// 用 SE 私钥对 `data` 做 ECDSA-P256-SHA256 签名（X9.62 DER 格式）。
    /// SE 内部会先对 data 做 SHA-256，再签摘要。
    static func sign(_ data: Data) throws -> Data {
        let key = try ensureKeyInternal()
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            let cfErr = error?.takeRetainedValue()
            throw SignError.signFailed(domain: cfErrorDomain(cfErr), code: cfErrorCode(cfErr))
        }
        return signature
    }

    /// 导出公钥的 X9.62 未压缩点表示（65 字节: 0x04 || X32 || Y32），可用于服务器验签。
    static func publicKeyX962() throws -> Data {
        let priv = try ensureKeyInternal()
        guard let pub = SecKeyCopyPublicKey(priv) else {
            throw SignError.publicKeyCopyFailed
        }
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            let cfErr = error?.takeRetainedValue()
            throw SignError.publicKeyExportFailed(domain: cfErrorDomain(cfErr), code: cfErrorCode(cfErr))
        }
        return data
    }

    // MARK: - Private

    private static func readCachedSupport() -> Bool? {
        lock.lock()
        defer { lock.unlock() }
        return probedSupport
    }

    private static func cacheSupport(_ value: Bool) {
        lock.lock()
        defer { lock.unlock() }
        probedSupport = value
    }

    /// 不再走 `isSupported` 的递归。直接尝试 load → create。
    private static func ensureKeyInternal() throws -> SecKey {
        lock.lock()
        defer { lock.unlock() }
        if let existing = try? loadExistingKeyLocked() {
            return existing
        }
        return try createKeyLocked()
    }

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
        return result as! SecKey  // swiftlint:disable:this force_cast
    }

    private static func createKeyLocked() throws -> SecKey {
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            [.privateKeyUsage],
            &accessError
        ) else {
            let cfErr = accessError?.takeRetainedValue()
            throw SignError.keyCreationFailed(domain: cfErrorDomain(cfErr), code: cfErrorCode(cfErr))
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
            let cfErr = error?.takeRetainedValue()
            throw SignError.keyCreationFailed(domain: cfErrorDomain(cfErr), code: cfErrorCode(cfErr))
        }
        return key
    }

    // MARK: - CFError helpers
    // 仅暴露 domain + code，不把 userInfo 序列化到信号里 — userInfo 会包含
    // Apple 内部字符串、可能含路径，跨 iOS 版本不稳定。

    private static func cfErrorDomain(_ err: CFError?) -> String {
        guard let err = err else { return "nil" }
        let raw = CFErrorGetDomain(err) as String? ?? "unknown"
        return raw
    }

    private static func cfErrorCode(_ err: CFError?) -> Int {
        guard let err = err else { return -1 }
        return CFErrorGetCode(err)
    }
}
