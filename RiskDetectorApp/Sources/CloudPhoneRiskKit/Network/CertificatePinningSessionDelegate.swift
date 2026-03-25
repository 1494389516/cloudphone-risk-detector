import CryptoKit
import Darwin
import Foundation
import Security

/// TLS 证书固定 — 防止中间人篡改远程配置与策略
///
/// 使用 SPKI (Subject Public Key Info) SHA-256 哈希进行固定，
/// 比证书固定更灵活（证书轮换时只需更新 hash，不需要嵌入新证书）。
public final class CertificatePinningSessionDelegate: NSObject, URLSessionDelegate {

    private let pinMaterial: PinnedCertificatePinMaterial
    private let allowsSystemCA: Bool

    /// 非模拟器上，`SecTrustEvaluateWithError` 耗时低于该阈值（纳秒）则记录时序异常侧信道（不单独断连）。
    private static let trustEvalSuspiciouslyFastNs: UInt64 = 5_000

    /// - Parameters:
    ///   - pinMaterial: Parsed SPKI SHA-256 digests (see ``PinnedCertificatePinMaterial``).
    ///   - allowsSystemCA: If true, falls back to system CA when no pins match (dev mode)
    public init(pinMaterial: PinnedCertificatePinMaterial, allowsSystemCA: Bool = false) {
        self.pinMaterial = pinMaterial
        self.allowsSystemCA = allowsSystemCA
        super.init()
    }

    /// - Parameters:
    ///   - pinnedHashes: SPKI SHA-256 hashes (e.g. `sha256/<base64>`); converted to digest-only material internally.
    ///   - allowsSystemCA: If true, falls back to system CA when no pins match (dev mode)
    public convenience init(pinnedHashes: Set<String>, allowsSystemCA: Bool = false) {
        self.init(pinMaterial: PinnedCertificatePinMaterial(pinStrings: pinnedHashes), allowsSystemCA: allowsSystemCA)
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let host = challenge.protectionSpace.host

        guard !pinMaterial.isEmpty else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        if !preflightPinningCore(host: host) {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let t0 = PinningMonotonicNanos.now()
        var error: CFError?
        let isValid = SecTrustEvaluateWithError(serverTrust, &error)
        let t1 = PinningMonotonicNanos.now()
        let elapsed = t1 &- t0

        #if !targetEnvironment(simulator)
        if elapsed < Self.trustEvalSuspiciouslyFastNs {
            recordPinning(
                host: host,
                kind: .trustEvalSuspiciouslyFast,
                detail: [
                    "elapsed_ns": "\(elapsed)",
                    "threshold_ns": "\(Self.trustEvalSuspiciouslyFastNs)",
                ]
            )
        }
        #endif

        guard isValid else {
            var detail: [String: String] = [:]
            if let err = error {
                let ns = err as Error as NSError
                detail["cf_error_domain"] = ns.domain
                detail["cf_error_code"] = "\(ns.code)"
            }
            recordPinning(host: host, kind: .trustEvalFailed, detail: detail)
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard crossCheckTrustEvaluation(serverTrust, host: host) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        if #available(iOS 14.0, macOS 11.0, *) {
            guard SecTrustCopyKey(serverTrust) != nil else {
                recordPinning(host: host, kind: .leafPublicKeyMissing, detail: [:])
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        }

        // Check each certificate in the chain
        let certificates: [SecCertificate]
        if #available(iOS 15.0, macOS 12.0, *) {
            guard let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate], !chain.isEmpty else {
                recordPinning(host: host, kind: .emptyCertificateChain, detail: ["reason": "ios15_chain"])
                if allowsSystemCA {
                    completionHandler(.performDefaultHandling, nil)
                } else {
                    completionHandler(.cancelAuthenticationChallenge, nil)
                }
                return
            }
            certificates = chain
        } else {
            var certs: [SecCertificate] = []
            let certCount = certificateCount(trust: serverTrust)
            for i in 0..<certCount {
                if let cert = certificateAt(trust: serverTrust, index: i) {
                    certs.append(cert)
                }
            }
            guard !certs.isEmpty else {
                recordPinning(host: host, kind: .emptyCertificateChain, detail: ["reason": "legacy_chain"])
                if allowsSystemCA {
                    completionHandler(.performDefaultHandling, nil)
                } else {
                    completionHandler(.cancelAuthenticationChallenge, nil)
                }
                return
            }
            certificates = certs
        }

        for cert in certificates {
            if let spkiDigest = spkiSHA256Digest(certificate: cert) {
                let swiftMatch = pinMaterial.containsRawDigest(spkiDigest)
                let coreMatch = pinMaterial.containsRawDigestViaCore(spkiDigest)
                if swiftMatch != coreMatch {
                    recordPinning(
                        host: host,
                        kind: .pinValidatorDiverged,
                        detail: [
                            "swift_match": swiftMatch ? "1" : "0",
                            "core_match": coreMatch ? "1" : "0",
                        ]
                    )
                    completionHandler(.cancelAuthenticationChallenge, nil)
                    return
                }
                if swiftMatch && coreMatch {
                    completionHandler(.useCredential, URLCredential(trust: serverTrust))
                    return
                }
            }
        }

        // No pin matched
        recordPinning(host: host, kind: .pinMismatch, detail: ["allows_system_ca": "\(allowsSystemCA)"])
        if allowsSystemCA {
            completionHandler(.performDefaultHandling, nil)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: - CRiskCore + redundant trust checks

    /// 失败时返回 false，调用方应取消挑战。
    private func preflightPinningCore(host: String) -> Bool {
        let stubMask = cprisk_verify_svc_stub_integrity()
        if stubMask != 0 {
            recordPinning(
                host: host,
                kind: .svcStubIntegrity,
                detail: ["stub_mask": "\(stubMask)"]
            )
            #if !targetEnvironment(simulator)
            return false
            #endif
        }

        let ir = cprisk_recheck_integrity()
        switch ir {
        case 1:
            recordPinning(host: host, kind: .integrityRecheckTamper, detail: ["recheck": "1"])
            return false
        case -2:
            recordPinning(host: host, kind: .integrityRecheckComputeFailed, detail: ["recheck": "-2"])
            return false
        case -1:
            break
        default:
            break
        }
        return true
    }

    /// 与 `SecTrustEvaluateWithError` 独立的 `SecTrustGetTrustResult` 交叉校验，降低单点 hook 面。
    private func crossCheckTrustEvaluation(_ serverTrust: SecTrust, host: String) -> Bool {
        var trustResult = SecTrustResultType.invalid
        let status = SecTrustGetTrustResult(serverTrust, &trustResult)
        guard status == errSecSuccess else {
            recordPinning(
                host: host,
                kind: .trustResultMismatch,
                detail: [
                    "sec_trust_get_result_status": "\(status)",
                    "trust_result": "\(trustResult.rawValue)",
                ]
            )
            return false
        }
        switch trustResult {
        case .proceed, .unspecified:
            return true
        default:
            recordPinning(
                host: host,
                kind: .trustResultMismatch,
                detail: [
                    "trust_result": "\(trustResult.rawValue)",
                ]
            )
            return false
        }
    }

    private func recordPinning(host: String, kind: CertificatePinningTelemetryKind, detail: [String: String]) {
        CertificatePinningTelemetry.shared.record(host: host, kind: kind, detail: detail)
    }

    // ASN.1 SPKI headers for wrapping raw key bytes into DER SubjectPublicKeyInfo.
    // Required so that SHA-256 hashes match those produced by standard tooling
    // (e.g. `openssl x509 -pubkey | openssl pkey -pubin -outform der | sha256`).
    // RSA-2048: PKCS#1 key data is 270 bytes
    private static let rsa2048SPKIHeader: [UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00
    ]
    // RSA-4096: PKCS#1 key data is 526 bytes
    private static let rsa4096SPKIHeader: [UInt8] = [
        0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00
    ]
    // EC P-256: uncompressed point is 65 bytes
    private static let ecP256SPKIHeader: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00
    ]
    // EC P-384: uncompressed point is 97 bytes
    private static let ecP384SPKIHeader: [UInt8] = [
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
        0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
    ]

    /// Extract raw SPKI SHA-256 digest bytes from a certificate.
    private func spkiSHA256Digest(certificate: SecCertificate) -> Data? {
        guard let publicKey = SecCertificateCopyKey(certificate) else { return nil }
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            _ = error?.takeRetainedValue()  // release to avoid leak
            return nil
        }

        // Determine the appropriate SPKI header based on key type and size
        let header: [UInt8]
        if let attrs = SecKeyCopyAttributes(publicKey) as? [CFString: Any],
           let type = attrs[kSecAttrKeyType] as? String {
            if type == (kSecAttrKeyTypeRSA as String) {
                switch publicKeyData.count {
                case 270: header = Self.rsa2048SPKIHeader
                case 526: header = Self.rsa4096SPKIHeader
                default:
                    Logger.log("spkiSHA256: unsupported RSA key size \(publicKeyData.count) bytes")
                    header = []
                }
            } else if type == (kSecAttrKeyTypeECSECPrimeRandom as String) {
                switch publicKeyData.count {
                case 65: header = Self.ecP256SPKIHeader
                case 97: header = Self.ecP384SPKIHeader
                default:
                    Logger.log("spkiSHA256: unsupported EC key size \(publicKeyData.count) bytes")
                    header = []
                }
            } else {
                Logger.log("spkiSHA256: unsupported key type")
                header = []
            }
        } else {
            header = []
        }

        var spkiData = Data(header)
        spkiData.append(publicKeyData)
        return Data(SHA256.hash(data: spkiData))
    }

    @available(iOS, deprecated: 15.0)
    @available(macOS, deprecated: 12.0)
    private func certificateCount(trust: SecTrust) -> Int {
        SecTrustGetCertificateCount(trust)
    }

    @available(iOS, deprecated: 15.0)
    @available(macOS, deprecated: 12.0)
    private func certificateAt(trust: SecTrust, index: Int) -> SecCertificate? {
        SecTrustGetCertificateAtIndex(trust, index)
    }

    /// Create a URLSession with certificate pinning (digest-backed material; no long-lived `sha256/...` strings on the delegate).
    public static func pinnedSession(
        pinMaterial: PinnedCertificatePinMaterial,
        configuration: URLSessionConfiguration = .ephemeral,
        allowsSystemCA: Bool = false
    ) -> URLSession {
        let delegate = CertificatePinningSessionDelegate(
            pinMaterial: pinMaterial,
            allowsSystemCA: allowsSystemCA
        )
        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }

    /// Convenience: builds ``PinnedCertificatePinMaterial`` from pin strings (invalid entries ignored).
    public static func pinnedSession(
        hashes: Set<String>,
        configuration: URLSessionConfiguration = .ephemeral,
        allowsSystemCA: Bool = false
    ) -> URLSession {
        pinnedSession(
            pinMaterial: PinnedCertificatePinMaterial(pinStrings: hashes),
            configuration: configuration,
            allowsSystemCA: allowsSystemCA
        )
    }
}

private enum PinningMonotonicNanos {
    private static let timebase: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    static func now() -> UInt64 {
        let t = mach_absolute_time()
        return t * UInt64(timebase.numer) / UInt64(timebase.denom)
    }
}
