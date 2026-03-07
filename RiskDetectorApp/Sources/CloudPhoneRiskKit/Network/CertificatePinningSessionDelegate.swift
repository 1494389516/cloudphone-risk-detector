import CryptoKit
import Foundation
import Security

/// TLS 证书固定 — 防止中间人篡改远程配置与策略
///
/// 使用 SPKI (Subject Public Key Info) SHA-256 哈希进行固定，
/// 比证书固定更灵活（证书轮换时只需更新 hash，不需要嵌入新证书）。
public final class CertificatePinningSessionDelegate: NSObject, URLSessionDelegate {

    private let pinnedHashes: Set<String>
    private let allowsSystemCA: Bool

    /// - Parameters:
    ///   - pinnedHashes: SPKI SHA-256 hashes in base64 format (e.g. "sha256/AAAA...")
    ///   - allowsSystemCA: If true, falls back to system CA when no pins match (dev mode)
    public init(pinnedHashes: Set<String>, allowsSystemCA: Bool = false) {
        self.pinnedHashes = pinnedHashes
        self.allowsSystemCA = allowsSystemCA
        super.init()
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

        guard !pinnedHashes.isEmpty else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Evaluate server trust
        var error: CFError?
        let isValid = SecTrustEvaluateWithError(serverTrust, &error)
        guard isValid else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Check each certificate in the chain
        let certificates: [SecCertificate]
        if #available(iOS 15.0, macOS 12.0, *) {
            guard let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate], !chain.isEmpty else {
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
            if let spkiHash = spkiSHA256(certificate: cert) {
                let pinString = "sha256/\(spkiHash)"
                if pinnedHashes.contains(pinString) {
                    completionHandler(.useCredential, URLCredential(trust: serverTrust))
                    return
                }
            }
        }

        // No pin matched
        if allowsSystemCA {
            completionHandler(.performDefaultHandling, nil)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// Extract SPKI SHA-256 hash from a certificate
    private func spkiSHA256(certificate: SecCertificate) -> String? {
        guard let publicKey = SecCertificateCopyKey(certificate) else { return nil }
        var error: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            return nil
        }
        let hash = SHA256.hash(data: publicKeyData)
        return Data(hash).base64EncodedString()
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

    /// Create a URLSession with certificate pinning
    public static func pinnedSession(
        hashes: Set<String>,
        configuration: URLSessionConfiguration = .ephemeral,
        allowsSystemCA: Bool = false
    ) -> URLSession {
        let delegate = CertificatePinningSessionDelegate(
            pinnedHashes: hashes,
            allowsSystemCA: allowsSystemCA
        )
        return URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }
}
