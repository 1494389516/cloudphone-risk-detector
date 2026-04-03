import CryptoKit
import Foundation
import Security

// MARK: - TLS Certificate Pinning

/// SPKI-hash based TLS certificate pinning delegate for the risk report upload endpoint.
///
/// ## Setup
/// ```swift
/// let pinning = CPRiskTLSPinning(pinnedSPKIHashes: [
///     "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  // leaf cert SPKI
///     "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",  // backup / intermediate
/// ])
/// let session = URLSession(
///     configuration: .ephemeral,   // never cache sensitive requests
///     delegate: pinning,
///     delegateQueue: nil
/// )
/// ```
///
/// ## Why SPKI pinning?
/// Pinning the SubjectPublicKeyInfo (SPKI) rather than the full certificate means
/// the pin survives certificate renewal as long as the same key pair is retained —
/// reducing the operational risk of accidental unpin events.
///
/// ## Generating SPKI hashes
/// Use the SDK utility:
/// ```swift
/// CPRiskTLSPinning.spkiHash(for: certificate)   // → "AABB...==" (base64)
/// ```
/// Or via openssl:
/// ```sh
/// openssl x509 -in cert.pem -pubkey -noout \
///   | openssl pkey -pubin -outform DER \
///   | openssl dgst -sha256 -binary | base64
/// ```
public final class CPRiskTLSPinning: NSObject, URLSessionDelegate, @unchecked Sendable {

    // MARK: Public

    /// Pinned SPKI SHA-256 fingerprints in `"<base64>"` format
    /// (without the `sha256/` prefix — strip it if copying from browser dev tools).
    public let pinnedHashes: Set<String>

    /// When `true` (default) the underlying TLS chain must also pass system
    /// trust evaluation before SPKI pinning is applied.  Set to `false` only
    /// for local dev/staging environments with self-signed certificates.
    public let requireSystemTrust: Bool

    public init(pinnedSPKIHashes: [String], requireSystemTrust: Bool = true) {
        // Normalise: strip optional "sha256/" prefix copied from browser tools
        self.pinnedHashes = Set(pinnedSPKIHashes.map {
            $0.hasPrefix("sha256/") ? String($0.dropFirst(7)) : $0
        })
        self.requireSystemTrust = requireSystemTrust
    }

    // MARK: URLSessionDelegate

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            // Non-TLS challenges (proxy auth, etc.) → reject outright
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 1. Optional system trust evaluation
        if requireSystemTrust {
            var cfError: CFError?
            guard SecTrustEvaluateWithError(serverTrust, &cfError) else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        }

        // 2. SPKI pinning: at least one certificate in the chain must match
        let certCount = SecTrustGetCertificateCount(serverTrust)
        for i in 0..<certCount {
            guard let cert = SecTrustGetCertificateAtIndex(serverTrust, i) else { continue }
            if let hash = Self.spkiHash(for: cert), pinnedHashes.contains(hash) {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }

        // No chain member matched any pinned hash → reject
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    // MARK: SPKI Hash Computation

    /// Computes the base64-encoded SHA-256 of the SubjectPublicKeyInfo (SPKI)
    /// for the given certificate.  Returns `nil` if the public key cannot be extracted.
    ///
    /// Use this to generate pin values for your server certificates at build time.
    public static func spkiHash(for certificate: SecCertificate) -> String? {
        guard let publicKey = SecCertificateCopyKey(certificate),
              let keyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }
        let spki = spkiWrapped(keyData, publicKey: publicKey)
        let digest = SHA256.hash(data: spki)
        return Data(digest).base64EncodedString()
    }

    // MARK: Private helpers

    /// Wraps raw key bytes in a minimal ASN.1 SubjectPublicKeyInfo structure.
    /// Supports EC P-256 and RSA keys — the two types used by modern TLS.
    private static func spkiWrapped(_ keyData: Data, publicKey: SecKey) -> Data {
        let attrs = SecKeyCopyAttributes(publicKey) as? [CFString: Any]
        let keyType = attrs?[kSecAttrKeyType] as? String

        if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            // EC P-256: fixed 26-byte SPKI header
            // SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 } BIT STRING }
            let header: [UInt8] = [
                0x30, 0x59,
                0x30, 0x13,
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,  // ecPublicKey OID
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,  // prime256v1 OID
                0x03, 0x42, 0x00,  // BIT STRING, 66 bytes, no unused bits
            ]
            return Data(header) + keyData
        } else {
            // RSA (PKCS#1 DER key bytes): wrap in SPKI with rsaEncryption OID
            // BIT STRING = 0x00 (no unused bits) || keyData
            let bitString = Data([0x00]) + keyData
            let bitStringDER = asn1TLV(tag: 0x03, value: bitString)

            // SEQUENCE { OID rsaEncryption, NULL }
            let rsaOID: [UInt8] = [
                0x30, 0x0d,
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,  // rsaEncryption
                0x05, 0x00,  // NULL
            ]
            let inner = Data(rsaOID) + bitStringDER
            return asn1TLV(tag: 0x30, value: inner)
        }
    }

    private static func asn1TLV(tag: UInt8, value: Data) -> Data {
        var result = Data([tag])
        let len = value.count
        if len < 128 {
            result.append(UInt8(len))
        } else if len < 256 {
            result.append(contentsOf: [0x81, UInt8(len)])
        } else {
            result.append(contentsOf: [0x82, UInt8(len >> 8), UInt8(len & 0xff)])
        }
        result.append(value)
        return result
    }
}
