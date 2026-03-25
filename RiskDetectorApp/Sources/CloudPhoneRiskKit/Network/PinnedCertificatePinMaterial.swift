import Darwin
import Foundation

/// Runtime material for TLS SPKI pinning without retaining `sha256/...` **strings** in the delegate /
/// global configuration path (reduces trivial `strings`/heap scans for pin literals).
///
/// **Limits:** Swift/ARC cannot guarantee immediate erasure of all copies; comparison still
/// materializes ephemeral `Data` for the candidate digest. True secure memory would require
/// dedicated allocator support not available in portable Swift.
public final class PinnedCertificatePinMaterial: @unchecked Sendable {

    /// Raw SPKI SHA-256 digests (32 bytes each), order preserved from input.
    private var slots: [ContiguousArray<UInt8>]
    /// Flattened digests for CRiskCore-side constant-time validation.
    private var packedDigests: ContiguousArray<UInt8>
    private static let digestLength = 32

    public static let empty = PinnedCertificatePinMaterial(slots: [])

    private init(slots: [ContiguousArray<UInt8>]) {
        self.slots = slots
        self.packedDigests = Self.pack(slots)
    }

    /// Invalid `sha256/<base64>` entries are dropped (same effective behavior as opaque strings that never matched).
    public convenience init(pinStrings: Set<String>) {
        self.init(slots: Self.parseDigests(from: pinStrings))
    }

    public var isEmpty: Bool { slots.isEmpty }

    public var digestCount: Int { slots.count }

    /// Returns true if `spkiSHA256Base64` (no `sha256/` prefix) matches any pinned digest.
    public func containsSPKISHA256Base64(_ spkiSHA256Base64: String) -> Bool {
        guard let candidate = Self.decodeBase64Digest(spkiSHA256Base64) else { return false }
        return containsRawDigest(candidate)
    }

    /// Raw 32-byte SPKI SHA-256 digest (e.g. decoded from server pin config).
    public func containsRawDigest(_ digest: Data) -> Bool {
        guard digest.count == Self.digestLength else { return false }
        return digest.withUnsafeBytes { candBuf -> Bool in
            guard let candBase = candBuf.bindMemory(to: UInt8.self).baseAddress else { return false }
            var acc: UInt8 = 0
            for slot in slots {
                let m: UInt8 = Self.constantTimeEqual(slot, candBase) ? 1 : 0
                acc |= m
            }
            return acc != 0
        }
    }

    /// CRiskCore-side duplicate validation path using a packed digest buffer.
    func containsRawDigestViaCore(_ digest: Data) -> Bool {
        guard digest.count == Self.digestLength, !slots.isEmpty else { return false }
        return digest.withUnsafeBytes { candBuf -> Bool in
            guard let candBase = candBuf.bindMemory(to: UInt8.self).baseAddress else { return false }
            return packedDigests.withUnsafeBufferPointer { pinBuf in
                guard let pinBase = pinBuf.baseAddress else { return false }
                let rc = cprisk_pinset_contains_sha256_digest(
                    candBase,
                    digest.count,
                    pinBase,
                    slots.count
                )
                return rc == 1
            }
        }
    }

    private static func parseDigests(from pinStrings: Set<String>) -> [ContiguousArray<UInt8>] {
        var out: [ContiguousArray<UInt8>] = []
        out.reserveCapacity(pinStrings.count)
        for raw in pinStrings {
            guard let d = Self.digestFromPinString(raw) else { continue }
            out.append(d)
        }
        return out
    }

    private static func pack(_ slots: [ContiguousArray<UInt8>]) -> ContiguousArray<UInt8> {
        var packed = ContiguousArray<UInt8>()
        packed.reserveCapacity(slots.count * digestLength)
        for slot in slots {
            packed.append(contentsOf: slot)
        }
        return packed
    }

    /// Parses `sha256/<base64>` (case-insensitive prefix); whitespace trimmed.
    static func digestFromPinString(_ raw: String) -> ContiguousArray<UInt8>? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let lower = trimmed.lowercased()
        let payload: String
        if lower.hasPrefix("sha256/") {
            payload = String(trimmed.dropFirst("sha256/".count))
        } else {
            payload = trimmed
        }
        let cleaned = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = Self.decodeBase64Digest(cleaned), data.count == digestLength else {
            return nil
        }
        return ContiguousArray(data)
    }

    /// Canonical `sha256/<base64>` for each valid pin (sorted for stable equality).
    static func canonicalPinStrings(from pinStrings: Set<String>) -> Set<String> {
        var canonical: [String] = []
        for raw in pinStrings {
            guard let digest = digestFromPinString(raw) else { continue }
            let b64 = Data(digest).base64EncodedString()
            canonical.append("sha256/\(b64)")
        }
        canonical.sort()
        return Set(canonical)
    }

    private static func decodeBase64Digest(_ s: String) -> Data? {
        Data(base64Encoded: s, options: [.ignoreUnknownCharacters])
    }

    private static func constantTimeEqual(_ a: ContiguousArray<UInt8>, _ b: UnsafePointer<UInt8>) -> Bool {
        guard a.count == digestLength else { return false }
        var diff: UInt8 = 0
        for i in 0..<digestLength {
            diff |= a[i] ^ b[i]
        }
        return diff == 0
    }

    deinit {
        for idx in slots.indices {
            slots[idx].withUnsafeMutableBufferPointer { buf in
                if let base = buf.baseAddress {
                    memset(base, 0, buf.count)
                }
            }
        }
        packedDigests.withUnsafeMutableBufferPointer { buf in
            if let base = buf.baseAddress {
                memset(base, 0, buf.count)
            }
        }
        slots.removeAll(keepingCapacity: false)
        packedDigests.removeAll(keepingCapacity: false)
    }
}
