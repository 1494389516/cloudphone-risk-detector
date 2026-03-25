import CRiskCore
import Darwin
import Foundation

/// Which certificate(s) in the validated chain a pin may match.
public enum CertificatePinScope: UInt8, Sendable {
    /// Match at any position (legacy `sha256/...` and explicit `any/sha256/...`).
    case any = 0
    /// End-entity only (chain index 0).
    case leaf = 1
    /// Any non-leaf certificate (chain index ≥ 1).
    case intermediate = 2
}

/// Runtime material for TLS SPKI pinning without retaining `sha256/...` **strings** in the delegate /
/// global configuration path (reduces trivial `strings`/heap scans for pin literals).
///
/// **Limits:** Swift/ARC cannot guarantee immediate erasure of all copies; comparison still
/// materializes ephemeral `Data` for the candidate digest. True secure memory would require
/// dedicated allocator support not available in portable Swift.
public final class PinnedCertificatePinMaterial: @unchecked Sendable {

    /// Raw SPKI SHA-256 digests (32 bytes each), order preserved from input.
    private var slots: [ContiguousArray<UInt8>]
    /// Parallel scope per slot (same length as `slots`).
    private var scopeBytes: [UInt8]
    /// Flattened digests for CRiskCore-side constant-time validation.
    private var packedDigests: ContiguousArray<UInt8>
    /// One byte per pin: ``CertificatePinScope.rawValue``.
    private var packedScopes: ContiguousArray<UInt8>
    private static let digestLength = 32

    public static let empty = PinnedCertificatePinMaterial(slots: [], scopeBytes: [])

    private init(slots: [ContiguousArray<UInt8>], scopeBytes: [UInt8]) {
        precondition(slots.count == scopeBytes.count)
        self.slots = slots
        self.scopeBytes = scopeBytes
        self.packedDigests = Self.pack(slots)
        self.packedScopes = ContiguousArray(scopeBytes)
    }

    /// Invalid `sha256/<base64>` entries are dropped (same effective behavior as opaque strings that never matched).
    /// Supports prefixes:
    /// - `sha256/<base64>` or `any/sha256/<base64>` — match any chain position (legacy-compatible).
    /// - `leaf/sha256/<base64>` — leaf only.
    /// - `intermediate/sha256/<base64>` — intermediates only (index ≥ 1).
    public convenience init(pinStrings: Set<String>) {
        let parsed = Self.parsePinEntries(from: pinStrings)
        self.init(slots: parsed.slots, scopeBytes: parsed.scopes)
    }

    public var isEmpty: Bool { slots.isEmpty }

    public var digestCount: Int { slots.count }

    /// Returns true if `spkiSHA256Base64` (no `sha256/` prefix) matches any pinned digest (ignores scope).
    public func containsSPKISHA256Base64(_ spkiSHA256Base64: String) -> Bool {
        guard let candidate = Self.decodeBase64Digest(spkiSHA256Base64) else { return false }
        return containsRawDigest(candidate)
    }

    /// Raw 32-byte SPKI SHA-256 digest: true if digest equals any pinned slot (**scope ignored**).
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

    /// Layered policy: digest must match a pin whose scope allows this `chainIndex` (0 = leaf).
    public func matchesLayeredDigest(_ digest: Data, chainIndex: Int) -> Bool {
        guard digest.count == Self.digestLength, !slots.isEmpty else { return false }
        guard chainIndex >= 0 else { return false }
        let idx = UInt32(chainIndex)
        return digest.withUnsafeBytes { candBuf -> Bool in
            guard let candBase = candBuf.bindMemory(to: UInt8.self).baseAddress else { return false }
            var acc: UInt8 = 0
            for i in slots.indices {
                let eq: UInt8 = Self.constantTimeEqual(slots[i], candBase) ? 1 : 0
                let posOk: UInt8 = Self.positionAllowed(scopeByte: scopeBytes[i], chainIndex: idx)
                acc |= (eq & posOk)
            }
            return acc != 0
        }
    }

    /// CRiskCore duplicate validation path for layered pins.
    func matchesLayeredDigestViaCore(_ digest: Data, chainIndex: Int) -> Bool {
        guard digest.count == Self.digestLength, !slots.isEmpty else { return false }
        guard chainIndex >= 0 else { return false }
        return digest.withUnsafeBytes { candBuf -> Bool in
            guard let candBase = candBuf.bindMemory(to: UInt8.self).baseAddress else { return false }
            return packedDigests.withUnsafeBufferPointer { pinBuf in
                guard let pinBase = pinBuf.baseAddress else { return false }
                return packedScopes.withUnsafeBufferPointer { scBuf in
                    guard let scBase = scBuf.baseAddress else { return false }
                    let rc = cprisk_pinset_match_layered_sha256_digest(
                        candBase,
                        digest.count,
                        pinBase,
                        slots.count,
                        scBase,
                        UInt32(chainIndex)
                    )
                    return rc == 1
                }
            }
        }
    }

    /// CRiskCore-side duplicate validation path using a packed digest buffer (non-layered; any scope).
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

    private static func positionAllowed(scopeByte: UInt8, chainIndex: UInt32) -> UInt8 {
        switch scopeByte {
        case CertificatePinScope.any.rawValue:
            return 1
        case CertificatePinScope.leaf.rawValue:
            return chainIndex == 0 ? 1 : 0
        case CertificatePinScope.intermediate.rawValue:
            return chainIndex >= 1 ? 1 : 0
        default:
            return 0
        }
    }

    private struct ParsedPins {
        var slots: [ContiguousArray<UInt8>]
        var scopes: [UInt8]
    }

    private static func parsePinEntries(from pinStrings: Set<String>) -> ParsedPins {
        var out = ParsedPins(slots: [], scopes: [])
        out.slots.reserveCapacity(pinStrings.count)
        out.scopes.reserveCapacity(pinStrings.count)
        for raw in pinStrings {
            guard let entry = pinEntryFromPinString(raw) else { continue }
            out.slots.append(entry.digest)
            out.scopes.append(entry.scope.rawValue)
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

    fileprivate struct PinEntry {
        let digest: ContiguousArray<UInt8>
        let scope: CertificatePinScope
    }

    /// Parses optional `leaf/` / `intermediate/` / `any/` prefix, then `sha256/<base64>` (case-insensitive).
    fileprivate static func pinEntryFromPinString(_ raw: String) -> PinEntry? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let lower = trimmed.lowercased()
        let scope: CertificatePinScope
        let rest: String
        if lower.hasPrefix("intermediate/") {
            scope = .intermediate
            rest = String(trimmed.dropFirst("intermediate/".count))
        } else if lower.hasPrefix("leaf/") {
            scope = .leaf
            rest = String(trimmed.dropFirst("leaf/".count))
        } else if lower.hasPrefix("any/") {
            scope = .any
            rest = String(trimmed.dropFirst("any/".count))
        } else {
            scope = .any
            rest = trimmed
        }
        let cleaned = rest.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let data = digestFromSha256Payload(cleaned), data.count == digestLength else {
            return nil
        }
        return PinEntry(digest: ContiguousArray(data), scope: scope)
    }

    /// Backward-compatible digest-only parse (strips optional `sha256/` prefix).
    static func digestFromPinString(_ raw: String) -> ContiguousArray<UInt8>? {
        pinEntryFromPinString(raw)?.digest
    }

    private static func digestFromSha256Payload(_ trimmed: String) -> Data? {
        let lower = trimmed.lowercased()
        let payload: String
        if lower.hasPrefix("sha256/") {
            payload = String(trimmed.dropFirst("sha256/".count))
        } else {
            payload = trimmed
        }
        let cleaned = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        return decodeBase64Digest(cleaned)
    }

    /// Canonical `sha256/<base64>` for each valid pin (sorted for stable equality).
    static func canonicalPinStrings(from pinStrings: Set<String>) -> Set<String> {
        var canonical: [String] = []
        for raw in pinStrings {
            guard let entry = pinEntryFromPinString(raw) else { continue }
            let b64 = Data(entry.digest).base64EncodedString()
            let body = "sha256/\(b64)"
            switch entry.scope {
            case .any:
                canonical.append(body)
            case .leaf:
                canonical.append("leaf/\(body)")
            case .intermediate:
                canonical.append("intermediate/\(body)")
            }
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
        packedScopes.withUnsafeMutableBufferPointer { buf in
            if let base = buf.baseAddress {
                memset(base, 0, buf.count)
            }
        }
        slots.removeAll(keepingCapacity: false)
        packedDigests.removeAll(keepingCapacity: false)
        packedScopes.removeAll(keepingCapacity: false)
        scopeBytes.removeAll(keepingCapacity: false)
    }
}
