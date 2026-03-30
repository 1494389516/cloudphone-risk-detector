import CryptoKit
import Foundation

/// How to fill bytes between the logical payload and the fixed-size `sectcreate` placeholder section.
public enum SectionSlackPadding: Sendable {
    case zeros
    /// Deterministic high-entropy fill (SHA256-CTR style) — does not embed new secrets beyond `material`.
    case keyedPseudorandom(material: Data)
}

/// Keyed PRF stream for slack / LINKEDIT scrub (build-time only).
public enum ArmorPseudoRandomFill: Sendable {
    /// Expands `material` into `count` bytes using iterated SHA256 (label || material || counter LE).
    public static func bytes(count: Int, material: Data) -> Data {
        guard count > 0 else { return Data() }
        let label = Data("cprisk.prf.v1".utf8)
        var out = Data()
        out.reserveCapacity(Swift.min(count, 65536))
        var counter: UInt64 = 0
        while out.count < count {
            var block = Data()
            block.reserveCapacity(label.count + material.count + 8)
            block.append(label)
            block.append(material)
            var c = counter.littleEndian
            Swift.withUnsafeBytes(of: &c) { block.append(contentsOf: $0) }
            let digest = SHA256.hash(data: block)
            out.append(contentsOf: digest)
            counter &+= 1
        }
        return out.prefix(count)
    }
}
