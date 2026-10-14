import Foundation

public struct WhiteBoxFixtureBundle {
    public let metadataSection: Data
    public let whiteboxCode: Data
    public let whiteboxData: Data
    public let whiteboxTag: Data

    let storage: ArmorWhiteBoxBundle

    init(storage: ArmorWhiteBoxBundle) {
        self.storage = storage
        self.metadataSection = storage.metadataSection
        self.whiteboxCode = storage.whiteboxCode
        self.whiteboxData = storage.whiteboxData
        self.whiteboxTag = storage.whiteboxTag
    }

    public func prf(domain: ArmorABI.WhiteBox.Domain, input: Data) -> Data {
        storage.prf(domain: domain, input: input)
    }
}

public enum WhiteBoxFixtureBuilder {
    /// Fixture helper for tests. The root key is required (exactly 32 bytes,
    /// non-zero) — no zero/default key fallback.
    public static func build(rootKey: Data) throws -> WhiteBoxFixtureBundle {
        WhiteBoxFixtureBundle(storage: try ArmorWhiteBox.build(rootKey: rootKey))
    }
}
