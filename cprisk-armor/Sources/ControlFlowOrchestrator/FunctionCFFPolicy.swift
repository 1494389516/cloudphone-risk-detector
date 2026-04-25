import Foundation

public enum FunctionCFFTier: String, CaseIterable, Codable, Sendable {
    case heavy
    /// Between heavy and light: stronger than light binary rewrite budget without full heavy orchestration defaults.
    case medium
    case light
    case never
    case regionOnly
}

public struct AntiDeobfuscationOptions: Codable, Equatable, Sendable {
    public var enableRuntimeSalt: Bool = true
    public var enableFakeStateReleaseOnly: Bool = true
    public var enableMultiDispatcher: Bool = true
    public var enableDefaultPoisonForHeavy: Bool = true
    public var enablePass8CFFAwareness: Bool = true
    /// When true, Pass 9 may swap physically adjacent NOP islands under CBZ/CBNZ (+8) patterns (safe subset).
    public var enableBinaryCFGShuffle: Bool = true
    /// When true, Pass 9 may replace a NOP slot with an always-false CBNZ XZR veneer (same execution path).
    public var enableCFGOpaqueIslands: Bool = true

    public init() {}
}

public struct FunctionCFFPolicy: Codable, Equatable, Sendable {
    public let version: Int
    public let heavy: [String]
    public let medium: [String]
    public let light: [String]
    public let never: [String]
    public let regionOnly: [String]
    public let antiDeobfuscation: AntiDeobfuscationOptions

    public init(
        version: Int,
        heavy: [String],
        medium: [String] = [],
        light: [String],
        never: [String],
        regionOnly: [String],
        antiDeobfuscation: AntiDeobfuscationOptions
    ) {
        self.version = version
        self.heavy = heavy
        self.medium = medium
        self.light = light
        self.never = never
        self.regionOnly = regionOnly
        self.antiDeobfuscation = antiDeobfuscation
    }

    public func functions(for tier: FunctionCFFTier) -> [String] {
        switch tier {
        case .heavy:
            return heavy
        case .medium:
            return medium
        case .light:
            return light
        case .never:
            return never
        case .regionOnly:
            return regionOnly
        }
    }

    public func tier(for symbol: String) -> FunctionCFFTier? {
        // `never` / `regionOnly` must win over flattening tiers when a symbol is listed in multiple
        // buckets (YAML hygiene should still keep one tier per symbol).
        if never.contains(symbol) { return .never }
        if regionOnly.contains(symbol) { return .regionOnly }
        if heavy.contains(symbol) { return .heavy }
        if medium.contains(symbol) { return .medium }
        if light.contains(symbol) { return .light }
        return nil
    }

    public var allManagedFunctions: [String] {
        unique(heavy + medium + light + never + regionOnly)
    }

    public static func load(from url: URL) throws -> FunctionCFFPolicy {
        let contents = try String(contentsOf: url, encoding: .utf8)
        return try parse(contents)
    }

    public static func parse(_ contents: String) throws -> FunctionCFFPolicy {
        enum Section {
            case root
            case functions
            case antiDeobfuscation
        }

        var version = 1
        var heavy: [String] = []
        var medium: [String] = []
        var light: [String] = []
        var never: [String] = []
        var regionOnly: [String] = []
        var options = AntiDeobfuscationOptions()
        var section: Section = .root
        var activeTier: FunctionCFFTier?

        for rawLine in contents.components(separatedBy: .newlines) {
            let sanitized = stripComment(rawLine).trimmingCharacters(in: .whitespaces)
            guard !sanitized.isEmpty else { continue }

            let indentation = rawLine.prefix { $0 == " " }.count

            switch indentation {
            case 0:
                activeTier = nil
                switch sanitized {
                case "functions:":
                    section = .functions
                case "anti_deobfuscation:":
                    section = .antiDeobfuscation
                default:
                    if sanitized.hasPrefix("version:") {
                        let value = sanitized.dropFirst("version:".count).trimmingCharacters(in: .whitespaces)
                        version = Int(value) ?? version
                        section = .root
                    } else {
                        section = .root
                    }
                }
            case 2:
                switch section {
                case .functions:
                    let key = sanitized.replacingOccurrences(of: ":", with: "")
                    activeTier = FunctionCFFTier(rawValue: key)
                case .antiDeobfuscation:
                    if let (key, value) = parseKeyValue(sanitized) {
                        apply(optionKey: key, value: value, into: &options)
                    }
                case .root:
                    break
                }
            default:
                guard section == .functions, sanitized.hasPrefix("- ") else { continue }
                let symbol = String(sanitized.dropFirst(2)).trimmingCharacters(in: .whitespaces)
                guard !symbol.isEmpty, let tier = activeTier else { continue }
                append(symbol, to: tier, heavy: &heavy, medium: &medium, light: &light, never: &never, regionOnly: &regionOnly)
            }
        }

        // Cross-tier duplicate detection: a symbol that appears in two
        // tiers (e.g. accidentally pasted into both `heavy:` and `light:`)
        // would silently dedupe through `unique()` while `tier()` returns
        // the higher-precedence classification. Surface the conflict so
        // the policy author resolves it explicitly.
        let crossTierDupes = findCrossTierDuplicates(
            heavy: heavy, medium: medium, light: light, never: never, regionOnly: regionOnly
        )
        if !crossTierDupes.isEmpty {
            FileHandle.standardError.write(Data(
                ("warning: cprisk_armor cff_policy: symbol(s) listed in multiple tiers — " +
                 "tier() will use highest precedence (never > regionOnly > heavy > medium > light), " +
                 "but you should remove the duplicates: " +
                 crossTierDupes.joined(separator: ", ") + "\n").utf8
            ))
        }

        return FunctionCFFPolicy(
            version: version,
            heavy: unique(heavy),
            medium: unique(medium),
            light: unique(light),
            never: unique(never),
            regionOnly: unique(regionOnly),
            antiDeobfuscation: options
        )
    }
}

private func stripComment(_ line: String) -> String {
    guard let index = line.firstIndex(of: "#") else {
        return line
    }
    return String(line[..<index])
}

private func parseKeyValue(_ line: String) -> (String, String)? {
    guard let separator = line.firstIndex(of: ":") else {
        return nil
    }

    let key = String(line[..<separator]).trimmingCharacters(in: .whitespaces)
    let value = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespaces)
    return key.isEmpty ? nil : (key, value)
}

private func apply(optionKey key: String, value: String, into options: inout AntiDeobfuscationOptions) {
    let boolValue = ["1", "true", "yes", "on"].contains(value.lowercased())

    switch key {
    case "enable_runtime_salt":
        options.enableRuntimeSalt = boolValue
    case "enable_fake_state_release_only":
        options.enableFakeStateReleaseOnly = boolValue
    case "enable_multi_dispatcher":
        options.enableMultiDispatcher = boolValue
    case "enable_default_poison_for_heavy":
        options.enableDefaultPoisonForHeavy = boolValue
    case "enable_pass8_cff_awareness":
        options.enablePass8CFFAwareness = boolValue
    case "enable_binary_cfg_shuffle":
        options.enableBinaryCFGShuffle = boolValue
    case "enable_cfg_opaque_islands":
        options.enableCFGOpaqueIslands = boolValue
    default:
        break
    }
}

private func append(
    _ symbol: String,
    to tier: FunctionCFFTier,
    heavy: inout [String],
    medium: inout [String],
    light: inout [String],
    never: inout [String],
    regionOnly: inout [String]
) {
    switch tier {
    case .heavy:
        heavy.append(symbol)
    case .medium:
        medium.append(symbol)
    case .light:
        light.append(symbol)
    case .never:
        never.append(symbol)
    case .regionOnly:
        regionOnly.append(symbol)
    }
}

private func unique(_ values: [String]) -> [String] {
    var seen = Set<String>()
    return values.filter { seen.insert($0).inserted }
}

private func findCrossTierDuplicates(
    heavy: [String],
    medium: [String],
    light: [String],
    never: [String],
    regionOnly: [String]
) -> [String] {
    var counts: [String: Int] = [:]
    for tierList in [heavy, medium, light, never, regionOnly] {
        for symbol in Set(tierList) {
            counts[symbol, default: 0] += 1
        }
    }
    return counts.filter { $0.value > 1 }.map { $0.key }.sorted()
}
