import Foundation

public enum FunctionCFFTier: String, CaseIterable, Codable, Sendable {
    case heavy
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

    public init() {}
}

public struct FunctionCFFPolicy: Codable, Equatable, Sendable {
    public let version: Int
    public let heavy: [String]
    public let light: [String]
    public let never: [String]
    public let regionOnly: [String]
    public let antiDeobfuscation: AntiDeobfuscationOptions

    public init(
        version: Int,
        heavy: [String],
        light: [String],
        never: [String],
        regionOnly: [String],
        antiDeobfuscation: AntiDeobfuscationOptions
    ) {
        self.version = version
        self.heavy = heavy
        self.light = light
        self.never = never
        self.regionOnly = regionOnly
        self.antiDeobfuscation = antiDeobfuscation
    }

    public func functions(for tier: FunctionCFFTier) -> [String] {
        switch tier {
        case .heavy:
            return heavy
        case .light:
            return light
        case .never:
            return never
        case .regionOnly:
            return regionOnly
        }
    }

    public func tier(for symbol: String) -> FunctionCFFTier? {
        if heavy.contains(symbol) { return .heavy }
        if light.contains(symbol) { return .light }
        if never.contains(symbol) { return .never }
        if regionOnly.contains(symbol) { return .regionOnly }
        return nil
    }

    public var allManagedFunctions: [String] {
        unique(heavy + light + never + regionOnly)
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
                append(symbol, to: tier, heavy: &heavy, light: &light, never: &never, regionOnly: &regionOnly)
            }
        }

        return FunctionCFFPolicy(
            version: version,
            heavy: unique(heavy),
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
    default:
        break
    }
}

private func append(
    _ symbol: String,
    to tier: FunctionCFFTier,
    heavy: inout [String],
    light: inout [String],
    never: inout [String],
    regionOnly: inout [String]
) {
    switch tier {
    case .heavy:
        heavy.append(symbol)
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
