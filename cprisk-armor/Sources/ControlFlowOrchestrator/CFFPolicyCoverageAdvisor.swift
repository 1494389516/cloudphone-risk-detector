import Foundation

public struct CFFPolicyCoverageSuggestion: Equatable, Sendable {
    public let heavy: [String]
    public let medium: [String]
    public let light: [String]
    public let never: [String]
    public let skipped: [String]

    public var isEmpty: Bool {
        heavy.isEmpty && medium.isEmpty && light.isEmpty && never.isEmpty
    }

    public init(
        heavy: [String],
        medium: [String] = [],
        light: [String],
        never: [String],
        skipped: [String]
    ) {
        self.heavy = heavy
        self.medium = medium
        self.light = light
        self.never = never
        self.skipped = skipped
    }
}

public enum CFFPolicyCoverageAdvisor {
    public static func suggestExpansions(
        policy: FunctionCFFPolicy,
        availableSymbols: [String],
        limitPerTier: Int = 12
    ) -> CFFPolicyCoverageSuggestion {
        let normalizedManaged = Set(policy.allManagedFunctions.map(normalizeSymbol))

        var heavy = [String]()
        var medium = [String]()
        var light = [String]()
        var never = [String]()
        var skipped = [String]()

        var seen = Set<String>()
        for rawSymbol in availableSymbols {
            let symbol = normalizeSymbol(rawSymbol)
            guard !symbol.isEmpty else { continue }
            guard seen.insert(symbol).inserted else { continue }
            guard !normalizedManaged.contains(symbol) else { continue }

            if shouldSkip(symbol) {
                skipped.append(symbol)
                continue
            }

            if shouldNever(symbol) {
                append(symbol, into: &never, limit: limitPerTier)
                continue
            }

            if shouldHeavy(symbol) {
                append(symbol, into: &heavy, limit: limitPerTier)
                continue
            }

            if shouldLight(symbol) {
                append(symbol, into: &light, limit: limitPerTier)
                continue
            }

            if shouldMedium(symbol) {
                append(symbol, into: &medium, limit: limitPerTier)
                continue
            }
        }

        return CFFPolicyCoverageSuggestion(
            heavy: heavy.sorted(),
            medium: medium.sorted(),
            light: light.sorted(),
            never: never.sorted(),
            skipped: skipped.sorted()
        )
    }

    public static func yamlSnippet(_ suggestion: CFFPolicyCoverageSuggestion) -> String {
        [
            "functions:",
            "  heavy:",
            yamlList(suggestion.heavy),
            "  medium:",
            yamlList(suggestion.medium),
            "  light:",
            yamlList(suggestion.light),
            "  never:",
            yamlList(suggestion.never),
        ].joined(separator: "\n")
    }
}

private func normalizeSymbol(_ symbol: String) -> String {
    var normalized = symbol.trimmingCharacters(in: .whitespacesAndNewlines)
    while normalized.hasPrefix("_") {
        normalized.removeFirst()
    }
    return normalized
}

private func shouldSkip(_ symbol: String) -> Bool {
    symbol.contains("XCTest")
        || symbol.contains("CloudPhoneRiskKitTests")
        || symbol.contains("CloudPhoneRiskAppCoreTests")
        || symbol.hasPrefix("___lldb")
}

private func shouldNever(_ symbol: String) -> Bool {
    let lowered = symbol.lowercased()
    return lowered.contains("direct_syscall")
        || lowered.contains("main")
        || lowered.contains("app.")
        || lowered.contains(".init")
        || lowered.contains("deinit")
}

private func shouldHeavy(_ symbol: String) -> Bool {
    let heavyMarkers = [
        "RiskDetectionEngine.",
        "DecisionTree.",
        "ChallengeSession.",
        "TrustChainManager.",
        "anti_debug_watchdog.",
        "cprisk_watchdog_",
    ]
    return heavyMarkers.contains(where: { symbol.contains($0) })
}

/// Sits between heavy and light: AST/evaluator helpers and shared orchestration paths that benefit
/// from Pass9 admission between light and heavy (evaluated after `shouldLight` so keyword-based
/// detection symbols stay in the light bucket).
private func shouldMedium(_ symbol: String) -> Bool {
    if shouldHeavy(symbol) { return false }
    let mediumMarkers = [
        "ConditionNode.",
        "ConditionExpression.",
        "ScoreActionNode.",
        "TrustChainManager.should",
        "ChallengeSession.mark",
        "RiskDetectionEngine.fastDigest",
        "RiskDetectionEngine.treeCommit",
    ]
    return mediumMarkers.contains(where: { symbol.contains($0) })
}

private func shouldLight(_ symbol: String) -> Bool {
    let lowered = symbol.lowercased()
    let markers = ["detect", "probe", "scan", "validate", "check", "signals", "collect"]
    return markers.contains(where: lowered.contains)
}

private func append(_ symbol: String, into bucket: inout [String], limit: Int) {
    guard bucket.count < max(0, limit) else { return }
    bucket.append(symbol)
}

private func yamlList(_ values: [String]) -> String {
    if values.isEmpty {
        return "    # no suggestion"
    }
    return values.map { "    - \($0)" }.joined(separator: "\n")
}
