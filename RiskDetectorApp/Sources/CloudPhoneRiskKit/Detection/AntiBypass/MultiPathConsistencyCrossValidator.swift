import Darwin
import Foundation

/// Cross-validates critical jailbreak paths with multiple independent probes.
///
/// Requirement target:
/// - At least 4 probes (including secure probes) must be available per path.
/// - Any cross-probe inconsistency is treated as high-risk tampering.
struct MultiPathConsistencyCrossValidator: Detector {
    enum Probe: String, CaseIterable {
        case coreAccess = "core_access"
        case coreStat = "core_stat"
        case coreFopen = "core_fopen"
        case secureAccess
        case secureStat
        case secureLstat
    }

    struct PathFinding {
        let path: String
        let results: [Probe: Bool]
        let unavailableProbes: Set<Probe>

        init(path: String, results: [Probe: Bool], unavailableProbes: Set<Probe> = []) {
            self.path = path
            self.results = results
            self.unavailableProbes = unavailableProbes
        }

        var availableResults: [Probe: Bool] {
            Dictionary(uniqueKeysWithValues: results.filter { !unavailableProbes.contains($0.key) })
        }
    }

    struct Assessment {
        let score: Double
        let methods: [String]
        let inconsistentFindings: [PathFinding]
        let secureUnavailablePathCount: Int
        let insufficientCoveragePathCount: Int
        let evaluatedPathCount: Int
    }

    let criticalPaths: [String]
    private let minimumProbeCountPerPath = 4
    private let minimumStableSplitPerPath = 2
    private let secureProbes: Set<Probe> = [.secureAccess, .secureStat, .secureLstat]

    init(criticalPaths: [String] = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/var/jb",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
    ]) {
        self.criticalPaths = criticalPaths
    }

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["multipath_consistency:unavailable_simulator"])
#else
        let findings = criticalPaths.map(probePath)
        let assessment = assess(findings: findings)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    func assess(findings: [PathFinding]) -> Assessment {
        var inconsistent: [PathFinding] = []
        var methods: [String] = []
        var secureUnavailablePathCount = 0
        var insufficientCoveragePathCount = 0

        for finding in findings {
            let available = finding.availableResults
            let secureAvailable = Dictionary(uniqueKeysWithValues: available.filter { secureProbes.contains($0.key) })
            let standardAvailable = Dictionary(uniqueKeysWithValues: available.filter { !secureProbes.contains($0.key) })

            if secureAvailable.isEmpty {
                secureUnavailablePathCount += 1
            }
            if available.count < minimumProbeCountPerPath || secureAvailable.isEmpty {
                insufficientCoveragePathCount += 1
                continue
            }

            let trueCount = available.values.filter { $0 }.count
            let falseCount = available.count - trueCount
            guard trueCount > 0, falseCount > 0 else { continue }

            let stableSplit = min(trueCount, falseCount) >= minimumStableSplitPerPath
            guard stableSplit else { continue }

            let secureTrueCount = secureAvailable.values.filter { $0 }.count
            let secureFalseCount = secureAvailable.count - secureTrueCount
            let standardTrueCount = standardAvailable.values.filter { $0 }.count
            let standardFalseCount = standardAvailable.count - standardTrueCount
            let crossMismatch = (secureTrueCount > 0 && standardFalseCount > 0)
                || (secureFalseCount > 0 && standardTrueCount > 0)
            guard crossMismatch else { continue }

            let trueProbes = available
                .filter { $0.value }
                .map(\.key.rawValue)
                .sorted()
                .joined(separator: ",")
            let falseProbes = available
                .filter { !$0.value }
                .map(\.key.rawValue)
                .sorted()
                .joined(separator: ",")
            methods.append("multipath_consistency:inconsistent:\(finding.path):t=\(trueProbes):f=\(falseProbes)")
            inconsistent.append(finding)
        }

        let evaluatedPathCount = findings.count
        let coveredPathCount = max(0, evaluatedPathCount - insufficientCoveragePathCount)
        methods.insert("multipath_consistency:coverage:\(coveredPathCount)/\(evaluatedPathCount)", at: 0)
        methods.insert("multipath_consistency:secure_unavailable_paths:\(secureUnavailablePathCount)", at: 1)

        guard !inconsistent.isEmpty else {
            if evaluatedPathCount > 0 && secureUnavailablePathCount == evaluatedPathCount {
                methods.append("multipath_consistency:secure_path_unavailable_degraded")
            } else if insufficientCoveragePathCount > 0 {
                methods.append("multipath_consistency:insufficient_probe_coverage")
            } else {
                methods.append("multipath_consistency:clean")
            }
            return Assessment(
                score: 0,
                methods: methods,
                inconsistentFindings: [],
                secureUnavailablePathCount: secureUnavailablePathCount,
                insufficientCoveragePathCount: insufficientCoveragePathCount,
                evaluatedPathCount: evaluatedPathCount
            )
        }

        let score = min(72 + Double(max(0, inconsistent.count - 1)) * 6, 90)
        return Assessment(
            score: score,
            methods: methods,
            inconsistentFindings: inconsistent,
            secureUnavailablePathCount: secureUnavailablePathCount,
            insufficientCoveragePathCount: insufficientCoveragePathCount,
            evaluatedPathCount: evaluatedPathCount
        )
    }

    private func probePath(_ path: String) -> PathFinding {
        var results: [Probe: Bool] = [:]
        var unavailableProbes = Set<Probe>()
        let standardSnapshot = SVCDirectCall.standardPathProbeSnapshot(path)
        results[.coreAccess] = standardSnapshot.access ?? false
        results[.coreStat] = standardSnapshot.stat ?? false
        results[.coreFopen] = standardSnapshot.fopen ?? false
        if standardSnapshot.access == nil { unavailableProbes.insert(.coreAccess) }
        if standardSnapshot.stat == nil { unavailableProbes.insert(.coreStat) }
        if standardSnapshot.fopen == nil { unavailableProbes.insert(.coreFopen) }
        let secureSnapshot = SVCDirectCall.securePathProbeSnapshot(path)
        results[.secureAccess] = secureSnapshot.access ?? false
        results[.secureStat] = secureSnapshot.stat ?? false
        results[.secureLstat] = secureSnapshot.lstat ?? false
        if secureSnapshot.access == nil { unavailableProbes.insert(.secureAccess) }
        if secureSnapshot.stat == nil { unavailableProbes.insert(.secureStat) }
        if secureSnapshot.lstat == nil { unavailableProbes.insert(.secureLstat) }
        return PathFinding(path: path, results: results, unavailableProbes: unavailableProbes)
    }

}

extension MultiPathConsistencyCrossValidator {
    func asSignals() -> [RiskSignal] {
        let findings = criticalPaths.map(probePath)
        let assessment = assess(findings: findings)
        guard assessment.score > 0 else { return [] }

        let details = assessment.inconsistentFindings.map { finding in
            let values = finding.availableResults
                .map { "\($0.key.rawValue)=\($0.value ? "1" : "0")" }
                .sorted()
                .joined(separator: ",")
            let unavailable = finding.unavailableProbes
                .map(\.rawValue)
                .sorted()
                .joined(separator: ",")
            return "\(finding.path)[\(values)]{unavailable=\(unavailable)}"
        }.joined(separator: ";")

        return [
            RiskSignal(
                id: SignalID.multiPathCrossInconsistency,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.score,
                evidence: [
                    "path_count": "\(assessment.inconsistentFindings.count)",
                    "evaluated_path_count": "\(assessment.evaluatedPathCount)",
                    "secure_unavailable_path_count": "\(assessment.secureUnavailablePathCount)",
                    "insufficient_coverage_path_count": "\(assessment.insufficientCoveragePathCount)",
                    "detail": details,
                ],
                state: .tampered,
                layer: 2,
                weightHint: 92
            ),
        ]
    }
}
