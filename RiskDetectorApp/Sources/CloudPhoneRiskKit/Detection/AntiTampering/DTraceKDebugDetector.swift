import Darwin
import Foundation
import MachO

/// Lightweight dtrace/kdebug activity detector.
///
/// This detector intentionally uses conservative scoring:
/// - Single hint => soft suspicion
/// - Multi-surface hints => tampering suspicion
struct DTraceKDebugDetector: Detector {
    struct Snapshot {
        let envHits: [String]
        let imageHits: [String]
        let toolPathHits: [String]
        let kdebugValues: [String: Int]
    }

    struct Assessment {
        let score: Double
        let methods: [String]
        let indicatorCount: Int
    }

    private let suspiciousEnvKeys = [
        "DYLD_PRINT_APIS",
        "DYLD_PRINT_LIBRARIES",
        "DYLD_PRINT_OPTS",
        "OS_ACTIVITY_DT_MODE",
        "MallocStackLogging",
        "DTXConnectionServicesEnabled",
    ]

    private let suspiciousImageTokens = [
        "dtrace",
        "ktrace",
        "xctrace",
        "instruments",
        "dtinstruments",
        "kdump",
    ]

    private let suspiciousToolPaths = [
        "/usr/sbin/dtrace",
        "/usr/bin/xctrace",
        "/usr/bin/ktrace",
    ]

    private let kdebugSysctlKeys = [
        "kern.kdebug",
        "debug.kdebug",
        "kern.kdebug_enable",
    ]

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["dtrace_kdebug:unavailable_simulator"])
#else
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    func assess(snapshot: Snapshot) -> Assessment {
        var score: Double = 0
        var methods: [String] = []
        var indicatorCount = 0

        if !snapshot.envHits.isEmpty {
            indicatorCount += 1
            methods.append("dtrace_kdebug:env:\(snapshot.envHits.joined(separator: ","))")
        }
        if !snapshot.imageHits.isEmpty {
            indicatorCount += 1
            methods.append("dtrace_kdebug:image:\(snapshot.imageHits.joined(separator: ","))")
        }
        if !snapshot.toolPathHits.isEmpty {
            indicatorCount += 1
            methods.append("dtrace_kdebug:tool_path:\(snapshot.toolPathHits.joined(separator: ","))")
        }
        if !snapshot.kdebugValues.isEmpty {
            indicatorCount += 1
            let detail = snapshot.kdebugValues
                .map { "\($0.key)=\($0.value)" }
                .sorted()
                .joined(separator: ",")
            methods.append("dtrace_kdebug:kdebug:\(detail)")
        }

        switch indicatorCount {
        case 0:
            return Assessment(score: 0, methods: ["dtrace_kdebug:clean"], indicatorCount: 0)
        case 1:
            score = 12
        case 2:
            score = 38
            methods.append("dtrace_kdebug:multi_surface")
        default:
            score = min(50 + Double(indicatorCount - 3) * 12, 78)
            methods.append("dtrace_kdebug:multi_surface")
        }

        return Assessment(score: score, methods: methods, indicatorCount: indicatorCount)
    }

    private func collectSnapshot() -> Snapshot {
        let environment = ProcessInfo.processInfo.environment
        let envHits: [String] = suspiciousEnvKeys.compactMap { (key: String) -> String? in
            guard let value = environment[key], !value.isEmpty else { return nil }
            return "\(key)=\(value)"
        }

        var imageHits: [String] = []
        let imageCount = _dyld_image_count()
        for index in 0..<imageCount {
            guard let cName = _dyld_get_image_name(index) else { continue }
            let path = String(cString: cName)
            let lower = path.lowercased()
            for token in suspiciousImageTokens where lower.contains(token) {
                imageHits.append("\(token)@\(path)")
                break
            }
            if imageHits.count >= 6 { break }
        }

        let toolPathHits = suspiciousToolPaths.filter { access($0, F_OK) == 0 }
        var kdebugValues: [String: Int] = [:]
        for key in kdebugSysctlKeys {
            if let value = Sysctl.int(key), value > 0 {
                kdebugValues[key] = value
            }
        }

        return Snapshot(
            envHits: envHits,
            imageHits: Array(Set(imageHits)).sorted(),
            toolPathHits: toolPathHits,
            kdebugValues: kdebugValues
        )
    }
}

extension DTraceKDebugDetector {
    func asSignals() -> [RiskSignal] {
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        guard assessment.score > 0 else { return [] }

        let evidence: [String: String] = [
            "indicator_count": "\(assessment.indicatorCount)",
            "env_hits": snapshot.envHits.joined(separator: ","),
            "image_hits": snapshot.imageHits.joined(separator: ","),
            "tool_hits": snapshot.toolPathHits.joined(separator: ","),
            "kdebug_hits": snapshot.kdebugValues
                .map { "\($0.key)=\($0.value)" }
                .sorted()
                .joined(separator: ","),
        ]

        if assessment.indicatorCount >= 2 {
            return [
                RiskSignal(
                    id: SignalID.dtraceKdebugActivity,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: assessment.score,
                    evidence: evidence,
                    state: .tampered,
                    layer: 2,
                    weightHint: 82
                ),
            ]
        }

        return [
            RiskSignal(
                id: SignalID.dtraceKdebugActivity,
                category: ObfuscatedConstants.categoryAntiTamper,
                score: assessment.score,
                evidence: evidence,
                state: .soft(confidence: 0.62),
                layer: 3,
                weightHint: 44
            ),
        ]
    }
}
