import CRiskCore
import CryptoKit
import Foundation
import Security

struct AppSigningIdentityDetector: Detector {
    enum BundleContainer: String, Sendable, Codable {
        case app
        case appExtension = "appex"
        case other
    }

    struct IdentitySnapshot: Sendable, Codable, Equatable {
        let teamIdentifierEntitlement: String?
        let applicationIdentifier: String?
        let bundleIdentifier: String?
        let infoPlistBundleIdentifier: String?
        let getTaskAllow: Bool?
        let bundleContainer: BundleContainer

        var derivedTeamIdentifier: String? {
            AppSigningIdentityDetector.teamPrefix(from: applicationIdentifier)
        }

        var effectiveTeamIdentifier: String? {
            AppSigningIdentityDetector.normalized(teamIdentifierEntitlement) ?? derivedTeamIdentifier
        }

        var effectiveBundleIdentifier: String? {
            AppSigningIdentityDetector.normalized(bundleIdentifier)
                ?? AppSigningIdentityDetector.normalized(infoPlistBundleIdentifier)
        }

        var materialCoverage: String {
            var components: [String] = []
            if AppSigningIdentityDetector.normalized(teamIdentifierEntitlement) != nil {
                components.append("team_entitlement")
            } else if derivedTeamIdentifier != nil {
                components.append("team_derived")
            }
            if AppSigningIdentityDetector.normalized(applicationIdentifier) != nil {
                components.append("application_identifier")
            }
            if effectiveBundleIdentifier != nil {
                components.append("bundle_identifier")
            }
            if getTaskAllow != nil {
                components.append("get_task_allow")
            }
            components.append("container:\(bundleContainer.rawValue)")
            return components.joined(separator: ",")
        }

        var bindingFingerprint: String {
            AppSigningIdentityDetector.bindingFingerprint(for: self)
        }

        var isExecutableAppContainer: Bool {
            bundleContainer == .app || bundleContainer == .appExtension
        }
    }

    struct IdentityBaseline: Codable, Equatable, Sendable {
        let teamIdentifier: String
        let applicationIdentifier: String
        let bundleIdentifier: String
    }

    struct Finding: Sendable, Equatable {
        let signalID: String
        let method: String
        let score: Double
        let evidence: [String: String]
        let state: RiskSignalState
        let weightHint: Double
        let poison: Bool
    }

    struct Inspection: Sendable {
        let snapshot: IdentitySnapshot
        let findings: [Finding]
        let baselineStored: Bool

        var shouldPoison: Bool {
            findings.contains(where: \.poison)
        }

        var score: Double {
            min(findings.reduce(0) { $0 + $1.score }, 100)
        }

        var methods: [String] {
            findings.map(\.method)
        }

        var reasonCodes: [String] {
            findings.map(\.signalID)
        }

        var statusCode: String {
            if shouldPoison {
                return "tampered"
            }
            if findings.isEmpty {
                return "clean"
            }
            return "soft_anomaly"
        }

        var baselineEligibility: String {
            if snapshot.effectiveBundleIdentifier == nil {
                return "missing_bundle_identifier"
            }
            if snapshot.applicationIdentifier == nil {
                return "missing_application_identifier"
            }
            if snapshot.effectiveTeamIdentifier == nil {
                return "missing_team_identifier"
            }
            return "eligible"
        }

        var telemetry: [String: String] {
            var rows: [String: String] = [
                "signing_identity_status": statusCode,
                "signing_identity_fp": snapshot.bindingFingerprint,
                "signing_identity_coverage": snapshot.materialCoverage,
                "signing_identity_reason_codes": reasonCodes.joined(separator: ","),
                "signing_identity_baseline_eligibility": baselineEligibility,
            ]
            if baselineStored {
                rows["signing_identity_baseline_stored"] = "1"
            }
            return rows
        }

        var detectorResult: DetectorResult {
            DetectorResult(score: score, methods: methods)
        }

        var signals: [RiskSignal] {
            guard !findings.isEmpty else { return [] }

            let findingIDs = findings.map(\.signalID).sorted()
            let poisonFindingIDs = findings.filter(\.poison).map(\.signalID).sorted()
            let softFindingIDs = findings.filter { !$0.poison }.map(\.signalID).sorted()
            var aggregateEvidence: [String: String] = [
                "methods": methods.joined(separator: ","),
                "team_identifier": snapshot.effectiveTeamIdentifier ?? "nil",
                "derived_team_identifier": snapshot.derivedTeamIdentifier ?? "nil",
                "application_identifier": snapshot.applicationIdentifier ?? "nil",
                "bundle_identifier": snapshot.bundleIdentifier ?? "nil",
                "info_bundle_identifier": snapshot.infoPlistBundleIdentifier ?? "nil",
                "effective_bundle_identifier": snapshot.effectiveBundleIdentifier ?? "nil",
                "get_task_allow": snapshot.getTaskAllow.map { $0 ? "1" : "0" } ?? "nil",
                "finding_ids": findingIDs.joined(separator: ","),
                "finding_count": "\(findingIDs.count)",
                "poison_count": "\(poisonFindingIDs.count)",
                "soft_count": "\(softFindingIDs.count)",
                "team_identifier_source": AppSigningIdentityDetector.teamIdentifierSource(for: snapshot),
                "bundle_container": snapshot.bundleContainer.rawValue,
                "signing_identity_fp": snapshot.bindingFingerprint,
                "signing_identity_coverage": snapshot.materialCoverage,
                "signing_identity_status": statusCode,
                "baseline_eligibility": baselineEligibility,
            ]
            if !poisonFindingIDs.isEmpty {
                aggregateEvidence["poison_finding_ids"] = poisonFindingIDs.joined(separator: ",")
            }
            if !softFindingIDs.isEmpty {
                aggregateEvidence["soft_finding_ids"] = softFindingIDs.joined(separator: ",")
            }
            if !reasonCodes.isEmpty {
                aggregateEvidence["reason_codes"] = reasonCodes.joined(separator: ",")
            }
            if baselineStored {
                aggregateEvidence["baseline_stored"] = "1"
            }

            var out = [
                RiskSignal(
                    id: ObfuscatedConstants.signalAppSigningIdentityTampered,
                    category: "integrity",
                    score: score,
                    evidence: aggregateEvidence,
                    state: shouldPoison ? .tampered : .soft(confidence: 0.8),
                    layer: 2,
                    weightHint: shouldPoison ? 92 : 68
                ),
            ]

            out.append(contentsOf: findings.map { finding in
                RiskSignal(
                    id: finding.signalID,
                    category: "integrity",
                    score: finding.score,
                    evidence: finding.evidence,
                    state: finding.state,
                    layer: 2,
                    weightHint: finding.weightHint
                )
            })

            return out
        }
    }

    private static let baselineStorageKey = "com.cloudphone.riskkit.app_signing_identity.baseline.v1"
    private static let baselineLock = UnfairLock()

    private let userDefaults: UserDefaults

    init(userDefaults: UserDefaults = .standard) {
        self.userDefaults = userDefaults
    }

    func detect() throws -> DetectorResult {
        inspect().detectorResult
    }

    func asSignals() throws -> [RiskSignal] {
        let inspection = inspect()
        if inspection.shouldPoison {
            Logger.log(
                "[AppSigningIdentityDetector] forcing integrity poison: " +
                inspection.findings.map(\.signalID).joined(separator: ",")
            )
            cprisk_integrity_poison_code_signing_lane()
        }
        return inspection.signals
    }

    func telemetry() -> [String: String] {
        inspect().telemetry
    }

    func inspect() -> Inspection {
#if targetEnvironment(simulator)
        return Inspection(
            snapshot: IdentitySnapshot(
                teamIdentifierEntitlement: nil,
                applicationIdentifier: nil,
                bundleIdentifier: nil,
                infoPlistBundleIdentifier: nil,
                getTaskAllow: nil,
                bundleContainer: .other
            ),
            findings: [],
            baselineStored: false
        )
#else
        inspect(snapshot: captureCurrentSnapshot(), isDebugBuild: Self.isDebugBuild)
#endif
    }

    func inspect(snapshot: IdentitySnapshot, isDebugBuild: Bool) -> Inspection {
        guard snapshot.isExecutableAppContainer else {
            return Inspection(snapshot: snapshot, findings: [], baselineStored: false)
        }

        var findings: [Finding] = []

        let bundleIdentifier = Self.normalized(snapshot.bundleIdentifier)
        let infoBundleIdentifier = Self.normalized(snapshot.infoPlistBundleIdentifier)
        let applicationIdentifier = Self.normalized(snapshot.applicationIdentifier)
        let explicitTeamIdentifier = Self.normalized(snapshot.teamIdentifierEntitlement)
        let effectiveTeamIdentifier = snapshot.effectiveTeamIdentifier

        if bundleIdentifier == nil, infoBundleIdentifier == nil {
            findings.append(Finding(
                signalID: "app_bundle_identifier_missing",
                method: "signing_identity:bundle_identifier_missing",
                score: 28,
                evidence: [
                    "bundle_identifier": "nil",
                    "info_bundle_identifier": "nil",
                    "bundle_container": snapshot.bundleContainer.rawValue,
                ],
                state: .soft(confidence: 0.88),
                weightHint: 72,
                poison: false
            ))
        }

        if let applicationIdentifier,
           Self.teamPrefix(from: applicationIdentifier) == nil || Self.bundleSuffix(from: applicationIdentifier) == nil {
            findings.append(Finding(
                signalID: "app_identifier_malformed",
                method: "signing_identity:application_identifier_malformed",
                score: 24,
                evidence: [
                    "application_identifier": applicationIdentifier,
                ],
                state: .soft(confidence: 0.84),
                weightHint: 64,
                poison: false
            ))
        }

        if let bundleIdentifier, let infoBundleIdentifier, bundleIdentifier != infoBundleIdentifier {
            findings.append(Finding(
                signalID: "app_bundle_identifier_mismatch",
                method: "signing_identity:bundle_identifier_mismatch",
                score: 36,
                evidence: [
                    "bundle_identifier": bundleIdentifier,
                    "info_bundle_identifier": infoBundleIdentifier,
                ],
                state: .tampered,
                weightHint: 88,
                poison: true
            ))
        }

        if let applicationIdentifier {
            if let entitledBundleIdentifier = Self.bundleSuffix(from: applicationIdentifier),
               let runtimeBundleIdentifier = bundleIdentifier ?? infoBundleIdentifier,
               !Self.bundleIdentifierMatches(entitledBundleIdentifier, runtimeBundleIdentifier) {
                findings.append(Finding(
                    signalID: "app_identifier_bundle_mismatch",
                    method: "signing_identity:application_identifier_bundle_mismatch",
                    score: 42,
                    evidence: [
                        "application_identifier": applicationIdentifier,
                        "entitled_bundle_identifier": entitledBundleIdentifier,
                        "runtime_bundle_identifier": runtimeBundleIdentifier,
                    ],
                    state: .tampered,
                    weightHint: 92,
                    poison: true
                ))
            }

            if let applicationTeamIdentifier = Self.teamPrefix(from: applicationIdentifier),
               let explicitTeamIdentifier,
               applicationTeamIdentifier != explicitTeamIdentifier {
                findings.append(Finding(
                    signalID: "app_team_identifier_mismatch",
                    method: "signing_identity:team_identifier_mismatch",
                    score: 40,
                    evidence: [
                        "team_identifier_entitlement": explicitTeamIdentifier,
                        "application_identifier_prefix": applicationTeamIdentifier,
                    ],
                    state: .tampered,
                    weightHint: 90,
                    poison: true
                ))
            }
        } else if Self.requiresApplicationIdentifierEntitlement && !isDebugBuild {
            findings.append(Finding(
                signalID: "app_identifier_missing",
                method: "signing_identity:application_identifier_missing",
                score: 16,
                evidence: [
                    "bundle_identifier": bundleIdentifier ?? "nil",
                    "info_bundle_identifier": infoBundleIdentifier ?? "nil",
                ],
                state: .soft(confidence: 0.75),
                weightHint: 58,
                poison: false
            ))
        }

        if let effectiveTeamIdentifier {
            if !Self.looksLikeAppleTeamIdentifier(effectiveTeamIdentifier) {
                findings.append(Finding(
                    signalID: "app_team_identifier_abnormal",
                    method: "signing_identity:team_identifier_abnormal",
                    score: 14,
                    evidence: [
                        "team_identifier": effectiveTeamIdentifier,
                        "source": explicitTeamIdentifier == nil ? "application_identifier_prefix" : "entitlement",
                    ],
                    state: .soft(confidence: 0.8),
                    weightHint: 55,
                    poison: false
                ))
            }
        } else if Self.requiresApplicationIdentifierEntitlement && !isDebugBuild {
            findings.append(Finding(
                signalID: "app_team_identifier_missing",
                method: "signing_identity:team_identifier_missing",
                score: 16,
                evidence: [
                    "application_identifier": applicationIdentifier ?? "nil",
                ],
                state: .soft(confidence: 0.8),
                weightHint: 60,
                poison: false
            ))
        }

        if snapshot.getTaskAllow == true && !isDebugBuild {
            findings.append(Finding(
                signalID: "app_get_task_allow_enabled",
                method: "signing_identity:get_task_allow_enabled_in_release",
                score: 34,
                evidence: [
                    "get_task_allow": "1",
                    "build_profile": "release",
                ],
                state: .tampered,
                weightHint: 86,
                poison: true
            ))
        }

        let baselineStored = reconcileBaseline(
            bundleIdentifier: bundleIdentifier ?? infoBundleIdentifier,
            applicationIdentifier: applicationIdentifier,
            teamIdentifier: effectiveTeamIdentifier,
            findings: &findings
        )

        return Inspection(snapshot: snapshot, findings: findings, baselineStored: baselineStored)
    }

    private func captureCurrentSnapshot() -> IdentitySnapshot {
        let bundle = Bundle.main
        let pathExtension = bundle.bundleURL.pathExtension.lowercased()
        let bundleContainer: BundleContainer

        switch pathExtension {
        case "app":
            bundleContainer = .app
        case "appex":
            bundleContainer = .appExtension
        default:
            bundleContainer = .other
        }

        #if os(macOS)
        let task = SecTaskCreateFromSelf(nil)
        return IdentitySnapshot(
            teamIdentifierEntitlement: entitlementString("com.apple.developer.team-identifier", task: task),
            applicationIdentifier: entitlementString("application-identifier", task: task),
            bundleIdentifier: Self.normalized(bundle.bundleIdentifier),
            infoPlistBundleIdentifier: Self.normalized(bundle.object(forInfoDictionaryKey: "CFBundleIdentifier") as? String),
            getTaskAllow: entitlementBool("get-task-allow", task: task),
            bundleContainer: bundleContainer
        )
        #else
        // SecTask API 仅 macOS 可用，iOS 上仅做 bundle 一致性校验
        return IdentitySnapshot(
            teamIdentifierEntitlement: nil,
            applicationIdentifier: nil,
            bundleIdentifier: Self.normalized(bundle.bundleIdentifier),
            infoPlistBundleIdentifier: Self.normalized(bundle.object(forInfoDictionaryKey: "CFBundleIdentifier") as? String),
            getTaskAllow: nil,
            bundleContainer: bundleContainer
        )
        #endif
    }

    #if os(macOS)
    private func entitlementString(_ key: String, task: SecTask?) -> String? {
        Self.normalized(entitlementValue(for: key, task: task) as? String)
    }

    private func entitlementBool(_ key: String, task: SecTask?) -> Bool? {
        guard let value = entitlementValue(for: key, task: task) else {
            return nil
        }
        if let boolValue = value as? Bool {
            return boolValue
        }
        if let number = value as? NSNumber {
            return number.boolValue
        }
        return nil
    }

    private func entitlementValue(for key: String, task: SecTask?) -> Any? {
        guard let task else { return nil }
        return SecTaskCopyValueForEntitlement(task, key as CFString, nil)
    }
    #endif

    private func reconcileBaseline(
        bundleIdentifier: String?,
        applicationIdentifier: String?,
        teamIdentifier: String?,
        findings: inout [Finding]
    ) -> Bool {
        guard let bundleIdentifier, let applicationIdentifier, let teamIdentifier else {
            return false
        }

        let current = IdentityBaseline(
            teamIdentifier: teamIdentifier,
            applicationIdentifier: applicationIdentifier,
            bundleIdentifier: bundleIdentifier
        )

        if let stored = loadBaseline() {
            let changedFields = changedFields(from: stored, to: current)
            guard !changedFields.isEmpty else {
                return false
            }

            findings.append(Finding(
                signalID: ObfuscatedConstants.signalAppSigningBaselineChanged,
                method: "signing_identity:baseline_changed",
                score: 44,
                evidence: [
                    "changed_fields": changedFields.joined(separator: ","),
                    "baseline_team_identifier": stored.teamIdentifier,
                    "current_team_identifier": current.teamIdentifier,
                    "baseline_application_identifier": stored.applicationIdentifier,
                    "current_application_identifier": current.applicationIdentifier,
                    "baseline_bundle_identifier": stored.bundleIdentifier,
                    "current_bundle_identifier": current.bundleIdentifier,
                ],
                state: .tampered,
                weightHint: 94,
                poison: true
            ))
            return false
        }

        guard findings.isEmpty else {
            return false
        }

        saveBaseline(current)
        return true
    }

    private func changedFields(from oldValue: IdentityBaseline, to newValue: IdentityBaseline) -> [String] {
        var out: [String] = []
        if oldValue.teamIdentifier != newValue.teamIdentifier {
            out.append("team_identifier")
        }
        if oldValue.applicationIdentifier != newValue.applicationIdentifier {
            out.append("application_identifier")
        }
        if oldValue.bundleIdentifier != newValue.bundleIdentifier {
            out.append("bundle_identifier")
        }
        return out
    }

    private func loadBaseline() -> IdentityBaseline? {
        Self.baselineLock.withLock {
            guard let data = userDefaults.data(forKey: Self.baselineStorageKey) else {
                return nil
            }

            return try? JSONDecoder().decode(IdentityBaseline.self, from: data)
        }
    }

    private func saveBaseline(_ baseline: IdentityBaseline) {
        Self.baselineLock.withLock {
            guard let data = try? JSONEncoder().encode(baseline) else {
                return
            }

            userDefaults.set(data, forKey: Self.baselineStorageKey)
        }
    }

    private static var isDebugBuild: Bool {
#if DEBUG
        true
#else
        false
#endif
    }

    private static var requiresApplicationIdentifierEntitlement: Bool {
#if canImport(UIKit)
        true
#else
        false
#endif
    }

    static func normalized(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else {
            return nil
        }
        return trimmed
    }

    static func teamIdentifierSource(for snapshot: IdentitySnapshot) -> String {
        if normalized(snapshot.teamIdentifierEntitlement) != nil {
            return "entitlement"
        }
        if snapshot.derivedTeamIdentifier != nil {
            return "application_identifier_prefix"
        }
        return "missing"
    }

    static func teamPrefix(from applicationIdentifier: String?) -> String? {
        guard let applicationIdentifier = normalized(applicationIdentifier),
              let separator = applicationIdentifier.firstIndex(of: ".") else {
            return nil
        }
        let prefix = String(applicationIdentifier[..<separator])
        return normalized(prefix)
    }

    static func bundleSuffix(from applicationIdentifier: String?) -> String? {
        guard let applicationIdentifier = normalized(applicationIdentifier),
              let separator = applicationIdentifier.firstIndex(of: ".") else {
            return nil
        }
        let suffix = String(applicationIdentifier[applicationIdentifier.index(after: separator)...])
        return normalized(suffix)
    }

    static func bundleIdentifierMatches(_ entitledBundleIdentifier: String, _ runtimeBundleIdentifier: String) -> Bool {
        if entitledBundleIdentifier == runtimeBundleIdentifier {
            return true
        }

        guard entitledBundleIdentifier.hasSuffix(".*"),
              entitledBundleIdentifier.count > 2 else {
            return false
        }

        let wildcardPrefix = String(entitledBundleIdentifier.dropLast(2))
        if runtimeBundleIdentifier == wildcardPrefix {
            return true
        }
        return runtimeBundleIdentifier.hasPrefix(wildcardPrefix + ".")
    }

    static func looksLikeAppleTeamIdentifier(_ teamIdentifier: String) -> Bool {
        guard teamIdentifier.count == 10 else {
            return false
        }

        return teamIdentifier.unicodeScalars.allSatisfy { scalar in
            let value = scalar.value
            return (48...57).contains(value) || (65...90).contains(value)
        }
    }

    static func bindingFingerprint(for snapshot: IdentitySnapshot) -> String {
        let material = [
            normalized(snapshot.teamIdentifierEntitlement) ?? "",
            snapshot.derivedTeamIdentifier ?? "",
            normalized(snapshot.applicationIdentifier) ?? "",
            snapshot.effectiveBundleIdentifier ?? "",
            snapshot.getTaskAllow.map { $0 ? "1" : "0" } ?? "",
            snapshot.bundleContainer.rawValue,
        ].joined(separator: "|")
        return SHA256.hash(data: Data(material.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
