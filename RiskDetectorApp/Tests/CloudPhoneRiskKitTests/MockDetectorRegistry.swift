import Foundation
@testable import CloudPhoneRiskKit

/// Mock implementation of DetectorRegistering for unit tests.
///
/// Allows tests to inject predetermined results for any detector type,
/// verify seal behavior, and simulate registration/unregistration.
final class MockDetectorRegistry: DetectorRegistering {

    // MARK: - Stubbed responses

    var stubbedResults: [DetectorRegistry.DetectorType: DetectorResult] = [:]
    var stubbedGroupResults: [DetectorRegistry.DetectorGroup: GroupDetectionResult] = [:]
    var stubbedManifest: [DetectorRegistry.DetectorType: DetectorRegistry.DetectorManifest] = [:]

    // MARK: - Call tracking

    private(set) var detectCalledTypes: [DetectorRegistry.DetectorType] = []
    private(set) var detectCalledGroups: [DetectorRegistry.DetectorGroup] = []
    private(set) var detectAllCalledCount = 0
    private(set) var registeredTypes: Set<DetectorRegistry.DetectorType> = []
    private(set) var unregisteredTypes: Set<DetectorRegistry.DetectorType> = []
    private(set) var sealCallCount = 0

    // MARK: - State

    private var _isSealed = false
    var isSealed: Bool { _isSealed }

    // MARK: - DetectorRegistering

    func detect(type: DetectorRegistry.DetectorType) -> DetectorResult {
        detectCalledTypes.append(type)
        return stubbedResults[type] ?? DetectorResult(score: 0, methods: ["mock:no_result"])
    }

    func detect(group: DetectorRegistry.DetectorGroup) -> GroupDetectionResult {
        detectCalledGroups.append(group)
        if let stubbed = stubbedGroupResults[group] {
            return stubbed
        }
        return GroupDetectionResult(results: [], totalScore: 0, methods: ["mock:no_group_result"])
    }

    func detectAll(enabledTypes: Set<DetectorRegistry.DetectorType>) -> ComprehensiveDetectionResult {
        detectAllCalledCount += 1
        var results: [(DetectorRegistry.DetectorType, DetectorResult)] = []
        var totalScore: Double = 0
        var methods: [String] = []

        for type in enabledTypes {
            let result = stubbedResults[type] ?? DetectorResult(score: 0, methods: [])
            results.append((type, result))
            totalScore += result.score
            methods.append(contentsOf: result.methods)
        }

        return ComprehensiveDetectionResult(
            results: results,
            totalScore: min(totalScore, 100),
            methods: methods
        )
    }

    func register(type: DetectorRegistry.DetectorType, factory: @escaping DetectorRegistry.DetectorFactory) {
        guard !_isSealed else { return }
        registeredTypes.insert(type)
    }

    func unregister(type: DetectorRegistry.DetectorType) {
        guard !_isSealed else { return }
        registeredTypes.remove(type)
        unregisteredTypes.insert(type)
    }

    func seal() {
        _isSealed = true
        sealCallCount += 1
    }

    func createDetector(type: DetectorRegistry.DetectorType) -> Detector? {
        nil
    }

    func manifest(for type: DetectorRegistry.DetectorType) -> DetectorRegistry.DetectorManifest {
        stubbedManifest[type] ?? DetectorRegistry.DetectorManifest(minOS: 14.0)
    }

    func isAvailable(_ type: DetectorRegistry.DetectorType, osVersion: Double) -> Bool {
        let m = manifest(for: type)
        guard osVersion >= m.minOS else { return false }
        if let maxOS = m.maxOS, osVersion > maxOS { return false }
        return true
    }

    // MARK: - Test helpers

    func reset() {
        stubbedResults.removeAll()
        stubbedGroupResults.removeAll()
        stubbedManifest.removeAll()
        detectCalledTypes.removeAll()
        detectCalledGroups.removeAll()
        detectAllCalledCount = 0
        registeredTypes.removeAll()
        unregisteredTypes.removeAll()
        sealCallCount = 0
        _isSealed = false
    }
}
