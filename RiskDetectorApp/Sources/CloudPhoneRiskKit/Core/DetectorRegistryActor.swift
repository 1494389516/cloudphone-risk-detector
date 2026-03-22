import Foundation

// MARK: - Actor-based Detector Registry Facade
//
// Provides async/await access to DetectorRegistry for new code paths.
// Coexists with the sync DetectorRegistering protocol implementation.
//
// Usage:
//   let result = await DetectorRegistryActor.shared.detect(type: .frida)

/// Actor-based facade for detector registry operations.
///
/// Wraps `DetectorRegistry.shared` with actor isolation, providing
/// compile-time thread safety for async callers.
@available(iOS 13.0, macOS 10.15, *)
public actor DetectorRegistryActor {

    public static let shared = DetectorRegistryActor()

    // MARK: - Detection

    /// Execute a single detector type.
    public func detect(type: DetectorRegistry.DetectorType) -> DetectorResult {
        DetectorRegistry.shared.detect(type: type)
    }

    /// Execute all detectors in a group.
    public func detect(group: DetectorRegistry.DetectorGroup) -> GroupDetectionResult {
        DetectorRegistry.shared.detect(group: group)
    }

    /// Execute all enabled detector types.
    public func detectAll(enabledTypes: Set<DetectorRegistry.DetectorType>) -> ComprehensiveDetectionResult {
        DetectorRegistry.shared.detectAll(enabledTypes: enabledTypes)
    }

    // MARK: - Query

    /// Get detector manifest.
    public func manifest(for type: DetectorRegistry.DetectorType) -> DetectorRegistry.DetectorManifest {
        DetectorRegistry.shared.manifest(for: type)
    }

    /// Check detector availability for OS version.
    public func isAvailable(_ type: DetectorRegistry.DetectorType, osVersion: Double) -> Bool {
        DetectorRegistry.shared.isAvailable(type, osVersion: osVersion)
    }

    /// Whether the registry is sealed.
    public func isSealed() -> Bool {
        DetectorRegistry.shared.isSealed
    }
}
