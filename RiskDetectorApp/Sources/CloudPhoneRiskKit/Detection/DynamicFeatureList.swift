import Foundation

/// Centralized dynamic feature list shared by multiple detectors.
/// Initialized with hardcoded defaults; RemoteConfig can append additional patterns at runtime.
/// All mutations are thread-safe.
final class DynamicFeatureList: @unchecked Sendable {
    static let shared = DynamicFeatureList()

    private struct State {
        var additionalLibraries: [String] = []
        var additionalPaths: [String] = []
        var additionalPorts: [Int] = []
    }
    private let state = Mutex(State())

    // MARK: - Suspicious library tokens (used by SDKIntegrityChecker, DyldImageMonitor)

    private static var defaultSuspiciousLibraries: [String] { ObfuscatedConstants.suspiciousLibraryTokensForDyld }

    var suspiciousLibraries: [String] {
        state.withLock { s in
            Self.defaultSuspiciousLibraries + s.additionalLibraries
        }
    }

    // MARK: - Suspicious file paths (used by FridaSocketDetector)

    private static var defaultSuspiciousPaths: [String] {
        let f = ObfuscatedConstants.keywordFrida
        return [
            "/tmp/\(f)-",
            "/tmp/.\(f)-",
            "/tmp/linjector",
            "/private/tmp/\(f)-",
            "/private/tmp/.\(f)-",
        ]
    }

    var suspiciousPaths: [String] {
        state.withLock { s in
            Self.defaultSuspiciousPaths + s.additionalPaths
        }
    }

    // MARK: - Suspicious ports (reserved for future TCP-based detection)

    private static let defaultSuspiciousPorts: [Int] = [
        27042, 27043, 4444
    ]

    var suspiciousPorts: [Int] {
        state.withLock { s in
            Self.defaultSuspiciousPorts + s.additionalPorts
        }
    }

    // MARK: - Update from RemoteConfig

    /// Append dynamic patterns from a verified RemoteConfig.
    /// Caller is responsible for verifying config signature before calling this method.
    func applyRemoteConfig(
        additionalSuspiciousLibraries: [String]?,
        additionalSuspiciousPaths: [String]?,
        additionalSuspiciousPorts: [Int]?
    ) {
        state.withLock { s in
            if let libs = additionalSuspiciousLibraries {
                let lowered = Set(libs.map { $0.lowercased() })
                for token in lowered where !s.additionalLibraries.contains(token) {
                    s.additionalLibraries.append(token)
                }
            }
            if let paths = additionalSuspiciousPaths {
                let unique = Set(paths)
                for path in unique where !s.additionalPaths.contains(path) {
                    s.additionalPaths.append(path)
                }
            }
            if let ports = additionalSuspiciousPorts {
                let unique = Set(ports)
                for port in unique where !s.additionalPorts.contains(port) {
                    s.additionalPorts.append(port)
                }
            }
        }

        #if DEBUG
        Logger.log("DynamicFeatureList.applyRemoteConfig: libs=+\(additionalSuspiciousLibraries?.count ?? 0) paths=+\(additionalSuspiciousPaths?.count ?? 0) ports=+\(additionalSuspiciousPorts?.count ?? 0)")
        #endif
    }

    /// Reset dynamic additions (keeps hardcoded defaults).
    func resetDynamic() {
        state.withLock { s in
            s.additionalLibraries.removeAll()
            s.additionalPaths.removeAll()
            s.additionalPorts.removeAll()
        }
    }

    private init() {}
}
