import Foundation

/// Centralized dynamic feature list shared by multiple detectors.
/// Initialized with hardcoded defaults; RemoteConfig can append additional patterns at runtime.
/// All mutations are thread-safe.
final class DynamicFeatureList: @unchecked Sendable {
    static let shared = DynamicFeatureList()

    private let lock = NSLock()

    // MARK: - Suspicious library tokens (used by SDKIntegrityChecker, DyldImageMonitor)

    private static let defaultSuspiciousLibraries: [String] = [
        "frida", "gadget", "gum", "substrate", "libsubstrate",
        "substitute", "libsubstitute", "cycript", "libcycript",
        "libhooker", "ellekit", "sslkill", "tweakinject",
        "shadow", "dopamine"
    ]

    private var _additionalLibraries: [String] = []

    var suspiciousLibraries: [String] {
        lock.lock()
        defer { lock.unlock() }
        return Self.defaultSuspiciousLibraries + _additionalLibraries
    }

    // MARK: - Suspicious file paths (used by FridaSocketDetector)

    private static let defaultSuspiciousPaths: [String] = [
        "/tmp/frida-",
        "/tmp/.frida-",
        "/tmp/linjector",
        "/private/tmp/frida-",
        "/private/tmp/.frida-",
    ]

    private var _additionalPaths: [String] = []

    var suspiciousPaths: [String] {
        lock.lock()
        defer { lock.unlock() }
        return Self.defaultSuspiciousPaths + _additionalPaths
    }

    // MARK: - Suspicious ports (reserved for future TCP-based detection)

    private static let defaultSuspiciousPorts: [Int] = [
        27042, 27043, 4444
    ]

    private var _additionalPorts: [Int] = []

    var suspiciousPorts: [Int] {
        lock.lock()
        defer { lock.unlock() }
        return Self.defaultSuspiciousPorts + _additionalPorts
    }

    // MARK: - Update from RemoteConfig

    /// Append dynamic patterns from a verified RemoteConfig.
    /// Caller is responsible for verifying config signature before calling this method.
    func applyRemoteConfig(
        additionalSuspiciousLibraries: [String]?,
        additionalSuspiciousPaths: [String]?,
        additionalSuspiciousPorts: [Int]?
    ) {
        lock.lock()
        defer { lock.unlock() }

        if let libs = additionalSuspiciousLibraries {
            let lowered = Set(libs.map { $0.lowercased() })
            for token in lowered where !_additionalLibraries.contains(token) {
                _additionalLibraries.append(token)
            }
        }
        if let paths = additionalSuspiciousPaths {
            let unique = Set(paths)
            for path in unique where !_additionalPaths.contains(path) {
                _additionalPaths.append(path)
            }
        }
        if let ports = additionalSuspiciousPorts {
            let unique = Set(ports)
            for port in unique where !_additionalPorts.contains(port) {
                _additionalPorts.append(port)
            }
        }

        Logger.log("DynamicFeatureList.applyRemoteConfig: libs=+\(additionalSuspiciousLibraries?.count ?? 0) paths=+\(additionalSuspiciousPaths?.count ?? 0) ports=+\(additionalSuspiciousPorts?.count ?? 0)")
    }

    /// Reset dynamic additions (keeps hardcoded defaults).
    func resetDynamic() {
        lock.lock()
        _additionalLibraries.removeAll()
        _additionalPaths.removeAll()
        _additionalPorts.removeAll()
        lock.unlock()
    }

    private init() {}
}
