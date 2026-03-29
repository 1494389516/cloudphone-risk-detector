import CRiskCore
import Darwin
import Foundation

// MARK: - Unix Socket Sweep Detection
//
// Enumerates all Unix domain socket connections in the process and inspects
// them for anomalies that may indicate Frida's IPC channels.
//
// This detector is DISABLED by default because it may produce false positives
// on normal system activity. It must be explicitly enabled via remote config
// (ServerRiskPolicy.enableUnixSocketSweep).

/// Maximum file descriptor range to scan for Unix domain sockets.
private let fdScanMax: Int32 = 1024

/// Suspicious path prefixes for Unix domain socket detection.
private let suspiciousPathPrefixes: [String] = [
    "/tmp/",
    "/var/tmp/",
]

/// Marker patterns often associated with Frida's Unix domain sockets.
private let fridaPathMarkers: [String] = [
    "frida",
    "linjector",
    "gmain",
    "gum-js-loop",
    "gdbus",
    "pool-frida",
]

/// Represents a single Unix domain socket observation.
private struct SocketObservation {
    let fd: Int32
    let localPath: String
    let peerPath: String
    let isAbstract: Bool
    let isSuspicious: Bool
    let reason: String
}

/// Unix domain socket full-sweep detector (disabled by default).
///
/// Enumerates all Unix domain socket connections, detecting anomalous IPC
/// channels that may indicate Frida or other instrumentation frameworks.
///
/// Note: This detector is disabled by default because socket enumeration
/// can produce false positives on normal system activity. Enable via
/// `ServerRiskPolicy.enableUnixSocketSweep` from remote configuration.
struct UnixSocketSweepDetector: Detector {

    /// Whether this detector is enabled (reads from remote configuration).
    private static var enabled: Bool {
        PolicyManager.shared.activePolicy?.enableUnixSocketSweep ?? false
    }

    @inline(never)
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unix_socket_sweep:unavailable_simulator"])
#else
        return detectKernel()
#endif
    }

    /// Keep the VMP-targeted `detect()` entry narrow and stable in optimized builds.
    @inline(never)
    private func detectKernel() -> DetectorResult {
        guard Self.enabled else {
            return DetectorResult(score: 0, methods: ["unix_socket_sweep:disabled"])
        }

        var score: Double = 0
        var methods: [String] = []

        let observations = sweepUnixSockets()

        // Classify observations
        var abstractCount = 0
        var tmpCount = 0
        var fridaMarkerCount = 0
        var totalSuspicious = 0

        for obs in observations where obs.isSuspicious {
            totalSuspicious += 1

            if obs.isAbstract {
                abstractCount += 1
            }
            if obs.localPath.hasPrefix("/tmp/") || obs.localPath.hasPrefix("/var/tmp/") ||
                obs.peerPath.hasPrefix("/tmp/") || obs.peerPath.hasPrefix("/var/tmp/") {
                tmpCount += 1
            }
            let combinedLower = (obs.localPath + " " + obs.peerPath).lowercased()
            if fridaPathMarkers.contains(where: { combinedLower.contains($0) }) {
                fridaMarkerCount += 1
            }

            methods.append("unix_socket_sweep:fd=\(obs.fd):\(obs.reason):\(obs.localPath)")
        }

        // Scoring
        // Abstract namespace sockets are extremely rare on iOS
        if abstractCount >= 1 {
            score += 10.0 * Double(abstractCount)
        }

        // Sockets in /tmp or /var/tmp
        if tmpCount >= 1 {
            score += 8.0 * Double(tmpCount)
        }

        // Direct Frida path marker hits
        if fridaMarkerCount >= 1 {
            score += 15.0 * Double(fridaMarkerCount)
        }

        // Multiple suspicious sockets — compound bonus
        if totalSuspicious >= 3 {
            score += Double(totalSuspicious) * 3
        }

        return DetectorResult(score: min(score, 80), methods: methods)
    }

    // MARK: - Socket Sweep

    /// Enumerates file descriptors looking for Unix domain sockets and
    /// collects their local/peer address information.
    private func sweepUnixSockets() -> [SocketObservation] {
        var observations: [SocketObservation] = []

        for fd: Int32 in 3..<fdScanMax {
            let localInfo = getSocketPath(fd: fd, getPeer: false)
            guard let localPath = localInfo.path, localInfo.isUnix else { continue }

            let peerInfo = getSocketPath(fd: fd, getPeer: true)
            let peerPath = peerInfo.path ?? ""

            let isAbstract = localPath.isEmpty || localPath.utf8.first == 0

            // Check for suspicious patterns
            var isSuspicious = false
            var reason = ""

            if isAbstract {
                isSuspicious = true
                reason = "abstract_namespace"
            }

            let localLower = localPath.lowercased()
            let peerLower = peerPath.lowercased()

            if suspiciousPathPrefixes.contains(where: { localPath.hasPrefix($0) || peerPath.hasPrefix($0) }) {
                isSuspicious = true
                reason = reason.isEmpty ? "tmp_path" : reason + "+tmp_path"
            }

            if fridaPathMarkers.contains(where: { localLower.contains($0) || peerLower.contains($0) }) {
                isSuspicious = true
                reason = reason.isEmpty ? "frida_marker" : reason + "+frida_marker"
            }

            // Check for socket in unexpected locations (not /var/run, /tmp, or system paths)
            if !localPath.isEmpty && !isAbstract {
                let isExpectedPrefix = localPath.hasPrefix("/var/run/") ||
                    localPath.hasPrefix("/var/tmp/") ||
                    localPath.hasPrefix("/tmp/") ||
                    localPath.hasPrefix("/private/var/") ||
                    localPath.hasPrefix("/usr/") ||
                    localPath.hasPrefix("/etc/")
                if !isExpectedPrefix && !localPath.hasPrefix("/") {
                    // Relative path socket — unusual
                    isSuspicious = true
                    reason = reason.isEmpty ? "relative_path" : reason + "+relative_path"
                }
            }

            observations.append(SocketObservation(
                fd: fd,
                localPath: localPath,
                peerPath: peerPath,
                isAbstract: isAbstract,
                isSuspicious: isSuspicious,
                reason: reason
            ))
        }

        return observations
    }

    // MARK: - Socket Address Query

    /// Gets the path associated with a Unix domain socket file descriptor.
    /// Uses getsockname for local address or getpeername for peer address.
    private func getSocketPath(fd: Int32, getPeer: Bool) -> (path: String?, isUnix: Bool) {
        var addr = sockaddr_un()
        var len = socklen_t(MemoryLayout<sockaddr_un>.size)

        let result: Int32
        if getPeer {
            result = withUnsafeMutablePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    getpeername(fd, sockPtr, &len)
                }
            }
        } else {
            result = withUnsafeMutablePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    getsockname(fd, sockPtr, &len)
                }
            }
        }

        guard result == 0, addr.sun_family == sa_family_t(AF_UNIX) else {
            return (nil, false)
        }

        // Extract path from sockaddr_un
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        let path = withUnsafePointer(to: &addr.sun_path) { ptr in
            let cptr = UnsafeRawPointer(ptr).assumingMemoryBound(to: CChar.self)
            let strLen = strnlen(cptr, maxLen)
            if strLen == 0 {
                // Could be an abstract namespace socket (sun_path[0] == '\0')
                // Try to read the abstract name after the leading NUL
                if maxLen > 1 && cptr[1] != 0 {
                    let abstractLen = strnlen(cptr + 1, maxLen - 1)
                    return "@" + String(data: Data(bytes: cptr + 1, count: abstractLen), encoding: .utf8)!
                }
                return ""
            }
            return String(data: Data(bytes: cptr, count: strLen), encoding: .utf8) ?? ""
        }

        return (path, true)
    }
}

// MARK: - Signal Conversion

extension UnixSocketSweepDetector {
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()

        // If disabled, emit no signals
        if result.methods.contains("unix_socket_sweep:disabled") {
            return []
        }

        guard result.score > 0 else { return [] }

        let suspiciousMethods = result.methods.filter { $0.hasPrefix("unix_socket_sweep:") && !$0.contains("disabled") }

        var signals: [RiskSignal] = []

        if !suspiciousMethods.isEmpty {
            let confidence = min(result.score / 60.0, 1.0)
            signals.append(RiskSignal(
                id: "unix_socket_anomaly",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(result.score, 40),
                evidence: [
                    "detail": suspiciousMethods.joined(separator: ","),
                    "suspicious_count": "\(suspiciousMethods.count)",
                ],
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 45
            ))
        }

        return signals
    }
}
