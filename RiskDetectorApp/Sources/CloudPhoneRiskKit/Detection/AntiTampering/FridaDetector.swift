import CRiskCore
import Darwin
import Foundation
struct FridaDetector: Detector {
    let knownPorts: [Int] = [27042, 27043, 23946]
    let knownServerPaths: [String] = ObfuscatedConstants.fridaServerPaths

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        if let envHit = detectFridaEnv() {
            score += 18
            methods.append("\(ObfuscatedConstants.methodPrefixFridaEnv)\(envHit)")
        }

        if let port = detectOpenFridaPort() {
            score += 16
            methods.append("\(ObfuscatedConstants.methodPrefixFridaPort)\(port)")
        }

        if detectFridaFileArtifact() {
            score += 18
            methods.append("\(ObfuscatedConstants.methodPrefixFridaFile)server")
        }

        return DetectorResult(score: min(score, 45), methods: methods)
#endif
    }

    private func detectFridaEnv() -> String? {
        let keys = ObfuscatedConstants.fridaEnvKeys
        for key in keys {
            guard let value = getenv(key) else { continue }
            let text = String(cString: value).lowercased()
            if text.contains(ObfuscatedConstants.keywordFrida) || key.contains(ObfuscatedConstants.fridaEnvNeedleUpper) {
                return key.lowercased()
            }
        }
        return nil
    }

    func detectFridaFileArtifact() -> Bool {
        for path in knownServerPaths where fileExists(path: path) {
            return true
        }
        return false
    }

    private func detectOpenFridaPort() -> Int? {
        for port in knownPorts where isPortOpen(port) {
            return port
        }
        return nil
    }

    private func isPortOpen(_ port: Int) -> Bool {
        var rawErrno: CInt = 0
        let fd = cprisk_socket_direct(AF_INET, SOCK_STREAM, 0, &rawErrno)
        guard fd >= 0 else { return false }
        defer { _ = cprisk_close_direct(fd, nil) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr -> Int32 in
                var connectErrno: CInt = 0
                return cprisk_connect_direct(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size), &connectErrno)
            }
        }
        return result == 0
    }

    private func fileExists(path: String) -> Bool {
        var rawErrno: CInt = 0
        let result = path.withCString { cprisk_access_direct($0, F_OK, &rawErrno) }
        if result == 0 { return true }
        if rawErrno == ENOENT || rawErrno == ENOTDIR { return false }
        Logger.log("[FD] fileExists(\(path)) errno=\(rawErrno), treating as non-existent")
        return false
    }
}
