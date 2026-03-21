import CRiskCore
import Darwin
import Foundation

struct FridaDetector: Detector {
    let knownPorts: [Int] = [27042, 27043, 23946]
    let knownServerPaths: [String] = ObfuscatedConstants.fridaServerPaths
    private let protocolProbeTimeoutMs: Int32 = 120
    private static let memSigLock = NSLock()
    private static var memorySignatureHooks: [() -> String?] = []

    static func registerMemorySignatureHook(_ hook: @escaping () -> String?) {
        memSigLock.lock()
        memorySignatureHooks.append(hook)
        memSigLock.unlock()
    }

    static func clearMemorySignatureHooks() {
        memSigLock.lock()
        memorySignatureHooks.removeAll()
        memSigLock.unlock()
    }

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

        let portBehavior = detectFridaPortBehaviors()
        score += portBehavior.score
        methods.append(contentsOf: portBehavior.methods)

        if detectFridaFileArtifact() {
            score += 18
            methods.append("\(ObfuscatedConstants.methodPrefixFridaFile)server")
        }

        if let memSig = detectMemorySignatureHit() {
            score += 10
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemorySig)\(memSig)")
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

    private var aggressivePortSweepEnabled: Bool {
        guard let raw = ProcessInfo.processInfo.environment["CPRISK_FRIDA_PORT_SWEEP"]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() else {
            return false
        }
        return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
    }

    private var fullPortSweepEnabled: Bool {
        guard let raw = ProcessInfo.processInfo.environment["CPRISK_FRIDA_PORT_SWEEP_ALL"]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() else {
            return false
        }
        return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
    }

    private var fullPortSweepMaxPort: Int {
        guard let raw = ProcessInfo.processInfo.environment["CPRISK_FRIDA_PORT_SWEEP_MAX"]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              let parsed = Int(raw),
              parsed >= 1 else {
            return 65535
        }
        return min(parsed, 65535)
    }

    /// 可选：外部/测试注入的内存命中（显式 `CPRISK_FRIDA_MEMSIG=1` 才启用，避免与内置扫描耦合）。
    private var hookMemorySignatureScanEnabled: Bool {
        guard let raw = ProcessInfo.processInfo.environment["CPRISK_FRIDA_MEMSIG"]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() else {
            return false
        }
        return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
    }

    private func candidatePorts() -> [Int] {
        if fullPortSweepEnabled {
            return Array(1...fullPortSweepMaxPort)
        }

        var ports = Set(knownPorts)
        if aggressivePortSweepEnabled {
            DynamicFeatureList.shared.suspiciousPorts.forEach {
                if (1...65535).contains($0) {
                    ports.insert($0)
                }
            }
        }
        return ports.sorted()
    }

    private func detectFridaPortBehaviors() -> (score: Double, methods: [String]) {
        var score: Double = 0
        var methods: [String] = []
        let knownPortSet = Set(knownPorts)

        for port in candidatePorts() {
            let probe = probeLocalPort(port, timeoutMs: protocolProbeTimeoutMs)
            guard probe.listening else { continue }

            if let token = probe.fingerprintToken {
                score += knownPortSet.contains(port) ? 22 : 14
                methods.append("\(ObfuscatedConstants.methodPrefixFridaProto)\(port):\(token)")
            } else if knownPortSet.contains(port) {
                score += 12
                methods.append("\(ObfuscatedConstants.methodPrefixFridaPort)\(port)")
            } else {
                score += 4
                methods.append("\(ObfuscatedConstants.methodPrefixFridaListen)\(port)")
            }
        }

        return (score, methods)
    }

    private func probeLocalPort(_ port: Int, timeoutMs: Int32) -> (listening: Bool, fingerprintToken: String?) {
        var rawErrno: CInt = 0
        let fd = cprisk_socket_direct(AF_INET, SOCK_STREAM, 0, &rawErrno)
        guard fd >= 0 else { return (false, nil) }
        defer { _ = cprisk_close_direct(fd, nil) }

        let originalFlags = fcntl(fd, F_GETFL, 0)
        if originalFlags >= 0 {
            _ = fcntl(fd, F_SETFL, originalFlags | O_NONBLOCK)
        }
        defer {
            if originalFlags >= 0 {
                _ = fcntl(fd, F_SETFL, originalFlags)
            }
        }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        var connectErrno: CInt = 0

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr -> Int32 in
                return cprisk_connect_direct(fd, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size), &connectErrno)
            }
        }
        if result != 0 {
            let errnoValue = connectErrno != 0 ? connectErrno : errno
            if errnoValue != EINPROGRESS && errnoValue != EALREADY {
                return (false, nil)
            }
            guard waitWritable(fd, timeoutMs: timeoutMs) else {
                return (false, nil)
            }
            var socketError: CInt = 0
            var optLen = socklen_t(MemoryLayout<CInt>.size)
            if getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &optLen) != 0 || socketError != 0 {
                return (false, nil)
            }
        }

        return (true, protocolFingerprint(fd, timeoutMs: timeoutMs))
    }

    private func waitWritable(_ fd: Int32, timeoutMs: Int32) -> Bool {
        var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let ready = withUnsafeMutablePointer(to: &descriptor) { ptr in
            poll(ptr, 1, timeoutMs)
        }
        return ready > 0 && (descriptor.revents & Int16(POLLOUT)) != 0
    }

    private func waitReadable(_ fd: Int32, timeoutMs: Int32) -> Bool {
        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let ready = withUnsafeMutablePointer(to: &descriptor) { ptr in
            poll(ptr, 1, timeoutMs)
        }
        let readableMask = Int16(POLLIN | POLLHUP)
        return ready > 0 && (descriptor.revents & readableMask) != 0
    }

    private func protocolFingerprint(_ fd: Int32, timeoutMs: Int32) -> String? {
        let sec = Int(timeoutMs / 1000)
        let usec = Int32((timeoutMs % 1000) * 1000)
        var sendTimeout = timeval(tv_sec: sec, tv_usec: usec)
        var recvTimeout = timeval(tv_sec: sec, tv_usec: usec)
        _ = setsockopt(
            fd,
            SOL_SOCKET,
            SO_SNDTIMEO,
            &sendTimeout,
            socklen_t(MemoryLayout<timeval>.size)
        )
        _ = setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &recvTimeout,
            socklen_t(MemoryLayout<timeval>.size)
        )

        let probes = ["AUTH\r\n", "GET / HTTP/1.0\r\n\r\n", "\u{0000}"]
        for probe in probes {
            probe.withCString { cstr in
                _ = send(fd, cstr, strlen(cstr), 0)
            }
        }
        guard waitReadable(fd, timeoutMs: timeoutMs) else { return nil }

        var buffer = [UInt8](repeating: 0, count: 160)
        let readCount = recv(fd, &buffer, buffer.count, 0)
        guard readCount > 0 else { return nil }

        let response = String(decoding: buffer.prefix(Int(readCount)), as: UTF8.self).lowercased()
        if response.contains("frida") { return "frida" }
        if response.contains("gum") { return "gum" }
        if response.contains("re.frida") { return "re.frida" }
        if response.contains("dbus") { return "dbus" }
        if response.contains("auth") && response.contains("reject") { return "dbus_auth" }
        return nil
    }

    private func detectMemorySignatureHit() -> String? {
        if hookMemorySignatureScanEnabled {
            Self.memSigLock.lock()
            let hooks = Self.memorySignatureHooks
            Self.memSigLock.unlock()
            for hook in hooks {
                guard let hit = hook()?.trimmingCharacters(in: .whitespacesAndNewlines),
                      !hit.isEmpty else {
                    continue
                }
                return hit
            }
        }

        if let builtinHit = FridaBuiltinMemorySignatureScanner.scanIfNeeded() {
            return builtinHit
        }
        return nil
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
