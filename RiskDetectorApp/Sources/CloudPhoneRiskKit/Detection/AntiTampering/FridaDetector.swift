import CRiskCore
import CryptoKit
import Darwin
import Foundation

struct FridaDetector: Detector {
    static let methodPrefixPatch = "frida:patch:"
    static let methodPrefixBehavior = "frida:behavior:"

    internal static func mapRuntimeBehaviorMethodsForTesting(
        flags: UInt32,
        hitCount: UInt32 = 0
    ) -> [String] {
        mapRuntimeBehaviorMethods(flags: flags, hitCount: hitCount)
    }

    /// XOR+SHA256(label) decode — matches CRiskCore `cprisk_obf_decode_sha256_label` v1.
    private static func protoToken(label: String, enc: [UInt8]) -> String {
        let d = SHA256.hash(data: Data(label.utf8))
        let digest = Array(d)
        let bytes = enc.enumerated().map { i, b in b ^ digest[i % 32] }
        return String(decoding: bytes, as: UTF8.self)
    }

    let knownPorts: [Int] = [27042, 27043, 23946]
    let knownServerPaths: [String] = ObfuscatedConstants.fridaServerPaths
    private let artifactNoisePaths: [String] = [
        "/usr/lib/dyld",
        "/System/Library/CoreServices/SystemVersion.plist",
        "/bin/sh",
    ]
    private let protocolProbeTimeoutMs: Int32 = 120
    private static let hookState = Mutex<[() -> String?]>([])

    /// Minimal little-endian D-Bus-shaped wire prefix (method call header); elicits auth-stack replies on D-Bus speakers.
    private static let dbusShapeProbeWire: [UInt8] = [
        0x6c, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]

    static func registerMemorySignatureHook(_ hook: @escaping () -> String?) {
        hookState.withLock { $0.append(hook) }
    }

    static func clearMemorySignatureHooks() {
        hookState.withLock { $0.removeAll() }
    }

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []
        let envHit = detectFridaEnv()
        let hookSurface = detectHookedRuntimeSurfaces()

        if let envHit {
            score += 18
            methods.append("\(ObfuscatedConstants.methodPrefixFridaEnv)\(envHit)")
        }

        let portBehavior = detectFridaPortBehaviors()
        score += portBehavior.score
        methods.append(contentsOf: portBehavior.methods)

        score += hookSurface.score
        methods.append(contentsOf: hookSurface.methods)

        let memorySignatureHit = detectMemorySignatureHit()
        if let memSig = memorySignatureHit {
            score += 10
            methods.append("\(ObfuscatedConstants.methodPrefixFridaMemorySig)\(memSig)")
        }

        let runtimeChannelCount = applyFridaRuntimeCRiskSignals(score: &score, methods: &methods)

        if shouldRunAnomalousPortScan(
            envHit: envHit != nil,
            portBehavior: portBehavior,
            hookSurfaceScore: hookSurface.score,
            memorySignatureHit: memorySignatureHit != nil,
            runtimeChannelCount: runtimeChannelCount
        ) {
            let anomalousPorts = detectAnomalousListeningPorts()
            score += anomalousPorts.score
            methods.append(contentsOf: anomalousPorts.methods)
        }

        // Reduce conspicuous Swift-layer path probes on clean devices.
        // File artifact checks become a corroboration step after higher-entropy runtime/behavior hits.
        if shouldProbeFileArtifacts(
            envHit: envHit != nil,
            portBehaviorScore: portBehavior.score,
            runtimeChannelCount: runtimeChannelCount,
            memorySignatureHit: memorySignatureHit != nil,
            hookSurfaceHit: hookSurface.score > 0
        ) {
            let fileArtifact = detectFridaFileArtifactAssessment()
            if fileArtifact.detected {
                score += fileArtifact.score
                methods.append(contentsOf: fileArtifact.methods)
            }
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
#if targetEnvironment(simulator)
        false
#else
        detectFridaFileArtifactAssessment().detected
#endif
    }

    private func detectFridaFileArtifactAssessment() -> (detected: Bool, score: Double, methods: [String]) {
#if targetEnvironment(simulator)
        (false, 0, [])
#else
        struct ArtifactProbe {
            let path: String
            let real: Bool
        }

        var probes = knownServerPaths.map { ArtifactProbe(path: $0, real: true) }
        probes.append(contentsOf: artifactNoisePaths.map { ArtifactProbe(path: $0, real: false) })
        probes.shuffle()

        var hitCount = 0
        var maskedCount = 0

        for probe in probes {
            let accessExists = self.fileExists(path: probe.path)
            let statExists = self.statFileExists(path: probe.path)
            guard probe.real else { continue }

            if accessExists || statExists {
                hitCount += 1
            }
            if accessExists != statExists {
                maskedCount += 1
            }
        }

        var score: Double = 0
        var methods: [String] = []
        if hitCount > 0 {
            score += min(18 + Double(max(0, hitCount - 1)) * 4, 26)
            methods.append("\(ObfuscatedConstants.methodPrefixFridaFile)artifact_hits_\(hitCount)")
        }
        if maskedCount > 0 {
            score += min(Double(maskedCount) * 6, 12)
            methods.append("\(ObfuscatedConstants.methodPrefixFridaFile)artifact_masked_\(maskedCount)")
        }
        return (hitCount > 0 || maskedCount > 0, score, methods)
#endif
    }

    internal func shouldProbeFileArtifacts(
        envHit: Bool,
        portBehaviorScore: Double,
        runtimeChannelCount: Int,
        memorySignatureHit: Bool,
        hookSurfaceHit: Bool
    ) -> Bool {
        envHit || portBehaviorScore > 0 || runtimeChannelCount > 0 || memorySignatureHit || hookSurfaceHit
    }

    private var aggressivePortSweepEnabled: Bool {
        guard let raw = ProcessInfo.processInfo.environment[ObfuscatedConstants.envKeyCpriskFridaPortSweep]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() else {
            return false
        }
        return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
    }

    private var fullPortSweepEnabled: Bool {
        guard let raw = ProcessInfo.processInfo.environment[ObfuscatedConstants.envKeyCpriskFridaPortSweepAll]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() else {
            return false
        }
        return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
    }

    private var fullPortSweepMaxPort: Int {
        guard let raw = ProcessInfo.processInfo.environment[ObfuscatedConstants.envKeyCpriskFridaPortSweepMax]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              let parsed = Int(raw),
              parsed >= 1 else {
            return 65535
        }
        return min(parsed, 65535)
    }

    /// 可选：外部/测试注入的内存命中（显式 `CPRISK_FRIDA_MEMSIG=1` 才启用，避免与内置扫描耦合）。
    private var hookMemorySignatureScanEnabled: Bool {
        guard let raw = ProcessInfo.processInfo.environment[ObfuscatedConstants.envKeyCpriskFridaMemsig]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() else {
            return false
        }
        return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
    }

    private var anomalousPortScanEnvEnabled: Bool {
        guard let raw = ProcessInfo.processInfo.environment[ObfuscatedConstants.envKeyCpriskFridaAnomScan]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased() else {
            return false
        }
        return raw == "1" || raw == "true" || raw == "yes" || raw == "on"
    }

    private func shouldRunAnomalousPortScan(
        envHit: Bool,
        portBehavior: (score: Double, methods: [String], fridaProtocolDetected: Bool),
        hookSurfaceScore: Double,
        memorySignatureHit: Bool,
        runtimeChannelCount: Int
    ) -> Bool {
        if anomalousPortScanEnvEnabled {
            return true
        }
        if envHit || memorySignatureHit || hookSurfaceScore > 0 || runtimeChannelCount > 0 {
            return true
        }
        return portBehavior.fridaProtocolDetected
    }

    internal func candidatePortsForTesting() -> [Int] {
        candidatePorts()
    }

    internal static func proactiveProtocolPayloadsForTesting() -> [Data] {
        [Data(dbusShapeProbeWire)] + ObfuscatedConstants.fridaProtocolActiveWirePayloads.map { Data($0.utf8) }
    }

    private func candidatePorts() -> [Int] {
        if fullPortSweepEnabled {
            return Array(1...fullPortSweepMaxPort)
        }

        var ports = Set(knownPorts)
        ObfuscatedConstants.suspiciousPortsBuiltinFallback.forEach {
            if (1...65535).contains($0) {
                ports.insert($0)
            }
        }
        if aggressivePortSweepEnabled {
            DynamicFeatureList.shared.suspiciousPorts.forEach {
                if (1...65535).contains($0) {
                    ports.insert($0)
                }
            }
        }
        return ports.sorted()
    }

    private func detectFridaPortBehaviors() -> (score: Double, methods: [String], fridaProtocolDetected: Bool) {
        var score: Double = 0
        var methods: [String] = []
        var fridaProtocolDetected = false
        let knownPortSet = Set(knownPorts)

        for port in candidatePorts() {
            let probe = probeLocalPort(port, timeoutMs: protocolProbeTimeoutMs)
            guard probe.listening else { continue }

            if let token = probe.fingerprintToken {
                fridaProtocolDetected = true
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

        return (score, methods, fridaProtocolDetected)
    }

    /// Ranges omit 8080–8090, 1080–1085, 5555–5560 (common legit local services on iOS).
    private static let anomalousPortRanges: [(ClosedRange<Int>)] = [
        9090...9100,
        1337...1340,
        4242...4250,
        6666...6670,
        7777...7780,
        31337...31340,
        42000...42010,
        47000...47010,
    ]

    private func detectAnomalousListeningPorts() -> (score: Double, methods: [String]) {
        let knownCandidates = Set(candidatePorts())
        let anomalousTimeoutMs: Int32 = 50
        var score: Double = 0
        var methods: [String] = []

        for range in Self.anomalousPortRanges {
            for port in range {
                guard !knownCandidates.contains(port) else { continue }
                let probe = probeLocalPort(port, timeoutMs: anomalousTimeoutMs)
                guard probe.listening else { continue }

                if let token = probe.fingerprintToken {
                    score += 16
                    methods.append("\(ObfuscatedConstants.methodPrefixFridaAnomalousProto)\(port):\(token)")
                    continue
                }

                if localServiceRespondsLikeHttp(port: port, timeoutMs: anomalousTimeoutMs) {
                    continue
                }

                methods.append("\(ObfuscatedConstants.methodPrefixSuspiciousLocalListen)\(port)")
            }
        }

        return (score, methods)
    }

    private func localServiceRespondsLikeHttp(port: Int, timeoutMs: Int32) -> Bool {
        guard let fd = connectLocalStream(port: port, timeoutMs: timeoutMs) else {
            return false
        }
        defer { _ = cprisk_close_direct(fd, nil) }
        applySocketTimeouts(fd: fd, timeoutMs: timeoutMs)

        let req = "GET / HTTP/1.0\r\n\r\n"
        guard let sent = req.data(using: .utf8) else { return false }
        let writeCount = sent.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return send(fd, base, sent.count, 0)
        }
        guard writeCount == sent.count else { return false }

        guard waitReadable(fd, timeoutMs: timeoutMs) else { return false }
        var buffer = [UInt8](repeating: 0, count: 64)
        let readCount = recv(fd, &buffer, buffer.count, 0)
        guard readCount > 0 else { return false }
        return Self.bufferLooksLikeHttpResponsePrefix(Array(buffer.prefix(Int(readCount))))
    }

    private static func bufferLooksLikeHttpResponsePrefix(_ raw: [UInt8]) -> Bool {
        guard !raw.isEmpty else { return false }
        let head = String(decoding: raw.prefix(min(32, raw.count)), as: UTF8.self)
        return head.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("http/1.")
    }

    internal static func httpResponseLooksLikeHttpForTesting(_ data: Data) -> Bool {
        bufferLooksLikeHttpResponsePrefix(Array(data))
    }

    private func probeLocalPort(_ port: Int, timeoutMs: Int32) -> (listening: Bool, fingerprintToken: String?) {
        guard let fd = connectLocalStream(port: port, timeoutMs: timeoutMs) else {
            return (false, nil)
        }
        defer { _ = cprisk_close_direct(fd, nil) }

        applySocketTimeouts(fd: fd, timeoutMs: timeoutMs)

        // Probe proactively on the first connection so even customized listeners that no longer
        // emit a default banner still expose a live D-Bus/SASL stack.
        if let proactive = tryActiveProbe(fd: fd, payload: Data(Self.dbusShapeProbeWire), timeoutMs: timeoutMs) {
            return (true, proactive)
        }

        if let passive = receiveProtocolFingerprint(fd: fd, timeoutMs: timeoutMs) {
            return (true, passive)
        }

        for payload in activeWireProbeDatas() {
            if let token = tryActiveProbe(port: port, payload: payload, timeoutMs: timeoutMs) {
                return (true, token)
            }
        }

        return (true, nil)
    }

    private func connectLocalStream(port: Int, timeoutMs: Int32) -> Int32? {
        var rawErrno: CInt = 0
        let fd = cprisk_socket_direct(AF_INET, SOCK_STREAM, 0, &rawErrno)
        guard fd >= 0 else { return nil }

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
                _ = cprisk_close_direct(fd, nil)
                return nil
            }
            guard waitWritable(fd, timeoutMs: timeoutMs) else {
                _ = cprisk_close_direct(fd, nil)
                return nil
            }
            var socketError: CInt = 0
            var optLen = socklen_t(MemoryLayout<CInt>.size)
            if getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &optLen) != 0 || socketError != 0 {
                _ = cprisk_close_direct(fd, nil)
                return nil
            }
        }

        return fd
    }

    private func applySocketTimeouts(fd: Int32, timeoutMs: Int32) {
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
    }

    private func activeWireProbeDatas() -> [Data] {
        ObfuscatedConstants.fridaProtocolActiveWirePayloads.map { Data($0.utf8) }
    }

    private func receiveProtocolFingerprint(fd: Int32, timeoutMs: Int32) -> String? {
        guard waitReadable(fd, timeoutMs: timeoutMs) else { return nil }
        var buffer = [UInt8](repeating: 0, count: 256)
        let readCount = recv(fd, &buffer, buffer.count, 0)
        guard readCount > 0 else { return nil }
        return Self.classifyFridaProtocolBytes(Array(buffer.prefix(Int(readCount))))
    }

    private func tryActiveProbe(fd: Int32, payload: Data, timeoutMs: Int32) -> String? {
        payload.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            _ = send(fd, base, payload.count, 0)
        }
        return receiveProtocolFingerprint(fd: fd, timeoutMs: timeoutMs)
    }

    private func tryActiveProbe(port: Int, payload: Data, timeoutMs: Int32) -> String? {
        guard let fd = connectLocalStream(port: port, timeoutMs: timeoutMs) else { return nil }
        defer { _ = cprisk_close_direct(fd, nil) }
        applySocketTimeouts(fd: fd, timeoutMs: timeoutMs)
        return tryActiveProbe(fd: fd, payload: payload, timeoutMs: timeoutMs)
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

    /// Unit tests: structural + legacy literal classification for one recv buffer.
    internal static func classifyFridaWireResponseForTesting(_ data: Data) -> String? {
        classifyFridaProtocolBytes(Array(data))
    }

    private static func classifyFridaProtocolBytes(_ raw: [UInt8]) -> String? {
        guard !raw.isEmpty else { return nil }

        let fridaTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelFnFrida, enc: [0x0f, 0x3e, 0x6c, 0x77, 0x8e])
        let gumTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelGum, enc: [0xee, 0xcc, 0x4e])
        let reFridaTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelReFrida, enc: [0x62, 0x0d, 0x3e, 0x3b, 0x52, 0x9d, 0xea, 0xc7])
        let dbusTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelDbus, enc: [0x1e, 0x63, 0xe8, 0xc6])
        let authTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelAuth, enc: [0xca, 0x31, 0x82, 0x18])
        let rejectTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelReject, enc: [0x94, 0x8f, 0xdf, 0x74, 0x92, 0xab])
        let dbusAuthTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelDbusAuth, enc: [0x4b, 0xb0, 0x51, 0x07, 0x01, 0xdf, 0x65, 0x43, 0x6c])

        let saslOkTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelSaslOK, enc: [163, 108, 24, 206, 57, 195, 121])
        let saslRejTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelSaslRej, enc: [84, 17, 246, 115, 133, 52, 33, 250])
        let dbusWireTok = Self.protoToken(label: ObfuscatedConstants.fridaProtoLabelDbusWire, enc: [188, 211, 249, 16, 118, 32, 94, 49, 195])

        let response = String(decoding: raw, as: UTF8.self).lowercased()
        if response.contains(fridaTok) { return fridaTok }
        if response.contains(gumTok) { return gumTok }
        if response.contains(reFridaTok) { return reFridaTok }
        if response.contains(dbusTok) { return dbusTok }
        if response.contains(authTok), response.contains(rejectTok) { return dbusAuthTok }

        if let firstLine = response.split(separator: "\r", maxSplits: 1, omittingEmptySubsequences: false).first {
            let t = String(firstLine).trimmingCharacters(in: .whitespacesAndNewlines)
            if t == "ok" || t.hasPrefix("ok ") { return saslOkTok }
            if t.hasPrefix("rejected") || t.hasPrefix("error") { return saslRejTok }
            if t == "data" || t.hasPrefix("data ") { return dbusWireTok }
        }

        if raw.count >= 16 {
            let endian = raw[0]
            if endian == 0x6c || endian == 0x42 {
                let msgType = raw[1]
                let ver = raw[3]
                if ver == 1, (1...8).contains(msgType) {
                    let bodyLen: UInt32
                    if endian == 0x6c {
                        bodyLen = UInt32(raw[4]) | UInt32(raw[5]) << 8 | UInt32(raw[6]) << 16 | UInt32(raw[7]) << 24
                    } else {
                        bodyLen = UInt32(raw[7]) | UInt32(raw[6]) << 8 | UInt32(raw[5]) << 16 | UInt32(raw[4]) << 24
                    }
                    if bodyLen < 128 * 1024 * 1024 {
                        return dbusWireTok
                    }
                }
            }
        }

        return nil
    }

    /// CRiskCore 多路运行时信号：镜像路径 / dlsym(Gum) / 进程表；双通道及以上叠加 `runtime_fused` 提高置信。
    @discardableResult
    private func applyFridaRuntimeCRiskSignals(score: inout Double, methods: inout [String]) -> Int {
        var snap = cprisk_frida_runtime_snapshot_t()
        guard cprisk_frida_runtime_snapshot(&snap) == 0, snap.supported != 0 else {
            return 0
        }

        let imageBit = UInt32(CPRISK_FRIDA_RT_IMAGE)
        let dlsymBit = UInt32(CPRISK_FRIDA_RT_DLSYM)
        let procBit = UInt32(CPRISK_FRIDA_RT_PROC)
        let behaviorBit = UInt32(CPRISK_FRIDA_RT_BEHAVIOR)

        var channelCount = 0
        if (snap.flags & imageBit) != 0 {
            channelCount += 1
            score += 6
            methods.append(
                "\(ObfuscatedConstants.methodPrefixFridaRuntime)image_hits_\(snap.image_hit_count)"
            )
        }
        if (snap.flags & dlsymBit) != 0 {
            channelCount += 1
            score += 8
            methods.append(
                "\(ObfuscatedConstants.methodPrefixFridaRuntime)dlsym_hits_\(snap.dlsym_hit_count)"
            )
        }
        if (snap.flags & procBit) != 0 {
            channelCount += 1
            score += 7
            methods.append(
                "\(ObfuscatedConstants.methodPrefixFridaRuntime)proc_hits_\(snap.proc_hit_count)"
            )
        }
        if (snap.flags & behaviorBit) != 0 {
            channelCount += 1
            let behaviorMethods = Self.mapRuntimeBehaviorMethods(
                flags: snap.behavior_flags,
                hitCount: snap.behavior_hit_count
            )
            if !behaviorMethods.isEmpty {
                score += min(10 + Double(max(0, behaviorMethods.count - 1)) * 3, 18)
                methods.append(contentsOf: behaviorMethods)
            }
        }
        if channelCount >= 2 {
            score += 18
            methods.append(
                "\(ObfuscatedConstants.methodPrefixFridaRuntimeFused)channels_\(channelCount)"
            )
        }
        return channelCount
    }

    private func detectHookedRuntimeSurfaces() -> DetectorResult {
        let prologueResult = (try? PrologueBranchDetector().detect()) ?? .empty
        let inlineResult = MemoryIntegrityChecker().detectInlineHookTraces()
        let dyldResult = (try? DyldInterposeDetector().detect()) ?? .empty

        let mappedMethods = Self.mapHookSurfaceMethods(
            prologueMethods: prologueResult.methods,
            inlineMethods: inlineResult.methods,
            dyldMethods: dyldResult.methods
        )
        guard !mappedMethods.isEmpty else { return .empty }

        let patchCount = mappedMethods.filter { $0.hasPrefix(Self.methodPrefixPatch) }.count
        let behaviorCount = mappedMethods.filter { $0.hasPrefix(Self.methodPrefixBehavior) }.count
        let totalScore = min(Double(patchCount) * 5 + Double(behaviorCount) * 4, 18)
        return DetectorResult(score: totalScore, methods: mappedMethods)
    }

    internal static func mapHookSurfaceMethods(
        prologueMethods: [String],
        inlineMethods: [String],
        dyldMethods: [String]
    ) -> [String] {
        var mapped = Set<String>()

        for method in prologueMethods {
            if let symbol = method.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: true).last {
                if method.hasPrefix("prologue_branch:") {
                    mapped.insert("\(methodPrefixPatch)prologue_branch:\(symbol)")
                } else if method.hasPrefix("prologue_unreadable:") {
                    mapped.insert("\(methodPrefixPatch)prologue_unreadable:\(symbol)")
                }
            }
        }

        for method in inlineMethods {
            if let detail = method.split(separator: ":", maxSplits: 2, omittingEmptySubsequences: true).last {
                if method.hasPrefix("memory_integrity:inline_hook:") {
                    mapped.insert("\(methodPrefixPatch)inline_hook:\(detail)")
                } else if method.hasPrefix("memory_integrity:unreadable:") {
                    mapped.insert("\(methodPrefixPatch)inline_unreadable:\(detail)")
                }
            }
        }

        for method in dyldMethods {
            if let detail = method.dyldBehaviorDetail {
                if method.hasPrefix("dyld_interpose:") {
                    mapped.insert("\(methodPrefixBehavior)dyld_interpose:\(detail)")
                } else if method.hasPrefix("dyld_env:") {
                    mapped.insert("\(methodPrefixBehavior)dyld_env:\(detail.lowercased())")
                } else if method.hasPrefix("dyld_image_count:") {
                    mapped.insert("\(methodPrefixBehavior)dyld_image_count:\(detail)")
                }
            }
        }

        return mapped.sorted()
    }

    private static func mapRuntimeBehaviorMethods(
        flags: UInt32,
        hitCount: UInt32
    ) -> [String] {
        guard flags != 0 else { return [] }

        var mapped = Set<String>()
        if (flags & UInt32(CPRISK_FRIDA_RT_BEHAVIOR_PROLOGUE)) != 0 {
            mapped.insert("\(methodPrefixBehavior)runtime_prologue")
        }
        if (flags & UInt32(CPRISK_FRIDA_RT_BEHAVIOR_TRAMPOLINE)) != 0 {
            mapped.insert("\(methodPrefixBehavior)runtime_trampoline")
        }
        if (flags & UInt32(CPRISK_FRIDA_RT_BEHAVIOR_FOREIGN_EXEC)) != 0 {
            mapped.insert("\(methodPrefixBehavior)runtime_foreign_exec")
        }
        if (flags & UInt32(CPRISK_FRIDA_RT_BEHAVIOR_TRUST_SURFACE)) != 0 {
            mapped.insert("\(methodPrefixBehavior)runtime_trust_surface")
        }
        if mapped.count >= 2 || hitCount >= 2 {
            mapped.insert("\(methodPrefixBehavior)runtime_multi_surface")
        }
        return mapped.sorted()
    }

    private func detectMemorySignatureHit() -> String? {
        if hookMemorySignatureScanEnabled {
            let hooks = Self.hookState.withLock { $0 }
            for hook in hooks {
                guard let hit = hook()?.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines),
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
        SVCDirectCall.secureAccess(path) == true
    }

    private func statFileExists(path: String) -> Bool {
        SVCDirectCall.secureStat(path) == true
    }
}

private extension String {
    var dyldBehaviorDetail: String? {
        let detail = split(separator: ":", maxSplits: 2, omittingEmptySubsequences: true)
            .dropFirst()
            .joined(separator: ":")
        return detail.isEmpty ? nil : detail
    }
}
