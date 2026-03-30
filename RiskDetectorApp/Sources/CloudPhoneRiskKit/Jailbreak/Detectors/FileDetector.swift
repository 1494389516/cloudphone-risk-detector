import CRiskCore
import Darwin
import Foundation

struct FileDetector: Detector {

    /// 每次 detect 随机抽样的 suspiciousPaths 百分比范围 (60-70%)
    private static let suspiciousSamplePercentRange = 60...70

    /// 抽样下限，即使百分比算出来更少也至少检查这么多
    private static let suspiciousSampleFloor = 10

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []
        var fileExistsMismatchCount = 0
        var lowLevelMismatchCount = 0

        // [4.4.5] 金丝雀探针：在检查越狱文件前执行，若 syscall 被致盲则直接告警
        if let canaryResult = CanaryFileProbe.probe() {
            score += canaryResult.score
            methods.append(contentsOf: canaryResult.methods)
        }

        var suspiciousPermissionScore: Double = 0

        // 沙盒视图隔离（Bind Mount 平行宇宙）防范
        if detectSandboxMountIsolation() {
            score += 30
            methods.append("sandbox_mount_isolation_detected")
            Logger.log("jailbreak.file.hit: sandbox_mount_isolation_detected (+30)")
        }

        // ── Anti-Stalker: path randomization + noise injection ──────────────
        // Frida Stalker 可以追踪所有 SVC #0x80 syscall 并一次性提取完整路径列表。
        // 对策：(1) 每次只随机抽样 60-70% 的路径，(2) 打乱顺序，(3) 在真实检查之间
        // 穿插对合法系统路径的噪声 access() 调用，使 Stalker 无法区分检测目标与噪声。
        // 抽样导致的检出率降低通过分数补偿因子 (N/X) 修正。

        let allSuspicious = ObfuscatedConstants.jailbreakSuspiciousPaths
        let totalN = allSuspicious.count
        let pct = Int.random(in: Self.suspiciousSamplePercentRange)
        let sampleCount = max(Self.suspiciousSampleFloor, (totalN * pct) / 100)
        let suspiciousPaths = PathRandomizer.randomSubset(from: allSuspicious, count: sampleCount)

        let noisePaths = ObfuscatedConstants.pathNoisePaths.shuffled()
        var noiseIdx = 0
        var suspiciousPathScore: Double = 0

        for item in suspiciousPaths {
            // Probabilistically inject a noise access() via direct SVC before some real checks
            if Bool.random() && noiseIdx < noisePaths.count {
                _ = SVCDirectCall.secureAccess(noisePaths[noiseIdx])
                noiseIdx += 1
            }

            // [4.4.6] EPERM 异常化：path 理应 ENOENT 却返回 EPERM/EACCES (iOS 16+)
            let (pathExists, pathErrno) = pathAccessWithErrno(item.path)
            if !pathExists && ExpectedBaseline.epermOnProtectedPathIsSuspicious && ExpectedBaseline.isPermissionDeniedErrno(pathErrno) {
                if suspiciousPermissionScore < 75 {
                    suspiciousPermissionScore = min(suspiciousPermissionScore + 15, 75)
                    methods.append("suspicious_permission_denied:\(item.path)")
                }
            }

            let exists = existsAnyWay(item.path)
            if exists.exists {
                suspiciousPathScore += item.score
                methods.append("file:\(item.path)")
                Logger.log("jailbreak.file.hit: \(item.path) (+\(item.score))")
            }

            if exists.pathProbeMismatch, fileExistsMismatchCount < 3 {
                fileExistsMismatchCount += 1
                suspiciousPathScore += 8
                methods.append("hook:fileExists_mismatch:\(item.path)")
                Logger.log("jailbreak.file.hit: fileExists_mismatch path=\(item.path) (+8)")
            }

            if exists.lowLevelPrimitiveMismatch, lowLevelMismatchCount < 4 {
                lowLevelMismatchCount += 1
                suspiciousPathScore += 12
                methods.append("hook:file_primitive_mismatch:\(item.path)")
                Logger.log("jailbreak.file.hit: file_primitive_mismatch path=\(item.path) (+12)")
            }

            if exists.bypassed {
                suspiciousPathScore += 20
                methods.append("syscall_bypassed:\(item.path)")
                Logger.log("jailbreak.file.hit: syscall_bypassed path=\(item.path) (+20)")
            }

            if exists.traced {
                suspiciousPathScore += 25
                methods.append("dbi_stalker_traced:\(item.path)")
                Logger.log("jailbreak.file.hit: dbi_stalker_traced path=\(item.path) (+25)")
            }
        }

        // Score compensation: checked X of N paths → scale by N/X
        let rawFactor = suspiciousPaths.isEmpty ? 1.0 : Double(totalN) / Double(suspiciousPaths.count)
        let compensationFactor = min(rawFactor, 4.0)
        score += suspiciousPathScore * compensationFactor

        if suspiciousPermissionScore > 0 {
            score += suspiciousPermissionScore
            Logger.log("jailbreak.file.hit: suspicious_permission_denied (+\(Int(suspiciousPermissionScore)))")
        }

        // ── Critical paths: always check ALL, order randomized + noise ────
        let criticalPaths = ObfuscatedConstants.jailbreakCriticalPaths.shuffled()
        let critNoisePaths = ObfuscatedConstants.pathNoisePaths.shuffled()
        var critNoiseIdx = 0
        var mismatchCount = 0
        var bypassCount = 0
        var tracedCount = 0
        for path in criticalPaths {
            if Bool.random() && critNoiseIdx < critNoisePaths.count {
                _ = SVCDirectCall.secureAccess(critNoisePaths[critNoiseIdx])
                critNoiseIdx += 1
            }

            let (_, tampered, bypassed, traced, _) = DualPathValidator.validateFileStat(path: path)
            if tampered {
                mismatchCount += 1
                methods.append("dual_path_mismatch:\(path.components(separatedBy: "/").last ?? path)")
                Logger.log("jailbreak.file.hit: dual_path_mismatch path=\(path) (+20)")
            }
            if bypassed {
                bypassCount += 1
                methods.append("syscall_bypassed:\(path.components(separatedBy: "/").last ?? path)")
                Logger.log("jailbreak.file.hit: syscall_bypassed path=\(path) (+20)")
            }
            if traced {
                tracedCount += 1
                methods.append("dbi_stalker_traced:\(path.components(separatedBy: "/").last ?? path)")
                Logger.log("jailbreak.file.hit: dbi_stalker_traced path=\(path) (+25)")
            }
        }
        if mismatchCount > 0 {
            score += Double(mismatchCount) * 20
        }
        if bypassCount > 0 {
            score += Double(bypassCount) * 20
        }
        if tracedCount > 0 {
            score += Double(min(tracedCount, 3)) * 25
        }

        // System configuration / integrity signals.
        let sys = try SystemConfigDetector().detect()
        score += sys.score
        methods.append(contentsOf: sys.methods)

        // /Applications directory listing (bypasses NSFileManager hook in some cases).
        if listApplicationsShowsJailbreakApps() {
            score += 15
            methods.append("dir:/Applications")
            Logger.log("jailbreak.file.hit: /Applications contains jailbreak apps (+15)")
        }

        // Writable outside sandbox is a strong signal
        if canWriteOutsideSandbox() {
            score += 35
            methods.append("write:/private/jb_test")
            Logger.log("jailbreak.file.hit: write_outside_sandbox (+35)")
        }

        if hasPrebootJBDirectory() {
            score += 20
            methods.append("file:/private/preboot/*/jb")
            Logger.log("jailbreak.file.hit: preboot_jb (+20)")
        }

        return DetectorResult(score: score, methods: methods)
#endif
    }

    /// access(F_OK) 并返回 errno（用于 [4.4.6] EPERM 异常化）
    private func pathAccessWithErrno(_ path: String) -> (exists: Bool, errno: Int32) {
        if let result = SVCDirectCall.standardAccessErrnoMasked(path) {
            return result
        }
        return (false, EINVAL)
    }

    private struct ExistenceResult {
        var exists: Bool
        var pathProbeMismatch: Bool
        var lowLevelPrimitiveMismatch: Bool
        var bypassed: Bool
        var traced: Bool
    }

    private func detectSandboxMountIsolation() -> Bool {
        return false
    }

    private func existsAnyWay(_ path: String) -> ExistenceResult {
        let standardSnapshot = SVCDirectCall.standardPathProbeSnapshot(path)
        let low = DualPathValidator.validateFileStat(path: path)
        let standardValues = standardSnapshot.availableValues
        let mismatch = standardValues.contains(true) && standardValues.contains(false)
        return ExistenceResult(
            exists: standardSnapshot.existsAny || low.exists,
            pathProbeMismatch: mismatch,
            lowLevelPrimitiveMismatch: low.tampered,
            bypassed: low.bypassed,
            traced: low.traced
        )
    }

    private func existsLowLevel(_ path: String) -> Bool {
        DualPathValidator.validateFileStat(path: path).exists
    }

    private func listApplicationsShowsJailbreakApps() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        guard let dir = opendir("/Applications") else { return false }
        defer { closedir(dir) }

        let needles = ObfuscatedConstants.listApplicationsNeedles
        while let ent = readdir(dir) {
            var nameBuf = ent.pointee.d_name
            let name = withUnsafePointer(to: &nameBuf.0) { ptr in
                let len = strnlen(ptr, 256)
                return (String(data: Data(bytes: ptr, count: len), encoding: .utf8) ?? "").lowercased()
            }
            if needles.contains(where: { name.contains($0) }) {
                return true
            }
        }
        return false
#endif
    }

    private func canWriteOutsideSandbox() -> Bool {
#if targetEnvironment(simulator)
        // Simulator is not a real iOS sandbox; this check is meaningless and can false-positive.
        return false
#else
        let testPath = "/private/jb_test_\(UUID().uuidString)"
        do {
            try "1".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
#endif
    }

    private func hasPrebootJBDirectory() -> Bool {
#if targetEnvironment(simulator)
        // Simulator doesn't have the same preboot filesystem layout as real devices.
        return false
#else
        // Rootless jailbreaks often have /private/preboot/<UUID>/jb
        let root = "/private/preboot"
        guard DualPathValidator.validateFileStat(path: root).exists else { return false }
        guard let dir = opendir(root) else { return false }
        defer { closedir(dir) }

        var scanned = 0
        while scanned < 10, let entry = readdir(dir) {
            var nameBuf = entry.pointee.d_name
            let name = withUnsafePointer(to: &nameBuf.0) { ptr in
                let len = strnlen(ptr, Int(MAXPATHLEN))
                return (String(data: Data(bytes: ptr, count: len), encoding: .utf8) ?? "")
            }
            guard name != "." && name != ".." else { continue }

            let candidate = "\(root)/\(name)/jb"
            if isDirectoryPath(candidate) {
                return true
            }
            scanned += 1
        }
        return false
#endif
    }

    private func isDirectoryPath(_ path: String) -> Bool {
        path.withCString { cPath in
            var sb = stat()
            guard cprisk_stat_direct(cPath, &sb, nil) == 0 else { return false }
            return (sb.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR)
        }
    }
}

private struct SystemConfigDetector: Detector {
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return .empty
#else
        var score: Double = 0
        var methods: [String] = []

        if checkSystemFileReadability() {
            score += 6
            methods.append("sysfiles:readable")
            Logger.log("jailbreak.sysfiles.hit: readable (+6)")
        }

        if checkHostsFile() {
            score += 18
            methods.append("sysfiles:hosts")
            Logger.log("jailbreak.sysfiles.hit: hosts (+18)")
        }

        if checkFstabConfiguration() {
            score += 18
            methods.append("sysfiles:fstab")
            Logger.log("jailbreak.sysfiles.hit: fstab (+18)")
        }

        if checkAPTConfiguration() {
            score += 22
            methods.append("sysfiles:apt")
            Logger.log("jailbreak.sysfiles.hit: apt (+22)")
        }

        if checkSymlinkIntegrity() {
            score += 15
            methods.append("sysfiles:symlink")
            Logger.log("jailbreak.sysfiles.hit: symlink_integrity (+15)")
        }

        return DetectorResult(score: min(score, 60), methods: methods)
#endif
    }

    private func checkSystemFileReadability() -> Bool {
        let paths = ObfuscatedConstants.systemConfigPaths

        for path in paths {
            if DualPathValidator.validateFileStat(path: path).exists {
                return true
            }
            if let content = try? String(contentsOfFile: path, encoding: .utf8), !content.isEmpty {
                return true
            }
        }
        return false
    }

    private func checkHostsFile() -> Bool {
        let hostsPath = ObfuscatedConstants.hostsPath
        guard let hosts = try? String(contentsOfFile: hostsPath, encoding: .utf8), !hosts.isEmpty else {
            return false
        }

        let suspiciousEntries = ObfuscatedConstants.suspiciousHostsEntries

        for entry in suspiciousEntries {
            if hosts.range(of: entry, options: .caseInsensitive) != nil {
                return true
            }
        }

        // Heuristic: modified hosts tends to be larger.
        if hosts.utf8.count > 2048 {
            return true
        }
        return false
    }

    private func checkFstabConfiguration() -> Bool {
        let fstabPath = ObfuscatedConstants.fstabPath
        guard let fstab = try? String(contentsOfFile: fstabPath, encoding: .utf8), !fstab.isEmpty else {
            return false
        }

        let suspiciousMounts = ObfuscatedConstants.suspiciousFstabMounts

        for pattern in suspiciousMounts where fstab.contains(pattern) {
            return true
        }

        let lines = fstab.components(separatedBy: "\n")
        var validLineCount = 0
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty && !trimmed.hasPrefix("#") { validLineCount += 1 }
        }
        return validLineCount > 5
    }

    private func checkAPTConfiguration() -> Bool {
        for path in ObfuscatedConstants.aptPaths {
            if DualPathValidator.validateFileStat(path: path).exists { return true }
        }

        let sourcesPath = ObfuscatedConstants.aptSourcesListPath
        if let sourcesList = try? String(contentsOfFile: sourcesPath, encoding: .utf8), !sourcesList.isEmpty {
            let needles = ObfuscatedConstants.aptRepoNeedles
            if needles.contains(where: { sourcesList.range(of: $0, options: .caseInsensitive) != nil }) {
                return true
            }
        }
        return false
    }

    private func checkSymlinkIntegrity() -> Bool {
        let expected: [String: String] = [
            "/etc": "/private/etc",
            "/var": "/private/var",
            "/tmp": "/private/tmp",
        ]

        for (path, expectedTarget) in expected {
            guard let actual = readlinkString(path) else { continue }
            if actual != expectedTarget {
                return true
            }
        }
        return false
    }

    private func readlinkString(_ path: String) -> String? {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        let len = readlink(path, &buf, Int(PATH_MAX) - 1)
        if len <= 0 { return nil }
        buf[len] = 0
        return String(cString: buf)
    }
}
