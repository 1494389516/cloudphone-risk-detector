import Darwin
import Foundation

struct FileDetector: Detector {
    private let suspiciousPaths: [(path: String, score: Double)] = [
        // Legacy package managers
        ("/Applications/Cydia.app", 30),
        ("/Applications/Sileo.app", 30),
        ("/Applications/Zebra.app", 25),
        ("/Applications/Installer.app", 20),
        ("/Applications/Filza.app", 20),
        ("/Applications/iFile.app", 15),

        // Substrate / hook frameworks (rootful)
        ("/Library/MobileSubstrate/MobileSubstrate.dylib", 25),
        ("/Library/MobileSubstrate/DynamicLibraries", 20),
        ("/Library/Frameworks/CydiaSubstrate.framework", 25),
        ("/usr/lib/libsubstrate.dylib", 20),
        ("/usr/lib/libsubstitute.dylib", 20),
        ("/usr/lib/substitute", 25),
        ("/usr/lib/ElleKit.dylib", 25),
        ("/usr/lib/libhooker.dylib", 20),
        ("/Library/PreferenceBundles/LibertyPref.bundle", 10),
        ("/Library/Substitute", 15),
        ("/usr/libexec/substrated", 20),

        // Rootless common prefixes
        ("/var/jb", 15),
        ("/var/jb/usr/bin/ssh", 10),
        ("/var/jb/Applications/Sileo.app", 20),
        ("/var/jb/Applications/Zebra.app", 20),
        ("/var/jb/Library/MobileSubstrate/MobileSubstrate.dylib", 25),
        ("/var/jb/usr/lib/ElleKit.dylib", 25),
        ("/var/jb/usr/lib/libhooker.dylib", 20),
        ("/var/jb/usr/lib/TweakInject", 15),

        // Jailbreak tools
        ("/Applications/checkra1n.app", 25),
        ("/Applications/odyssey.app", 20),
        ("/Applications/odysseyra1n.app", 20),
        ("/Applications/unc0ver.app", 25),
        ("/Applications/chimera.app", 20),
        ("/Applications/Taurine.app", 20),
        ("/Applications/Activator.app", 15),
        ("/Applications/PreferenceLoader.app", 15),
        ("/Applications/cycript.app", 15),
        ("/Applications/AppSync.app", 15),

        // APT (Debian package manager)
        ("/etc/apt", 25),
        ("/etc/apt/sources.list", 20),
        ("/etc/apt/sources.list.d", 20),
        ("/var/lib/apt", 15),
        ("/var/cache/apt", 15),
        ("/User/Library/apt", 10),

        // Tools
        ("/usr/sbin/sshd", 15),
        ("/usr/bin/ssh", 10),
        ("/bin/bash", 10),
    ]

    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        var fileExistsMismatchCount = 0

        for item in suspiciousPaths {
            let exists = existsAnyWay(item.path)
            if exists.exists {
                score += item.score
                methods.append("file:\(item.path)")
                Logger.log("jailbreak.file.hit: \(item.path) (+\(item.score))")
            }

            if exists.fileManagerMismatch, fileExistsMismatchCount < 3 {
                fileExistsMismatchCount += 1
                score += 8
                methods.append("hook:fileExists_mismatch:\(item.path)")
                Logger.log("jailbreak.file.hit: fileExists_mismatch path=\(item.path) (+8)")
            }
        }

        // System configuration / integrity signals.
        let sys = SystemConfigDetector().detect()
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
    }

    private struct ExistenceResult {
        var exists: Bool
        var fileManagerMismatch: Bool
    }

    private func existsAnyWay(_ path: String) -> ExistenceResult {
        let fm = FileManager.default.fileExists(atPath: path)
        let low = existsLowLevel(path)

        // If high-level API says NO but low-level says YES, a common bypass is hooking NSFileManager.
        let mismatch = (!fm && low)
        return ExistenceResult(exists: fm || low, fileManagerMismatch: mismatch)
    }

    private func existsLowLevel(_ path: String) -> Bool {
        // lstat covers both files and symlinks.
        var st = stat()
        if lstat(path, &st) == 0 { return true }
        // access(F_OK) is another common primitive.
        return access(path, F_OK) == 0
    }

    private func listApplicationsShowsJailbreakApps() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        guard let dir = opendir("/Applications") else { return false }
        defer { closedir(dir) }

        let needles = ["sileo", "cydia", "zebra", "filza", "checkra1n", "taurine", "unc0ver", "chimera"]
        while let ent = readdir(dir) {
            var nameBuf = ent.pointee.d_name
            let name = withUnsafePointer(to: &nameBuf.0) { ptr in
                String(cString: ptr).lowercased()
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
        guard FileManager.default.fileExists(atPath: root) else { return false }
        guard let children = try? FileManager.default.contentsOfDirectory(atPath: root) else { return false }
        // Cap to avoid expensive scans.
        for name in children.prefix(10) {
            let candidate = "\(root)/\(name)/jb"
            var isDir: ObjCBool = false
            if FileManager.default.fileExists(atPath: candidate, isDirectory: &isDir), isDir.boolValue {
                return true
            }
        }
        return false
#endif
    }
}

private struct SystemConfigDetector: Detector {
    func detect() -> DetectorResult {
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
        let paths = [
            "/etc/fstab",
            "/etc/hosts",
            "/etc/apt/sources.list",
            "/private/etc/fstab",
            "/private/etc/hosts",
        ]

        for path in paths {
            var st = stat()
            if stat(path, &st) == 0 {
                return true
            }
            if let content = try? String(contentsOfFile: path, encoding: .utf8), !content.isEmpty {
                return true
            }
        }
        return false
    }

    private func checkHostsFile() -> Bool {
        let hostsPath = "/etc/hosts"
        guard let hosts = try? String(contentsOfFile: hostsPath, encoding: .utf8), !hosts.isEmpty else {
            return false
        }

        let suspiciousEntries = [
            "127.0.0.1 ocsp",
            "127.0.0.1 ocsp2",
            "127.0.0.1 *.apple.com",
            "adbconnect",
            "cydia",
            "sileo",
        ]

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
        let fstabPath = "/etc/fstab"
        guard let fstab = try? String(contentsOfFile: fstabPath, encoding: .utf8), !fstab.isEmpty else {
            return false
        }

        let suspiciousMounts = [
            "/var",
            "/Applications",
            "/Library/MobileSubstrate",
            "rw",
            "nodev",
        ]

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
        let aptPaths = [
            "/etc/apt",
            "/etc/apt/sources.list",
            "/etc/apt/sources.list.d",
            "/var/lib/apt",
            "/var/cache/apt",
            "/User/Library/apt",
        ]

        for path in aptPaths {
            var st = stat()
            if stat(path, &st) == 0 { return true }
        }

        if let sourcesList = try? String(contentsOfFile: "/etc/apt/sources.list", encoding: .utf8), !sourcesList.isEmpty {
            let needles = ["cydia", "bigboss", "modmyi"]
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
