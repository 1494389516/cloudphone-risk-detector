import Darwin
import Foundation

struct MultiPathFileDetector: Detector {
    enum DetectionMethod: String, CaseIterable {
        case fileManager
        case stat
        case lstat
        case access
        case fopen
    }

    struct MultiPathResult {
        let path: String
        let methodResults: [DetectionMethod: Bool]
        let consensusExists: Bool
        let isHooked: Bool
        let hookMethods: [String]
    }

    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        let criticalPaths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/var/jb",
            "/Library/MobileSubstrate/MobileSubstrate.dylib"
        ]

        for path in criticalPaths {
            let result = checkPathWithAllMethods(path)
            if result.consensusExists {
                score += 25
                methods.append("multipart:\(path)")
            }
            if result.isHooked {
                score += 30
                methods.append("multipart_hook:\(path):\(result.hookMethods.joined(separator: ","))")
            }
        }

        if performDirectoryTraversalConsistencyCheck() {
            score += 12
            methods.append("multipart:directory_inconsistency")
        }

        return DetectorResult(score: score, methods: methods)
    }

    private func checkPathWithAllMethods(_ path: String) -> MultiPathResult {
        var methodResults: [DetectionMethod: Bool] = [:]
        methodResults[.fileManager] = FileManager.default.fileExists(atPath: path)
        methodResults[.stat] = checkViaStat(path)
        methodResults[.lstat] = checkViaLstat(path)
        methodResults[.access] = access(path, F_OK) == 0
        methodResults[.fopen] = checkViaFopen(path)

        let trueCount = methodResults.values.filter { $0 }.count
        let falseCount = methodResults.count - trueCount
        let consensusExists = trueCount > falseCount

        var hookMethods: [String] = []
        if trueCount > 0 && falseCount > 0 {
            let minority = trueCount < falseCount
            hookMethods = methodResults
                .filter { $0.value == minority }
                .map { $0.key.rawValue }
                .sorted()
        }

        return MultiPathResult(
            path: path,
            methodResults: methodResults,
            consensusExists: consensusExists,
            isHooked: !hookMethods.isEmpty,
            hookMethods: hookMethods
        )
    }

    private func checkViaStat(_ path: String) -> Bool {
        var st = stat()
        return stat(path, &st) == 0
    }

    private func checkViaLstat(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0
    }

    private func checkViaFopen(_ path: String) -> Bool {
        guard let fp = fopen(path, "r") else { return false }
        fclose(fp)
        return true
    }

    private func performDirectoryTraversalConsistencyCheck() -> Bool {
#if targetEnvironment(simulator)
        return false
#else
        let directory = "/Applications"
        let fmContents = Set((try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? [])
        let posixContents = getDirectoryContentsViaPosix(directory)

        let maxCount = max(fmContents.count, posixContents.count)
        let minCount = min(fmContents.count, posixContents.count)
        guard maxCount > 0 else { return false }
        let discrepancy = Double(maxCount - minCount) / Double(maxCount)
        return discrepancy > 0.3
#endif
    }

    private func getDirectoryContentsViaPosix(_ path: String) -> Set<String> {
        var names: Set<String> = []
        guard let dir = opendir(path) else { return names }
        defer { closedir(dir) }

        while let entry = readdir(dir) {
            let name = withUnsafePointer(to: entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                    String(cString: $0)
                }
            }
            if name != "." && name != ".." {
                names.insert(name)
            }
        }

        return names
    }
}
