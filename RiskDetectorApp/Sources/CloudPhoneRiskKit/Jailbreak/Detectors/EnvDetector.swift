import Foundation

struct EnvDetector: Detector {
    private let suspiciousVars: [(name: String, score: Double)] = [
        ("DYLD_INSERT_LIBRARIES", 50),
        ("DYLD_LIBRARY_PATH", 25),
        ("DYLD_FALLBACK_LIBRARY_PATH", 20),
        ("DYLD_PRINT_LIBRARIES", 15),
        ("DYLD_PRINT_SEGMENTS", 12),
        ("DYLD_PRINT_INITIALIZERS", 12),
        ("DYLD_PRINT_DOFS", 10),
        ("DYLD_PRINT_APIS", 10),
        ("DYLD_PRINT_STATISTICS", 10),
        ("DYLD_PRINT_WARNINGS", 10),
        ("DYLD_VERBOSE", 10),
        ("DYLD_BIND_AT_LAUNCH", 10),
        ("LD_LIBRARY_PATH", 20),
        ("LD_PRELOAD", 25),
        ("DYLD_NO_PIE", 12),
        ("DYLD_DISABLE_PREFETCH", 10),
    ]

    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        let envMap = readEnvironMap()
        var mismatchCount = 0

        for item in suspiciousVars {
            let g = getenvString(item.name)
            let d = envMap?[item.name]

            if let value = (g ?? d), !value.isEmpty {
                score += item.score
                if item.name == "DYLD_INSERT_LIBRARIES" {
                    methods.append("env:\(item.name)=\(sanitizeEnvValue(value))")
                } else {
                    methods.append("env:\(item.name)")
                }
                Logger.log("jailbreak.env.hit: \(item.name) (+\(item.score))")
            }

            // Hook-resistant cross check: getenv() vs environ table.
            if g == nil, d != nil, mismatchCount < 3 {
                mismatchCount += 1
                score += 12
                methods.append("env_hook:getenv_mismatch:\(item.name)")
                Logger.log("jailbreak.env.hit: getenv_mismatch var=\(item.name) (+12)")
            }
        }

        return DetectorResult(score: score, methods: methods)
    }

    private func getenvString(_ name: String) -> String? {
        guard let p = getenv(name) else { return nil }
        let s = String(cString: p)
        return s.isEmpty ? nil : s
    }

    private func sanitizeEnvValue(_ value: String) -> String {
        // Avoid leaking full paths; keep it short for reporting.
        if value.count <= 64 { return value }
        let prefix = value.prefix(60)
        return "\(prefix)…"
    }

    private func readEnvironMap() -> [String: String]? {
        guard let envpPtrPtr = _NSGetEnviron() else { return nil }
        guard let envp = envpPtrPtr.pointee else { return nil }

        var out: [String: String] = [:]
        var i = 0
        while i < 512, let entryPtr = envp.advanced(by: i).pointee {
            let entry = String(cString: entryPtr)
            if let idx = entry.firstIndex(of: "=") {
                let key = String(entry[..<idx])
                let val = String(entry[entry.index(after: idx)...])
                if !key.isEmpty, out[key] == nil {
                    out[key] = val
                }
            }
            i += 1
        }
        return out
    }
}

@_silgen_name("_NSGetEnviron")
private func _NSGetEnviron() -> UnsafeMutablePointer<UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?>?
