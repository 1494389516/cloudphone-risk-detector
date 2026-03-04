import Darwin
import Foundation

struct HookFrameworkSymbolDetector: Detector {
    let suspiciousSymbols: [(name: String, score: Double)] = [
        ("MSHookFunction", 20),
        ("MSHookMessageEx", 20),
        ("MSHookMemory", 18),
        ("MSFindSymbol", 12),
        ("substitute_hook_functions", 15),
        ("substitute_hook_objc_message", 15),
        ("LHHookFunctions", 15),
        ("rebind_symbols", 10),
        ("rebind_symbols_image", 10),
        ("fishhook_rebind_symbols", 10),
        ("gum_interceptor_attach", 20),
        ("gum_module_find_export_by_name", 16),
        ("frida_agent_main", 20),
    ]

    let suspiciousImageTokens: [String] = [
        "frida",
        "gadget",
        "gum",
        "substrate",
        "substitute",
        "libhooker",
        "ellekit",
        "tweak",
        "hook",
    ]

    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        for item in suspiciousSymbols {
            guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), item.name) else { continue }
            score += item.score
            methods.append("hook_symbol:\(item.name)")

            if let path = imagePath(of: symbol), isSuspiciousImagePath(path) || !isTrustedSystemPath(path) {
                score += 4
                methods.append("hook_symbol_path:\(item.name)")
                Logger.log("jailbreak.hook.hit: exported_symbol=\(item.name) path=\(path) (+\(item.score + 4))")
            } else {
                Logger.log("jailbreak.hook.hit: exported_symbol=\(item.name) (+\(item.score))")
            }
        }
        return DetectorResult(score: min(score, 90), methods: methods)
    }

    func isSuspiciousImagePath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        return suspiciousImageTokens.contains(where: { normalized.contains($0) })
    }

    func isTrustedSystemPath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        return normalized.hasPrefix("/usr/lib/system/")
            || normalized.hasPrefix("/usr/lib/libsystem")
            || normalized.hasPrefix("/usr/lib/libobjc.")
            || normalized.hasPrefix("/system/library/")
    }

    private func imagePath(of symbol: UnsafeMutableRawPointer) -> String? {
        var info = Dl_info()
        guard dladdr(symbol, &info) != 0, let cPath = info.dli_fname else { return nil }
        return String(cString: cPath)
    }
}
