import Darwin
import Foundation

struct HookFrameworkSymbolDetector: Detector {
    private let suspiciousSymbols: [(name: String, score: Double)] = [
        ("MSHookFunction", 20),
        ("MSHookMessageEx", 20),
        ("substitute_hook_functions", 15),
        ("substitute_hook_objc_message", 15),
        ("LHHookFunctions", 15),
        ("rebind_symbols", 10),
    ]

    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        for item in suspiciousSymbols {
            if dlsym(UnsafeMutableRawPointer(bitPattern: -2), item.name) != nil {
                score += item.score
                methods.append("hook_symbol:\(item.name)")
                Logger.log("jailbreak.hook.hit: exported_symbol=\(item.name) (+\(item.score))")
            }
        }
        return DetectorResult(score: score, methods: methods)
    }
}

