import Foundation
import MachO

struct DyldDetector: Detector {
    private let suspiciousLibraries = [
        "frida",
        "gadget",
        "gum",
        "substrate",
        "libsubstrate",
        "substitute",
        "libsubstitute",
        "cycript",
        "libcycript",
        "libhooker",
        "ellekit",
        "sslkill",
        "sslkill switch",
        "sslkillswitch",
        "preferenceloader",
        "flex",
        "rocketbootstrap",
        "activator",
        "libactivator",
        "cephei",
        "tweakinject",
        "shadow",
        "dopamine",
    ]

    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        let count = _dyld_image_count()
        if count > 500 {
            score += 15
            methods.append("dylib_count:\(count)")
            Logger.log("jailbreak.dyld.hit: dylib_count=\(count) (+15)")
        }

        for i in 0..<count {
            guard let name = _dyld_get_image_name(i) else { continue }
            let path = String(cString: name).lowercased()
            for needle in suspiciousLibraries where path.contains(needle) {
                score += 25
                methods.append("dylib:\(needle)")
                Logger.log("jailbreak.dyld.hit: \(needle) (+25) from=\(path)")
                break
            }
        }

        return DetectorResult(score: score, methods: methods)
    }
}
