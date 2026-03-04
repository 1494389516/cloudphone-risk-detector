import Foundation
import MachO

struct DyldDetector: Detector {
    let suspiciousLibraries = [
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
        var hitTokens = Set<String>()
        var hitImageCount = 0

        let count = _dyld_image_count()
        if count > 500 {
            score += 15
            methods.append("dylib_count:\(count)")
            Logger.log("jailbreak.dyld.hit: dylib_count=\(count) (+15)")
        }

        for i in 0..<count {
            guard let name = _dyld_get_image_name(i) else { continue }
            let path = String(cString: name).lowercased()
            guard let token = firstSuspiciousToken(in: path) else { continue }
            hitImageCount += 1
            if hitTokens.insert(token).inserted {
                score += 25
                methods.append("dylib:\(token)")
                Logger.log("jailbreak.dyld.hit: \(token) (+25) from=\(path)")
            }
        }

        if hitImageCount >= 3 {
            score += 10
            methods.append("dylib_multi_hit:\(hitImageCount)")
        }

        return DetectorResult(score: min(score, 90), methods: methods)
    }

    func firstSuspiciousToken(in imagePath: String) -> String? {
        let normalized = imagePath.lowercased()
        return suspiciousLibraries.first(where: { normalized.contains($0) })
    }
}
