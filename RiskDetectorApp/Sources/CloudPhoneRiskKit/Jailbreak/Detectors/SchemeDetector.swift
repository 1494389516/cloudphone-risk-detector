import Foundation
#if canImport(UIKit)
import UIKit

struct SchemeDetector: Detector {
    private let schemes: [(scheme: String, score: Double)] = [
        ("cydia://", 20),
        ("sileo://", 20),
        ("zbra://", 10),
        ("filza://", 15),
        ("undecimus://", 20),
    ]

    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        for item in schemes {
            guard let url = URL(string: item.scheme) else { continue }
            if canOpenURL(url) {
                score += item.score
                methods.append("scheme:\(item.scheme)")
                Logger.log("jailbreak.scheme.hit: \(item.scheme) (+\(item.score))")
            }
        }

        return DetectorResult(score: score, methods: methods)
    }

    private func canOpenURL(_ url: URL) -> Bool {
        if Thread.isMainThread {
            return UIApplication.shared.canOpenURL(url)
        }
        var ok = false
        DispatchQueue.main.sync {
            ok = UIApplication.shared.canOpenURL(url)
        }
        return ok
    }
}
#else

struct SchemeDetector: Detector {
    func detect() -> DetectorResult { .empty }
}
#endif
