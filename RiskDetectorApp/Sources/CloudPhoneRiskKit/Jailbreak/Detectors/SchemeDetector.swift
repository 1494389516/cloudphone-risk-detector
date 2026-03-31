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
    private static let canOpenURLHookSurfaceIndicators: Set<String> = [
        "objc_imp:uiapp_canOpenURL",
        "runtime_integrity:selector_unresolved:canOpenURL:",
        "runtime_integrity:selector_nil_imp:canOpenURL:",
        "runtime_integrity:selector_imp_outside_system:canOpenURL:",
    ]

    func detect() throws -> DetectorResult {
        let suspiciousSurfaceMethods = canOpenURLHookSurfaceMethods()
        guard suspiciousSurfaceMethods.isEmpty else {
            return DetectorResult(
                score: 0,
                methods: suspiciousSurfaceMethods.map { "scheme_probe_skipped:\($0)" }
            )
        }

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

        return DetectorResult(score: min(score, 100), methods: methods)
    }

    private func canOpenURLHookSurfaceMethods() -> [String] {
        var hits = Set<String>()

        if let objcResult = try? ObjCIMPDetector().detect() {
            for method in objcResult.methods where Self.canOpenURLHookSurfaceIndicators.contains(method) {
                hits.insert(method)
            }
        }

        if let runtimeResult = try? RuntimeIntegrityValidator().detect() {
            for method in runtimeResult.methods where Self.canOpenURLHookSurfaceIndicators.contains(method) {
                hits.insert(method)
            }
        }

        return hits.sorted()
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
    func detect() throws -> DetectorResult { .empty }
}
#endif
