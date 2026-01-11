import Darwin
import Foundation
import ObjectiveC.runtime

/// Detects method swizzling used to hide jailbreak indicators by validating IMP origins.
struct ObjCIMPDetector: Detector {
    private struct Target {
        var cls: AnyClass
        var sel: Selector
        var id: String
        var score: Double
    }

    func detect() -> DetectorResult {
        var targets: [Target] = []

        if let fm = NSClassFromString("NSFileManager") {
            targets.append(Target(cls: fm, sel: #selector(FileManager.fileExists(atPath:)), id: "nsfilemanager_fileExists", score: 8))
        }
        if let bundle = NSClassFromString("NSBundle") {
            targets.append(Target(cls: bundle, sel: #selector(getter: Bundle.bundleIdentifier), id: "bundle_bundleIdentifier", score: 6))
            targets.append(Target(cls: bundle, sel: #selector(Bundle.object(forInfoDictionaryKey:)), id: "bundle_infoKey", score: 6))
        }

        #if canImport(UIKit)
        if let app = NSClassFromString("UIApplication") {
            targets.append(Target(cls: app, sel: NSSelectorFromString("canOpenURL:"), id: "uiapp_canOpenURL", score: 8))
        }
        if let dev = NSClassFromString("UIDevice") {
            targets.append(Target(cls: dev, sel: NSSelectorFromString("identifierForVendor"), id: "uidevice_idfv", score: 6))
        }
        #endif

        var score: Double = 0
        var methods: [String] = []

        for t in targets {
            guard let m = class_getInstanceMethod(t.cls, t.sel) else { continue }
            let imp = method_getImplementation(m)
            let p = UnsafeRawPointer(bitPattern: UInt(bitPattern: imp))
            guard let p else { continue }

            var info = Dl_info()
            guard dladdr(p, &info) != 0, let cPath = info.dli_fname else { continue }
            let path = String(cString: cPath)

            if !(path.hasPrefix("/System/Library/") || path.hasPrefix("/usr/lib/")) {
                score += t.score
                methods.append("objc_imp:\(t.id)")
                Logger.log("jailbreak.objcimp.hit: \(t.id) path=\(path) (+\(t.score))")
            }
        }

        if score > 40 { score = 40 }
        return DetectorResult(score: score, methods: methods)
    }
}
