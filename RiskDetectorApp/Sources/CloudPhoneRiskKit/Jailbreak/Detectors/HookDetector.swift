import Foundation
import Darwin

struct HookDetector: Detector {
    private let suspiciousObjCClasses = [
        // Cydia / Sileo / package managers
        "CydiaObject",
        "Cydia",
        "CydiaDelegate",
        "SileoPackage",
        "SileoSource",
        "SileoManager",

        "FLEXManager",
        "FLEXExplorerViewController",
        "FLEXExplorer",
        "FLEXWindow",
        "FishHook",
        "CydiaSubstrate",
        "SubstrateLoader",
        "FridaServer",
        "FridaGadget",
        "FridaAgent",
        "GumInvocationContext",
        "GumInterceptor",
        "SSLKillSwitch",
        "Liberty",
        "LibertyLite",
        "ABypass",
        "RocketBootstrap",
        "RBManager",
        "CPDistributedMessaging",
        "HBPreferences",
        "HBLOptionsController",
    ]

    let symbolImageChecks: [(symbol: String, score: Double)] = [
        ("open", 25),
        ("openat", 22),
        ("fopen", 18),
        ("stat", 16),
        ("lstat", 16),
        ("access", 16),
        ("dlopen", 20),
        ("sysctl", 16),
        ("syscall", 20),
        ("__syscall", 20),
        ("objc_msgSend", 18),
    ]

    let suspiciousImageTokens: [String] = [
        "frida",
        "gadget",
        "substrate",
        "substitute",
        "libhooker",
        "ellekit",
        "tweak",
        "xposed",
        "hook",
    ]

    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        for name in suspiciousObjCClasses where NSClassFromString(name) != nil {
            score += 15
            methods.append("objc_class:\(name)")
            Logger.log("jailbreak.hook.hit: objc_class=\(name) (+15)")
        }

        for check in symbolImageChecks {
            guard let path = imagePath(of: check.symbol) else { continue }

            if isSuspiciousImagePath(path) {
                score += check.score
                methods.append("symbol_image_suspicious:\(check.symbol):\(path)")
                Logger.log("jailbreak.hook.hit: symbol_image_suspicious \(check.symbol)=\(path) (+\(check.score))")
                continue
            }

            if !isTrustedSystemImagePath(path, for: check.symbol) {
                let penalty = min(18, max(8, check.score * 0.7))
                score += penalty
                methods.append("symbol_image_untrusted:\(check.symbol):\(path)")
                Logger.log("jailbreak.hook.hit: symbol_image_untrusted \(check.symbol)=\(path) (+\(penalty))")
            }
        }

        // Advanced checks
        let ptr = PointerValidationDetector().detect()
        score += ptr.score
        methods.append(contentsOf: ptr.methods)

        let fw = HookFrameworkSymbolDetector().detect()
        score += fw.score
        methods.append(contentsOf: fw.methods)

        let prologue = PrologueBranchDetector().detect()
        score += prologue.score
        methods.append(contentsOf: prologue.methods)

        let fishhook = IndirectSymbolPointerDetector().detect()
        score += fishhook.score
        methods.append(contentsOf: fishhook.methods)

        let objc = ObjCIMPDetector().detect()
        score += objc.score
        methods.append(contentsOf: objc.methods)

        let meta = ObjCMetadataDetector().detect()
        score += meta.score
        methods.append(contentsOf: meta.methods)

        return DetectorResult(score: score, methods: methods)
    }

    func isSuspiciousImagePath(_ path: String) -> Bool {
        let normalized = path.lowercased()
        return suspiciousImageTokens.contains { normalized.contains($0) }
    }

    func isTrustedSystemImagePath(_ path: String, for symbol: String) -> Bool {
        let normalized = path.lowercased()
        let baseTrustedPrefixes = [
            "/usr/lib/system/",
            "/usr/lib/libsystem_",
            "/system/library/",
        ]
        let objcTrustedPrefixes = baseTrustedPrefixes + [
            "/usr/lib/libobjc.",
        ]
        let trustedPrefixes = symbol == "objc_msgSend" ? objcTrustedPrefixes : baseTrustedPrefixes
        return trustedPrefixes.contains(where: { normalized.hasPrefix($0) })
    }

    private func imagePath(of symbol: String) -> String? {
        guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), symbol) else { return nil } // RTLD_DEFAULT
        var info = Dl_info()
        guard dladdr(sym, &info) != 0, let cPath = info.dli_fname else { return nil }
        return String(cString: cPath)
    }
}

private struct ObjCMetadataDetector: Detector {
    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []

        let classHits = scanAllLoadedClasses()
        if !classHits.isEmpty {
            score += 15
            for name in classHits.prefix(3) {
                methods.append("objc_scan:\(name)")
            }
            Logger.log("jailbreak.objcmeta.hit: class_scan hits=\(classHits.count) (+15)")
        }

        let protoHits = suspiciousProtocolsFound()
        if !protoHits.isEmpty {
            score += 10
            for p in protoHits.prefix(3) {
                methods.append("objc_proto:\(p)")
            }
            Logger.log("jailbreak.objcmeta.hit: protocols hits=\(protoHits.count) (+10)")
        }

        if let m = suspiciousNSObjectExtensionMethod() {
            score += 8
            methods.append("objc_method:\(m)")
            Logger.log("jailbreak.objcmeta.hit: nsobject_extension method=\(m) (+8)")
        }

        return DetectorResult(score: min(score, 35), methods: methods)
    }

    private func scanAllLoadedClasses() -> [String] {
        var count: UInt32 = 0
        guard let classes = objc_copyClassList(&count) else { return [] }
        defer { free(UnsafeMutableRawPointer(classes)) }

        let patterns = [
            "cydia", "sileo", "zebra", "filza", "frida", "gum",
            "substrate", "substitute", "preferenceloader", "activator",
            "rocketbootstrap", "libhooker", "ellekit", "shadow", "dopamine",
        ]

        var hits: [String] = []
        hits.reserveCapacity(8)
        for i in 0..<Int(count) {
            let cls: AnyClass = classes[i]
            let name = String(cString: class_getName(cls)).lowercased()
            if patterns.contains(where: { name.contains($0) }) {
                hits.append(name)
                if hits.count >= 12 { break }
            }
        }
        return Array(Set(hits)).sorted()
    }

    private func suspiciousProtocolsFound() -> [String] {
        let names = [
            "CydiaDelegate",
            "SileoDelegate",
            "SubstituteDelegate",
            "FridaHelper",
            "JailbreakProtocol",
        ]
        var hits: [String] = []
        for n in names {
            if objc_getProtocol(n) != nil { hits.append(n) }
        }
        return hits
    }

    private func suspiciousNSObjectExtensionMethod() -> String? {
        let cls: AnyClass = NSObject.self
        var methodCount: UInt32 = 0
        guard let methods = class_copyMethodList(cls, &methodCount) else { return nil }
        defer { free(methods) }

        let prefixes = [
            "jb_",
            "cydia_",
            "sileo_",
            "hook_",
            "patch_",
            "tweak_",
            "substrate_",
            "ms_",
        ]

        for i in 0..<Int(methodCount) {
            let sel = method_getName(methods[i])
            let name = NSStringFromSelector(sel).lowercased()
            if prefixes.contains(where: { name.hasPrefix($0) }) {
                return name
            }
        }
        return nil
    }
}
