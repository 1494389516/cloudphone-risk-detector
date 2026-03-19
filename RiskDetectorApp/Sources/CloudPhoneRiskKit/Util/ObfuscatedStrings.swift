import Foundation

enum StringDeobfuscator {
    static func xorDecode(_ bytes: [UInt8], key: UInt8) -> String {
        let decoded = bytes.map { $0 ^ key }
        return String(bytes: decoded, encoding: .utf8) ?? ""
    }

    static func rot13(_ input: String) -> String {
        return String(input.unicodeScalars.map { scalar in
            let v = scalar.value
            switch v {
            case 65...90: return Character(Unicode.Scalar((v - 65 + 13) % 26 + 65)!)
            case 97...122: return Character(Unicode.Scalar((v - 97 + 13) % 26 + 97)!)
            default: return Character(scalar)
            }
        })
    }

    static func reverseBytes(_ bytes: [UInt8]) -> String {
        return String(bytes: bytes.reversed(), encoding: .utf8) ?? ""
    }

    static func caesarShift(_ bytes: [UInt8], shift: Int) -> String {
        let s = (shift % 26 + 26) % 26
        let decoded = bytes.map { b -> UInt8 in
            switch b {
            case 65...90: return UInt8((Int(b) - 65 - s + 26) % 26 + 65)
            case 97...122: return UInt8((Int(b) - 97 - s + 26) % 26 + 97)
            default: return b
            }
        }
        return String(bytes: decoded, encoding: .utf8) ?? ""
    }

    static func base64Decode(_ base64: String) -> String {
        guard let data = Data(base64Encoded: base64),
              let s = String(data: data, encoding: .utf8) else { return "" }
        return s
    }

    static func multiStage(_ stages: [() -> String], separator: String = "") -> String {
        return stages.map { $0() }.joined(separator: separator)
    }
}

enum ObfuscatedConstants {
    static var appleParavirtualDevice: String {
        StringDeobfuscator.multiStage([
            { StringDeobfuscator.xorDecode([0x03, 0x32, 0x32, 0x2e, 0x27, 0x62, 0x12, 0x23, 0x30, 0x23], key: 0x42) },
            { StringDeobfuscator.rot13("iveghny ") },
            { StringDeobfuscator.reverseBytes([0x65, 0x63, 0x69, 0x76, 0x65, 0x64]) },
        ])
    }

    static var llvmpipe: String {
        StringDeobfuscator.caesarShift([0x73, 0x73, 0x63, 0x74, 0x77, 0x70, 0x77, 0x6c], shift: 7)
    }

    static var iphone99Pattern: String {
        StringDeobfuscator.rot13("vcubar99")
    }

    static var vresearchPattern: String {
        StringDeobfuscator.xorDecode([0x41, 0x55, 0x52, 0x44, 0x52, 0x56, 0x55, 0x42, 0x5f], key: 0x37)
    }

    static var paravirtualPattern: String {
        StringDeobfuscator.reverseBytes([0x6c, 0x61, 0x75, 0x74, 0x69, 0x72, 0x76, 0x61, 0x72, 0x61, 0x70])
    }

    static var fridaServerPaths: [String] {
        [
            StringDeobfuscator.base64Decode("L3Vzci9zYmluL2ZyaWRhLXNlcnZlcg=="),
            StringDeobfuscator.base64Decode("L3Vzci9iaW4vZnJpZGEtc2VydmVy"),
            StringDeobfuscator.xorDecode([0x16, 0x16, 0x15, 0x01, 0x17, 0x17, 0x06, 0x00, 0x17, 0x14, 0x15, 0x06, 0x00, 0x17, 0x14, 0x15, 0x06, 0x15, 0x15, 0x14, 0x01, 0x15], key: 0x65),
            StringDeobfuscator.base64Decode("L3Zhci9qYi91c3Ivc2Jpbi9mcmlkYS1zZXJ2ZXI="),
            StringDeobfuscator.base64Decode("L3Zhci9qYi91c3IvYmluL2ZyaWRhLXNlcnZlcg=="),
        ]
    }

    static var cydiaPath: String {
        StringDeobfuscator.base64Decode("L0FwcGxpY2F0aW9ucy9DeWRpYS5hcHA=")
    }

    static var substratePath: String {
        StringDeobfuscator.base64Decode("L0xpYnJhcnkvTW9iaWxlU3Vic3RyYXRl")
    }

    static var sysctlbyname: String {
        StringDeobfuscator.caesarShift([0x78, 0x64, 0x79, 0x68, 0x79, 0x71, 0x67, 0x64, 0x66, 0x73, 0x72, 0x6a], shift: 21)
    }

    static var dlopen: String {
        StringDeobfuscator.caesarShift([0x67, 0x6f, 0x72, 0x73, 0x68, 0x71], shift: 23)
    }

    static var denyAttachToken: String {
        StringDeobfuscator.caesarShift([0x61, 0x65, 0x63, 0x6c, 0x6e, 0x70], shift: 15)
    }

    static var fridaMarkers: [String] {
        [
            StringDeobfuscator.xorDecode([0x43, 0x57, 0x6c, 0x61, 0x44], key: 0x25),
            StringDeobfuscator.rot13("sevqn-ntrag"),
            StringDeobfuscator.reverseBytes([0x72, 0x65, 0x76, 0x72, 0x65, 0x73, 0x2d, 0x61, 0x74, 0x69, 0x72, 0x64, 0x66]),
            StringDeobfuscator.caesarShift([0x6e, 0x68, 0x6b, 0x6e, 0x6c, 0x61], shift: 7),
            StringDeobfuscator.xorDecode([0x43, 0x55, 0x4d], key: 0x24),
            StringDeobfuscator.multiStage([
                { StringDeobfuscator.xorDecode([0x43, 0x55, 0x4d], key: 0x24) },
                { StringDeobfuscator.rot13("-wf-ybbc") },
            ], separator: ""),
        ]
    }

    static var hookFrameworkPatterns: [String] {
        [
            StringDeobfuscator.reverseBytes([0x65, 0x74, 0x61, 0x72, 0x74, 0x73, 0x62, 0x75, 0x73]),
            StringDeobfuscator.xorDecode([0x29, 0x2c, 0x27, 0x3d, 0x2a, 0x2a, 0x2e, 0x20, 0x37], key: 0x45),
            StringDeobfuscator.caesarShift([0x6c, 0x73, 0x73, 0x6c, 0x72, 0x70, 0x61], shift: 7),
            StringDeobfuscator.rot13("fhogfvghr"),
        ]
    }

    static var keywordFrida: String {
        StringDeobfuscator.base64Decode("ZnJpZGE=")
    }

    static var keywordHook: String {
        StringDeobfuscator.base64Decode("aG9vaw==")
    }

    static var keywordJailbreak: String {
        StringDeobfuscator.base64Decode("amFpbGJyZWFr")
    }

    static var keywordTamper: String {
        StringDeobfuscator.base64Decode("dGFtcGVy")
    }

    static var keywordRiskScore: String {
        StringDeobfuscator.base64Decode("cmlza19zY29yZQ==")
    }

    static var keywordWatchdog: String {
        StringDeobfuscator.base64Decode("d2F0Y2hkb2c=")
    }

    static var keywordTaskPort: String {
        StringDeobfuscator.base64Decode("dGFza19wb3J0")
    }

    static var keywordVMRemap: String {
        StringDeobfuscator.base64Decode("dm1fcmVtYXA=")
    }

    static var keywordTaskForPid: String {
        StringDeobfuscator.base64Decode("dGFza19mb3JfcGlk")
    }

    static var signalJailbreak: String {
        StringDeobfuscator.base64Decode("amFpbGJyZWFr")
    }

    static var signalHookDetected: String {
        StringDeobfuscator.base64Decode("aG9va19kZXRlY3RlZA==")
    }

    static var signalAntiDebugWatchdogAnomaly: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19hbm9tYWx5")
    }

    static var signalAntiDebugWatchdogTraced: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ190cmFjZWQ=")
    }

    static var signalAntiDebugWatchdogDenyAttachFailed: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19kZW55X2F0dGFjaF9mYWlsZWQ=")
    }

    static var signalAntiDebugWatchdogExceptionPort: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19leGNlcHRpb25fcG9ydA==")
    }

    static var signalAntiDebugWatchdogExceptionQuery: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZ19leGNlcHRpb25fcXVlcnk=")
    }

    static var signalFridaModuleDetected: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlX2RldGVjdGVk")
    }

    static var signalFridaModuleImage: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlX2ltYWdl")
    }

    static var signalFridaModuleSection: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlX3NlY3Rpb24=")
    }

    static var signalFridaModuleString: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlX3N0cmluZw==")
    }

    static var signalVMRemapSharedAnonymous: String {
        StringDeobfuscator.base64Decode("dm1fcmVtYXBfc2hhcmVkX2Fub255bW91c19leGVj")
    }

    static var signalVMRemapImageAlias: String {
        StringDeobfuscator.base64Decode("dm1fcmVtYXBfaW1hZ2VfYWxpYXM=")
    }

    static var signalTaskPortExceptionHijack: String {
        StringDeobfuscator.base64Decode("dGFza19wb3J0X2V4Y2VwdGlvbl9oaWphY2s=")
    }

    static var signalTaskPortRightsAnomaly: String {
        StringDeobfuscator.base64Decode("dGFza19wb3J0X3JpZ2h0c19hbm9tYWx5")
    }

    static var detectorIDTaskPortAudit: String {
        StringDeobfuscator.base64Decode("dGFza19wb3J0X2F1ZGl0")
    }

    static var detectorIDVMRemap: String {
        keywordVMRemap
    }

    static var detectorIDAntiDebugWatchdog: String {
        StringDeobfuscator.base64Decode("YW50aV9kZWJ1Z193YXRjaGRvZw==")
    }

    static var detectorIDAntiTampering: String {
        StringDeobfuscator.base64Decode("YW50aV90YW1wZXJpbmc=")
    }

    static var detectorIDDebugger: String {
        StringDeobfuscator.base64Decode("ZGVidWdnZXI=")
    }

    static var detectorIDObjCSwizzle: String {
        StringDeobfuscator.base64Decode("b2JqY19zd2l6emxl")
    }

    static var detectorIDFridaModule: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxl")
    }

    static var detectorIDFridaThread: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfdGhyZWFk")
    }

    static var detectorIDFridaHeap: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfaGVhcA==")
    }

    static var detectorIDFridaSocket: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc29ja2V0")
    }

    static var detectorScopeAntiTamperingProviderCoreChecks: String {
        StringDeobfuscator.base64Decode("YW50aV90YW1wZXJpbmdfcHJvdmlkZXIuY29yZV9jaGVja3M=")
    }

    static var detectorGroupJailbreak: String {
        signalJailbreak
    }

    static var overlapGroupHook: String {
        keywordHook
    }

    static var overlapGroupFrida: String {
        keywordFrida
    }

    static var overlapGroupJailbreakFile: String {
        StringDeobfuscator.base64Decode("amFpbGJyZWFrX2ZpbGU=")
    }

    static var methodPrefixMultipartHook: String {
        StringDeobfuscator.base64Decode("bXVsdGlwYXJ0X2hvb2s6")
    }

    static var signalMultipathHookDetected: String {
        StringDeobfuscator.base64Decode("bXVsdGlwYXRoX2hvb2tfZGV0ZWN0ZWQ=")
    }

    static var signalMultipathJailbreakFile: String {
        StringDeobfuscator.base64Decode("bXVsdGlwYXRoX2phaWxicmVha19maWxl")
    }

    static var signalMemoryProtectionTampered: String {
        StringDeobfuscator.base64Decode("bWVtb3J5X3Byb3RlY3Rpb25fdGFtcGVyZWQ=")
    }

    static var signalMemoryProtectionSemanticBypass: String {
        StringDeobfuscator.base64Decode("bWVtb3J5X3Byb3RlY3Rpb25fc2VtYW50aWNfYnlwYXNz")
    }

    static var methodPrefixMemoryHook: String {
        StringDeobfuscator.base64Decode("bWVtb3J5X2hvb2s6")
    }

    static var methodPrefixMemoryInline: String {
        StringDeobfuscator.base64Decode("bWVtb3J5X2lubGluZTo=")
    }

    static var signalPrefixHook: String {
        StringDeobfuscator.base64Decode("aG9va18=")
    }

    static var signalPrefixInlineHook: String {
        StringDeobfuscator.base64Decode("aW5saW5lX2hvb2tf")
    }

    static var antiTamperMethodPrefix: String {
        StringDeobfuscator.base64Decode("YW50aV90YW1wZXI6")
    }

    static var methodPrefixFridaEnv: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6ZW52Og==")
    }

    static var methodPrefixFridaPort: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6cG9ydDo=")
    }

    static var methodPrefixFridaFile: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6ZmlsZTo=")
    }

    static var methodPrefixFridaSymbol: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6c3ltYm9sOg==")
    }

    static var methodPrefixFridaThread: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6dGhyZWFkOg==")
    }

    static var methodPrefixFridaProcess: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6cHJvY2Vzczo=")
    }

    static var methodPrefixFridaModuleImage: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlOmltYWdlOg==")
    }

    static var methodPrefixFridaModuleSection: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlOnNlY3Rpb246")
    }

    static var methodPrefixFridaModuleString: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlOnN0cmluZzo=")
    }

    static var methodFridaUnavailableSimulator: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6dW5hdmFpbGFibGVfc2ltdWxhdG9y")
    }

    static var methodFridaModuleUnavailableSimulator: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfbW9kdWxlOnVuYXZhaWxhYmxlX3NpbXVsYXRvcg==")
    }

    static var methodFridaClean: String {
        StringDeobfuscator.base64Decode("ZnJpZGE6Y2xlYW4=")
    }

    static var methodPrefixFridaHeap: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfaGVhcDo=")
    }

    static var methodPrefixFridaStalker: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc3RhbGtlcjo=")
    }

    static var signalFridaDetected: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZGV0ZWN0ZWQ=")
    }

    static var signalFridaJSEngineHeap: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfanNfZW5naW5lX2hlYXA=")
    }

    static var signalFridaStalker: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc3RhbGtlcg==")
    }

    static var signalFridaStalkerJit: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc3RhbGtlcl9qaXQ=")
    }

    static var signalFridaUnixSocket: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfdW5peF9zb2NrZXQ=")
    }

    static var signalFridaTimingAnomaly: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfdGltaW5nX2Fub21hbHk=")
    }

    static var signalFridaStalkerAmplified: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc3RhbGtlcl9hbXBsaWZpZWQ=")
    }

    static var signalThreadAnomaly: String {
        StringDeobfuscator.base64Decode("dGhyZWFkX2Fub21hbHk=")
    }

    static var signalFridaExceptionPort: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZXhjZXB0aW9uX3BvcnQ=")
    }

    static var signalFridaDispatchQueue: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZGlzcGF0Y2hfcXVldWU=")
    }

    static var signalArmorRuntimeInitFailed: String {
        StringDeobfuscator.base64Decode("YXJtb3JfcnVudGltZV9pbml0X2ZhaWxlZA==")
    }

    static var signalIntegrityRuntimeTampered: String {
        StringDeobfuscator.base64Decode("aW50ZWdyaXR5X3J1bnRpbWVfdGFtcGVyZWQ=")
    }

    static var signalTextSegmentTampered: String {
        StringDeobfuscator.base64Decode("dGV4dF9zZWdtZW50X3RhbXBlcmVk")
    }

    static var signalAppSigningIdentityTampered: String {
        StringDeobfuscator.base64Decode("YXBwX3NpZ25pbmdfaWRlbnRpdHlfdGFtcGVyZWQ=")
    }

    static var signalAppSigningBaselineChanged: String {
        StringDeobfuscator.base64Decode("YXBwX3NpZ25pbmdfYmFzZWxpbmVfY2hhbmdlZA==")
    }

    static var signalKernelHookTimingAnomaly: String {
        StringDeobfuscator.base64Decode("a2VybmVsX2hvb2tfdGltaW5nX2Fub21hbHk=")
    }

    static var signalKernelHookStalkerAmplified: String {
        StringDeobfuscator.base64Decode("a2VybmVsX2hvb2tfc3RhbGtlcl9hbXBsaWZpZWQ=")
    }

    static var detectorIDKernelHookSideChannel: String {
        StringDeobfuscator.base64Decode("a2VybmVsX2hvb2tfc2M=")
    }

    static var detectorNameFridaDetector: String {
        StringDeobfuscator.base64Decode("RnJpZGFEZXRlY3Rvcg==")
    }

    static var detectorNameFridaModuleDetector: String {
        StringDeobfuscator.base64Decode("RnJpZGFNb2R1bGVEZXRlY3Rvcg==")
    }

    static var detectorNameAntiTamperingDetector: String {
        StringDeobfuscator.base64Decode("QW50aVRhbXBlcmluZ0RldGVjdG9y")
    }

    static var signalLibcInlineHookDetected: String {
        StringDeobfuscator.base64Decode("bGliY19pbmxpbmVfaG9va19kZXRlY3RlZA==")
    }

    static var signalObjcInlineHookDetected: String {
        StringDeobfuscator.base64Decode("b2JqY19pbmxpbmVfaG9va19kZXRlY3RlZA==")
    }

    static var methodPrefixFridaThreadName: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfdGhyZWFkOg==")
    }

    static var methodPrefixFridaException: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZXhjZXB0aW9u")
    }

    static var methodPrefixFridaExceptionThreadMask: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZXhjZXB0aW9uX3BvcnQ6dGhyZWFkX21hc2tf")
    }

    static var methodPrefixFridaExceptionMask: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfZXhjZXB0aW9uX3BvcnQ6bWFza18=")
    }

    static var methodPrefixFridaSocketPath: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc29ja2V0OnBhdGg6")
    }

    static var methodPrefixFridaSocketTmpEntry: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc29ja2V0OnRtcF9lbnRyeTo=")
    }

    static var methodPrefixFridaSocketUnixFd: String {
        StringDeobfuscator.base64Decode("ZnJpZGFfc29ja2V0OnVuaXhfZmQ6")
    }

    static var methodPrefixTimingAnomaly: String {
        StringDeobfuscator.base64Decode("dGltaW5nX2Fub21hbHk=")
    }

    static var methodPrefixTimingStalkerAmplified: String {
        StringDeobfuscator.base64Decode("dGltaW5nX3N0YWxrZXJfYW1wbGlmaWVk")
    }

    static var methodPrefixSuspiciousQueue: String {
        StringDeobfuscator.base64Decode("c3VzcGljaW91c19xdWV1ZTo=")
    }

    static var fridaEnvKeys: [String] {
        [
            StringDeobfuscator.base64Decode("RlJJREE="),
            StringDeobfuscator.base64Decode("RlJJREFfVkVSU0lPTg=="),
            StringDeobfuscator.base64Decode("RlJJREFfU0NSSVBU"),
            StringDeobfuscator.base64Decode("RFlMRF9JTlNFUlRfTElCUkFSSUVT"),
        ]
    }

    static var fridaEnvNeedleUpper: String {
        StringDeobfuscator.base64Decode("RlJJREE=")
    }

    static var fridaModuleMarkers: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("ZnJpZGEtYWdlbnQ="),
            StringDeobfuscator.base64Decode("ZnJpZGEtZ2FkZ2V0"),
            StringDeobfuscator.base64Decode("ZnJpZGEtc2VydmVy"),
            StringDeobfuscator.base64Decode("Z2FkZ2V0"),
            StringDeobfuscator.base64Decode("bGliZ3Vt"),
            StringDeobfuscator.base64Decode("Z3VtLWNvcmU="),
            StringDeobfuscator.base64Decode("ZnJpZGFndW0="),
            StringDeobfuscator.base64Decode("Z3VtLWpzLWxvb3A="),
            StringDeobfuscator.base64Decode("Z3VtanM="),
        ]
    }

    static var fridaSectionMarkers: [String] {
        [
            StringDeobfuscator.base64Decode("X19mcmlkYQ=="),
            StringDeobfuscator.base64Decode("X19mcmlkYV9nYWRnZXQ="),
            StringDeobfuscator.base64Decode("X19mcmlkYV9kYXRh"),
            StringDeobfuscator.base64Decode("X19ndW0="),
            StringDeobfuscator.base64Decode("X19ndW1qcw=="),
        ]
    }

    static var fridaStringMarkers: [String] {
        [
            StringDeobfuscator.base64Decode("ZnJpZGE6cnBj"),
            StringDeobfuscator.base64Decode("ZnJpZGEtYWdlbnQ="),
            StringDeobfuscator.base64Decode("ZnJpZGEtZ2FkZ2V0"),
            StringDeobfuscator.base64Decode("Z3VtLWpzLWxvb3A="),
            StringDeobfuscator.base64Decode("Z3VtLWludGVyY2VwdG9y"),
            StringDeobfuscator.base64Decode("Z3VtLWNvcmU="),
            StringDeobfuscator.base64Decode("Z3Vtc3RhbGtlcg=="),
            StringDeobfuscator.base64Decode("bGluamVjdG9y"),
        ]
    }

    static var fridaSocketEntryMarkers: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("LmZyaWRh"),
            StringDeobfuscator.base64Decode("bGluamVjdG9y"),
        ]
    }

    static var fridaSocketPathMarkers: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("bGluamVjdG9y"),
            StringDeobfuscator.base64Decode("Z3Vt"),
        ]
    }

    static var fridaThreadNameMarkers: [String] {
        [
            StringDeobfuscator.base64Decode("Z3VtLWpzLWxvb3A="),
            StringDeobfuscator.base64Decode("Z21haW4="),
            StringDeobfuscator.base64Decode("Z2RidXM="),
            keywordFrida,
            StringDeobfuscator.base64Decode("Z3VtLWpz"),
            StringDeobfuscator.base64Decode("djg6"),
        ]
    }

    static var fridaQueueLabelMarkers: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("Z3VtLWpz"),
            StringDeobfuscator.base64Decode("Z21haW4="),
            StringDeobfuscator.base64Decode("Z2RidXM="),
            StringDeobfuscator.base64Decode("cmUuZnJpZGE="),
            StringDeobfuscator.base64Decode("bGluamVjdG9y"),
        ]
    }

    static var debuggerParentNeedles: [String] {
        [
            StringDeobfuscator.base64Decode("bGxkYg=="),
            StringDeobfuscator.base64Decode("ZGVidWdzZXJ2ZXI="),
            StringDeobfuscator.base64Decode("Z2Ri"),
            StringDeobfuscator.base64Decode("eGNvZGU="),
            keywordFrida,
            StringDeobfuscator.base64Decode("aG9wcGVy"),
            StringDeobfuscator.base64Decode("aWRh"),
        ]
    }

    static var hookSuspiciousImageTokens: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("Z2FkZ2V0"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("dHdlYWs="),
            StringDeobfuscator.base64Decode("eHBvc2Vk"),
            keywordHook,
        ]
    }

    static var hookSuspiciousImageTokensCore: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("Z2FkZ2V0"),
            StringDeobfuscator.base64Decode("Z3Vt"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("dHdlYWs="),
            keywordHook,
        ]
    }

    static var hookObjcScanPatterns: [String] {
        [
            StringDeobfuscator.base64Decode("Y3lkaWE="),
            StringDeobfuscator.base64Decode("c2lsZW8="),
            StringDeobfuscator.base64Decode("emVicmE="),
            StringDeobfuscator.base64Decode("ZmlsemE="),
            keywordFrida,
            StringDeobfuscator.base64Decode("Z3Vt"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("cHJlZmVyZW5jZWxvYWRlcg=="),
            StringDeobfuscator.base64Decode("YWN0aXZhdG9y"),
            StringDeobfuscator.base64Decode("cm9ja2V0Ym9vdHN0cmFw"),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("c2hhZG93"),
            StringDeobfuscator.base64Decode("ZG9wYW1pbmU="),
        ]
    }

    static var hookObjcMethodPrefixes: [String] {
        [
            StringDeobfuscator.base64Decode("amJf"),
            StringDeobfuscator.base64Decode("Y3lkaWFf"),
            StringDeobfuscator.base64Decode("c2lsZW9f"),
            StringDeobfuscator.base64Decode("aG9va18="),
            StringDeobfuscator.base64Decode("cGF0Y2hf"),
            StringDeobfuscator.base64Decode("dHdlYWtf"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRlXw=="),
            StringDeobfuscator.base64Decode("bXNf"),
        ]
    }

    static var hookSuspiciousProtocolNames: [String] {
        [
            StringDeobfuscator.base64Decode("Q3lkaWFEZWxlZ2F0ZQ=="),
            StringDeobfuscator.base64Decode("U2lsZW9EZWxlZ2F0ZQ=="),
            StringDeobfuscator.base64Decode("U3Vic3RpdHV0ZURlbGVnYXRl"),
            StringDeobfuscator.base64Decode("RnJpZGFIZWxwZXI="),
            StringDeobfuscator.base64Decode("SmFpbGJyZWFrUHJvdG9jb2w="),
        ]
    }

    static var hookSuspiciousObjCClasses: [String] {
        [
            StringDeobfuscator.base64Decode("Q3lkaWFPYmplY3Q="),
            StringDeobfuscator.base64Decode("Q3lkaWE="),
            StringDeobfuscator.base64Decode("Q3lkaWFEZWxlZ2F0ZQ=="),
            StringDeobfuscator.base64Decode("U2lsZW9QYWNrYWdl"),
            StringDeobfuscator.base64Decode("U2lsZW9Tb3VyY2U="),
            StringDeobfuscator.base64Decode("U2lsZW9NYW5hZ2Vy"),
            StringDeobfuscator.base64Decode("RkxFWE1hbmFnZXI="),
            StringDeobfuscator.base64Decode("RkxFWEV4cGxvcmVyVmlld0NvbnRyb2xsZXI="),
            StringDeobfuscator.base64Decode("RkxFWEV4cGxvcmVy"),
            StringDeobfuscator.base64Decode("RkxFWFdpbmRvdw=="),
            StringDeobfuscator.base64Decode("RmlzaEhvb2s="),
            StringDeobfuscator.base64Decode("Q3lkaWFTdWJzdHJhdGU="),
            StringDeobfuscator.base64Decode("U3Vic3RyYXRlTG9hZGVy"),
            StringDeobfuscator.base64Decode("RnJpZGFTZXJ2ZXI="),
            StringDeobfuscator.base64Decode("RnJpZGFHYWRnZXQ="),
            StringDeobfuscator.base64Decode("RnJpZGFBZ2VudA=="),
            StringDeobfuscator.base64Decode("R3VtSW52b2NhdGlvbkNvbnRleHQ="),
            StringDeobfuscator.base64Decode("R3VtSW50ZXJjZXB0b3I="),
            StringDeobfuscator.base64Decode("U1NMS2lsbFN3aXRjaA=="),
            StringDeobfuscator.base64Decode("TGliZXJ0eQ=="),
            StringDeobfuscator.base64Decode("TGliZXJ0eUxpdGU="),
            StringDeobfuscator.base64Decode("QUJ5cGFzcw=="),
            StringDeobfuscator.base64Decode("Um9ja2V0Qm9vdHN0cmFw"),
            StringDeobfuscator.base64Decode("UkJNYW5hZ2Vy"),
            StringDeobfuscator.base64Decode("Q1BEaXN0cmlidXRlZE1lc3NhZ2luZw=="),
            StringDeobfuscator.base64Decode("SEJQcmVmZXJlbmNlcw=="),
            StringDeobfuscator.base64Decode("SEJMT3B0aW9uc0NvbnRyb2xsZXI="),
        ]
    }

    static var categoryAntiTamper: String {
        StringDeobfuscator.base64Decode("YW50aV90YW1wZXI=")
    }

    static var evidenceKeyHooked: String {
        "\(keywordHook)ed"
    }

    /// Category value "jailbreak" (same as signalJailbreak, used where category is intended).
    static var categoryJailbreak: String { signalJailbreak }

    /// "lldb" for parent process / path checks.
    static var keywordLldb: String {
        StringDeobfuscator.base64Decode("bGxkYg==")
    }

    /// Signal id "vpn_active" for scenario requiredSignals.
    static var requiredSignalVpnActive: String {
        StringDeobfuscator.base64Decode("dnBuX2FjdGl2ZQ==")
    }

    /// Suspicious image name patterns for baseline env check (no literal tokens in binary).
    static var suspiciousImagePatternsBaseline: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
        ]
    }

    /// Full suspicious library tokens for dyld image scan (DyldDetector / DynamicFeatureList).
    static var suspiciousLibraryTokensForDyld: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("Z2FkZ2V0"),
            StringDeobfuscator.base64Decode("Z3Vt"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("bGlic3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("bGlic3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("Y3ljcmlwdA=="),
            StringDeobfuscator.base64Decode("bGliY3ljcmlwdA=="),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("c3Nsa2lsbA=="),
            StringDeobfuscator.base64Decode("c3Nsa2lsbCBzd2l0Y2g="),
            StringDeobfuscator.base64Decode("c3Nsa2lsbHN3aXRjaA=="),
            StringDeobfuscator.base64Decode("cHJlZmVyZW5jZWxvYWRlcg=="),
            StringDeobfuscator.base64Decode("ZmxleA=="),
            StringDeobfuscator.base64Decode("cm9ja2V0Ym9vdHN0cmFw"),
            StringDeobfuscator.base64Decode("YWN0aXZhdG9y"),
            StringDeobfuscator.base64Decode("bGliYWN0aXZhdG9y"),
            StringDeobfuscator.base64Decode("Y2VwaGVp"),
            StringDeobfuscator.base64Decode("dHdlYWtpbmplY3Q="),
            StringDeobfuscator.base64Decode("c2hhZG93"),
            StringDeobfuscator.base64Decode("ZG9wYW1pbmU="),
        ]
    }

    /// Shorter list for memory/code-signature integrity checks.
    static var suspiciousLibraryTokensForIntegrity: [String] {
        [
            keywordFrida,
            StringDeobfuscator.base64Decode("Z2FkZ2V0"),
            StringDeobfuscator.base64Decode("Z3Vt"),
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
        ]
    }

    /// For code signature validator: integrity tokens + "tweak", "hook".
    static var suspiciousInjectedLibraryTokens: [String] {
        suspiciousLibraryTokensForIntegrity + [
            StringDeobfuscator.base64Decode("dHdlYWs="),
            keywordHook,
        ]
    }

    /// Keywords for dylib injection detector (path/layout checks).
    static var dylibInjectionSuspiciousKeywords: [String] {
        [
            StringDeobfuscator.base64Decode("c3Vic3RyYXRl"),
            StringDeobfuscator.base64Decode("c3Vic3RpdHV0ZQ=="),
            StringDeobfuscator.base64Decode("ZWxsZWtpdA=="),
            StringDeobfuscator.base64Decode("bGliaG9va2Vy"),
            StringDeobfuscator.base64Decode("Y3luamVjdA=="),
            StringDeobfuscator.base64Decode("c3Bhd24="),
            StringDeobfuscator.base64Decode("dHdlYWtpbmplY3Q="),
            StringDeobfuscator.base64Decode("Y3lkaWFzdWJzdHJhdGU="),
            StringDeobfuscator.base64Decode("c2hhZG93"),
            StringDeobfuscator.base64Decode("bGliYmxhY2tqYWNr"),
            StringDeobfuscator.base64Decode("Y2hvaWN5"),
            StringDeobfuscator.base64Decode("c3Nsa2lsbHN3aXRjaA=="),
            StringDeobfuscator.base64Decode("ZmxleA=="),
            StringDeobfuscator.base64Decode("cmV2ZWFsZGVidWc="),
            StringDeobfuscator.base64Decode("Y3ljcmlwdA=="),
        ]
    }

    static var detectorIDDylibInjection: String {
        StringDeobfuscator.base64Decode("ZHlsaWJfaW5qZWN0aW9u")
    }
}

extension ObfuscatedConstants {
    static func withDeobfuscated<T>(_ getter: () -> String, _ body: (String) -> T) -> T {
        var str = getter()
        defer {
            str = ""
        }
        return body(str)
    }
}

enum BuildConfig {
    static let isRelease: Bool = {
        #if DEBUG
        return false
        #else
        return true
        #endif
    }()

    private(set) static var isConfigured = false

    static func configureForRelease() {
        guard !isConfigured else { return }
        isConfigured = true

        if isRelease {
            Logger.isEnabled = false
        }
    }
}
