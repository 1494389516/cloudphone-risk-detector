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

    static var ptrace: String {
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
