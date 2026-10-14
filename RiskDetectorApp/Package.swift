// swift-tools-version: 5.9
import Foundation
import PackageDescription

let packageEnvironment = ProcessInfo.processInfo.environment

func packageEnvEnabled(_ key: String) -> Bool {
    guard let rawValue = packageEnvironment[key]?
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased() else {
        return false
    }

    switch rawValue {
    case "1", "true", "yes", "on":
        return true
    default:
        return false
    }
}

func emitPackageWarning(_ message: String) {
    FileHandle.standardError.write(Data("warning: \(message)\n".utf8))
}

func configuredTool(_ key: String) -> Bool {
    guard let value = packageEnvironment[key]?.trimmingCharacters(in: .whitespacesAndNewlines),
          !value.isEmpty else {
        return false
    }
    if value.contains("/") {
        let path = value.hasPrefix("/") ? value : URL(
            fileURLWithPath: FileManager.default.currentDirectoryPath,
            isDirectory: true
        ).appendingPathComponent(value).path
        return FileManager.default.isExecutableFile(atPath: path)
    }
    return (packageEnvironment["PATH"] ?? "").split(
        separator: ":", omittingEmptySubsequences: false
    ).contains { entry in
        let directory = entry.isEmpty ? "." : String(entry)
        let path = URL(fileURLWithPath: directory, isDirectory: true)
            .appendingPathComponent(value).path
        return FileManager.default.isExecutableFile(atPath: path)
    }
}

// ⚠️ 供应链风险说明：以下两处均已是显式 env opt-in（默认关闭），
// 但开启后会改变构建行为，须在受控 CI 环境中审慎使用：
//  - `CPRISK_ENABLE_SWIFT_METADATA_CONVERGENCE=1` 开启 `unsafeFlags`
//   （`-disable-reflection-metadata` / `-disable-reflection-names`）：
//    会剥离反射元数据，影响 Mirror / 反射类调试与部分运行时行为；
//    任何能设置该环境变量的人都能改变 Release 产物。
//  - `CPRISK_ENABLE_HIKARI=1` / `CPRISK_HIKARI_REQUIRED=1` 允许
//    `SWIFT_EXEC` / `CC` 指向自定义编译器包装器：包装器在构建时以
//    构建机权限运行，可注入任意代码到产物中。切勿在不可信环境
//    或从不可信来源的脚本中开启；CI 中应固定包装器路径并校验其哈希。
let protectedReleaseSwiftSettings: [SwiftSetting] = packageEnvEnabled("CPRISK_ENABLE_SWIFT_METADATA_CONVERGENCE") ? [
    .unsafeFlags([
        "-Xfrontend", "-disable-reflection-metadata",
        "-Xfrontend", "-disable-reflection-names",
    ], .when(configuration: .release)),
    .define("CPRISK_MTE_COMPILE_SUPPORT", .when(configuration: .release)),
] : [
    .define("CPRISK_MTE_COMPILE_SUPPORT", .when(configuration: .release)),
]

if packageEnvEnabled("CPRISK_ENABLE_HIKARI") || packageEnvEnabled("CPRISK_HIKARI_REQUIRED") {
    let hikariRequired = packageEnvEnabled("CPRISK_HIKARI_REQUIRED")

    if !configuredTool("SWIFT_EXEC") {
        if hikariRequired {
            fatalError("CPRISK_HIKARI_REQUIRED=1 but SWIFT_EXEC is missing or not executable")
        }
        if let hikariSwiftc = packageEnvironment["HIKARI_SWIFTC"], !hikariSwiftc.isEmpty {
            emitPackageWarning("CPRISK_ENABLE_HIKARI=1: SwiftPM does not auto-consume HIKARI_SWIFTC, export SWIFT_EXEC=\"\(hikariSwiftc)\" to enable a custom Swift compiler wrapper")
        } else {
            emitPackageWarning("CPRISK_ENABLE_HIKARI=1 but SWIFT_EXEC is not set; SwiftPM builds continue with the host swiftc")
        }
    }

    if !configuredTool("CC") {
        if hikariRequired {
            fatalError("CPRISK_HIKARI_REQUIRED=1 but CC is missing or not executable")
        }
        if let hikariClang = packageEnvironment["HIKARI_CLANG"], !hikariClang.isEmpty {
            emitPackageWarning("CPRISK_ENABLE_HIKARI=1: SwiftPM does not auto-consume HIKARI_CLANG, export CC=\"\(hikariClang)\" to compile CRiskCore with a custom Clang wrapper")
        } else {
            emitPackageWarning("CPRISK_ENABLE_HIKARI=1 but CC is not set; CRiskCore continues with the host clang")
        }
    }
}

let package = Package(
    name: "CloudPhoneRiskKit",
    platforms: [
        .iOS(.v14),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "CloudPhoneRiskKit",
            targets: ["CloudPhoneRiskKit"]
        ),
        .library(
            name: "CloudPhoneRiskAppCore",
            targets: ["CloudPhoneRiskAppCore"]
        ),
    ],
    targets: [
        .target(
            name: "CRiskCore",
            dependencies: [],
            publicHeadersPath: "include",
            cSettings: [
                .define("CPRISK_MTE_COMPILE_SUPPORT", .when(configuration: .release)),
            ],
            linkerSettings: [
                .linkedFramework("Security", .when(platforms: [.iOS, .macOS])),
                .linkedFramework("IOKit", .when(platforms: [.macOS])),
            ]
        ),
        .target(
            name: "CloudPhoneRiskKit",
            dependencies: ["CRiskCore"],
            resources: [
                .copy("Resources/PrivacyInfo.xcprivacy"),
            ],
            swiftSettings: protectedReleaseSwiftSettings
        ),
        .target(
            name: "CloudPhoneRiskAppCore",
            dependencies: ["CloudPhoneRiskKit"],
            swiftSettings: protectedReleaseSwiftSettings
        ),
    ]
)
