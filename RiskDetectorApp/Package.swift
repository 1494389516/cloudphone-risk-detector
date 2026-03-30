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

let protectedReleaseSwiftSettings: [SwiftSetting] = packageEnvEnabled("CPRISK_ENABLE_SWIFT_METADATA_CONVERGENCE") ? [
    .unsafeFlags([
        "-Xfrontend", "-disable-reflection-metadata",
        "-Xfrontend", "-disable-reflection-names",
    ], .when(configuration: .release)),
    .define("CPRISK_MTE_COMPILE_SUPPORT", .when(configuration: .release)),
] : [
    .define("CPRISK_MTE_COMPILE_SUPPORT", .when(configuration: .release)),
]

if packageEnvEnabled("CPRISK_ENABLE_HIKARI") {
    if packageEnvironment["SWIFT_EXEC"] == nil {
        if let hikariSwiftc = packageEnvironment["HIKARI_SWIFTC"], !hikariSwiftc.isEmpty {
            emitPackageWarning("CPRISK_ENABLE_HIKARI=1: SwiftPM does not auto-consume HIKARI_SWIFTC, export SWIFT_EXEC=\"\(hikariSwiftc)\" to enable a custom Swift compiler wrapper")
        } else {
            emitPackageWarning("CPRISK_ENABLE_HIKARI=1 but SWIFT_EXEC is not set; SwiftPM builds continue with the host swiftc")
        }
    }

    if packageEnvironment["CC"] == nil {
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
    dependencies: [
        .package(path: "../cprisk-armor"),
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
        .testTarget(
            name: "CloudPhoneRiskKitTests",
            dependencies: [
                "CloudPhoneRiskKit",
                .product(name: "MachOKit", package: "cprisk-armor"),
                .product(name: "VMProtector", package: "cprisk-armor"),
            ]
        ),
        .testTarget(
            name: "CloudPhoneRiskAppCoreTests",
            dependencies: ["CloudPhoneRiskAppCore", "CloudPhoneRiskKit"]
        ),
    ]
)
