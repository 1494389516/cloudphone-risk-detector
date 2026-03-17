// swift-tools-version: 5.9
import PackageDescription

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
            publicHeadersPath: "include"
        ),
        .target(
            name: "CloudPhoneRiskKit",
            dependencies: ["CRiskCore"],
            resources: [
                .copy("Resources/PrivacyInfo.xcprivacy"),
            ]
        ),
        .target(
            name: "CloudPhoneRiskAppCore",
            dependencies: ["CloudPhoneRiskKit"]
        ),
        .testTarget(
            name: "CloudPhoneRiskKitTests",
            dependencies: [
                "CloudPhoneRiskKit",
                .product(name: "MachOKit", package: "cprisk-armor"),
            ]
        ),
        .testTarget(
            name: "CloudPhoneRiskAppCoreTests",
            dependencies: ["CloudPhoneRiskAppCore", "CloudPhoneRiskKit"]
        ),
    ]
)
