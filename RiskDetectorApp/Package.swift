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
    targets: [
        .target(
            name: "CloudPhoneRiskKit",
            dependencies: []
        ),
        .target(
            name: "CloudPhoneRiskAppCore",
            dependencies: ["CloudPhoneRiskKit"]
        ),
        .testTarget(
            name: "CloudPhoneRiskKitTests",
            dependencies: ["CloudPhoneRiskKit", "CloudPhoneRiskAppCore"],
            path: "Tests/CloudPhoneRiskKitTests"
            
        ),
    ]
)
