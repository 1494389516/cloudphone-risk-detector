// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "cprisk-armor",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "cprisk-armor", targets: ["cprisk-armor"])
    ],
    targets: [
        .target(name: "MachOKit"),
        .target(name: "StringEncryptor", dependencies: ["MachOKit"]),
        .target(name: "MetadataScrubber", dependencies: ["MachOKit"]),
        .target(name: "DataSegmentEncryptor", dependencies: ["MachOKit"]),
        .target(name: "IntegrityAnchor", dependencies: ["MachOKit"]),
        .target(name: "StructureObfuscator", dependencies: ["MachOKit"]),
        .target(name: "SymbolStripper", dependencies: ["MachOKit"]),
        .executableTarget(
            name: "cprisk-armor",
            dependencies: [
                "MachOKit",
                "StringEncryptor",
                "MetadataScrubber",
                "DataSegmentEncryptor",
                "IntegrityAnchor",
                "StructureObfuscator",
                "SymbolStripper"
            ]
        ),
        .testTarget(name: "MachOKitTests", dependencies: [
            "MachOKit", "StringEncryptor", "MetadataScrubber",
            "DataSegmentEncryptor", "IntegrityAnchor", "StructureObfuscator",
            "SymbolStripper",
        ])
    ]
)
