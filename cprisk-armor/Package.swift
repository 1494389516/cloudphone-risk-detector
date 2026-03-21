// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "cprisk-armor",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "MachOKit", targets: ["MachOKit"]),
        .executable(name: "cprisk-armor", targets: ["cprisk-armor"])
    ],
    targets: [
        .target(name: "MachOKit"),
        .target(name: "StringEncryptor", dependencies: ["MachOKit"]),
        .target(name: "MetadataScrubber", dependencies: ["MachOKit"]),
        .target(name: "DataSegmentEncryptor", dependencies: ["MachOKit"]),
        .target(name: "IntegrityAnchor", dependencies: ["MachOKit"]),
        .target(name: "StructureObfuscator", dependencies: ["MachOKit"]),
        .target(name: "AntiDebugInjector", dependencies: ["MachOKit"]),
        .target(name: "InstructionSubstitution", dependencies: ["MachOKit"]),
        .target(name: "ControlFlowOrchestrator", dependencies: ["MachOKit", "InstructionSubstitution"]),
        .target(name: "SymbolStripper", dependencies: ["MachOKit"]),
        .target(name: "ImportEncryptor", dependencies: ["MachOKit"]),
        .target(name: "HeaderEncryptor", dependencies: ["MachOKit"]),
        .target(name: "TextSegmentEncryptor", dependencies: ["MachOKit"]),
        .executableTarget(
            name: "cprisk-armor",
            dependencies: [
                "MachOKit",
                "StringEncryptor",
                "MetadataScrubber",
                "DataSegmentEncryptor",
                "IntegrityAnchor",
                "StructureObfuscator",
                "AntiDebugInjector",
                "InstructionSubstitution",
                "ControlFlowOrchestrator",
                "SymbolStripper",
                "ImportEncryptor",
                "HeaderEncryptor",
                "TextSegmentEncryptor"
            ]
        ),
        .testTarget(name: "MachOKitTests", dependencies: [
            "MachOKit", "StringEncryptor", "MetadataScrubber",
            "DataSegmentEncryptor", "IntegrityAnchor", "StructureObfuscator",
            "AntiDebugInjector", "InstructionSubstitution", "ControlFlowOrchestrator", "SymbolStripper", "ImportEncryptor", "HeaderEncryptor",
            "TextSegmentEncryptor",
        ])
    ]
)
