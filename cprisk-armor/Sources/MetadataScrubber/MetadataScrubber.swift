import Foundation
import MachOKit

/// Pass 2: Scrub non-essential Swift / ObjC metadata to hinder reverse engineering.
///
/// Strips or obfuscates type names, protocol conformance descriptors,
/// and reflection metadata that are not required at runtime.
public final class MetadataScrubberPass: ArmorPass {
    public let name = "MetadataScrubber"

    private static let sdkMethodMarkers = [
        "cprisk", "CPRisk", "cloudPhone", "CloudPhone",
        "riskSignal", "RiskSignal", "riskReport", "RiskReport",
        "detection", "Detection", "jailbreak", "Jailbreak",
        "antiTamper", "AntiTamper", "trustChain", "TrustChain",
        "behavior", "Behavior", "evaluate", "armoring",
    ]

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        var itemsProcessed = 0
        var bytesModified = 0
        var details = [String]()

        let typeResult = try scrubSwiftTypeNames(in: file)
        itemsProcessed += typeResult.obfuscated
        bytesModified += typeResult.bytes
        details.append("Swift type names obfuscated: \(typeResult.obfuscated)/\(typeResult.total)")

        let reflBytes = try scrubReflectionStrings(in: file)
        if reflBytes > 0 {
            itemsProcessed += 1
            bytesModified += reflBytes
            details.append("Reflection strings scrubbed: \(reflBytes) bytes")
        }

        let methResult = try scrubObjCMethodNames(in: file)
        if methResult.total > 0 {
            itemsProcessed += methResult.obfuscated
            bytesModified += methResult.bytes
            details.append("ObjC method names obfuscated: \(methResult.obfuscated)/\(methResult.total)")
        }

        return PassResult(
            passName: name,
            itemsProcessed: itemsProcessed,
            bytesModified: bytesModified,
            details: details
        )
    }

    // MARK: - A. Swift Type Name Obfuscation

    private func scrubSwiftTypeNames(
        in file: MachOFile
    ) throws -> (total: Int, obfuscated: Int, bytes: Int) {
        let metadata = try file.findSwiftTypeMetadata()
        var obfuscated = 0
        var bytes = 0

        for entry in metadata {
            guard shouldObfuscateType(entry) else { continue }
            let nameLength = entry.name.utf8.count
            guard nameLength > 0 else { continue }

            try file.replaceBytes(at: entry.nameOffset, with: Self.randomHexBytes(count: nameLength))
            obfuscated += 1
            bytes += nameLength
        }

        return (metadata.count, obfuscated, bytes)
    }

    // MARK: - B. Reflection String Scrubbing

    private func scrubReflectionStrings(in file: MachOFile) throws -> Int {
        guard let section = try file.section(
            segment: "__TEXT",
            section: ArmorABI.MetadataSections.swiftReflectionStrings
        ) else { return 0 }

        let size = Int(section.size)
        guard size > 0 else { return 0 }

        try file.replaceBytes(at: UInt64(section.offset), with: Self.randomBytes(count: size))
        return size
    }

    // MARK: - C. ObjC Method Name Obfuscation

    private func scrubObjCMethodNames(
        in file: MachOFile
    ) throws -> (total: Int, obfuscated: Int, bytes: Int) {
        guard let section = try file.section(
            segment: "__TEXT",
            section: ArmorABI.MetadataSections.objcMethodNames
        ) else { return (0, 0, 0) }

        let content = try section.readContent(from: file.data)
        guard !content.isEmpty else { return (0, 0, 0) }

        let sectionFileOffset = UInt64(section.offset)
        var total = 0
        var obfuscated = 0
        var bytes = 0
        var position = 0

        while position < content.count {
            var end = position
            while end < content.count && content[end] != 0 { end += 1 }

            if end > position,
               let methodName = String(data: content.subdata(in: position..<end), encoding: .utf8)
            {
                total += 1
                if Self.shouldObfuscateMethod(methodName) {
                    let length = end - position
                    try file.replaceBytes(
                        at: sectionFileOffset + UInt64(position),
                        with: Self.randomHexBytes(count: length)
                    )
                    obfuscated += 1
                    bytes += length
                }
            }

            position = end + 1
        }

        return (total, obfuscated, bytes)
    }

    // MARK: - Decision Logic

    private func shouldObfuscateType(_ metadata: SwiftTypeMetadata) -> Bool {
        let name = metadata.name
        guard name.count > 2 else { return false }
        if name.contains("cprisk_") { return false }
        return true
    }

    private static func shouldObfuscateMethod(_ name: String) -> Bool {
        guard !name.isEmpty else { return false }
        for marker in sdkMethodMarkers where name.contains(marker) {
            return true
        }
        return false
    }

    // MARK: - Random Generation

    private static let hexTable: [UInt8] = Array("0123456789abcdef".utf8)

    private static func randomHexBytes(count: Int) -> Data {
        Data((0..<count).map { _ in hexTable[Int.random(in: 0..<16)] })
    }

    private static func randomBytes(count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255) })
    }
}
