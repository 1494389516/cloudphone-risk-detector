import Foundation
import MachOKit

/// Pass 6: Strip or obfuscate ALL defined-local symbols from the Mach-O
/// nlist symbol table to prevent IDA / Hopper from demangling function names.
///
/// Only touches LOCAL symbols (no N_EXT, no N_UNDF, no N_STAB).
/// Every local symbol is obfuscated **unless** it matches a conservative
/// whitelist of system/runtime prefixes. The symbol name bytes in the string
/// table are replaced with random hex of the same length, preserving the
/// null terminator and overall table layout.
public final class SymbolStripperPass: ArmorPass {
    public let name = "SymbolStripper"

    private static let systemModulePrefixes: [String] = [
        "Swift", "Foundation", "UIKit", "SwiftUI",
        "CoreFoundation", "ObjectiveC", "Combine",
        "Darwin", "os", "Dispatch",
    ]

    private static let entryPoints: Set<String> = ["_main"]

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        let symbols = try file.readSymbols()
        guard !symbols.isEmpty else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["No symbol table found or empty"]
            )
        }

        var obfuscatedCount = 0
        var bytesModified = 0
        var details = [String]()

        for entry in symbols {
            guard entry.nlist.isDefinedLocal else { continue }
            guard entry.nameLength > 0 else { continue }
            guard shouldObfuscate(entry.name) else { continue }

            let replacement = Self.randomHexBytes(count: entry.nameLength)
            try file.obfuscateSymbolName(entry, with: replacement)
            obfuscatedCount += 1
            bytesModified += entry.nameLength

            if config.verbose {
                let truncated = entry.name.prefix(80)
                details.append("Obfuscated: \(truncated)")
            }
        }

        let localCount = symbols.filter { $0.nlist.isDefinedLocal }.count
        details.insert(
            "Local symbols: \(localCount)/\(symbols.count) total, \(obfuscatedCount) obfuscated",
            at: 0
        )

        return PassResult(
            passName: name,
            itemsProcessed: obfuscatedCount,
            bytesModified: bytesModified,
            details: details
        )
    }

    // MARK: - Decision Logic

    private func shouldObfuscate(_ symbolName: String) -> Bool {
        if symbolName.count <= 1 { return false }

        if symbolName.hasPrefix("_$s") {
            for module in Self.systemModulePrefixes where symbolName.contains(module) {
                return false
            }
        }

        if symbolName.hasPrefix("_objc_") || symbolName.hasPrefix("_OBJC_") { return false }
        if symbolName.hasPrefix("_swift_") { return false }
        if symbolName.hasPrefix("___swift_") { return false }
        if Self.entryPoints.contains(symbolName) { return false }

        return true
    }

    // MARK: - Random Generation

    private static let hexTable: [UInt8] = Array("0123456789abcdef".utf8)

    private static func randomHexBytes(count: Int) -> Data {
        Data((0..<count).map { _ in hexTable[Int.random(in: 0..<hexTable.count)] })
    }
}
