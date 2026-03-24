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
///
/// After randomizing all names, the pass also zeroes LC_SYMTAB.{symoff,nsyms,
/// stroff,strsize} and the six LC_DYSYMTAB sym-count fields so that disassemblers
/// (IDA, Hopper, Binary Ninja) see an empty symbol table and display every
/// function as sub_XXXX rather than a randomised hex name — eliminating the
/// need for any external post-processing step.
public final class SymbolStripperPass: ArmorPass {
    public let name = "SymbolStripper"

    private static let LC_SYMTAB:   UInt32 = 0x02
    private static let LC_DYSYMTAB: UInt32 = 0x0B

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

        let symtabSnapshot = try file.findSymbolTable()

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

        // Zero LC_SYMTAB and LC_DYSYMTAB count/offset fields so disassemblers
        // treat the symbol table as empty and show sub_XXXX for all functions.
        let headerBytes = try zeroSymtabHeaders(in: file)
        bytesModified += headerBytes

        var scrubbed = 0
        if let snap = symtabSnapshot {
            scrubbed = try scrubStaleSymtabPayloads(in: file, snapshot: snap, config: config)
            bytesModified += scrubbed
        }

        let localCount = symbols.filter { $0.nlist.isDefinedLocal }.count
        details.insert(
            "Local symbols: \(localCount)/\(symbols.count) total, \(obfuscatedCount) obfuscated, symtab header zeroed, stale sym payload scrub: \(scrubbed) B",
            at: 0
        )

        return PassResult(
            passName: name,
            itemsProcessed: obfuscatedCount,
            bytesModified: bytesModified,
            details: details
        )
    }

    // MARK: - Symtab Header Zeroing

    /// Walk the load-command list and zero the count/offset fields in
    /// LC_SYMTAB (symoff, nsyms, stroff, strsize) and the six sym-count
    /// fields in LC_DYSYMTAB.  The cmdsize fields are deliberately preserved
    /// so the load-command chain stays intact and IDA can parse the binary.
    private func zeroSymtabHeaders(in file: MachOFile) throws -> Int {
        var bytesZeroed = 0
        let header = file.header
        var cmdOffset = MachOHeader.size

        for _ in 0..<Int(header.numberOfCommands) {
            let cmd    = try file.readUInt32(at: cmdOffset)
            let cmdSize = try file.readUInt32(at: cmdOffset + 4)
            guard cmdSize >= 8 else { break }

            if cmd == Self.LC_SYMTAB {
                // LC_SYMTAB layout (offsets relative to command start):
                //  +0  cmd      (preserved)
                //  +4  cmdsize  (preserved — must not touch)
                //  +8  symoff   ← zero
                //  +12 nsyms    ← zero
                //  +16 stroff   ← zero
                //  +20 strsize  ← zero
                guard cmdSize >= 24 else { cmdOffset += Int(cmdSize); continue }
                try file.writeUInt32(0, at: cmdOffset + 8)
                try file.writeUInt32(0, at: cmdOffset + 12)
                try file.writeUInt32(0, at: cmdOffset + 16)
                try file.writeUInt32(0, at: cmdOffset + 20)
                bytesZeroed += 16

            } else if cmd == Self.LC_DYSYMTAB {
                // LC_DYSYMTAB — zero the six local/ext/undef sym count fields:
                //  +8  ilocalsym   +12 nlocalsym
                //  +16 iextdefsym  +20 nextdefsym
                //  +24 iundefsym   +28 nundefsym
                guard cmdSize >= 32 else { cmdOffset += Int(cmdSize); continue }
                for fieldOff in [8, 12, 16, 20, 24, 28] {
                    try file.writeUInt32(0, at: cmdOffset + fieldOff)
                }
                bytesZeroed += 24
            }

            cmdOffset += Int(cmdSize)
        }

        return bytesZeroed
    }

    /// After LC_SYMTAB is logically empty, the historical nlist/strtab bytes may still
    /// linger in ``__LINKEDIT`` and be recovered by raw file scanners. Overwrite those
    /// regions with deterministic high-entropy filler (same sizes; dyld does not consult
    /// symtab when offsets are zero).
    private func scrubStaleSymtabPayloads(in file: MachOFile, snapshot: SymbolTableInfo, config: PassConfig) throws -> Int {
        var base = Data("cprisk.pass6.linkedit_symtab_scrub.v1".utf8)
        if let key = config.encryptionKey {
            base.append(key)
        }
        var bs = config.buildSeed.littleEndian
        Swift.withUnsafeBytes(of: &bs) { base.append(contentsOf: $0) }

        var total = 0
        let symoff = Int(snapshot.symoff)
        let nsyms = Int(snapshot.nsyms)
        let nlistBytes = nsyms * Nlist64Entry.entrySize
        if nlistBytes > 0, symoff >= 0, symoff + nlistBytes <= file.data.count {
            var mat = base
            mat.append(0x4E) // 'N' — nlist region
            let noise = ArmorPseudoRandomFill.bytes(count: nlistBytes, material: mat)
            try file.replaceBytes(at: UInt64(symoff), with: noise)
            total += nlistBytes
        }

        let stroff = Int(snapshot.stroff)
        let strsize = Int(snapshot.strsize)
        if strsize > 0, stroff >= 0, stroff + strsize <= file.data.count {
            var mat = base
            mat.append(0x53) // 'S' — string table region
            let noise = ArmorPseudoRandomFill.bytes(count: strsize, material: mat)
            try file.replaceBytes(at: UInt64(stroff), with: noise)
            total += strsize
        }

        return total
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
