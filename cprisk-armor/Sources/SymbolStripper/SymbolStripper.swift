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
    private static let LC_FUNCTION_STARTS: UInt32 = 0x26
    private static let LC_DATA_IN_CODE: UInt32 = 0x29

    private static let systemModulePrefixes: [String] = [
        "Swift", "Foundation", "UIKit", "SwiftUI",
        "CoreFoundation", "ObjectiveC", "Combine",
        "Darwin", "os", "Dispatch",
    ]

    private static let entryPoints: Set<String> = ["_main"]

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        let symbols = try file.readSymbols()
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
        // This still runs when `readSymbols()` is empty: pre-stripped inputs may
        // retain nonzero LC_DYSYMTAB linkedit pointers that make post-armor
        // system strip fail.
        let headerBytes = try zeroSymtabHeaders(in: file)
        bytesModified += headerBytes

        let staticAnalysisBytes = try zeroStaticAnalysisLinkeditCommands(in: file)
        bytesModified += staticAnalysisBytes

        var scrubbed = 0
        if let snap = symtabSnapshot {
            scrubbed = try scrubStaleSymtabPayloads(in: file, snapshot: snap, config: config)
            bytesModified += scrubbed
        }

        let removedCodeSignatureBytes = try file.removeCodeSignatureCommands()
        bytesModified += removedCodeSignatureBytes

        let compactedBytes = try file.compactUnreferencedLinkeditTail()
        bytesModified += compactedBytes

        let localCount = symbols.filter { $0.nlist.isDefinedLocal }.count
        details.insert(
            "Local symbols: \(localCount)/\(symbols.count) total, \(obfuscatedCount) obfuscated, symtab/dysymtab normalized, stale sym payload scrub: \(scrubbed) B, code signature command removed: \(removedCodeSignatureBytes) B, linkedit compacted: \(compactedBytes) B",
            at: 0
        )
        if staticAnalysisBytes > 0 {
            details.append("Static linkedit analysis commands cleared: \(staticAnalysisBytes) B")
        }
        if symbols.isEmpty {
            details.append("No nlist symbols found; linkedit symbol metadata still normalized")
        }

        return PassResult(
            passName: name,
            itemsProcessed: obfuscatedCount,
            bytesModified: bytesModified,
            details: details
        )
    }

    /// Function starts and data-in-code tables are static-analysis hints, not
    /// runtime requirements. Once we intentionally remove the symbol table, stale
    /// linkedit gaps before these tables make Apple's `strip` fail its strict
    /// ordering checks. Clear them so a later linkedit compaction can produce a
    /// self-consistent already-stripped file.
    private func zeroStaticAnalysisLinkeditCommands(in file: MachOFile) throws -> Int {
        var bytesZeroed = 0
        var cmdOffset = MachOHeader.size

        for _ in 0..<Int(file.header.numberOfCommands) {
            let cmd = try file.readUInt32(at: cmdOffset)
            let cmdSize = try file.readUInt32(at: cmdOffset + 4)
            guard cmdSize >= 8 else { break }

            if (cmd == Self.LC_FUNCTION_STARTS || cmd == Self.LC_DATA_IN_CODE), cmdSize >= 16 {
                let oldOff = try file.readUInt32(at: cmdOffset + 8)
                let oldSize = try file.readUInt32(at: cmdOffset + 12)
                if oldOff != 0 || oldSize != 0 {
                    try file.writeUInt32(0, at: cmdOffset + 8)
                    try file.writeUInt32(0, at: cmdOffset + 12)
                    bytesZeroed += 8
                }
            }

            cmdOffset += Int(cmdSize)
        }

        return bytesZeroed
    }

    // MARK: - Symtab Header Zeroing

    /// Walk the load-command list and zero the count/offset fields in
    /// LC_SYMTAB (symoff, nsyms, stroff, strsize) and every linkedit table
    /// pointer/count pair in LC_DYSYMTAB. The cmdsize fields are deliberately
    /// preserved so the load-command chain stays intact and IDA can parse the
    /// binary.
    ///
    /// Keeping `indirectsymoff/nindirectsyms` after clearing `LC_SYMTAB` leaves
    /// a dangling linkedit table. Apple's `strip` then tries to preserve that
    /// later table and rejects earlier `LC_FUNCTION_STARTS` payloads as "out of
    /// place". Clearing the whole dysymtab metadata makes the armored binary
    /// self-consistent for both static tools and post-armor strip invocations.
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
                // LC_DYSYMTAB — zero every offset/count pair after cmd/cmdsize:
                //  +8  ilocalsym      +12 nlocalsym
                //  +16 iextdefsym     +20 nextdefsym
                //  +24 iundefsym      +28 nundefsym
                //  +32 tocoff         +36 ntoc
                //  +40 modtaboff      +44 nmodtab
                //  +48 extrefsymoff   +52 nextrefsyms
                //  +56 indirectsymoff +60 nindirectsyms
                //  +64 extreloff      +68 nextrel
                //  +72 locreloff      +76 nlocrel
                guard cmdSize >= 32 else { cmdOffset += Int(cmdSize); continue }
                for fieldOff in stride(from: 8, through: min(Int(cmdSize) - 4, 76), by: 4) {
                    try file.writeUInt32(0, at: cmdOffset + fieldOff)
                    bytesZeroed += 4
                }
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
        if symbolName.hasPrefix("_dyld_") || symbolName.hasPrefix("__dyld_") { return false }
        if symbolName.hasPrefix("__mh_") { return false }
        if Self.entryPoints.contains(symbolName) { return false }

        return true
    }

    // MARK: - Random Generation

    private static let hexTable: [UInt8] = Array("0123456789abcdef".utf8)

    private static func randomHexBytes(count: Int) -> Data {
        Data((0..<count).map { _ in hexTable[Int.random(in: 0..<hexTable.count)] })
    }
}
