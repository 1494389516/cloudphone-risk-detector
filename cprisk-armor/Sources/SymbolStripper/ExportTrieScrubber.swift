import Foundation
import MachOKit

/// Pass 6b: export trie scrub for executable outputs.
///
/// IDA/Hopper can recover symbol names from dyld export trie even after LC_SYMTAB
/// is zeroed. This pass scrubs export trie payload bytes and clears the command
/// offsets/sizes so static tooling no longer resolves names via exports metadata.
///
/// Safety boundary:
/// - `MH_EXECUTE`: scrub + zero fields (default)
/// - non-executable images (e.g. dylib): skipped to avoid runtime ABI breakage
public final class ExportTrieScrubberPass: ArmorPass {
    public let name = "ExportTrieScrubber"

    private struct ExportRegion {
        let kind: String
        let offset: Int
        let size: Int
        let offsetFieldOffset: Int
        let sizeFieldOffset: Int
    }

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        guard file.header.fileType == MachOHeader.MH_EXECUTE else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["Skipped: file type \(file.header.fileType) (only MH_EXECUTE is scrubbed)"]
            )
        }

        let regions = try collectExportRegions(in: file)
        guard !regions.isEmpty else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["No export trie load command found"]
            )
        }

        var headerBytes = 0
        var scrubbedBytes = 0
        var scrubbedRegions = 0
        var invalidRegions = 0
        var seen = Set<String>()

        for region in regions {
            // Always clear command pointers first.
            try file.writeUInt32(0, at: region.offsetFieldOffset)
            try file.writeUInt32(0, at: region.sizeFieldOffset)
            headerBytes += 8

            guard region.size > 0 else { continue }
            guard region.offset >= 0,
                  region.offset <= file.data.count,
                  region.size <= file.data.count - region.offset else {
                invalidRegions += 1
                continue
            }

            // LC_DYLD_INFO_ONLY and LC_DYLD_EXPORTS_TRIE may point to the same blob.
            let key = "\(region.offset):\(region.size)"
            guard seen.insert(key).inserted else { continue }

            let noise = Self.exportNoise(
                count: region.size,
                kind: region.kind,
                offset: region.offset,
                config: config
            )
            try file.replaceBytes(at: UInt64(region.offset), with: noise)
            scrubbedBytes += region.size
            scrubbedRegions += 1
        }

        var details = [
            "Export commands touched: \(regions.count)",
            "Export regions scrubbed: \(scrubbedRegions)",
            "Export bytes scrubbed: \(scrubbedBytes)",
            "Load-command fields zeroed: \(headerBytes) B"
        ]
        if invalidRegions > 0 {
            details.append("Skipped out-of-bounds export regions: \(invalidRegions)")
        }

        return PassResult(
            passName: name,
            itemsProcessed: scrubbedRegions,
            bytesModified: scrubbedBytes + headerBytes,
            details: details
        )
    }

    private func collectExportRegions(in file: MachOFile) throws -> [ExportRegion] {
        var regions = [ExportRegion]()

        for cmd in file.loadCommands {
            let cmdOffset = Int(cmd.offset)

            switch cmd.cmd {
            case LoadCommand.LC_DYLD_INFO_ONLY:
                guard cmd.cmdSize >= 48 else { continue }
                let exportOff = try Int(file.readUInt32(at: cmdOffset + 40))
                let exportSize = try Int(file.readUInt32(at: cmdOffset + 44))
                regions.append(
                    ExportRegion(
                        kind: "dyld_info_only.export",
                        offset: exportOff,
                        size: exportSize,
                        offsetFieldOffset: cmdOffset + 40,
                        sizeFieldOffset: cmdOffset + 44
                    )
                )

            case LoadCommand.LC_DYLD_EXPORTS_TRIE:
                guard cmd.cmdSize >= 16 else { continue }
                let exportOff = try Int(file.readUInt32(at: cmdOffset + 8))
                let exportSize = try Int(file.readUInt32(at: cmdOffset + 12))
                regions.append(
                    ExportRegion(
                        kind: "dyld_exports_trie",
                        offset: exportOff,
                        size: exportSize,
                        offsetFieldOffset: cmdOffset + 8,
                        sizeFieldOffset: cmdOffset + 12
                    )
                )

            default:
                continue
            }
        }

        return regions
    }

    private static func exportNoise(
        count: Int,
        kind: String,
        offset: Int,
        config: PassConfig
    ) -> Data {
        var material = Data("cprisk.pass6.export_trie_scrub.v1".utf8)
        material.append(Data(kind.utf8))

        var off = UInt64(offset).littleEndian
        Swift.withUnsafeBytes(of: &off) { material.append(contentsOf: $0) }

        var seed = config.buildSeed.littleEndian
        Swift.withUnsafeBytes(of: &seed) { material.append(contentsOf: $0) }

        if let key = config.encryptionKey {
            material.append(key)
        }
        return ArmorPseudoRandomFill.bytes(count: count, material: material)
    }
}
