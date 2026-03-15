import Foundation

/// Represents a Mach-O load command header with its raw payload.
public struct LoadCommand {
    public let cmd: UInt32
    public let cmdSize: UInt32
    public let offset: UInt64
    public let rawData: Data

    // Well-known load command types
    public static let LC_SEGMENT_64: UInt32     = 0x19
    public static let LC_SYMTAB: UInt32         = 0x02
    public static let LC_DYSYMTAB: UInt32       = 0x0B
    public static let LC_UUID: UInt32           = 0x1B
    public static let LC_CODE_SIGNATURE: UInt32 = 0x1D
    public static let LC_DYLD_INFO_ONLY: UInt32 = 0x80000022
    public static let LC_FUNCTION_STARTS: UInt32 = 0x26
    public static let LC_DATA_IN_CODE: UInt32   = 0x29

    public init(from data: Data, offset: UInt64) throws {
        let off = Int(offset)
        guard off + 8 <= data.count else {
            throw MachOError.invalidLoadCommand
        }

        cmd = try data.readUInt32(at: off)
        cmdSize = try data.readUInt32(at: off + 4)

        guard cmdSize >= 8, off + Int(cmdSize) <= data.count else {
            throw MachOError.invalidLoadCommand
        }

        self.offset = offset
        rawData = data.subdata(in: off..<(off + Int(cmdSize)))
    }
}
