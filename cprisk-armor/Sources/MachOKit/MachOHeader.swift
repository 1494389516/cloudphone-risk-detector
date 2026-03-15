import Foundation

/// Represents a 64-bit Mach-O file header (mach_header_64, 32 bytes).
public struct MachOHeader {
    public let magic: UInt32
    public let cpuType: UInt32
    public let cpuSubtype: UInt32
    public let fileType: UInt32
    public let numberOfCommands: UInt32
    public let sizeOfCommands: UInt32
    public let flags: UInt32
    public let reserved: UInt32

    public static let size: Int = 32

    public static let MH_MAGIC_64: UInt32 = 0xFEEDFACF
    public static let CPU_TYPE_ARM64: UInt32 = 0x0100000C
    public static let MH_EXECUTE: UInt32 = 2
    public static let MH_DYLIB: UInt32 = 6

    public init(from data: Data) throws {
        guard data.count >= Self.size else {
            throw MachOError.invalidHeader
        }

        magic = try data.readUInt32(at: 0)
        cpuType = try data.readUInt32(at: 4)
        cpuSubtype = try data.readUInt32(at: 8)
        fileType = try data.readUInt32(at: 12)
        numberOfCommands = try data.readUInt32(at: 16)
        sizeOfCommands = try data.readUInt32(at: 20)
        flags = try data.readUInt32(at: 24)
        reserved = try data.readUInt32(at: 28)
    }

    public var isValid: Bool { magic == Self.MH_MAGIC_64 }
}
