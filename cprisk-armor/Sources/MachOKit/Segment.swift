import Foundation

// MARK: - Segment

/// Represents a 64-bit Mach-O segment (segment_command_64, base size 72 bytes).
public struct Segment {
    public let name: String
    public let vmAddress: UInt64
    public let vmSize: UInt64
    public let fileOffset: UInt64
    public let fileSize: UInt64
    public let maxProt: UInt32
    public let initProt: UInt32
    public let numberOfSections: UInt32
    public let flags: UInt32
    public var sections: [Section]

    /// segment_command_64 header size (excluding section headers).
    public static let headerSize: Int = 72

    /// Parse a segment_command_64 and its section headers from file data.
    ///
    /// - Parameters:
    ///   - data: Full Mach-O file data.
    ///   - commandOffset: Byte offset of the segment_command_64 within `data`.
    public init(from data: Data, commandOffset: UInt64) throws {
        let command = try LoadCommand(from: data, offset: commandOffset)
        guard command.cmd == LoadCommand.LC_SEGMENT_64 else {
            throw MachOError.invalidLoadCommand
        }
        let commandData = command.rawData
        guard commandData.count >= Self.headerSize else {
            throw MachOError.invalidLoadCommand
        }

        // segment_command_64 layout (offsets relative to command start):
        //   +0  cmd          UInt32
        //   +4  cmdsize      UInt32
        //   +8  segname      char[16]
        //  +24  vmaddr       UInt64
        //  +32  vmsize       UInt64
        //  +40  fileoff      UInt64
        //  +48  filesize     UInt64
        //  +56  maxprot      UInt32
        //  +60  initprot     UInt32
        //  +64  nsects       UInt32
        //  +68  flags        UInt32

        name = try commandData.readCString(at: 8, maxLength: 16)
        vmAddress = try commandData.readUInt64(at: 24)
        vmSize = try commandData.readUInt64(at: 32)
        fileOffset = try commandData.readUInt64(at: 40)
        fileSize = try commandData.readUInt64(at: 48)
        maxProt = try commandData.readUInt32(at: 56)
        initProt = try commandData.readUInt32(at: 60)
        numberOfSections = try commandData.readUInt32(at: 64)
        flags = try commandData.readUInt32(at: 68)

        let expectedCommandSize = Self.headerSize + Int(numberOfSections) * Section.size
        guard expectedCommandSize <= commandData.count else {
            throw MachOError.invalidData("Segment \(name) command is too small for \(numberOfSections) sections")
        }

        sections = []
        var secOffset = Self.headerSize
        for _ in 0..<numberOfSections {
            let secData = commandData.subdata(in: secOffset..<(secOffset + Section.size))
            let section = try Section(from: secData)
            sections.append(section)
            secOffset += Section.size
        }
    }
}

// MARK: - Section

/// Represents a 64-bit Mach-O section header (section_64, 80 bytes).
public struct Section {
    public let sectionName: String
    public let segmentName: String
    public let address: UInt64
    public let size: UInt64
    public let offset: UInt32
    public let align: UInt32
    public let relocationOffset: UInt32
    public let numberOfRelocations: UInt32
    public let flags: UInt32
    public let reserved1: UInt32
    public let reserved2: UInt32
    public let reserved3: UInt32

    public static let size: Int = 80
    public static let S_ZEROFILL: UInt32 = 0x1
    public static let S_GB_ZEROFILL: UInt32 = 0xC

    // section_64 layout (each header is self-contained):
    //   +0  sectname     char[16]
    //  +16  segname      char[16]
    //  +32  addr         UInt64
    //  +40  size         UInt64
    //  +48  offset       UInt32
    //  +52  align        UInt32
    //  +56  reloff       UInt32
    //  +60  nreloc       UInt32
    //  +64  flags        UInt32
    //  +68  reserved1    UInt32
    //  +72  reserved2    UInt32
    //  +76  reserved3    UInt32

    /// Parse from an 80-byte section_64 header blob.
    public init(from data: Data) throws {
        guard data.count >= Self.size else {
            throw MachOError.invalidData("Section header too small (\(data.count) < \(Self.size))")
        }

        sectionName = try data.readCString(at: 0, maxLength: 16)
        segmentName = try data.readCString(at: 16, maxLength: 16)
        address = try data.readUInt64(at: 32)
        size = try data.readUInt64(at: 40)
        offset = try data.readUInt32(at: 48)
        align = try data.readUInt32(at: 52)
        relocationOffset = try data.readUInt32(at: 56)
        numberOfRelocations = try data.readUInt32(at: 60)
        flags = try data.readUInt32(at: 64)
        reserved1 = try data.readUInt32(at: 68)
        reserved2 = try data.readUInt32(at: 72)
        reserved3 = try data.readUInt32(at: 76)
    }

    /// Memberwise initializer for programmatic construction.
    public init(
        sectionName: String, segmentName: String,
        address: UInt64, size: UInt64,
        offset: UInt32, align: UInt32,
        relocationOffset: UInt32, numberOfRelocations: UInt32,
        flags: UInt32, reserved1: UInt32, reserved2: UInt32, reserved3: UInt32
    ) {
        self.sectionName = sectionName
        self.segmentName = segmentName
        self.address = address
        self.size = size
        self.offset = offset
        self.align = align
        self.relocationOffset = relocationOffset
        self.numberOfRelocations = numberOfRelocations
        self.flags = flags
        self.reserved1 = reserved1
        self.reserved2 = reserved2
        self.reserved3 = reserved3
    }

    /// Read the raw content bytes of this section from the full file data.
    public var sectionType: UInt32 { flags & 0xFF }

    public var storesDataInFile: Bool {
        sectionType != Self.S_ZEROFILL && sectionType != Self.S_GB_ZEROFILL
    }

    public func readContent(from fileData: Data) throws -> Data {
        guard storesDataInFile else { return Data() }
        let start = Int(offset)
        guard size > 0 else { return Data() }
        let (end, overflow) = start.addingReportingOverflow(Int(size))
        guard !overflow, start >= 0, end <= fileData.count, start < end else {
            throw MachOError.validationFailed(
                "Section \(segmentName),\(sectionName) content range [\(start), \(start) + \(size)) is invalid"
            )
        }
        return fileData.subdata(in: start..<end)
    }
}

// MARK: - SwiftTypeMetadata

public struct SwiftTypeMetadata {
    public let offset: UInt64
    public let nameOffset: UInt64
    public let name: String
    public let isPublic: Bool

    public init(offset: UInt64, nameOffset: UInt64, name: String, isPublic: Bool) {
        self.offset = offset
        self.nameOffset = nameOffset
        self.name = name
        self.isPublic = isPublic
    }
}
